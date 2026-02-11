using System.Text;
using System.Text.Json;
using OAuthBandit.Core;
using OAuthBandit.Crypto;
using OAuthBandit.Utils;

namespace OAuthBandit.Extractors;

public abstract class BaseExtractor
{
    protected string ExtractedAt { get; } = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

    public abstract List<Token> Extract();

    protected bool IsMicrosoftToken(string? clientId, string? scope, string? upn, string tokenValue)
    {
        if (clientId != null && Constants.AllMicrosoftAppIds.Contains(clientId))
            return true;

        if (scope != null)
        {
            foreach (var msScope in Constants.MicrosoftScopes)
                if (scope.Contains(msScope, StringComparison.OrdinalIgnoreCase))
                    return true;
        }

        if (upn != null)
        {
            string[] msDomains = { "@microsoft.com", "@outlook.com", "@hotmail.com", "@live.com", "@office365.com", "onmicrosoft.com" };
            if (msDomains.Any(d => upn.Contains(d, StringComparison.OrdinalIgnoreCase)))
                return true;
        }

        if (tokenValue.StartsWith("1.A"))
            return true;

        return false;
    }

    // fallback: if appid/azp missing, use aud if its a guid
    protected string? GetClientIdWithAudFallback(Dictionary<string, object> payload)
    {
        var cid = GetJsonString(payload, "appid", "azp", "client_id");
        if (cid != null) return cid;

        var aud = GetJsonString(payload, "aud");
        if (aud != null && Constants.GuidPattern.IsMatch(aud))
            return aud;
        return null;
    }

    protected string IdentifyApplication(string? clientId, string? scope)
    {
        if (clientId == null)
        {
            if (scope != null)
            {
                var sl = scope.ToLowerInvariant();
                if (sl.Contains("teams")) return "Microsoft Teams";
                if (sl.Contains("outlook") || sl.Contains("mail")) return "Outlook";
                if (sl.Contains("sharepoint") || sl.Contains("sites")) return "SharePoint";
                if (sl.Contains("onedrive") || sl.Contains("files")) return "OneDrive";
            }
            return "Microsoft (Unknown)";
        }

        // Use the new FociApps/OtherApps dictionaries
        var appName = Constants.GetAppName(clientId);
        if (appName != clientId && !appName.EndsWith("..."))
            return appName;
        return "Microsoft (Other)";
    }

    protected Dictionary<string, object>? ParseJwtPayload(string jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length < 2) return null;
            var payload = CryptoUtils.DecodeBase64Url(parts[1]);
            return JsonSerializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(payload));
        }
        catch { return null; }
    }

    protected (string? clientId, string? tenantId) ExtractRefreshTokenMetadata(string refreshToken)
    {
        if (string.IsNullOrEmpty(refreshToken) || !refreshToken.StartsWith("1."))
            return (null, null);

        try
        {
            var body = refreshToken[2..];
            int dot = body.IndexOf('.');
            if (dot > 0) body = body[..dot];
            if (body.StartsWith("AV0A")) body = body[4..];
            if (body.Length < 44) return (null, null);

            var decoded = CryptoUtils.DecodeBase64Url(body[..44]);
            if (decoded.Length >= 32)
            {
                var tenantId = EncodingUtils.FormatGuidFromBytes(decoded, 0);
                var clientId = EncodingUtils.FormatGuidFromBytes(decoded, 16);
                return (clientId, tenantId);
            }
        }
        catch { }
        return (null, null);
    }

    protected static string? GetJsonString(Dictionary<string, object> dict, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (dict.TryGetValue(key, out var val) && val is JsonElement je && je.ValueKind == JsonValueKind.String)
                return je.GetString();
        }
        return null;
    }

    protected static long? GetJsonLong(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var val) && val is JsonElement je && je.ValueKind == JsonValueKind.Number)
            return je.GetInt64();
        return null;
    }
}
