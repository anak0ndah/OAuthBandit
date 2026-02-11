using System.DirectoryServices.Protocols;
using System.Net;
using OAuthBandit.Core;

namespace OAuthBandit.Remote;

public class LdapEnumerator : IDisposable
{
    private readonly string _dcIp;
    private readonly string _domain;
    private readonly string _username;
    private readonly string? _password;
    private readonly string? _nthash;
    private readonly string _baseDn;
    private LdapConnection? _connection;

    public LdapEnumerator(string dcIp, string domain, string username,
        string? password = null, string? nthash = null)
    {
        _dcIp = dcIp;
        _domain = domain;
        _username = username;
        _password = password;
        _nthash = nthash;
        _baseDn = string.Join(",", domain.Split('.').Select(p => $"DC={p}"));
    }

    public bool Connect()
    {
        try
        {
            var identifier = new LdapDirectoryIdentifier(_dcIp, 389);
            var credential = new NetworkCredential(_username, _password ?? "", _domain);

            _connection = new LdapConnection(identifier, credential, AuthType.Ntlm);
            _connection.SessionOptions.ProtocolVersion = 3;
            _connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            _connection.Timeout = TimeSpan.FromSeconds(15);
            _connection.Bind();

            Console.WriteLine($"[+] Connected to LDAP: {_dcIp}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] LDAP connection error: {ex.Message}");
            return false;
        }
    }

    public List<DomainComputer> GetComputers(bool onlyEnabled = true)
    {
        if (_connection == null) return new();

        var computers = new List<DomainComputer>();

        var filter = onlyEnabled
            ? "(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            : "(&(objectCategory=computer)(objectClass=computer))";

        try
        {
            var request = new SearchRequest(_baseDn, filter, SearchScope.Subtree,
                "cn", "dNSHostName", "operatingSystem", "userAccountControl");
            request.SizeLimit = 0;
            var pageControl = new PageResultRequestControl(1000);
            request.Controls.Add(pageControl);

            while (true)
            {
                var response = (SearchResponse)_connection.SendRequest(request);

                foreach (SearchResultEntry entry in response.Entries)
                {
                    var name = GetAttr(entry, "cn") ?? "";
                    var dnsHostname = GetAttr(entry, "dNSHostName") ?? name;
                    var os = GetAttr(entry, "operatingSystem") ?? "Unknown";

                    computers.Add(new DomainComputer
                    {
                        Name = name,
                        DnsHostname = dnsHostname,
                        OperatingSystem = os,
                        Enabled = true
                    });
                }

                var pageResponse = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                if (pageResponse == null || pageResponse.Cookie.Length == 0) break;
                pageControl.Cookie = pageResponse.Cookie;
            }

            Console.WriteLine($"[+] Found {computers.Count} computers in domain");
            return computers;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] LDAP search error: {ex.Message}");
            return new();
        }
    }

    public List<string> GetDomainUsers()
    {
        if (_connection == null) return new();

        var users = new List<string>();

        try
        {
            var filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
            var request = new SearchRequest(_baseDn, filter, SearchScope.Subtree,
                "sAMAccountName", "userPrincipalName");
            request.SizeLimit = 0;
            var pageControl = new PageResultRequestControl(1000);
            request.Controls.Add(pageControl);

            while (true)
            {
                var response = (SearchResponse)_connection.SendRequest(request);

                foreach (SearchResultEntry entry in response.Entries)
                {
                    var upn = GetAttr(entry, "userPrincipalName");
                    var sam = GetAttr(entry, "sAMAccountName");
                    users.Add(upn ?? sam ?? "");
                }

                var pageResponse = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                if (pageResponse == null || pageResponse.Cookie.Length == 0) break;
                pageControl.Cookie = pageResponse.Cookie;
            }

            Console.WriteLine($"[+] Found {users.Count} users in domain");
            return users;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] LDAP user search error: {ex.Message}");
            return new();
        }
    }

    private static string? GetAttr(SearchResultEntry entry, string name)
    {
        if (entry.Attributes.Contains(name) && entry.Attributes[name].Count > 0)
            return entry.Attributes[name][0]?.ToString();
        return null;
    }

    public void Dispose()
    {
        _connection?.Dispose();
    }
}
