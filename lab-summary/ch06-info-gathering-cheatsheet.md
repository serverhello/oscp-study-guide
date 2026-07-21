# Information Gathering Cheat Sheet (PEN-200, Ch. 6)

## Pentest Lifecycle
1. Defining Scope
2. Information Gathering
3. Vulnerability Detection
4. Initial Foothold
5. Privilege Escalation
6. Lateral Movement
7. Reporting/Analysis
8. Lessons Learned/Remediation

Info gathering (enumeration) is **cyclic** — never stops after initial recon; repeat as new hosts/creds/services are discovered throughout the engagement.

- **Passive**: little/no direct interaction with target (or only "normal user" interaction, e.g. registering an account). Lower footprint.
- **Active**: direct interaction with target infra (scanning, enumeration). Bigger footprint / more detectable.

---

## 6.2 Passive Information Gathering

### Whois enumeration
TCP port 43. Query public registrar databases for domain records.

```bash
whois megacorpone.com -h 192.168.50.251        # forward lookup
whois 38.100.193.70 -h 192.168.50.251           # reverse lookup (IP -> org)
```

Useful fields: Registrant, Admin Contact, Tech Contact, Name Servers, Creation/Expiry dates, Domain Status.

### Google Hacking (Dorks)
Operators (combine to narrow results):

| Operator | Purpose |
|---|---|
| `site:` | limit to a domain |
| `filetype:` / `ext:` | limit to file type |
| `-filetype:html` | exclude a file type |
| `intitle:"index of"` | find open directory listings |
| `inurl:` | keyword in URL (admin, login, upload, etc.) |
| `related:` | find similar sites |
| `cache:` | view cached version of a page |

Examples:
```
site:megacorpone.com filetype:txt
site:megacorpone.com -filetype:html
site:megacorpone.com intitle:"index of"
```
Also check the **Google Hacking Database (GHDB)** and **DorkSearch** for pre-built dorks.

### Netcraft
Third-party site — DNS search (subdomain discovery), Site Report (registration info, **site technology / tech stack**, hosting history).

### Code repositories (OSINT)
Search GitHub / GitHub Gist / GitLab / SourceForge for accidentally committed secrets.
- GitHub search supports operators, e.g. `path:users` to find files with "users" in the filename.
- Automate large repos with **Gitrob** or **Gitleaks** (regex + entropy-based secret detection — high-entropy strings often = keys/passwords/tokens).

### Shodan
Search engine for internet-connected devices (not just web content) — servers, routers, IoT. Register a free account.
- `hostname:megacorpone.com` — find hosts/services (e.g. exact OpenSSH version) tied to a domain.
- Click an IP for a full host summary (banners, open ports, vulns).

### Security posture check sites (passive/active gray area — third party runs the scan)
- **Security Headers** (securityheaders.com) — checks HTTP response headers (CSP, X-Frame-Options, etc.) → indicates server-hardening maturity.
- **Qualys SSL Labs (SSL Server Test)** — analyzes SSL/TLS config, flags legacy protocols (TLS 1.0/1.1), weak ciphers, and known vulns (POODLE, Heartbleed).

### LLMs for passive info gathering
LLMs are good at synthesizing unstructured text (social media, corporate policy references, employee posts) at scale. Useful prompts:
- `whois <domain>` (forces the LLM to run a live query rather than answer from stale training data)
- "Print out all public info about company structure and employees of `<company>`" → org chart, emails, socials
- "Give me the top 20 Google dorks for `<domain>`" (LLM won't run dorks itself, but will generate a tailored list)
- "What is the website technology stack of `<domain>`?" (may hallucinate/simulate Netcraft-style data — verify)

**Caveats:** hallucination/outdated info, needs cross-verification, avoid leaking sensitive/scope data into cloud LLMs, check engagement scope allows LLM use, mind bias/compliance requirements.

---

## 6.4 Active Information Gathering

> Port scanning may be illegal without written authorization — stay in scope.

### DNS record types
| Record | Purpose |
|---|---|
| NS | authoritative nameservers |
| A | IPv4 address |
| AAAA | IPv6 address |
| MX | mail server(s), with priority |
| PTR | reverse lookup (IP → hostname) |
| CNAME | alias |
| TXT | arbitrary text (SPF, domain verification, etc.) |

### DNS enumeration — Linux
```bash
host www.megacorpone.com                 # A record
host -t mx megacorpone.com               # MX records
host -t txt megacorpone.com              # TXT records
host idontexist.megacorpone.com          # NXDOMAIN = doesn't exist

# forward brute force with a wordlist
for ip in $(cat list.txt); do host $ip.megacorpone.com; done

# reverse brute force over an IP range
for ip in $(seq 64 79); do host 167.114.21.$ip; done | grep -Ev "not found|timed out"

# automated tools
dnsrecon -d megacorpone.com -t std                  # standard scan (NS, SOA, MX, TXT, zone transfer attempt)
dnsrecon -d megacorpone.com -D ~/list.txt -t brt     # brute force with wordlist
dnsenum megacorpone.com                              # also attempts zone transfer, shows netranges
```
SecLists wordlists: `sudo apt install seclists` → `/usr/share/seclists`.

### DNS enumeration — Windows / LOLBAS
```powershell
nslookup mail.megacorptwo.com                          # default DNS server, A record
nslookup -type=TXT info.megacorptwo.com 192.168.50.151 # specific record/server
```
LOLBAS/LOLBins = trusted native OS binaries repurposed for enumeration/post-exploitation (`whoami.exe`, `ping.exe`, `netstat.exe`, `nslookup`, `net`).

### Port scanning theory
- **TCP connect scan**: full 3-way handshake (SYN → SYN/ACK → ACK). Reliable but noisy/logged.
- **TCP SYN ("stealth") scan**: sends SYN only, reads SYN/ACK, never completes handshake → not logged at app layer, faster. Default nmap scan when run as root/raw-socket-capable.
- **UDP scan**: stateless, no handshake. Open port often gives *no response*; closed port → ICMP port-unreachable. Ambiguous behind a firewall (silently-dropped ⇒ looks "open").

Netcat as a crude scanner:
```bash
nc -nvv -w 1 -z 192.168.50.152 3388-3390     # TCP scan (-z = zero I/O, -w = timeout)
nc -nv -u -z -w 1 192.168.50.149 120-123     # UDP scan (-u)
```

### Nmap
Needs raw sockets (root/sudo) for SYN scans/OS detection; default scan = top 1000 TCP ports.

```bash
nmap 192.168.50.149                          # top 1000 TCP ports
nmap -p 1-65535 192.168.50.149               # all TCP ports (generates much more traffic)
sudo nmap -sS 192.168.50.149                 # SYN/stealth scan
sudo nmap -sT 192.168.50.149                 # TCP connect scan (needed via proxy/no raw sockets)
sudo nmap -sU 192.168.50.149                 # UDP scan
sudo nmap -sU -sS 192.168.50.149             # combined UDP + SYN

# host discovery / sweeping
nmap -sn 192.168.50.1-253                    # ping sweep (ICMP + SYN:443 + ACK:80 + ICMP timestamp)
nmap -PN <range>                             # skip host discovery, treat all as up
nmap -p 80 192.168.50.1-253 -oG web-sweep.txt
grep open web-sweep.txt | cut -d" " -f2

# top ports & aggressive detection
nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt

# OS fingerprinting
sudo nmap -O --osscan-guess 192.168.50.151

# service/banner detection
nmap -sV 192.168.50.14          # service/version only
nmap -sT -A 192.168.50.14       # OS detect + version + scripts + traceroute

# NSE scripts
nmap --script http-headers 192.168.50.6
nmap --script-help http-headers
ls -1 /usr/share/nmap/scripts/smb*
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
```

Traffic cost note: default top-1000 scan ≈ tens of KB per host; full 65535-port scan ≈ several MB per host — matters at class B/A scale or slow links. Modern fast scanners (MASSCAN, RustScan) are faster but noisier/burstier; nmap rate-limits and is comparatively more covert.

`-Pn` disables host discovery (treats all hosts as online) — useful when ICMP is blocked.

### Port scanning — Windows / LOLBAS (no Kali available)
```powershell
Test-NetConnection -Port 445 192.168.50.151

# quick port sweep 1-1024
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

### SMB enumeration
- SMB = TCP/445. NetBIOS (legacy, still often paired with SMB) = TCP/139 + UDP/137,138.

```bash
nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
sudo nbtscan -r 192.168.50.0/24                       # NetBIOS names (-r = source UDP/137)

# NSE SMB scripts live in /usr/share/nmap/scripts/smb*
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
```
(Also: `smb-enum-shares`, `smb-enum-users`, `smb-enum-domains`, `smb-enum-sessions`, `smb-brute`, `smb-double-pulsar-backdoor`, etc.)

Windows-native:
```cmd
net view \\dc01 /all      :: list shares incl. admin shares (ending in $)
```

### SMTP enumeration
`VRFY <user>` and `EXPN <list>` can leak valid usernames.

```bash
nc -nv 192.168.50.8 25
VRFY root        # 252 = likely valid (accepted, doesn't confirm delivery)
VRFY idontexist  # 550 = user unknown
```
Automate with a small Python socket script sending `VRFY <user>\r\n` and checking the response code (per-user loop).

Windows (no nc/python):
```powershell
Test-NetConnection -Port 25 192.168.50.8
dism /online /Enable-Feature /FeatureName:TelnetClient   # requires admin; or copy telnet.exe from another host
telnet 192.168.50.8 25
```

### SNMP enumeration
- UDP/161, stateless → spoofable/replayable. v1/v2/2c = **no encryption**, weak/default community strings (`public`, `private`, `manager`). v3 adds auth+encryption (older impls only DES-56; modern support AES-256).
- MIB = tree-structured DB of OIDs; useful Windows OIDs:

| OID | Data |
|---|---|
| `1.3.6.1.2.1.25.1.6.0` | System Processes |
| `1.3.6.1.2.1.25.4.2.1.2` | Running Programs |
| `1.3.6.1.2.1.25.4.2.1.4` | Processes Path |
| `1.3.6.1.2.1.25.2.3.1.4` | Storage Units |
| `1.3.6.1.2.1.25.6.3.1.2` | Installed Software |
| `1.3.6.1.4.1.77.1.2.25` | User Accounts |
| `1.3.6.1.2.1.6.13.1.3` | TCP Local Ports |

```bash
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt

# brute-force community strings across a range
echo public > community; echo private >> community; echo manager >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips

# walk MIB tree (community string usually "public")
snmpwalk -c public -v1 -t 10 192.168.50.151                            # entire tree
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25            # user accounts
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2           # running processes
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2           # installed software
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3             # listening TCP ports
```

### LLM-aided active enumeration
LLMs can't run live DNS queries/dorks themselves, but are strong at generating **tailored wordlists** for brute-forcing (subdomains, directories) based on public/inferred org context (industry, products, departments, regions).

```bash
sudo apt install gobuster
gobuster dns -d megacorpone.com -w wordlist.txt -t 10    # -w = LLM-generated wordlist, -t = threads
```
(Newer gobuster versions may use `--domain` instead of `-d`; check `--help`.)

Same caveats as passive LLM use: validate output, cross-check against real tools, mind scope/data-sharing.

---

## Quick Recon Workflow Summary
1. **Scope** confirmed → start **passive**: Whois (fwd+rev), Google dorks/GHDB, Netcraft, code repos (Gitleaks/Gitrob), Shodan, header/TLS scanners, LLM OSINT.
2. Move to **active**: DNS enum (host/nslookup → dnsrecon/dnsenum brute force → note IP ranges) → Nmap sweep (ping sweep → top ports → full port scan on interesting hosts) → OS/service fingerprinting (`-O`, `-sV`, `-A`, NSE scripts).
3. Protocol-specific deep dives as discovered: **SMB** (shares/users/OS via nmap NSE, nbtscan, `net view`), **SMTP** (VRFY/EXPN user enum), **SNMP** (community string brute force + MIB walk for users/processes/software/ports).
4. Feed every new hostname/IP/user/tech back into step 1–3 — **enumeration is cyclic**.
5. On Windows-only footholds, fall back to **LOLBAS**: `nslookup`, `net view`, `Test-NetConnection`, PowerShell TCP-socket loops, Telnet client.
