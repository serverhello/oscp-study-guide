# DNS Crash Course

A practical rundown of how DNS works, with a byte-by-byte trace of a real lookup as the centerpiece.

------

## What DNS Is

DNS (Domain Name System) translates human-readable names like `www.example.com` into IP addresses like `93.184.216.34`. It's the internet's phone book — but it's also much more: a globally distributed, hierarchical, cached database that every internet interaction depends on.

Without DNS, you'd need to memorize IPs for every service you use, and those IPs couldn't change without breaking everything. DNS decouples *names* (stable, human-friendly) from *addresses* (which can change freely).

It runs primarily on UDP port 53, with TCP port 53 as a fallback for large responses and zone transfers. Modern variants (DoT, DoH, DoQ) add encryption on top.

------

## The Hierarchy

DNS is a tree, read right-to-left:

```
                        . (root)
                        |
        +---------------+---------------+
        |               |               |
       com             org              ie       (TLDs)
        |               |               |
      example        wikipedia        revenue    (second-level)
        |
       www                                      (subdomain)
```

Reading `www.example.com.` right-to-left:

- `.` — the root
- `com` — top-level domain (TLD)
- `example` — second-level domain (the registered part)
- `www` — a subdomain of example.com

The trailing dot on `www.example.com.` is technically always there — it represents the root. Browsers hide it.

### Who runs each level

- **Root** (`.`): 13 logical root server "letters" (A through M), each actually a globally distributed Anycast cluster. Operated by organizations like Verisign, ICANN, NASA, and various universities.
- **TLDs** (`com`, `org`, `ie`, `uk`, etc.): run by registries. Verisign runs `.com`. IEDR runs `.ie`.
- **Second-level domains**: run by whoever registered them — you, your company, or their DNS provider (Cloudflare, Route 53, Azure DNS, etc.).

Each level only knows about the level directly below it. The root doesn't know about `example.com` — it only knows "ask the `.com` servers." The `.com` servers don't know about `www.example.com` — they only know "ask example.com's nameservers."

------

## Record Types

DNS stores different kinds of information in "records." The common ones:

| Type      | Purpose                                                  |
| --------- | -------------------------------------------------------- |
| **A**     | IPv4 address                                             |
| **AAAA**  | IPv6 address (called "quad-A")                           |
| **CNAME** | Alias — "this name is really that name, go look it up"   |
| **MX**    | Mail server for a domain                                 |
| **NS**    | Which nameservers are authoritative for this zone        |
| **TXT**   | Arbitrary text — used for SPF, DKIM, domain verification |
| **SOA**   | Start of Authority — metadata about the zone             |
| **PTR**   | Reverse lookup (IP → name)                               |
| **SRV**   | Service location (used by SIP, XMPP, Active Directory)   |
| **CAA**   | Which CAs are allowed to issue certs for this domain     |

Each record has a **TTL** (time-to-live) in seconds, telling resolvers how long they can cache it.

------

## The Players in a Lookup

Four kinds of DNS servers participate in a typical query:

**Stub resolver**: the tiny DNS client built into your OS. Your browser asks it "what's the IP for example.com?" It doesn't do much — just forwards the query to a recursive resolver.

**Recursive resolver** (aka recursor, caching resolver): does the real work. It queries the hierarchy on your behalf, caches results, and returns the final answer. Usually run by your ISP, or public ones like 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), or 9.9.9.9 (Quad9).

**Root servers**: tell you which TLD server to ask.

**TLD servers**: tell you which authoritative nameserver to ask.

**Authoritative nameservers**: the source of truth for a specific domain. They hold the actual records.

The distinction that trips people up: *recursive* resolvers do the walking; *authoritative* servers just answer for the zones they're responsible for. An authoritative server won't chase referrals for you — it only answers about its own zones.

------

## How a Full Lookup Works

You type `www.example.com` into your browser. Here's what happens before the TCP connection from the previous rundown even starts:

1. **Browser cache check**: browsers cache DNS results themselves for a short time.
2. **OS cache check**: the stub resolver checks the OS-level cache.
3. **Hosts file check**: `/etc/hosts` on Linux/macOS, `C:\Windows\System32\drivers\etc\hosts` on Windows. Static overrides.
4. **Query to recursive resolver**: stub resolver sends a UDP packet to the configured resolver (learned via DHCP, or set manually to 1.1.1.1 etc.).
5. **Resolver cache check**: if the resolver has cached this recently, it returns immediately.
6. **Recursive walk** (if nothing cached):
   - Resolver asks a root server: "where's `.com`?"
   - Root replies with NS records for `.com` TLD servers.
   - Resolver asks a `.com` TLD server: "where's `example.com`?"
   - TLD replies with NS records for example.com's authoritative servers.
   - Resolver asks an authoritative server: "what's the A record for `www.example.com`?"
   - Authoritative server replies with the answer.
7. **Resolver caches** the answer (respecting TTL) and returns it to your stub resolver.
8. **Stub resolver caches** locally and hands the IP to your browser.
9. **Browser opens a TCP connection** to that IP.

In practice, step 6 rarely runs in full — the resolver has `.com`'s nameservers cached for days, and often has example.com's nameservers cached too. Usually only the final authoritative query is actually made over the wire.

------

## Byte-by-Byte Example: A DNS Lookup

Your machine (192.168.1.50) looks up `www.example.com` via resolver 1.1.1.1. Let's trace the UDP packet.

### Step 1: Application triggers a lookup

Your browser calls `getaddrinfo("www.example.com", ...)`. The stub resolver constructs a DNS query message.

### Step 2: DNS query message

DNS messages have a fixed 12-byte header followed by variable-length sections (Question, Answer, Authority, Additional).

**Header (12 bytes):**

```
Transaction ID:   0x1A2B         (random; matches response to query)
Flags:            0x0100         (standard query, recursion desired)
Questions:        1
Answer RRs:       0
Authority RRs:    0
Additional RRs:   0
```

**Question section:**

Domain names are encoded as length-prefixed labels ending with a zero byte. `www.example.com` becomes:

```
03 'w' 'w' 'w'              (length 3, "www")
07 'e' 'x' 'a' 'm' 'p' 'l' 'e'   (length 7, "example")
03 'c' 'o' 'm'              (length 3, "com")
00                          (root label, terminator)
```

Then:

```
QTYPE:   0x0001   (A record — IPv4)
QCLASS:  0x0001   (IN — internet)
```

Total DNS message: 12-byte header + 17 bytes for the name + 4 bytes for type/class = **33 bytes**.

### Step 3: UDP wraps the DNS message

UDP adds an 8-byte header:

```
Source port:      51234        (ephemeral)
Dest port:        53           (DNS)
Length:           41           (8 header + 33 payload)
Checksum:         (computed)
[Payload: the 33-byte DNS message]
```

Total UDP datagram: 41 bytes.

### Step 4: IP and Ethernet wrap it

IP adds its 20-byte header (source 192.168.1.50, dest 1.1.1.1, protocol 17 meaning UDP). Ethernet adds its header with MAC addresses for the next hop. The packet is routed to 1.1.1.1 exactly like the TCP packet in the previous rundown — hop by hop, routers only reading the IP header.

**Key difference from TCP**: there's no handshake. This single UDP datagram *is* the entire outbound interaction. If it gets lost, there's no automatic retransmission at the transport layer — the stub resolver is responsible for retrying.

### Step 5: Resolver receives and processes

1.1.1.1's UDP stack delivers the 33-byte DNS payload to the resolver process listening on port 53. The resolver:

1. Parses the header, notes Transaction ID `0x1A2B`.
2. Parses the question: "A record for www.example.com, class IN."
3. **Checks its cache.** If a fresh answer exists (TTL not expired), skip to step 8.
4. If not cached, starts the recursive walk.

### Step 6: The recursive walk (cache miss path)

The resolver queries the hierarchy. Each of these is its own UDP exchange on port 53:

**Query 1 — to a root server (e.g., a.root-servers.net, 198.41.0.4):** "A record for www.example.com?"

Root replies with a **referral** — no answer, but authority and additional sections pointing to `.com` nameservers:

```
Authority:
  com. NS a.gtld-servers.net.
  com. NS b.gtld-servers.net.
  ...
Additional:
  a.gtld-servers.net. A 192.5.6.30
  b.gtld-servers.net. A 192.33.14.30
  ...
```

The additional section is called **glue** — it gives the IPs directly so the resolver doesn't have to do another lookup to find the TLD servers.

**Query 2 — to a `.com` TLD server (192.5.6.30):** "A record for www.example.com?"

TLD replies with another referral:

```
Authority:
  example.com. NS a.iana-servers.net.
  example.com. NS b.iana-servers.net.
Additional:
  a.iana-servers.net. A 199.43.135.53
  b.iana-servers.net. A 199.43.133.53
```

**Query 3 — to example.com's authoritative server (199.43.135.53):** "A record for www.example.com?"

Authoritative server replies with the actual answer:

```
Answer:
  www.example.com. 86400 IN A 93.184.216.34
```

The `86400` is the TTL in seconds (24 hours). The resolver can cache this answer for that long.

### Step 7: Resolver caches everything

The resolver stashes not just the final answer but also the NS records for `.com` and for `example.com`, along with their glue. Next time someone asks for anything under `.com`, it skips the root query. Next time someone asks for anything under `example.com`, it skips both the root and TLD queries.

This caching is why DNS scales. The root servers aren't answering 40 billion queries a day per user — they're mostly answering resolvers whose caches have expired.

### Step 8: Resolver responds to your stub

The resolver builds a DNS response message back to your machine. Same 12-byte header format:

```
Transaction ID:   0x1A2B         (matches your query)
Flags:            0x8180         (response, recursion available, no error)
Questions:        1
Answer RRs:       1
Authority RRs:    0
Additional RRs:   0
```

**Question section** (echoed back):

```
03 'w' 'w' 'w' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
QTYPE:  0x0001
QCLASS: 0x0001
```

**Answer section:**

```
Name:    0xC00C            (compression pointer — see below)
Type:    0x0001            (A)
Class:   0x0001            (IN)
TTL:     0x00015180        (86400 seconds)
RDLENGTH: 0x0004           (4 bytes of data)
RDATA:   5D B8 D8 22       (93.184.216.34)
```

### DNS name compression

That `0xC00C` is worth a moment. DNS messages often repeat names (the question name appears again in the answer), which wastes bytes. DNS uses **pointer compression**: any byte starting with bits `11` is a pointer to an offset earlier in the message.

`0xC00C` = `11000000 00001100` — pointer flag plus offset `0x0C` (12), which is right after the DNS header, where the question name starts. So instead of re-encoding `www.example.com`, the answer just says "the name here is the same as the name at offset 12."

Without compression the answer would repeat all 17 bytes of the name. Compression keeps DNS messages small — important because UDP has size constraints (traditionally 512 bytes, now usually 4096 with EDNS).

### Step 9: Stub resolver hands IP to application

Your stub resolver parses the response, matches Transaction ID `0x1A2B` to the outstanding query, extracts `93.184.216.34`, caches it for 86400 seconds, and returns it to your browser. Your browser can now open a TCP connection.

### The full picture

```
[Ethernet [IP [UDP [DNS header + question + answer]]]]
```

Compared to the TCP example:

- **Transport is UDP, not TCP.** One packet out, one packet back. No handshake, no retransmission at transport level.
- **The resolver does the hard work.** Your stub resolver sends one query and gets one answer. The resolver possibly sent three queries to walk the hierarchy — or zero if everything was cached.
- **The message format is DNS-specific.** Unlike HTTP which is text, DNS is a compact binary format with its own name-compression scheme.

------

## Caching and TTLs

Caching is the load-bearing feature that makes DNS work at internet scale. Every level caches:

- **Authoritative server** sets a TTL on each record.
- **Recursive resolver** caches the answer for up to that TTL.
- **OS stub resolver** caches briefly.
- **Applications/browsers** may cache too (often ignoring the TTL).

### TTL tradeoffs

- **High TTL** (hours/days): great for performance, terrible for agility. If you need to change an IP, the old value lingers in caches worldwide.
- **Low TTL** (minutes): fast to change, but more load on authoritative servers and slower lookups on cache misses.

Typical choices: 3600 (1 hour) for stable records, 300 (5 minutes) during planned migrations, 60 for very dynamic setups.

### Negative caching

If a name *doesn't exist* (NXDOMAIN response), resolvers cache that fact too. The SOA record's minimum TTL controls how long. This prevents repeated queries for names that fail.

### The cache poisoning concern

If an attacker can inject a forged response matching the Transaction ID and question before the real response arrives, the resolver caches the forged data — potentially redirecting traffic. Modern mitigations: random source ports (expands entropy from 16 bits to ~32 bits), 0x20 encoding (random case in query names, which must be echoed), and DNSSEC for cryptographic validation.

------

## DNSSEC

DNSSEC adds cryptographic signatures to DNS records so resolvers can verify they haven't been tampered with. Each zone signs its records with a private key; the public key is published in the parent zone (so `.com` signs a fingerprint of example.com's key, and the root signs `.com`'s key). This creates a chain of trust from the root down.

Adoption is uneven. Many TLDs are signed, but most second-level domains aren't. Resolvers that validate DNSSEC (like 1.1.1.1 and 8.8.8.8) will refuse to return tampered answers.

DNSSEC doesn't encrypt — anyone on the wire can still see your queries. That's what DoT/DoH/DoQ are for.

------

## Encrypted DNS

Traditional DNS over UDP/53 is plaintext. Anyone on the path can see every name you look up, and your ISP can log or modify answers. Three encrypted variants have emerged:

- **DoT (DNS over TLS)**: port 853, straightforward TLS wrapper around DNS. Used by system resolvers.
- **DoH (DNS over HTTPS)**: port 443, DNS queries inside HTTPS POSTs. Harder to block because it looks like regular web traffic. Used by browsers (Firefox, Chrome) and mobile OSes.
- **DoQ (DNS over QUIC)**: port 853 over QUIC. Lower latency than DoT, used with HTTP/3-era stacks.

All three encrypt the query between your device and the resolver. Your resolver still sees your queries — to hide them from the resolver itself you'd need something like Oblivious DoH.

------

## Common DNS Operations You'll Actually Do

### Looking things up

```bash
dig www.example.com              # A record, with full response
dig www.example.com +short       # just the answer
dig www.example.com AAAA         # IPv6
dig www.example.com MX           # mail servers
dig www.example.com @1.1.1.1     # ask a specific resolver
dig www.example.com +trace       # show the full recursive walk
nslookup www.example.com         # older, still works
host www.example.com             # simpler output
```

### Reverse lookups

```bash
dig -x 93.184.216.34
```

This queries the PTR record under the `in-addr.arpa` tree.

### Checking propagation

After changing a DNS record, query multiple resolvers to see if the change has propagated:

```bash
dig example.com @1.1.1.1
dig example.com @8.8.8.8
dig example.com @9.9.9.9
```

### Clearing caches

- macOS: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
- Windows: `ipconfig /flushdns`
- Linux (systemd-resolved): `sudo resolvectl flush-caches`
- Browser caches: often need a restart, or visit `chrome://net-internals/#dns`

------

## Summary

| Concept               | Key point                                                 |
| --------------------- | --------------------------------------------------------- |
| **Purpose**           | Translate names to IPs (and other data)                   |
| **Hierarchy**         | Root → TLD → domain → subdomain, read right-to-left       |
| **Transport**         | Mostly UDP/53, TCP/53 for large or zone transfers         |
| **Players**           | Stub resolver, recursive resolver, root/TLD/authoritative |
| **Records**           | A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA           |
| **Scaling mechanism** | Aggressive caching at every level, governed by TTLs       |
| **Security**          | DNSSEC for integrity, DoT/DoH/DoQ for privacy             |

The fundamental trick: no single server knows everything. The hierarchy distributes authority, the caching flattens load, and the recursive resolver hides all the complexity behind a simple "name in, IP out" interface.