# TCP/IP Crash Course

A practical rundown of how TCP/IP works, with a byte-by-byte trace of a real HTTP request as the centerpiece.

------

## The Four Layers

TCP/IP is organized into four layers, each with a specific job. Each layer wraps the one above it with its own header, and the receiver unwraps them in reverse.

### Link layer

Handles the physical network — Ethernet, WiFi, MAC addresses. Moves bits between devices on the same network segment.

### Internet layer (IP)

Handles addressing and routing. Every device gets an IP address (e.g., 192.168.1.10 for IPv4, 2001:db8::1 for IPv6). IP's job is to get packets from source to destination across networks, but it's unreliable — packets can be lost, duplicated, or arrive out of order. Routers forward packets based on destination IP.

### Transport layer

Where TCP and UDP live.

- **TCP**: reliable, ordered, connection-based delivery. Three-way handshake (SYN, SYN-ACK, ACK), byte numbering, acknowledgments, retransmission, flow/congestion control.
- **UDP**: fire-and-forget. No handshake, no guarantees, much lower overhead.

Use TCP for HTTP, SSH, databases. Use UDP for DNS, video streaming, gaming.

### Application layer

Your protocols — HTTP, DNS, SMTP, gRPC. These ride on top of TCP or UDP.

### Key concepts

- **Ports** (0–65535) let one machine run many services — port 443 for HTTPS, 22 for SSH.
- **Socket** = IP + port pair.
- **NAT** lets many private IPs share one public IP by rewriting addresses at your router.
- **DNS** translates names to IPs.
- **MTU** is the max packet size on a link (typically 1500 bytes on Ethernet); bigger payloads get fragmented.

When you load a webpage: DNS resolves the name → TCP handshake to port 443 → TLS handshake → HTTP request/response → TCP connection closes.

------

## The Transport Layer in Depth

### TCP

**Connection establishment (three-way handshake):** Client sends SYN with an initial sequence number (ISN). Server replies SYN-ACK with its own ISN plus ack of client's ISN+1. Client sends ACK. Both sides have agreed on starting sequence numbers.

**Reliable delivery:** Every byte gets a sequence number. The receiver sends ACKs saying "I've got everything up to byte N." If the sender doesn't see an ACK within the retransmission timeout (RTO, calculated from round-trip time), it retransmits. Modern TCP uses *selective acknowledgment* (SACK) so receivers can say "I got bytes 1000-2000 and 3000-4000 but not 2000-3000."

**Flow control (receiver protection):** The receiver advertises a *window* — how many bytes it can buffer. Sender never sends more unacked data than the window allows. Prevents a fast sender from overwhelming a slow receiver.

**Congestion control (network protection):** Separate from flow control. Sender maintains a *congestion window* (cwnd) that grows and shrinks based on network feedback.

- **Slow start**: cwnd doubles each RTT until it hits a threshold.
- **Congestion avoidance**: cwnd grows linearly after threshold.
- **Fast retransmit/recovery**: three duplicate ACKs signal loss, cwnd halves.
- Modern Linux defaults to **CUBIC**; Google's **BBR** models bandwidth and RTT directly instead of treating loss as the only congestion signal.

**Connection teardown:** Four-way via FIN/ACK in each direction (connections are full-duplex, so each side closes independently). The TIME_WAIT state keeps the socket around for 2×MSL to catch stragglers.

**TCP state machine:** LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT_1/2, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSED. Visible in `netstat` or `ss`.

**Head-of-line blocking:** TCP delivers bytes in order, so one lost packet stalls everything behind it. This is a real problem for HTTP/2 which multiplexes streams over one connection — hence QUIC/HTTP/3 moving to UDP.

### UDP

Basically just IP plus ports and a checksum. No connection, no ordering, no retransmission, no congestion control. 8-byte header versus TCP's 20+ bytes. The application handles whatever reliability it needs.

Good for: DNS, real-time media, VPN tunnels, QUIC.

### QUIC

Built on UDP but provides TCP-like reliability plus TLS 1.3, all in one protocol. Streams are independent so one lost packet doesn't block others. Connection migration survives IP changes (WiFi to cellular). Powers HTTP/3.

------

## How TCP and IP Work Together

**IP delivers packets between machines. TCP delivers a reliable byte stream between applications.**

Think of IP like the postal service. It takes an envelope and routes it from your house to some address across the country. Each envelope is independent — some might get lost, arrive out of order, or be duplicated. IP's job ends the moment a packet arrives at the destination machine's network interface.

TCP runs *on top of* IP, on the two endpoint machines only — not on the routers in between. When your app calls `send()` on a TCP socket, TCP chops your data into segments, wraps each one in a TCP header, and hands each segment to IP. IP wraps it in its own header and ships it. **Routers in between only look at the IP header** — they don't even know TCP exists.

On the receiving machine, IP strips its header and hands the segment up to TCP. TCP reassembles segments in order, throws away duplicates, asks for retransmission of missing ones, and only then hands a clean, ordered byte stream to the receiving application.

The two layers answer different questions:

- **IP answers:** "Which machine, and how do I route one packet there?" Addressing and hop-by-hop forwarding.
- **TCP answers:** "Did all the bytes arrive, in order, without duplicates, to the right application on that machine?" Reliability and ordering, end-to-end.

A useful reframe: **IP is best-effort per-packet. TCP is guaranteed per-stream.** TCP builds the illusion of a reliable pipe out of IP's unreliable packet-tossing.

------

## Byte-by-Byte Example: An HTTP Request

Your browser sends `GET /\r\n\r\n` (6 bytes) to a web server at 93.184.216.34 on port 80. Your machine is 192.168.1.50, using ephemeral port 54321.

### Step 1: Application hands bytes to TCP

Your browser calls `send(socket, "GET /\r\n\r\n", 6)`. TCP now has 6 bytes of payload to deliver.

### Step 2: TCP builds a segment

TCP wraps those 6 bytes with a 20-byte header:

```
Source port:      54321
Dest port:        80
Sequence number:  1000  (connection already established)
Ack number:       5000  (acking server's last byte)
Flags:            PSH, ACK
Window:           64240
Checksum:         (computed)
[Payload: "GET /\r\n\r\n"]
```

Total TCP segment: 26 bytes. TCP hands this down to IP with the instruction "send to 93.184.216.34."

### Step 3: IP builds a packet

IP wraps the 26-byte TCP segment in a 20-byte IP header:

```
Version:     4
Protocol:    6  (meaning "TCP is inside")
Source IP:   192.168.1.50
Dest IP:     93.184.216.34
TTL:         64
Checksum:    (computed)
[Payload: the entire 26-byte TCP segment]
```

Total IP packet: 46 bytes. IP consults the routing table — destination isn't local, so send to the default gateway (your router at 192.168.1.1). IP asks the link layer "get this to 192.168.1.1."

### Step 4: Link layer wraps it again

Ethernet adds its own header with MAC addresses (your NIC's MAC → your router's MAC) and ships the frame out the wire.

**Key insight:** Ethernet uses MAC addresses for the *next hop only*, while the IP header still says the final destination is 93.184.216.34.

### Step 5: The router

Your router receives the frame, strips the Ethernet header, looks at the IP header, sees destination 93.184.216.34, decrements TTL, does NAT (rewrites source IP from 192.168.1.50 to your public IP and possibly rewrites the source port), recomputes checksums, wraps it in a *new* Ethernet frame addressed to the next router, and forwards it.

**The router never looks at the TCP header.** It doesn't know or care that there's a GET request inside.

This repeats across every router between you and the server — maybe 10–15 hops. Each hop: strip link header, inspect IP, decrement TTL, re-wrap, forward. The TCP segment inside is untouched.

### Step 6: Arrival at the server

The server's NIC receives an Ethernet frame. Link layer strips the Ethernet header and hands the IP packet up. IP looks at the header: "dest is me, protocol field says 6, so this is TCP" — strips its own header and hands the 26-byte TCP segment up to the TCP stack.

### Step 7: TCP processing on the server

TCP looks at the segment:

- Dest port 80 → find the socket listening there (the web server process)
- Sequence number 1000 → "is this the next byte I'm expecting?" Yes → accept it
- Verify checksum
- Send an ACK back saying "I've got everything up to byte 1006"
- Strip the TCP header
- Hand the 6 bytes of payload to the web server application via its socket

### Step 8: Application reads

The web server calls `recv(socket, buffer, ...)` and gets `"GET /\r\n\r\n"`. It has no idea how many packets it took, what path they traveled, or that one might have been retransmitted. It just sees clean bytes.

### The key observation

Each layer wrapped the one above it, and each layer on the receiving side only looked at its own header:

```
[Ethernet [IP [TCP [GET /\r\n\r\n]]]]
```

- Routers read only the IP header
- The server's IP stack read only the IP header, then handed payload to TCP
- TCP read only the TCP header, then handed payload to the app
- The app read only its own data

If the network had dropped this packet, TCP on your side would notice the missing ACK after the RTO and retransmit the *exact same segment* — IP would route it again, possibly via a different path. The app still sees a clean 6-byte stream on the other end.

------

## How Routers Choose the Next Hop

Routers decide the next hop using a **routing table** — a lookup table that maps destination network prefixes to the next-hop router and outgoing interface.

### The routing table

A simplified entry:

```
Destination         Next hop         Interface
0.0.0.0/0           192.168.1.1      eth0      (default route)
192.168.1.0/24      (direct)         eth0
10.0.0.0/8          10.5.1.1         eth1
```

The `/24` is a CIDR prefix — "the first 24 bits are the network part." So `192.168.1.0/24` covers 192.168.1.0 through 192.168.1.255.

When a packet arrives, the router finds the **most specific matching prefix** (longest prefix match). If a packet is destined for 10.5.1.47, and the table has both `10.0.0.0/8` and `10.5.0.0/16`, the /16 wins because it's more specific.

If nothing matches, the default route (`0.0.0.0/0`) catches everything.

### How entries get there

**Static routes** are manually configured. Your laptop's routing table is mostly static — "local subnet is direct, everything else goes to the gateway I learned via DHCP."

**Dynamic routing protocols** are how the internet scales:

- **BGP (Border Gateway Protocol)** runs the internet between organizations. Every ISP, cloud provider, and large network is an *Autonomous System* (AS) with a number. BGP routers announce "I can reach these prefixes" to their neighbors, along with the AS path. BGP is policy-driven — networks choose routes based on business relationships, not just path length.
- **OSPF and IS-IS** run *inside* a single organization (an "interior gateway protocol"). They flood link-state information so every router builds a complete map of the internal topology, then run Dijkstra to compute shortest paths.
- **EIGRP** is Cisco's proprietary interior protocol, still common in enterprise networks.

### The practical picture

For your HTTP request leaving your house:

1. **Your laptop**: routing table says "not local, send to 192.168.1.1."
2. **Your home router**: "not local, send to ISP's gateway" (learned via DHCP).
3. **ISP edge router**: consults a BGP-learned table with ~950,000 entries covering the whole internet. Finds the longest prefix match for 93.184.216.34 — maybe `93.184.216.0/22` learned from a peer AS. Forwards accordingly.
4. **Intermediate backbone routers**: each one does its own longest-prefix-match lookup against its BGP table.
5. **Destination AS's router**: prefix is now local, hands off to interior routing (OSPF/IS-IS) to reach the specific server.

Each router makes an **independent decision** based on its own table. There's no end-to-end path planning — it's hop-by-hop. This is why packets in the same TCP connection can take different paths, and why the internet keeps working when links fail.

### One nuance

Routers don't store individual IPs — they store *prefixes*. The entire internet's ~47 billion IPv4 addresses compress down to roughly 950,000 BGP routes because addresses are allocated in blocks. This aggregation is what makes global routing tractable.

The fundamental trick: each router only needs to know "which direction is closer to the destination," not the full path. As long as every router along the way makes a locally-correct choice, the packet gets there.

------

## Summary: The Layer Separation

| Layer                | Responsible for                        | Reads           |
| -------------------- | -------------------------------------- | --------------- |
| Application          | The actual data/protocol (HTTP, etc.)  | Its own payload |
| Transport (TCP/UDP)  | Reliable delivery between applications | TCP/UDP header  |
| Internet (IP)        | Routing packets between machines       | IP header       |
| Link (Ethernet/WiFi) | One hop across a physical medium       | Link header     |

Each layer is genuinely independent — it only trusts its own header and treats everything above as opaque payload. This is why you can swap Ethernet for WiFi without TCP noticing, why a bug in your HTTP layer doesn't affect IP routing, and why the internet can evolve one layer at a time.

## Further Reading

- [A TCP/IP Tutorial (RFC 1180)](https://datatracker.ietf.org/doc/html/rfc1180)

- [Transmission Control Protocol (RFC 9293)](https://www.rfc-editor.org/rfc/rfc9293.html)

- [What is the Internet Protocol](https://www.cloudflare.com/learning/network-layer/internet-protocol/)

  