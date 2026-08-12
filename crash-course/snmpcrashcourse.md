# SNMP Crash Course

A practical rundown of how SNMP works, with a byte-by-byte trace of a real query as the centerpiece.

------

## What SNMP Is

SNMP (Simple Network Management Protocol) lets a central system monitor and configure network devices — routers, switches, printers, UPS units, servers — without needing device-specific software for each one. A single "manager" application can ask hundreds of different devices from different vendors "what's your CPU load?" or "how many packets went out interface 3?" using one common protocol, because every device exposes its data through the same standardized structure.

It's deliberately simple (it's in the name): a handful of request types, a flat request/response exchange, and a tree-structured naming scheme for "everything a device might report." It's also stateless and connectionless — riding on UDP rather than TCP, since a management poll every few seconds doesn't need (and shouldn't pay for) TCP's connection overhead.

------

## Versions

| Version    | Introduced | Security model                                                        |
| ---------- | ---------- | ------------------------------------------------------------------------|
| **SNMPv1** | 1988       | **Community strings** only — a plaintext shared "password" sent with every request. No encryption, no per-user identity. |
| **SNMPv2c**| 1996       | Same community-string model as v1, but adds `GetBulkRequest` (fetch many values in one round trip) and richer error codes. The "c" stands for community-based — this is still the most commonly deployed version in the wild. |
| **SNMPv3** | 2002       | Replaces community strings with **USM** (User-based Security Model): per-user authentication (HMAC-MD5/SHA) and optional encryption ("privacy," DES or AES) of the whole PDU. |

Because v1/v2c authentication is just a string sent in the clear on every single packet, and devices frequently ship with default community strings (`public` for read-only, `private` for read-write), SNMP is one of the highest-value low-effort targets during enumeration — if it's exposed and using a default string, you get read (and sometimes write) access to a device's entire management data.

------

## Ports and Transport

- **UDP 161** — the agent listens here for requests from the manager (Get/GetNext/GetBulk/Set).
- **UDP 162** — the *manager* listens here for unsolicited **traps** pushed by agents (e.g., "interface down," "temperature threshold exceeded").

Like DNS, SNMP is a single-datagram request/response protocol with no handshake — if a packet is lost, the manager's SNMP library is responsible for timing out and retrying, not the transport layer.

------

## The Players

**Manager (NMS — Network Management Station)**: the monitoring system — Nagios, PRTG, SolarWinds, or a plain `snmpwalk` command line. Initiates requests and receives traps.

**Agent**: software running on the managed device that answers SNMP requests by reading local counters/state and translating them into the standard tree structure.

**MIB (Management Information Base)**: the schema — a tree-structured, hierarchical definition of every value an agent *can* report, with a human-readable name for each (`sysDescr`, `ifInOctets`, `hrProcessorLoad`). Vendors publish MIB files for their own devices' custom data.

**OID (Object Identifier)**: the actual dotted-number address of one specific value in that tree, e.g. `1.3.6.1.2.1.1.1.0`. MIB names are just human-friendly labels for OIDs — `sysDescr.0` and `1.3.6.1.2.1.1.1.0` refer to the exact same thing.

------

## The MIB Tree

Every OID is a path from the root of a single global tree, standardized by ISO/ITU so that no two organizations' object identifiers can collide:

```
                                   root
                                    |
                    +---------------+---------------+
                    |                                |
                 iso(1)                          ccitt(0)
                    |
                 org(3)
                    |
                 dod(6)
                    |
              internet(1)
        +-----------+-----------+-----------+
        |           |           |           |
   directory(1)   mgmt(2)   experimental(3) private(4)
                     |                          |
                  mib-2(1)                enterprise(1)
                     |                          |
          +----------+----------+       vendor-specific subtrees
          |          |          |       (e.g. 1.3.6.1.4.1.9 = Cisco)
       system(1)  interfaces(2) ...
          |
    sysDescr(1).0
```

Reading `1.3.6.1.2.1.1.1.0` left to right: `iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0` — a standard, vendor-neutral value every SNMP-speaking device must expose (a text description of the device). The `.0` at the end is the "instance" suffix required on scalar (single-value) objects; table entries instead end in an index (e.g., the interface number for `ifInOctets`).

Two branches matter most in practice:

- **`mib-2` (1.3.6.1.2.1)**: the standard objects every compliant agent implements — system info, interfaces, IP stats, TCP/UDP connection tables.
- **`enterprise` (1.3.6.1.4.1)**: where vendors hang their own proprietary data, keyed by a registered enterprise number (Cisco is 9, Microsoft is 311, and so on).

### Useful OIDs

| OID                              | Data                          |
| --------------------------------- | ------------------------------|
| `1.3.6.1.2.1.1.1.0`               | System description (`sysDescr`) |
| `1.3.6.1.2.1.25.1.6.0`            | System processes              |
| `1.3.6.1.2.1.25.4.2.1.2`          | Running programs               |
| `1.3.6.1.2.1.25.4.2.1.4`          | Process path                   |
| `1.3.6.1.2.1.25.2.3.1.4`          | Storage units                  |
| `1.3.6.1.2.1.25.6.3.1.2`          | Installed software             |
| `1.3.6.1.4.1.77.1.2.25`           | User accounts                  |
| `1.3.6.1.2.1.6.13.1.3`            | TCP local ports                |

------

## PDU Types

| PDU               | Direction        | Purpose                                                     |
| ------------------ | ---------------- | -------------------------------------------------------------|
| `GetRequest`       | Manager → Agent  | Fetch the value of one or more specific OIDs                 |
| `GetNextRequest`   | Manager → Agent  | Fetch the *next* OID after the one given — how you "walk" a tree without knowing its shape in advance |
| `GetBulkRequest`   | Manager → Agent  | (v2c/v3 only) Fetch many consecutive OIDs in one round trip — an efficient bulk version of repeated GetNext |
| `SetRequest`       | Manager → Agent  | Write a new value to a writable OID                          |
| `Response`         | Agent → Manager  | Answer to any of the above                                    |
| `Trap` / `SNMPv2-Trap` | Agent → Manager | Unsolicited notification of an event, sent to UDP 162, no response expected |
| `InformRequest`    | Agent → Manager  | Like a trap, but the manager must acknowledge it (reliable notification) |

`snmpwalk` is just a loop of `GetNextRequest` (or `GetBulkRequest` on v2c+) calls, each one starting from the OID returned by the previous response, stopping once the returned OID falls outside the requested subtree.

------

## How an SNMP Query Works

1. Manager builds a `GetRequest` PDU naming one or more OIDs, wraps it with a version number and a community string.
2. Manager sends it as a single UDP datagram to the agent's port 161.
3. Agent checks the community string against its configured access list (v1/v2c) — or validates the user's auth/privacy credentials (v3).
4. If authorized, the agent looks up each requested OID in its local MIB implementation and reads the current value.
5. Agent builds a `Response` PDU containing the same request-id and the retrieved values, and sends it back in a single UDP datagram.
6. Manager matches the response to its outstanding request by request-id and displays/stores the result.

No connection state persists between requests — every single request/response pair, including the community string, stands entirely on its own.

------

## Byte-by-Byte Example: A GetRequest

A manager at 192.168.1.20 asks an agent at 192.168.1.10 for `sysDescr.0` (`1.3.6.1.2.1.1.1.0`) using SNMPv1 and community string `public`.

SNMP messages are encoded in **ASN.1 BER** (Basic Encoding Rules) — a tag/length/value (TLV) binary format, the same encoding family used by X.509 certificates. Every field is `[tag byte][length byte(s)][value bytes]`, and structures nest by putting TLVs inside other TLVs.

### Building the message, inside out

**The OID**, `1.3.6.1.2.1.1.1.0`: BER packs the first two numbers into a single byte as `40*X + Y` (`40*1 + 3 = 43 = 0x2B`), then encodes each remaining number as its own byte since none exceed 127:

```
06 08 2B 06 01 02 01 01 01 00
^^ ^^ ^^-----------------------^^
|  |  \_ value: 43,6,1,2,1,1,1,0 (= 1.3.6.1.2.1.1.1.0)
|  \_ length: 8 bytes
\_ tag: OBJECT IDENTIFIER
```

**The VarBind** (one name/value pair — value is `NULL` in a request, since we're asking, not answering):

```
30 0C  06 08 2B 06 01 02 01 01 01 00  05 00
^^ ^^                                  ^^ ^^
|  \_ length: 12 bytes of content      \_ NULL (tag 05, length 0) — placeholder value
\_ tag: SEQUENCE
```

**The variable-bindings list** (a SEQUENCE OF VarBind — just one entry here):

```
30 0E  30 0C 06 08 2B 06 01 02 01 01 01 00 05 00
```

**The GetRequest-PDU** (tag `0xA0` — each PDU type gets its own tag: `A0`=Get, `A1`=GetNext, `A2`=Response, `A3`=Set, `A5`=GetBulk):

```
A0 19  02 01 01  02 01 00  02 01 00  30 0E 30 0C 06 08 2B 06 01 02 01 01 01 00 05 00
^^ ^^  ^^^^^^^^  ^^^^^^^^  ^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
|  |   request-id=1  error-status=0  error-index=0    variable-bindings list
|  \_ length: 25 bytes
\_ tag: GetRequest-PDU
```

**The full message**:

```
30 26                          (SEQUENCE — the whole message, 38 bytes of content)
  02 01 00                     (INTEGER — version: 0 = SNMPv1)
  04 06 70 75 62 6C 69 63      (OCTET STRING — community = "public")
  A0 19                        (GetRequest-PDU, 25 bytes of content)
    02 01 01                   (request-id = 1)
    02 01 00                   (error-status = 0)
    02 01 00                   (error-index = 0)
    30 0E                      (variable-bindings, 14 bytes)
      30 0C                    (VarBind, 12 bytes)
        06 08 2B 06 01 02 01 01 01 00   (OID: sysDescr.0)
        05 00                           (value: NULL)
```

Total message: **40 bytes**. Notice the community string sits in plain OCTET STRING bytes right at the top — anyone who can see this packet (a network tap, a compromised switch, a permissive VLAN) reads `public` directly off the wire. There's no framing that hides it, unlike a password field in a protocol designed with confidentiality in mind.

### Wrapping in UDP and IP

```
UDP header (8 bytes):  src port 52341 (ephemeral)  dst port 161  length 48  checksum
IP header (20 bytes):  src 192.168.1.20  dst 192.168.1.10  protocol 17 (UDP)
```

```
[Ethernet [IP [UDP [40-byte SNMP GetRequest]]]]
```

Same nesting principle as the DNS example — one UDP datagram out, one back, no transport-level handshake or retransmission.

### The response

The agent replies with a `Response`-PDU (tag `0xA2`) that mirrors the request's structure exactly, except the VarBind's `NULL` is replaced with the actual value — e.g. an OCTET STRING containing `"Linux server1 5.15.0 #1 SMP x86_64"` — and the `request-id` is echoed back so the manager can match it to its outstanding query.

------

## Security

- **v1/v2c community strings are the entire access control model** — no encryption, no per-user identity, and by default many devices ship with `public` (read) and `private` (read-write) enabled out of the box.
- **UDP is spoofable**: since there's no handshake, a forged source IP can potentially inject a spoofed response or trap if the real agent doesn't answer first — mitigated by the same kind of controls as any UDP service (source-address validation, rate limiting).
- **SNMPv3's USM** fixes both: `authNoPriv` mode requires HMAC (MD5 or SHA) so a request can't be forged or replayed without the shared key, and `authPriv` mode additionally encrypts the whole PDU (DES in older implementations, AES-128/256 in modern ones) so a network observer can't even see which OIDs are being queried.
- Best practice on any device: change default community strings, restrict SNMP source IPs to management subnets only, and migrate to SNMPv3 where the hardware/software supports it.

------

## Common Operations You'll Actually Do

### Finding SNMP-speaking hosts

```bash
sudo nmap -sU --open -p 161 192.168.1.0/24 -oG open-snmp.txt
```

### Guessing community strings

```bash
onesixtyone -c community.txt -i ips.txt
```

### Querying values

```bash
snmpget -v1 -c public 192.168.1.10 1.3.6.1.2.1.1.1.0        # single OID
snmpwalk -v2c -c public 192.168.1.10                        # walk the entire MIB tree
snmpbulkwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.25     # bulk walk one subtree
snmptranslate -On 1.3.6.1.2.1.1.1.0                          # name <-> numeric OID conversion
```

### Writing a value (if the community string has write access)

```bash
snmpset -v1 -c private 192.168.1.10 1.3.6.1.2.1.1.5.0 s "new-hostname"
```

------

## Summary

| Concept        | Key point                                                              |
| -------------- | --------------------------------------------------------------------- |
| **Purpose**    | Vendor-neutral monitoring/configuration of network devices              |
| **Versions**   | v1/v2c — plaintext community strings; v3 — per-user auth + encryption   |
| **Transport**  | UDP 161 (requests), UDP 162 (traps) — stateless, no handshake           |
| **Naming**     | MIB tree of OIDs, e.g. `1.3.6.1.2.1.1.1.0` = `sysDescr.0`                |
| **Encoding**   | ASN.1 BER — tag/length/value binary format                              |
| **Core PDUs**  | Get, GetNext/GetBulk (walking), Set, Response, Trap                     |
| **Security**   | Default/weak community strings + cleartext wire format make v1/v2c a common high-value enumeration target |

The fundamental trick: every device, regardless of vendor, exposes its state through the same globally-registered tree of numbers — so one manager and one protocol can speak to a router, a printer, and a UPS without any of them needing to know about the others.
