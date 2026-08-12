# SMB Crash Course

A practical rundown of how SMB works, with a byte-by-byte trace of a real session negotiation as the centerpiece.

------

## What SMB Is

SMB (Server Message Block) is a request-response protocol for sharing files, printers, and named pipes over a network. When a Windows machine browses `\\fileserver\accounting`, opens a file on a network drive, or a domain controller answers an RPC call for authentication — that's SMB underneath.

It's the backbone of Windows networking: file sharing, print sharing, inter-process communication (via named pipes), and a transport for other protocols (like RPC used for domain authentication, service control, and remote registry access) all ride on top of it. Samba re-implements the same protocol on Linux/Unix, which is why a Linux box can serve files to Windows clients and vice versa.

It runs on TCP port 445 today. Older installs still support the legacy NetBIOS transport (TCP 139, UDP 137/138), kept around for compatibility with very old clients.

------

## Dialects and History

SMB isn't one fixed wire format — clients and servers negotiate a **dialect**, and the dialect determines what features and message formats are in play.

| Dialect        | Introduced           | Notable changes                                              |
| -------------- | --------------------- | -------------------------------------------------------------|
| **SMB 1.0 (CIFS)** | Pre-Vista / pre-2003  | Original IBM/Microsoft protocol from the late 1980s. Over 100 commands, chatty, no built-in encryption. The dialect exploited by EternalBlue/WannaCry. Deprecated and disabled by default on modern Windows. |
| **SMB 2.0**    | Vista / Server 2008    | Complete redesign — command set slashed to 19, larger buffer sizes, request compounding (batching multiple requests in one packet). |
| **SMB 2.1**    | Windows 7 / Server 2008 R2 | Client oplock leasing, large MTU support for better throughput. |
| **SMB 3.0**    | Windows 8 / Server 2012 | End-to-end encryption (AES-CCM), multichannel (use multiple NICs/paths for one session), RDMA support ("SMB Direct"). |
| **SMB 3.0.2**  | Windows 8.1 / Server 2012 R2 | Minor revision. |
| **SMB 3.1.1**  | Windows 10 / Server 2016 | Pre-authentication integrity (HMAC-SHA512) to stop downgrade attacks, stronger encryption (AES-128-GCM). |

During Negotiate, the client offers every dialect it supports; the server picks the highest one it also supports. This is how a modern Windows 11 client can still talk to an ancient NAS box that only understands SMB 2.0.

------

## Ports and Transport

- **TCP 445** — "direct hosting" of SMB over TCP, no NetBIOS involved. What every modern stack uses.
- **Legacy NetBIOS over TCP/IP (NBT)**:
  - **UDP 137** — NetBIOS Name Service (name resolution, like a local DNS for machine names)
  - **UDP 138** — NetBIOS Datagram Service
  - **TCP 139** — NetBIOS Session Service (SMB actually rides inside this session layer)

A modern Windows client tries port 445 first and only falls back to 139 if 445 is unreachable. Because SMB rides on TCP, every session starts with the normal three-way handshake (SYN, SYN-ACK, ACK) covered in the TCP/IP crash course — SMB adds its own request/response layer on top of that reliable byte stream.

------

## The Players in an SMB Session

**Client (redirector)**: the OS component that intercepts UNC paths (`\\server\share\file.txt`) and translates file-system calls into SMB requests. On Windows this is the "Workstation" service; applications never talk raw SMB themselves.

**Server**: the service listening on port 445 that answers requests — `srv2.sys` on Windows, `smbd` in Samba on Linux.

**Session**: established once authentication succeeds. Identified by a `SessionId`. A single TCP connection can carry multiple sessions (different users), and SMB 3 multichannel can spread one session across multiple TCP connections.

**Tree Connect**: a connection to one specific share within a session, identified by a `TreeId`. You "tree connect" to `\\server\accounting` separately from `\\server\public`, even in the same session.

**File handle (FileId)**: returned after a successful Create (open) request; every subsequent Read/Write/Close on that file references this handle.

**Named pipes**: SMB doesn't only serve files — the special `IPC$` share exposes named pipes that carry RPC traffic (e.g., `\pipe\lsarpc`, `\pipe\samr`, `\pipe\srvsvc`). This is how tools enumerate users, shares, and domain info over SMB without touching a single real file.

### Share types

| Type              | Purpose                                                       |
| ----------------- | -------------------------------------------------------------- |
| **Disk share**    | Access to a folder tree (e.g., `\\server\public`)              |
| **Print share**   | Access to a shared printer                                     |
| **IPC$**          | Not a filesystem share — a pipe endpoint for RPC calls          |
| **Admin shares**  | Hidden (name ends in `$`) — `C$`, `D$` (root of each drive), `ADMIN$` (the Windows install directory). Present by default, restricted to administrators. |

------

## How an SMB Session Works

1. **TCP handshake** to port 445.
2. **Negotiate Protocol**: client sends every dialect it supports; server picks the best mutual one and replies with its capabilities, security modes, and max message sizes.
3. **Session Setup**: authentication exchange — NTLM (challenge-response) or Kerberos (ticket-based), typically wrapped in SPNEGO so both sides agree on the mechanism. Success returns a `SessionId`.
4. **Tree Connect**: client asks for a specific share by UNC path; server checks share and NTFS permissions and returns a `TreeId` (or denies access).
5. **Create**: client opens a file, directory, or named pipe by path; server returns a `FileId`.
6. **Read / Write / Query Info / Set Info / IOCTL**: the actual work — reading bytes, writing bytes, listing directory contents, querying/setting file attributes, or issuing control codes (used heavily by RPC-over-named-pipes).
7. **Close**: releases the `FileId`.
8. **Tree Disconnect**: releases the `TreeId`.
9. **Logoff**: ends the session.

Real-world traffic compounds several of these into one packet (SMB2's "compounding") to cut round trips — e.g., Create + Query Info + Close can travel as a single request.

------

## Byte-by-Byte Example: Negotiate Protocol

A client at 192.168.1.50 connects to a file server at 192.168.1.10. After the TCP handshake, the first thing that crosses the wire is a Negotiate Protocol request.

### The SMB2 packet header (64 bytes, present on every message)

```
ProtocolId:       FE 53 4D 42        ("\xFE" + "SMB" — distinguishes SMB2+ from SMB1's "\xFFSMB")
StructureSize:    0x0040 (64)        (fixed size of this header)
CreditCharge:     0x0001
ChannelSequence:  0x0000             (Reserved/ChannelSequence on requests; NTSTATUS on responses)
Command:          0x0000             (0x0000 = SMB2_NEGOTIATE)
Credits:          0x0001             (credits requested, part of SMB2 flow control)
Flags:            0x00000000         (0 = this is a request; SERVER_TO_REDIR bit set on responses)
NextCommand:      0x00000000         (nonzero when compounding multiple requests)
MessageId:        0x0000000000000000 (first message on this connection)
Reserved/TreeId:  0x00000000         (no tree yet — Negotiate happens before Tree Connect)
SessionId:        0x0000000000000000 (no session yet)
Signature:        (all zero — signing isn't active until after Session Setup)
```

### Negotiate Request body

```
StructureSize:      0x0024 (36, fixed for this request shape)
DialectCount:       0x0004             (offering 4 dialects)
SecurityMode:       0x0001             (SMB2_NEGOTIATE_SIGNING_ENABLED)
Capabilities:       0x00000040         (e.g., SMB2_GLOBAL_CAP_ENCRYPTION)
ClientGuid:         {a1b2c3d4-...}     (16-byte GUID identifying this client)
Dialects[]:         0x0202 0x0210 0x0300 0x0311
                    (SMB 2.0.2, SMB 2.1, SMB 3.0, SMB 3.1.1 — offered best-effort)
```

Total on the wire: 64-byte SMB2 header + negotiate body ≈ 100 bytes, wrapped in a TCP segment, then an IP packet, then an Ethernet frame — same nesting as the HTTP example in the TCP/IP crash course.

### Negotiate Response

The server picks the highest dialect it also understands and replies:

```
StructureSize:        0x0041 (65, fixed for this response shape)
SecurityMode:         0x0001            (signing enabled)
DialectRevision:      0x0311            (server chose SMB 3.1.1)
ServerGuid:           {f9e8d7c6-...}
Capabilities:         0x0000007F        (encryption, multichannel, large MTU, etc.)
MaxTransactSize:      0x00800000        (8 MB)
MaxReadSize:          0x00800000
MaxWriteSize:         0x00800000
SystemTime:           (server's current time, FILETIME format)
SecurityBufferOffset: (points into this message)
SecurityBufferLength: N bytes           (a SPNEGO token listing supported auth mechanisms:
                                          typically Kerberos first, NTLM as fallback)
```

The client now knows: "we're speaking SMB 3.1.1, signing is required, and I should try Kerberos before falling back to NTLM." Everything that follows — Session Setup, Tree Connect, file I/O — uses the message shapes defined by that negotiated dialect.

### Session Setup, at a glance

Session Setup carries the actual authentication tokens (NTLM messages or a Kerberos AP-REQ) inside the SMB2 payload rather than as separate protocol fields — SMB doesn't reinvent authentication, it just transports whatever GSS-API/SPNEGO mechanism was agreed on during Negotiate. For NTLM this is a three-leg exchange: NEGOTIATE_MESSAGE → CHALLENGE_MESSAGE (server sends a random nonce) → AUTHENTICATE_MESSAGE (client proves it knows the password hash without sending the hash itself). Success returns a nonzero `SessionId` that every subsequent request in the header must include.

------

## Signing and Encryption

**SMB signing**: once a session is established, every message can carry an HMAC in the header's `Signature` field, computed over the message using a key derived from the session. This stops an on-path attacker from tampering with traffic or replaying a captured request — the classic concern being **SMB relay**, where a captured NTLM authentication attempt gets forwarded to a different target. Signing (required by default on domain controllers since 2020, and by default on all Windows and Samba since 2025) closes that gap because a forwarded/tampered message won't carry a valid signature for the second connection.

**SMB encryption** (SMB 3.0+): wraps the entire message in AES-CCM (3.0/3.0.2) or AES-GCM (3.1.1), enabled per-share or globally. Unlike signing, it also hides the content of the traffic, not just its integrity.

**Pre-authentication integrity** (3.1.1): a running HMAC-SHA512 hash covers the Negotiate and Session Setup exchange itself, so an attacker can't downgrade the negotiation to a weaker dialect or tamper with the security-mode fields before signing even kicks in.

------

## Common SMB Operations You'll Actually Do

### Discovering shares

```bash
smbclient -L //192.168.1.10 -N          # list shares, -N = no password (null session)
smbclient -L //192.168.1.10 -U user     # list shares as a specific user
```

### Connecting to a share

```bash
smbclient //192.168.1.10/public -N
smbclient //192.168.1.10/public -U user%password
```

Inside an `smbclient` session: `ls`, `get file.txt`, `put file.txt`, `cd`, `dir`.

### Mounting a share (Linux)

```bash
sudo mount -t cifs //192.168.1.10/public /mnt/share -o username=user,password=pass
```

### Windows-native

```cmd
net view \\fileserver              :: list visible shares
net view \\fileserver /all         :: include hidden/admin shares
net use Z: \\fileserver\public     :: map a share to a drive letter
```

### Enumeration tools

```bash
enum4linux -a 192.168.1.10          # shares, users, groups, OS info, password policy
smbmap -H 192.168.1.10              # shares + effective permissions per share
nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users 192.168.1.10
```

------

## Summary

| Concept        | Key point                                                             |
| -------------- | ---------------------------------------------------------------------|
| **Purpose**    | File, printer, and named-pipe sharing; also an RPC transport          |
| **Dialects**   | Negotiated per connection — SMB1 (legacy/deprecated) through SMB 3.1.1|
| **Transport**  | TCP 445 (modern); legacy NetBIOS on TCP 139 / UDP 137,138             |
| **Session flow** | Negotiate → Session Setup (auth) → Tree Connect → Create/Read/Write/Close |
| **Auth**       | NTLM (challenge-response) or Kerberos, wrapped in SPNEGO              |
| **Integrity**  | Message signing (HMAC); SMB3 adds full encryption (AES-CCM/GCM)       |
| **Special share** | `IPC$` — no files, just named pipes carrying RPC traffic            |

The fundamental trick: SMB decouples the *dialect* (negotiated once, up front) from everything that follows, so a single wire protocol has been able to evolve from a chatty 1980s LAN protocol into an encrypted, multichannel, RDMA-capable one without breaking compatibility with decades of clients.
