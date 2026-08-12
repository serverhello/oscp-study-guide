# SMTP Crash Course

A practical rundown of how SMTP works, with a byte-by-byte trace of a real message hand-off as the centerpiece.

------

## What SMTP Is

SMTP (Simple Mail Transfer Protocol) is how email gets *sent* — from your mail client to your provider, and from your provider's server to the recipient's server. It's a **store-and-forward** protocol: each server along the way accepts full responsibility for a message before passing it on, so a hop can be offline without the message being lost — it just gets retried later by whichever server is currently holding it.

SMTP is a plaintext, line-oriented, command/response protocol — you can hold an entire conversation with a mail server by hand over a raw TCP connection, which makes it one of the easiest protocols to inspect directly.

**Important distinction**: SMTP only handles *sending*. Retrieving mail from your mailbox into a client uses a different protocol entirely — POP3 (port 110/995) or IMAP (port 143/993). SMTP moves mail *toward* a mailbox; POP3/IMAP pulls it *out* of one.

------

## Ports and Transport

| Port    | Role                                                                |
| ------- | -------------------------------------------------------------------|
| **25**  | Server-to-server relay (MTA to MTA). ISPs commonly block outbound 25 for residential connections to cut down on spam from infected machines. |
| **587** | Message submission (client to server). Expects authentication and, per current standards, `STARTTLS` before credentials are sent. This is what your mail client actually uses to send. |
| **465** | Submission over implicit TLS (SMTPS) — the TLS handshake happens immediately, no `STARTTLS` negotiation. Originally unofficial, now standardized (RFC 8314) and increasingly preferred over 587+STARTTLS. |

All three carry the same SMTP commands underneath — the port just signals the expected security/authentication posture, riding on a normal TCP connection like any other application protocol.

------

## The Players

**MUA (Mail User Agent)**: your email client — Outlook, Thunderbird, the Gmail app. Where you compose and read mail.

**MSA (Mail Submission Agent)**: accepts mail from an authenticated MUA, typically on port 587/465. Does basic sanity checks (is this user allowed to send as this address?) before handing off to an MTA.

**MTA (Mail Transfer Agent)**: the workhorse — relays mail between organizations over port 25. Postfix, Exim, and Microsoft's Exchange Transport service are all MTAs. An MTA looks up the recipient domain's **MX record** (see the DNS crash course) to find which server to hand the message to next.

**MDA (Mail Delivery Agent)**: the final hop — deposits an accepted message into the actual mailbox (a Maildir, an mbox file, an Exchange database).

The MUA/MSA distinction from MTA matters because it's the security boundary: MSA requires authentication (you must prove you're allowed to send as `you@example.com`), while a receiving MTA on port 25 accepts mail from *anyone* on the internet — it just decides whether to accept, reject, or queue it based on the recipient, not the sender's identity.

------

## How an Email Gets From Sender to Recipient

Alice (`alice@example.com`) emails Bob (`bob@example.org`):

1. **Alice's MUA connects to her provider's MSA** on port 587, authenticates, and submits the message.
2. **The MSA hands off to example.com's outbound MTA** (often the same server).
3. **That MTA looks up the MX record for `example.org`** via DNS — say it resolves to `mail.example.org`.
4. **The MTA opens a TCP connection to `mail.example.org` on port 25** and has an SMTP conversation, transferring the message.
5. **`mail.example.org` (the receiving MTA) accepts the message**, running spam/virus checks, and hands it to the **MDA**, which files it into Bob's mailbox.
6. **Bob's MUA retrieves it** later via IMAP or POP3 — a completely separate protocol conversation.

Every hop in steps 2–5 is store-and-forward: each server fully owns the message (usually written to disk in a mail queue) before acknowledging acceptance to the previous hop.

------

## Byte-by-Byte Example: An SMTP Conversation

Continuing the example above — the TCP connection from `example.com`'s MTA to `mail.example.org` on port 25 is already established (three-way handshake, same as any TCP session). Every line below is terminated with `\r\n` — SMTP requires CRLF line endings even though most Unix tools default to bare `\n`, which is a common source of "it works from telnet but not from my script" bugs.

```
S: 220 mail.example.org ESMTP Postfix
C: EHLO mail.example.com
S: 250-mail.example.org Hello mail.example.com [203.0.113.5]
S: 250-PIPELINING
S: 250-SIZE 35882577
S: 250-STARTTLS
S: 250-8BITMIME
S: 250 ENHANCEDSTATUSCODES
C: MAIL FROM:<alice@example.com>
S: 250 2.1.0 Ok
C: RCPT TO:<bob@example.org>
S: 250 2.1.5 Ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: From: Alice <alice@example.com>
C: To: Bob <bob@example.org>
C: Subject: Project update
C: Date: Wed, 12 Aug 2026 09:15:00 -0400
C:
C: Hi Bob, attached is the update we discussed.
C: .
S: 250 2.0.0 Ok: queued as 4A2B1C3D
C: QUIT
S: 221 2.0.0 Bye
```

### What's actually happening on the wire

- The server speaks first: `220` is the greeting — servers announce themselves before the client sends anything, unlike HTTP where the client always goes first.
- `EHLO` (Extended HELO) both identifies the client and asks the server to list its supported extensions. The dashes (`250-`) mark continuation lines; the final line uses a space (`250 `) to signal the end of the list. Legacy `HELO` gets a plain single-line reply with no extension list.
- **`MAIL FROM` and `RCPT TO` are the envelope** — this is what actually controls delivery and what appears in the SMTP transaction logs. It is completely separate from the `From:`/`To:` **headers** typed inside the `DATA` block, which are just text the mail client displays to a human. A message can have a `MAIL FROM` of one address and a `From:` header showing a completely different one — this mismatch (or its absence of verification) is exactly what SPF/DKIM/DMARC exist to police.
- `DATA` switches the connection into a raw text-upload mode. The server replies `354` and now treats everything sent as message content until it sees a line containing only a single dot (`.`). Any line in the actual message body that begins with a dot gets an extra dot prepended by the sender (and stripped by the receiver) — "dot-stuffing" — so a legitimate line of `.` doesn't accidentally terminate the message.
- Each response starts with a **three-digit status code**; the human-readable text after it is only for logs/debugging and isn't meant to be parsed by clients.
- `221 Bye` and the connection closing is the SMTP-level teardown, followed by the normal TCP FIN/ACK teardown underneath.

### The full picture

```
[Ethernet [IP [TCP [SMTP command/response lines]]]]
```

Same layering as the HTTP example in the TCP/IP crash course — SMTP is just another plaintext application protocol riding on a reliable TCP byte stream. The only SMTP-specific behavior at the wire level is that the *server* speaks first, and that a multi-line command/response uses the dash-vs-space convention shown above.

------

## Command Reference

| Command      | Purpose                                                        |
| ------------ | ----------------------------------------------------------------|
| `HELO`       | Basic greeting, identify the client                             |
| `EHLO`       | Extended greeting — also returns supported extensions           |
| `MAIL FROM`  | Start a transaction, declare the envelope sender                |
| `RCPT TO`    | Declare an envelope recipient (repeatable for multiple recipients) |
| `DATA`       | Begin the message content; terminated by a lone `.` line        |
| `RSET`       | Abort the current transaction                                   |
| `VRFY`       | Ask the server to verify whether an address/mailbox exists      |
| `EXPN`       | Ask the server to expand a mailing list into its members        |
| `NOOP`       | No-op, keep the connection alive                                |
| `STARTTLS`   | Upgrade the plaintext connection to TLS mid-session              |
| `AUTH`       | Authenticate (mechanisms: `PLAIN`, `LOGIN`, `CRAM-MD5`, etc.)    |
| `QUIT`       | Close the connection gracefully                                 |

`VRFY` and `EXPN` are holdovers from SMTP's trusting early-internet design — most modern servers disable or lie in response to both, since they're a straightforward way to confirm valid usernames.

### Response codes

| Range   | Meaning                                                        |
| ------- | ----------------------------------------------------------------|
| **2xx** | Success (`220` greeting, `221` closing, `250` OK, `251` will forward, `252` cannot verify but will try) |
| **3xx** | Intermediate (`354` — send the message data)                    |
| **4xx** | Transient failure — retry later (`421` service unavailable, `450` mailbox busy, `452` insufficient storage) |
| **5xx** | Permanent failure — don't retry as-is (`500` syntax error, `550` mailbox unavailable/unknown user, `552` message too large, `554` transaction failed) |

------

## Extensions and Security

**ESMTP**: the "Extended SMTP" framework introduced with `EHLO` — the server advertises what it supports (`SIZE`, `PIPELINING`, `STARTTLS`, `AUTH`, `8BITMIME`, etc.) so clients can adapt instead of guessing.

**STARTTLS**: negotiated mid-connection over the *same* TCP session — the client sees `STARTTLS` advertised, sends the `STARTTLS` command, and both sides then perform a TLS handshake on that same socket before continuing with `EHLO` again. This is opportunistic by default: if a client silently continues in plaintext when `STARTTLS` isn't offered (rather than refusing), that's a downgrade opportunity for an on-path attacker — which is exactly why implicit-TLS port 465 is gaining ground over 587.

**AUTH**: submission servers require authentication before accepting `MAIL FROM`. Common mechanisms are `PLAIN` and `LOGIN` (both just base64-encoded credentials — worthless without TLS already active) and `CRAM-MD5` (challenge-response, doesn't send the password itself).

**SPF / DKIM / DMARC**: published as DNS `TXT` records (see the DNS crash course) — SPF lists which servers are allowed to send as a domain, DKIM lets a domain cryptographically sign outgoing mail, and DMARC tells receiving servers what to do when SPF/DKIM fail (quarantine, reject, or nothing) and where to send failure reports. All three exist specifically because the `MAIL FROM`/`From:` header trust described above has no protection built into SMTP itself.

------

## Common Operations You'll Actually Do

### Manually talking to a mail server

```bash
nc -nv 192.168.1.8 25
telnet 192.168.1.8 25
```

Then type commands by hand — `EHLO test`, `MAIL FROM:<a@b.com>`, `RCPT TO:<c@d.com>`, `DATA`, etc.

### Testing STARTTLS/TLS directly

```bash
openssl s_client -starttls smtp -connect 192.168.1.8:25
openssl s_client -connect 192.168.1.8:465          # implicit TLS
```

### Sending a test message from the command line

```bash
swaks --to bob@example.org --from alice@example.com --server 192.168.1.8
```

### Windows (no nc/openssl available)

```powershell
Test-NetConnection -Port 25 192.168.1.8
dism /online /Enable-Feature /FeatureName:TelnetClient   # requires admin
telnet 192.168.1.8 25
```

------

## Summary

| Concept        | Key point                                                             |
| -------------- | -----------------------------------------------------------------------|
| **Purpose**    | Store-and-forward transport for sending email                          |
| **Ports**      | 25 (relay, MTA↔MTA), 587 (submission+STARTTLS), 465 (submission, implicit TLS) |
| **Players**    | MUA → MSA → MTA(s) → MDA → mailbox                                     |
| **Discovery**  | Sending MTA finds the next hop via the recipient domain's DNS MX record |
| **Envelope vs. header** | `MAIL FROM`/`RCPT TO` control delivery; `From:`/`To:` are just displayed text |
| **Security**   | STARTTLS/implicit TLS for confidentiality; SPF/DKIM/DMARC for sender authenticity |

The fundamental trick: SMTP splits "who this message is legally addressed to" (the envelope) from "what a human reads" (the headers and body) — which is exactly why sender-verification had to be bolted on decades later as separate DNS-based standards, rather than being part of the protocol itself.
