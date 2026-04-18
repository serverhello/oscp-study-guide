# Recon and Enumeration Notes

## Initial Process

- Discovery Scan => Port Scan => Service enumeration => Vulnerability research
- Don't discard less common ports, as companies generally spend a lot of effort securing the more common ports, such as 22, 80, etc.
- Perform a new enumeration every time you get a new level of access
- Avoid rabbit holes
  - Enumerate everything before attempting to exploit
  - Timebox your exploit attempts, e.g., after 1 hour, move on.
  - Enumerate, enumerate, enumerate

## Network Discovery

- Identify live hosts on a network before performing heavy scans, e.g., 10.10.0.0/24 network range ( 254 potential hosts ) or 192.168.0.0/16 network range ( 64K potential hosts ) might just have a few live running server
- Use ICMP pings against all IPs in scope, but might be disabled on the host
- Top TCP/UDP port scan on most common ports
  - Can detect if a host alive even if the port is closed

### NMap

NMap is one of the most important tools to have a deep understanding of for any type of pen testing. It can cover:

- Discovery scans
- Port scans
- Service scans
- Vulnerability scans
- Custom scans

#### Basics

##### Discovery Scan

```bash
nmap -sn 192.168.2.0/24
```

Will only perform a discovery scan to find live hosts, and not an additional port scan

An important note here is that running only the `-sn` flag as root, it is generally equivalent to running the command:

```bash
nmap -sn -PE -PS443 -PA80 -PP
```

Where

- `PE` is an ICMP echo request
- `PS443` is a TCP SYN to port 443
- `PA80` is a TCP ACK to port 80
- `PP` is an ICMP timestamp request

##### Port scan

```bash
nmap 192.168.2.56
```

Will perform a discovery scan to ensure the host is active, and then perform a port scan on the top 1000 ports

Can also provide an entire network segment, e.g.,

```bash
nmap 192.168.2.0/24
```

which will scan the entire subnet

or

```bash
nmap 192.168.2.10-50
```

which will scan IPs that end in 10 until 50.

You can also provide a list of targets from an input file, e.g.,

```bash
nmap -iL targets.txt
```

