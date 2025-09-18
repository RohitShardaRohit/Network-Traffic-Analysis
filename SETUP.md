# Wireshark Network Traffic Analysis — Setup & Commands

This document describes how to reproduce the analysis environment and run the exact commands/filters used to investigate the PCAP. Use on systems you own or have permission to test.

---

## 1) Prerequisites / downloads

Install the following tools:

- **Wireshark** (GUI): https://www.wireshark.org/  
- **tshark** (CLI; comes with Wireshark)  
- **tcpdump** (packet capture): usually `sudo apt install tcpdump`  
- **nmap** (optional, for simulation): `sudo apt install nmap`  
- **netcat** (optional connectivity checks): `sudo apt install netcat`  
- Python (optional analysis scripts)

On Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y wireshark tshark tcpdump nmap netcat python3
# you may be prompted during wireshark install to allow non-root capture users
```
## 2) Getting the PCAP

Place your PCAP into the repo root (suggest name capture.pcap). If it’s large, add it as a release asset and link it from README.

## 3) Quick inspection (tshark / tcpdump)

Show top-level summary:
```bash
tshark -r capture.pcap -q -z io,phs
```

Count packets:
```bash
tshark -r capture.pcap -q -z io,stat,0
```

Extract only DNS packets into a smaller file:
```bash
tshark -r capture.pcap -Y "dns" -w dns_only.pcap
```

Extract only HTTP:
```bash
tshark -r capture.pcap -Y "http.request" -w http_only.pcap
```

Generate a CSV of flows (five-tuple + packet count):
```bash
tshark -r capture.pcap -q -z conv,ip
```

## 4) Wireshark filters (copy/paste)
Open capture.pcap in Wireshark and use these display filters:

High-entropy DNS candidates (manually inspect long subdomains):

- Display filter: dns.qry.name contains "." then sort by dns.qry.name length, or use frame.len/dns fields.

- Example approach (manual): dns && frame.len > 200

Stealth SYN scans (SYN set, ACK not set):
```bash
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

HTTP POST (potential exfil):
```bash
http.request.method == "POST"
```

Then expand the packet’s HTTP request and inspect http.request.full_uri, http.user_agent, and http.content_length (or look for ~600-byte body).

Filter by destination IP (example suspicious IP):
```bash
ip.dst == 203.0.113.80
```

## 5) CLI analysis snippets (tshark)

List packets that match SYN-scan pattern:
```bash
tshark -r capture.pcap -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
```

Show HTTP POST URIs and user agents:
```bash
tshark -r capture.pcap -Y 'http.request.method == "POST"' -T fields -e frame.number -e ip.src -e ip.dst -e http.request.uri -e http.user_agent -e http.content_length
```

Dump DNS query names to a file for entropy inspection:
```bash
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn > dns_qry_counts.txt
```

Measure entropy (simple heuristic) with Python on DNS names:
```bash
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | python3 -c "import sys,math
def ent(s): from collections import Counter
 c=Counter(s);p=[v/len(s) for v in c.values()]; return -sum(map(lambda x: x*math.log2(x),p))
for line in sys.stdin:
 s=line.strip()
 if s:
  print(ent(s),s)"
```

## 6) Validate suspicious IPs (VirusTotal / AbuseIPDB)

Quick manual checks:

VirusTotal — paste IP into https://www.virustotal.com/
 and inspect network / URLs / community verdicts.

AbuseIPDB — paste IP into https://www.abuseipdb.com/
 to view reports and tags.

 CLI (example, using curl to AbuseIPDB API — requires API key):
 ```bash
# AbuseIPDB example (replace <API_KEY> and <IP>)
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=<IP>" \
  -d maxAgeInDays=90 \
  -H "Key: <API_KEY>" \
  -H "Accept: application/json"
```

## 7) Acknowledgements

PCAP inspired by Georgia Tech CS 6035 coursework. Thanks to course materials for the dataset and scenarios.
