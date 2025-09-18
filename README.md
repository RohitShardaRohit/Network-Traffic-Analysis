# Wireshark Network Traffic Analysis

**Short project summary**  
Capture and analyze network traffic (PCAP) to detect suspicious behaviors — DNS tunneling (high-entropy DNS), stealth SYN scans, and suspicious HTTP POSTs — and validate findings with external threat intelligence (VirusTotal / AbuseIPDB). The PCAP used in this repo was developed as part of the Georgia Tech CS 6035 course.

---

## What I did

- Captured and analyzed a traffic trace (PCAP) using Wireshark / tshark / tcpdump.
- Looked for three classes of suspicious activity:
  - **High-entropy DNS** (possible DNS tunneling).
  - **Stealth SYN scans** (many SYNs without completing the 3-way handshake).
  - **Suspicious HTTP POST** with a nonstandard user agent and ~600-byte body (possible data exfiltration).
- Cross-checked suspicious remote IPs using VirusTotal and AbuseIPDB to validate reputation.
- Documented findings, filter expressions, and investigative steps in this repository.

---

## Key results (high level)

- Filtered **12K+** packets with Wireshark/tcpdump for focused inspection.
- Detected **80+** SYN-scan style probes (SYN set, ACK not set) consistent with stealth scanning.
- Identified an HTTP `POST /exfil` with a ~600 byte body and custom user-agent — flagged for further investigation.
- Confirmed suspicious remote destination (`203.0.113.80` in this dataset) using external threat intel lookups (VirusTotal / AbuseIPDB).

---

## Tools / technologies used

Wireshark, tshark, tcpdump, nmap (for simulation), Python (analysis snippets), VirusTotal / AbuseIPDB (threat intel).

---

## Files in this repo

- `capture.pcap` — PCAP file captured / processed. 
- `README.md` — this file.  
- `setup.md` — step-by-step setup & analysis commands (copy/pasteable).  
- `demo/` — demonstration video

---

## Responsible use

This project is for education and defensive testing only. Do not run offensive scans or exfiltration tests on networks you do not own or have explicit permission to test.

If you publish findings that include suspect external IPs, follow your organization’s responsible disclosure / incident handling process before publicizing.

---

## Attribution

PCAP / capture used in this analysis was created during Georgia Tech CS 6035 coursework and adapted for this demonstration.


