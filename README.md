# Network Traffic Analyzer

A high-performance security telemetry and network analysis engine built with Python, Scapy, Pandas, and Pytest. The platform reads raw `.pcap` files, transforms packet streams into structured Pandas DataFrames, and utilizes vectorized analytics to detect suspicious cyber threat activities.

---

## Key Features & Anomaly Detection

1. **DNS Tunneling & Data Exfiltration**:
   - Calculates **Shannon Entropy** ($H(X) = -\sum P(x) \log_2 P(x)$) on DNS query strings (`qname`).
   - Flags suspicious base64/hex-encoded data exfiltration queries with entropy $> 3.6$.

2. **Stealth TCP Port Scans**:
   - **NULL Scans**: Vectorized detection of TCP packets with no flags set (`flags=0x00`).
   - **XMAS Scans**: Vectorized detection of TCP packets with FIN, PSH, and URG flags set (`flags=0x29`).

3. **Layer 2 ARP Cache Poisoning / Spoofing**:
   - Analyzes ARP responses (`is-at`) mapping IP addresses to MAC addresses.
   - Detects conflicting responses claiming the same IP with multiple different MAC addresses.

4. **Volumetric Traffic Anomalies**:
   - High-frequency talker detection identifying denial-of-service / packet flooding sources exceeding defined volume thresholds.

---

## Project Structure

```text
network-traffic-analyzer/
├── analyzer.py            # Core analysis engine, Shannon entropy, and anomaly detector
├── generate_pcap.py       # Standalone Scapy generator creating realistic test traces
├── requirements.txt       # Dependencies (scapy, pandas, pytest)
├── README.md              # Project documentation
├── data/
│   └── sample.pcap        # Synthetic packet capture with benign flows & attacks
└── tests/
    └── test_analyzer.py   # Unit and integration test suite (13 test cases)
```

---

## Installation

Ensure Python 3.10+ is installed, then install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Generate Synthetic PCAP Data
Generate a realistic trace containing benign HTTP/DNS flows alongside stealth scans, DNS tunneling, ARP spoofing, and volumetric flood traffic:

```bash
python generate_pcap.py
```
This saves the trace to `data/sample.pcap`.

### 2. Run Telemetry Analysis and Anomaly Detection
Analyze the generated PCAP trace:

```bash
python analyzer.py data/sample.pcap
```

**Sample Output:**
```text
[*] Reading and analyzing PCAP file: data/sample.pcap
====================================================================
             NETWORK TRAFFIC ANALYZER - TELEMETRY REPORT
====================================================================
Total Packets Parsed : 102
Capture Time Span    : 1700000000.01s to 1700000005.39s (duration: 5.38s)
Total Bytes Analyzed : 6,103 bytes (Avg: 59.8 bytes/pkt)
--------------------------------------------------------------------
PROTOCOL DISTRIBUTION:
  - UDP       :    80 packets ( 78.4%)
  - TCP       :    14 packets ( 13.7%)
  - DNS       :     6 packets (  5.9%)
  - ARP       :     2 packets (  2.0%)
--------------------------------------------------------------------
TOP TALKERS (SOURCE IPS):
  - 192.168.1.200     :    80 packets ( 78.4%)
  - 10.0.0.99         :    10 packets (  9.8%)
  - 192.168.1.10      :     8 packets (  7.8%)
  - 192.168.1.1       :     2 packets (  2.0%)
  - 8.8.8.8           :     1 packets (  1.0%)
--------------------------------------------------------------------
DNS QUERIES MONITORED: 6 (Max Entropy: 5.00)
====================================================================

====================================================================
             SECURITY ANOMALIES DETECTED : 15
====================================================================
01. [HIGH]     Stealth TCP NULL Scan
    Source      : 10.0.0.99
    Destination : 192.168.1.10
    Details     : Stealth NULL TCP scan with no flags targeting destination port 21
...
11. [HIGH]     DNS Tunneling
    Source      : 192.168.1.10
    Destination : 8.8.8.8
    Details     : High Shannon entropy DNS query (4.45 > 3.6): 'aW50ZWwuanNvbi5zZWNyZXRz.c2.attacker.com'
...
14. [CRITICAL] ARP Cache Poisoning
    Source      : 192.168.1.1
    Destination : 192.168.1.10
    Details     : Conflicting ARP responses for IP 192.168.1.1: claimed by distinct MACs ['00:50:56:c0:00:01', 'de:ad:be:ef:13:37']
...
15. [MEDIUM]   Volumetric Flooding
    Source      : 192.168.1.200
    Destination : 192.168.1.10
    Details     : High-frequency packet flooding: 80 packets sent from source (threshold: 50)
====================================================================
```

---

## Running the Test Suite

Run unit and integration tests using Pytest:

```bash
pytest -v
```
All 13 test cases validate:
- Shannon entropy mathematical edge cases (empty strings, uniform frequencies, binary, and DNS payloads)
- DataFrame schema conformance across required columns
- Vectorized detection of NULL scans, XMAS scans, DNS exfiltration, ARP spoofing, and volumetric packet floods
- Full end-to-end detection pipeline on synthetic PCAP traces

# Network Traffic Analyzer & Anomaly Detection Platform

A forensic packet analysis engine built in Python using **Scapy** and **Pandas** to detect stealth scans, protocol misuse, Layer 2 spoofing, and covert DNS data exfiltration.

## Features
- **Vectorized Ingestion:** Dissects PCAP captures into structured Pandas DataFrames for high-performance telemetry analysis.
- **Shannon Entropy Analysis:** Computes $H(X) = -\sum P(x)\log_2 P(x)$ across DNS query subdomains to flag encoded exfiltration channels ($>3.6$).
- **Stealth Port Scan Detection:** Identifies RFC 793 violations including NULL scans (`0x00`) and XMAS scans (`FIN+PSH+URG` / `0x29`).
- **ARP Poisoning Detection:** Tracks dynamic IP-to-MAC associations and flags conflicting gratuitous replies.
- **Volumetric Flood Detection:** Groups traffic by source IP to alert on high-frequency bursts exceeding baseline thresholds.

## Quickstart

### 1. Setup Environment
```bash
pip install -r requirements.txt
