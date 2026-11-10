# Network Traffic Analyzer & Forensic Anomaly Detection Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Packet%20Dissection-Scapy-red.svg)](https://scapy.net/)
[![Pandas](https://img.shields.io/badge/Analysis-Pandas-150458.svg)](https://pandas.pydata.org/)
[![Tests](https://img.shields.io/badge/Pytest-13%20passed-brightgreen.svg)](https://docs.pytest.org/)

A Python-based network packet analysis and forensic anomaly detection project. It reads packet capture files (.pcap) with **Scapy**, converts packet metadata into structured **Pandas DataFrames**, and applies rule-based and statistical heuristics to highlight suspicious network activity.

The repository includes a synthetic PCAP generator, a sample capture, a command-line telemetry report, and a 13-test Pytest suite.

> **Verified sample:** the committed data/sample.pcap contains 102 packets. Running the analyzer against this synthetic trace produces 15 anomaly records across five detection categories. These are results from the supplied test capture, not a claim about live network traffic.

---

## Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Detection logic](#detection-logic)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Example telemetry results](#example-telemetry-results)
- [Verify with Wireshark](#verify-with-wireshark)
- [Automated tests](#automated-tests)
- [How to interpret alerts](#how-to-interpret-alerts)
- [Limitations and safe use](#limitations-and-safe-use)

## Highlights

- **PCAP ingestion:** parses packet captures and extracts timestamps, protocol names, IP addresses, ports, TCP flags, DNS queries, packet lengths, and Ethernet MAC addresses.
- **Structured telemetry:** normalizes parsed packet metadata into a Pandas DataFrame for filtering, grouping, and analysis.
- **Shannon entropy:** calculates character-distribution entropy for DNS query strings to flag unusually random-looking names.
- **Stealth scan heuristics:** identifies TCP NULL and XMAS flag combinations.
- **ARP conflict detection:** identifies an IP address associated with multiple source MAC addresses in captured ARP traffic.
- **Traffic-volume heuristics:** identifies source IPs whose packet counts meet or exceed a configurable threshold.
- **Readable reporting:** prints protocol distribution, top talkers, DNS entropy statistics, and structured anomaly details.
- **Reproducible testing:** generates a synthetic trace and validates parsing and detection behavior with Pytest.

## Architecture

The processing flow is:

~~~mermaid
flowchart TD
    A["PCAP capture"] --> B["Scapy packet ingestion"]
    B --> C["Protocol and header dissection"]
    C --> D["Pandas DataFrame"]
    D --> E["Feature extraction"]
    E --> F["Anomaly detection"]
    F --> G["Telemetry summary"]
    F --> H["Structured security alerts"]

    E --> I["TCP flag analysis"]
    E --> J["DNS Shannon entropy"]
    E --> K["ARP IP-to-MAC correlation"]
    E --> L["Source packet-count analysis"]
~~~

### Packet fields extracted

| Field | Description |
|---|---|
| timestamp | Packet capture timestamp |
| protocol | Detected protocol label, such as TCP, UDP, DNS, ARP, ICMP, or IP |
| src_ip, dst_ip | Source and destination IP addresses |
| src_port, dst_port | Source and destination transport ports, when available |
| tcp_flags | TCP flag value, when the packet contains TCP |
| dns_query | Extracted DNS query name, when present |
| dns_entropy | Shannon entropy calculated from the DNS query string |
| length | Packet length in bytes |
| src_mac, dst_mac | Source and destination Ethernet/ARP MAC addresses, when available |

## Detection logic

The analyzer currently implements five detection categories.

| Detection | Logic | Default severity |
|---|---|---|
| TCP NULL scan | TCP packet with no flags set (0x00) | HIGH |
| TCP XMAS scan | TCP packet with FIN, PSH, and URG set (0x29) | HIGH |
| DNS tunneling heuristic | DNS query-string entropy exceeds 3.6 | HIGH |
| ARP IP/MAC conflict | One ARP source IP is observed with multiple source MAC addresses | CRITICAL |
| Volumetric flooding heuristic | A source IP reaches at least 50 packets in the capture | MEDIUM or HIGH |

Thresholds can be changed when calling detect_anomalies() from Python:

~~~python
from analyzer import detect_anomalies, parse_pcap_to_dataframe

packets = parse_pcap_to_dataframe("data/sample.pcap")

alerts = detect_anomalies(
    packets,
    flood_threshold=50,
    entropy_threshold=3.6,
)

for alert in alerts:
    print(alert)
~~~

### DNS entropy

Shannon entropy measures the distribution of characters in a string:

$$
H(X) = -\sum_{i=1}^{n} P(x_i)\log_2 P(x_i)
$$

In this project, entropy is calculated over the extracted DNS query string. A higher value indicates a more varied character distribution. The default heuristic flags queries with entropy greater than 3.6.

Entropy is a signal, not proof of malicious activity. Legitimate generated domains can also have high entropy, and real DNS tunneling may evade a simple threshold.

### TCP flag patterns

- **NULL scan:** no TCP control flags are set (0x00).
- **XMAS scan:** FIN, PSH, and URG are set together (0x29).

The analyzer reports matching packets individually, including their source, destination, and destination port.

### ARP conflicts

The analyzer groups captured ARP records by source IP and checks whether an IP has been associated with more than one source MAC address. This is a useful indicator of a possible ARP spoofing or cache-poisoning event; network context is required to determine whether the change is legitimate.

### Volumetric activity

The analyzer counts packets by source IP across the supplied capture. A source meeting the configured threshold is reported as a possible high-volume talker. This is a simple capture-wide heuristic, not a time-windowed rate calculation or a complete denial-of-service detector.

## Repository layout

~~~text
network-traffic-analyzer/
├── data/
│   └── sample.pcap          # Synthetic sample capture (102 packets)
├── tests/
│   └── test_analyzer.py     # 13 unit and integration tests
├── analyzer.py              # PCAP parser, entropy and anomaly detection
├── generate_pcap.py         # Synthetic traffic and attack-trace generator
├── requirements.txt         # Python dependencies
├── telemetry_report.txt     # Saved sample telemetry output
└── README.md
~~~

## Requirements

- Python 3.10 or newer
- pip
- The Python dependencies listed in requirements.txt
- Wireshark (optional, for independent packet inspection)

The project uses:

- [Scapy](https://scapy.net/) for packet capture parsing and packet generation
- [Pandas](https://pandas.pydata.org/) for structured packet data and analysis
- [NumPy](https://numpy.org/) for numerical support
- [Pytest](https://docs.pytest.org/) for automated tests

## Quick start

### 1. Clone the repository

~~~bash
git clone https://github.com/sam29sahil/network-traffic-analyzer.git
cd network-traffic-analyzer
~~~

### 2. Create and activate a virtual environment

**Linux / macOS**

~~~bash
python3 -m venv .venv
source .venv/bin/activate
~~~

**Windows PowerShell**

~~~powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
~~~

### 3. Install dependencies

~~~bash
python -m pip install --upgrade pip
pip install -r requirements.txt
~~~

### 4. Generate the synthetic PCAP

~~~bash
python generate_pcap.py
~~~

By default, the generator writes the capture to data/sample.pcap.

### 5. Analyze the capture

~~~bash
python analyzer.py data/sample.pcap
~~~

Save the console output to a report file if desired:

**Linux / macOS**

~~~bash
python analyzer.py data/sample.pcap | tee telemetry_report.txt
~~~

**Windows PowerShell**

~~~powershell
python analyzer.py data/sample.pcap | Tee-Object -FilePath telemetry_report.txt
~~~

### 6. Run the tests

~~~bash
pytest -v
~~~

## Example telemetry results

The following summary is from the committed telemetry_report.txt generated using the repository's sample capture.

| Metric | Sample result |
|---|---:|
| Packets parsed | 102 |
| Capture duration | 5.38 seconds |
| Bytes analyzed | 6,103 bytes |
| Average packet size | 59.8 bytes |
| DNS queries monitored | 6 |
| Maximum DNS entropy | 5.00 |
| Anomaly records | 15 |

### Protocol distribution

| Protocol | Packets | Share |
|---|---:|---:|
| UDP | 80 | 78.4% |
| TCP | 14 | 13.7% |
| DNS | 6 | 5.9% |
| ARP | 2 | 2.0% |

### Detected anomaly breakdown

| Anomaly category | Records | Severity in sample |
|---|---:|---|
| TCP NULL scans | 5 | HIGH |
| TCP XMAS scans | 5 | HIGH |
| High-entropy DNS queries | 3 | HIGH |
| ARP IP/MAC conflict | 1 | CRITICAL |
| Volumetric flooding heuristic | 1 | MEDIUM |
| **Total** | **15** | |

The sample capture includes these illustrative endpoints:

- Scan source: 10.0.0.99
- Scan target: 192.168.1.10
- DNS resolver destination: 8.8.8.8
- High-volume source: 192.168.1.200
- ARP address with conflicting MAC claims: 192.168.1.1

For the full console output and individual alert details, see [telemetry_report.txt](telemetry_report.txt).

## Verify with Wireshark

Open data/sample.pcap in Wireshark and use these display filters to inspect the traffic independently.

| Scenario | Display filter | What to inspect |
|---|---|---|
| TCP NULL scan | tcp.flags == 0x000 | TCP packets with all flags unset |
| TCP XMAS scan | tcp.flags == 0x029 | TCP packets with FIN, PSH, and URG set |
| ARP replies | arp.opcode == 2 | ARP replies and the MAC addresses claiming an IP |
| DNS queries | dns.flags.response == 0 | DNS requests; inspect query names for unusually encoded labels |
| High-volume source | ip.src == 192.168.1.200 && udp | UDP packets from the sample high-volume source |

These filters help inspect candidate traffic; they do not independently prove that an event is malicious.

## Automated tests

Run the complete test suite:

~~~bash
pytest -v
~~~

The repository's test suite contains **13 tests** covering:

| Area | Tests |
|---|---|
| Shannon entropy | Empty/trivial input, known theoretical values, and DNS domain strings |
| PCAP parsing | Missing-file handling and sample capture parsing/DataFrame schema |
| Baseline behavior | Empty DataFrame and benign traffic |
| TCP scan detection | NULL scan and XMAS scan detection |
| DNS detection | High-entropy DNS query detection |
| ARP detection | Conflicting IP-to-MAC mapping detection |
| Volumetric detection | High packet-count source detection |
| End-to-end pipeline | Detection of all five anomaly categories in the sample PCAP |

The recorded test run in the project notes is:

~~~text
13 passed in 1.39s
~~~

Test duration can vary by machine and environment. Run the command above to verify the current checkout.

## How to interpret alerts

Each anomaly is returned as a structured dictionary with these fields:

| Key | Meaning |
|---|---|
| type | Detection category |
| severity | Heuristic severity assigned by the detector |
| source | Source IP associated with the event |
| destination | Destination IP or destination context |
| details | Detection-specific evidence, such as flags, port, entropy, or MAC addresses |

Treat alerts as investigation leads. Validate suspicious events against the original packet capture, known network devices, expected traffic patterns, and other security telemetry before drawing conclusions.

## Limitations and safe use

- **Offline analysis:** this project analyzes PCAP files; it is not a live packet-capture agent or a full SIEM/NIDS platform.
- **Heuristic detections:** entropy, packet-count, and ARP conflict rules can produce false positives and false negatives.
- **Capture-wide threshold:** the current volumetric check counts packets by source across the capture; it does not calculate packets per second or use rolling time windows.
- **Protocol scope:** packet parsing extracts selected Ethernet/ARP, IPv4/IPv6, TCP, UDP, ICMP, and DNS metadata. It does not perform full application-payload inspection across every OSI layer.
- **Synthetic sample:** the included PCAP is generated for controlled testing. Its addresses and attack-like traffic are illustrative.

Use the generator and analyzer only in systems and environments you own or are authorized to test. Do not use synthetic detection results as evidence of an actual compromise.

---

**Project:** [sam29sahil/network-traffic-analyzer](https://github.com/sam29sahil/network-traffic-analyzer)
