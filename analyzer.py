#!/usr/bin/env python3
"""
analyzer.py: Network Traffic Analyzer Engine.
Parses packet captures (.pcap) into structured Pandas DataFrames and
executes vectorized anomaly detection to flag suspicious network activities.
"""

import sys
import math
import logging
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any, Optional

import numpy as np
import pandas as pd

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (
    conf,
    rdpcap,
    PcapReader,
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
    DNS,
    DNSQR,
    ARP,
)

conf.verb = 0

REQUIRED_COLUMNS = [
    "timestamp",
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "tcp_flags",
    "dns_query",
    "dns_entropy",
    "length",
]


def calculate_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a given string.
    Formula: H(X) = - sum( P(x_i) * log2(P(x_i)) )

    Returns 0.0 for empty or uniform strings.
    """
    if not data or not isinstance(data, str):
        return 0.0

    length = len(data)
    if length <= 1:
        return 0.0

    counts = Counter(data)
    if len(counts) <= 1:
        return 0.0

    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
    return float(entropy) if entropy > 0.0 else 0.0


def parse_pcap_to_dataframe(pcap_path: str) -> pd.DataFrame:
    """
    Parses packets from a .pcap file into a structured Pandas DataFrame.

    Required columns:
      - timestamp (float)
      - protocol (str)
      - src_ip (str or None)
      - dst_ip (str or None)
      - src_port (int or None)
      - dst_port (int or None)
      - tcp_flags (int or None)
      - dns_query (str or None)
      - dns_entropy (float)
      - length (int)
    Additional columns:
      - src_mac (str or None)
      - dst_mac (str or None)
    """
    path_obj = Path(pcap_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    rows: List[Dict[str, Any]] = []

    try:
        packets = rdpcap(str(path_obj))
    except Exception as exc:
        raise ValueError(f"Failed to read PCAP at {pcap_path}: {exc}") from exc

    for pkt in packets:
        ts = float(pkt.time) if hasattr(pkt, "time") else 0.0
        pkt_len = len(pkt)
        proto = "OTHER"
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[int] = None
        dns_query: Optional[str] = None
        dns_entropy: float = 0.0

        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None

        if pkt.haslayer(ARP):
            proto = "ARP"
            arp = pkt[ARP]
            src_ip = arp.psrc
            dst_ip = arp.pdst
            src_mac = arp.hwsrc
            dst_mac = arp.hwdst
        elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            else:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            if pkt.haslayer(TCP):
                proto = "TCP"
                tcp = pkt[TCP]
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                tcp_flags = int(tcp.flags)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = int(udp.sport)
                dst_port = int(udp.dport)

                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNSQR].qname:
                    proto = "DNS"
                    qname_raw = pkt[DNSQR].qname
                    if isinstance(qname_raw, bytes):
                        qname_str = qname_raw.decode("utf-8", errors="ignore")
                    else:
                        qname_str = str(qname_raw)
                    qname_clean = qname_str.rstrip(".")
                    dns_query = qname_clean
                    dns_entropy = calculate_entropy(qname_clean)
                else:
                    proto = "UDP"
            elif pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNSQR].qname:
                proto = "DNS"
                qname_raw = pkt[DNSQR].qname
                if isinstance(qname_raw, bytes):
                    qname_str = qname_raw.decode("utf-8", errors="ignore")
                else:
                    qname_str = str(qname_raw)
                qname_clean = qname_str.rstrip(".")
                dns_query = qname_clean
                dns_entropy = calculate_entropy(qname_clean)
            elif pkt.haslayer("ICMP"):
                proto = "ICMP"
            else:
                proto = "IP"

        rows.append({
            "timestamp": ts,
            "protocol": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "dns_query": dns_query,
            "dns_entropy": dns_entropy,
            "length": pkt_len,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        })

    if not rows:
        return pd.DataFrame(columns=REQUIRED_COLUMNS + ["src_mac", "dst_mac"])

    df = pd.DataFrame(rows)
    return df


def _is_null_scan_flag(val: Any) -> bool:
    """Helper to detect NULL scan flag values across numeric and string representations."""
    if pd.isna(val):
        return False
    if isinstance(val, (int, np.integer, float)):
        return int(val) == 0
    if isinstance(val, str):
        v = val.strip()
        return v in ("", "0", "0x00", "0x0", "None", "NULL")
    return False


def _is_xmas_scan_flag(val: Any) -> bool:
    """Helper to detect XMAS scan flags (0x29 / FIN+PSH+URG)."""
    if pd.isna(val):
        return False
    if isinstance(val, (int, np.integer, float)):
        int_val = int(val)
        return int_val == 0x29 or ((int_val & 0x29) == 0x29)
    if isinstance(val, str):
        v = val.strip().upper()
        if v in ("41", "0X29", "0X029"):
            return True
        # Check for FIN (F), PSH (P), and URG (U)
        if "F" in v and "P" in v and "U" in v:
            return True
    return False


def detect_anomalies(
    df: pd.DataFrame,
    flood_threshold: int = 50,
    entropy_threshold: float = 3.6,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """
    Detects network anomalies using vectorized Pandas operations:
    1. Stealth NULL TCP scan (flags=0x00).
    2. Stealth XMAS TCP scan (flags=0x29 / FIN+PSH+URG).
    3. High-entropy DNS exfiltration queries (Shannon entropy > 3.6).
    4. Layer 2 ARP Cache Poisoning / Spoofing attempts.
    5. Volumetric Anomalies (high-frequency talkers / packet flooding).

    Returns a list of structured anomaly dictionaries with keys:
    'type', 'severity', 'source', 'destination', 'details'.
    """
    anomalies: List[Dict[str, Any]] = []

    if df.empty:
        return anomalies

    # Handle alias kwargs if passed
    actual_flood_threshold = kwargs.get("packet_threshold", flood_threshold)
    actual_entropy_threshold = kwargs.get("entropy_threshold", entropy_threshold)

    # -------------------------------------------------------------
    # 1. Stealth TCP NULL Scans (flags=0x00)
    # -------------------------------------------------------------
    if "protocol" in df.columns and "tcp_flags" in df.columns:
        is_tcp = df["protocol"].astype(str).str.upper() == "TCP"
        is_null = df["tcp_flags"].apply(_is_null_scan_flag)
        null_scans = df[is_tcp & is_null]

        for _, row in null_scans.iterrows():
            dst_port = row["dst_port"]
            port_str = f":{int(dst_port)}" if pd.notna(dst_port) else ""
            anomalies.append({
                "type": "Stealth TCP NULL Scan",
                "severity": "HIGH",
                "source": str(row.get("src_ip", "Unknown")),
                "destination": str(row.get("dst_ip", "Unknown")),
                "details": f"Stealth NULL TCP scan with no flags targeting destination port {port_str.lstrip(':') or 'N/A'}",
            })

    # -------------------------------------------------------------
    # 2. Stealth TCP XMAS Scans (flags=0x29 / FIN+PSH+URG)
    # -------------------------------------------------------------
    if "protocol" in df.columns and "tcp_flags" in df.columns:
        is_tcp = df["protocol"].astype(str).str.upper() == "TCP"
        is_xmas = df["tcp_flags"].apply(_is_xmas_scan_flag)
        xmas_scans = df[is_tcp & is_xmas]

        for _, row in xmas_scans.iterrows():
            dst_port = row["dst_port"]
            port_str = f":{int(dst_port)}" if pd.notna(dst_port) else ""
            anomalies.append({
                "type": "Stealth TCP XMAS Scan",
                "severity": "HIGH",
                "source": str(row.get("src_ip", "Unknown")),
                "destination": str(row.get("dst_ip", "Unknown")),
                "details": f"Stealth XMAS TCP scan (FIN+PSH+URG) targeting destination port {port_str.lstrip(':') or 'N/A'}",
            })

    # -------------------------------------------------------------
    # 3. DNS Tunneling & Data Exfiltration via Shannon Entropy
    # -------------------------------------------------------------
    if "dns_entropy" in df.columns and "dns_query" in df.columns:
        has_query = df["dns_query"].notna() & (df["dns_query"] != "")
        high_entropy = df["dns_entropy"] > actual_entropy_threshold
        dns_tunneling = df[has_query & high_entropy]

        for _, row in dns_tunneling.iterrows():
            entropy_val = float(row["dns_entropy"])
            query_str = str(row["dns_query"])
            anomalies.append({
                "type": "DNS Tunneling",
                "severity": "HIGH",
                "source": str(row.get("src_ip", "Unknown")),
                "destination": str(row.get("dst_ip", "Unknown")),
                "details": f"High Shannon entropy DNS query ({entropy_val:.2f} > {actual_entropy_threshold}): '{query_str}'",
            })

    # -------------------------------------------------------------
    # 4. Layer 2 ARP Cache Poisoning / Spoofing Attempts
    # -------------------------------------------------------------
    if "protocol" in df.columns and "src_ip" in df.columns and "src_mac" in df.columns:
        arp_mask = df["protocol"].astype(str).str.upper() == "ARP"
        arp_df = df[arp_mask].dropna(subset=["src_ip", "src_mac"])

        if not arp_df.empty:
            mac_counts_per_ip = arp_df.groupby("src_ip")["src_mac"].nunique()
            poisoned_ips = mac_counts_per_ip[mac_counts_per_ip > 1].index.tolist()

            for ip in poisoned_ips:
                associated_macs = sorted(arp_df[arp_df["src_ip"] == ip]["src_mac"].unique().tolist())
                dst_ips = arp_df[arp_df["src_ip"] == ip]["dst_ip"].dropna().unique().tolist()
                dest_str = dst_ips[0] if dst_ips else "Broadcast"
                anomalies.append({
                    "type": "ARP Cache Poisoning",
                    "severity": "CRITICAL",
                    "source": str(ip),
                    "destination": str(dest_str),
                    "details": f"Conflicting ARP responses for IP {ip}: claimed by distinct MACs {associated_macs}",
                })

    # -------------------------------------------------------------
    # 5. Volumetric Anomalies (High-Frequency Talkers / Flooding)
    # -------------------------------------------------------------
    if "src_ip" in df.columns:
        src_series = df["src_ip"].dropna()
        if not src_series.empty:
            talker_counts = src_series.value_counts()
            flood_sources = talker_counts[talker_counts >= actual_flood_threshold]

            for src_ip, count in flood_sources.items():
                targets = df[df["src_ip"] == src_ip]["dst_ip"].dropna().unique().tolist()
                target_str = ", ".join(targets[:2]) if targets else "Multiple"
                if len(targets) > 2:
                    target_str += f" and {len(targets) - 2} more"

                anomalies.append({
                    "type": "Volumetric Flooding",
                    "severity": "HIGH" if count >= actual_flood_threshold * 2 else "MEDIUM",
                    "source": str(src_ip),
                    "destination": target_str,
                    "details": f"High-frequency packet flooding: {count} packets sent from source (threshold: {actual_flood_threshold})",
                })

    return anomalies


def format_telemetry_summary(df: pd.DataFrame) -> str:
    """Produces structured text summary statistics for parsed telemetry."""
    if df.empty:
        return "No packet telemetry available (DataFrame is empty)."

    lines = [
        "=" * 68,
        "             NETWORK TRAFFIC ANALYZER - TELEMETRY REPORT",
        "=" * 68,
        f"Total Packets Parsed : {len(df)}",
        f"Capture Time Span    : {df['timestamp'].min():.2f}s to {df['timestamp'].max():.2f}s (duration: {df['timestamp'].max() - df['timestamp'].min():.2f}s)",
        f"Total Bytes Analyzed : {df['length'].sum():,} bytes (Avg: {df['length'].mean():.1f} bytes/pkt)",
        "-" * 68,
        "PROTOCOL DISTRIBUTION:",
    ]

    proto_counts = df["protocol"].value_counts()
    for proto, cnt in proto_counts.items():
        pct = (cnt / len(df)) * 100
        lines.append(f"  - {proto:<10}: {cnt:>5} packets ({pct:>5.1f}%)")

    lines.append("-" * 68)
    lines.append("TOP TALKERS (SOURCE IPS):")
    top_talkers = df["src_ip"].dropna().value_counts().head(5)
    for ip, cnt in top_talkers.items():
        pct = (cnt / len(df)) * 100
        lines.append(f"  - {ip:<18}: {cnt:>5} packets ({pct:>5.1f}%)")

    dns_queries = df[df["dns_query"].notna()]
    if not dns_queries.empty:
        lines.append("-" * 68)
        lines.append(f"DNS QUERIES MONITORED: {len(dns_queries)} (Max Entropy: {dns_queries['dns_entropy'].max():.2f})")

    lines.append("=" * 68)
    return "\n".join(lines)


def format_anomalies_report(anomalies: List[Dict[str, Any]]) -> str:
    """Formats detected anomalies into a security analyst incident report."""
    lines = [
        "=" * 68,
        f"             SECURITY ANOMALIES DETECTED : {len(anomalies)}",
        "=" * 68,
    ]

    if not anomalies:
        lines.append(" [✓] No suspicious security anomalies detected. Traffic is benign.")
        lines.append("=" * 68)
        return "\n".join(lines)

    for idx, anomaly in enumerate(anomalies, 1):
        sev = anomaly.get("severity", "INFO")
        sev_badge = f"[{sev}]"
        lines.append(f"{idx:02d}. {sev_badge:<10} {anomaly.get('type')}")
        lines.append(f"    Source      : {anomaly.get('source')}")
        lines.append(f"    Destination : {anomaly.get('destination')}")
        lines.append(f"    Details     : {anomaly.get('details')}")
        lines.append("-" * 68)

    lines.append("=" * 68)
    return "\n".join(lines)


if __name__ == "__main__":
    target_pcap = sys.argv[1] if len(sys.argv) > 1 else "data/sample.pcap"

    # Also resolve relative to current script directory if not found in cwd
    if not Path(target_pcap).exists():
        script_relative = Path(__file__).resolve().parent / target_pcap
        if script_relative.exists():
            target_pcap = str(script_relative)

    print(f"[*] Reading and analyzing PCAP file: {target_pcap}")
    try:
        telemetry_df = parse_pcap_to_dataframe(target_pcap)
    except Exception as err:
        print(f"[!] Error parsing PCAP: {err}", file=sys.stderr)
        sys.exit(1)

    print(format_telemetry_summary(telemetry_df))
    detected = detect_anomalies(telemetry_df)
    print()
    print(format_anomalies_report(detected))
