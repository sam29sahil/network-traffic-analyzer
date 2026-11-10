"""
test_analyzer.py: Unit and integration tests for Network Traffic Analyzer.
Validates Shannon entropy calculations, PCAP parsing into Pandas DataFrames,
and vectorized anomaly detection algorithms.
"""

import sys
import math
from pathlib import Path

# Add project root to sys.path so analyzer module can be imported anywhere
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import pandas as pd
import numpy as np

from analyzer import (
    calculate_entropy,
    parse_pcap_to_dataframe,
    detect_anomalies,
    REQUIRED_COLUMNS,
)


# =====================================================================
# 1. Shannon Entropy Calculation Tests
# =====================================================================

def test_entropy_empty_and_trivial():
    """Verify entropy handles empty, None, and trivial single-character inputs."""
    assert calculate_entropy("") == 0.0
    assert calculate_entropy(None) == 0.0
    assert calculate_entropy("a") == 0.0
    assert calculate_entropy("aaaaaaa") == 0.0
    assert calculate_entropy("11111111") == 0.0


def test_entropy_known_theoretical_values():
    """
    Verify Shannon entropy against mathematically exact values:
    - 2 equiprobable symbols: H = - 2 * (0.5 * log2(0.5)) = 1.0 bit
    - 4 equiprobable symbols: H = - 4 * (0.25 * log2(0.25)) = 2.0 bits
    - 8 equiprobable symbols: H = - 8 * (0.125 * log2(0.125)) = 3.0 bits
    """
    assert math.isclose(calculate_entropy("ab"), 1.0, rel_tol=1e-5)
    assert math.isclose(calculate_entropy("aabb"), 1.0, rel_tol=1e-5)
    assert math.isclose(calculate_entropy("abcd"), 2.0, rel_tol=1e-5)
    assert math.isclose(calculate_entropy("abcdefgh"), 3.0, rel_tol=1e-5)


def test_entropy_dns_domains():
    """Verify standard domains have low entropy while exfiltration payloads exceed 3.6."""
    benign_domain = "www.google.com"
    benign_entropy = calculate_entropy(benign_domain)
    assert benign_entropy < 3.6

    exfil_domain = "aW50ZWwuanNvbi5zZWNyZXRz.c2.attacker.com"
    exfil_entropy = calculate_entropy(exfil_domain)
    assert exfil_entropy > 3.6


# =====================================================================
# 2. PCAP Parsing & DataFrame Structure Tests
# =====================================================================

def test_parse_pcap_file_not_found():
    """Verify parse_pcap_to_dataframe raises FileNotFoundError for non-existent files."""
    with pytest.raises(FileNotFoundError):
        parse_pcap_to_dataframe("non_existent_path.pcap")


def test_parse_sample_pcap():
    """Verify parsing data/sample.pcap returns a DataFrame with all required columns."""
    sample_path = Path(__file__).resolve().parent.parent / "data" / "sample.pcap"
    assert sample_path.exists(), f"Sample pcap missing at: {sample_path}"

    df = parse_pcap_to_dataframe(str(sample_path))

    assert isinstance(df, pd.DataFrame)
    assert not df.empty
    assert len(df) >= 100

    # Ensure all required columns are present
    for col in REQUIRED_COLUMNS:
        assert col in df.columns, f"Required column '{col}' is missing in DataFrame"

    # Layer 2 MAC addresses should be present
    assert "src_mac" in df.columns
    assert "dst_mac" in df.columns

    # Verify types and non-null values for core telemetry
    assert pd.api.types.is_float_dtype(df["timestamp"])
    assert pd.api.types.is_integer_dtype(df["length"])
    assert set(df["protocol"].unique()).issuperset({"TCP", "UDP", "DNS", "ARP"})


# =====================================================================
# 3. Vectorized Anomaly Detection Tests
# =====================================================================

def test_detect_anomalies_empty_df():
    """Verify detect_anomalies gracefully handles empty DataFrames."""
    empty_df = pd.DataFrame(columns=REQUIRED_COLUMNS)
    anomalies = detect_anomalies(empty_df)
    assert anomalies == []


def test_detect_anomalies_clean_traffic():
    """Verify normal benign traffic triggers no security alerts."""
    clean_df = pd.DataFrame([
        {
            "timestamp": 1700000000.0,
            "protocol": "TCP",
            "src_ip": "192.168.1.10",
            "dst_ip": "93.184.216.34",
            "src_port": 50000,
            "dst_port": 80,
            "tcp_flags": 2,  # SYN
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 64,
            "src_mac": "00:11:22:33:44:01",
            "dst_mac": "00:11:22:33:44:02",
        },
        {
            "timestamp": 1700000000.1,
            "protocol": "DNS",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 53000,
            "dst_port": 53,
            "tcp_flags": None,
            "dns_query": "example.com",
            "dns_entropy": 2.7,
            "length": 72,
            "src_mac": "00:11:22:33:44:01",
            "dst_mac": "00:11:22:33:44:02",
        },
    ])
    anomalies = detect_anomalies(clean_df, flood_threshold=50)
    assert anomalies == []


def test_detect_stealth_null_scans():
    """Verify vectorized detection of TCP NULL scans (flags=0x00)."""
    df = pd.DataFrame([
        {
            "timestamp": 1700000000.0,
            "protocol": "TCP",
            "src_ip": "10.0.0.99",
            "dst_ip": "192.168.1.10",
            "src_port": 40001,
            "dst_port": 22,
            "tcp_flags": 0,  # flags=0x00
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 54,
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "aa:bb:cc:dd:ee:02",
        },
        {
            "timestamp": 1700000000.1,
            "protocol": "TCP",
            "src_ip": "10.0.0.99",
            "dst_ip": "192.168.1.10",
            "src_port": 40002,
            "dst_port": 80,
            "tcp_flags": 2,  # Normal SYN packet
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 60,
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "aa:bb:cc:dd:ee:02",
        },
    ])
    anomalies = detect_anomalies(df)
    assert len(anomalies) == 1
    alert = anomalies[0]
    assert alert["type"] == "Stealth TCP NULL Scan"
    assert alert["severity"] == "HIGH"
    assert alert["source"] == "10.0.0.99"
    assert alert["destination"] == "192.168.1.10"
    assert "22" in alert["details"]


def test_detect_stealth_xmas_scans():
    """Verify vectorized detection of TCP XMAS scans (flags=0x29 / FIN+PSH+URG)."""
    df = pd.DataFrame([
        {
            "timestamp": 1700000000.0,
            "protocol": "TCP",
            "src_ip": "10.0.0.99",
            "dst_ip": "192.168.1.10",
            "src_port": 40001,
            "dst_port": 443,
            "tcp_flags": 0x29,  # 41
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 54,
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "aa:bb:cc:dd:ee:02",
        },
        {
            "timestamp": 1700000000.1,
            "protocol": "TCP",
            "src_ip": "10.0.0.99",
            "dst_ip": "192.168.1.10",
            "src_port": 40002,
            "dst_port": 445,
            "tcp_flags": "FPU",  # String flag representation
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 54,
            "src_mac": "aa:bb:cc:dd:ee:01",
            "dst_mac": "aa:bb:cc:dd:ee:02",
        },
    ])
    anomalies = detect_anomalies(df)
    assert len(anomalies) == 2
    for alert in anomalies:
        assert alert["type"] == "Stealth TCP XMAS Scan"
        assert alert["severity"] == "HIGH"
        assert alert["source"] == "10.0.0.99"


def test_detect_dns_tunneling():
    """Verify detection of DNS exfiltration via Shannon entropy > 3.6."""
    df = pd.DataFrame([
        {
            "timestamp": 1700000000.0,
            "protocol": "DNS",
            "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8",
            "src_port": 53000,
            "dst_port": 53,
            "tcp_flags": None,
            "dns_query": "aW50ZWwuanNvbi5zZWNyZXRz.c2.attacker.com",
            "dns_entropy": 4.45,
            "length": 85,
            "src_mac": "aa:bb:cc:00:00:01",
            "dst_mac": "aa:bb:cc:00:00:02",
        },
        {
            "timestamp": 1700000000.1,
            "protocol": "DNS",
            "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8",
            "src_port": 53001,
            "dst_port": 53,
            "tcp_flags": None,
            "dns_query": "www.wikipedia.org",
            "dns_entropy": 3.10,
            "length": 65,
            "src_mac": "aa:bb:cc:00:00:01",
            "dst_mac": "aa:bb:cc:00:00:02",
        },
    ])
    anomalies = detect_anomalies(df, entropy_threshold=3.6)
    assert len(anomalies) == 1
    alert = anomalies[0]
    assert alert["type"] == "DNS Tunneling"
    assert alert["severity"] == "HIGH"
    assert alert["source"] == "192.168.1.50"
    assert "aW50ZWwuanNvbi5zZWNyZXRz" in alert["details"]


def test_detect_arp_cache_poisoning():
    """Verify detection of conflicting ARP responses for the same IP."""
    df = pd.DataFrame([
        {
            "timestamp": 1700000000.0,
            "protocol": "ARP",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.10",
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 42,
            "src_mac": "00:50:56:c0:00:01",
            "dst_mac": "00:0c:29:ab:cd:ef",
        },
        {
            "timestamp": 1700000000.1,
            "protocol": "ARP",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.10",
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 42,
            "src_mac": "de:ad:be:ef:13:37",  # Rogue MAC claiming same IP
            "dst_mac": "00:0c:29:ab:cd:ef",
        },
    ])
    anomalies = detect_anomalies(df)
    assert len(anomalies) == 1
    alert = anomalies[0]
    assert alert["type"] == "ARP Cache Poisoning"
    assert alert["severity"] == "CRITICAL"
    assert alert["source"] == "192.168.1.1"
    assert "00:50:56:c0:00:01" in alert["details"]
    assert "de:ad:be:ef:13:37" in alert["details"]


def test_detect_volumetric_flooding():
    """Verify detection of high-frequency talkers / packet flooding."""
    records = []
    # 30 packets from flooded attacker
    for i in range(30):
        records.append({
            "timestamp": 1700000000.0 + (i * 0.01),
            "protocol": "UDP",
            "src_ip": "192.168.1.250",
            "dst_ip": "192.168.1.10",
            "src_port": 10000 + i,
            "dst_port": 80,
            "tcp_flags": None,
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 100,
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "dst_mac": "11:22:33:44:55:66",
        })
    # 2 packets from normal host
    for i in range(2):
        records.append({
            "timestamp": 1700000000.0 + (i * 0.01),
            "protocol": "UDP",
            "src_ip": "192.168.1.15",
            "dst_ip": "192.168.1.10",
            "src_port": 20000 + i,
            "dst_port": 80,
            "tcp_flags": None,
            "dns_query": None,
            "dns_entropy": 0.0,
            "length": 100,
            "src_mac": "aa:bb:cc:dd:ee:00",
            "dst_mac": "11:22:33:44:55:66",
        })

    df = pd.DataFrame(records)
    # Set flood_threshold to 20 to trigger anomaly
    anomalies = detect_anomalies(df, flood_threshold=20)
    assert len(anomalies) == 1
    alert = anomalies[0]
    assert alert["type"] == "Volumetric Flooding"
    assert alert["source"] == "192.168.1.250"
    assert "30 packets" in alert["details"]


# =====================================================================
# 4. End-to-End Synthetic Trace Validation
# =====================================================================

def test_full_pipeline_on_sample_pcap():
    """
    End-to-end integration test: parses data/sample.pcap and ensures
    all 5 suspicious behaviors are flagged.
    """
    sample_path = Path(__file__).resolve().parent.parent / "data" / "sample.pcap"
    df = parse_pcap_to_dataframe(str(sample_path))
    anomalies = detect_anomalies(df, flood_threshold=50, entropy_threshold=3.6)

    assert len(anomalies) > 0

    anomaly_types = {a["type"] for a in anomalies}
    assert "Stealth TCP NULL Scan" in anomaly_types
    assert "Stealth TCP XMAS Scan" in anomaly_types
    assert "DNS Tunneling" in anomaly_types
    assert "ARP Cache Poisoning" in anomaly_types
    assert "Volumetric Flooding" in anomaly_types

    # Ensure every single anomaly conforms to the structured dictionary schema
    required_keys = {"type", "severity", "source", "destination", "details"}
    for alert in anomalies:
        assert required_keys.issubset(alert.keys())
        assert alert["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"}
        assert alert["source"] is not None
        assert alert["destination"] is not None
        assert len(alert["details"]) > 0
