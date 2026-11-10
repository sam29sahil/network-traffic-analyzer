#!/usr/bin/env python3
"""
generate_pcap.py: Synthetic PCAP generator for Network Traffic Analyzer.
Produces realistic network traffic traces containing both benign flows and
attack vectors (stealth scans, DNS exfiltration, ARP spoofing, flood anomalies).
"""

import os
from pathlib import Path
import logging

# Suppress scapy warnings and runtime IPv6/route noise
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (
    conf,
    wrpcap,
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    ARP,
    Raw,
)

conf.verb = 0


def generate_sample_pcap(output_path: str = "data/sample.pcap") -> str:
    """
    Generates a realistic synthetic PCAP file with benign traffic and attack scenarios:
    1. Standard HTTP & DNS benign traffic.
    2. Stealth TCP NULL scan (flags=0x00).
    3. Stealth TCP XMAS scan (flags=0x29 / FIN+PSH+URG).
    4. High-entropy DNS exfiltration queries (Shannon entropy > 3.6).
    5. Conflicting ARP responses (Layer 2 ARP cache poisoning / spoofing).
    6. Volumetric traffic flooding (high-frequency talker).
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    packets = []
    base_time = 1700000000.0

    gateway_ip = "192.168.1.1"
    gateway_mac = "00:50:56:c0:00:01"
    victim_ip = "192.168.1.10"
    victim_mac = "00:0c:29:ab:cd:ef"
    attacker_ip = "10.0.0.99"
    attacker_mac = "00:0c:29:66:66:66"
    dns_server = "8.8.8.8"

    # ---------------------------------------------------------
    # 1. Benign Traffic (DNS & HTTP)
    # ---------------------------------------------------------
    # Normal DNS lookup: google.com
    pkt_dns1 = (
        Ether(src=victim_mac, dst=gateway_mac)
        / IP(src=victim_ip, dst=dns_server)
        / UDP(sport=53210, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="www.google.com"))
    )
    pkt_dns1.time = base_time + 0.01
    packets.append(pkt_dns1)

    pkt_dns1_resp = (
        Ether(src=gateway_mac, dst=victim_mac)
        / IP(src=dns_server, dst=victim_ip)
        / UDP(sport=53, dport=53210)
        / DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname="www.google.com"),
              an=DNSRR(rrname="www.google.com", rdata="142.250.190.46"))
    )
    pkt_dns1_resp.time = base_time + 0.03
    packets.append(pkt_dns1_resp)

    # Normal DNS lookup: api.github.com
    pkt_dns2 = (
        Ether(src=victim_mac, dst=gateway_mac)
        / IP(src=victim_ip, dst=dns_server)
        / UDP(sport=53211, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="api.github.com"))
    )
    pkt_dns2.time = base_time + 0.10
    packets.append(pkt_dns2)

    # Benign HTTP connection (SYN -> SYN-ACK -> ACK -> GET)
    http_server_ip = "93.184.216.34"
    http_sport = 49152

    # SYN
    syn = (
        Ether(src=victim_mac, dst=gateway_mac)
        / IP(src=victim_ip, dst=http_server_ip)
        / TCP(sport=http_sport, dport=80, flags="S", seq=1000)
    )
    syn.time = base_time + 0.20
    packets.append(syn)

    # SYN-ACK
    synack = (
        Ether(src=gateway_mac, dst=victim_mac)
        / IP(src=http_server_ip, dst=victim_ip)
        / TCP(sport=80, dport=http_sport, flags="SA", seq=2000, ack=1001)
    )
    synack.time = base_time + 0.23
    packets.append(synack)

    # ACK
    ack = (
        Ether(src=victim_mac, dst=gateway_mac)
        / IP(src=victim_ip, dst=http_server_ip)
        / TCP(sport=http_sport, dport=80, flags="A", seq=1001, ack=2001)
    )
    ack.time = base_time + 0.25
    packets.append(ack)

    # HTTP GET
    http_req = (
        Ether(src=victim_mac, dst=gateway_mac)
        / IP(src=victim_ip, dst=http_server_ip)
        / TCP(sport=http_sport, dport=80, flags="PA", seq=1001, ack=2001)
        / Raw(load="GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    http_req.time = base_time + 0.26
    packets.append(http_req)

    # ---------------------------------------------------------
    # 2. Stealth TCP NULL Scans (flags=0x00)
    # ---------------------------------------------------------
    null_target_ports = [21, 22, 80, 443, 8080]
    for idx, port in enumerate(null_target_ports):
        null_pkt = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=50000 + idx, dport=port, flags=0)
        )
        null_pkt.time = base_time + 1.0 + (idx * 0.05)
        packets.append(null_pkt)

    # ---------------------------------------------------------
    # 3. Stealth TCP XMAS Scans (flags=0x29 / FIN+PSH+URG)
    # ---------------------------------------------------------
    xmas_target_ports = [23, 25, 110, 143, 3306]
    for idx, port in enumerate(xmas_target_ports):
        xmas_pkt = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=51000 + idx, dport=port, flags=0x29)
        )
        xmas_pkt.time = base_time + 2.0 + (idx * 0.05)
        packets.append(xmas_pkt)

    # ---------------------------------------------------------
    # 4. High-Entropy DNS Exfiltration Queries
    # ---------------------------------------------------------
    exfil_queries = [
        "aW50ZWwuanNvbi5zZWNyZXRz.c2.attacker.com",
        "ZXhwaWx0cmF0aW9uLWRhdGEtY2hlY2tzdW0=.c2.attacker.com",
        "ODhjZjkyMWE1MDU4MzAyOTExMmU4YmIzZjExOTIwMGI=.data.evilcorp.net",
    ]
    for idx, query in enumerate(exfil_queries):
        dns_exfil = (
            Ether(src=victim_mac, dst=gateway_mac)
            / IP(src=victim_ip, dst=dns_server)
            / UDP(sport=54000 + idx, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=query))
        )
        dns_exfil.time = base_time + 3.0 + (idx * 0.1)
        packets.append(dns_exfil)

    # ---------------------------------------------------------
    # 5. Layer 2 ARP Cache Poisoning / Spoofing
    # Conflicting ARP responses for the same IP claiming different MAC addresses
    # ---------------------------------------------------------
    # Legitimate ARP announcement / reply for gateway
    legit_arp = (
        Ether(src=gateway_mac, dst=victim_mac)
        / ARP(
            op=2,  # is-at
            psrc=gateway_ip,
            hwsrc=gateway_mac,
            pdst=victim_ip,
            hwdst=victim_mac,
        )
    )
    legit_arp.time = base_time + 4.0
    packets.append(legit_arp)

    # Spoofed ARP reply for same gateway IP claiming attacker MAC
    rogue_mac = "de:ad:be:ef:13:37"
    spoofed_arp = (
        Ether(src=rogue_mac, dst=victim_mac)
        / ARP(
            op=2,  # is-at
            psrc=gateway_ip,
            hwsrc=rogue_mac,
            pdst=victim_ip,
            hwdst=victim_mac,
        )
    )
    spoofed_arp.time = base_time + 4.05
    packets.append(spoofed_arp)

    # ---------------------------------------------------------
    # 6. Volumetric Anomalies (High-Frequency Flooding)
    # Attacker flooding the victim with a burst of packets
    # ---------------------------------------------------------
    flood_src_ip = "192.168.1.200"
    flood_src_mac = "aa:bb:cc:11:22:33"
    flood_count = 80
    for i in range(flood_count):
        flood_pkt = (
            Ether(src=flood_src_mac, dst=victim_mac)
            / IP(src=flood_src_ip, dst=victim_ip)
            / UDP(sport=40000 + (i % 1000), dport=9999)
            / Raw(load=b"FLOOD_PAYLOAD_" + str(i).encode())
        )
        flood_pkt.time = base_time + 5.0 + (i * 0.005)
        packets.append(flood_pkt)

    # Write trace to PCAP file
    wrpcap(str(output_file), packets)
    print(f"[+] Successfully generated synthetic PCAP at: {output_file} ({len(packets)} packets)")
    return str(output_file)


if __name__ == "__main__":
    import sys
    dest = sys.argv[1] if len(sys.argv) > 1 else "data/sample.pcap"
    generate_sample_pcap(dest)
