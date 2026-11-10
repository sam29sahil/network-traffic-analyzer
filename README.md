# Network Traffic Analyzer & Forensic Anomaly Detection Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Packet%20Engine-Scapy-red.svg)](https://scapy.net/)
[![Pandas](https://img.shields.io/badge/Analytics-Pandas-150458.svg)](https://pandas.pydata.org/)
[![Pytest](https://img.shields.io/badge/Testing-Pytest%20(13%20Passed)-green.svg)](https://docs.pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A modular, high-performance network packet forensics engine built in Python using **Scapy** and **Pandas**. The platform ingests packet captures (`.pcap`) and dissects multi-layer protocol headers into structured Pandas DataFrames to perform vectorized threat hunting, Shannon entropy analysis, and heuristic anomaly detection across Layers 2 through 7.

---

## Architecture Overview