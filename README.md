# Packet Spectre - Advanced Network Traffic and Security Forensics Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.100.0+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Scapy-2.5.0+-00A3E0?style=for-the-badge&logo=scapy&logoColor=white" alt="Scapy" />
  <img src="https://img.shields.io/badge/DeepSeek_AI-Integrated-a855f7?style=for-the-badge&logo=openai&logoColor=white" alt="DeepSeek AI" />
  <img src="https://img.shields.io/badge/Frontend-Glassmorphism-blue?style=for-the-badge" alt="Frontend" />
</p>

---

## Overview

Packet Spectre is an integrated platform for network traffic analysis, network intrusion detection (NIDS), and network digital forensics (Network Forensics & DFIR). Designed to surpass traditional analysis limits, the platform provides an interactive and highly polished web interface featuring a modern glassmorphism design, coupled with full DeepSeek AI integration to generate instant investigative incident response reports.

---

## Key Features

### 1. Intelligent Analysis and Reporting with DeepSeek AI
* **Automated Investigation Report**: The system compiles a statistical and engineering summary of detected network threats and triggers the DeepSeek AI engine to generate a comprehensive digital forensics investigation report.
* **Executive Summary and IR Guidelines**: The generated report contains a high-level executive summary along with actionable, step-by-step instructions to contain compromised devices and secure the network path.

### 2. Network Digital Forensics (DFIR)
* **Hex and ASCII Dump Replay**: Generates a classic packet byte viewer (Wireshark-style) for payloads that triggered security alerts or data leaks, allowing immediate manual verification.
* **DNS Spoofing and Hijacking Detection**: Tracks DNS resolutions and triggers immediate warnings upon detecting mismatched or suspicious dual-resolution responses.
* **High Ratio Data Exfiltration Flow Audit**: Monitors and computes the ratio of uploaded versus downloaded data for local hosts communicating with external servers to detect document exfiltration.
* **DHCP Hostname Discovery**: Parses DHCP option fields to dynamically map local IP addresses to actual device hostnames.
* **Command and Control (C2) Beaconing Detection**: Analyzes connection intervals over time using standard deviation heuristics (StdDev) to identify stealthy, periodic C2 beaconing check-ins.
* **Network File Carving**: Automatically detects and catalogs files in transit (Windows EXE/DLL, Linux ELF, ZIP, PDF, PNG/JPEG).
* **OS Fingerprint Mismatch Detection**: Compares network layer TTL values against application layer User-Agent strings to flag attempts at device identity spoofing.

### 3. Network Intrusion Detection (NIDS)
* **Web Attacks**: Detects common web application vulnerabilities including SQLi, XSS, LFI, RFI, SSRF, Log4j, and the Shellshock exploit.
* **DDoS Flooding Alerts**: Triggers real-time alerts for TCP SYN, UDP, and ICMP flood attacks.
* **Cryptomining Protocol Audit**: Identifies JSON-RPC Stratum commands and resolves DNS requests pointing to cryptocurrency mining pools.
* **SMB and Ransomware Auditing**: Monitors NTLM authentication failures and tracks high-frequency SMB write operations to identify active ransomware encryption campaigns.
* **Data Loss Prevention (DLP)**: Scans unencrypted traffic for credit cards, cloud credentials (AWS, Google Cloud), and cleartext credentials.
* **Attack Tool Fingerprinting**: Automatically flags reconnaissance and exploitation tools (Nmap, Sqlmap, Nikto, Cobalt Strike, Sliver, Havoc, Hydra).

---

## Project Directory Structure

```plaintext
packet-spectre/
├── backend/
│   ├── analyzer.py       # Core packet parsing and threat logic engine
│   ├── main.py           # FastAPI server and REST endpoints
│   ├── config.json       # Local configuration file (contains DeepSeek API Key)
│   └── requirements.txt  # Python package requirements
├── frontend/
│   ├── index.html        # Interactive dashboard web interface
│   ├── css/
│   │   └── style.css     # Glassmorphism frontend stylesheets
│   └── js/
│       └── app.js        # UI rendering, charts, and asynchronous API calls
└── run_packet_spectre.bat # Single-click Windows startup batch script
```

---

## Installation and Setup

The platform is designed to launch with a single click on Windows environments:

1. **Download the Project**: Clone or download the repository to your local system.
2. **Launch Server**:
   Double-click the startup script:
   `run_packet_spectre.bat`
   * *This script automatically creates a Python virtual environment, installs dependencies, starts the FastAPI web server, and opens your default browser at `http://127.0.0.1:8000`.*
3. **Configure API Key**:
   * Open the configuration file `backend/config.json`.
   * Insert your DeepSeek API key and save the file.
   * Upload your PCAP capture file on the dashboard and trigger the AI analysis.

---

## Tech Stack

* **Backend**: Python, FastAPI, Scapy, Uvicorn.
* **Frontend**: HTML5, Vanilla CSS3 (Glassmorphism), Vanilla Javascript.
* **Visualizations**: Chart.js (Interactive Doughnut charts).
* **Typography**: Outfit & Tajawal Google Fonts.
* **Icons**: FontAwesome 6.4.0.

---

## License

This project is licensed under the MIT License. For details, please consult the LICENSE file.
