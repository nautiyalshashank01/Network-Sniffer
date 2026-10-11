# Custom Python Packet Sniffer & Traffic Analyzer

## What It Is
A lightweight command-line network traffic analyzer built in Python using the **Scapy** library. It captures incoming and outgoing network packets on your local machine in real time, parses core headers (such as IP, TCP, and UDP), and prints a live summary to your terminal. It also includes built-in security alerts for unencrypted traffic flows (like port 80 HTTP requests).

## How It Is Useful
* **Telemetry & Troubleshooting:** Mimics foundational network telemetry tools used by engineers to inspect active data flows and diagnose connectivity.
* **Security Awareness:** Helps identify unencrypted protocols and monitor which external servers your device is actively communicating with.
* **Educational Tool:** Provides a hands-on introduction to packet sniffing, networking layers, and Python scripting.

---

## Prerequisites & Dependencies
Before running the script, make sure you have the following installed on your system:
1. **Python** (v3.x)
2. **Scapy Library**: Install it via your terminal by running:
   ```bash
   pip install scapy
