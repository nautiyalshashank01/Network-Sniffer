# 🛡️ Custom Python Packet Sniffer & Traffic Analyzer - Master Guide



---



## 📋 1. Project Overview & Benefits

* **What It Is:** A lightweight command-line network traffic analyzer built in Python using the **Scapy** library. It captures incoming and outgoing network packets on your local machine in real time, parses core headers (IP, TCP, UDP), logs events, and flags unencrypted traffic.

* **Why It Is Useful:** 

  * **Telemetry & Troubleshooting:** Mimics foundational network telemetry tools used by engineers to inspect active data flows.

  * **Security Awareness:** Helps identify unencrypted protocols and monitor external server communications.

  * **Educational Tool:** Provides a hands-on introduction to packet sniffing, networking layers, and Python scripting.



---



## ⚙️ 2. Prerequisites & System Setup

Before running the script, ensure you have the following installed:

1. **Python** (v3.x)

2. **Scapy Library:** Install it via your terminal by running:

   ```bash

   pip install scapy

   ```

3. **Npcap** *(Windows Users Only)*: Download and install [Npcap](https://nmap.org/npcap/). Make sure to check **"Install Npcap in WinPcap API-compatible Mode"** during setup.



---



## 💻 3. The Complete Python Script (`sniffer.py`)

Create a new file named **`sniffer.py`** in your project directory and paste this complete script:



```python

from datetime import datetime

from scapy.all import sniff

from scapy.layers.inet import IP, TCP, UDP



LOG_FILE = "traffic_log.txt"



def log_packet(summary_text):

    with open(LOG_FILE, "a") as f:

        f.write(f"[{datetime.now()}] {summary_text}\n")



def packet_callback(packet):

    if packet.haslayer(IP):

        ip = packet.getlayer(IP)

        src, dst = ip.src, ip.dst

        

        if packet.haslayer(TCP):

            sport, dport = packet[TCP].sport, packet[TCP].dport

            summary = f"TCP | {src}:{sport} ---> {dst}:{dport}"

            print(f"[+] {summary}")

            log_packet(summary)

            

            # Flag unencrypted HTTP traffic (Port 80)

            if dport == 80 or sport == 80:

                alert = f"[!] ALERT: Unencrypted HTTP traffic between {src} and {dst}"

                print(alert)

                log_packet(alert)

        elif packet.haslayer(UDP):

            summary = f"UDP | {src} ---> {dst}"

            print(f"[+] {summary}")

            log_packet(summary)



def main():

    print("Starting packet sniffer & traffic analyzer... Press Ctrl+C to stop.")

    sniff(prn=packet_callback, store=False)



if __name__ == "__main__":

    main()

```



---



## 🚀 4. Running Your Sniffer

Because packet sniffing interacts directly with your network card, administrative privileges are required:

* **On Windows:** Open your terminal (Command Prompt or PowerShell) **AS ADMINISTRATOR** and run:

  ```bash

  python sniffer.py

  ```

* **On macOS / Linux:** Run the script using root permissions (`sudo`):

  ```bash

  sudo python3 sniffer.py

  ```

* **To Stop:** Press **Ctrl + C** in your terminal window at any time.



---



## ❓ 5. Troubleshooting & Help

1. **`RuntimeError: winpcap is not installed` (Windows)**

   * **Cause:** Scapy cannot find the required packet capture driver
