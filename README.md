# CyberSniff Engine: A Real-Time Network Security & Traffic Analytics Monitor

# 🛡️ CyberSniff Engine v2.0

CyberSniff is a real-time, web-based Network Intrusion Detection System (NIDS) and packet analyzer. Built with Python and Flask, it captures live network traffic, identifies device manufacturers, tracks Geo-IP locations, and alerts users to potential network floods—all through a sleek, neon-styled dashboard.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-brightgreen.svg)

## ✨ Key Features

* **Live Packet Sniffing:** Real-time capture of TCP, UDP, and ICMP traffic using the Scapy engine.
* **Intrusion Detection:** Automatic flagging of **External (Public) IPs** with a "Red Alert" status.
* **Vendor Identification:** Resolves MAC addresses to identify manufacturers (e.g., Apple, Samsung, LG).
* **Geo-IP Tracking:** Real-time country identification for all outgoing/incoming internet traffic.
* **Flood Detection:** Visual warnings for devices exceeding 80 packets per second (potential DDoS or heavy streaming).
* **Interactive Analytics:** * **Traffic Load Chart:** Real-time PPS (Packets Per Second) line graph.
    * **Protocol Distribution:** Doughnut chart showing the TCP/UDP/Other mix.
    * **Top Talkers:** A leaderboard of the most active devices on the network.

## 🚀 Getting Started

### Prerequisites

1.  **Python 3.11+**
2.  **Npcap (Windows Users):** Required for packet sniffing. [Download here](https://npcap.com/). 
    * *Note: Ensure "Install Npcap in WinPcap API-compatible Mode" is checked during installation.*

### Installation

1. Clone the repository: git clone https://github.com/MoriartyPuth/Cyber-Sniff-Engine
## 📄 Project Documentation
1. Project Overview

CyberSniff Engine is a specialized network monitoring tool designed to provide real-time visibility into local area network (LAN) traffic. Unlike standard text-based sniffers, CyberSniff translates raw binary data into a human-readable, visual dashboard. It acts as a lightweight Intrusion Detection System (IDS) by identifying external threats, device manufacturers, and network congestion (flooding).

2. Objectives

- Packet Inspection: Capture and parse live IP, TCP, and UDP packets.

- Security Auditing: Identify and flag non-local (external) traffic to detect unauthorized connections.

- Device Profiling: Map MAC addresses to known vendors (Apple, Samsung, LG, etc.) to identify "ghost" devices.

- Behavioral Analysis: Monitor "Packets Per Second" (PPS) to detect network flooding or potential DDoS attacks.

3. Key Technical Features

<div class="card" style="margin-top: 30px;">
    <div style="overflow-x: auto;">
        <table style="border: 1px solid #30363d;">
            <thead style="background: #1a1f26;">
                <tr>
                    <th style="color: var(--neon); width: 30%;">Engine Component</th>
                    <th style="color: var(--neon);">Technical Implementation & Logic</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Sniffing Engine</strong></td>
                    <td>Utilizes <strong>Scapy</strong> for low-level socket access. It operates in promiscuous mode to capture and dissect 802.3 Ethernet frames into IP, TCP, and UDP layers.</td>
                </tr>
                <tr>
                    <td><strong>Geo-IP Mapping</strong></td>
                    <td>Integrated <strong>IP-API</strong> interface. It performs asynchronous lookups to resolve public IP addresses into Country Codes and ISPs, providing a global footprint of traffic.</td>
                </tr>
                <tr>
                    <td><strong>Real-time UI Pipeline</strong></td>
                    <td>Powered by <strong>Flask-SocketIO</strong> (WebSockets). This creates a full-duplex communication channel, pushing packet data to the UI with sub-millisecond latency.</td>
                </tr>
                <tr>
                    <td><strong>OUI Vendor Lookup</strong></td>
                    <td>Uses a dictionary-based <strong>Organizationally Unique Identifier (OUI)</strong> database to map the first 24 bits of a MAC address to hardware manufacturers like Apple, Samsung, or LG.</td>
                </tr>
                <tr>
                    <td><strong>Threat Intel (Flood)</strong></td>
                    <td>Behavioral analysis engine that tracks <strong>PPS (Packets Per Second)</strong> per unique IP. Automatically triggers a "Flood Alert" state if traffic exceeds a 100-packet threshold.</td>
                </tr>
                <tr>
                    <td><strong>Data Persistence</strong></td>
                    <td>All captured sessions are streamed into a <strong>CSV Log</strong>. This ensures that network forensic data is saved even after the browser session is closed.</td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

4. System Architecture

Backend (Python): * A background thread runs the sniffer.

- A statistics thread calculates PPS and protocol counts every second.

- The Flask server handles user commands (Start/Stop/Clear).

Frontend (HTML/JS):

- Chart.js renders live intensity and distribution graphs.

- WebSocket listener dynamically updates the traffic table as packets arrive.

5. Methodology (How it works)

- Capture: The engine hooks into the network interface card (NIC) using the Npcap driver.

- Analyze: Each packet is "peeled" like an onion to find its Source IP, MAC address, and Port number.

- Enrich: The IP is checked against private IP ranges. If public, a Geo-IP lookup is performed. The MAC is checked against the OUI (Organizationally Unique Identifier) database.

- Visualize: The enriched data is sent to the dashboard, turning a line of code into a neon-colored security alert.

# 


