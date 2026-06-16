# 🚨 IP/ARP Spoofing Detection Tool

A desktop graphical user interface (GUI) application built in Python designed to monitor local network traffic and detect ARP/IP spoofing attacks in real-time. The tool scans the local subnet, maps IP addresses to their corresponding MAC addresses, and alerts the user if malicious MAC address modifications occur.

## 🛠️ Key Technical Features
- **Local Subnet Mapping:** Automatically identifies the host's local IP and scans the `/24` subnet using ARP requests to build a baseline IP-to-MAC mapping.
- **Real-Time Packet Sniffing:** Utilizes `scapy`'s `AsyncSniffer` to continuously monitor local network traffic for unsolicited ARP replies.
- **Asynchronous Monitoring:** Runs the network scanning and sniffing engines on background threads to prevent the GUI from freezing.
- **Automated Security Audits:** Features a one-click 60-second automated monitoring window that safely stops sniffing and reports the final network status.
- **Interactive GUI:** Built with `Tkinter`, featuring a live scrolling log, dynamic status indicators, and a toggleable Dark/Light mode theme.

## 🧰 Built With
- **Language:** Python 3
- **GUI Engine:** Tkinter
- **Core Networking:** `scapy`, `socket`, `psutil`

## 🚀 Installation & Usage

### Prerequisites
- Python 3.10+ installed
- Npcap (Windows) or libpcap (Linux/Mac) required for raw network socket access

### Setup

1. Clone this repository:
```bash
git clone https://github.com/Ash-Hackz/ip-spoof-detector.git
cd ip-spoof-detector
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Execute the tool:
```bash
python app.py
```

## 📄 License
This project is licensed under the MIT License.
