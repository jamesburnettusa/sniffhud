# SniffHud

**SniffHud** is a real-time network monitoring tool designed to detect, track, and highlight potentially privacy-invasive connections on your network. This tool provides detailed insights into network traffic, DNS lookups, and geolocation information for destination IPs, all while keeping sensitive data handling transparent and privacy-conscious.

---

## Table of Contents

- [Features](#features)   
- [Installation](#installation)  
- [Usage](#usage)  
- [Configuration](#configuration)  
- [License](#license)  

---

## Features

- **Real-time Packet Capture**: Monitors both IPv4 and IPv6 traffic on a specified network interface.  
- **DNS Resolution**: Performs reverse DNS lookups to identify destination hostnames.  
- **IP Information Lookup**: Uses `ipinfo.io` (optionally with a token) to fetch country and organization info for destination IPs.  
- **Blacklist Detection**: Flags connections to known malicious or suspicious domains using customizable blacklists.  
- **Interactive Terminal UI**: Displays captured data in a curses-based interface, highlighting suspicious or foreign traffic.  
- **Packet Classification**: Prioritizes potentially malicious or non-US traffic and displays it in an easy-to-read table.  
- **Caching**: Caches IP information locally to minimize repeated network requests and protect privacy.  


---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/jamesburnettusa/sniffhud.git
cd sniffhud
```

2. Install dependencies (Linux):

```bash
pip install pcapy dpkt requests
```

> **Note:** You must run the program with sufficient privileges to capture packets (e.g., using `sudo` on Linux).  

---

## Usage

```bash
python sniffhud.py -i <network_interface> [-s <src_ip>] [-o <origin_country>] [-ip <ipinfo_token>]
```

### Example:

```bash
sudo python sniffhud.py -i eth0 -o US
```

- `-i / --iface`: Network interface to capture packets from. **Required**.  
- `-s / --src-ip`: Optional. Only monitor traffic from a specific source IP.  
- `-o / --origin-country`: Set your origin country code (default: `US`). Traffic from non-US hosts is highlighted.  
- `-ip / --token`: Optional ipinfo.io token for enhanced IP geolocation.  

---

## Configuration

- **Blacklists**: Place URLs of blacklist text files in `blacklists.txt`, one per line. Each URL should point to a plain text file containing domain names to block or monitor.  

- **Color Codes in UI**:  
  - **Red** → Potentially malicious host (found in blacklist).  
  - **Yellow** → Non-US traffic.  
  - **Normal** → Local/US traffic.  

---

## License

This project is licensed under the MIT License. See `LICENSE` for more details.  

---

**Disclaimer:** SniffHud is intended for network monitoring and educational purposes. Ensure you have permission to monitor network traffic on any network where you deploy this tool.