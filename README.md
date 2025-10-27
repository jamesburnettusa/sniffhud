# snifhud
A real-time network connection monitor with a live web HUD, reverse DNS, and GeoIP country highlighting.

# 🕵️ snif.py — HUD-Style Network Sniffer

`snif.py` v1.8-pre is a Python-based **network sniffer** with a built-in **web dashboard (HUD)**.It shows live network traffic, performs **reverse DNS lookups**, **GeoIP country detection**, and highlights traffic **not from your country**.

The web UI provides interactive filters and quick links to WHOIS, Shodan, AbuseIPDB, and Geo lookup pages.

![snifHUD Screenshot](https://jamesburnettusa.com/wp-content/uploads/2025/10/snifHUD-screenshot.jpg)

---

## 🚀 Features

- Real-time packet capture (TCP and UDP)
- Reverse DNS resolution (asynchronous)
- GeoIP lookup via [ipinfo.io](https://ipinfo.io/)
- SQLite caching for hostnames and country codes
- Flask web interface for monitoring traffic
- Highlight foreign traffic based on your country code
- Clickable filters (FROM_IP / TO_IP / protocol)
- External lookup links:
  - [iplocation.net](https://www.iplocation.net/)
  - [bgp.he.net](https://bgp.he.net/)
  - [abuseipdb.com](https://www.abuseipdb.com/)
  - [shodan.io](https://www.shodan.io/)

---

## 🧩 Installation

### 1. Install system dependencies
You need `libpcap` for Scapy to capture packets.

On **Debian/Ubuntu**:
```bash
sudo apt install python3-pip python3-scapy libpcap-dev
```


On **Fedora**:
```bash
sudo dnf install python3-pip python3-scapy libpcap-devel
```



### 2. Install Python dependencies
```bash
sudo pip install flask scapy ipinfo
```

### 3. Usage
```bash
sudo python3 snif.py [options]
```

### Command-line Arguments

| Argument | Description | Default |
|-----------|--------------|----------|
| `--iface` | Network interface to sniff on (e.g., `eth0`, `wlan0`). | System default |
| `--db` | SQLite database file path for caching and connections. | `connections.db` |
| `--ipinfo-token` | Optional [ipinfo.io](https://ipinfo.io/) API token for GeoIP lookups. | None |
| `--filter` | Protocol filter: `tcp`, `udp`, or `both`. | `tcp` |
| `--country-code` | Your ISO 2-letter country code for highlighting foreign traffic. | `US` |

### Examples
Sniff TCP traffic on interface eth0:
```bash
sudo python3 snif.py --iface eth0
```

Sniff both TCP and UDP traffic, highlighting non-Canadian traffic:
```bash
sudo python3 snif.py --iface eth0 --filter both --country-code CA
```

Use an API token for more accurate GeoIP results:
```bash
sudo python3 snif.py --ipinfo-token <YOUR_TOKEN>
```