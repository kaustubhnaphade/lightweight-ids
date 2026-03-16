# Lightweight Intrusion Detection System (IDS)

A **pure Python-based** intrusion detection system that analyzes packet captures and detects classic network attack signatures using only **cybersecurity logic** - no machine learning, no heavy frameworks.


## Demo

<video src="Demo_video.mp4" controls="controls" style="max-width: 100%;">
</video>

To view this video in high quality click [here](https://drive.google.com/file/d/1ZwhzEItwaENoQrNmgrSOU4_ppRJzfmbo/view?usp=sharing).

## Features

✅ **Signature-Based Detection** for 6 classic attacks:
- **SYN Flood** - Detects half-open connection floods
- **Port Scanning** - Identifies reconnaissance attempts
- **ICMP Flood** - Detects ping floods and smurf attacks
- **ARP Spoofing** - Catches IP-MAC mapping conflicts
- **TCP Reset Attacks** - Monitors excessive RST packets
- **DNS Amplification** - Detects large DNS responses and query floods

✅ **Dual Mode Operation**:
- Offline PCAP file analysis
- Live network traffic capture

✅ **Lightweight Architecture**:
- Only 2 dependencies: Scapy + Colorama
- Pure packet-level logic with threshold-based detection
- Efficient memory management with automatic cleanup

✅ **Rich Alerting**:
- Color-coded console output (severity-based)
- JSON log file for forensic analysis
- Alert deduplication to prevent spam
- Detection statistics and summary

✅ **Graphical User Interface** (NEW!):
- Modern GUI with automatic admin elevation
- PCAP file browser and live capture modes
- Real-time color-coded alert display
- Statistics dashboard
- One-click operation

## Quick Start

### GUI Mode (Recommended for Beginners)

**Double-click** `Launch IDS GUI.bat` or run:
```bash
py ids_gui.py
```

The GUI will automatically request administrator privileges and provides:
- 📁 Easy PCAP file selection
- 🌐 Live network capture with auto-interface detection
- 📊 Real-time statistics
- 🎨 Color-coded alerts
- ⚙️ No command-line knowledge needed

See [GUI_README.md](GUI_README.md) for detailed GUI documentation.

### Command-Line Mode (For Advanced Users)

```bash
# Quick test with sample data
py ids_engine.py --pcap test_attacks.pcap

# Live capture with auto-detect
py ids_engine.py --interface auto --duration 60
```

## Installation

### Prerequisites
- Python 3.7 or higher
- Administrator/root privileges (for live capture)

### Setup

```bash
# Clone or download the project
cd "C:\Users\KIIT\Desktop\hackathon problem 1"

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Analyze a PCAP File

```bash
python ids_engine.py --pcap sample.pcap
```

### Live Network Capture

```bash
# Capture for 60 seconds
python ids_engine.py --interface eth0 --duration 60

# Capture 1000 packets
python ids_engine.py --interface eth0 --count 1000

# Continuous capture (Ctrl+C to stop)
python ids_engine.py --interface eth0
```

**Note**: Live capture requires administrator/root privileges:
- **Windows**: Run Command Prompt as Administrator
- **Linux/Mac**: Use `sudo python ids_engine.py ...`

### Get Help

```bash
python ids_engine.py --help
```

## Detection Logic

### SYN Flood Detection
- **Signature**: >100 SYN packets from single source in 10 seconds
- **Logic**: Tracks SYN packets without corresponding SYN-ACK or ACK
- **Severity**: HIGH

### Port Scan Detection
- **Signature**: >20 unique destination ports from single source in 5 seconds
- **Logic**: Monitors connection attempts to different ports (vertical scan)
- **Severity**: MEDIUM

### ICMP Flood Detection
- **Signature**: >100 ICMP packets per second from single source
- **Logic**: Time-windowed ICMP packet rate monitoring
- **Severity**: HIGH

### ARP Spoofing Detection
- **Signature**: Same IP address mapped to different MAC addresses
- **Logic**: Maintains ARP cache and detects IP-MAC conflicts
- **Severity**: CRITICAL

### TCP Reset Attack Detection
- **Signature**: >50 RST packets from single source in 5 seconds
- **Logic**: Monitors TCP RST flag frequency
- **Severity**: MEDIUM

### DNS Amplification Detection
- **Signature**: 
  - DNS responses >512 bytes
  - >50 DNS queries per second to single resolver
- **Logic**: DNS packet size analysis and query rate limiting
- **Severity**: HIGH

## Configuration

Edit `config.py` to customize detection thresholds:

```python
# Example: Adjust SYN flood sensitivity
SYN_FLOOD_THRESHOLD = 150  # Default: 100
SYN_FLOOD_WINDOW = 15      # Default: 10 seconds
```

All thresholds are configurable for different network environments.

## Output

### Console Output
Color-coded alerts displayed in real-time:
- 🔴 **CRITICAL** (Red, Bright) - ARP Spoofing
- 🔴 **HIGH** (Red) - SYN Flood, ICMP Flood, DNS Amplification
- 🟡 **MEDIUM** (Yellow) - Port Scan, TCP Reset Attack

### JSON Log File
Alerts saved to `ids_alerts.json` in structured format:

```json
{
  "timestamp": "2025-12-13T11:30:00.123456",
  "attack_type": "SYN_FLOOD",
  "severity": "HIGH",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.50",
  "additional_info": {
    "syn_count": 150,
    "time_window": "10s",
    "description": "Possible SYN flood attack detected"
  }
}
```

### Summary Statistics
After analysis, view detection summary:
```
==============================================================
IDS DETECTION SUMMARY
==============================================================
Runtime: 12.34 seconds
Total Alerts: 15
Alerts per Minute: 72.96

Alerts by Type:
  - SYN_FLOOD: 8 (HIGH)
  - PORT_SCAN: 5 (MEDIUM)
  - ICMP_FLOOD: 2 (HIGH)
==============================================================
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    IDS Engine                           │
│                  (ids_engine.py)                        │
└─────────────────────────────────────────────────────────┘
                          │
                          ├─────────────────┐
                          │                 │
                          ▼                 ▼
            ┌──────────────────────┐  ┌──────────────────┐
            │  Packet Analyzer      │  │  Config Manager  │
            │ (packet_analyzer.py)  │  │   (config.py)    │
            └──────────────────────┘  └──────────────────┘
                          │
                          ▼
            ┌──────────────────────────────┐
            │   Signature Detector          │
            │  (signature_detector.py)      │
            └──────────────────────────────┘
                          │
                          ▼
            ┌──────────────────────────────┐
            │     Alert Logger              │
            │   (alert_logger.py)           │
            └──────────────────────────────┘
```

## Project Structure

```
hackathon problem 1/
├── ids_engine.py           # Main orchestrator and CLI
├── ids_gui.py              # GUI application (NEW!)
├── packet_analyzer.py      # Deep packet inspection
├── signature_detector.py   # Attack detection logic
├── alert_logger.py         # Alert management
├── config.py               # Configuration and thresholds
├── list_interfaces.py      # Network interface helper
├── generate_test_pcap.py   # Test data generator
├── requirements.txt        # Dependencies
├── Launch IDS GUI.bat      # GUI launcher (NEW!)
├── README.md               # Main documentation
├── GUI_README.md           # GUI documentation (NEW!)
├── test_attacks.pcap       # Sample test file
└── ids_alerts.json         # Alert log (generated)
```

## Limitations

- **Encrypted Traffic**: Cannot inspect encrypted payloads (HTTPS, VPN)
- **Known Signatures Only**: Detects classic attacks, not zero-day exploits
- **Threshold Tuning**: May require adjustment for high-traffic networks
- **No Prevention**: Detection only - does not block attacks
- **IPv4 Only**: Currently supports IPv4 (IPv6 support can be added)

## Future Enhancements

- IPv6 support
- HTTP/HTTPS anomaly detection
- Fragmentation attack detection
- Slow-scan detection (low-and-slow attacks)
- Integration with firewall for automatic blocking
- Web dashboard for real-time monitoring

## Testing

### Generate Test Traffic

You can test the IDS using network tools:

```bash
# Port scan (triggers PORT_SCAN alert)
nmap -sS -p 1-100 <target_ip>

# Ping flood (triggers ICMP_FLOOD alert)
hping3 -1 --flood <target_ip>

# SYN flood (triggers SYN_FLOOD alert)
hping3 -S --flood -p 80 <target_ip>
```

### Sample PCAP Files

Download sample attack PCAP files from:
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)

## License

This project is for educational and research purposes.

---

**Cybersecurity Note**: This IDS is designed as a lightweight detection tool. For production environments, consider using comprehensive solutions like Snort, Suricata, or Zeek alongside this tool.
