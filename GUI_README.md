# Lightweight IDS - GUI Version

This is the graphical user interface for the Lightweight Intrusion Detection System.

## Quick Start

### Option 1: Double-click the launcher (Easiest)
Simply double-click `Launch IDS GUI.bat` and the GUI will open.

### Option 2: Command line
```bash
py ids_gui.py
```

## Features

### Automatic Admin Elevation
- On startup, the GUI automatically requests administrator privileges
- Required for live network capture on Windows
- PCAP file analysis works without admin rights

### Two Operating Modes

#### 1. PCAP File Analysis
- Browse and select any .pcap or .pcapng file
- Analyze offline packet captures
- No admin rights required

#### 2. Live Network Capture
- Select network interface from dropdown
- Auto-detect option for automatic interface selection
- Set capture duration (in seconds)
- Optional packet count limit
- Requires admin privileges

### Real-Time Display
- Color-coded alert log
  - **Red**: CRITICAL/HIGH severity attacks
  - **Orange**: MEDIUM severity attacks
  - **Green**: Success messages
  - **Gray**: Info messages
- Live statistics updates
  - Packets processed
  - Total alerts
  - Runtime

### Controls
- **▶ Start Analysis**: Begin analyzing packets
- **⬛ Stop**: Stop ongoing analysis
- **Clear Log**: Clear all logs and reset statistics
- **Refresh**: Reload network interfaces

## GUI Layout

```
┌─────────────────────────────────────────────────┐
│  Configuration                                   │
│  ○ PCAP File Analysis  ○ Live Network Capture   │
│  PCAP File: [Browse...]                         │
│  Interface: [Auto-detect ▼] [Refresh]           │
│  Duration: 60s  Packet Limit: (optional)        │
├─────────────────────────────────────────────────┤
│  [▶ Start] [⬛ Stop] [Clear Log]    ● Status    │
├─────────────────────────────────────────────────┤
│  Statistics                                      │
│  Packets: 0  Alerts: 0  Runtime: 0s             │
├─────────────────────────────────────────────────┤
│  Alert Log                                       │
│  [Real-time color-coded alerts display]         │
│                                                  │
│                                                  │
└─────────────────────────────────────────────────┘
```

## Usage Examples

### Analyze a PCAP File
1. Select "PCAP File Analysis" mode
2. Click "Browse..." and select your .pcap file
3. Click "▶ Start Analysis"
4. Watch alerts appear in real-time

### Live Capture
1. Select "Live Network Capture" mode
2. Choose interface (use "Auto-detect" for default)
3. Set duration (e.g., 60 seconds)
4. Click "▶ Start Analysis"
5. Monitor network traffic in real-time

### Test with Sample Data
1. Use the provided `test_attacks.pcap` file
2. Should detect 3 attacks immediately
3. Review color-coded alerts

## Requirements

- Python 3.7 or higher
- Libraries: scapy, tkinter (included with Python)
- Windows administrator privileges (for live capture)

## Troubleshooting

### "Permission Denied" Error
**Solution**: Run as administrator
- Right-click `Launch IDS GUI.bat` → "Run as administrator"
- Or right-click Command Prompt → "Run as administrator" → `py ids_gui.py`

### "Interface not found" Error
**Solution**: Use auto-detect or refresh interfaces
1. Click "Refresh" button to reload interfaces
2. Select "Auto-detect" from dropdown
3. Ensure network adapter is enabled

### GUI doesn't start
**Solution**: Check Python installation
```bash
py --version
```
Should show Python 3.7+

## Admin Elevation

The GUI automatically handles admin elevation:

1. **First Launch**: Asks if you want to run as administrator
2. **If Yes**: Restarts with elevated privileges
3. **If No**: Continues with limited functionality
   - PCAP analysis: ✅ Works
   - Live capture: ❌ May fail

## Color Coding

- 🔴 **Red**: CRITICAL/HIGH severity (SYN flood, ICMP flood, DNS amp, ARP spoof)
- 🟡 **Orange**: MEDIUM severity (Port scan, TCP reset)
- 🟢 **Green**: Success messages
- ⚫ **Black/Gray**: Info messages

## Notes

- GUI runs analysis in background thread (non-blocking)
- Statistics update every 500ms
- Logs persist until manually cleared
- Safe to stop analysis at any time
