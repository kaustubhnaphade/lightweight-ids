"""
Debug IDS - Shows what packets are being captured in real-time
Use this to troubleshoot live capture issues
"""

import sys
from scapy.all import sniff, IP, TCP, conf, get_if_list
from datetime import datetime

def packet_callback(packet):
    """Print packet info"""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    if packet.haslayer(IP):
        ip = packet[IP]
        proto = "?"
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            proto = "TCP"
            flags = tcp.sprintf("%TCP.flags%")
            print(f"[{timestamp}] {proto:4s} {ip.src:15s}:{tcp.sport:5d} → {ip.dst:15s}:{tcp.dport:5d} [Flags: {flags}]")
        else:
            proto = packet.sprintf("%IP.proto%")
            print(f"[{timestamp}] {proto:4s} {ip.src:15s} → {ip.dst:15s}")
    else:
        print(f"[{timestamp}] Non-IP packet: {packet.summary()}")

def main():
    print("\n" + "="*80)
    print("DEBUG PACKET CAPTURE - Real-time packet viewer")
    print("="*80)
    print("\nThis tool shows ALL packets being captured by Scapy.")
    print("Use this to verify if your port scanner traffic is being seen.")
    print("\n" + "="*80)
    
    # List interfaces
    interfaces = get_if_list()
    print(f"\nAvailable Interfaces:")
    for i, iface in enumerate(interfaces, 1):
        marker = " (default)" if iface == conf.iface else ""
        print(f"  {i}. {iface}{marker}")
    
    # Choose interface
    print(f"\nDefault: {conf.iface}")
    choice = input("\nUse default interface? [Y/n]: ").strip().lower()
    
    if choice == 'n':
        try:
            idx = int(input(f"Enter interface number [1-{len(interfaces)}]: ")) - 1
            interface = interfaces[idx]
        except:
            print("Invalid choice, using default")
            interface = conf.iface
    else:
        interface = conf.iface
    
    print("\n" + "="*80)
    print(f"Capturing on: {interface}")
    print("Press Ctrl+C to stop")
    print("="*80 + "\n")
    
    try:
        # Capture with filter for faster processing
        sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        print("\n❌ ERROR: Permission denied!")
        print("   Please run this script as Administrator")
    except KeyboardInterrupt:
        print("\n\n✓ Capture stopped")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    main()
