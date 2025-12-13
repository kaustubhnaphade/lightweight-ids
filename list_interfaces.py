"""
List Network Interfaces Helper Script
Shows all available network interfaces for live capture
"""

from scapy.all import get_if_list, conf
import sys

def list_interfaces():
    """List all available network interfaces"""
    print("\n" + "="*60)
    print("Available Network Interfaces")
    print("="*60)
    
    try:
        # Get all interfaces
        interfaces = get_if_list()
        
        if not interfaces:
            print("[!] No network interfaces found!")
            print("[!] Make sure Npcap/WinPcap is installed")
            return
        
        print(f"\nFound {len(interfaces)} interface(s):\n")
        
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        
        print("\n" + "="*60)
        print("\nUsage example:")
        print('  py ids_engine.py --interface "<interface_name>" --duration 60')
        print("\nNote: Copy the EXACT interface name from the list above")
        print("="*60)
        
        # Show default interface
        try:
            default_iface = conf.iface
            print(f"\nDefault interface: {default_iface}")
        except:
            pass
            
    except Exception as e:
        print(f"[!] Error listing interfaces: {e}")
        print("[!] Make sure you have Npcap installed:")
        print("    https://npcap.com/#download")

if __name__ == '__main__':
    list_interfaces()
