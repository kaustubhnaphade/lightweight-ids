"""
Generate a PCAP file with only normal traffic (no attacks)
This will help test that the log file gets updated even with 0 alerts
"""

from scapy.all import IP, TCP, wrpcap
import random

def generate_normal_traffic_only(count=100):
    """Generate benign normal traffic"""
    packets = []
    
    for i in range(count):
        src_ip = f"192.168.1.{random.randint(10, 50)}"
        dst_ip = f"10.0.0.{random.randint(10, 50)}"
        
        # Normal TCP handshake - SYN-ACK and ACK packets
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(
            sport=random.randint(1024, 65535), 
            dport=random.choice([80, 443, 22, 53]),
            flags=random.choice(['SA', 'A', 'PA'])  # SYN-ACK, ACK, PSH-ACK
        )
        packets.append(pkt)
    
    return packets

def main():
    """Generate normal traffic PCAP"""
    print("[*] Generating normal traffic PCAP file...")
    
    packets = generate_normal_traffic_only(100)
    
    output_file = "normal_traffic.pcap"
    wrpcap(output_file, packets)
    
    print(f"[+] Created: {output_file}")
    print(f"[+] Total packets: {len(packets)}")
    print("[+] This file contains ONLY normal traffic (no attacks)")
    print("\n[*] Run: py ids_engine.py --pcap normal_traffic.pcap")
    print("[*] Expected: 0 alerts (file should still be updated)")

if __name__ == '__main__':
    main()
