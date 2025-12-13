"""
Simple test script to verify IDS functionality
Creates synthetic packet data to test detection logic
"""

from scapy.all import IP, TCP, ICMP, ARP, Ether, wrpcap
import random

def generate_syn_flood_packets(count=150):
    """Generate SYN flood attack packets"""
    packets = []
    attacker_ip = "192.168.1.100"
    target_ip = "10.0.0.50"
    
    for i in range(count):
        pkt = IP(src=attacker_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags='S')
        packets.append(pkt)
    
    return packets

def generate_port_scan_packets(port_count=30):
    """Generate port scanning packets"""
    packets = []
    scanner_ip = "192.168.1.200"
    target_ip = "10.0.0.100"
    
    for port in range(1, port_count + 1):
        pkt = IP(src=scanner_ip, dst=target_ip)/TCP(sport=54321, dport=port, flags='S')
        packets.append(pkt)
    
    return packets

def generate_icmp_flood_packets(count=150):
    """Generate ICMP flood packets"""
    packets = []
    attacker_ip = "192.168.1.150"
    target_ip = "10.0.0.75"
    
    for i in range(count):
        pkt = IP(src=attacker_ip, dst=target_ip)/ICMP()
        packets.append(pkt)
    
    return packets

def generate_normal_traffic(count=50):
    """Generate normal benign traffic"""
    packets = []
    
    for i in range(count):
        src_ip = f"192.168.1.{random.randint(1, 50)}"
        dst_ip = f"10.0.0.{random.randint(1, 50)}"
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags='SA')
        packets.append(pkt)
    
    return packets

def main():
    """Generate test PCAP file with various attacks"""
    print("[*] Generating test PCAP file...")
    
    all_packets = []
    
    # Add normal traffic
    print("  - Adding normal traffic (50 packets)")
    all_packets.extend(generate_normal_traffic(50))
    
    # Add SYN flood attack
    print("  - Adding SYN flood attack (150 packets)")
    all_packets.extend(generate_syn_flood_packets(150))
    
    # Add more normal traffic
    all_packets.extend(generate_normal_traffic(20))
    
    # Add port scan
    print("  - Adding port scan attack (30 packets)")
    all_packets.extend(generate_port_scan_packets(30))
    
    # Add more normal traffic
    all_packets.extend(generate_normal_traffic(20))
    
    # Add ICMP flood
    print("  - Adding ICMP flood attack (150 packets)")
    all_packets.extend(generate_icmp_flood_packets(150))
    
    # Add final normal traffic
    all_packets.extend(generate_normal_traffic(30))
    
    # Shuffle to make more realistic
    random.shuffle(all_packets)
    
    # Write to PCAP file
    output_file = "test_attacks.pcap"
    wrpcap(output_file, all_packets)
    
    print(f"\n[+] Test PCAP file created: {output_file}")
    print(f"[+] Total packets: {len(all_packets)}")
    print("\n[*] Expected detections:")
    print("  - SYN_FLOOD from 192.168.1.100")
    print("  - PORT_SCAN from 192.168.1.200")
    print("  - ICMP_FLOOD from 192.168.1.150")
    print("\n[*] Run IDS with: py ids_engine.py --pcap test_attacks.pcap")

if __name__ == '__main__':
    main()
