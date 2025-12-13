"""
Lightweight Intrusion Detection System (IDS)
Main engine for packet capture analysis and attack detection
"""

import sys
import argparse
from scapy.all import rdpcap, sniff, IP
from packet_analyzer import PacketAnalyzer
from signature_detector import SignatureDetector
from alert_logger import AlertLogger
from config import IDSConfig


class IDSEngine:
    """Main IDS engine orchestrating packet analysis and detection"""
    
    def __init__(self):
        self.analyzer = PacketAnalyzer()
        self.logger = AlertLogger()
        self.detector = SignatureDetector(self.analyzer, self.logger)
        self.packet_count = 0
    
    def process_packet(self, packet):
        """
        Process a single packet through the detection pipeline
        
        Args:
            packet: Scapy packet object
        """
        # Only process packets with IP layer (skip pure L2 traffic except ARP)
        if not (packet.haslayer(IP) or packet.haslayer('ARP')):
            return
        
        self.packet_count += 1
        
        # Analyze packet and extract metadata
        metadata = self.analyzer.analyze_packet(packet)
        
        # Run attack detection
        self.detector.detect_attacks(metadata)
        
        # Periodically cleanup old tracking data
        if self.packet_count % 1000 == 0:
            self.analyzer.cleanup_old_data()
    
    def analyze_pcap(self, pcap_file):
        """
        Analyze a PCAP file for attacks
        
        Args:
            pcap_file: Path to PCAP file
        """
        print(f"\n[*] Loading PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            total_packets = len(packets)
            print(f"[*] Loaded {total_packets} packets")
            print(f"[*] Starting analysis...\n")
            
            # Process each packet
            for i, packet in enumerate(packets, 1):
                self.process_packet(packet)
                
                # Progress indicator
                if i % 1000 == 0:
                    print(f"[*] Processed {i}/{total_packets} packets...", end='\r')
            
            print(f"\n[*] Analysis complete. Processed {total_packets} packets.")
            
        except FileNotFoundError:
            print(f"[!] Error: PCAP file not found: {pcap_file}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading PCAP file: {e}")
            sys.exit(1)
    
    def capture_live(self, interface=None, duration=None, packet_count=None):
        """
        Capture and analyze live network traffic
        
        Args:
            interface: Network interface to capture from (None = auto-detect)
            duration: Capture duration in seconds (optional)
            packet_count: Number of packets to capture (optional)
        """
        # Auto-detect interface if not specified
        if interface is None:
            from scapy.all import conf
            interface = conf.iface
            print(f"\n[*] Auto-selected interface: {interface}")
        
        print(f"\n[*] Starting live capture on interface: {interface}")
        
        if duration:
            print(f"[*] Capture duration: {duration} seconds")
        if packet_count:
            print(f"[*] Capture packet count: {packet_count}")
        
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            # Build sniff parameters
            sniff_params = {
                'iface': interface,
                'prn': self.process_packet,
                'store': False  # Don't store packets in memory
            }
            
            if duration:
                sniff_params['timeout'] = duration
            if packet_count:
                sniff_params['count'] = packet_count
            
            # Start capture
            sniff(**sniff_params)
            
            print(f"\n[*] Capture complete. Processed {self.packet_count} packets.")
            
        except KeyboardInterrupt:
            print(f"\n[*] Capture stopped by user. Processed {self.packet_count} packets.")
        except PermissionError:
            print("[!] Error: Permission denied. Try running with administrator/root privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error during live capture: {e}")
            sys.exit(1)
    
    def print_summary(self):
        """Print detection summary"""
        self.logger.print_summary()


def main():
    """Main entry point for IDS"""
    parser = argparse.ArgumentParser(
        description='Lightweight Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a PCAP file
  py ids_engine.py --pcap capture.pcap
  
  # Live capture with auto-detected interface for 60 seconds
  py ids_engine.py --interface auto --duration 60
  
  # Live capture on specific interface
  py ids_engine.py --interface "\\Device\\NPF_{...}" --duration 60
  
  # Capture 1000 packets
  py ids_engine.py --interface auto --count 1000
  
  # List available interfaces
  py list_interfaces.py
        """
    )
    
    # Input source group
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        '--pcap',
        type=str,
        help='Path to PCAP file for analysis'
    )
    source_group.add_argument(
        '--interface',
        type=str,
        help='Network interface for live capture'
    )
    
    # Live capture options
    parser.add_argument(
        '--duration',
        type=int,
        help='Capture duration in seconds (for live capture)'
    )
    parser.add_argument(
        '--count',
        type=int,
        help='Number of packets to capture (for live capture)'
    )
    
    args = parser.parse_args()
    
    # Create IDS engine
    ids = IDSEngine()
    
    # Print banner
    print("="*60)
    print("   Lightweight Intrusion Detection System (IDS)")
    print("   Classic Attack Signature Detection")
    print("="*60)
    
    # Run analysis
    if args.pcap:
        ids.analyze_pcap(args.pcap)
    elif args.interface:
        # Handle 'auto' as interface name
        interface = None if args.interface.lower() == 'auto' else args.interface
        ids.capture_live(interface, args.duration, args.count)
    
    # Print summary
    ids.print_summary()
    
    # Print log file location
    if IDSConfig.LOG_TO_FILE:
        print(f"\n[*] Alerts logged to: {IDSConfig.LOG_FILE}")


if __name__ == '__main__':
    main()
