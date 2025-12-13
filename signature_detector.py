"""
Signature Detector module for IDS
Implements detection logic for classic network attacks
"""

from config import IDSConfig
from packet_analyzer import PacketAnalyzer
from alert_logger import AlertLogger


class SignatureDetector:
    """Detects classic attack signatures using packet metadata"""
    
    def __init__(self, packet_analyzer, alert_logger):
        """
        Initialize detector
        
        Args:
            packet_analyzer: PacketAnalyzer instance
            alert_logger: AlertLogger instance
        """
        self.analyzer = packet_analyzer
        self.logger = alert_logger
        self.port_scan_checked = {}  # Track IPs and last alert time for port scan
    
    def detect_attacks(self, packet_metadata):
        """
        Run all detection checks on packet metadata
        
        Args:
            packet_metadata: Dictionary from PacketAnalyzer
        """
        # Run all detection checks
        self.detect_syn_flood(packet_metadata)
        self.detect_port_scan(packet_metadata)
        self.detect_icmp_flood(packet_metadata)
        self.detect_arp_spoofing(packet_metadata)
        self.detect_tcp_rst_attack(packet_metadata)
        self.detect_dns_amplification(packet_metadata)
    
    def detect_syn_flood(self, metadata):
        """
        Detect SYN flood attacks
        
        Logic: Track SYN packets from each source. If a source sends too many
        SYN packets in a short time window without completing handshakes,
        it indicates a SYN flood attack.
        """
        if not metadata.get('is_syn'):
            return
        
        src_ip = metadata.get('src_ip')
        if not src_ip:
            return
        
        # Check SYN packet count in time window
        syn_count = self.analyzer.get_syn_packets_in_window(
            src_ip, 
            IDSConfig.SYN_FLOOD_WINDOW
        )
        
        if syn_count >= IDSConfig.SYN_FLOOD_THRESHOLD:
            additional_info = {
                'syn_count': syn_count,
                'time_window': f"{IDSConfig.SYN_FLOOD_WINDOW}s",
                'description': 'Possible SYN flood attack detected'
            }
            
            self.logger.generate_alert(
                attack_type='SYN_FLOOD',
                src_ip=src_ip,
                dst_ip=metadata.get('dst_ip'),
                additional_info=additional_info
            )
    
    def detect_port_scan(self, metadata):
        """
        Detect port scanning attacks
        
        Logic: Track unique destination ports accessed by each source IP.
        If a source tries to connect to many different ports in a short time,
        it indicates a port scan (vertical scan).
        """
        if not metadata.get('has_tcp'):
            return
        
        src_ip = metadata.get('src_ip')
        if not src_ip:
            return
        
        # Get unique port count (this is always current because analyzer tracks it)
        port_count = self.analyzer.get_port_scan_count(src_ip)
        
        if port_count >= IDSConfig.PORT_SCAN_THRESHOLD:
            # Check if we already alerted for this IP recently (within 60 seconds)
            current_time = metadata.get('timestamp', 0)
            if src_ip in self.port_scan_checked:
                last_alert_time = self.port_scan_checked[src_ip]
                if current_time - last_alert_time < 60:  # Dedup window
                    return
            
            # Record alert time
            self.port_scan_checked[src_ip] = current_time
            
            additional_info = {
                'unique_ports': port_count,
                'threshold': IDSConfig.PORT_SCAN_THRESHOLD,
                'description': 'Port scanning activity detected'
            }
            
            self.logger.generate_alert(
                attack_type='PORT_SCAN',
                src_ip=src_ip,
                dst_ip=metadata.get('dst_ip'),
                additional_info=additional_info
            )
    
    def detect_icmp_flood(self, metadata):
        """
        Detect ICMP flood attacks
        
        Logic: Monitor ICMP packet rate from each source. Excessive ICMP
        packets in a short time window indicates ping flood or smurf attack.
        """
        if not metadata.get('has_icmp'):
            return
        
        src_ip = metadata.get('src_ip')
        if not src_ip:
            return
        
        # Check ICMP packet count in time window
        icmp_count = self.analyzer.get_icmp_packets_in_window(
            src_ip,
            IDSConfig.ICMP_FLOOD_WINDOW
        )
        
        if icmp_count >= IDSConfig.ICMP_FLOOD_THRESHOLD:
            additional_info = {
                'icmp_count': icmp_count,
                'icmp_type': metadata.get('icmp_type'),
                'time_window': f"{IDSConfig.ICMP_FLOOD_WINDOW}s",
                'description': 'ICMP flood attack detected'
            }
            
            self.logger.generate_alert(
                attack_type='ICMP_FLOOD',
                src_ip=src_ip,
                dst_ip=metadata.get('dst_ip'),
                additional_info=additional_info
            )
    
    def detect_arp_spoofing(self, metadata):
        """
        Detect ARP spoofing attacks
        
        Logic: Maintain an ARP cache of IP-MAC mappings. If we see the same
        IP address with a different MAC address, it indicates ARP spoofing.
        """
        if not metadata.get('has_arp'):
            return
        
        arp_op = metadata.get('arp_op')
        if arp_op != 2:  # Only check ARP replies
            return
        
        src_ip = metadata.get('arp_src_ip')
        src_mac = metadata.get('arp_src_mac')
        
        if not src_ip or not src_mac:
            return
        
        # Check for IP-MAC conflict
        is_conflict, old_mac = self.analyzer.check_arp_conflict(src_ip, src_mac)
        
        if is_conflict:
            additional_info = {
                'conflicting_ip': src_ip,
                'old_mac': old_mac,
                'new_mac': src_mac,
                'description': 'ARP spoofing detected - IP mapped to different MAC'
            }
            
            self.logger.generate_alert(
                attack_type='ARP_SPOOF',
                src_ip=src_ip,
                dst_ip=metadata.get('arp_dst_ip'),
                additional_info=additional_info
            )
    
    def detect_tcp_rst_attack(self, metadata):
        """
        Detect TCP reset attacks
        
        Logic: Monitor RST flag packets. Excessive RST packets can indicate
        an attempt to disrupt connections (RST attack).
        """
        if not metadata.get('is_rst'):
            return
        
        src_ip = metadata.get('src_ip')
        if not src_ip:
            return
        
        # Check RST packet count in time window
        rst_count = self.analyzer.get_rst_packets_in_window(
            src_ip,
            IDSConfig.TCP_RST_WINDOW
        )
        
        if rst_count >= IDSConfig.TCP_RST_THRESHOLD:
            additional_info = {
                'rst_count': rst_count,
                'time_window': f"{IDSConfig.TCP_RST_WINDOW}s",
                'description': 'TCP reset attack detected'
            }
            
            self.logger.generate_alert(
                attack_type='TCP_RST_ATTACK',
                src_ip=src_ip,
                dst_ip=metadata.get('dst_ip'),
                additional_info=additional_info
            )
    
    def detect_dns_amplification(self, metadata):
        """
        Detect DNS amplification attacks
        
        Logic: Check for:
        1. Unusually large DNS responses (>512 bytes)
        2. High rate of DNS queries to a single resolver
        """
        if not metadata.get('has_dns'):
            return
        
        # Check for large DNS responses (amplification indicator)
        if metadata.get('dns_qr') == 1:  # DNS response
            response_size = metadata.get('dns_response_size', 0)
            
            if response_size > IDSConfig.DNS_AMP_SIZE_THRESHOLD:
                src_ip = metadata.get('src_ip')
                dst_ip = metadata.get('dst_ip')
                
                additional_info = {
                    'response_size': response_size,
                    'threshold': IDSConfig.DNS_AMP_SIZE_THRESHOLD,
                    'description': 'Unusually large DNS response - possible amplification'
                }
                
                self.logger.generate_alert(
                    attack_type='DNS_AMPLIFICATION',
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    additional_info=additional_info
                )
        
        # Check for high rate of DNS queries to single resolver
        if metadata.get('dns_qr') == 0:  # DNS query
            dst_ip = metadata.get('dst_ip')
            if not dst_ip:
                return
            
            query_count = self.analyzer.get_dns_queries_in_window(
                dst_ip,
                IDSConfig.DNS_AMP_WINDOW
            )
            
            if query_count >= IDSConfig.DNS_AMP_RATE_THRESHOLD:
                src_ip = metadata.get('src_ip')
                
                additional_info = {
                    'query_count': query_count,
                    'dns_resolver': dst_ip,
                    'time_window': f"{IDSConfig.DNS_AMP_WINDOW}s",
                    'description': 'High rate DNS query - possible amplification attack'
                }
                
                self.logger.generate_alert(
                    attack_type='DNS_AMPLIFICATION',
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    additional_info=additional_info
                )
