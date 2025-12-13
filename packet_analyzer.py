"""
Packet Analyzer module for IDS
Handles packet parsing, protocol analysis, and metadata extraction
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS
from collections import defaultdict
import time


class PacketAnalyzer:
    """Analyzes packets and extracts relevant information for detection"""
    
    def __init__(self):
        # Connection tracking
        self.tcp_connections = {}  # Track TCP connection states
        self.connection_timestamps = defaultdict(list)
        
        # Statistical tracking
        self.packet_counts = defaultdict(int)
        self.byte_counts = defaultdict(int)
        
        # Protocol-specific tracking
        self.syn_packets = defaultdict(list)  # Track SYN packets by source
        self.rst_packets = defaultdict(list)  # Track RST packets by source
        self.icmp_packets = defaultdict(list)  # Track ICMP by source
        self.port_access = defaultdict(set)  # Track ports accessed by each IP
        self.dns_queries = defaultdict(list)  # Track DNS queries
        self.arp_cache = {}  # IP -> MAC mapping
        
        self.last_cleanup = time.time()
    
    def analyze_packet(self, packet):
        """
        Analyze a packet and extract relevant information
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Packet metadata for detection
        """
        metadata = {
            'timestamp': time.time(),
            'has_ip': packet.haslayer(IP),
            'has_tcp': packet.haslayer(TCP),
            'has_udp': packet.haslayer(UDP),
            'has_icmp': packet.haslayer(ICMP),
            'has_arp': packet.haslayer(ARP),
            'has_dns': packet.haslayer(DNS)
        }
        
        # IP layer analysis
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            metadata['src_ip'] = ip_layer.src
            metadata['dst_ip'] = ip_layer.dst
            metadata['ip_len'] = ip_layer.len
            
            self.packet_counts[ip_layer.src] += 1
            self.byte_counts[ip_layer.src] += ip_layer.len
        
        # TCP layer analysis
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            metadata['src_port'] = tcp_layer.sport
            metadata['dst_port'] = tcp_layer.dport
            metadata['tcp_flags'] = tcp_layer.flags
            
            # Track TCP flags
            if tcp_layer.flags & 0x02:  # SYN flag
                metadata['is_syn'] = True
                if not (tcp_layer.flags & 0x10):  # Not SYN-ACK
                    src_ip = packet[IP].src
                    self.syn_packets[src_ip].append(metadata['timestamp'])
            
            if tcp_layer.flags & 0x04:  # RST flag
                metadata['is_rst'] = True
                src_ip = packet[IP].src
                self.rst_packets[src_ip].append(metadata['timestamp'])
            
            # Track port access for port scan detection
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_port = tcp_layer.dport
                self.port_access[src_ip].add(dst_port)
        
        # UDP layer analysis
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            metadata['src_port'] = udp_layer.sport
            metadata['dst_port'] = udp_layer.dport
        
        # ICMP layer analysis
        if packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            metadata['icmp_type'] = icmp_layer.type
            metadata['icmp_code'] = icmp_layer.code
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                self.icmp_packets[src_ip].append(metadata['timestamp'])
        
        # ARP layer analysis
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            metadata['arp_op'] = arp_layer.op  # 1=request, 2=reply
            metadata['arp_src_ip'] = arp_layer.psrc
            metadata['arp_dst_ip'] = arp_layer.pdst
            metadata['arp_src_mac'] = arp_layer.hwsrc
            metadata['arp_dst_mac'] = arp_layer.hwdst
            
            # Update ARP cache
            if arp_layer.op == 2:  # ARP reply
                self.arp_cache[arp_layer.psrc] = {
                    'mac': arp_layer.hwsrc,
                    'timestamp': metadata['timestamp']
                }
        
        # DNS layer analysis
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            metadata['dns_qr'] = dns_layer.qr  # 0=query, 1=response
            metadata['dns_qd_count'] = dns_layer.qdcount
            metadata['dns_an_count'] = dns_layer.ancount
            
            if packet.haslayer(IP):
                # Track DNS queries/responses
                if dns_layer.qr == 0:  # Query
                    dst_ip = packet[IP].dst
                    self.dns_queries[dst_ip].append(metadata['timestamp'])
                elif dns_layer.qr == 1:  # Response
                    # Check for unusually large DNS response
                    if packet.haslayer(IP):
                        metadata['dns_response_size'] = packet[IP].len
        
        return metadata
    
    def get_syn_packets_in_window(self, src_ip, window_seconds):
        """Get count of SYN packets from source in time window"""
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        syn_times = self.syn_packets.get(src_ip, [])
        recent_syns = [t for t in syn_times if t > cutoff_time]
        self.syn_packets[src_ip] = recent_syns  # Clean old data
        
        return len(recent_syns)
    
    def get_rst_packets_in_window(self, src_ip, window_seconds):
        """Get count of RST packets from source in time window"""
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        rst_times = self.rst_packets.get(src_ip, [])
        recent_rsts = [t for t in rst_times if t > cutoff_time]
        self.rst_packets[src_ip] = recent_rsts
        
        return len(recent_rsts)
    
    def get_icmp_packets_in_window(self, src_ip, window_seconds):
        """Get count of ICMP packets from source in time window"""
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        icmp_times = self.icmp_packets.get(src_ip, [])
        recent_icmp = [t for t in icmp_times if t > cutoff_time]
        self.icmp_packets[src_ip] = recent_icmp
        
        return len(recent_icmp)
    
    def get_dns_queries_in_window(self, dst_ip, window_seconds):
        """Get count of DNS queries to destination in time window"""
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        query_times = self.dns_queries.get(dst_ip, [])
        recent_queries = [t for t in query_times if t > cutoff_time]
        self.dns_queries[dst_ip] = recent_queries
        
        return len(recent_queries)
    
    def get_port_scan_count(self, src_ip):
        """Get number of unique ports accessed by source IP"""
        return len(self.port_access.get(src_ip, set()))
    
    def check_arp_conflict(self, ip, mac):
        """
        Check if IP-MAC mapping conflicts with ARP cache
        
        Returns:
            tuple: (is_conflict, old_mac)
        """
        if ip in self.arp_cache:
            cached_mac = self.arp_cache[ip]['mac']
            if cached_mac != mac:
                return (True, cached_mac)
        return (False, None)
    
    def cleanup_old_data(self, max_age_seconds=300):
        """Clean up old tracking data to prevent memory bloat"""
        current_time = time.time()
        
        # Only cleanup periodically
        if current_time - self.last_cleanup < 30:
            return
        
        cutoff_time = current_time - max_age_seconds
        
        # Clean SYN packets
        for ip in list(self.syn_packets.keys()):
            self.syn_packets[ip] = [t for t in self.syn_packets[ip] if t > cutoff_time]
            if not self.syn_packets[ip]:
                del self.syn_packets[ip]
        
        # Clean RST packets
        for ip in list(self.rst_packets.keys()):
            self.rst_packets[ip] = [t for t in self.rst_packets[ip] if t > cutoff_time]
            if not self.rst_packets[ip]:
                del self.rst_packets[ip]
        
        # Clean ICMP packets
        for ip in list(self.icmp_packets.keys()):
            self.icmp_packets[ip] = [t for t in self.icmp_packets[ip] if t > cutoff_time]
            if not self.icmp_packets[ip]:
                del self.icmp_packets[ip]
        
        # Clean DNS queries
        for ip in list(self.dns_queries.keys()):
            self.dns_queries[ip] = [t for t in self.dns_queries[ip] if t > cutoff_time]
            if not self.dns_queries[ip]:
                del self.dns_queries[ip]
        
        # Clean ARP cache
        for ip in list(self.arp_cache.keys()):
            if current_time - self.arp_cache[ip]['timestamp'] > max_age_seconds:
                del self.arp_cache[ip]
        
        self.last_cleanup = current_time
