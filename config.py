"""
Configuration module for the Lightweight IDS
Contains detection thresholds and system parameters
"""

class IDSConfig:
    """Configuration class for IDS detection thresholds and parameters"""
    
    # Detection Thresholds
    SYN_FLOOD_THRESHOLD = 100  # Half-open connections from single source in time window
    SYN_FLOOD_WINDOW = 10  # seconds
    
    PORT_SCAN_THRESHOLD = 20  # Unique ports accessed in time window
    PORT_SCAN_WINDOW = 5  # seconds
    
    ICMP_FLOOD_THRESHOLD = 100  # ICMP packets per second from single source
    ICMP_FLOOD_WINDOW = 1  # seconds
    
    TCP_RST_THRESHOLD = 50  # RST packets in time window
    TCP_RST_WINDOW = 5  # seconds
    
    DNS_AMP_SIZE_THRESHOLD = 512  # Bytes - suspicious DNS response size
    DNS_AMP_RATE_THRESHOLD = 50  # DNS queries per second to single resolver
    DNS_AMP_WINDOW = 1  # seconds
    
    # ARP Spoofing Detection
    ARP_CACHE_TIMEOUT = 300  # seconds - how long to keep ARP entries
    
    # Alert Settings
    ALERT_SEVERITY = {
        'SYN_FLOOD': 'HIGH',
        'PORT_SCAN': 'MEDIUM',
        'ICMP_FLOOD': 'HIGH',
        'ARP_SPOOF': 'CRITICAL',
        'TCP_RST_ATTACK': 'MEDIUM',
        'DNS_AMPLIFICATION': 'HIGH'
    }
    
    # Logging Settings
    LOG_FILE = 'ids_alerts.json'
    CONSOLE_OUTPUT = True
    LOG_TO_FILE = True
    
    # Alert Deduplication
    DEDUP_WINDOW = 60  # seconds - prevent duplicate alerts for same attack
    
    # Performance Settings
    CLEANUP_INTERVAL = 30  # seconds - how often to clean old tracking data
    MAX_TRACKED_IPS = 10000  # Maximum IPs to track simultaneously
    
    @classmethod
    def get_severity(cls, attack_type):
        """Get severity level for an attack type"""
        return cls.ALERT_SEVERITY.get(attack_type, 'UNKNOWN')
