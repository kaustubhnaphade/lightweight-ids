"""
Alert Logger module for IDS
Handles alert generation, formatting, console output, and JSON logging
"""

import json
import time
from datetime import datetime
from collections import defaultdict
from config import IDSConfig

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False


class AlertLogger:
    """Manages IDS alerts with deduplication, formatting, and logging"""
    
    def __init__(self):
        self.alerts = []
        self.alert_counts = defaultdict(int)
        self.last_alert_time = {}  # For deduplication
        self.start_time = time.time()
        
        # Initialize log file for this session
        if IDSConfig.LOG_TO_FILE:
            self._initialize_log_file()
    
    def _initialize_log_file(self):
        """Initialize/clear log file and write session header"""
        try:
            with open(IDSConfig.LOG_FILE, 'w') as f:
                # Write session header
                session_info = {
                    'session_start': datetime.now().isoformat(),
                    'ids_version': 'Lightweight IDS v1.0',
                    'log_type': 'IDS Alert Log'
                }
                json.dump(session_info, f)
                f.write('\n')
        except Exception as e:
            print(f"Warning: Could not initialize log file: {e}")
        
    def generate_alert(self, attack_type, src_ip, dst_ip=None, additional_info=None):
        """
        Generate and log an alert
        
        Args:
            attack_type: Type of attack detected
            src_ip: Source IP address
            dst_ip: Destination IP address (optional)
            additional_info: Dictionary with additional context
        """
        # Deduplication check
        dedup_key = f"{attack_type}_{src_ip}_{dst_ip}"
        current_time = time.time()
        
        if dedup_key in self.last_alert_time:
            time_diff = current_time - self.last_alert_time[dedup_key]
            if time_diff < IDSConfig.DEDUP_WINDOW:
                return  # Skip duplicate alert
        
        self.last_alert_time[dedup_key] = current_time
        
        # Create alert structure
        alert = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'severity': IDSConfig.get_severity(attack_type),
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'additional_info': additional_info or {}
        }
        
        self.alerts.append(alert)
        self.alert_counts[attack_type] += 1
        
        # Output alert
        if IDSConfig.CONSOLE_OUTPUT:
            self._print_alert(alert)
        
        if IDSConfig.LOG_TO_FILE:
            self._log_to_file(alert)
    
    def _print_alert(self, alert):
        """Print colored alert to console"""
        severity = alert['severity']
        attack_type = alert['attack_type']
        
        # Color coding based on severity
        if COLORS_AVAILABLE:
            if severity == 'CRITICAL':
                color = Fore.RED + Style.BRIGHT
            elif severity == 'HIGH':
                color = Fore.RED
            elif severity == 'MEDIUM':
                color = Fore.YELLOW
            else:
                color = Fore.WHITE
        else:
            color = ''
        
        reset = Style.RESET_ALL if COLORS_AVAILABLE else ''
        
        # Format alert message
        msg = f"{color}[{alert['timestamp']}] [{severity}] {attack_type}{reset}\n"
        msg += f"  Source: {alert['source_ip']}"
        
        if alert['destination_ip']:
            msg += f" -> Destination: {alert['destination_ip']}"
        
        if alert['additional_info']:
            msg += f"\n  Details: {alert['additional_info']}"
        
        print(msg)
    
    def _log_to_file(self, alert):
        """Append alert to JSON log file"""
        try:
            with open(IDSConfig.LOG_FILE, 'a') as f:
                json.dump(alert, f)
                f.write('\n')
        except Exception as e:
            print(f"Error writing to log file: {e}")
    
    def _write_session_end(self, stats):
        """Write session end marker with statistics"""
        try:
            with open(IDSConfig.LOG_FILE, 'a') as f:
                session_end = {
                    'session_end': datetime.now().isoformat(),
                    'total_runtime_seconds': stats['runtime_seconds'],
                    'total_alerts': stats['total_alerts'],
                    'alerts_by_type': stats['alerts_by_type']
                }
                json.dump(session_end, f)
                f.write('\n')
        except Exception as e:
            print(f"Error writing session end: {e}")
    
    def get_statistics(self):
        """Return summary statistics"""
        runtime = time.time() - self.start_time
        
        stats = {
            'runtime_seconds': round(runtime, 2),
            'total_alerts': len(self.alerts),
            'alerts_by_type': dict(self.alert_counts),
            'alerts_per_minute': round(len(self.alerts) / (runtime / 60), 2) if runtime > 0 else 0
        }
        
        return stats
    
    def print_summary(self):
        """Print summary statistics"""
        stats = self.get_statistics()
        
        print("\n" + "="*60)
        print("IDS DETECTION SUMMARY")
        print("="*60)
        print(f"Runtime: {stats['runtime_seconds']} seconds")
        print(f"Total Alerts: {stats['total_alerts']}")
        print(f"Alerts per Minute: {stats['alerts_per_minute']}")
        print("\nAlerts by Type:")
        
        for attack_type, count in stats['alerts_by_type'].items():
            severity = IDSConfig.get_severity(attack_type)
            print(f"  - {attack_type}: {count} ({severity})")
        
        print("="*60)
        
        # Write session end marker to log file
        if IDSConfig.LOG_TO_FILE:
            self._write_session_end(stats)
