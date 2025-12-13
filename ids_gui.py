"""
GUI for Lightweight Intrusion Detection System
Modern interface with automatic admin elevation for Windows
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import sys
import os
import ctypes
from datetime import datetime
from scapy.all import get_if_list, conf
from packet_analyzer import PacketAnalyzer
from signature_detector import SignatureDetector
from alert_logger import AlertLogger
from config import IDSConfig
from scapy.all import rdpcap, sniff, IP


def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """Re-launch the script with administrator privileges"""
    if sys.platform == 'win32':
        try:
            # Get the Python executable and current script
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:])
            
            # Request elevation
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                params, 
                None, 
                1  # SW_SHOWNORMAL
            )
            sys.exit(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to elevate privileges: {e}")
            return False
    return True


class IDSGuiLogger:
    """Custom logger for GUI output"""
    
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.alerts = []
        self.alert_counts = {}
        
    def log_message(self, message, level="INFO"):
        """Log a message to the GUI"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        color_map = {
            "INFO": "black",
            "SUCCESS": "green",
            "WARNING": "orange",
            "ERROR": "red",
            "CRITICAL": "dark red",
            "HIGH": "red",
            "MEDIUM": "orange"
        }
        
        color = color_map.get(level, "black")
        
        # Insert into text widget
        self.text_widget.config(state='normal')
        self.text_widget.insert('end', f"[{timestamp}] ", "timestamp")
        self.text_widget.insert('end', f"{message}\n", level.lower())
        self.text_widget.tag_config("timestamp", foreground="gray")
        self.text_widget.tag_config(level.lower(), foreground=color)
        self.text_widget.see('end')
        self.text_widget.config(state='disabled')
    
    def log_alert(self, attack_type, src_ip, dst_ip, severity, details):
        """Log an attack alert"""
        self.alerts.append({
            'timestamp': datetime.now(),
            'attack_type': attack_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'severity': severity,
            'details': details
        })
        
        self.alert_counts[attack_type] = self.alert_counts.get(attack_type, 0) + 1
        
        msg = f"[{severity}] {attack_type} - Source: {src_ip}"
        if dst_ip:
            msg += f" → Dest: {dst_ip}"
        
        self.log_message(msg, severity)


class IDSGUI:
    """Main GUI Application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Lightweight IDS - Intrusion Detection System")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # IDS components
        self.analyzer = None
        self.detector = None
        self.gui_logger = None
        self.is_running = False
        self.capture_thread = None
        self.packet_count = 0
        
        # Build GUI
        self.create_widgets()
        self.load_interfaces()
        
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # ===== Top Frame: Mode Selection =====
        top_frame = ttk.LabelFrame(self.root, text="Configuration", padding=10)
        top_frame.pack(fill='x', padx=10, pady=5)
        
        # Mode selection
        ttk.Label(top_frame, text="Mode:").grid(row=0, column=0, sticky='w', padx=5)
        self.mode_var = tk.StringVar(value="pcap")
        
        mode_frame = ttk.Frame(top_frame)
        mode_frame.grid(row=0, column=1, sticky='w', padx=5)
        
        ttk.Radiobutton(mode_frame, text="PCAP File Analysis", 
                       variable=self.mode_var, value="pcap",
                       command=self.toggle_mode).pack(side='left', padx=5)
        ttk.Radiobutton(mode_frame, text="Live Network Capture", 
                       variable=self.mode_var, value="live",
                       command=self.toggle_mode).pack(side='left', padx=5)
        
        # PCAP file selection
        ttk.Label(top_frame, text="PCAP File:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.pcap_entry = ttk.Entry(top_frame, width=50)
        self.pcap_entry.grid(row=1, column=1, sticky='ew', padx=5)
        self.browse_btn = ttk.Button(top_frame, text="Browse...", command=self.browse_pcap)
        self.browse_btn.grid(row=1, column=2, padx=5)
        
        # Interface selection
        ttk.Label(top_frame, text="Interface:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(top_frame, textvariable=self.interface_var, 
                                           width=47, state='readonly')
        self.interface_combo.grid(row=2, column=1, sticky='ew', padx=5)
        self.refresh_btn = ttk.Button(top_frame, text="Refresh", command=self.load_interfaces)
        self.refresh_btn.grid(row=2, column=2, padx=5)
        
        # Duration and packet count
        options_frame = ttk.Frame(top_frame)
        options_frame.grid(row=3, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(options_frame, text="Duration (sec):").pack(side='left', padx=5)
        self.duration_var = tk.StringVar(value="60")
        ttk.Entry(options_frame, textvariable=self.duration_var, width=10).pack(side='left', padx=5)
        
        ttk.Label(options_frame, text="Packet Limit:").pack(side='left', padx=15)
        self.packet_limit_var = tk.StringVar(value="")
        ttk.Entry(options_frame, textvariable=self.packet_limit_var, width=10).pack(side='left', padx=5)
        
        top_frame.columnconfigure(1, weight=1)
        
        # ===== Control Buttons =====
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="▶ Start Analysis", 
                                    command=self.start_analysis, style='Accent.TButton')
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="⬛ Stop", 
                                   command=self.stop_analysis, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        self.clear_btn = ttk.Button(control_frame, text="Clear Log", command=self.clear_log)
        self.clear_btn.pack(side='left', padx=5)
        
        # Status indicator
        self.status_label = ttk.Label(control_frame, text="● Ready", foreground="green")
        self.status_label.pack(side='right', padx=10)
        
        # ===== Statistics Frame =====
        stats_frame = ttk.LabelFrame(self.root, text="Statistics", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        self.packets_label = ttk.Label(stats_frame, text="Packets Processed: 0")
        self.packets_label.grid(row=0, column=0, sticky='w', padx=10)
        
        self.alerts_label = ttk.Label(stats_frame, text="Total Alerts: 0")
        self.alerts_label.grid(row=0, column=1, sticky='w', padx=10)
        
        self.runtime_label = ttk.Label(stats_frame, text="Runtime: 0s")
        self.runtime_label.grid(row=0, column=2, sticky='w', padx=10)
        
        self.alerts_per_min_label = ttk.Label(stats_frame, text="Alerts/min: 0.0")
        self.alerts_per_min_label.grid(row=0, column=3, sticky='w', padx=10)
        
        # ===== Alert Log =====
        log_frame = ttk.LabelFrame(self.root, text="Alert Log", padding=10)
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Scrolled text widget
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, 
                                                  font=('Consolas', 9),
                                                  state='disabled')
        self.log_text.pack(fill='both', expand=True)
        
        # Initialize GUI logger
        self.gui_logger = IDSGuiLogger(self.log_text)
        
        # Initial mode setup
        self.toggle_mode()
        
        # Welcome message
        self.gui_logger.log_message("═" * 80, "INFO")
        self.gui_logger.log_message("   Lightweight Intrusion Detection System - GUI Interface", "INFO")
        self.gui_logger.log_message("   Ready to analyze network traffic", "INFO")
        self.gui_logger.log_message("═" * 80, "INFO")
        
    def toggle_mode(self):
        """Toggle between PCAP and Live capture modes"""
        mode = self.mode_var.get()
        
        if mode == "pcap":
            self.pcap_entry.config(state='normal')
            self.browse_btn.config(state='normal')
            self.interface_combo.config(state='disabled')
            self.refresh_btn.config(state='disabled')
        else:
            self.pcap_entry.config(state='disabled')
            self.browse_btn.config(state='disabled')
            self.interface_combo.config(state='readonly')
            self.refresh_btn.config(state='normal')
    
    def browse_pcap(self):
        """Open file browser for PCAP selection"""
        filename = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if filename:
            self.pcap_entry.delete(0, 'end')
            self.pcap_entry.insert(0, filename)
    
    def load_interfaces(self):
        """Load available network interfaces"""
        try:
            interfaces = get_if_list()
            default_iface = conf.iface
            
            # Add auto-detect option
            interface_list = ["Auto-detect"] + interfaces
            self.interface_combo['values'] = interface_list
            
            # Select auto-detect by default
            self.interface_combo.current(0)
            
            self.gui_logger.log_message(f"Loaded {len(interfaces)} network interface(s)", "INFO")
        except Exception as e:
            self.gui_logger.log_message(f"Error loading interfaces: {e}", "ERROR")
    
    def start_analysis(self):
        """Start IDS analysis"""
        mode = self.mode_var.get()
        
        # Validation
        if mode == "pcap":
            pcap_file = self.pcap_entry.get().strip()
            if not pcap_file:
                messagebox.showwarning("Input Required", "Please select a PCAP file")
                return
            if not os.path.exists(pcap_file):
                messagebox.showerror("File Not Found", f"PCAP file not found: {pcap_file}")
                return
        else:
            interface = self.interface_var.get()
            if not interface:
                messagebox.showwarning("Input Required", "Please select a network interface")
                return
        
        # Initialize IDS components
        self.analyzer = PacketAnalyzer()
        self.file_logger = AlertLogger()  # For JSON file logging
        self.detector = SignatureDetector(self.analyzer, self)
        self.packet_count = 0
        self.start_time = datetime.now()
        
        # Update UI
        self.is_running = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_label.config(text="● Running...", foreground="orange")
        
        # Start analysis in separate thread
        self.capture_thread = threading.Thread(target=self.run_analysis, daemon=True)
        self.capture_thread.start()
        
        # Update statistics periodically
        self.update_statistics()
    
    def run_analysis(self):
        """Run IDS analysis (called in separate thread)"""
        mode = self.mode_var.get()
        
        try:
            if mode == "pcap":
                self.analyze_pcap()
            else:
                self.capture_live()
        except Exception as e:
            self.gui_logger.log_message(f"Error during analysis: {e}", "ERROR")
        finally:
            self.is_running = False
            self.root.after(0, self.analysis_complete)
    
    def analyze_pcap(self):
        """Analyze PCAP file"""
        pcap_file = self.pcap_entry.get().strip()
        
        self.gui_logger.log_message(f"Loading PCAP file: {pcap_file}", "INFO")
        
        try:
            packets = rdpcap(pcap_file)
            total_packets = len(packets)
            
            self.gui_logger.log_message(f"Loaded {total_packets} packets. Starting analysis...", "SUCCESS")
            
            for i, packet in enumerate(packets, 1):
                if not self.is_running:
                    break
                
                self.process_packet(packet)
                
                # Progress update every 100 packets
                if i % 100 == 0:
                    self.gui_logger.log_message(f"Progress: {i}/{total_packets} packets processed", "INFO")
            
            self.gui_logger.log_message(f"Analysis complete. Processed {total_packets} packets.", "SUCCESS")
            
        except Exception as e:
            self.gui_logger.log_message(f"Error reading PCAP: {e}", "ERROR")
    
    def capture_live(self):
        """Capture live network traffic"""
        interface = self.interface_var.get()
        
        # Handle auto-detect
        if interface == "Auto-detect":
            interface = conf.iface
            self.gui_logger.log_message(f"Auto-selected interface: {interface}", "INFO")
        
        duration = None
        packet_limit = None
        
        try:
            if self.duration_var.get().strip():
                duration = int(self.duration_var.get())
            if self.packet_limit_var.get().strip():
                packet_limit = int(self.packet_limit_var.get())
        except ValueError:
            self.gui_logger.log_message("Invalid duration or packet limit", "ERROR")
            return
        
        self.gui_logger.log_message(f"Starting live capture on: {interface}", "INFO")
        if duration:
            self.gui_logger.log_message(f"Capture duration: {duration} seconds", "INFO")
        if packet_limit:
            self.gui_logger.log_message(f"Packet limit: {packet_limit}", "INFO")
        
        try:
            sniff_params = {
                'iface': interface,
                'prn': self.process_packet,
                'store': False,
                'stop_filter': lambda x: not self.is_running
            }
            
            if duration:
                sniff_params['timeout'] = duration
            if packet_limit:
                sniff_params['count'] = packet_limit
            
            sniff(**sniff_params)
            
            self.gui_logger.log_message(f"Capture complete. Processed {self.packet_count} packets.", "SUCCESS")
            
        except PermissionError:
            self.gui_logger.log_message("Permission denied. Please run as Administrator!", "ERROR")
        except Exception as e:
            self.gui_logger.log_message(f"Capture error: {e}", "ERROR")
    
    def process_packet(self, packet):
        """Process a single packet"""
        if not (packet.haslayer(IP) or packet.haslayer('ARP')):
            return
        
        self.packet_count += 1
        
        # Analyze packet
        metadata = self.analyzer.analyze_packet(packet)
        
        # Detect attacks
        self.detector.detect_attacks(metadata)
        
        # Cleanup periodically
        if self.packet_count % 1000 == 0:
            self.analyzer.cleanup_old_data()
    
    def generate_alert(self, attack_type, src_ip, dst_ip=None, additional_info=None):
        """Generate alert (called by signature detector)"""
        severity = IDSConfig.get_severity(attack_type)
        
        # Log to GUI display
        self.gui_logger.log_alert(
            attack_type=attack_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            severity=severity,
            details=additional_info
        )
        
        # Also log to JSON file
        if hasattr(self, 'file_logger'):
            self.file_logger.generate_alert(attack_type, src_ip, dst_ip, additional_info)
    
    def update_statistics(self):
        """Update statistics display"""
        if self.is_running or self.packet_count > 0:
            runtime = (datetime.now() - self.start_time).total_seconds()
            total_alerts = len(self.gui_logger.alerts)
            
            # Calculate alerts per minute
            alerts_per_min = (total_alerts / (runtime / 60)) if runtime > 0 else 0.0
            
            self.packets_label.config(text=f"Packets Processed: {self.packet_count}")
            self.alerts_label.config(text=f"Total Alerts: {total_alerts}")
            self.runtime_label.config(text=f"Runtime: {runtime:.1f}s")
            self.alerts_per_min_label.config(text=f"Alerts/min: {alerts_per_min:.1f}")
        
        if self.is_running:
            self.root.after(500, self.update_statistics)
    
    def stop_analysis(self):
        """Stop ongoing analysis"""
        self.is_running = False
        self.gui_logger.log_message("Stopping analysis...", "WARNING")
    
    def analysis_complete(self):
        """Called when analysis completes"""
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text="● Complete", foreground="green")
        
        # Show summary in GUI
        total_alerts = len(self.gui_logger.alerts)
        if total_alerts > 0:
            self.gui_logger.log_message("═" * 80, "INFO")
            self.gui_logger.log_message(f"DETECTION SUMMARY: {total_alerts} total alerts", "INFO")
            for attack_type, count in self.gui_logger.alert_counts.items():
                self.gui_logger.log_message(f"  - {attack_type}: {count}", "INFO")
            self.gui_logger.log_message("═" * 80, "INFO")
        else:
            self.gui_logger.log_message("═" * 80, "INFO")
            self.gui_logger.log_message("DETECTION SUMMARY: No attacks detected", "SUCCESS")
            self.gui_logger.log_message("═" * 80, "INFO")
        
        # Write session end to JSON file
        if hasattr(self, 'file_logger'):
            self.file_logger.print_summary()
            self.gui_logger.log_message(f"Results saved to: {IDSConfig.LOG_FILE}", "INFO")
    
    def clear_log(self):
        """Clear the log display"""
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, 'end')
        self.log_text.config(state='disabled')
        
        self.gui_logger.alerts = []
        self.gui_logger.alert_counts = {}
        self.packet_count = 0
        
        self.packets_label.config(text="Packets Processed: 0")
        self.alerts_label.config(text="Total Alerts: 0")
        self.runtime_label.config(text="Runtime: 0s")
        self.alerts_per_min_label.config(text="Alerts/min: 0.0")


def main():
    """Main entry point"""
    
    # Create root window first to prevent it from disappearing
    root = tk.Tk()
    root.withdraw()  # Hide it temporarily
    
    # Check for admin privileges on Windows
    if sys.platform == 'win32':
        if not is_admin():
            response = messagebox.askyesno(
                "Administrator Required",
                "This application requires administrator privileges for live packet capture.\n\n"
                "Would you like to restart with administrator privileges?",
                icon='warning'
            )
            if response:
                root.destroy()
                run_as_admin()
                return
            else:
                messagebox.showinfo(
                    "Limited Functionality",
                    "Running without admin privileges. PCAP file analysis will work, "
                    "but live capture may fail."
                )
    
    # Show the window now
    root.deiconify()
    
    # Create and run GUI
    app = IDSGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
