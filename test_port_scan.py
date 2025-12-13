"""
Port Scanner Test Script
Run this to test IDS port scan detection

This script will scan multiple ports on a target IP to trigger
the IDS port scan detection (threshold: 20 ports in 5 seconds)
"""

import socket
import sys
import time
import concurrent.futures
from datetime import datetime

def get_local_ip():
    """Get local IP address"""
    try:
        # Create a socket to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "Unknown"

def scan_port(target, port, timeout=0.1):
    """
    Scan a single port
    
    Args:
        target: Target IP address
        port: Port number to scan
        timeout: Connection timeout in seconds
    
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False

def port_scan_attack(target, start_port=1, end_port=100, scan_mode="fast"):
    """
    Perform a port scan (simulated attack) - CONCURRENT VERSION
    
    Args:
        target: Target IP address
        start_port: Starting port number
        end_port: Ending port number
        scan_mode: "fast" or "normal"
    """
    print("\n" + "="*60)
    print("PORT SCAN TEST - IDS Detection Simulator")
    print("="*60)
    print(f"\nTarget IP: {target}")
    print(f"Port Range: {start_port}-{end_port}")
    print(f"Scan Mode: {scan_mode.upper()}")
    print(f"Your IP: {get_local_ip()}")
    print("\n⚠️  This will trigger the IDS PORT_SCAN alert!")
    print(f"IDS Threshold: 20 ports in 5 seconds")
    print("\nStarting scan in 3 seconds...")
    time.sleep(3)
    
    print("\n" + "-"*60)
    print("SCANNING... (Using concurrent connections for speed)")
    print("-"*60)
    
    
    open_ports = []
    start_time = datetime.now()
    
    # Concurrent scanning for speed
    timeout = 0.1 if scan_mode == "fast" else 0.3
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # Submit all port scans
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port 
            for port in range(start_port, end_port + 1)
        }
        
        # Collect results as they complete
        for i, future in enumerate(concurrent.futures.as_completed(future_to_port), 1):
            port = future_to_port[future]
            try:
                is_open = future.result()
                if is_open:
                    print(f"✓ Port {port:5d} - OPEN")
                    open_ports.append(port)
                else:
                    # Show progress every 10 ports
                    if i % 10 == 0:
                        print(f"  Scanned {i} ports...", end='\r')
            except Exception:
                pass
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Results
    total_ports = end_port - start_port + 1
    closed_ports = total_ports - len(open_ports)
    
    print("\n\n" + "="*60)
    print("SCAN COMPLETE")
    print("="*60)
    print(f"Ports Scanned: {total_ports}")
    print(f"Open Ports: {len(open_ports)}")
    print(f"Closed Ports: {closed_ports}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Speed: {total_ports/duration:.1f} ports/second")
    
    if open_ports:
        print(f"\nOpen Ports Found: {', '.join(map(str, open_ports[:10]))}")
        if len(open_ports) > 10:
            print(f"  ... and {len(open_ports) - 10} more")
    
    print("\n🎯 IDS Detection Expected:")
    if (end_port - start_port + 1) >= 20:
        print("   ✅ YES - Scanned 20+ ports, should trigger PORT_SCAN alert")
    else:
        print(f"   ⚠️  MAYBE - Only {end_port - start_port + 1} ports scanned (threshold: 20)")
    
    print("\n💡 Check your IDS for PORT_SCAN alert from: " + get_local_ip())
    print("="*60)

def main():
    """Main function"""
    print("\n" + "="*60)
    print("PORT SCAN TEST SCRIPT FOR IDS")
    print("="*60)
    print("\nThis script simulates a port scanning attack to test")
    print("your IDS port scan detection capability.")
    print("\nIMPORTANT:")
    print("1. Start your IDS with live capture FIRST")
    print("2. Run this script from the SAME network")
    print("3. Watch for PORT_SCAN alert in IDS")
    print("\n" + "="*60)
    
    # Get target IP
    print("\nEnter target IP address:")
    print("(This should be the IP of the machine running IDS)")
    local_ip = get_local_ip()
    print(f"Your current IP: {local_ip}")
    
    target = input("\nTarget IP [press Enter for localhost/127.0.0.1]: ").strip()
    
    if not target:
        target = "127.0.0.1"
        print(f"Using localhost: {target}")
    
    # Validate IP
    try:
        socket.inet_aton(target)
    except socket.error:
        print(f"\n❌ Invalid IP address: {target}")
        sys.exit(1)
    
    # Get port range
    print("\nPort Range Options:")
    print("1. Quick Test (1-30 ports) - Fast, guaranteed detection")
    print("2. Medium Test (1-50 ports) - Standard scan")
    print("3. Full Test (1-100 ports) - Comprehensive")
    print("4. Custom range")
    
    choice = input("\nChoice [1/2/3/4, default=1]: ").strip()
    
    if choice == "2":
        start_port, end_port = 1, 50
    elif choice == "3":
        start_port, end_port = 1, 100
    elif choice == "4":
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))
    else:
        start_port, end_port = 1, 30
    
    # Get scan mode
    print("\nScan Mode:")
    print("1. Fast - Concurrent scanning (RECOMMENDED for IDS test)")
    print("2. Normal - Concurrent but slightly slower")
    
    mode_choice = input("\nMode [1/2, default=1]: ").strip()
    scan_mode = "fast" if mode_choice != "2" else "normal"
    
    # Confirm
    print("\n" + "="*60)
    print("READY TO START")
    print("="*60)
    print(f"Target: {target}")
    print(f"Ports: {start_port}-{end_port} ({end_port - start_port + 1} ports)")
    print(f"Mode: {scan_mode.upper()}")
    print(f"\nEstimated time: ~{(end_port - start_port + 1) * 0.1:.1f} seconds")
    
    confirm = input("\nProceed? [y/N]: ").strip().lower()
    
    if confirm != 'y':
        print("\n❌ Cancelled")
        sys.exit(0)
    
    # Run the scan
    port_scan_attack(target, start_port, end_port, scan_mode)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
