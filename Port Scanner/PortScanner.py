import pyfiglet
import sys
import socket
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
import os

if not os.path.exists("IPs Scanned"):
    os.makedirs("IPs Scanned")

ascii_banner = pyfiglet.figlet_format("Port Scanner - Made By Exploits")
print(ascii_banner)

target = input("Enter the IP or hostname you want to scan: ").strip()

try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("Invalid hostname or IP address")
    sys.exit()

print("-" * 50)
print(f"Scanning Target: {target_ip}")
print(f"Scanning started at: {str(datetime.now())}")
print("-" * 50)

open_ports_tcp = []
closed_ports_tcp = []
open_ports_udp = []
closed_ports_udp = []

timeout = 1

def scan_tcp_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(timeout)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            open_ports_tcp.append(port)
        else:
            closed_ports_tcp.append(port)
        s.close()
    except socket.error as e:
        print(f"Error with port {port} (TCP): {e}")

def scan_udp_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket.setdefaulttimeout(timeout)
        s.sendto(b'', (target_ip, port))
        open_ports_udp.append(port)
        s.close()
    except socket.error as e:
        closed_ports_udp.append(port)

def scan_ports_in_range(start, end, scan_type='both'):
    with ThreadPoolExecutor(max_workers=50) as executor:
        if scan_type in ['both', 'tcp']:
            for port in range(start, end):
                executor.submit(scan_tcp_port, port)
        if scan_type in ['both', 'udp']:
            for port in range(start, end):
                executor.submit(scan_udp_port, port)

def get_port_range():
    print("\nPlease enter the port range to scan.")
    while True:
        try:
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                print("Invalid port range. Please enter a valid range between 1 and 65535.")
            else:
                break
        except ValueError:
            print("Invalid input. Please enter numeric values for ports.")
    return start_port, end_port

def get_scan_type():
    scan_type = input("\nChoose scan type: (1) TCP, (2) UDP, (3) Both: ").strip()
    if scan_type == '1':
        return 'tcp'
    elif scan_type == '2':
        return 'udp'
    else:
        return 'both'

def generate_report():
    ip_filename = f"IPs Scanned/{target}_scanned.txt"


    report = f"Port Scan Results for {target}\n"
    report += "=" * 50 + "\n"
    report += f"Scanning started at: {str(datetime.now())}\n\n"
    

    report += "TCP Port Results:\n"
    report += f"Open TCP ports: {len(open_ports_tcp)}\n"
    report += f"Closed TCP ports: {len(closed_ports_tcp)}\n"
    report += "Open TCP Ports: " + ', '.join(map(str, open_ports_tcp)) + "\n"
    report += "Closed TCP Ports: " + ', '.join(map(str, closed_ports_tcp)) + "\n"
    
    report += "UDP Port Results:\n"
    report += f"Open UDP ports: {len(open_ports_udp)}\n"
    report += f"Closed UDP ports: {len(closed_ports_udp)}\n"
    report += "Open UDP Ports: " + ', '.join(map(str, open_ports_udp)) + "\n"
    report += "Closed UDP Ports: " + ', '.join(map(str, closed_ports_udp)) + "\n"
    
    report += "=" * 50 + "\n"
    report += f"Scanning ended at: {str(datetime.now())}\n"
    
    # Save the report to the file
    with open(ip_filename, "w") as ip_file:
        ip_file.write(report)
    print(f"\nScan results saved to '{ip_filename}'")

def main():
    start_port, end_port = get_port_range()
    scan_type = get_scan_type()
    scan_ports_in_range(start_port, end_port + 1, scan_type)
    generate_report()

if __name__ == "__main__":
    main()
