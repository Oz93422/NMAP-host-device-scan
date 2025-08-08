import socket
import nmap
import json
from datetime import datetime
import argparse
import hashlib
import sys

# Hash the server's IP address using SHA256
def hash_ip(server_ip):
    sha256_hash = hashlib.sha256(server_ip.encode())
    return sha256_hash.hexdigest()


class Server:
    
    #get server's IP address
    def find_server_ip(self):
        try:
            server_ip = socket.gethostbyname(socket.gethostname())
            return server_ip
        except socket.gaierror:
            print("Error: Could not resolve local hostname.")
            sys.exit(1)
    
    #scans the networks ports from port 1 to 1024
    def scan_network(self, server_ip):
        try:
            nmap_scanner = nmap.PortScanner()
            nmap_scanner.scan(server_ip, '1-1024')
            if server_ip not in nmap_scanner.all_hosts():
                print(f"Error: Host {server_ip} is not reachable or scanning failed.")
                sys.exit(1)
            return nmap_scanner
        except Exception as e:
            print(f"Scan failed: {e}")
            sys.exit(1)
    
    #prints the open ports
    def print_open_ports(self, server_ip, scan_data):
        print(f"Open ports on {server_ip}:")
        if server_ip not in scan_data.all_hosts():
            print("Host not found in scan results.")
            return
        if 'tcp' not in scan_data[server_ip]:
            print("No TCP ports found.")
            return
        for port, data in scan_data[server_ip]['tcp'].items():
            if data['state'] == 'open':
                print(f"Port: {port}, State: {data['state']}")

    #prints the closed ports
    def print_closed_ports(self, server_ip, scan_data):
        print(f"Closed ports on {server_ip}:")
        if server_ip not in scan_data.all_hosts():
            print("Host not found in scan results.")
            return
        if 'tcp' not in scan_data[server_ip]:
            print("No TCP ports found.")
            return
        for port, data in scan_data[server_ip]['tcp'].items():
            if data['state'] == 'closed':
                print(f"Port: {port}, State: {data['state']}")


    
    #creates a json report for open and closed ports
    def create_report(self, server_ip, scan_data):
        if server_ip not in scan_data.all_hosts():
            print("Host not found in scan results.")
            return
        if 'tcp' not in scan_data[server_ip]:
            print("No TCP ports found.")
            return
        open_ports = []
        closed_ports = []
        for port, data in scan_data[server_ip]['tcp'].items():
            if data['state'] == 'open':
                open_ports.append({"port": port, "state": data['state']})
            else:
                closed_ports.append({"port": port, "state": data['state']})
        report = {
            "server_ip": server_ip,
            "hashed_ip": hash_ip(server_ip),
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        try:
            with open("server_report.json", "w") as file:
                json.dump(report, file, indent=4)
                print("\n Report created successfully! (server_report.json)")
        except Exception as e:
            print(f"Failed to write report: {e}")

    #detects the server's risk level based on open ports
    def risk_level(self, scan_data, server_ip):
        if server_ip not in scan_data.all_hosts():
            print("Host not found in scan results.")
            return
        if 'tcp' not in scan_data[server_ip]:
            print("No TCP ports found.")
            return
        open_count = 0
        for port, data in scan_data[server_ip]['tcp'].items():
            if data['state'] == 'open':
                open_count += 1
        print("\n Risk Level:", end=" ")
        if open_count > 20:
            print("High")
        elif open_count > 10:
            print("Medium")
        else:
            print("Low")

    #uses argparse to handle command-line arguments
    def use_args(self):
        parser = argparse.ArgumentParser(description="Server Information Gathering Tool")
        parser.add_argument("-ip", "--server-ip", help="Specify the server IP address")
        parser.add_argument("-o", "--open-ports", action="store_true", help="Display open ports")
        parser.add_argument("-c", "--closed-ports", action="store_true", help="Display closed ports")
        parser.add_argument("-r", "--risk-level", action="store_true", help="Display risk level")
        parser.add_argument("-j", "--json-report", action="store_true", help="Create JSON report")
        parser.add_argument("-e", "--exit", action="store_true", help="Exit the program")
        return parser.parse_args()

    #main program
    def main(self):
        args = self.use_args()
        server_ip = args.server_ip if args.server_ip else self.find_server_ip()

        if not any([args.open_ports, args.closed_ports, args.risk_level, args.json_report, args.exit]):
            print("Choose an action in the terminal")
            print("Example: python3 main.py ... -o (open ports) -c (closed ports) -r (risk level) -j (json report) -e (exit)")
            return

        print(f"\n🔍 Scanning IP: {server_ip}")
        print(f"Hashed IP (SHA256): {hash_ip(server_ip)}")

        scan_data = self.scan_network(server_ip)
            
        
        if args.open_ports:
            self.print_open_ports(server_ip, scan_data)

        if args.closed_ports:
            self.print_closed_ports(server_ip, scan_data)

        if args.risk_level:
            self.risk_level(scan_data, server_ip)

        if args.json_report:
            self.create_report(server_ip, scan_data)

        if args.exit:
            print("\n Exiting the program...")
            sys.exit(0)
            


if __name__ == "__main__":
    Server().main()

