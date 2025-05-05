# Save as check_port.py

import socket
import sys

def check_port(host, port):
    """Check if a port is open on a host"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)  # 2 second timeout
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

if __name__ == "__main__":
    # Check common MySQL/MariaDB ports
    host = "127.0.0.1"
    ports_to_check = [3306, 3307, 3308]
    
    print(f"Checking for MySQL/MariaDB on {host}")
    for port in ports_to_check:
        if check_port(host, port):
            print(f"MySQL/MariaDB service found on port {port}")
        else:
            print(f"No service detected on port {port}")