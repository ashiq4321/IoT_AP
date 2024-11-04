import socket
import subprocess
import re
import platform

def get_hotspot_ip():
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        print("Error: Unable to retrieve hotspot IP.")
        return None

def scan_network(hotspot_subnet):
    # Check operating system for compatibility with arp command
    os_type = platform.system()
    
    # Windows uses 'arp -a'; Unix-based systems may differ
    if os_type == "Windows":
        arp_command = ["arp", "-a"]
    else:
        print("Non-Windows OS detected. Using `ip neigh` as a fallback for scanning.")
        arp_command = ["ip", "neigh"]
    
    try:
        result = subprocess.run(arp_command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running {arp_command}: {e}")
        return []
    
    devices = []
    for line in result.stdout.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})", line)
        if match:
            ip, mac = match.groups()
            if ip.startswith(hotspot_subnet) and mac.lower() != "ff-ff-ff-ff-ff-ff":
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown Device"
                devices.append({"ip": ip, "mac": mac, "hostname": hostname})
    
    return devices
