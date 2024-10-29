import socket
import subprocess
import re

def get_hotspot_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def scan_network(hotspot_subnet):
    # Run arp -a to list all connected devices
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    
    devices = []
    for line in result.stdout.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})", line)
        if match:
            ip, mac = match.groups()
            # Check if the IP belongs to the same subnet as the hotspot
            if ip.startswith(hotspot_subnet) and mac.lower() != "ff-ff-ff-ff-ff-ff":
                # Attempt to resolve the hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown Device"  # Default if hostname can't be resolved
                devices.append({"ip": ip, "mac": mac, "hostname": hostname})
    
    return devices
