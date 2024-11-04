# src/network/device_scanner.py
import socket
import subprocess
import re
import platform
from typing import List, Dict, Optional

class DeviceScanner:
    @staticmethod
    def get_hotspot_ip() -> Optional[str]:
        """Get the IP address of the hotspot."""
        hostname = socket.gethostname()
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            print("Error: Unable to retrieve hotspot IP.")
            return None

    @staticmethod
    def scan_network(hotspot_subnet: str) -> List[Dict[str, str]]:
        """Scan the network for connected devices."""
        os_type = platform.system()
        arp_command = ["arp", "-a"] if os_type == "Windows" else ["ip", "neigh"]
        
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
                    hostname = DeviceScanner._get_hostname(ip)
                    devices.append({"ip": ip, "mac": mac, "hostname": hostname})
        
        return devices
    
    @staticmethod
    def _get_hostname(ip: str) -> str:
        """Get hostname for an IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown Device"