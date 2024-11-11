import socket
import subprocess
import re
import platform
from typing import List, Dict, Optional, Tuple

class DeviceScanner:
    @staticmethod
    def check_hotspot() -> Tuple[bool, Optional[str], str]:
        """
        Check if hotspot is active and get its IP.
        
        Returns:
            Tuple containing:
            - Boolean: True if hotspot is active
            - String or None: Hotspot IP if active, None otherwise
            - String: Status message
        """
        hostname = socket.gethostname()
        try:
            ip = socket.gethostbyname(hostname)
            # Check if it's a valid hotspot IP (typically 192.168.x.x)
            if ip.startswith('192.168.') and ip != '127.0.0.1':
                # Verify network connectivity
                if platform.system() == "Windows":
                    test = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                       capture_output=True, text=True)
                else:  # Linux/Mac
                    test = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                       capture_output=True, text=True)
                
                if test.returncode == 0:
                    return True, ip, f"Hotspot active with IP {ip}"
                else:
                    return False, None, "Hotspot IP found but network is not responding"
            else:
                return False, None, "No valid hotspot IP configuration found"
                
        except socket.gaierror:
            return False, None, "Error: Unable to retrieve hotspot IP"
        except subprocess.SubprocessError:
            return False, None, "Error: Unable to verify network connectivity"
        except Exception as e:
            return False, None, f"Unexpected error checking hotspot: {str(e)}"

    @staticmethod
    def get_hotspot_ip() -> Optional[str]:
        """Get the IP address of the hotspot."""
        is_active, ip, _ = DeviceScanner.check_hotspot()
        return ip if is_active else None

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