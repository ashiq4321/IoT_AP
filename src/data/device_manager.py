import json
import os
from typing import Dict, Optional
from datetime import datetime

class DeviceManager:
    def __init__(self):
        self.devices = {}
        self.data_file = "device_data.json"
        self.load_devices()

    def load_devices(self):
        """Load devices from JSON file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    self.devices = json.load(f)
                    # Normalize MAC addresses
                    normalized_devices = {}
                    for mac, device in self.devices.items():
                        normalized_mac = self.normalize_mac(mac)
                        device['mac'] = normalized_mac
                        normalized_devices[normalized_mac] = device
                    self.devices = normalized_devices
            return True
        except Exception as e:
            print(f"Error loading devices: {e}")
            self.devices = {}
            return False

    def normalize_mac(self, mac):
        """Normalize MAC address format to XX:XX:XX:XX:XX:XX"""
        clean_mac = mac.replace('-', ':').lower()
        return clean_mac

    def get_stored_devices(self):
        """Return stored devices"""
        return self.devices

    def save_devices(self):
        """Save devices to JSON file"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.devices, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving devices: {e}")
            return False
    
    def update_device(self, mac_address: str, device_info: Dict):
        """Update or add device information."""
        self.devices[mac_address] = device_info
        self.save_devices()
    
    def forget_device(self, mac_address: str):
        """Remove device from stored data."""
        if mac_address in self.devices:
            del self.devices[mac_address]
            self.save_devices()
    
    def get_device_info(self, mac_address: str) -> Optional[Dict]:
        """Get stored information for a device."""
        return self.devices.get(mac_address)
    
    def get_all_devices(self) -> Dict:
        """Get all stored devices."""
        return self.devices
    
    def merge_scan_data(self, scan_data: Dict, is_active: bool = True):
        """Merge new scan data with stored device information."""
        mac_address = scan_data['mac']
        stored_info = self.get_device_info(mac_address)
        
        merged_data = {
            'name': scan_data['hostname'],
            'ip': scan_data['ip'],
            'mac': mac_address,
            'vendor': '',
            'model': '',
            'version': '',
            'notes': '',
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': is_active
        }
        
        if stored_info:
            merged_data.update({
                'name': stored_info.get('name', scan_data['hostname']),
                'vendor': stored_info.get('vendor', ''),
                'model': stored_info.get('model', ''),
                'version': stored_info.get('version', ''),
                'notes': stored_info.get('notes', '')
            })
            
            # Keep the old last_seen time if device is not active
            if not is_active and 'last_seen' in stored_info:
                merged_data['last_seen'] = stored_info['last_seen']
        
        return merged_data