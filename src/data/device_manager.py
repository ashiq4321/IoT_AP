import json
import os
from typing import Dict, Optional
from datetime import datetime

class DeviceManager:
    def __init__(self, storage_file: str = "device_data.json"):
        self.storage_file = storage_file
        self.devices = self._load_devices()
    
    def _load_devices(self) -> Dict:
        """Load device data from storage file."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def save_devices(self):
        """Save device data to storage file."""
        with open(self.storage_file, 'w') as f:
            json.dump(self.devices, f, indent=4)
    
    def update_device(self, mac_address: str, device_info: Dict):
        """Update or add device information."""
        self.devices[mac_address] = device_info
        self.save_devices()
    
    def get_device_info(self, mac_address: str) -> Optional[Dict]:
        """Get stored information for a device."""
        return self.devices.get(mac_address)
    
    def merge_scan_data(self, scan_data: Dict):
        """Merge new scan data with stored device information."""
        stored_info = self.get_device_info(scan_data['mac'])
        if stored_info:
            scan_data.update({
                'name': stored_info.get('name', scan_data['hostname']),
                'vendor': stored_info.get('vendor', ''),
                'model': stored_info.get('model', ''),
                'version': stored_info.get('version', ''),
                'notes': stored_info.get('notes', '')
            })
        return scan_data