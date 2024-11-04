# src/ui/main_window.py
import tkinter as tk
from ..network.device_scanner import DeviceScanner
from typing import List, Dict

class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Hotspot Device Detector")
        self.root.geometry("600x400")
        self.scanner = DeviceScanner()
        self.setup_ui()

    def setup_ui(self):
        """Setup the main UI components."""
        self._create_title()
        self.devices_table = self._create_devices_table()
        self._create_buttons()

    def _create_title(self):
        title_label = tk.Label(
            self.root, 
            text="Devices Connected to Your Hotspot",
            font=("Arial", 14)
        )
        title_label.pack(pady=10)

    def _create_devices_table(self) -> tk.Frame:
        devices_table = tk.Frame(self.root)
        devices_table.pack(pady=10)
        return devices_table

    def _create_buttons(self):
        tk.Button(
            self.root,
            text="Detect Devices",
            command=self.detect_devices_handler
        ).pack(pady=10)

        tk.Button(
            self.root,
            text="Exit",
            command=self.root.quit
        ).pack(pady=10)

    def detect_devices_handler(self):
        """Handle the device detection button click."""
        hotspot_ip = self.scanner.get_hotspot_ip()
        if hotspot_ip:
            hotspot_subnet = ".".join(hotspot_ip.split('.')[:3])
            devices = self.scanner.scan_network(hotspot_subnet)
            self.populate_table(devices)

    def populate_table(self, devices: List[Dict[str, str]]):
        """Populate the table with detected devices."""
        for widget in self.devices_table.winfo_children():
            widget.destroy()

        headers = ["Device Name", "IP Address", "MAC Address"]
        for idx, header in enumerate(headers):
            tk.Label(
                self.devices_table,
                text=header,
                font=('Arial', 12, 'bold')
            ).grid(row=0, column=idx, padx=10, pady=5)

        if not devices:
            tk.Label(
                self.devices_table,
                text="No devices found"
            ).grid(row=1, column=0, columnspan=3, padx=10, pady=10)
            return

        for idx, device in enumerate(devices, 1):
            tk.Label(
                self.devices_table,
                text=device['hostname']
            ).grid(row=idx, column=0, padx=10, pady=5)
            tk.Label(
                self.devices_table,
                text=device['ip']
            ).grid(row=idx, column=1, padx=10, pady=5)
            tk.Label(
                self.devices_table,
                text=device['mac']
            ).grid(row=idx, column=2, padx=10, pady=5)

    def run(self):
        """Start the application."""
        self.root.mainloop()