# src/ui/main_window.py
import tkinter as tk
from tkinter import ttk
import time
from datetime import datetime
from ..network.device_scanner import DeviceScanner
from typing import List, Dict

class ModernTable(ttk.Treeview):
    def __init__(self, parent, columns):
        super().__init__(parent, columns=columns, show='headings')
        self.setup_columns(columns)
        self.setup_style()
        
    def setup_columns(self, columns):
        for col in columns:
            self.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.column(col, anchor='center', width=150)
            
    def setup_style(self):
        style = ttk.Style()
        style.configure('Treeview', rowheight=30, font=('Arial', 10))
        style.configure('Treeview.Heading', font=('Arial', 11, 'bold'))
        
    def sort_column(self, col):
        items = [(self.set(item, col), item) for item in self.get_children('')]
        items.sort()
        for index, (_, item) in enumerate(items):
            self.move(item, '', index)

class StatusBar(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        self.status_label = tk.Label(
            self,
            text="Ready",
            font=('Arial', 9),
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X, padx=5, pady=2)
        
    def update_status(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_label.config(text=f"{timestamp} - {message}")

class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Device Monitor")
        self.root.geometry("800x600")
        self.scanner = DeviceScanner()
        self.setup_styles()
        self.setup_ui()
        
    def setup_styles(self):
        self.root.configure(bg='#f0f0f0')
        style = ttk.Style()
        style.configure('Modern.TFrame', background='#f0f0f0')
        style.configure('Modern.TButton', 
                       padding=10, 
                       font=('Arial', 10, 'bold'))
        style.configure('Title.TLabel',
                       font=('Arial', 16, 'bold'),
                       background='#f0f0f0')
        style.configure('Stats.TLabel',
                       font=('Arial', 10),
                       background='#f0f0f0')

    def setup_ui(self):
        # Main container
        self.main_frame = ttk.Frame(self.root, style='Modern.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Title and last scan info
        self.setup_header()
        
        # Statistics panel
        self.setup_stats_panel()
        
        # Device table
        self.setup_table()
        
        # Control buttons
        self.setup_controls()
        
        # Status bar
        self.status_bar = StatusBar(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Initialize stats
        self.update_stats()

    def setup_header(self):
        header_frame = ttk.Frame(self.main_frame, style='Modern.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title = ttk.Label(
            header_frame,
            text="Network Device Monitor",
            style='Title.TLabel'
        )
        title.pack(side=tk.LEFT)
        
        self.last_scan_label = ttk.Label(
            header_frame,
            text="Last scan: Never",
            style='Stats.TLabel'
        )
        self.last_scan_label.pack(side=tk.RIGHT)

    def setup_stats_panel(self):
        self.stats_frame = ttk.Frame(self.main_frame, style='Modern.TFrame')
        self.stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.total_devices_label = ttk.Label(
            self.stats_frame,
            text="Total Devices: 0",
            style='Stats.TLabel'
        )
        self.total_devices_label.pack(side=tk.LEFT, padx=5)
        
        self.active_devices_label = ttk.Label(
            self.stats_frame,
            text="Active Devices: 0",
            style='Stats.TLabel'
        )
        self.active_devices_label.pack(side=tk.LEFT, padx=5)

    def setup_table(self):
        # Create frame for table and scrollbar
        table_frame = ttk.Frame(self.main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create table
        columns = ('Device Name', 'IP Address', 'MAC Address', 'Status', 'Last Seen')
        self.table = ModernTable(table_frame, columns)
        self.table.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)
        self.table.configure(yscrollcommand=scrollbar.set)

    def setup_controls(self):
        control_frame = ttk.Frame(self.main_frame, style='Modern.TFrame')
        control_frame.pack(fill=tk.X, pady=10)
        
        self.scan_button = ttk.Button(
            control_frame,
            text="Scan Network",
            style='Modern.TButton',
            command=self.detect_devices_handler
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            control_frame,
            text="Export Data",
            style='Modern.TButton',
            command=self.export_data
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            control_frame,
            text="Exit",
            style='Modern.TButton',
            command=self.root.quit
        ).pack(side=tk.RIGHT, padx=5)

    def detect_devices_handler(self):
        """Handle the device detection button click."""
        self.scan_button.state(['disabled'])
        self.status_bar.update_status("Scanning network...")
        self.root.update()
        
        hotspot_ip = self.scanner.get_hotspot_ip()
        if hotspot_ip:
            hotspot_subnet = ".".join(hotspot_ip.split('.')[:3])
            devices = self.scanner.scan_network(hotspot_subnet)
            self.populate_table(devices)
            self.update_stats(devices)
            self.last_scan_label.config(
                text=f"Last scan: {datetime.now().strftime('%H:%M:%S')}"
            )
            self.status_bar.update_status(f"Scan complete. Found {len(devices)} devices.")
        else:
            self.status_bar.update_status("Error: Could not retrieve hotspot IP.")
            
        self.scan_button.state(['!disabled'])

    def populate_table(self, devices: List[Dict[str, str]]):
        """Populate the table with detected devices."""
        # Clear existing items
        for item in self.table.get_children():
            self.table.delete(item)
            
        # Add new items
        for device in devices:
            self.table.insert(
                '',
                'end',
                values=(
                    device['hostname'],
                    device['ip'],
                    device['mac'],
                    'Active',
                    datetime.now().strftime('%H:%M:%S')
                )
            )

    def update_stats(self, devices: List[Dict[str, str]] = None):
        """Update statistics display."""
        if devices is not None:
            self.total_devices_label.config(text=f"Total Devices: {len(devices)}")
            self.active_devices_label.config(text=f"Active Devices: {len(devices)}")

    def export_data(self):
        """Export the current device list to a CSV file."""
        # Implementation for exporting data
        self.status_bar.update_status("Export feature not implemented yet.")

    def run(self):
        """Start the application."""
        self.root.mainloop()