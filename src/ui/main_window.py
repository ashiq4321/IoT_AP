# src/ui/main_window.py
import tkinter as tk
from tkinter import ttk
import time
from datetime import datetime
from ..network.device_scanner import DeviceScanner
from typing import List, Dict
from ..data.device_manager import DeviceManager
from .device_editor import DeviceEditorDialog

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
        self.device_manager = DeviceManager()
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
        columns = ('Device Name', 'IP Address', 'MAC Address', 'Vendor', 'Model', 'Status', 'Last Seen')
        self.table = ModernTable(table_frame, columns)
        self.table.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        # Add double-click binding
        self.table.bind('<Double-1>', self.edit_device)

        # Add right-click menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Edit", command=self.edit_selected_device)
        self.context_menu.add_command(label="Forget", command=self.forget_selected_device)
        self.table.bind('<Button-3>', self.show_context_menu)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)
        self.table.configure(yscrollcommand=scrollbar.set)

    def show_context_menu(self, event):
        """Show context menu on right click."""
        item = self.table.identify_row(event.y)
        if item:
            self.table.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def edit_selected_device(self):
        """Edit the selected device."""
        selected = self.table.selection()
        if selected:
            self.edit_device(None, item=selected[0])

    def forget_selected_device(self):
        """Remove the selected device from stored data."""
        selected = self.table.selection()
        if selected:
            item = selected[0]
            values = self.table.item(item)['values']
            if values:
                mac_address = values[2]  # MAC address is the third column
                self.device_manager.forget_device(mac_address)
                self.table.delete(item)
                self.status_bar.update_status(f"Device {values[0]} has been forgotten.")
                self.update_stats()

    def edit_device(self, event):
        """Handle double-click on a device in the table."""
        item = self.table.selection()[0]
        values = self.table.item(item)['values']
        if not values:
            return
            
        # Get existing device data
        mac_address = values[2]  # MAC address is the third column
        device_data = {
            'name': values[0],
            'ip': values[1],
            'mac': mac_address,
            'vendor': values[3],
            'model': values[4]
        }
        
        # Get stored information
        stored_info = self.device_manager.get_device_info(mac_address)
        if stored_info:
            device_data.update(stored_info)
        
        # Open editor dialog
        editor = DeviceEditorDialog(self.root, device_data)
        self.root.wait_window(editor.dialog)
        
        # Update device information if changes were made
        if editor.result:
            self.device_manager.update_device(mac_address, editor.result)
            self.update_table_row(item, editor.result)

    def update_table_row(self, item, device_data):
        """Update a single row in the table with new device data."""
        self.table.item(item, values=(
            device_data['name'],
            device_data['ip'],
            device_data['mac'],
            device_data['vendor'],
            device_data['model'],
            'Active',
            datetime.now().strftime('%H:%M:%S')
        ))

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
        
        # Get currently active devices
        active_devices = {}
        hotspot_ip = self.scanner.get_hotspot_ip()
        if hotspot_ip:
            hotspot_subnet = ".".join(hotspot_ip.split('.')[:3])
            for device in self.scanner.scan_network(hotspot_subnet):
                device_info = self.device_manager.merge_scan_data(device, is_active=True)
                active_devices[device_info['mac']] = device_info
        
        # Get stored devices and update their status
        stored_devices = self.device_manager.get_all_devices()
        for mac, device in stored_devices.items():
            if mac not in active_devices:
                device_info = self.device_manager.merge_scan_data(
                    {'mac': mac, 'ip': device['ip'], 'hostname': device['name']},
                    is_active=False
                )
                active_devices[mac] = device_info
        
        # Update the table
        self.populate_table(list(active_devices.values()))
        self.update_stats(active_devices)
        self.last_scan_label.config(
            text=f"Last scan: {datetime.now().strftime('%H:%M:%S')}"
        )
        
        active_count = sum(1 for device in active_devices.values() if device['is_active'])
        self.status_bar.update_status(
            f"Scan complete. Found {active_count} active devices, "
            f"{len(active_devices) - active_count} inactive."
        )
        
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
                    device['name'],
                    device['ip'],
                    device['mac'],
                    device.get('vendor', ''),
                    device.get('model', ''),
                    'Active' if device['is_active'] else 'Inactive',
                    device['last_seen']
                )
            )


    def update_stats(self, devices: Dict[str, Dict] = None):
        """Update statistics display."""
        if devices is not None:
            total_devices = len(devices)
            active_devices = sum(1 for device in devices.values() if device['is_active'])
            self.total_devices_label.config(text=f"Total Devices: {total_devices}")
            self.active_devices_label.config(text=f"Active Devices: {active_devices}")

    def export_data(self):
        """Export the current device list to a CSV file."""
        # Implementation for exporting data
        self.status_bar.update_status("Export feature not implemented yet.")

    def run(self):
        """Start the application."""
        self.root.mainloop()