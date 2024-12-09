# src/ui/main_window.py
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import time
from datetime import datetime
from ..ui.ids_monitor import IdsMonitorPanel
from ..network.device_scanner import DeviceScanner
from ..network.packet_capture import PacketCaptureManager
from typing import List, Dict
from ..data.device_manager import DeviceManager
from .device_editor import DeviceEditorDialog

from .packet_capture_dialog import PacketCaptureDialog

class ModernTable(ttk.Treeview):
    def __init__(self, parent, columns):
        super().__init__(parent, columns=columns, show='headings')
        self.setup_columns(columns)
        self.setup_style()
        
    def setup_columns(self, columns):
        # Column configurations
        column_configs = {
            'Device Name': {'width': 150, 'anchor': 'w'},
            'IP Address': {'width': 120, 'anchor': 'center'},
            'MAC Address': {'width': 150, 'anchor': 'center'},
            'Vendor': {'width': 120, 'anchor': 'w'},
            'Model': {'width': 120, 'anchor': 'w'},
            'Status': {'width': 80, 'anchor': 'center'},
            'Last Seen': {'width': 100, 'anchor': 'center'},
            'Capture Status': {'width': 120, 'anchor': 'center'}
        }
        
        for col in columns:
            config = column_configs.get(col, {'width': 150, 'anchor': 'center'})
            self.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.column(col, width=config['width'], anchor=config['anchor'])
            
    def setup_style(self):
        style = ttk.Style()
        style.configure('Treeview', rowheight=30, font=('Arial', 10))
        style.configure('Treeview.Heading', font=('Arial', 11, 'bold'))
        
    def sort_column(self, col):
        """Sort tree contents when a column header is clicked."""
        # Get all items in the tree
        items = [(self.set(item, col), item) for item in self.get_children('')]
        
        # Sort by the selected column
        items.sort()
        
        # Rearrange items in sorted positions
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
        self.root.geometry("1200x700")
        self.scanner = DeviceScanner()
        self.device_manager = DeviceManager()
        self.packet_capture_manager = PacketCaptureManager()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.setup_styles()
        self.setup_ui()
        self.load_stored_devices()
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create main frame for existing UI
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="Devices")
        
        # Move existing UI elements to main_frame instead of root
        # Status bar frame
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Table frame 
        self.table_frame = ttk.Frame(self.main_frame)
        self.table_frame.pack(fill=tk.BOTH, expand=True)
        # Add IDS monitoring tab
        self.ids_monitor = IdsMonitorPanel(self.notebook, self.packet_capture_manager.ids_manager)
        self.notebook.add(self.ids_monitor, text="IDS Monitor")
      
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

    def setup_context_menu(self):
        """Set up the right-click context menu with packet capture option."""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Packet Capture", command=self.start_packet_capture)
        self.context_menu.add_command(label="Forget", command=self.forget_selected_device)
        self.table.bind('<Button-3>', self.show_context_menu)

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
        
        # Create table without capture status column
        columns = ('Device Name', 'IP Address', 'MAC Address', 'Vendor', 
                  'Model', 'Status', 'Last Seen')
        self.table = ModernTable(table_frame, columns)
        self.table.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        # Add double-click binding
        self.table.bind('<Double-1>', self.edit_device)
        
        # Set up context menu
        self.setup_context_menu()
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT)
        self.table.configure(yscrollcommand=scrollbar.set)

    def start_packet_capture(self):
        """Open packet capture dialog for selected device."""
        selected = self.table.selection()
        if not selected:
            return
            
        # Get device info
        values = self.table.item(selected[0])['values']
        if not values:
            return
            
        device_info = {
            'name': values[0],
            'ip': values[1],
            'mac': values[2],
            'vendor': values[3],
            'model': values[4]
        }
        
        # Open packet capture dialog
        PacketCaptureDialog(self.root, device_info, self.packet_capture_manager)
        

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

    def load_stored_devices(self):
        """Load and display stored devices from device_data.json with status check"""
        stored_devices = self.device_manager.get_all_devices()
        devices_list = []
        
        # Check hotspot status first
        is_active, hotspot_ip, _ = self.scanner.check_hotspot()
        
        # If hotspot is active, get currently active devices
        active_macs = set()
        if is_active:
            hotspot_subnet = ".".join(hotspot_ip.split('.')[:3])
            current_scan = self.scanner.scan_network(hotspot_subnet)
            active_macs = {device['mac'] for device in current_scan}
            
        # Process stored devices
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for mac, device in stored_devices.items():
            # Check if device is in currently active devices
            is_device_active = mac in active_macs
            
            device_info = {
                'name': device.get('name', 'Unknown Device'),
                'ip': device.get('ip', ''),
                'mac': mac,
                'vendor': device.get('vendor', ''),
                'model': device.get('model', ''),
                'version': device.get('version', ''),
                'notes': device.get('notes', ''),
                'is_active': is_device_active,
                'last_seen': current_time if is_device_active else device.get('last_seen', 'Never')
            }
            
            # Update the stored device info if status changed
            if is_device_active:
                self.device_manager.update_device(mac, device_info)
            
            devices_list.append(device_info)
        
        # Add any new active devices that weren't in storage
        if is_active:
            for device in current_scan:
                mac = device['mac']
                if mac not in stored_devices:
                    device_info = self.device_manager.merge_scan_data(device, is_active=True)
                    device_info['last_seen'] = current_time
                    devices_list.append(device_info)
                    # Save new device to storage
                    self.device_manager.update_device(mac, device_info)
        
        # Populate the table with devices
        if devices_list:
            self.populate_table(devices_list)
            active_count = sum(1 for device in devices_list if device.get('is_active', False))
            self.status_bar.update_status(
                f"Loaded {len(devices_list)} devices. {active_count} currently active."
            )
        else:
            self.status_bar.update_status("No stored devices found")
            
        # Update statistics
        device_dict = {device['mac']: device for device in devices_list}
        self.update_stats(device_dict)
        
        # Update last scan time if we performed a scan
        if is_active:
            self.last_scan_label.config(
                text=f"Last scan: {datetime.now().strftime('%H:%M:%S')}"
            )
    def detect_devices_handler(self):
        """Handle the device detection button click."""
        self.scan_button.state(['disabled'])
        
        # Check hotspot status
        is_active, hotspot_ip, status_message = self.scanner.check_hotspot()
        
        if not is_active:
            self.status_bar.update_status(f"Error: {status_message}")
            self.scan_button.state(['!disabled'])
            return
        
        self.status_bar.update_status("Scanning network...")
        self.root.update()
        
        # Get hotspot info
        hotspot_info = self.scanner.get_hotspot_info()
        
        # Get currently active devices and merge with stored data
        active_devices = {}
        hotspot_subnet = ".".join(hotspot_ip.split('.')[:3])
        
        # Get stored devices first
        stored_devices = self.device_manager.get_all_devices()
        for mac, device in stored_devices.items():
            device_info = {
                'name': device.get('name', 'Unknown Device'),
                'ip': device.get('ip', ''),
                'mac': mac,
                'vendor': device.get('vendor', ''),
                'model': device.get('model', ''),
                'version': device.get('version', ''),
                'notes': device.get('notes', ''),
                'is_active': False,
                'last_seen': device.get('last_seen', 'Never')
            }
            active_devices[mac] = device_info
        
        # Update with currently active devices
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for device in self.scanner.scan_network(hotspot_subnet):
            mac = device['mac']
            device_info = self.device_manager.merge_scan_data(device, is_active=True)
            device_info['last_seen'] = current_time
            
            if mac in active_devices:
                # Update existing device info
                active_devices[mac].update(device_info)
                active_devices[mac]['is_active'] = True
                active_devices[mac]['last_seen'] = current_time
                # Save updated info to JSON
                self.device_manager.update_device(mac, active_devices[mac])
            else:
                # Add and save new device
                device_info['is_active'] = True
                active_devices[mac] = device_info
                # Save new device to JSON
                self.device_manager.update_device(mac, device_info)
        
        # Update inactive devices in storage
        for mac, device in active_devices.items():
            if not device['is_active']:
                self.device_manager.update_device(mac, device)
        
        # Update the table and stats
        self.populate_table(list(active_devices.values()))
        self.update_stats(active_devices)
        
        # Update last scan time
        self.last_scan_label.config(
            text=f"Last scan: {datetime.now().strftime('%H:%M:%S')}"
        )
        
        # Calculate active devices count
        active_count = sum(1 for device in active_devices.values() if device['is_active'])
        
        self.status_bar.update_status(
            f"Scan complete. Found {active_count} active devices. "
            f"Total devices: {len(active_devices)}. "
            f"Hotspot reports {hotspot_info.get('ClientCount', 0)} connected clients."
        )
        
        self.scan_button.state(['!disabled'])
    def populate_table(self, devices: List[Dict[str, str]]):
        """Populate the table with detected devices."""
        # Clear existing items
        for item in self.table.get_children():
            self.table.delete(item)
            
        # Add new items
        for device in devices:
            # Get capture status
            status = self.packet_capture_manager.get_capture_status(device['mac'])
            if status['running']:
                capture_status = f"{'Paused' if status['paused'] else 'Capturing'} ({status['packet_count']})"
            else:
                capture_status = ""
            
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
                    device['last_seen'],
                    capture_status
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

    def on_closing(self):
        """Handle application shutdown."""
        # Check if any captures are running
        active_captures = False
        for item in self.table.get_children():
            values = self.table.item(item)['values']
            if values and values[7]:  # Check capture status column
                active_captures = True
                break
        
        if active_captures:
            if messagebox.askyesno("Quit", "Some packet captures are still running. Stop them and quit?"):
                self.packet_capture_manager.cleanup()
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        """Start the application."""
        self.root.mainloop()