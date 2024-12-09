# src/ui/main_window.py
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                           QPushButton, QLabel, QTableWidget, QTableWidgetItem,
                           QStatusBar, QTabWidget, QMessageBox, QMenu, QDialog, QApplication)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
import json
import os
from .ids_monitor import IdsMonitorPanel
from ..network.device_scanner import DeviceScanner
from ..network.packet_capture import PacketCaptureManager
from ..data.device_manager import DeviceManager
from datetime import datetime
from .device_editor import DeviceEditorDialog
from .packet_capture_dialog import PacketCaptureDialog

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scanner = DeviceScanner()
        self.device_manager = DeviceManager()
        self.packet_capture_manager = PacketCaptureManager()
        
        self.setWindowTitle("Network Device Monitor")
        self.setGeometry(100, 100, 1200, 700)
        
        self.setup_ui()
        self.load_stored_devices()

    def setup_ui(self):
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Devices tab
        devices_widget = QWidget()
        devices_layout = QVBoxLayout(devices_widget)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("Network Device Monitor")
        title_label.setFont(QFont('Arial', 16, QFont.Weight.Bold))
        self.last_scan_label = QLabel("Last scan: Never")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.last_scan_label)
        devices_layout.addLayout(header_layout)

        # Stats panel
        stats_layout = QHBoxLayout()
        self.total_devices_label = QLabel("Total Devices: 0")
        self.active_devices_label = QLabel("Active Devices: 0")
        stats_layout.addWidget(self.total_devices_label)
        stats_layout.addWidget(self.active_devices_label)
        stats_layout.addStretch()
        devices_layout.addLayout(stats_layout)

        # Device table
        self.table = QTableWidget()
        self.setup_table()
        devices_layout.addWidget(self.table)

        # Control buttons
        controls_layout = QHBoxLayout()
        scan_btn = QPushButton("Scan Network")
        scan_btn.setObjectName("scan_btn")
        scan_btn.clicked.connect(self.detect_devices_handler)
        
        controls_layout.addWidget(scan_btn)
        controls_layout.addStretch()
        
        self.capture_btn = QPushButton("Start Packet Capture")
        self.capture_btn.setEnabled(False)  # Initially disabled
        self.capture_btn.clicked.connect(self.open_packet_capture)
        controls_layout.addWidget(self.capture_btn)
        
        devices_layout.addLayout(controls_layout)

        # Add devices tab
        self.tab_widget.addTab(devices_widget, "Devices")

        # Add IDS Monitor tab
        self.ids_monitor = IdsMonitorPanel(
            ids_manager=self.packet_capture_manager.ids_manager,
            packet_capture_manager=self.packet_capture_manager
        )
        self.tab_widget.addTab(self.ids_monitor, "IDS Monitor")

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def detect_devices_handler(self):
        """Scan for devices connected to Windows hotspot"""
        try:
            # Disable scan button during scan
            scan_btn = self.findChild(QPushButton, "scan_btn")
            if (scan_btn):
                scan_btn.setEnabled(False)

            # Initial status
            self.status_bar.showMessage("🔍 Initializing network scan...")
            QApplication.processEvents()  # Update UI

            # Check hotspot
            self.status_bar.showMessage("🔍 Checking hotspot status...")
            is_active, hotspot_ip, status = self.scanner.check_hotspot()
            if not is_active:
                raise Exception("Windows Mobile Hotspot is not active")

            # Start scanning
            self.status_bar.showMessage("🔍 Scanning network for connected devices...")
            QApplication.processEvents()

            # Scan for devices
            found_devices = self.scanner.scan_network(hotspot_ip)
            
            # Update device manager
            self.status_bar.showMessage("📝 Updating device database...")
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Mark inactive devices
            for device in self.device_manager.devices.values():
                device['is_active'] = False
                
            # Process found devices
            for device in found_devices:
                mac = self.device_manager.normalize_mac(device['mac'])
                if mac in self.device_manager.devices:
                    self.device_manager.devices[mac].update({
                        'ip': device['ip'],
                        'is_active': True,
                        'last_seen': current_time
                    })
                else:
                    self.device_manager.devices[mac] = {
                        'name': device['hostname'],
                        'ip': device['ip'],
                        'mac': mac,
                        'vendor': '',
                        'model': '',
                        'is_active': True,
                        'last_seen': current_time
                    }

            # Save and update UI
            self.device_manager.save_devices()
            self.load_stored_devices()
            
            # Show results
            active_count = sum(1 for d in self.device_manager.devices.values() if d['is_active'])
            self.status_bar.showMessage(f"✅ Scan complete - Found {active_count} active devices")
            self.last_scan_label.setText(f"Last scan: {current_time}")

        except Exception as e:
            self.status_bar.showMessage(f"❌ Scan failed: {str(e)}")
            QMessageBox.warning(self, "Error", f"Network scan failed: {str(e)}")
        
        finally:
            # Re-enable scan button
            if scan_btn:
                scan_btn.setEnabled(True)

    def setup_table(self):
        columns = ['Device Name', 'IP Address', 'MAC Address', 'Vendor', 
                  'Model', 'Status', 'Last Seen']
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        # Set column widths
        widths = [150, 120, 150, 120, 120, 80, 100]
        for i, width in enumerate(widths):
            self.table.setColumnWidth(i, width)
        
        # Enable double-click editing
        self.table.doubleClicked.connect(self.edit_selected_device)
        
        # Setup context menu
        self.setup_context_menu()
        
        # Enable capture button when device selected
        self.table.itemSelectionChanged.connect(self.update_button_states)
    
    def load_stored_devices(self):
        """Load and display stored devices"""
        try:
            devices = self.device_manager.get_stored_devices()
            if not devices:
                self.status_bar.showMessage("No stored devices found")
                return

            self.table.setRowCount(0)
            for device_data in devices.values():
                row = self.table.rowCount()
                self.table.insertRow(row)
                
                # Create table items
                items = [
                    QTableWidgetItem(device_data.get('name', 'Unknown')),
                    QTableWidgetItem(device_data.get('ip', '')),
                    QTableWidgetItem(device_data.get('mac', '')),
                    QTableWidgetItem(device_data.get('vendor', '')),
                    QTableWidgetItem(device_data.get('model', '')),
                    QTableWidgetItem('Active' if device_data.get('is_active', False) else 'Inactive'),
                    QTableWidgetItem(device_data.get('last_seen', 'Never'))
                ]
                
                # Set items in table
                for col, item in enumerate(items):
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.table.setItem(row, col, item)
                    
                    # Highlight active devices
                    if col == 5 and item.text() == 'Active':
                        item.setBackground(QColor('#c8e6c9'))  # Light green

            self.status_bar.showMessage(f"Loaded {len(devices)} devices")

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load devices: {str(e)}")
            self.status_bar.showMessage("Error loading devices")

    def setup_context_menu(self):
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        self.context_menu = QMenu(self)
        
        # Existing actions
        refresh_action = self.context_menu.addAction("Refresh Device")
        refresh_action.triggered.connect(self.refresh_selected_device)
        
        forget_action = self.context_menu.addAction("Forget Device")
        forget_action.triggered.connect(self.forget_selected_device)

        # Add separator
        self.context_menu.addSeparator()
        
        # Add packet capture action
        capture_action = self.context_menu.addAction("Start Packet Capture")
        capture_action.triggered.connect(self.open_packet_capture)

    def show_context_menu(self, position):
        selected = len(self.table.selectedItems()) > 0
        for action in self.context_menu.actions():
            action.setEnabled(selected)
        self.context_menu.exec(self.table.viewport().mapToGlobal(position))

    def get_selected_device(self):
        """Get selected device data from table"""
        row = self.table.currentRow()
        if (row >= 0):
            mac = self.table.item(row, 2).text()  # MAC address column
            return mac, self.device_manager.devices.get(mac)
        return None, None

    def edit_selected_device(self):
        """Open dialog to edit selected device"""
        mac, device = self.get_selected_device()
        if device:
            dialog = DeviceEditorDialog(self, device)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                # Update device data
                updated_data = dialog.get_device_data()
                self.device_manager.devices[mac].update(updated_data)
                self.device_manager.save_devices()
                self.load_stored_devices()
                self.status_bar.showMessage("Device updated successfully")

    def forget_selected_device(self):
        """Remove selected device from stored devices"""
        mac, device = self.get_selected_device()
        if device:
            reply = QMessageBox.question(
                self, 
                'Confirm Delete',
                f'Are you sure you want to forget device {device["name"]}?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                del self.device_manager.devices[mac]
                self.device_manager.save_devices()
                self.load_stored_devices()
                self.status_bar.showMessage("Device forgotten")
    
    def update_button_states(self):
        selected = len(self.table.selectedItems()) > 0
        self.capture_btn.setEnabled(selected)

    def open_packet_capture(self):
        selected_row = self.table.currentRow()
        if selected_row >= 0:
            device_info = {
                'mac': self.table.item(selected_row, 0).text(),
                'ip': self.table.item(selected_row, 1).text(),
                'name': self.table.item(selected_row, 2).text()
            }
            
            dialog = PacketCaptureDialog(
                self,
                device_info,
                self.packet_capture_manager
            )
            dialog.show()
        # In src/ui/main_window.py
    
    def refresh_selected_device(self):
        """Refresh information for selected device."""
        selected_row = self.table.currentRow()
        if selected_row >= 0:
            mac = self.table.item(selected_row, 0).text()
            ip = self.table.item(selected_row, 1).text()
            
            # Scan single device
            device = self.scanner.scan_device(ip, mac)
            
            if device:
                # Update table with new info
                self.table.setItem(selected_row, 1, QTableWidgetItem(device.get('ip', '')))
                self.table.setItem(selected_row, 2, QTableWidgetItem(device.get('name', '')))
                self.table.setItem(selected_row, 3, QTableWidgetItem(device.get('vendor', '')))
                self.table.setItem(selected_row, 4, QTableWidgetItem(device.get('last_seen', '')))
                self.table.setItem(selected_row, 5, QTableWidgetItem('Yes' if device.get('active') else 'No'))
                
                self.status_bar.showMessage(f"Device {mac} refreshed successfully", 3000)
            else:
                self.status_bar.showMessage(f"Failed to refresh device {mac}", 3000)