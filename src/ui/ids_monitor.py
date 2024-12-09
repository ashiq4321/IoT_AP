# src/ui/ids_monitor.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                           QTableWidget, QTableWidgetItem, QFrame, QPushButton,
                           QInputDialog, QMessageBox, QLineEdit, QMenu)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor
import pyqtgraph as pg
from datetime import datetime

class IdsMonitorPanel(QWidget):
    def __init__(self, ids_manager):
        super().__init__()
        self.ids_manager = ids_manager
        self.update_interval = 1000  # 1 second
        
        self.setup_ui()
        self.start_updates()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Alert panel
        self.alert_panel = QFrame()
        self.alert_panel.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Raised)
        alert_layout = QVBoxLayout(self.alert_panel)
        self.alert_labels = {}  # Store alert labels per device
        layout.addWidget(self.alert_panel)
        
        # Stats table with context menu
        self.stats_table = QTableWidget()
        self.stats_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.stats_table.customContextMenuRequested.connect(self.show_context_menu)
        self.stats_table.setColumnCount(6)
        headers = ["Device", "Current Rate", "Avg Rate", "Max Rate", "Threshold", "Status"]
        self.stats_table.setHorizontalHeaderLabels(headers)
        layout.addWidget(self.stats_table)

        # Traffic graph using PyQtGraph
        self.graph = pg.PlotWidget()
        self.graph.setTitle("Device Traffic History")
        self.graph.setLabel('left', "Data Rate (B/s)")
        self.graph.setLabel('bottom', "Time")
        self.graph.addLegend()
        self.plot_lines = {}  # Store plot lines for each device
        layout.addWidget(self.graph)

    def start_updates(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_display)
        self.timer.start(self.update_interval)

    def update_display(self):
        # Store current table data for devices
        current_data = {}
        for row in range(self.stats_table.rowCount()):
            mac = self.stats_table.item(row, 0).text()
            threshold = self.ids_manager.get_threshold(mac)
            current_data[mac] = threshold

        self.stats_table.setRowCount(0)
        
        # Clear old alert labels
        for label in self.alert_labels.values():
            label.setParent(None)
        self.alert_labels.clear()

        for row, mac in enumerate(self.ids_manager.data_rates.keys()):
            stats = self.ids_manager.get_device_stats(mac)
            if not stats:
                continue

            self.stats_table.insertRow(row)
            current_rate = list(self.ids_manager.data_rates[mac])[-1]
            
            # Use stored threshold or get default
            threshold = current_data.get(mac, self.ids_manager.get_threshold(mac))
            
            # Check if device has an active alert
            alert_status = "Normal"
            status_color = QColor(200, 255, 200)  # Light green
            
            if current_rate > threshold:
                alert_status = "ALERT"
                status_color = QColor(255, 200, 200)  # Light red
                self.create_alert_label(mac, current_rate, threshold)

            items = [
                QTableWidgetItem(mac),
                QTableWidgetItem(f"{current_rate:.2f} B/s"),
                QTableWidgetItem(f"{stats['avg_rate']:.2f} B/s"),
                QTableWidgetItem(f"{stats['max_rate']:.2f} B/s"),
                QTableWidgetItem(f"{threshold:.2f} B/s"),
                QTableWidgetItem(alert_status)
            ]
            
            for col, item in enumerate(items):
                self.stats_table.setItem(row, col, item)
                if col == 5:  # Status column
                    item.setBackground(status_color)

        # Auto-adjust column widths
        self.stats_table.resizeColumnsToContents()
        self.update_graph()

    def update_graph(self):
        self.graph.clear()
        
        for mac in self.ids_manager.data_rates.keys():
            rates = list(self.ids_manager.data_rates[mac])
            if rates:
                # Keep last 60 samples
                rates = rates[-60:]
                self.graph.plot(rates, name=mac[-8:], pen=(hash(mac) % 8, 8))

    def set_threshold(self):
        selected_items = self.stats_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Error", "Please select a device")
            return
            
        try:
            threshold = float(self.threshold_input.text())
            if threshold <= 0:
                QMessageBox.warning(self, "Error", "Threshold must be positive")
                return
                
            mac = self.stats_table.item(selected_items[0].row(), 0).text()
            self.ids_manager.set_threshold(mac, threshold)
            self.threshold_input.clear()
            
        except ValueError:
            QMessageBox.warning(self, "Error", "Invalid threshold value")

    def show_context_menu(self, position):
        row = self.stats_table.rowAt(position.y())
        if row < 0:
            return

        mac = self.stats_table.item(row, 0).text()
        current_threshold = self.ids_manager.get_threshold(mac)

        menu = QMenu()
        set_threshold = menu.addAction("Set Threshold")
        action = menu.exec(self.stats_table.viewport().mapToGlobal(position))

        if action == set_threshold:
            threshold, ok = QInputDialog.getDouble(
                self,
                "Set Threshold",
                f"Enter threshold for {mac} (B/s):",
                value=current_threshold,
                min=0.0,
                decimals=2
            )
            if ok and threshold > 0:
                self.ids_manager.set_threshold(mac, threshold)

    def create_alert_label(self, mac, current_rate, threshold):
        alert_text = (f"⚠️ Alert for {mac}\n"
                     f"Rate: {current_rate:.2f} B/s\n"
                     f"Threshold: {threshold:.2f} B/s\n"
                     f"Time: {datetime.now().strftime('%H:%M:%S')}")
        alert_label = QLabel(alert_text)
        alert_label.setStyleSheet(
            "color: red; background-color: #FFE0E0; padding: 5px; border-radius: 3px;"
        )
        self.alert_panel.layout().addWidget(alert_label)
        self.alert_labels[mac] = alert_label

    def update_alert_panel(self, current_alerts):
        # Remove old alert labels
        for label in self.alert_labels.values():
            label.deleteLater()
        self.alert_labels.clear()
        
        if current_alerts:
            # Add new alert labels
            for mac, message in current_alerts.items():
                label = QLabel(message)
                label.setStyleSheet("color: red; font-weight: bold;")
                self.alert_frame.layout().addWidget(label)
                self.alert_labels[mac] = label
        else:
            # Show "no alerts" message
            label = QLabel("No Active Alerts")
            label.setStyleSheet("color: green; font-weight: bold;")
            self.alert_frame.layout().addWidget(label)
            self.alert_labels['none'] = label

    def update_alert_status(self, alert_count):
        if alert_count > 0:
            self.alert_label.setText(f"Active Alerts: {alert_count}")
            self.alert_label.setStyleSheet("color: red; font-weight: bold;")
        else:
            self.alert_label.setText("No Alerts")
            self.alert_label.setStyleSheet("color: green; font-weight: bold;")