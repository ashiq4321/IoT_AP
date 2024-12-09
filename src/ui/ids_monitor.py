# src/ui/ids_monitor.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                           QTableWidget, QTableWidgetItem, QFrame)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor
import pyqtgraph as pg

class IdsMonitorPanel(QWidget):
    def __init__(self, ids_manager):
        super().__init__()
        self.ids_manager = ids_manager
        self.update_interval = 1000  # 1 second
        
        self.setup_ui()
        self.start_updates()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Status panel
        status_frame = QFrame()
        status_frame.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Raised)
        status_layout = QVBoxLayout(status_frame)
        
        self.monitoring_label = QLabel("Monitoring Active")
        self.monitoring_label.setStyleSheet("font-weight: bold;")
        self.alert_label = QLabel("No Alerts")
        self.alert_label.setStyleSheet("color: green; font-weight: bold;")
        
        status_layout.addWidget(self.monitoring_label)
        status_layout.addWidget(self.alert_label)
        layout.addWidget(status_frame)

        # Traffic statistics table
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(5)
        headers = ["Device", "Current Rate", "Avg Rate", "Max Rate", "Alerts"]
        self.stats_table.setHorizontalHeaderLabels(headers)
        self.stats_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.stats_table.setSortingEnabled(True)
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
        self.stats_table.setRowCount(0)
        alert_count = 0

        for row, mac in enumerate(self.ids_manager.data_rates.keys()):
            stats = self.ids_manager.get_device_stats(mac)
            if not stats:
                continue

            self.stats_table.insertRow(row)
            current_rate = list(self.ids_manager.data_rates[mac])[-1]
            
            items = [
                QTableWidgetItem(mac),
                QTableWidgetItem(f"{current_rate:.2f} B/s"),
                QTableWidgetItem(f"{stats['avg_rate']:.2f} B/s"),
                QTableWidgetItem(f"{stats['max_rate']:.2f} B/s"),
                QTableWidgetItem(str(stats.get('alert_count', 0)))
            ]
            
            for col, item in enumerate(items):
                self.stats_table.setItem(row, col, item)
            
            alert_count += stats.get('alert_count', 0)

        # Update alert status
        if alert_count > 0:
            self.alert_label.setText(f"Active Alerts: {alert_count}")
            self.alert_label.setStyleSheet("color: red; font-weight: bold;")
        else:
            self.alert_label.setText("No Alerts")
            self.alert_label.setStyleSheet("color: green; font-weight: bold;")

        self.update_graph()

    def update_graph(self):
        self.graph.clear()
        
        for mac in self.ids_manager.data_rates.keys():
            rates = list(self.ids_manager.data_rates[mac])
            if rates:
                # Keep last 60 samples
                rates = rates[-60:]
                self.graph.plot(rates, name=mac[-8:], pen=(hash(mac) % 8, 8))