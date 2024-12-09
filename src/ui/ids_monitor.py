# src/ui/ids_monitor.py
import tkinter as tk
from tkinter import ttk
from typing import Dict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class IdsMonitorPanel(ttk.Frame):
    def __init__(self, parent, ids_manager):
        super().__init__(parent)
        self.ids_manager = ids_manager
        self.update_interval = 1000  # 1 second
        self.setup_ui()

    def setup_ui(self):
        # Status frame
        status_frame = ttk.LabelFrame(self, text="IDS Status")
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.monitoring_label = ttk.Label(status_frame, text="Monitoring Active")
        self.monitoring_label.pack(pady=5)
        
        self.alert_label = ttk.Label(status_frame, foreground="green", text="No Alerts")
        self.alert_label.pack(pady=5)
        
        # Device stats table
        columns = ("Device", "Current Rate", "Avg Rate", "Max Rate", "Alerts")
        self.stats_table = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            self.stats_table.heading(col, text=col)
            self.stats_table.column(col, width=100) 
        self.stats_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.stats_table.yview)
        self.stats_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Traffic graph
        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.after(self.update_interval, self.update_display)
        
    def update_display(self):
        """Update IDS monitoring display"""
        if not self.winfo_exists():
            return
            
        # Clear current display
        for item in self.stats_table.get_children():
            self.stats_table.delete(item)
            
        # Update device stats
        alert_count = 0
        for mac in self.ids_manager.data_rates.keys():
            stats = self.ids_manager.get_device_stats(mac)
            if stats:
                current_rate = list(self.ids_manager.data_rates[mac])[-1]
                self.stats_table.insert("", "end", values=(
                    mac,
                    f"{current_rate:.2f} B/s",
                    f"{stats['avg_rate']:.2f} B/s", 
                    f"{stats['max_rate']:.2f} B/s",
                    stats.get('alert_count', 0)
                ))
                alert_count += stats.get('alert_count', 0)
        
        # Update alert status
        if alert_count > 0:
            self.alert_label.configure(
                text=f"Active Alerts: {alert_count}",
                foreground="red"
            )
        
        # Update graph
        self.update_graph()
        
        self.after(self.update_interval, self.update_display)
        
    def update_graph(self):
        """Update traffic history graph"""
        self.ax.clear()
        
        for mac in self.ids_manager.data_rates.keys():
            rates = list(self.ids_manager.data_rates[mac])
            if rates:
                self.ax.plot(rates[-60:], label=mac[-8:])  # Last 60 samples
                
        self.ax.set_title("Device Traffic History")
        self.ax.set_ylabel("Data Rate (B/s)")
        self.ax.legend()
        self.canvas.draw()