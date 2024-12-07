# src/ui/packet_capture_dialog.py
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import os
from typing import Optional, Dict

class PacketCaptureDialog:
    def __init__(self, parent, device_info: Dict, capture_manager):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Packet Capture - {device_info['name']}")
        self.dialog.geometry("500x400")
        self.dialog.resizable(False, False)
        
        # Make dialog modal
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.device_info = device_info
        self.capture_manager = capture_manager
        self.setup_ui()
        
        # Start status update timer
        self.update_status()
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Capture Settings
        settings_frame = ttk.LabelFrame(main_frame, text="Capture Settings", padding="10")
        settings_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Duration
        duration_frame = ttk.Frame(settings_frame)
        duration_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(duration_frame, text="Duration (seconds):").pack(side=tk.LEFT)
        self.duration = tk.StringVar(value="")
        ttk.Entry(duration_frame, textvariable=self.duration, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Label(duration_frame, text="(optional)").pack(side=tk.LEFT)
        
        # Filename
        filename_frame = ttk.Frame(settings_frame)
        filename_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filename_frame, text="Filename:").pack(side=tk.LEFT)
        self.filename = tk.StringVar(value="")
        ttk.Entry(filename_frame, textvariable=self.filename, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Label(filename_frame, text=".pcap").pack(side=tk.LEFT)
        
        # Status Frame
        status_frame = ttk.LabelFrame(main_frame, text="Capture Status", padding="10")
        status_frame.pack(fill=tk.X, pady=10)
        
        self.status_label = ttk.Label(status_frame, text="Not running")
        self.status_label.pack(anchor=tk.W)
        
        
        # Control Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = ttk.Button(
            button_frame,
            text="Start Capture",
            command=self.start_capture
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.pause_button = ttk.Button(
            button_frame,
            text="Pause",
            command=self.pause_capture,
            state=tk.DISABLED
        )
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop",
            command=self.stop_capture,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Close",
            command=self.close
        ).pack(side=tk.RIGHT, padx=5)
    
    def start_capture(self):
        """Start packet capture with current settings."""
        try:
            duration = int(self.duration.get()) if self.duration.get() else None
            filename = self.filename.get()
            
            if filename and not filename.endswith('.pcap'):
                filename += '.pcap'
                
        except ValueError:
            messagebox.showerror(
                "Invalid Input",
                "Please enter a valid number for duration."
            )
            return
            
        # Start capture
        success = self.capture_manager.start_capture(
            self.device_info['mac'],
            self.device_info['ip'],
            filename=filename,
            duration=duration
        )
        
        if success:
            self.start_button.configure(state=tk.DISABLED)
            self.pause_button.configure(state=tk.NORMAL)
            self.stop_button.configure(state=tk.NORMAL)
        else:
            messagebox.showerror(
                "Error",
                "Failed to start packet capture. A capture might already be running."
            )
    
    def pause_capture(self):
        """Pause or resume packet capture."""
        status = self.capture_manager.get_capture_status(self.device_info['mac'])
        
        if status['paused']:
            # Resume capture
            self.capture_manager.resume_capture(self.device_info['mac'])
            self.pause_button.configure(text="Pause")
        else:
            # Pause capture
            self.capture_manager.pause_capture(self.device_info['mac'])
            self.pause_button.configure(text="Resume")
    
    def stop_capture(self):
        """Stop packet capture."""
        self.capture_manager.stop_capture(self.device_info['mac'])
        self.start_button.configure(state=tk.NORMAL)
        self.pause_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.DISABLED)
        self.pause_button.configure(text="Pause")
    
    def update_status(self):
        """Update status display."""
        if not self.dialog.winfo_exists():
            return
            
        try:
            status = self.capture_manager.get_capture_status(self.device_info['mac'])
            
            if status['running']:
                state = "Paused" if status['paused'] else "Running"
                self.status_label.configure(text=f"Status: {state}")
                # Keep controls in correct state while running
                self.start_button.configure(state=tk.DISABLED)
                self.pause_button.configure(state=tk.NORMAL)
                self.stop_button.configure(state=tk.NORMAL)
            else:
                self.status_label.configure(text="Status: Not running")
                # Reset controls when not running
                self.start_button.configure(state=tk.NORMAL)
                self.pause_button.configure(state=tk.DISABLED)
                self.stop_button.configure(state=tk.DISABLED)
                self.pause_button.configure(text="Pause")
                
        except Exception as e:
            logger.error(f"Error updating status: {str(e)}")
            
        # Schedule next update with shorter interval for responsiveness
        self.dialog.after(500, self.update_status)
    
    def close(self):
        """Close the dialog."""
        if self.capture_manager.get_capture_status(self.device_info['mac'])['running']:
            if messagebox.askyesno(
                "Stop Capture",
                "A capture is still running. Stop it and close?"
            ):
                self.stop_capture()
                self.dialog.destroy()
        else:
            self.dialog.destroy()
