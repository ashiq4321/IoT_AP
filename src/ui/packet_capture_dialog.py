# src/ui/packet_capture_dialog.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QLineEdit, QPushButton, QFrame, QGroupBox, QMessageBox)
from PyQt6.QtCore import QTimer, Qt

class PacketCaptureDialog(QDialog):
    def __init__(self, parent, device_info, capture_manager):
        super().__init__(parent)
        self.device_info = device_info
        self.capture_manager = capture_manager
        
        self.setWindowTitle(f"Packet Capture - {device_info['name']}")
        self.setModal(True)
        self.setMinimumWidth(400)
        
        self.setup_ui()
        self.start_status_updates()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Capture Settings
        settings_group = QGroupBox("Capture Settings")
        settings_layout = QVBoxLayout(settings_group)

        # Duration
        duration_layout = QHBoxLayout()
        duration_layout.addWidget(QLabel("Duration (seconds):"))
        self.duration_input = QLineEdit()
        duration_layout.addWidget(self.duration_input)
        duration_layout.addWidget(QLabel("(optional)"))
        settings_layout.addLayout(duration_layout)

        # Filename
        filename_layout = QHBoxLayout()
        filename_layout.addWidget(QLabel("Filename:"))
        self.filename_input = QLineEdit()
        filename_layout.addWidget(self.filename_input)
        filename_layout.addWidget(QLabel(".pcap"))
        settings_layout.addLayout(filename_layout)

        layout.addWidget(settings_group)

        # Status Frame
        status_group = QGroupBox("Capture Status")
        status_layout = QVBoxLayout(status_group)
        self.status_label = QLabel("Not running")
        status_layout.addWidget(self.status_label)
        layout.addWidget(status_group)

        # Control Buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        
        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(self.pause_capture)
        self.pause_button.setEnabled(False)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)

        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.pause_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)

    def start_status_updates(self):
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(500)

    def update_status(self):
        try:
            status = self.capture_manager.get_capture_status(self.device_info['mac'])
            
            if status['running']:
                state = "Paused" if status['paused'] else "Running"
                self.status_label.setText(f"Status: {state}")
                self.start_button.setEnabled(False)
                self.pause_button.setEnabled(True)
                self.stop_button.setEnabled(True)
            else:
                self.status_label.setText("Status: Not running")
                self.start_button.setEnabled(True)
                self.pause_button.setEnabled(False)
                self.stop_button.setEnabled(False)
                self.pause_button.setText("Pause")
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
 
    def start_capture(self):
        """Start packet capture with current settings."""
        try:
            # Fix: Use text() instead of get() for QLineEdit
            duration = int(self.duration_input.text()) if self.duration_input.text() else None
            filename = self.filename_input.text()
            
            if filename and not filename.endswith('.pcap'):
                filename += '.pcap'
                
            success = self.capture_manager.start_capture(
                self.device_info['mac'],
                self.device_info['ip'],
                filename=filename,
                duration=duration
            )
            
            if success:
                self.start_button.setEnabled(False)
                self.pause_button.setEnabled(True)
                self.stop_button.setEnabled(True)
            else:
                QMessageBox.critical(
                    self,
                    "Error", 
                    "Failed to start packet capture. A capture might already be running."
                )
                
        except ValueError:
            QMessageBox.critical(
                self,
                "Invalid Input",
                "Please enter a valid number for duration."
            )
    
    def pause_capture(self):
        """Pause or resume packet capture."""
        status = self.capture_manager.get_capture_status(self.device_info['mac'])
        
        if status['paused']:
            # Resume capture
            self.capture_manager.resume_capture(self.device_info['mac'])
            self.pause_button.setText("Pause")
        else:
            # Pause capture
            self.capture_manager.pause_capture(self.device_info['mac'])
            self.pause_button.setText("Resume")
    
    def stop_capture(self):
        """Stop packet capture."""
        self.capture_manager.stop_capture(self.device_info['mac'])
        self.start_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.pause_button.setText("Pause")
