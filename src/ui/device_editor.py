from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QFormLayout, QLineEdit,
                           QPushButton, QDialogButtonBox, QMessageBox)
from PyQt6.QtCore import Qt, QRegularExpression
from PyQt6.QtGui import QRegularExpressionValidator

class DeviceEditorDialog(QDialog):
    def __init__(self, parent, device_data=None):
        super().__init__(parent)
        self.device_data = device_data or {}
        self.setWindowTitle("Edit Device" if device_data else "Add Device")
        self.setModal(True)
        self.setMinimumWidth(400)
        self.setup_ui()
        self.load_device_data()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        form = QFormLayout()

        # Device name field
        self.name_input = QLineEdit()
        form.addRow("Device Name:", self.name_input)

        # IP address field with validation
        self.ip_input = QLineEdit()
        ip_regex = QRegularExpression(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        self.ip_input.setValidator(QRegularExpressionValidator(ip_regex))
        form.addRow("IP Address:", self.ip_input)

        # MAC address field with validation
        self.mac_input = QLineEdit()
        mac_regex = QRegularExpression(
            r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        )
        self.mac_input.setValidator(QRegularExpressionValidator(mac_regex))
        form.addRow("MAC Address:", self.mac_input)

        # Vendor field
        self.vendor_input = QLineEdit()
        form.addRow("Vendor:", self.vendor_input)

        # Model field
        self.model_input = QLineEdit()
        form.addRow("Model:", self.model_input)

        layout.addLayout(form)

        # Add buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | 
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def load_device_data(self):
        if self.device_data:
            self.name_input.setText(self.device_data.get('name', ''))
            self.ip_input.setText(self.device_data.get('ip', ''))
            self.mac_input.setText(self.device_data.get('mac', ''))
            self.vendor_input.setText(self.device_data.get('vendor', ''))
            self.model_input.setText(self.device_data.get('model', ''))

    def validate_inputs(self):
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Device name is required")
            return False
        if not self.ip_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "IP address is required")
            return False
        if not self.mac_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "MAC address is required")
            return False
        return True

    def accept(self):
        if not self.validate_inputs():
            return
        
        self.device_data = {
            'name': self.name_input.text().strip(),
            'ip': self.ip_input.text().strip(),
            'mac': self.mac_input.text().strip(),
            'vendor': self.vendor_input.text().strip(),
            'model': self.model_input.text().strip()
        }
        super().accept()

    def get_device_data(self):
        return self.device_data