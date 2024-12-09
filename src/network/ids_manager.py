# src/network/ids_manager.py
from collections import deque
from datetime import datetime, timedelta
import logging
import json
import os
import statistics
from typing import Dict, Optional
import smtplib
from email.message import EmailMessage

logger = logging.getLogger(__name__)

class IdsManager:
    def __init__(self, config_file: str = "ids_config.json"):
        self.config_file = config_file
        self.load_config()
        
        # Store 7 days of data rates per device
        self.data_rates: Dict[str, deque] = {}
        self.rate_history: Dict[str, list] = {}
        self.current_windows: Dict[str, dict] = {}
        self.device_thresholds = {}  # Store thresholds in memory
        self.device_alerts = {}  # Track alerts per device
        
        # Set default threshold for all devices
        self.default_threshold = 5000  # 5000 B/s

        # Load historical data if exists
        self.history_file = "ids_history.json"
        self.load_history()

    def load_config(self):
        """Load IDS configuration"""
        default_config = {
            "threshold_multiplier": 2.0,  # Alert if rate > 2x average
            "window_size": 5,  # seconds for rate calculation
            "history_days": 7,
            "email_notifications": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_addr": "",
                "to_addr": ""
            },
            "device_thresholds": {}  # Custom thresholds per device
        }
        
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = {**default_config, **json.load(f)}
        else:
            self.config = default_config
            self.save_config()

    def save_config(self):
        """Save current configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def load_history(self):
        """Load historical data rates"""
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                data = json.load(f)
                # Convert stored lists to deques
                for mac, rates in data.items():
                    self.data_rates[mac] = deque(rates, maxlen=10080)  # 7 days * 1440 minutes

    def save_history(self):
        """Save historical data rates"""
        with open(self.history_file, 'w') as f:
            # Convert deques to lists for JSON serialization
            data = {mac: list(rates) for mac, rates in self.data_rates.items()}
            json.dump(data, f, indent=4)

    def update_data_rate(self, mac_address: str, bytes_count: int, timestamp: float):
        """Update data rate tracking for a device"""
        if mac_address not in self.current_windows:
            self.current_windows[mac_address] = {
                'start_time': timestamp,
                'bytes': 0
            }
            
        window = self.current_windows[mac_address]
        window['bytes'] += bytes_count
        
        # Calculate rate if window is complete
        if timestamp - window['start_time'] >= self.config['window_size']:
            rate = window['bytes'] / self.config['window_size']  # bytes per second
            
            if mac_address not in self.data_rates:
                self.data_rates[mac_address] = deque(maxlen=10080)
            
            self.data_rates[mac_address].append(rate)
            
            # Check for anomalies
            self.detect_anomaly(mac_address, rate)
            
            # Reset window
            self.current_windows[mac_address] = {
                'start_time': timestamp,
                'bytes': 0
            }

    def set_device_threshold(self, mac_address: str, threshold: float) -> None:
        """Set custom threshold for a device in bytes/sec"""
        self.config['device_thresholds'][mac_address] = threshold
        self.save_config()
        
    def get_device_threshold(self, mac_address: str) -> Optional[float]:
        """Get custom threshold for a device if set"""
        return self.config['device_thresholds'].get(mac_address)
        
    def detect_anomaly(self, mac_address: str, current_rate: float):
        """Detect abnormal data rates using device threshold"""
        if len(self.data_rates[mac_address]) < 10:
            return
            
        threshold = self.device_thresholds.get(mac_address, 
                   self.config['threshold_multiplier'])
        
        if current_rate > threshold:
            self.device_alerts[mac_address] = {
                'current_rate': current_rate,
                'threshold': threshold,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }
        else:
            self.device_alerts.pop(mac_address, None)

    def trigger_alert(self, mac_address: str, current_rate: float, avg_rate: float):
        """Handle anomaly detection alerts"""
        msg = (f"Traffic anomaly detected\n"
               f"Device: {mac_address}\n"
               f"Current rate: {current_rate:.2f} B/s\n"
               f"Average rate: {avg_rate:.2f} B/s\n"
               f"Time: {datetime.now()}")
               
        if self.config['email_notifications']['enabled']:
            self.send_email_alert(msg)
        
        logger.info(msg)

    def send_email_alert(self, message: str):
        """Send email notification"""
        cfg = self.config['email_notifications']
        try:
            msg = EmailMessage()
            msg.set_content(message)
            msg['Subject'] = 'IDS Alert - Traffic Anomaly Detected'
            msg['From'] = cfg['from_addr']
            msg['To'] = cfg['to_addr']
            
            with smtplib.SMTP(cfg['smtp_server'], cfg['smtp_port']) as server:
                server.starttls()
                server.login(cfg['username'], cfg['password'])
                server.send_message(msg)
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")

    def get_device_stats(self, mac_address: str, days: int = 7) -> Dict:
        """Get device statistics for the specified period"""
        if mac_address not in self.data_rates:
            return {}
            
        samples = list(self.data_rates[mac_address])[-days * 1440:]
        if not samples:
            return {}
            
        return {
            'avg_rate': statistics.mean(samples),
            'max_rate': max(samples),
            'min_rate': min(samples),
            'samples': len(samples)
        }
        
    def set_threshold(self, mac_address: str, threshold: float) -> None:
        """Set threshold for a device in bytes/sec"""
        self.device_thresholds[mac_address] = threshold
        
    def get_threshold(self, mac_address: str) -> float:
        """Get threshold for a device, return default if not set"""
        return self.device_thresholds.get(mac_address, self.default_threshold)