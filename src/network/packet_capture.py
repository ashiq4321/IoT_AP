# src/network/packet_capture.py
from scapy.all import sniff, wrpcap, IP
from threading import Thread, Event, Lock
from typing import Dict, Optional, List
import time
import os
import sys
import platform
from datetime import datetime

class PacketCaptureManager:
    def __init__(self, save_dir: str = "captures"):
        self.save_dir = save_dir
        self.capture_threads: Dict[str, Thread] = {}
        self.stop_events: Dict[str, Event] = {}
        self.pause_events: Dict[str, Event] = {}
        self.packets: Dict[str, List] = {}
        self.capture_locks: Dict[str, Lock] = {}
        
        # Create capture directory if it doesn't exist
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)
    
    @staticmethod
    def _check_capture_privileges() -> bool:
        """Check if the program has sufficient privileges for packet capture."""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except Exception as e:
            print(f"Error checking privileges: {str(e)}")
            return False
        
    def _capture_packets(self, 
                        device_mac: str, 
                        ip_address: str, 
                        filepath: str,
                        packet_count: Optional[int],
                        duration: Optional[int]):
        """Packet capture worker function."""
        start_time = time.time()
        
        try:
            # Create or truncate the capture file
            with open(filepath, 'wb'):
                pass
            
            def packet_callback(pkt):
                """Process each captured packet"""
                try:
                    if IP in pkt:
                        # Check if packet is related to our target IP
                        if pkt[IP].src == ip_address or pkt[IP].dst == ip_address:
                            # Check stop conditions
                            if self.stop_events[device_mac].is_set():
                                return True
                            
                            # Handle pause
                            if self.pause_events[device_mac].is_set():
                                return False
                            
                            # Check duration limit
                            if duration and (time.time() - start_time) >= duration:
                                self.stop_events[device_mac].set()
                                return True
                            
                            # Store and write packet
                            with self.capture_locks[device_mac]:
                                self.packets[device_mac].append(pkt)
                                wrpcap(filepath, [pkt], append=True)
                                
                                # Check packet count limit
                                if packet_count and len(self.packets[device_mac]) >= packet_count:
                                    self.stop_events[device_mac].set()
                                    return True
                    
                    return False
                    
                except Exception as e:
                    print(f"Error processing packet: {str(e)}")
                    return False
            
            # Start capture with optimized settings
            sniff(
                filter=f"host {ip_address}",  # BPF filter to capture only relevant packets
                prn=packet_callback,
                store=0,
                timeout=duration,
                stop_filter=lambda _: self.stop_events[device_mac].is_set()
            )
            
        except Exception as e:
            print(f"Error in packet capture for {device_mac}: {str(e)}")
        finally:
            with self.capture_locks[device_mac]:
                self.cleanup_device(device_mac)
    
    def start_capture(self, 
                     device_mac: str, 
                     ip_address: str,
                     filename: Optional[str] = None,
                     packet_count: Optional[int] = None,
                     duration: Optional[int] = None) -> bool:
        """Start capturing packets for a specific device."""
        if not self._check_capture_privileges():
            print("Warning: Insufficient privileges for packet capture. Run as administrator/root.")
            return False
    
        try:
            # Create lock if it doesn't exist
            if device_mac not in self.capture_locks:
                self.capture_locks[device_mac] = Lock()
            
            with self.capture_locks[device_mac]:
                # Check if capture is already running
                if device_mac in self.capture_threads and self.capture_threads[device_mac].is_alive():
                    return False
                
                # Clean up any existing capture resources
                self.cleanup_device(device_mac)
                
                # Generate filename if not provided
                if not filename:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"capture_{device_mac.replace(':', '')}_{timestamp}.pcap"
                
                # Ensure .pcap extension
                if not filename.endswith('.pcap'):
                    filename += '.pcap'
                
                filepath = os.path.join(self.save_dir, filename)
                
                # Initialize capture state
                self.packets[device_mac] = []
                self.stop_events[device_mac] = Event()
                self.pause_events[device_mac] = Event()
                
                # Create and start capture thread
                capture_thread = Thread(
                    target=self._capture_packets,
                    args=(device_mac, ip_address, filepath, packet_count, duration)
                )
                capture_thread.daemon = True
                self.capture_threads[device_mac] = capture_thread
                capture_thread.start()
                
                return True
                
        except Exception as e:
            print(f"Error starting capture for {device_mac}: {str(e)}")
            self.cleanup_device(device_mac)
            return False
    
    def stop_capture(self, device_mac: str) -> bool:
        """Stop packet capture for a device."""
        try:
            with self.capture_locks.get(device_mac, Lock()):
                if device_mac in self.stop_events:
                    self.stop_events[device_mac].set()
                    
                    # Wait briefly for thread to finish
                    if device_mac in self.capture_threads:
                        self.capture_threads[device_mac].join(timeout=2.0)
                    
                    self.cleanup_device(device_mac)
                    return True
            return False
            
        except Exception as e:
            print(f"Error stopping capture for {device_mac}: {str(e)}")
            return False

    def get_capture_status(self, device_mac: str) -> Dict:
        """Get current capture status for a device."""
        try:
            with self.capture_locks.get(device_mac, Lock()):
                is_running = (device_mac in self.capture_threads and 
                            self.capture_threads[device_mac].is_alive())
                is_paused = (device_mac in self.pause_events and 
                            self.pause_events[device_mac].is_set())
                packet_count = len(self.packets.get(device_mac, []))
                
                return {
                    'running': is_running,
                    'paused': is_paused,
                    'packet_count': packet_count
                }
        except Exception as e:
            print(f"Error getting capture status for {device_mac}: {str(e)}")
            return {'running': False, 'paused': False, 'packet_count': 0}

    def cleanup_device(self, device_mac: str):
        """Clean up resources for a specific device."""
        try:
            if device_mac in self.capture_threads:
                del self.capture_threads[device_mac]
            if device_mac in self.stop_events:
                del self.stop_events[device_mac]
            if device_mac in self.pause_events:
                del self.pause_events[device_mac]
            if device_mac in self.packets:
                del self.packets[device_mac]
        except Exception as e:
            print(f"Error cleaning up resources for {device_mac}: {str(e)}")

    def cleanup(self):
        """Stop all active captures and cleanup resources."""
        for device_mac in list(self.capture_threads.keys()):
            self.stop_capture(device_mac)