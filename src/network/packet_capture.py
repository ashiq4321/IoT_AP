from scapy.all import sniff, wrpcap, IP, conf
from scapy.arch.windows import get_windows_if_list  # Updated import
from threading import Thread, Event, Lock
from typing import Dict, Optional, List, Tuple
import time
import os
import sys
import platform
from datetime import datetime
import netifaces  # For backup interface detection

class PacketCaptureManager:
    def __init__(self, save_dir: str = "captures"):
        self.save_dir = save_dir
        self.capture_threads: Dict[str, Thread] = {}
        self.stop_events: Dict[str, Event] = {}
        self.pause_events: Dict[str, Event] = {}
        self.packets: Dict[str, List] = {}
        self.capture_locks: Dict[str, Lock] = {}
        
        # Create absolute path for captures directory
        self.save_dir = os.path.abspath(save_dir)
        if not os.path.exists(self.save_dir):
            os.makedirs(self.save_dir)

    def _find_hotspot_interface(self) -> Optional[str]:
        """Find the network interface for the Mobile Hotspot."""
        try:
            # First try using Windows-specific network interface detection
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                for iface in interfaces:
                    # Look for interfaces that might be the hotspot
                    name = str(iface.get('name', '')).lower()
                    description = str(iface.get('description', '')).lower()
                    if ('local area connection* ' in name or 
                        'wi-fi direct' in name or
                        'mobile hotspot' in name or
                        'local area connection* ' in description or
                        'wi-fi direct' in description):
                        print(f"Found hotspot interface: {iface['name']}")
                        return iface['name']
            except Exception as e:
                print(f"Error using Scapy interface detection: {str(e)}")

            # Fallback: Use netifaces
            try:
                for iface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            if addr['addr'].startswith('192.168.137.'):
                                print(f"Found hotspot interface (fallback): {iface}")
                                return iface
            except Exception as e:
                print(f"Error using netifaces fallback: {str(e)}")

            # Last resort: Use conf.iface
            try:
                print(f"Using default interface: {conf.iface}")
                return conf.iface
            except Exception as e:
                print(f"Error getting default interface: {str(e)}")
                return None

        except Exception as e:
            print(f"Error finding hotspot interface: {str(e)}")
            return None

    def _verify_requirements(self) -> Tuple[bool, str]:
        """Verify all requirements for packet capture are met."""
        try:
            # Check administrator privileges
            if platform.system() == "Windows":
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    return False, "Administrator privileges required. Please run as administrator."
            else:
                if os.geteuid() != 0:
                    return False, "Root privileges required. Please run with sudo."

            # Check if we can find a suitable interface
            if not self._find_hotspot_interface():
                return False, "Could not find suitable network interface for capture"

            # Test Scapy configuration
            try:
                conf.use_pcap = True
                return True, "All requirements met"
            except Exception as e:
                return False, f"Error configuring Scapy: {str(e)}"

        except Exception as e:
            return False, f"Error checking requirements: {str(e)}"

    def _capture_packets(self, 
                        device_mac: str, 
                        ip_address: str, 
                        filepath: str,
                        packet_count: Optional[int],
                        duration: Optional[int]):
        """Packet capture worker function."""
        start_time = time.time()
        packets_captured = 0
        
        try:
            print(f"Starting capture for device {device_mac} at {ip_address}")
            print(f"Saving captures to: {filepath}")
            
            # Find the correct interface
            iface = self._find_hotspot_interface()
            if not iface:
                print("Error: Could not find hotspot interface")
                return
                
            print(f"Using interface: {iface}")
            
            # Create or truncate capture file
            with open(filepath, 'wb') as f:
                pass
                
            def packet_callback(pkt):
                """Process captured packet"""
                nonlocal packets_captured
                try:
                    if IP in pkt:
                        # Debug print for the first few packets
                        if packets_captured < 5:
                            print(f"Packet: {pkt[IP].src} -> {pkt[IP].dst}")
                            
                        if pkt[IP].src == ip_address or pkt[IP].dst == ip_address:
                            print(f"Captured packet for {ip_address}")
                            
                            # Check stop condition
                            if self.stop_events[device_mac].is_set():
                                return True
                            
                            # Handle pause
                            while self.pause_events[device_mac].is_set():
                                time.sleep(0.1)
                                if self.stop_events[device_mac].is_set():
                                    return True
                            
                            # Process packet
                            with self.capture_locks[device_mac]:
                                self.packets[device_mac].append(pkt)
                                wrpcap(filepath, [pkt], append=True)
                                packets_captured += 1
                                print(f"Packets captured: {packets_captured}")
                                
                                # Check limits
                                if packet_count and packets_captured >= packet_count:
                                    print(f"Reached packet count limit: {packet_count}")
                                    self.stop_events[device_mac].set()
                                    return True
                                    
                                if duration and (time.time() - start_time) >= duration:
                                    print(f"Reached duration limit: {duration}s")
                                    self.stop_events[device_mac].set()
                                    return True
                                    
                    return False
                    
                except Exception as e:
                    print(f"Error processing packet: {str(e)}")
                    return False

            try:
                # Configure Scapy
                conf.use_pcap = True
                
                # Start capture with specific interface
                print("Starting packet capture...")
                sniff(
                    iface=iface,
                    filter=f"host {ip_address}",
                    prn=packet_callback,
                    store=0,
                    timeout=duration,
                    stop_filter=lambda _: self.stop_events[device_mac].is_set()
                )
            except Exception as e:
                print(f"Error in sniff operation: {str(e)}")
                self.stop_events[device_mac].set()
                
        except Exception as e:
            print(f"Error in capture thread: {str(e)}")
        finally:
            print(f"Capture ended for {device_mac}")
            with self.capture_locks[device_mac]:
                self.cleanup_device(device_mac)

    def start_capture(self, 
                     device_mac: str, 
                     ip_address: str,
                     filename: Optional[str] = None,
                     packet_count: Optional[int] = None,
                     duration: Optional[int] = None) -> Tuple[bool, str]:
        """Start capturing packets for a specific device."""
        try:
            # Verify requirements first
            requirements_met, message = self._verify_requirements()
            if not requirements_met:
                print(f"Requirements not met: {message}")
                return False, message
            
            # Create lock if needed
            if device_mac not in self.capture_locks:
                self.capture_locks[device_mac] = Lock()
            
            with self.capture_locks[device_mac]:
                # Check if capture is already running
                if device_mac in self.capture_threads and self.capture_threads[device_mac].is_alive():
                    return False, "Capture already running for this device"
                
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
                print(f"Capture will be saved to: {filepath}")
                
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
                
                try:
                    capture_thread.start()
                    print(f"Capture thread started for {device_mac}")
                    return True, "Capture started successfully"
                except Exception as e:
                    self.cleanup_device(device_mac)
                    error_msg = f"Failed to start capture thread: {str(e)}"
                    print(error_msg)
                    return False, error_msg
                
        except Exception as e:
            error_msg = f"Error starting capture: {str(e)}"
            print(error_msg)
            return False, error_msg
        
    def pause_capture(self, device_mac: str) -> Tuple[bool, str]:
        """Pause packet capture for a device."""
        try:
            if device_mac in self.pause_events and device_mac in self.capture_threads:
                if self.capture_threads[device_mac].is_alive():
                    self.pause_events[device_mac].set()
                    return True, "Capture paused successfully"
            return False, "No active capture to pause"
        except Exception as e:
            return False, f"Error pausing capture: {str(e)}"

    def resume_capture(self, device_mac: str) -> Tuple[bool, str]:
        """Resume packet capture for a device."""
        try:
            if device_mac in self.pause_events and device_mac in self.capture_threads:
                if self.capture_threads[device_mac].is_alive():
                    self.pause_events[device_mac].clear()
                    return True, "Capture resumed successfully"
            return False, "No paused capture to resume"
        except Exception as e:
            return False, f"Error resuming capture: {str(e)}"

    def stop_capture(self, device_mac: str) -> Tuple[bool, str]:
        """Stop packet capture for a device."""
        try:
            with self.capture_locks.get(device_mac, Lock()):
                if device_mac in self.stop_events:
                    self.stop_events[device_mac].set()
                    if device_mac in self.pause_events:
                        self.pause_events[device_mac].clear()  # Clear pause state when stopping
                    
                    if device_mac in self.capture_threads:
                        self.capture_threads[device_mac].join(timeout=2.0)
                    
                    self.cleanup_device(device_mac)
                    return True, "Capture stopped successfully"
                return False, "No capture running for this device"
            
        except Exception as e:
            return False, f"Error stopping capture: {str(e)}"

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
                    'paused': is_paused,  # Added paused status
                    'packet_count': packet_count
                }
        except Exception as e:
            print(f"Error getting capture status: {str(e)}")
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
            print(f"Error cleaning up resources: {str(e)}")

    def cleanup(self):
        """Stop all active captures and cleanup resources."""
        for device_mac in list(self.capture_threads.keys()):
            self.stop_capture(device_mac)