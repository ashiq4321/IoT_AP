import logging
from scapy.all import sniff, wrpcap, IP, conf
from threading import Thread, Event, Lock
from typing import Dict, Optional, List, Tuple
import time
import os
import sys
import platform
from datetime import datetime
import netifaces  # For backup interface detection
from queue import Queue, Empty
import threading
from ..network.ids_manager import IdsManager

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class PacketCaptureManager:
    def __init__(self, save_dir: str = "captures"):
        self.save_dir = os.path.abspath(save_dir)
        if not os.path.exists(self.save_dir):
            os.makedirs(self.save_dir)
        logger.debug(f"Initialized PacketCaptureManager with save_dir: {self.save_dir}")
        self.capture_threads: Dict[str, Thread] = {}
        self.stop_events: Dict[str, Event] = {}
        self.pause_events: Dict[str, Event] = {}
        self.packets: Dict[str, List] = {}
        self.capture_locks: Dict[str, Lock] = {}
        self.packet_queues: Dict[str, Queue] = {}
        self.save_threads: Dict[str, Thread] = {}
        self.ids_manager = IdsManager()
        
    def _find_hotspot_interface(self) -> Optional[tuple]:
        """Find the Wi-Fi Direct Virtual Adapter interface.
        Returns tuple of (interface_name, interface_index)"""
        logger.debug("Searching for hotspot interface...")
        try:
            for iface_name, iface in conf.ifaces.items():
                if (hasattr(iface, 'description') and 
                    'Wi-Fi Direct Virtual Adapter' in iface.description and
                    hasattr(iface, 'ip') and
                    str(iface.ip).startswith('192.168.137.')):
                    # Get interface index
                    index = conf.ifaces[iface_name].index
                    logger.debug(f"Found hotspot interface: {iface_name} (index: {index})")
                    return (iface_name, index)
            logger.error("Hotspot interface not found")
            return None
        except Exception as e:
            logger.error(f"Error finding interface: {str(e)}")
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

    def _save_packets_worker(self, mac_address: str, save_path: str):
        """Background worker to save packets."""
        try:
            queue = self.packet_queues.get(mac_address)
            if not queue:
                logger.error(f"No queue found for device {mac_address}")
                return
                
            while True:
                # Check if stop event exists and is set
                if mac_address in self.stop_events and self.stop_events[mac_address].is_set():
                    if queue.empty():
                        break
                        
                try:
                    packets = queue.get(timeout=1)
                    if packets:
                        with self.capture_locks.get(mac_address, Lock()):
                            wrpcap(save_path, packets, append=True)
                except Empty:
                    continue
                except Exception as e:
                    logger.error(f"Error saving packets: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Save worker error for {mac_address}: {str(e)}")
        finally:
            logger.debug(f"Save worker finished for {mac_address}")

    def _capture_packets(self, mac_address: str, ip_address: str, 
                        interface_info: tuple, save_path: str,
                        packet_count: Optional[int] = None,
                        duration: Optional[int] = None):
        """Capture packets for a specific device."""
        interface_name, interface_index = interface_info
        logger.debug(f"Starting capture for device {mac_address} at {ip_address}")
        
        # Initialize packet queue and save thread
        self.packet_queues[mac_address] = Queue(maxsize=1000)
        self.save_threads[mac_address] = Thread(
            target=self._save_packets_worker,
            args=(mac_address, save_path)
        )
        self.save_threads[mac_address].start()

        packet_buffer = []
        start_time = time.time()
        last_save = start_time
        packet_counter = 0

        try:
            def packet_handler(packet):
                nonlocal packet_counter, packet_buffer, last_save
                
                if IP in packet and (packet[IP].src == ip_address or packet[IP].dst == ip_address):
                    if not self.stop_events[mac_address].is_set() and not self.pause_events[mac_address].is_set():
                        packet_buffer.append(packet)
                        packet_counter += 1
                        # Update IDS with packet size
                        self.ids_manager.update_data_rate(
                            mac_address,
                            len(packet),
                            time.time()
                        )
                        # Buffer packets and save periodically
                        current_time = time.time()
                        if len(packet_buffer) >= 100 or (current_time - last_save) >= 5:
                            if not self.packet_queues[mac_address].full():
                                self.packet_queues[mac_address].put(packet_buffer)
                            packet_buffer = []
                            last_save = current_time

                        with self.capture_locks[mac_address]:
                            self.packets[mac_address] = packet_counter

                return (packet_count and packet_counter >= packet_count) or \
                       (duration and (time.time() - start_time) > duration) or \
                       self.stop_events[mac_address].is_set()

            sniff(
                iface=interface_name,
                prn=packet_handler,
                store=0,
                stop_filter=lambda _: self.stop_events[mac_address].is_set()
            )

        except Exception as e:
            logger.error(f"Capture error: {str(e)}")
        finally:
            # Save remaining packets
            if packet_buffer:
                self.packet_queues[mac_address].put(packet_buffer)
            
            # Wait for save thread to finish
            self.stop_events[mac_address].set()
            self.save_threads[mac_address].join()

            logger.debug(f"Capture ended for {mac_address}")

    def start_capture(self, mac_address: str, ip_address: str, 
                     filename: Optional[str] = None,
                     packet_count: Optional[int] = None,
                     duration: Optional[int] = None) -> bool:
        """Start packet capture."""
        try:
            interface = self._find_hotspot_interface()
            if not interface:
                logger.error("No suitable network interface found")
                return False

            if not filename:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                filename = f"capture_{mac_address.replace(':', '')}_{timestamp}.pcap"
                
            filepath = os.path.join(self.save_dir, filename)
            logger.debug(f"Capture will be saved to: {filepath}")

            # Initialize capture data structures
            self.stop_events[mac_address] = Event()
            self.pause_events[mac_address] = Event()
            self.packets[mac_address] = []
            self.capture_locks[mac_address] = Lock()
            
            # Start capture thread
            self.capture_threads[mac_address] = Thread(
                target=self._capture_packets,
                args=(mac_address, ip_address, interface, filepath, packet_count, duration)
            )
            self.capture_threads[mac_address].start()
            
            logger.info(f"Capture thread started for {mac_address}")
            return True
                
        except Exception as e:
            logger.error(f"Failed to start capture: {str(e)}")
            return False
        
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
                            self.capture_threads[device_mac].is_alive() and
                            not self.stop_events.get(device_mac, Event()).is_set())
                is_paused = (device_mac in self.pause_events and 
                           self.pause_events[device_mac].is_set())
                
                return {
                    'running': is_running,
                    'paused': is_paused
                }
        except Exception as e:
            logger.error(f"Error getting capture status: {str(e)}")
            return {'running': False, 'paused': False}

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
            logger.error(f"Error cleaning up resources: {str(e)}")

    def cleanup(self):
        """Stop all active captures and cleanup resources."""
        for device_mac in list(self.capture_threads.keys()):
            self.stop_capture(device_mac)
        self.ids_manager.save_history()