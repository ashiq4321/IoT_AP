import tkinter as tk
import psutil
import socket

# Function to detect all connected devices
def detect_devices():
    devices = []
    
    # Iterate through all network interfaces
    for interface, addrs in psutil.net_if_addrs().items():
        device_info = {}
        
        # Get the MAC address
        for addr in addrs:
            if addr.family == psutil.AF_LINK:  # MAC address family
                device_info['mac_address'] = addr.address
        
        # Get IPv4 and IPv6 addresses
        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4
                device_info['ipv4'] = addr.address
            elif addr.family == socket.AF_INET6:  # IPv6
                device_info['ipv6'] = addr.address
        
        # Only add devices with a MAC address (physical devices)
        if 'mac_address' in device_info:
            devices.append(device_info)
    return devices

# Function to populate the table with detected devices
def populate_table(devices_table, devices):
    print("Populating table...")  # Debugging statement to confirm the function is called
    
    # Remove any previously displayed devices in the table
    for widget in devices_table.winfo_children():
        widget.destroy()

    # Add headers to the table
    headers = ["Device", "MAC Address", "IPv4", "IPv6"]
    for idx, header in enumerate(headers):
        header_label = tk.Label(devices_table, text=header, font=('Arial', 12, 'bold'))
        header_label.grid(row=0, column=idx, padx=10, pady=5)

    # Add detected devices to the table
    for idx, device in enumerate(devices, 1):
        tk.Label(devices_table, text=f"Device {idx}").grid(row=idx, column=0, padx=10, pady=5)
        tk.Label(devices_table, text=device['mac_address']).grid(row=idx, column=1, padx=10, pady=5)
        tk.Label(devices_table, text=device.get('ipv4', 'N/A')).grid(row=idx, column=2, padx=10, pady=5)
        tk.Label(devices_table, text=device.get('ipv6', 'N/A')).grid(row=idx, column=3, padx=10, pady=5)

    # If no devices are found
    if not devices:
        tk.Label(devices_table, text="No devices found").grid(row=1, column=0, columnspan=4, padx=10, pady=10)

# Function to handle the "Detect Devices" button click
def detect_devices_handler(devices_table):
    devices = detect_devices()  # Detect the devices
    populate_table(devices_table, devices)  # Populate the table with detected devices

# Main Tkinter UI
def create_ui():
    root = tk.Tk()
    root.title("Device Detector")
    root.geometry("600x400")

    # Title label
    title_label = tk.Label(root, text="Detected Devices", font=("Arial", 14))
    title_label.pack(pady=10)

    # Table to display devices (using a frame with grid layout)
    devices_table = tk.Frame(root)
    devices_table.pack(pady=10)

    # Button to detect devices
    detect_button = tk.Button(root, text="Detect Devices", command=lambda: detect_devices_handler(devices_table))
    detect_button.pack(pady=10)

    # Exit button
    exit_button = tk.Button(root, text="Exit", command=root.quit)
    exit_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_ui()
