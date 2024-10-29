import tkinter as tk
from conn_devices import scan_network, get_hotspot_ip  # Import functions from conn_devices.py

# Function to detect all connected devices specifically from the hotspot
def detect_devices():
    hotspot_ip = get_hotspot_ip()
    hotspot_subnet = ".".join(hotspot_ip.split('.')[:3])  # e.g., "192.168.137"
    devices = scan_network(hotspot_subnet)  # Scan only the hotspot's subnet
    return devices

# Function to populate the table with detected devices
def populate_table(devices_table, devices):
    # Clear any previous entries in the table
    for widget in devices_table.winfo_children():
        widget.destroy()

    # Add headers to the table
    headers = ["Device Name", "IP Address", "MAC Address"]
    for idx, header in enumerate(headers):
        header_label = tk.Label(devices_table, text=header, font=('Arial', 12, 'bold'))
        header_label.grid(row=0, column=idx, padx=10, pady=5)

    # Add detected devices to the table
    for idx, device in enumerate(devices, 1):
        tk.Label(devices_table, text=device['hostname']).grid(row=idx, column=0, padx=10, pady=5)
        tk.Label(devices_table, text=device['ip']).grid(row=idx, column=1, padx=10, pady=5)
        tk.Label(devices_table, text=device['mac']).grid(row=idx, column=2, padx=10, pady=5)

    # If no devices are found
    if not devices:
        tk.Label(devices_table, text="No devices found").grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Function to handle the "Detect Devices" button click
def detect_devices_handler(devices_table):
    devices = detect_devices()  # Detect the devices connected to the hotspot
    populate_table(devices_table, devices)  # Populate the table with detected devices

# Main Tkinter UI
def create_ui():
    root = tk.Tk()
    root.title("Hotspot Device Detector")
    root.geometry("600x400")

    # Title label
    title_label = tk.Label(root, text="Devices Connected to Your Hotspot", font=("Arial", 14))
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
