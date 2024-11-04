import tkinter as tk
from tkinter import ttk

class DeviceEditorDialog:
    def __init__(self, parent, device_data):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Edit Device Information")
        self.dialog.geometry("400x500")
        self.dialog.resizable(False, False)
        
        # Make dialog modal
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.device_data = device_data
        self.setup_ui()
        
    def setup_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create and pack widgets
        fields = [
            ("Name:", "name"),
            ("IP Address:", "ip"),
            ("MAC Address:", "mac"),
            ("Vendor:", "vendor"),
            ("Model:", "model"),
            ("Version:", "version")
        ]
        
        self.entries = {}
        for label_text, field in fields:
            frame = ttk.Frame(main_frame)
            frame.pack(fill=tk.X, pady=5)
            
            label = ttk.Label(frame, text=label_text, width=15)
            label.pack(side=tk.LEFT)
            
            entry = ttk.Entry(frame)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            entry.insert(0, self.device_data.get(field, ""))
            
            # Make IP and MAC read-only
            if field in ['ip', 'mac']:
                entry.configure(state='readonly')
                
            self.entries[field] = entry
        
        # Notes field
        notes_frame = ttk.Frame(main_frame)
        notes_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        notes_label = ttk.Label(notes_frame, text="Notes:")
        notes_label.pack(anchor=tk.W)
        
        self.notes_text = tk.Text(notes_frame, height=6)
        self.notes_text.pack(fill=tk.BOTH, expand=True)
        self.notes_text.insert('1.0', self.device_data.get('notes', ''))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(
            button_frame,
            text="Save",
            command=self.save
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.dialog.destroy
        ).pack(side=tk.RIGHT)
        
    def save(self):
        """Save the edited information."""
        self.result = {
            'name': self.entries['name'].get(),
            'ip': self.entries['ip'].get(),
            'mac': self.entries['mac'].get(),
            'vendor': self.entries['vendor'].get(),
            'model': self.entries['model'].get(),
            'version': self.entries['version'].get(),
            'notes': self.notes_text.get('1.0', tk.END).strip()
        }
        self.dialog.destroy()