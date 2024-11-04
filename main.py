# main.py
import tkinter as tk
from tkinter import ttk
from src.ui.main_window import MainWindow

def main():
    # Set up basic theme
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use('clam')  # Or 'alt', 'default', 'classic' depending on your preference
    root.destroy()
    
    # Start application
    app = MainWindow()
    app.run()

if __name__ == "__main__":
    main()