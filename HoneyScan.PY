#
# A simple honeypot script with a GUI to log connection attempts on various ports.
# This script is designed to be packaged into a standalone .exe (Windows) or
# executable (Linux) file using PyInstaller.
#
# Requirements:
#   - Python 3.x
#   - For Tkinter on Linux (if not already installed):
#     - Debian/Ubuntu: `sudo apt-get install python3-tk`
#     - Fedora: `sudo dnf install python3-tkinter`
#     - Arch Linux: `sudo pacman -S tk`
#
# PyInstaller Command for Linux (Bash/Zsh):
#   pyinstaller --onefile --noconsole --icon="honeypot.ico" --name="HoneyScan" honeypot_script.py
#
# PyInstaller Command for Windows (Command Prompt):
#   pyinstaller --onefile --noconsole --icon="honeypot.ico" --name="HoneyScan" honeypot_script.py
#
#   - `--onefile`: Creates a single executable file.
#   - `--noconsole`: Prevents the command-line window from appearing (important for GUI apps).
#   - `--icon="honeypot.ico"`: (Optional) Adds a custom icon to the executable.
#   - `--name="HoneyScan"`: Sets the name of the executable file.
#   - `honeypot_script.py`: The name of this script file.
#
# Important Note for Linux:
#   To listen on ports below 1024 (privileged ports like 20, 21, 22, 23, 25, 80, 443),
#   you MUST run the HoneyScan executable with `sudo`.
#   Example: `sudo ./HoneyScan` (after navigating to the dist/ folder)
#

import socket
import threading
import time
import os
import sys
from tkinter import Tk, Text, Button, Label, Scrollbar, Frame, Menu
from tkinter.constants import END
from queue import Queue

# --- Configuration ---
# The ports you want to monitor. Expanded to include more commonly targeted services.
PORTS_TO_MONITOR = [
    20,  # FTP (Data)
    21,  # FTP (Control)
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS (TCP/UDP)
    80,  # HTTP
    110, # POP3
    123, # NTP (UDP)
    135, # DCE/RPC Endpoint Mapper
    137, # NetBIOS-NS (UDP)
    138, # NetBIOS-DGM (UDP)
    139, # NetBIOS-SSN
    143, # IMAP
    161, # SNMP (agents) (UDP)
    162, # SNMP (traps) (UDP)
    389, # LDAP
    443, # HTTPS
    445, # Microsoft-DS (SMB)
    465, # SMTPS
    587, # SMTP (submission)
    636, # LDAPS
    3306,# MySQL
    3389,# RDP
    5060,# SIP (UDP)
    5432,# PostgreSQL
    8080,# HTTP Proxy / Alternate HTTP
    1433,# MSSQL
    902, # VMware vSphere/ESXi
]
# The host IP to bind to. Use '0.0.0.0' to listen on all available network interfaces.
HOST = '0.0.0.0'
# Maximum number of concurrent connections for each port.
MAX_CONNECTIONS = 5
# A queue to safely pass log messages from the threads to the main GUI thread.
log_queue = Queue()
# A flag to control the state of the honeypot threads.
is_running = False

# --- GUI Class ---
class HoneypotGUI:
    """
    Handles the creation and management of the Tkinter GUI.
    """
    def __init__(self, master):
        self.master = master
        master.title("HoneyScan Logger") # Renamed application title
        master.geometry("700x450") # Slightly larger to accommodate more info
        master.configure(bg="#2d2d2d")

        # Configure rows and columns for proper resizing using grid
        self.master.grid_rowconfigure(0, weight=0) # Status label row - fixed height
        self.master.grid_rowconfigure(1, weight=1) # Log frame row - expands
        self.master.grid_rowconfigure(2, weight=0) # Buttons row - fixed height
        self.master.grid_columnconfigure(0, weight=1) # Single column - expands

        # Status Label
        self.status_label = Label(
            self.master, text="Status: Stopped", fg="white", bg="#2d2d2d",
            font=("Arial", 12)
        )
        # Place the status label in row 0, column 0, centered horizontally
        self.status_label.grid(row=0, column=0, pady=10, sticky="n")

        # Log Display (Text widget)
        self.log_frame = Text(
            self.master, wrap="word", bg="#1e1e1e", fg="#00ff00",
            font=("Courier New", 10), state="disabled",
            borderwidth=2, relief="sunken"
        )
        # Place the log frame in row 1, column 0, and make it fill and expand
        self.log_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

        # Create a right-click context menu for the log_frame
        self.context_menu = Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_log_text)
        self.log_frame.bind("<Button-3>", self.show_context_menu) # Bind right-click

        # Buttons Frame - using a Frame widget for better grouping and layout
        self.button_frame = Frame(self.master, bg="#2d2d2d")
        # Place the button frame in row 2, column 0, centered horizontally
        self.button_frame.grid(row=2, column=0, pady=(0, 10))

        self.start_button = Button(
            self.button_frame, text="Start HoneyScan", command=self.start_honeypot, # Updated button text
            bg="#4caf50", fg="white", font=("Arial", 10, "bold"),
            relief="raised", borderwidth=3, padx=10, pady=5,
            activebackground="#66bb6a"
        )
        self.start_button.pack(side="left", padx=10) # Pack buttons within the button_frame

        self.stop_button = Button(
            self.button_frame, text="Stop HoneyScan", command=self.stop_honeypot, # Updated button text
            bg="#f44336", fg="white", font=("Arial", 10, "bold"),
            relief="raised", borderwidth=3, padx=10, pady=5,
            activebackground="#e57373", state="disabled"
        )
        self.stop_button.pack(side="left", padx=10) # Pack buttons within the button_frame

        # Polling the queue for updates
        self.master.after(100, self.update_log_from_queue)

    def show_context_menu(self, event):
        """
        Displays the right-click context menu at the mouse pointer's position.
        """
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def copy_log_text(self):
        """
        Copies the selected text from the log_frame to the clipboard.
        If no text is selected, it copies all content.
        """
        try:
            # Check if there's any text selected
            if self.log_frame.tag_ranges("sel"):
                selected_text = self.log_frame.get("sel.first", "sel.last")
            else:
                # If nothing is selected, copy all content
                selected_text = self.log_frame.get("1.0", END)

            self.master.clipboard_clear()
            self.master.clipboard_append(selected_text)
        except Exception as e:
            self.log_message(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error copying text: {e}")


    def start_honeypot(self):
        """
        Starts the honeypot by creating and starting listener threads.
        """
        global is_running
        if not is_running:
            is_running = True
            self.status_label.config(text="Status: Running...", fg="#4caf50")
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.log_message(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] HoneyScan started. Listening on ports: {PORTS_TO_MONITOR}")
            
            # Start a thread for each port listener
            for port in PORTS_TO_MONITOR:
                listener_thread = threading.Thread(target=port_listener, args=(port,)) # Removed geoip_reader argument
                listener_thread.daemon = True
                listener_thread.start()

    def stop_honeypot(self):
        """
        Stops the honeypot by setting the global flag and closing any listening sockets.
        """
        global is_running
        if is_running:
            is_running = False
            self.status_label.config(text="Status: Stopping...", fg="#ffc107")
            self.log_message(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] HoneyScan stopping...")

            # Re-enable the start button and disable the stop button
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            
            self.status_label.config(text="Status: Stopped", fg="white")

    def log_message(self, message):
        """
        Adds a message to the log queue to be displayed by the GUI.
        """
        log_queue.put(message)

    def update_log_from_queue(self):
        """
        Checks the queue for new messages and updates the GUI log display.
        This runs in the main GUI thread, making it safe for UI updates.
        """
        while not log_queue.empty():
            message = log_queue.get()
            self.log_frame.config(state="normal")
            self.log_frame.insert(END, message + "\n")
            self.log_frame.see(END)
            self.log_frame.config(state="disabled")
        self.master.after(100, self.update_log_from_queue)

# --- Honeypot Core Logic ---
def port_listener(port): # Removed reader argument
    """
    Listens for incoming connections on a specific port and logs them.
    This function is designed to be run in a separate thread.
    """
    global is_running
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, port))
        s.listen(MAX_CONNECTIONS)
        
        while is_running:
            try:
                conn, addr = s.accept()
                ip_address = addr[0]
                port_connected = addr[1]
                
                # GeoIP lookup removed
                log_message = (
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"Connection on port {port} from {ip_address}:{port_connected}" # Removed geo_info
                )
                log_queue.put(log_message)
                conn.close()
            except socket.timeout:
                pass
            except Exception as e:
                log_message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error on port {port}: {e}"
                log_queue.put(log_message)
                break
    except Exception as e:
        log_message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Could not start listener on port {port}: {e}"
        log_queue.put(log_message)
    finally:
        s.close()

# --- Main Program Execution ---
if __name__ == "__main__":
    root = Tk()
    app = HoneypotGUI(root)
    root.mainloop()
