import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import socket
import threading
import time
import cloudscraper
from fake_useragent import UserAgent
from datetime import datetime

# Function to generate random headers
def get_random_headers():
    ua = UserAgent()
    return {"User-Agent": ua.random, "Accept": "*/*", "Referer": "http://example.com"}

# Function to identify service name for common ports
def get_service_name(port):
    services = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP", 110: "POP3", 3306: "MySQL", 5432: "PostgreSQL"}
    return services.get(port, "Unknown Service")

# Function to scan a specific port
def scan_port(host, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))

        if result == 0:
            service = get_service_name(port)
            results.append((port, "OPEN", service))
            update_output(f"[✅ OPEN] Port {port} ({service}) is OPEN!")
        else:
            results.append((port, "CLOSED", "Unknown"))
            update_output(f"[❌ CLOSED] Port {port} is CLOSED!")

        sock.close()
    except Exception as e:
        update_output(f"[ERROR] Scanning port {port}: {e}")

# Function to scan multiple ports
def start_scan():
    results.clear()
    host = host_entry.get().strip()
    ports = port_entry.get().strip()
    start_time = time.time()
    
    if not host:
        update_output("[ERROR] No host provided. Exiting.")
        return

    try:
        ip = socket.gethostbyname(host)
        update_output(f"\n🔍 Resolving {host} to {ip}")
    except socket.gaierror:
        update_output("[ERROR] Unable to resolve host. Exiting.")
        return

    try:
        ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    except ValueError:
        update_output("[ERROR] Invalid port numbers.")
        return

    if not ports:
        update_output("[ERROR] No valid ports provided.")
        return

    update_output("\n🚀 Scanning Ports...")
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(host, port, results), daemon=True)
        thread.start()

    total_time = time.time() - start_time
    root.after(3000, lambda: update_output(f"\n🎉 Scan complete! Total time: {total_time:.2f} sec"))

# Function to update output in GUI
def update_output(message):
    output_box.config(state=tk.NORMAL)
    output_box.insert(tk.END, message + "\n")
    output_box.see(tk.END)
    output_box.config(state=tk.DISABLED)

# Function to save scan results
def save_results():
    if not results:
        messagebox.showerror("Error", "No scan results to save!")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(f"Port Scanner Results - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            file.write("=" * 60 + "\n")
            for port, status, service in results:
                file.write(f"Port {port}: {status} ({service})\n")
            file.write("=" * 60 + "\n")
        messagebox.showinfo("Success", "Results saved successfully!")

# Function to check if HTTP service is running
def check_http():
    host = host_entry.get().strip()
    url = f"http://{host}"
    scraper = cloudscraper.create_scraper()
    headers = get_random_headers()

    for attempt in range(3):
        try:
            update_output(f"🌐 Attempt {attempt+1}: Checking {url}...")
            response = scraper.get(url, headers=headers, timeout=5)
            update_output(f"[HTTP {response.status_code}] {url}")

            if response.status_code == 200:
                update_output("🔹 Security Insight: HTTP server is live!")
            return
        except Exception as e:
            update_output(f"[ERROR] Attempt {attempt+1} failed: {e}")
            time.sleep(1)

    update_output(f"[ERROR] Could not connect to {url} after multiple attempts.")

# GUI setup
root = tk.Tk()
root.title("Advanced Port Scanner")
root.geometry("600x500")
root.resizable(False, False)

# Styling
style = ttk.Style()
style.configure("TButton", font=("Arial", 10), padding=5)

# Title
title_label = tk.Label(root, text="🔍 Advanced Port Scanner", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

# Host Entry
host_frame = tk.Frame(root)
host_frame.pack(pady=5)
tk.Label(host_frame, text="🔗 Host/IP: ").pack(side=tk.LEFT)
host_entry = tk.Entry(host_frame, width=40)
host_entry.pack(side=tk.LEFT)

# Port Entry
port_frame = tk.Frame(root)
port_frame.pack(pady=5)
tk.Label(port_frame, text="🔌 Ports: ").pack(side=tk.LEFT)
port_entry = tk.Entry(port_frame, width=30)
port_entry.pack(side=tk.LEFT)

# Buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)
scan_button = ttk.Button(button_frame, text="Start Scan 🚀", command=start_scan)
scan_button.grid(row=0, column=0, padx=5)
check_http_button = ttk.Button(button_frame, text="Check HTTP 🌐", command=check_http)
check_http_button.grid(row=0, column=1, padx=5)
save_button = ttk.Button(button_frame, text="Save Results 💾", command=save_results)
save_button.grid(row=0, column=2, padx=5)

# Output Box
output_box = scrolledtext.ScrolledText(root, height=15, width=70, state=tk.DISABLED)
output_box.pack(pady=10)

# Store results
results = []

# Run GUI
root.mainloop()
