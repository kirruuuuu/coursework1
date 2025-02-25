import socket
from datetime import datetime, UTC
import time

def resolve_host(domain):
    """Resolve the domain to an IP address."""
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        print(f"❌ Error resolving {domain}: {e}")
        return None

def scan_port(ip, port):
    """Scan a specific port on the given IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set timeout to 1 second
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0  # Return True if port is open
    except socket.error as e:
        print(f"❌ Error scanning port {port}: {e}")
        return False

def check_web_server(url):
    """Check if the web server is reachable."""
    try:
        import requests
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except Exception as e:  # Catch all exceptions
        print(f"❌ Error checking {url}: {e}")
        return False  # Ensure this line is present

def main():
    print("🚀 Welcome to the Advanced Port Scanner! 🚀")
    print("=" * 60)

    # Input target domain and ports
    target = input("Enter the domain or IP to scan: ")
    ports = input("Enter ports to scan (comma-separated, e.g., 80,443,22): ")
    ports = [int(p.strip()) for p in ports.split(",")]

    # Step 1: Resolve host information
    print("\n🔍 Step 1: Resolving Host Information")
    print("-" * 60)
    ip_address = resolve_host(target)
    if not ip_address:
        return

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"✅ Target Domain: {target}")
    print(f"✅ Resolved IP Address: {ip_address}")
    print(f"✅ Scan Start Time: {timestamp}")
    print("-" * 60)

    # Step 2: Port scanning
    print("\n🔍 Step 2: Port Scanning in Progress...")
    print("-" * 60)
    open_ports = []
    start_time = time.time()

    for port in ports:
        print(f"🛠 Scanning port {port} on {target}...")
        if scan_port(ip_address, port):
            print(f"[✅ OPEN] Port {port} successfully scanned! 🚀 Time: {time.time() - start_time:.2f} seconds")
            open_ports.append(port)
        else:
            print(f"[❌ CLOSED] Port {port} is closed. 🚫 Time: {time.time() - start_time:.2f} seconds")

    # Step 3: Verify web server availability
    print("\n🌐 Step 3: Verifying Web Server Availability...")
    print("-" * 60)
    if 80 in open_ports:
        url = f"http://{target}"
        print(f"🌐 Attempting to connect to {url}...")
        if check_web_server(url):
            print(f"[HTTP 200] {url}")
            print("🔹 Security Insight: A **200 OK** response indicates the web server is operational.")
            print("   - Ensure **SSL/TLS** is properly configured for secure communication.")
            print("   - Open ports **80 & 443** suggest the presence of a web application.")
        else:
            print(f"❌ Could not connect to {url}.")

    # Scan summary
    print("\n📊 Scan Summary:")
    print("=" * 60)
    print(f"🟢 Total Open Ports: {len(open_ports)}")
    for port in open_ports:
        print(f"   - Port {port}: {'HTTP' if port == 80 else 'Other'}")
    print(f"🔴 Total Closed Ports: {len(ports) - len(open_ports)}")
    print(f"⏳ Total Scan Time: {time.time() - start_time:.2f} seconds")
    print("=" * 60)
    print("✅ Scan Complete! This information can be used for further security analysis.")

if __name__ == "__main__":
    main()