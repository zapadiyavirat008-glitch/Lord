# -*- coding: utf-8 -*-
import os
import socket
import threading
import sys
import requests

if len(sys.argv) < 2:
    print("Usage: python cf_finder.py <ips.txt>")
    sys.exit(1)

IP_FILE = sys.argv[1]

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")

# Testing common CDN ports to find which one is open/responding
PORTS = [80, 443, 8080]
THREADS = 150  
OUTPUT_FILE = "found_snis.txt"

progress_lock = threading.Lock()
results_lock = threading.Lock()

processed_count = 0
total_tasks = 0
qualified_ips = []

def send_telegram_message(text):
    if not BOT_TOKEN or not CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception:
        pass

def send_telegram_document(file_path):
    if not BOT_TOKEN or not CHAT_ID or not os.path.exists(file_path):
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
    try:
        with open(file_path, 'rb') as f:
            files = {'document': f}
            data = {'chat_id': CHAT_ID}
            requests.post(url, data=data, files=files, timeout=15)
    except Exception:
        pass

def check_ip_response(ip):
    global processed_count
    is_responsive = False
    
    # Try the ports to see if the IP responds to a raw HTTP GET
    for port in PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0) # 2 seconds timeout per port
            
            # Direct TCP connection without SSL overhead blocking it
            sock.connect((ip, port))
            
            # Send a raw HTTP probe string
            payload = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            sock.sendall(payload.encode())
            
            # Read the beginning of the response
            response = sock.recv(256).decode(errors='ignore')
            sock.close()
            
            # If we get ANY valid HTTP response signature back, the IP gateway is alive
            if "HTTP/1." in response or "server:" in response.lower():
                is_responsive = True
                break # Found a working port, no need to check others
                
        except Exception:
            try:
                sock.close()
            except:
                pass
            continue

    if is_responsive:
        with results_lock:
            qualified_ips.append(ip)

    with progress_lock:
        processed_count += 1
        if processed_count % 1000 == 0 or processed_count == total_tasks:
            sys.stdout.write(f"\rProgress: [{processed_count}/{total_tasks}] Checking IP responses...")
            sys.stdout.flush()

def worker(ip_chunk):
    for ip in ip_chunk:
        check_ip_response(ip)

if __name__ == "__main__":
    send_telegram_message("🚀 *Scan Initialized:* Raw HTTP capability probe (No SNI/SSL requirement)...")

    try:
        with open(IP_FILE, 'r') as f:
            ips = [i.strip() for f_line in f.readlines() if (i := f_line.strip())]
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    total_tasks = len(ips)

    chunk_size = max(1, len(ips) // THREADS)
    threads = []
    for i in range(0, len(ips), chunk_size):
        chunk = ips[i:i + chunk_size]
        t = threading.Thread(target=worker, args=(chunk,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Filter duplicates and sort
    unique_ips = sorted(list(set(qualified_ips)))
    
    with open(OUTPUT_FILE, "w") as out:
        for ip in unique_ips:
            out.write(f"{ip}\n")

    if os.path.exists(OUTPUT_FILE) and os.path.getsize(OUTPUT_FILE) > 0:
        send_telegram_document(OUTPUT_FILE)
    else:
        send_telegram_message("⚠️ *Scan Finalized:* No responsive IPs caught in this range.")

    print(f"\nDone. Found {len(unique_ips)} responsive bare IPs saved to {OUTPUT_FILE}.")
