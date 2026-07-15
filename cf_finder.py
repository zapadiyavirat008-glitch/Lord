# -*- coding: utf-8 -*-
import os
import sys
import socket
import threading
import requests

if len(sys.argv) < 2:
    print("Usage: python cf_finder.py <ips.txt>")
    sys.exit(1)

IP_FILE = sys.argv[1]

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")

PORT = 443
THREADS = 100  # Normal stable thread count
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

def check_ip(ip):
    global processed_count, qualified_ips
    
    try:
        # Direct raw connection to the IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.5) # Fast response check
        
        # Connect strictly using direct TCP handshake
        sock.connect((ip, PORT))
        
        # Send raw HTTP payload to probe response capability
        payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(payload.encode())
        
        response = sock.recv(256).decode(errors='ignore')
        sock.close()
        
        # Agar connection response me standard signatures hain, to IP active hai
        # (Jaise HTTP/1.1 response status code, server: cloudflare or similar)
        if "HTTP/1." in response or "server:" in response.lower():
            with results_lock:
                qualified_ips.append(ip)
                
    except Exception:
        pass

    with progress_lock:
        processed_count += 1
        if processed_count % 100 == 0 or processed_count == total_tasks:
            sys.stdout.write(f"\rProgress: [{processed_count}/{total_tasks}] Scanning IPs...")
            sys.stdout.flush()

def worker(ip_list):
    for ip in ip_list:
        check_ip(ip)

if __name__ == "__main__":
    send_telegram_message("🚀 *Scan Started:* Scanning bare IPs for direct HTTP response...")

    # Load IPs
    try:
        with open(IP_FILE, 'r') as f:
            ips = [i.strip() for f_line in f.readlines() if (i := f_line.strip())]
    except Exception as e:
        print(f"Error loading {IP_FILE}: {e}")
        sys.exit(1)

    total_tasks = len(ips)
    print(f"Loaded {total_tasks} IPs to scan.")

    if total_tasks == 0:
        print("Error: No IPs found in input file.")
        send_telegram_message("⚠️ *Scan Aborted:* ips.txt file was empty!")
        sys.exit(1)

    # Thread chunking logic that won't divide by zero or break
    threads = []
    chunk_size = max(1, len(ips) // THREADS)
    
    chunks = [ips[i:i + chunk_size] for i in range(0, len(ips), chunk_size)]
    
    for chunk in chunks:
        t = threading.Thread(target=worker, args=(chunk,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Save only clean, unique IPs
    unique_ips = sorted(list(set(qualified_ips)))
    
    with open(OUTPUT_FILE, "w") as out:
        for ip in unique_ips:
            out.write(f"{ip}\n")

    # Send results to Telegram
    if os.path.exists(OUTPUT_FILE) and os.path.getsize(OUTPUT_FILE) > 0:
        send_telegram_document(OUTPUT_FILE)
        send_telegram_message(f"✅ *Scan Complete:* Found {len(unique_ips)} working bare IPs.")
    else:
        # Output empty detection alerts
        send_telegram_message("⚠️ *Scan Finalized:* No responsive IPs found.")

    print(f"\nDone. Found {len(unique_ips)} responsive IPs.")
