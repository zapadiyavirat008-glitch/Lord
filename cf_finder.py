# -*- coding: utf-8 -*-
import os
import socket
import ssl
import threading
import sys
import requests

if len(sys.argv) < 3:
    print("Usage: python cf_finder.py <hosts.txt> <ips.txt>")
    sys.exit(1)

HOST_FILE = sys.argv[1]
IP_FILE = sys.argv[2]

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")

PORT = 443
THREADS = 120  # Increased for faster scanning since we stripped the database
OUTPUT_FILE = "found_snis.txt"

progress_lock = threading.Lock()
results_lock = threading.Lock()

processed_count = 0
total_tasks = 0
qualified_targets = []

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

def check_target(ip, host):
    global processed_count
    
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(2.5) # Fast timeout to keep the scan moving
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        secure_sock = context.wrap_socket(raw_sock, server_hostname=host)
        secure_sock.connect((ip, PORT))
        
        # Craft payload to check potential capability (WebSocket handshake)
        payload = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        secure_sock.sendall(payload.encode())
        response = secure_sock.recv(512).decode(errors='ignore')
        secure_sock.close()
        
        # If it allows the upgrade connection path, it's qualified for Termux
        if "HTTP/1.1 101" in response:
            with results_lock:
                # Store it in the format you need (e.g., just the IP, or ip:port@host)
                qualified_targets.append(f"{ip}:{PORT}@{host}")
                
    except Exception:
        pass

    with progress_lock:
        processed_count += 1
        if processed_count % 1000 == 0 or processed_count == total_tasks:
            sys.stdout.write(f"\rProgress: [{processed_count}/{total_tasks}] Filtering capable IPs...")
            sys.stdout.flush()

def worker(task_list):
    for ip, host in task_list:
        check_target(ip, host)

if __name__ == "__main__":
    send_telegram_message("🚀 *Scan Initialized:* Filtering for potentially capable IPs...")

    try:
        with open(HOST_FILE, 'r') as f:
            hosts = [h.strip() for f_line in f.readlines() if (h := f_line.strip())]
        with open(IP_FILE, 'r') as f:
            ips = [i.strip() for f_line in f.readlines() if (i := f_line.strip())]
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    tasks = [(ip, host) for ip in ips for host in hosts]
    total_tasks = len(tasks)

    chunk_size = max(1, len(tasks) // THREADS)
    threads = []
    for i in range(0, len(tasks), chunk_size):
        chunk = tasks[i:i + chunk_size]
        t = threading.Thread(target=worker, args=(chunk,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Save ONLY the qualified strings to the text file
    with open(OUTPUT_FILE, "w") as out:
        for target in sorted(qualified_targets):
            out.write(f"{target}\n")

    # Send the raw file over to your Telegram
    if os.path.exists(OUTPUT_FILE) and os.path.getsize(OUTPUT_FILE) > 0:
        send_telegram_document(OUTPUT_FILE)
    else:
        send_telegram_message("⚠️ *Scan Finalized:* No capable IPs responded in this range.")

    print(f"\nDone. Found {len(qualified_targets)} qualified targets.")
