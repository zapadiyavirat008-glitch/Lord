# -*- coding: utf-8 -*-
import os
import socket
import ssl
import threading
import sys
import requests

if len(sys.argv) < 2:
    print("Usage: python cf_finder.py <ips.txt>")
    sys.exit(1)

IP_FILE = sys.argv[1]

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")

PORT = 443
THREADS = 150  # High thread count for fast scanning
OUTPUT_FILE = "found_snis.txt"  # Keeps the same output name for your Telegram setup

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

def check_ip_capability(ip):
    global processed_count
    
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(2.0) # Swift timeout to keep scan highly performant
        
        # Create a relaxed SSL context that does NOT send an SNI extension
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Wrap without server_hostname to avoid SNI dependency
        secure_sock = context.wrap_socket(raw_sock)
        secure_sock.connect((ip, PORT))
        
        # Send a direct generic HTTP probe to trigger a response from the edge server
        payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"Connection: close\r\n\r\n"
        )
        secure_sock.sendall(payload.encode())
        response = secure_sock.recv(1024).decode(errors='ignore')
        secure_sock.close()
        
        # Verify the IP behaves like a Cloudflare/CDN edge node
        # Cloudflare nodes return specific headers even on bad/missing SNI requests
        is_cf = any(sig in response.lower() for sig in [
            "server: cloudflare", 
            "cf-ray", 
            "cf-cache-status",
            "400 bad request"
        ])
        
        if is_cf or "HTTP/1." in response:
            with results_lock:
                # Save ONLY the bare IP address as requested
                qualified_ips.append(ip)
                
    except Exception:
        pass

    with progress_lock:
        processed_count += 1
        if processed_count % 1000 == 0 or processed_count == total_tasks:
            sys.stdout.write(f"\rProgress: [{processed_count}/{total_tasks}] Scanning IPs for capability...")
            sys.stdout.flush()

def worker(ip_chunk):
    for ip in ip_chunk:
        check_ip_capability(ip)

if __name__ == "__main__":
    send_telegram_message("🚀 *Scan Initialized:* Direct IP capability filtering (No SNI check)...")

    try:
        with open(IP_FILE, 'r') as f:
            ips = [i.strip() for f_line in f.readlines() if (i := f_line.strip())]
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    total_tasks = len(ips)

    # Chunk tasks for threads
    chunk_size = max(1, len(ips) // THREADS)
    threads = []
    for i in range(0, len(ips), chunk_size):
        chunk = ips[i:i + chunk_size]
        t = threading.Thread(target=worker, args=(chunk,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Save only unique, sorted bare IP addresses
    unique_ips = sorted(list(set(qualified_ips)))
    with open(OUTPUT_FILE, "w") as out:
        for ip in unique_ips:
            out.write(f"{ip}\n")

    # Send the raw IP file to your Telegram channel
    if os.path.exists(OUTPUT_FILE) and os.path.getsize(OUTPUT_FILE) > 0:
        send_telegram_document(OUTPUT_FILE)
    else:
        send_telegram_message("⚠️ *Scan Finalized:* No active or capable IPs found in this range.")

    print(f"\nDone. Found {len(unique_ips)} qualified bare IPs saved to {OUTPUT_FILE}.")
