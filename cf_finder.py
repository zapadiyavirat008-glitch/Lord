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

PORTS = [443]
THREADS = 1800  
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
    is_cloudflare = False
    
    for port in PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((ip, port))
            
            # Send raw HTTP probe
            payload = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            sock.sendall(payload.encode())
            
            # Read first 512 bytes of header response
            response = sock.recv(512).decode(errors='ignore').lower()
            sock.close()
            
            # Strict Filtering for Cloudflare Server Header & Response Tokens
            if "server: cloudflare" in response or "cf-ray:" in response or "__cfduid" in response:
                is_cloudflare = True
                break
                
        except Exception:
            try:
                sock.close()
            except:
                pass
            continue

    if is_cloudflare:
        with results_lock:
            qualified_ips.append(ip)

    with progress_lock:
        processed_count += 1
        if processed_count % 1000 == 0 or processed_count == total_tasks:
            sys.stdout.write(f"\rProgress: [{processed_count}/{total_tasks}] Scanning for Cloudflare Edge Servers...")
            sys.stdout.flush()

def worker(ip_chunk):
    for ip in ip_chunk:
        check_ip_response(ip)

if __name__ == "__main__":
    send_telegram_message("🚀 *Scan Initialized:* Strict Cloudflare Edge Server Detection Mode...")

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

    unique_ips = sorted(list(set(qualified_ips)))
    
    with open(OUTPUT_FILE, "w") as out:
        for ip in unique_ips:
            out.write(f"{ip}\n")

    if os.path.exists(OUTPUT_FILE) and os.path.getsize(OUTPUT_FILE) > 0:
        send_telegram_document(OUTPUT_FILE)
        send_telegram_message(f"✅ *Scan Completed:* Found `{len(unique_ips)}` verified Cloudflare IPs.")
    else:
        send_telegram_message("⚠️ *Scan Finalized:* No Cloudflare servers detected in this range.")

    print(f"\nDone. Found {len(unique_ips)} verified Cloudflare IPs saved to {OUTPUT_FILE}.")
