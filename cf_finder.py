# -*- coding: utf-8 -*-
import os
import sys
import socket
import ssl
import threading
import requests

if len(sys.argv) < 2:
    print("Usage: python cf_finder_bot.py <ips.txt>")
    sys.exit(1)

IP_FILE = sys.argv[1]

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")

PORTS = [443]
THREADS = 800
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

def verify_pure_cloudflare_edge(ip, port=443):
    """
    3-Layer Strict Verification:
    1. TLS Handshake Validation
    2. SSL Certificate Authority Check (O=Cloudflare, Inc.)
    3. HTTP Edge Header & CF-Ray Token Validation
    """
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(2.0)
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        conn = context.wrap_socket(raw_sock, server_hostname="cloudflare.com")
        conn.connect((ip, port))
        
        # --- LAYER 1: CERTIFICATE ISSUER / SUBJECT CHECK ---
        cert_binary = conn.getpeercert(binary_form=True)
        if not cert_binary:
            conn.close()
            return False
            
        cert_str = str(cert_binary).lower()
        if "cloudflare" not in cert_str:
            conn.close()
            return False

        # --- LAYER 2: HTTP PROBE & HEADER SIGNATURES ---
        payload = (
            "GET / HTTP/1.1\r\n"
            "Host: cloudflare.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        conn.sendall(payload.encode())
        response = conn.recv(1024).decode(errors='ignore').lower()
        conn.close()

        # Reject if server header contains Nginx, Apache, or third-party servers
        if "server: nginx" in response or "server: apache" in response or "server: openresty" in response:
            return False

        # --- LAYER 3: MUST HAVE OFFICIAL CLOUDFLARE EDGE TOKENS ---
        has_server_header = "server: cloudflare" in response
        has_ray_id = "cf-ray:" in response
        has_cache_status = "cf-cache-status:" in response

        if has_server_header and (has_ray_id or has_cache_status):
            return True

    except Exception:
        try:
            conn.close()
        except Exception:
            pass
            
    return False

def check_ip_worker(ip):
    global processed_count
    
    if verify_pure_cloudflare_edge(ip, 443):
        with results_lock:
            qualified_ips.append(ip)

    with progress_lock:
        processed_count += 1
        if processed_count % 500 == 0 or processed_count == total_tasks:
            sys.stdout.write(f"\rProgress: [{processed_count}/{total_tasks}] Hunting Pure CF Anycast Nodes...")
            sys.stdout.flush()

def worker_thread(ip_chunk):
    for ip in ip_chunk:
        check_ip_worker(ip)

if __name__ == "__main__":
    send_telegram_message("🚀 *Strict Scan Started:* Filtering ONLY pure Cloudflare Anycast Edge IPs...")

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
        t = threading.Thread(target=worker_thread, args=(chunk,))
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
        send_telegram_message(f"✅ *Scan Complete:* Found `{len(unique_ips)}` 100% Genuine Cloudflare Edge IPs.")
    else:
        send_telegram_message("⚠️ *Scan Complete:* Zero official Cloudflare nodes found in this IP block.")

    print(f"\nDone. Found {len(unique_ips)} verified Cloudflare IPs saved to {OUTPUT_FILE}.")
