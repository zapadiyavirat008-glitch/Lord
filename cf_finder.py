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

PORTS = [443]
THREADS = 1000  
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
    is_valid_cdn = False
    
    for port in PORTS:
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(2.0)
            
            # Wrap in SSL with dummy SNI to force TLS Server Response
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect TLS
            conn = context.wrap_socket(raw_sock, server_hostname="cloudflare.com")
            conn.connect((ip, port))
            
            payload = f"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            conn.sendall(payload.encode())
            
            response = conn.recv(512).decode(errors='ignore').lower()
            conn.close()
            
            # Broad CDN Detection (Cloudflare / CloudFront / Akamai / Fastly)
            cdn_tokens = ["cloudflare", "cf-ray", "__cfduid", "cloudfront", "akamai", "fastly"]
            if any(token in response for token in cdn_tokens) or "101" in response or "403 forbidden" in response:
                is_valid_cdn = True
                break
                
        except Exception:
            try:
                conn.close()
            except:
                pass
            continue

    if is_valid_cdn:
        with results_lock:
            qualified_ips.append(ip)

    with progress_lock:
        processed_count += 1
        if processed_count % 500 == 0 or processed_count == total_tasks:
            sys.stdout.write(f"\rProgress: [{processed_count}/{total_tasks}] TLS Probing IPs...")
            sys.stdout.flush()

def worker(ip_chunk):
    for ip in ip_chunk:
        check_ip_response(ip)

if __name__ == "__main__":
    send_telegram_message("🚀 *Scan Initialized:* TLS SNI & Broad CDN Detection Mode...")

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
        send_telegram_message(f"✅ *Scan Completed:* Found `{len(unique_ips)}` responsive CDN IPs.")
    else:
        send_telegram_message("⚠️ *Scan Finalized:* No responsive CDN targets found.")

    print(f"\nDone. Found {len(unique_ips)} responsive IPs saved to {OUTPUT_FILE}.")
