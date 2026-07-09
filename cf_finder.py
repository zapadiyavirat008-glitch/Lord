# -*- coding: utf-8 -*-
import os
import socket
import ssl
import threading
import sys
import time
import json
from datetime import datetime

if len(sys.argv) < 3:
    print("Usage: python cf_finder.py <hosts.txt> <ips.txt>")
    sys.exit(1)

HOST_FILE = sys.argv[1]
IP_FILE = sys.argv[2]

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")

PORT = 443
THREADS_PHASE1 = 800  
THREADS_PHASE2 = 100  
DB_FILE = "live_database.json"

db_lock = threading.Lock()

live_ips_phase1 = []
final_hits = []

def send_telegram_message(text):
    if not BOT_TOKEN or not CHAT_ID:
        return
    import requests
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception:
        pass

# --- PHASE 1: MASS TCP PORT SCANNER ---
def phase1_worker(ip_chunk):
    global live_ips_phase1
    for ip in ip_chunk:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4)  
            result = sock.connect_ex((ip, PORT))
            sock.close()
            if result == 0:
                with db_lock:
                    live_ips_phase1.append(ip)
        except Exception:
            pass

# --- PHASE 2: DUAL-ENGINE FINGERPRINTING & VERIFICATION ---
def phase2_worker(task_chunk):
    global final_hits
    for ip, host in task_chunk:
        provider = None
        is_genuine = False
        
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(2.5)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            secure_sock = context.wrap_socket(raw_sock, server_hostname=host)
            secure_sock.connect((ip, PORT))
            
            # WebSocket Handshake Payload
            payload = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            secure_sock.sendall(payload.encode())
            response = secure_sock.recv(4096).decode(errors='ignore')
            secure_sock.close()
            
            response_lower = response.lower()
            
            # 1. Check for Genuine Connection (Status 101 Switching Protocols)
            if "http/1.1 101" in response_lower and "sec-websocket-accept" in response_lower:
                # Anti-Fake Filter: ISP recharge/portal pages contains HTML tags usually
                if "<html" not in response_lower and "recharge" not in response_lower:
                    is_genuine = True
            
            # 2. Identify Engine Provider using Server Headers & Signatures
            if "server: cloudflare" in response_lower or "cf-ray:" in response_lower:
                provider = "Cloudflare 🟠"
            elif "server: cloudfront" in response_lower or "x-amz-cf-id:" in response_lower or "via:" in response_lower and "cloudfront" in response_lower:
                provider = "Cloudfront 🔵"
            else:
                # Agar generic CDN signature mile tab bhi capture karein
                if is_genuine:
                    provider = "Unknown CDN/VPS 🌐"

        except Exception:
            pass

        # Valid Hit Processing
        if is_genuine and provider:
            # Latency/Speed Calculation
            t1 = time.time()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ss = ctx.wrap_socket(s, server_hostname=host)
                ss.connect((ip, PORT))
                ss.close()
                speed = int((time.time() - t1) * 1000)
            except Exception:
                speed = 9999

            with db_lock:
                final_hits.append({"ip": ip, "host": host, "speed": speed, "provider": provider})

# --- MAIN CONTROLLER ---
start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
send_telegram_message(f"🚀 *Dual-Engine Scanner Engine Activated*\n⏱️ *Started At:* `{start_time_str}`\n🔄 Phase 1: Running Mass TCP Filter...")

try:
    with open(HOST_FILE, 'r') as f:
        hosts = [h.strip() for f_line in f.readlines() if (h := f_line.strip())]
    with open(IP_FILE, 'r') as f:
        ips = [i.strip() for f_line in f.readlines() if (i := f_line.strip())]
except FileNotFoundError as e:
    print(f"Error: {e}")
    sys.exit(1)

# EXECUTE PHASE 1
print(f"Executing Phase 1 on {len(ips)} raw IPs...")
chunk_size_p1 = max(1, len(ips) // THREADS_PHASE1)
threads_p1 = []
for i in range(0, len(ips), chunk_size_p1):
    chunk = ips[i:i + chunk_size_p1]
    t = threading.Thread(target=phase1_worker, args=(chunk,))
    threads_p1.append(t)
    t.start()

for t in threads_p1:
    t.join()

print(f"Phase 1 Complete. Active TCP Ports: {len(live_ips_phase1)}")

# EXECUTE PHASE 2
tasks_p2 = [(ip, host) for ip in live_ips_phase1 for host in hosts]

if tasks_p2:
    print(f"Executing Phase 2 on {len(tasks_p2)} live targets...")
    chunk_size_p2 = max(1, len(tasks_p2) // THREADS_PHASE2)
    threads_p2 = []
    for i in range(0, len(tasks_p2), chunk_size_p2):
        chunk = tasks_p2[i:i + chunk_size_p2]
        t = threading.Thread(target=phase2_worker, args=(chunk,))
        threads_p2.append(t)
        t.start()

for t in threads_p2:
    t.join()

# --- CONSOLIDATE & FINAL CLEAN REPORT ---
db_data = {"active": {}, "scanned_at": now_str := datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
report_text = f"🏁 *SCAN ENGINE ROUND COMPLETE* 🏁\n\n🎯 *Total Genuine Tunnels Found:* `{len(final_hits)}`\n\n"

if len(final_hits) > 0:
    report_text += "📝 *VERIFIED TUNNEL NETWORKS:*\n"
    final_hits.sort(key=lambda x: x["speed"])
    
    for item in final_hits:
        key = f"{item['ip']}:{PORT}@{item['host']}"
        db_data["active"][key] = {
            "verified_time": now_str,
            "speed_ms": item["speed"],
            "engine": item["provider"]
        }
        report_text += f"✨ {item['provider']}\n🌐 `Proxy:` `{item['ip']}:{PORT}`\n⚡ `Latency:` `{item['speed']}ms`\n🎯 `Host:` `{item['host']}`\n\n"
else:
    report_text += "❌ Is round mein koi bhi genuine working SNI-IP connection tunnel bypass nahi mila."

try:
    with open(DB_FILE, 'w') as f:
        json.dump(db_data, f, indent=4)
except Exception:
    pass

send_telegram_message(report_text)
print("Scan process completed perfectly.")
