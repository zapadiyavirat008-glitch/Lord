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
THREADS = 80
DB_FILE = "live_database.json"

GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

progress_lock = threading.Lock()
db_lock = threading.Lock()

processed_count = 0
total_tasks = 0
round_hits_count = 0

def load_database():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {"active": {}, "dead_history": {}}
    return {"active": {}, "dead_history": {}}

def save_database(data):
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception:
        pass

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

def check_target_speed(ip, host):
    t1 = time.time()
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(2.0)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        secure_sock = context.wrap_socket(raw_sock, server_hostname=host)
        secure_sock.connect((ip, PORT))
        secure_sock.close()
        return int((time.time() - t1) * 1000)
    except Exception:
        return 9999

def check_target(ip, host, db_data):
    global processed_count, round_hits_count
    key = f"{ip}:{PORT}@{host}"
    
    is_hit = False
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(3.0) 
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        secure_sock = context.wrap_socket(raw_sock, server_hostname=host)
        secure_sock.connect((ip, PORT))
        
        payload = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        secure_sock.sendall(payload.encode())
        response1 = secure_sock.recv(1024).decode(errors='ignore')
        
        if "HTTP/1.1 101" in response1:
            time.sleep(0.5)
            secure_sock.send(b"\r\n")
            response2 = secure_sock.recv(1024).decode(errors='ignore')
            if "SSH-" in response2 or "SSH-2.0" in response2:
                is_hit = True
        secure_sock.close()
    except Exception:
        pass

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with db_lock:
        if is_hit:
            round_hits_count += 1
            speed = check_target_speed(ip, host)
            
            if key not in db_data["active"]:
                # Agar pehle dead list mein tha aur firse alive ho gaya (Downtime recovery)
                if key in db_data.get("dead_history", {}):
                    old_dead_info = db_data["dead_history"][key]
                    accumulated = old_dead_info.get("accumulated_minutes", 0) + old_dead_info.get("total_alive_before_death", 0)
                    
                    db_data["active"][key] = {
                        "first_seen": now_str,
                        "last_seen": now_str,
                        "accumulated_minutes": accumulated,
                        "speed_ms": speed,
                        "status": "RECOVERED 🔄"
                    }
                    text = f"🔄 *TUNNEL RECOVERED / BACK ALIVE!*\n\n🌐 *Proxy:* `{ip}:{PORT}`\n🎯 *SNI:* `{host}`\n⚡ *Speed:* `{speed}ms`\n⏱️ *Previous History Restored!*"
                    send_telegram_message(text)
                    del db_data["dead_history"][key]
                else:
                    # Bilkul naya fresh SNI hit
                    db_data["active"][key] = {
                        "first_seen": now_str,
                        "last_seen": now_str,
                        "accumulated_minutes": 0,
                        "speed_ms": speed,
                        "status": "NEW ✨"
                    }
                    text = f"✨ *NEW TUNNEL HIT FOUND!*\n\n🌐 *Proxy:* `{ip}:{PORT}`\n🎯 *SNI:* `{host}`\n⚡ *Speed:* `{speed}ms`"
                    send_telegram_message(text)
            else:
                # Pehle se active tha, uptime update karo
                old_info = db_data["active"][key]
                old_info["last_seen"] = now_str
                old_info["speed_ms"] = speed
                old_info["status"] = "ALIVE 🟢"
        else:
            # Agar pehle active chal raha tha par is round mein dead ho gaya
            if key in db_data["active"]:
                old_info = db_data["active"][key]
                first_time = datetime.strptime(old_info["first_seen"], "%Y-%m-%d %H:%M:%S")
                this_run_mins = int((datetime.now() - first_time).total_seconds() // 60)
                total_minutes = this_run_mins + old_info.get("accumulated_minutes", 0)
                
                text = f"❌ *TUNNEL DROPPED / DEAD*\n\n🌐 *Proxy:* `{ip}:{PORT}`\n🎯 *SNI:* `{host}`\n⏱️ *Total Survived Time:* `{total_minutes} mins`"
                send_telegram_message(text)
                
                # Permanently bhoolne ke bajay history mein record karo taaki recovery check ho sake
                if "dead_history" not in db_data:
                    db_data["dead_history"] = {}
                db_data["dead_history"][key] = {
                    "death_time": now_str,
                    "total_alive_before_death": total_minutes,
                    "accumulated_minutes": old_info.get("accumulated_minutes", 0)
                }
                del db_data["active"][key]

    with progress_lock:
        processed_count += 1
        if processed_count % 500 == 0 or processed_count == total_tasks:
            sys.stdout.write(f"\rProgress: [{processed_count}/{total_tasks}] Scanning core...")
            sys.stdout.flush()

def worker(task_list, db_data):
    for ip, host in task_list:
        check_target(ip, host, db_data)

# --- MAIN CONTROLLER ---
db_data = load_database()

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
    t = threading.Thread(target=worker, args=(chunk, db_data))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# --- ROUND END LOGIC: ALIVE REPORTS & SUMMARY ---
with db_lock:
    save_database(db_data)
    active_tunnels = list(db_data["active"].items())

if len(active_tunnels) > 0:
    # 1. Sabse pehle LIVE/ALIVE status summary report banoa
    alive_report = "📊 *CURRENT ACTIVE TUNNELS STATUS* 📊\n\n"
    for key, info in active_tunnels:
        ip_port, host = key.split("@")
        first_time = datetime.strptime(info["first_seen"], "%Y-%m-%d %H:%M:%S")
        total_mins = int((datetime.now() - first_time).total_seconds() // 60) + info.get("accumulated_minutes", 0)
        alive_report += f"🟢 `{ip_port}` | Uptime: `{total_mins} min` | Speed: `{info['speed_ms']}ms` | SNI: `{host}`\n"
    send_telegram_message(alive_report)

    # 2. Phir TOP 3 Fastest report bhejo
    active_tunnels.sort(key=lambda x: x[1].get("speed_ms", 9999))
    speed_report = "⚡ *TOP FASTEST LIVE TUNNELS REPORT* ⚡\n\n"
    for rank, (key, info) in enumerate(active_tunnels[:3], 1):
        ip_port, host = key.split("@")
        speed_report += f"{rank}️⃣ `{ip_port}` | `{info['speed_ms']}ms` | SNI: `{host}`\n"
    send_telegram_message(speed_report)

print("\nRound completed successfully. State saved and reports sent.")
