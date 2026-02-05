import ipaddress
import threading
import time
import csv
import requests
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- SETTINGS & CACHES ---
sniffing_active = True
geo_cache = {}
manufacturer_cache = {}
proto_counts = Counter()
ip_activity = Counter()
ip_pps_tracker = Counter() # For flood detection
packet_counts = {"total": 0}

# Port to Service Mapping
PORT_MAP = {
    53: "DNS", 80: "HTTP", 443: "HTTPS", 1900: "SSDP", 
    3289: "Apple DDP", 5353: "mDNS", 8008: "Chromecast", 
    5000: "Flask Web"
}

# MAC OUI prefixes (Manufacturer Lookup)
OUI_MAP = {
    "ac:37:43": "LG Electronics", "b8:27:eb": "Raspberry Pi",
    "3c:6a:2c": "Samsung TV", "60:69:fb": "Apple Device",
    "f4:f5:e8": "Google/Nest", "00:15:5d": "Microsoft",
    "00:0c:29": "VMware", "d4:f5:47": "Apple Inc."
}

# --- HELPERS ---
def get_geo_info(ip):
    if ipaddress.ip_address(ip).is_private: return "Internal Network"
    if ip in geo_cache: return geo_cache[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=0.5).json()
        info = r.get('countryCode', '??')
        geo_cache[ip] = info
        return info
    except: return "???"

def get_vendor(mac):
    if not mac: return "Generic Device"
    prefix = mac[:8].lower()
    return OUI_MAP.get(prefix, "Unidentified")

# --- SNIFFER LOGIC ---
def packet_callback(packet):
    global sniffing_active
    if not sniffing_active: return

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet.src
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        
        # Service & Manufacturer
        sport = packet.sport if hasattr(packet, 'sport') else None
        service = PORT_MAP.get(sport, "Data")
        vendor = get_vendor(src_mac)
        
        # Security Checks
        is_external = not ipaddress.ip_address(src_ip).is_private
        ip_pps_tracker[src_ip] += 1
        is_flooding = True if ip_pps_tracker[src_ip] > 80 else False # Threshold for alert

        # Update Live Stats
        proto_counts[proto] += 1
        ip_activity[src_ip] += 1
        packet_counts["total"] += 1

        data = {
            "src": src_ip, "vendor": vendor, "service": service,
            "loc": get_geo_info(src_ip) if is_external else "Local",
            "len": len(packet), "external": is_external, "flood": is_flooding
        }
        socketio.emit('new_packet', data)

# --- ROUTES ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/toggle')
def toggle():
    global sniffing_active
    sniffing_active = not sniffing_active
    return jsonify({"status": "Running" if sniffing_active else "Stopped"})

@app.route('/clear')
def clear():
    global proto_counts, ip_activity, packet_counts, ip_pps_tracker
    proto_counts.clear(); ip_activity.clear(); ip_pps_tracker.clear(); packet_counts["total"] = 0
    return jsonify({"status": "cleared"})

# --- BACKGROUND THREADS ---
def stats_broadcaster():
    while True:
        time.sleep(1)
        if sniffing_active:
            socketio.emit('stats_update', {
                'pps': packet_counts["total"],
                'protocols': dict(proto_counts),
                'top_ips': ip_activity.most_common(5)
            })
            packet_counts["total"] = 0
            ip_pps_tracker.clear() # Reset flood tracker every second

if __name__ == '__main__':
    threading.Thread(target=lambda: sniff(prn=packet_callback, store=0), daemon=True).start()
    threading.Thread(target=stats_broadcaster, daemon=True).start()
    print("🚀 CYBERSNIFF ULTIMATE RUNNING")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
