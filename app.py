import eventlet
eventlet.monkey_patch()

import os, re, json, time, struct, socket, threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from flask import Flask, request, jsonify, render_template, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import logging
import requests
import smtplib
from email.mime.text import MIMEText
from flask import session, redirect, url_for
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("SOC")

app = Flask(__name__)
USERNAME = "socteam"
PASSWORD = "socteam123"
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'tomato-soc-secret-2024')
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*")

# ─────────────────────────────────────────────
#  IN-MEMORY STORE  (replace with Redis/DB for production)
# ─────────────────────────────────────────────
traffic_logs   = []          # all ingested requests
blocked_ips    = {}          # ip → {reason, blocked_at, expires}
ip_tracker     = defaultdict(lambda: {"requests":[], "login_attempts":0, "last_seen": 0})
attack_counters= defaultdict(int)  # threat_type → count
alert_history  = []
pcap_packets   = []          # raw packet records for PCAP export

MAX_LOGS = 5000

# ─────────────────────────────────────────────
#  DETECTION RULES
# ─────────────────────────────────────────────
SQLI_PATTERNS = re.compile(
    r"('|\"|;|--|\b(OR|AND)\b.*?[=<>]|UNION\s+SELECT|DROP\s+TABLE|"
    r"INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+.*?\bSET\b|"
    r"EXEC(\s|\()|xp_|0x[0-9a-fA-F]+|\bCAST\s*\(|\bCONVERT\s*\()",
    re.IGNORECASE
)
XSS_PATTERNS = re.compile(
    r"(<script|</script|javascript:|onerror\s*=|onload\s*=|"
    r"onclick\s*=|alert\s*\(|document\.cookie|<iframe|<img[^>]+on\w+\s*=)",
    re.IGNORECASE
)
MALWARE_UA = re.compile(
    r"(sqlmap|nmap|nikto|masscan|metasploit|nessus|w3af|burpsuite|"
    r"hydra|medusa|acunetix|openvas|dirbuster|gobuster|wfuzz|zap|"
    r"python-requests|curl\/|wget\/|libwww-perl)",
    re.IGNORECASE
)
PHISHING_PATHS = re.compile(
    r"/(admin|config|backup|\.env|\.git|wp-admin|phpmyadmin|"
    r"login-secure|verify|account-verify|secure-login|passwd|shadow|"
    r"etc/passwd|proc/self|\.htaccess|web\.config)",
    re.IGNORECASE
)
DDOS_THRESHOLD   = 30   # requests per window
DDOS_WINDOW      = 5    # seconds
BRUTEFORCE_LIMIT = 8    # login attempts
BLOCK_DURATION   = 3600 # 1 hour in seconds

# ─────────────────────────────────────────────
#  DETECTION ENGINE
# ─────────────────────────────────────────────
def detect_threats(data: dict) -> list[dict]:
    threats = []
    ip      = data.get("ip", "0.0.0.0")
    path    = data.get("path", "/")
    method  = data.get("method", "GET")
    ua      = data.get("user_agent", "")
    params  = json.dumps(data.get("params", {}))
    form    = json.dumps(data.get("form_data", {}))
    payload = f"{path} {params} {form}"

    # 1. SQLi
    if SQLI_PATTERNS.search(payload):
        threats.append({"type":"SQL_INJECTION","severity":"HIGH","detail":f"SQLi pattern in: {payload[:120]}"})

    # 2. XSS
    if XSS_PATTERNS.search(payload):
        threats.append({"type":"XSS","severity":"MEDIUM","detail":f"XSS pattern: {payload[:120]}"})

    # 3. Malware UA
    if MALWARE_UA.search(ua):
        threats.append({"type":"MALWARE_TOOL","severity":"CRITICAL","detail":f"Malicious UA: {ua[:80]}"})

    # 4. Phishing / recon paths
    if PHISHING_PATHS.search(path):
        threats.append({"type":"PHISHING_RECON","severity":"MEDIUM","detail":f"Suspicious path: {path}"})

    # 5. DDoS detection
    now = time.time()
    tracker = ip_tracker[ip]
    tracker["requests"] = [t for t in tracker["requests"] if now - t < DDOS_WINDOW]
    tracker["requests"].append(now)
    if len(tracker["requests"]) > DDOS_THRESHOLD:
        threats.append({"type":"DDOS","severity":"CRITICAL","detail":f"{len(tracker['requests'])} req in {DDOS_WINDOW}s"})

    # 6. Brute force (login paths)
    if method == "POST" and re.search(r"/(login|signin|auth)", path, re.I):
        tracker["login_attempts"] += 1
        if tracker["login_attempts"] >= BRUTEFORCE_LIMIT:
            threats.append({"type":"BRUTE_FORCE","severity":"HIGH","detail":f"{tracker['login_attempts']} login attempts"})

    tracker["last_seen"] = now
    return threats


def should_block(threats: list) -> tuple[bool, str]:
    critical = [t for t in threats if t["severity"] in ("CRITICAL","HIGH")]
    if critical:
        return True, critical[0]["type"]
    return False, ""


def block_ip(ip: str, reason: str, duration: int = BLOCK_DURATION):
    blocked_ips[ip] = {
        "reason":     reason,
        "blocked_at": datetime.utcnow().isoformat(),
        "expires":    (datetime.utcnow() + timedelta(seconds=duration)).isoformat(),
        "duration":   duration
    }
    log.warning(f"[BLOCKED] {ip} — {reason}")
    socketio.emit("ip_blocked", {"ip": ip, "reason": reason, "ts": datetime.utcnow().isoformat()})


def unblock_expired():
    """Background thread: auto-unblock IPs after duration"""
    while True:
        now = datetime.utcnow()
        to_remove = [ip for ip, v in blocked_ips.items()
                     if datetime.fromisoformat(v["expires"]) <= now]
        for ip in to_remove:
            del blocked_ips[ip]
            log.info(f"[UNBLOCKED] {ip} — block expired")
            socketio.emit("ip_unblocked", {"ip": ip, "ts": now.isoformat()})
        time.sleep(30)


threading.Thread(target=unblock_expired, daemon=True).start()

# ─────────────────────────────────────────────
#  PCAP BUILDER  (minimal libpcap format, no scapy needed)
# ─────────────────────────────────────────────
PCAP_MAGIC       = 0xa1b2c3d4
PCAP_VERSION_MAJ = 2
PCAP_VERSION_MIN = 4
PCAP_SNAPLEN     = 65535
PCAP_LINKTYPE    = 101  # LINKTYPE_RAW (raw IPv4/IPv6)

def _ip_to_bytes(ip_str: str) -> bytes:
    try:    return socket.inet_aton(ip_str)
    except: return b'\x00\x00\x00\x00'

def build_fake_ip_packet(src_ip: str, dst_ip: str, payload: str) -> bytes:
    """Build a minimal raw IPv4/TCP packet for PCAP embedding."""
    data    = payload.encode("utf-8", errors="replace")[:1400]
    src     = _ip_to_bytes(src_ip)
    dst     = _ip_to_bytes(dst_ip)
    # TCP header (minimal, no checksum)
    tcp = struct.pack("!HHIIBBHHH",
        80, 80,          # src port, dst port
        0, 0,            # seq, ack
        0x50, 0x02,      # data offset, flags (SYN)
        8192, 0, 0       # window, checksum, urg
    )
    total_len = 20 + len(tcp) + len(data)
    # IPv4 header (no checksum)
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45,            # version + IHL
        0,               # DSCP/ECN
        total_len,
        1,               # ID
        0,               # flags + frag offset
        64,              # TTL
        6,               # protocol TCP
        0,               # checksum (0 = skip)
        src, dst
    )
    return ip + tcp + data

def generate_pcap(logs: list) -> bytes:
    """Generate a valid PCAP file from traffic logs."""
    # Global header
    pcap_header = struct.pack("=IHHiIII",
        PCAP_MAGIC, PCAP_VERSION_MAJ, PCAP_VERSION_MIN,
        0, 0, PCAP_SNAPLEN, PCAP_LINKTYPE
    )
    records = bytearray(pcap_header)

    SERVER_IP = "10.0.0.1"  # simulated server IP

    for entry in logs:
        try:
            ts     = entry.get("timestamp_unix", time.time())
            src_ip = entry.get("ip", "0.0.0.0")
            method = entry.get("method", "GET")
            path   = entry.get("path", "/")
            ua     = entry.get("user_agent", "")
            threat = entry.get("primary_threat", "")

            payload = f"{method} {path} HTTP/1.1\r\nHost: tomato-app.vercel.app\r\nUser-Agent: {ua}\r\nX-Threat: {threat}\r\n\r\n"
            packet  = build_fake_ip_packet(src_ip, SERVER_IP, payload)

            ts_sec  = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            rec_hdr = struct.pack("=IIII", ts_sec, ts_usec, len(packet), len(packet))
            records += rec_hdr + packet
        except Exception as e:
            log.debug(f"PCAP skip packet: {e}")
            continue

    return bytes(records)

# ─────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == USERNAME and password == PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")
#────────────────────────
#  ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "tomato-soc", "ts": datetime.utcnow().isoformat()})


@app.route("/ingest", methods=["POST"])
def ingest():
    """Main ingestion endpoint — called by Tomato app on every request."""
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip") or request.remote_addr or "0.0.0.0"
    data["ip"] = ip

    # Check if already blocked
    if ip in blocked_ips:
        return jsonify({"status":"blocked","message":"IP is blocked"}), 403

    # Detect threats
    threats = detect_threats(data)

    # Build log entry
    ts = time.time()
    entry = {
        "id":             len(traffic_logs) + 1,
        "timestamp":      datetime.utcfromtimestamp(ts).strftime("%H:%M:%S"),
        "timestamp_full": datetime.utcfromtimestamp(ts).isoformat(),
        "timestamp_unix": ts,
        "ip":             ip,
        "method":         data.get("method", "GET"),
        "path":           data.get("path", "/"),
        "user_agent":     data.get("user_agent", ""),
        "params":         data.get("params", {}),
        "form_data":      data.get("form_data", {}),
        "threats":        threats,
        "primary_threat": threats[0]["type"] if threats else "CLEAN",
        "severity":       threats[0]["severity"] if threats else "NONE",
        "blocked":        False,
    }

    # Auto-block on HIGH/CRITICAL
    do_block, reason = should_block(threats)
    if do_block:
        block_ip(ip, reason)
        entry["blocked"] = True

 # 🔔 SEND ALERTS
        send_telegram_alert(ip, reason, entry["severity"])
        send_email_alert(ip, reason, entry["severity"])

    # Update counters
    for t in threats:
        attack_counters[t["type"]] += 1

    # Store log
    traffic_logs.append(entry)
    if len(traffic_logs) > MAX_LOGS:
        traffic_logs.pop(0)

    # Store for PCAP
    pcap_packets.append(entry)
    if len(pcap_packets) > MAX_LOGS:
        pcap_packets.pop(0)

    # Alert history for medium+
    if threats:
        severity = threats[0]["severity"]
        if severity in ("MEDIUM","HIGH","CRITICAL"):
            alert = {
                "ts":      entry["timestamp_full"],
                "ip":      ip,
                "type":    threats[0]["type"],
                "severity":severity,
                "detail":  threats[0]["detail"],
                "blocked": entry["blocked"],
            }
            alert_history.append(alert)
            if len(alert_history) > 500:
                alert_history.pop(0)
            # Push to dashboard
            socketio.emit("new_alert", alert)

    # Push log to dashboard
    socketio.emit("new_log", entry)

    return jsonify({
        "status":   "received",
        "threats":  threats,
        "blocked":  entry["blocked"],
        "entry_id": entry["id"]
    })


@app.route("/api/stats")
def stats():
    total     = len(traffic_logs)
    blocked_c = sum(1 for l in traffic_logs if l.get("blocked"))
    clean     = sum(1 for l in traffic_logs if l["primary_threat"] == "CLEAN")
    return jsonify({
        "total_requests":  total,
        "blocked_requests":blocked_c,
        "clean_requests":  clean,
        "attack_counts":   dict(attack_counters),
        "blocked_ips":     len(blocked_ips),
        "alerts":          len(alert_history),
    })


@app.route("/api/logs")
def logs():
    limit  = int(request.args.get("limit", 200))
    offset = int(request.args.get("offset", 0))
    return jsonify(list(reversed(traffic_logs))[ offset : offset+limit ])


@app.route("/api/alerts")
def alerts():
    return jsonify(list(reversed(alert_history))[:100])


@app.route("/api/blocked-ips")
def get_blocked():
    return jsonify([{"ip":ip, **v} for ip, v in blocked_ips.items()])


@app.route("/api/block", methods=["POST"])
def manual_block():
    d   = request.get_json(silent=True) or {}
    ip  = d.get("ip","").strip()
    reason = d.get("reason","MANUAL_BLOCK")
    if not ip:
        return jsonify({"error":"No IP provided"}), 400
    block_ip(ip, reason)
    return jsonify({"status":"blocked","ip":ip})


@app.route("/api/unblock", methods=["POST"])
def unblock():
    d  = request.get_json(silent=True) or {}
    ip = d.get("ip","").strip()
    if ip in blocked_ips:
        del blocked_ips[ip]
        socketio.emit("ip_unblocked", {"ip":ip, "ts": datetime.utcnow().isoformat()})
        return jsonify({"status":"unblocked","ip":ip})
    return jsonify({"error":"IP not in block list"}), 404


@app.route("/api/export/pcap")
def export_pcap():
    """Generate and download a PCAP file of all captured traffic."""
    limit  = int(request.args.get("limit", 2000))
    only_threats = request.args.get("threats_only", "false").lower() == "true"
    data = traffic_logs[-limit:]
    if only_threats:
        data = [l for l in data if l["primary_threat"] != "CLEAN"]
    pcap_bytes = generate_pcap(data)
    fname = f"tomato-soc-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.pcap"
    import io
    return send_file(
        io.BytesIO(pcap_bytes),
        mimetype="application/vnd.tcpdump.pcap",
        as_attachment=True,
        download_name=fname
    )


@app.route("/api/export/logs/json")
def export_logs_json():
    import io
    data = json.dumps(traffic_logs, indent=2).encode()
    fname = f"tomato-logs-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True, download_name=fname)


@app.route("/api/export/logs/csv")
def export_logs_csv():
    import io, csv
    buf = io.StringIO()
    fields = ["id","timestamp_full","ip","method","path","primary_threat","severity","blocked","user_agent"]
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(traffic_logs)
    fname = f"tomato-logs-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return send_file(
        io.BytesIO(buf.getvalue().encode()),
        mimetype="text/csv", as_attachment=True, download_name=fname
    )


@app.route("/api/simulate", methods=["POST"])
def simulate():
    """Simulate attack traffic for testing (dev only)."""
    import random
    attack_ips = ["192.168.1.10","10.0.0.55","172.16.0.99","45.33.32.156","185.220.101.5"]
    samples = [
        {"ip":random.choice(attack_ips),"method":"GET","path":"/login?user=admin' OR 1=1 --","user_agent":"sqlmap/1.7","params":{"user":"admin' OR 1=1 --"}},
        {"ip":random.choice(attack_ips),"method":"GET","path":"/<script>alert(1)</script>","user_agent":"Mozilla/5.0","params":{}},
        {"ip":"10.0.0.55","method":"GET","path":"/menu","user_agent":"nmap scripting engine","params":{}},
        {"ip":random.choice(attack_ips),"method":"GET","path":"/admin/.env","user_agent":"curl/7.88","params":{}},
        {"ip":"192.168.1.10","method":"POST","path":"/login","user_agent":"Hydra","form_data":{"user":"admin","pass":"test"}},
    ]
    for s in samples:
        with app.test_request_context('/ingest', method='POST', json=s):
            ingest()
    return jsonify({"status":"simulated", "count": len(samples)})


# ─────────────────────────────────────────────
#  SOCKETIO EVENTS
# ─────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    # Send current state on connect
    emit("init", {
        "stats": {
            "total_requests":  len(traffic_logs),
            "attack_counts":   dict(attack_counters),
            "blocked_ips":     len(blocked_ips),
            "alerts":          len(alert_history),
        },
        "recent_logs":   list(reversed(traffic_logs))[:50],
        "recent_alerts": list(reversed(alert_history))[:20],
        "blocked_ips":   [{"ip":ip,**v} for ip,v in blocked_ips.items()],
    })

@socketio.on("disconnect")
def on_disconnect():
    pass

# ─────────────────────────────
# ALERT SYSTEM
# ─────────────────────────────

def send_telegram_alert(ip, threat, severity):
    TOKEN = "AAERHL_5jamJk55HLzX8QgQ5ZpwZ9GxcCFY"
    CHAT_ID = "8458458404"

    msg = f"🚨 SOC ALERT\nIP: {ip}\nThreat: {threat}\nSeverity: {severity}"

    try:
        requests.get(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            params={"chat_id": CHAT_ID, "text": msg}
        )
    except Exception as e:
        log.error(f"Telegram alert failed: {e}")


def send_email_alert(ip, threat, severity):
    sender = "your_email@gmail.com"
    password = "your_app_password"

    msg = MIMEText(f"""
🚨 SOC ALERT

IP: {ip}
Threat: {threat}
Severity: {severity}
""")

    msg["Subject"] = "SOC ALERT"
    msg["From"] = sender
    msg["To"] = sender

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        log.error(f"Email alert failed: {e}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    socketio.run(app, host="0.0.0.0", port=port)
