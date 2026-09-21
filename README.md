 # Tomato SOC 🍅

**Real-time intrusion detection and security operations dashboard.**

Tomato SOC ingests HTTP traffic from a monitored web application, runs it through six detection engines, automatically blocks hostile IPs, and streams alerts to a live dashboard over WebSocket. It exports captured traffic as PCAP for offline analysis in Wireshark.

Built to understand how a SOC actually works end to end: ingestion → detection → alerting → response → forensic export.

<!-- SCREENSHOT: replace this line with a dashboard screenshot or GIF.
     Drag the image straight into the GitHub README editor and it uploads automatically. -->

---

## What it does

| | |
|---|---|
| **6 detection engines** | SQL injection, XSS, malicious scanner tooling, recon/path traversal, DDoS, brute force |
| **64 signature patterns** | Compiled regex across four rule families, matched against path, query params and form data |
| **Automatic response** | HIGH/CRITICAL detections block the source IP for 1 hour; a background thread auto-expires blocks |
| **Real-time streaming** | Flask-SocketIO pushes every log line and alert to the dashboard with no polling |
| **Forensic export** | PCAP (hand-built libpcap format, no scapy), plus JSON and CSV |
| **15 REST endpoints** | Stats, logs, alerts, manual block/unblock, three export formats, traffic simulator |

---

## Architecture

```
Monitored app  ──POST /ingest──►  Detection engine  ──►  In-memory store
(Tomato web app)                   6 rule families        logs · alerts · blocklist
                                          │
                                          ├──► Auto-block (HIGH/CRITICAL, 1h TTL)
                                          ├──► Telegram + email alerts
                                          └──► WebSocket push ──► Live dashboard
                                                                        │
                                                          PCAP / JSON / CSV export
```

Three layers: a **detection engine** of pure functions over a request dict; a **state layer** holding traffic logs, alert history and the blocklist (in-memory, capped at 5000 entries); and a **transport layer** of REST endpoints plus a SocketIO channel.

---

## Detection rules

| Threat | Severity | How it's detected |
|---|---|---|
| `SQL_INJECTION` | HIGH | 17 patterns — `UNION SELECT`, `OR 1=1`, `DROP TABLE`, hex literals, `CAST`/`CONVERT`, comment markers |
| `XSS` | MEDIUM | 10 patterns — `<script>`, `javascript:`, event handlers (`onerror`, `onload`, `onclick`), `document.cookie`, `<iframe>` |
| `MALWARE_TOOL` | CRITICAL | 20 scanner user-agents — sqlmap, nmap, nikto, metasploit, hydra, gobuster, burpsuite, nessus |
| `PHISHING_RECON` | MEDIUM | 17 sensitive paths — `/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `/etc/passwd`, `/proc/self` |
| `DDOS` | CRITICAL | Sliding window — more than 30 requests from one IP in 5 seconds |
| `BRUTE_FORCE` | HIGH | 8+ POST attempts against `/login`, `/signin` or `/auth` from one IP |

DDoS and brute force are **stateful** — they track per-IP history over time rather than pattern-matching a single request. That distinction (signature vs. behavioural detection) is the core design idea of the project.

---

## Quick start

```bash
git clone https://github.com/Nithishmsd/tomato-soc.git
cd tomato-soc

python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env        # then edit .env and set SECRET_KEY and SOC_PASSWORD
python app.py
```

Open **http://localhost:5001** and log in with the credentials from your `.env`.

### See it working

```bash
curl -X POST http://localhost:5001/api/simulate
```

This fires five sample attacks — SQLi, XSS, an nmap user-agent, a `/.env` probe, and a Hydra brute-force POST. Watch the dashboard: alerts appear instantly and the offending IPs land in the blocklist.

### Send it real traffic

Any application can report to the SOC by POSTing to `/ingest`:

```python
import requests

requests.post("http://localhost:5001/ingest", json={
    "ip":         request.remote_addr,
    "method":     request.method,
    "path":       request.full_path,
    "user_agent": request.headers.get("User-Agent", ""),
    "params":     dict(request.args),
    "form_data":  dict(request.form),
})
```

The response tells the caller whether to serve the request or reject it:
```json
{ "status": "received", "threats": [...], "blocked": true, "entry_id": 42 }
```

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/ingest` | Main ingestion — analyse a request, return verdict |
| `GET` | `/api/stats` | Totals, per-threat counts, blocked IP count |
| `GET` | `/api/logs?limit=&offset=` | Paginated traffic log |
| `GET` | `/api/alerts` | 100 most recent MEDIUM+ alerts |
| `GET` | `/api/blocked-ips` | Current blocklist with expiry times |
| `POST` | `/api/block` · `/api/unblock` | Manual analyst override |
| `GET` | `/api/export/pcap?threats_only=true` | Download traffic as PCAP |
| `GET` | `/api/export/logs/json` · `/csv` | Structured log export |
| `POST` | `/api/simulate` | Generate sample attack traffic |
| `GET` | `/health` | Health check |

**WebSocket events:** `init` (state snapshot on connect), `new_log`, `new_alert`, `ip_blocked`, `ip_unblocked`.

---

## Security & configuration

All secrets are read from environment variables — nothing sensitive is committed. Copy `.env.example` to `.env` and fill it in:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session signing. **Required** — the app refuses to start without it |
| `SOC_USERNAME` / `SOC_PASSWORD` | Dashboard login |
| `TELEGRAM_TOKEN` / `TELEGRAM_CHAT_ID` | Optional — Telegram alerts, silently skipped if unset |
| `SMTP_USER` / `SMTP_PASS` | Optional — email alerts, silently skipped if unset |

`.env` is gitignored.

---

## Known limitations

Being explicit about these, because a monitoring tool that oversells itself is worse than one that doesn't:

- **State is in-memory.** Restarting clears logs, alerts and the blocklist. Redis or Postgres would be the production fix.
- **Single process.** The in-memory store isn't shared across workers, so it won't scale horizontally as-is.
- **PCAP packets are synthesised**, not captured off the wire. They reconstruct each HTTP request into a valid raw IPv4/TCP frame so Wireshark can open the file — checksums are zeroed and the TCP stream is not a real session.
- **Signature-based detection is evadable.** Encoding, case mixing and fragmentation can slip past regex rules. Real WAFs normalise input before matching.
- **Session auth only** — no user accounts, roles, or rate limiting on the login endpoint.

---

## Built with

Python 3 · Flask · Flask-SocketIO · eventlet · Flask-CORS · vanilla JS dashboard

---

## What I learned

- **Behavioural detection needs state that signatures don't.** SQLi is one regex against one request; DDoS detection requires a sliding time window per IP, and deciding the window size is a false-positive tradeoff, not a correctness question.
- **Auto-blocking is a product decision, not a technical one.** Blocking on HIGH/CRITICAL only, with a 1-hour expiry, is a deliberate balance — block too eagerly and you lock out real users behind shared NAT.
- **Writing the PCAP format by hand** taught me the libpcap global header, per-packet records, and the IPv4/TCP header layout at byte level — far more than importing scapy would have.
- **WebSocket beats polling for a SOC dashboard.** Analysts need alerts the moment they fire; a 5-second poll is 5 seconds of attacker head start.

---

## Disclaimer

Educational project. The detection rules are illustrative, not production-hardened — don't put this in front of real traffic as your only defence.
