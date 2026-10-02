# WiFi Guardian

WiFi Guardian is a local network observability tool. It discovers devices on the current LAN, measures local IP traffic, and reports sustained TCP port-scan patterns in a browser dashboard.

Use it only on networks you own or are authorized to administer. Packet capture and ARP discovery require elevated network permissions.

## What it does

- Shows the network this machine is connected to: IP addressing and subnet, MAC, gateway, DNS, IPv6, Wi-Fi SSID/BSSID/security/channel/band/signal, link bandwidth, and live throughput (dashboard view "Mon reseau", `GET /api/network`).
- Discovers LAN devices with `arp-scan` and passively from ARP, DHCP (hostname, vendor class), mDNS names, and observed traffic; vendors come from arp-scan or an offline OUI file, and randomized MACs are flagged.
- Aggregates packets into bidirectional flows labelled with the server name from TLS SNI, HTTP Host, or earlier DNS answers.
- Logs DNS queries per client and aggregates contacted domains over time.
- Correlates alerts per device into scored incidents with an acknowledge/close workflow, learns per-device upload volume and usual destinations, and sends notifications (webhook, ntfy, Telegram, e-mail) for serious incidents. Expected behaviour can be silenced with allowlist rules.
- Maps every alert to MITRE ATT&CK techniques and forwards alerts and incidents to a SIEM (Wazuh, Elastic, Splunk...) as ECS JSON or CEF, over Syslog or a JSON Lines file. See [docs/SIEM.md](docs/SIEM.md).
- Detects new devices, gateway ARP spoofing, IP conflicts, rogue DHCP servers, LLMNR/NBT-NS poisoning (Responder), brute force against SSH/RDP/SMB and other login services, inbound and outbound port scans, host and ping sweeps, beaconing, DNS tunnelling, risky protocols to the Internet, services exposed to the Internet, and contacts with IPs or domains from threat-intel lists. Repeated alerts are throttled (`ALERT_COOLDOWN`).
- Captures IP traffic with Scapy and reports upload/download totals per local IP.
- Retains a bounded, payload-free packet metadata history for filtering by IP, protocol, direction, and port.
- Raises a port-scan alert only after a configurable number of distinct TCP SYN ports are contacted within a time window.
- Offers REST snapshots and live Socket.IO updates.

- Supervises its capture, scan, and flush workers: a crashed worker is restarted with backoff, and the capture follows interface or network changes without a restart.
- Persists devices, structured alerts, and hourly traffic totals in SQLite (`DB_PATH`, default `data/wifi_guardian.db`) with a `RETENTION_DAYS` retention window.
- Reports component health on `GET /api/health` (HTTP 503 when degraded), also used by the Docker healthcheck and shown in the dashboard header.

Live counters and the packet metadata history stay in memory; set `DB_PATH=` (empty) to run without any persistence.

## Run locally

```bash
sudo apt-get install arp-scan libpcap-dev
./install.sh
./run.sh
```

Open `http://127.0.0.1:5000`.

Copy `.env.example` to `.env` to change settings. `CORS_ALLOWED_ORIGINS` is optional; when set, it is a comma-separated allow-list for browser origins.

`NETWORK_INTERFACE` pins the capture interface; by default it follows the interface of the default IPv4 route and is re-checked every `INTERFACE_REFRESH_INTERVAL` seconds.

`MAX_PACKET_HISTORY` controls the number of recent packet metadata entries held in memory. The application never retains packet payloads.

## Authentication

On the default `127.0.0.1` bind no login is required. To expose the dashboard on the network, configure a login and, for scripts, a token:

```bash
python -m moniwifi.auth            # prints a password hash
# .env
HOST=0.0.0.0
AUTH_USERNAME=admin
AUTH_PASSWORD_HASH=scrypt:...      # output of the command above
API_TOKEN=a-long-random-token      # optional: Authorization: Bearer <token>
SECRET_KEY=a-long-random-value
SESSION_COOKIE_SECURE=true         # when served over HTTPS
```

The application refuses to start on a non-loopback address without authentication, unless `ALLOW_UNAUTHENTICATED=true` is set because an authenticating reverse proxy sits in front. Logins are rate-limited, session cookies are `HttpOnly` and `SameSite=Lax`, and cookie-authenticated writes from another origin are refused. Unauthenticated `/api/health` calls only receive the status, which keeps container healthchecks working.

## Offline analysis of a capture

The same detection and correlation pipeline can analyse a pcap file recorded elsewhere (tcpdump, Wireshark):

```bash
python -m moniwifi.replay capture.pcap --gateway 192.168.1.1 --intel-dir data/intel
python -m moniwifi.replay capture.pcap --network 10.0.0.0/24 --json > report.json
```

The local network is inferred when `--network` is omitted. The exit code is 1 when a high or critical incident is found, which makes it usable in scripts.

## Export

`GET /api/export/<alerts|incidents|devices|flows|dns|domains>?format=csv|json&hours=24` downloads data as a file. The Alerts and Devices views have CSV export buttons.

## Run with Docker

Docker needs the host network to see and capture the LAN. On Linux:

```bash
docker compose up --build
```

The compose configuration grants only `NET_ADMIN` and `NET_RAW`, not full privileged access. History is stored in `./data` on the host. The dashboard remains available on `http://127.0.0.1:5000` by default. Local and Docker launches use Gunicorn with one worker so the in-memory monitor state has one owner.

## Development and checks

```bash
python3 -m unittest discover -s tests -t . -v   # or: make test
python3 -m compileall -q app.py config.py moniwifi
```

## SIEM integration

Set `SIEM_JSON_FILE=data/siem/alerts.jsonl` for a Wazuh agent or Filebeat to read, and/or `SIEM_SYSLOG_HOST` to send Syslog (`SIEM_SYSLOG_FORMAT=json` or `cef`). Events use Elastic Common Schema fields and carry their MITRE ATT&CK techniques. [docs/SIEM.md](docs/SIEM.md) is a step-by-step guide (in French) for Wazuh, Elastic, and others, including example Wazuh rules.

## Notifications

Configure one or more channels in `.env` (`NOTIFY_WEBHOOK_URL`, `NOTIFY_NTFY_URL`, `NOTIFY_TELEGRAM_TOKEN` with `NOTIFY_TELEGRAM_CHAT_ID`, or `SMTP_*` with `NOTIFY_EMAIL_TO`). Only incidents at or above `NOTIFY_MIN_SEVERITY` (default `high`) are sent. Check the setup with:

```bash
curl -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:5000/api/notifications/test
```

## Threat intelligence

Every `*.txt` file in `THREAT_INTEL_DIR` (default `data/intel`) is loaded: one IP, CIDR, or domain per line, or hosts-file lines (`0.0.0.0 bad.example`). Files are reloaded every hour. To download public feeds automatically, set `THREAT_INTEL_FEEDS`, for example:

```bash
THREAT_INTEL_FEEDS=https://feodotracker.abuse.ch/downloads/ipblocklist.txt,https://www.spamhaus.org/drop/drop.txt,https://urlhaus.abuse.ch/downloads/hostfile/
```

Feeds are disabled by default so the monitor makes no outbound request you did not configure.

The complete HTTP and Socket.IO API is documented in [API.md](API.md).
