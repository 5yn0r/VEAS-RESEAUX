# Changelog

## Unreleased

- "Mon reseau" view and `/api/network`: interface, IPv4/IPv6 addressing, gateway and DNS, Wi-Fi link (SSID, BSSID, security, standard, band, channel, signal, bitrates), link bandwidth, live throughput, and interface counters.

- MITRE ATT&CK mapping on every alert (techniques, tactics, links) and on incidents; ATT&CK tags in the dashboard.
- SIEM export: Syslog over UDP/TCP (RFC 5424, RFC 6587 framing) with ECS JSON or CEF, and a rotating ECS JSON Lines file; `docs/SIEM.md` guide for Wazuh and Elastic; `--siem-json` option for pcap replay.
- New detections: LLMNR/NBT-NS poisoning (Responder, WPAD) and brute force against authentication services; new attack-chain bonuses.
- GitHub Actions workflow running compilation and the full test suite.
- Fix: a host that spoofed another IP lost its own IP mapping, so its later alerts were attributed to the victim.
- Fix: identity alerts used the system clock instead of the packet capture time.

- Authentication: dashboard login with hashed password, API bearer token, login rate limiting, same-origin check for cookie-authenticated writes, Socket.IO authentication, and refusal to serve a non-loopback address without authentication.
- Offline pcap analysis (`python -m moniwifi.replay`) with the live pipeline, and end-to-end tests that replay an attack scenario.
- Detections use packet capture timestamps.
- CSV/JSON export endpoint and dashboard export buttons; device detail drawer (identity, baseline, incidents, alerts, domains, flows, DNS).
- Fix: unicast DNS from source port 5353 was treated as mDNS.

- Incident correlation per device with scoring, attack-chain bonuses, escalation, and an open/acknowledged/closed workflow (API and dashboard view).
- Per-device baselines: upload-volume anomalies (`traffic_anomaly`) and new destinations for quiet devices (`new_destination`).
- Notifications through webhook, ntfy, Telegram, and SMTP with severity filter and rate limit; test endpoint.
- Allowlist rules (type, IP, MAC, domain) managed through the API.

- `DetectionEngine` with sliding-window scan detection (inbound and outbound port scans, host sweeps, ping sweeps), gateway ARP spoofing, IP conflicts, rogue DHCP, risky protocols, exposed services, beaconing, DNS tunnelling, and unapproved resolvers.
- Offline threat intelligence from local files and optional feeds (IP, CIDR, domain, hosts-file formats) matched on flows, DNS, SNI, and HTTP Host.
- Alert throttling per type and subject (`ALERT_COOLDOWN`); detection statistics in `/api/health`.

- Passive device discovery from ARP, DHCP (hostname, vendor class), mDNS, and traffic; offline OUI vendor lookup; randomized-MAC detection. Devices are active while seen within `DEVICE_ACTIVE_TIMEOUT`.
- `new_device` alert with a learning period on fresh installs (`NEW_DEVICE_LEARNING_PERIOD`).
- Flow aggregation with TLS SNI, HTTP Host, and DNS-derived server names; expired flows stored in SQLite.
- DNS query log and per-client domain aggregation.
- New endpoints `/api/devices/<mac>`, `/api/flows`, `/api/dns`, `/api/domains`, and a Connections dashboard view.

- Supervise scanner, sniffer, and flush workers and restart them with backoff when they crash or exit.
- Replace the process-lifetime interface cache with a refreshed `NetworkContext`; capture restarts when the interface changes. Add `NETWORK_INTERFACE`.
- Persist devices, alerts, and hourly traffic in SQLite (`DB_PATH`, `RETENTION_DAYS`), and reload them on start.
- Structured alerts with id, severity, timestamp, and evidence; `/api/alerts` accepts `limit`, `severity`, and `type`.
- Add `/api/health`, `/api/devices/known`, and `/api/traffic/history`; add a Docker healthcheck and a dashboard health indicator.
- Add tests for storage, supervision, network detection, packet handling, and the HTTP API.

- Add bounded packet metadata capture, filters, summary endpoints, and the packet-analysis dashboard view.
- Bound DNS and traffic history using the configured limits.
- Report only devices observed in the latest successful scan.
- Replace per-connection port-scan alerts with a distinct-port threshold.
- Restrict Socket.IO to same-origin by default and bind the server to localhost by default.
- Remove Docker privileged mode and the in-process `sudo` call.
- Remove unsafe dashboard HTML insertion and the broken traffic-total element reference.
- Add state-level regression tests and a tracked environment template.
- Rewrite documentation to describe the behavior and deployment model that actually exist.
