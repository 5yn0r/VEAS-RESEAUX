# API

All endpoints return JSON unless noted. When authentication is configured, every endpoint except `/login` and `/api/health` requires a session (dashboard login) or `Authorization: Bearer <API_TOKEN>`. Unauthenticated API calls get 401. Unauthenticated `/api/health` returns only `{"status": ...}`. Socket.IO connections need a session or `auth: {token}`.

| Endpoint | Description |
| --- | --- |
| `GET /api/stats` | Current device count, accumulated traffic, alert count, and current byte-per-second rates. |
| `GET /api/health` | Component health: workers, capture interface and counters, last scan, storage. HTTP 200 when `status` is `ok`, 503 when `degraded`. |
| `GET /api/network` | The network this host is connected to: interface (name, type, MAC, vendor, MTU, state), IPv4 (address, mask, network, broadcast, host range), IPv6 addresses, gateway (IP, MAC, vendor), DNS servers, Wi-Fi link (SSID, BSSID, security, standard, band, channel, width, signal in dBm and %, rx/tx bitrate, transmit power) or Ethernet speed, and traffic (link capacity in Mbit/s, current download/upload in bytes per second measured on the whole interface, utilization %, interface counters). Fields whose source tool (`iw`, `nmcli`, `resolvectl`) is missing are `null`. |
| `GET /api/devices` | Devices seen (ARP scan, ARP/DHCP/mDNS, or traffic) within `DEVICE_ACTIVE_TIMEOUT`, keyed by MAC address. |
| `GET /api/devices/known` | Every device ever seen (persisted across restarts). |
| `GET /api/devices/<mac>` | One device with its recent flows, DNS queries, top domains, and related alerts. |
| `GET /api/flows` | Active and recently completed flows, newest first. `ip`, `limit`. With `history=1`: stored flows, plus `hours` and `name` (server-name substring). |
| `GET /api/dns` | Recent DNS queries from local clients with their answers. `ip`, `q` (substring), `limit`. |
| `GET /api/domains` | Domains contacted per client, aggregated from DNS, TLS SNI, and HTTP Host. `ip`, `hours`, `limit`. 404 without persistence. |
| `GET /api/alerts` | Most recent alerts, oldest first. Filters: `limit` (default 50), `severity`, `type`. Served from SQLite when persistence is enabled. |
| `GET /api/traffic` | Most recently active local IPs with accumulated upload/download bytes. `limit` defaults to 10. |
| `GET /api/traffic/history` | Hourly upload/download totals from SQLite: `hours` (default 24), optional `ip`. 404 when persistence is disabled. |
| `GET /api/incidents` | Incidents, open first then newest. Filters: `status` (`open`, `acknowledged`, `closed`), `severity` (minimum), `limit`. |
| `GET /api/incidents/<id>` | One incident with its alerts. |
| `POST /api/incidents/<id>` | JSON `{"status": "acknowledged" | "closed" | "open"}`. |
| `GET /api/allowlist` | Exception rules. |
| `POST /api/allowlist` | JSON rule with at least one of `type`, `ip`, `mac`, `domain` (subdomains match), plus optional `comment`. Returns 201. |
| `DELETE /api/allowlist/<id>` | Remove a rule. Returns 204. |
| `POST /api/notifications/test` | JSON `{}`. Sends a test notification to every configured channel; 409 if none, 502 if one fails. |
| `GET /api/export/<kind>` | File download of `alerts`, `incidents`, `devices`, `flows`, `dns`, or `domains`. `format` (`csv` or `json`), `hours` (default 24). |
| `GET /api/packets` | Recent packet metadata, filterable by `ip`, `protocol`, `direction`, `port`, and `limit`. |
| `GET /api/packets/summary` | Counts of retained packets grouped by protocol and direction. |

POST and DELETE endpoints require `Content-Type: application/json` where they take a body, which browsers cannot send cross-site without CORS approval.

`/api/stats` includes `open_incidents`, `devices_count`, `total_traffic_bytes`, `alerts_count`, `current_upload_bps`, `current_download_bps`, `current_total_bps`, and `timestamp`.

## Socket.IO events

| Event | Payload |
| --- | --- |
| `device_update` | Active device snapshot, keyed by MAC address, sent when devices change. |
| `traffic_update` | `{ ip, upload, download, unique_connections, timestamp }` for one local IP since the last flush. |
| `alert` | One structured alert (see below). |
| `incident_update` | `{event, incident}` where `event` is `created`, `updated`, `escalated`, or `status`. |

## Devices

Each device carries `mac`, `ip`, `ip_history`, `vendor` (from arp-scan or the offline OUI file; `Randomized MAC` for locally administered addresses), `hostname` and `hostname_source` (`dhcp` > `mdns` > `scan`), `sources` (`scan`, `passive`, `dhcp`, `mdns`), optional `dhcp_vendor_class`, `first_seen`, and `last_seen`.

## Flows

A flow is one conversation keyed by protocol and client/server address and port. The client is the side that sent the first SYN, or otherwise the side not on a well-known port. Fields: `client_ip`, `client_port`, `server_ip`, `server_port`, `protocol`, `direction` (seen from the client), `packets_out`/`bytes_out` (client to server), `packets_in`/`bytes_in`, `tcp_flags` (union), `server_name` with `server_name_source` (`tls`, `http`, or `dns`), `first_seen`, `last_seen`, `closed`, and `active`. TCP flows expire after 300 s idle or 5 s after FIN/RST, and other flows after 60 s idle. Expired flows are written to SQLite.

## Alerts

```json
{
  "id": "5f0c...",
  "type": "port_scan",
  "severity": "medium",
  "timestamp": 1790535395.2,
  "source_ip": "192.168.1.10",
  "destination_ip": "192.168.1.1",
  "detail": "192.168.1.10 contacted 20 TCP ports on 192.168.1.1 in 60s",
  "evidence": {"distinct_ports": 20, "window_seconds": 60, "sample_ports": [22, 80, 443]},
  "message": "[PORT_SCAN] 192.168.1.10 contacted 20 TCP ports on 192.168.1.1 in 60s",
  "mitre": [{"id": "T1046", "name": "Network Service Discovery", "tactics": ["discovery"], "url": "https://attack.mitre.org/techniques/T1046/"}]
}
```

Alert types:

| Type | Severity | MITRE ATT&CK | Trigger |
| --- | --- | --- | --- |
| `new_device` | low | T1200 | A MAC never seen before (silent during `NEW_DEVICE_LEARNING_PERIOD` on a fresh database). |
| `arp_spoofing` | critical | T1557.002 | The gateway IP is claimed by a different MAC. |
| `ip_conflict` | medium | T1557 | An IP is claimed by a new MAC while the previous owner is still active. |
| `rogue_dhcp` | high | T1557.003 | A DHCP offer/ack from a server outside `TRUSTED_DHCP_SERVERS` (default: the gateway, or the first server seen). |
| `port_scan` | medium, high if the source is remote | T1046 | `PORT_SCAN_THRESHOLD` distinct TCP SYN ports to one host within a sliding `PORT_SCAN_WINDOW`. |
| `host_sweep` | medium, high if remote | T1046 | One source sends SYNs to the same port on `HOST_SWEEP_THRESHOLD` hosts. |
| `ping_sweep` | medium | T1018 | ICMP echo requests to `HOST_SWEEP_THRESHOLD` hosts. |
| `brute_force` | medium, high if remote | T1110 | `BRUTE_FORCE_THRESHOLD` new connections from one source to one authentication service (SSH, RDP, SMB, databases...) within `BRUTE_FORCE_WINDOW`. |
| `llmnr_poisoning` | high | T1557.001 | A host answers an LLMNR/NBT-NS lookup for WPAD, or answers `NAME_POISONING_THRESHOLD` different names: the behaviour of Responder-style credential capture. |
| `threat_intel_ip` | high | T1071 | A flow with an IP or CIDR listed in the threat-intel files. |
| `threat_intel_domain` | high | T1071, T1568 | A DNS query, TLS SNI, or HTTP Host matching a listed domain or one of its parents. |
| `risky_protocol` | medium | T1021 | A local client opens a `RISKY_PORTS` service (Telnet, SMB, RDP...) to an Internet host. |
| `exposed_service` | medium, high for `RISKY_PORTS` | T1133 | A local server answers a TCP connection from an Internet host. |
| `beaconing` | low | T1071 | At least `BEACON_MIN_EVENTS` connections to the same destination at a regular interval (jitter below `BEACON_MAX_JITTER`). |
| `dns_tunnel` | medium | T1071.004, T1572 | Long high-entropy labels, or many unique names under one domain within the window. |
| `traffic_anomaly` | medium | T1048 | A device uploads far more than its learned baseline in one `BASELINE_BUCKET_SECONDS` bucket (mean + `BASELINE_SIGMA` standard deviations, at least `BASELINE_MIN_ANOMALY_MB`), after `BASELINE_MIN_SAMPLES` buckets. |
| `new_destination` | low | T1071 | A "quiet" device (at most `BASELINE_QUIET_DESTINATIONS` known destinations, learned for `BASELINE_LEARNING_HOURS`) contacts a new domain or IP. |
| `dns_bypass` | low | T1071.004 | A query to a resolver outside `ALLOWED_DNS_SERVERS` (only when that list is set). |

The same type and subject is reported at most once per `ALERT_COOLDOWN`. Alerts matching an allowlist rule are dropped. When the alert concerns a local IP with a known MAC, the MAC is added to `evidence.mac`.

Every alert carries `mitre`: the list of associated MITRE ATT&CK techniques (`id`, `name`, `tactics`, `url`). Incidents carry `mitre_techniques` and `mitre_tactics`. A mapping names the adversary technique the behaviour is evidence of; it does not prove intent.

## Incidents

Alerts about the same device (MAC, or IP when unknown) within `INCIDENT_WINDOW` of each other form one incident. The score adds each alert type's worst severity weight (info 1, low 2, medium 5, high 10, critical 25) up to three occurrences, plus 5 per additional distinct type, plus a bonus for known attack chains (listed in `reasons`), such as a new device that starts scanning, or a threat-intel hit followed by beaconing or exfiltration. Incident severity follows the score (10 medium, 25 high, 50 critical) and is never lower than its worst alert. Incidents that are created or escalated to at least `NOTIFY_MIN_SEVERITY` are sent to the configured channels (webhook JSON, ntfy, Telegram, SMTP e-mail), at most `NOTIFY_MAX_PER_HOUR` per hour.

`severity` is one of `info`, `low`, `medium`, `high`, `critical`. `message` keeps the previous display string.

## Health

`/api/health` also includes `siem` (sinks, events sent, errors), `detection` (alerts raised per type, suppressed duplicates, threat-intel indicator counts) and returns `status`, `problems` (human-readable list), `uptime_seconds`, `threads` (per worker: `alive`, `restarts`, `last_error`, `last_heartbeat`), `capture` (`interface`, `local_network`, `packets_seen`, `packets_dropped`, `packets_per_second`, `callback_errors`), `scanner` (`ok`, `error`, `last_success_at`, `devices`), and `storage`.

Traffic values are bytes. Current rates in `/api/stats` are bytes per second.

Packet inspection retains metadata only. Payload bytes are read transiently to extract a TLS server name or an HTTP Host header and are then discarded. Retained metadata is timestamp, source/destination IP and port, protocol, packet size, direction, and TCP flags. Packet payloads are never returned or stored. `limit` is capped by `MAX_PACKET_HISTORY`.
