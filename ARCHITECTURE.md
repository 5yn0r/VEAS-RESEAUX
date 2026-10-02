# Architecture

```
Browser dashboard
       | REST / Socket.IO
Flask application
       |
NetworkMonitor ── NetworkContext (interface + LAN, refreshed on a timer)
  | ThreadSupervisor
  |   | Scanner (arp-scan)
  |   | Sniffer (Scapy AsyncSniffer)
  |   | Flush loop
       |
MonitorState (thread-safe, in memory) ── Storage (SQLite, optional)
```

`NetworkMonitor` registers six workers (Scanner, Sniffer, Flush, ThreatIntel, SIEM, Notifier) with `ThreadSupervisor`, which restarts any worker that raises or returns, with exponential backoff, and records restarts, last error, and heartbeats:

- The scanner refreshes the visible-device snapshot at `SCAN_INTERVAL` and persists every device it sees.
- The sniffer runs an `AsyncSniffer` on the interface given by `NetworkContext`. It raises when the capture thread dies (so the supervisor restarts it) and restarts capture when the interface changes.
- The flush loop emits buffered traffic and alerts every `UPDATE_INTERVAL`, writes alerts and hourly traffic to storage, and purges data older than `RETENTION_DAYS` once an hour.

`NetworkContext` replaces a process-lifetime cache: the default route is re-read every `INTERFACE_REFRESH_INTERVAL` seconds, and every few seconds while no network is available, so a late DHCP lease or a Wi-Fi change is picked up.

Each packet goes through `NetworkMonitor.packet_callback`: ARP and DHCP packets feed device identity, mDNS answers name devices, DNS queries and answers go to `DomainTracker`, TLS ClientHello and HTTP requests yield a server name (`moniwifi.protocols`), and every local IP packet updates the `FlowTable`. The sniffer filter is `ip or arp`.

Detection is centralised in `DetectionEngine` (`moniwifi.detectors`). The monitor calls it on device changes, DHCP server replies, TCP SYNs and ICMP echo requests, new flows, inbound connections answered by a local server, DNS queries, and server names. Scan rules use `SlidingDistinct` (a true sliding window of distinct values per key). `emit()` builds the alert and throttles repeats per (type, subject) for `ALERT_COOLDOWN`. `ThreatIntel` (`moniwifi.threatintel`) holds IP, CIDR, and domain indicators, caches IP lookups, and is refreshed by the supervised `ThreatIntel` worker, which also downloads any configured feeds.

Correlation happens in the flush loop. New alerts go to `IncidentManager` (`moniwifi.incidents`), which picks the entity (the local device the alert is about) and groups, scores, and escalates incidents. Created or escalated incidents are queued to `Notifier` (`moniwifi.notify`), a supervised worker that delivers them with a rate limit. `BaselineTracker` (`moniwifi.baseline`) receives flushed per-IP traffic and new outbound flows; the engine turns its findings into `traffic_anomaly` and `new_destination` alerts. `Allowlist` (`moniwifi.allowlist`) is checked by `DetectionEngine.emit` after throttling. Incidents, baselines, and allowlist rules are stored in SQLite and reloaded on start.

Identity lives in `DeviceRegistry` (`moniwifi.devices`), keyed by MAC. `observe()` reports what changed (a new MAC, a device changing IP, an IP taken over by another MAC) so detectors can raise alerts; passive sightings of the same MAC/IP are throttled to one every 30 s. Changed devices are written to SQLite on the next flush.

`MonitorState` owns shared live data behind a lock. It bounds alerts, DNS entries, and traffic-history entries with the corresponding environment settings, and keeps health counters (packets seen and dropped, callback errors, last scan result). Alerts are structured dictionaries built by `moniwifi.alerts.make_alert` (id, type, severity, timestamp, source and destination IP, detail, evidence). A device is active while it has been seen within `DEVICE_ACTIVE_TIMEOUT`.

`Storage` holds one SQLite connection (WAL mode) behind a lock with tables `devices` (base columns plus a `details` JSON), `alerts`, `traffic_hourly`, `flows` (expired flows), and `domains` (per-client domain counters by source). Storage failures are logged and surfaced by `/api/health`; they never stop capture.

The dashboard is organized as independent client-side views: Overview, Devices, Traffic, Connections (flows and DNS), Packet analysis, Incidents, and Alerts. They consume REST snapshots plus Socket.IO updates, and the header shows `/api/health`.

`NetworkInfo` (`moniwifi.linkinfo`) describes the host's own connection on request: addressing from netifaces, counters and link state from `/sys/class/net`, the gateway MAC from `/proc/net/arp`, and Wi-Fi details from `iw`, `nmcli`, and `resolvectl` when installed. Throughput is the difference between two interface counter samples; the first request takes two samples half a second apart.

`moniwifi.attack` maps each alert type to MITRE ATT&CK techniques; `make_alert` attaches them and incidents aggregate their tactics. `SiemExporter` (`moniwifi.siem`) is a supervised worker that converts alerts and incident changes to ECS JSON (or CEF) and writes them to Syslog and/or a rotating JSON Lines file; the flush loop submits events and never waits on the network.

`moniwifi.auth` adds a login page (session cookie) and bearer-token authentication through a `before_request` hook and the Socket.IO `connect` handler. `moniwifi.replay` feeds a pcap through `NetworkMonitor.packet_callback` with a `StaticNetworkContext`. Detections use each packet's capture timestamp, so offline results match live behaviour, including time-based rules such as beaconing.

The process is deliberately single-node. For multi-site monitoring, run one instance per site and collect their exports or notifications centrally.
