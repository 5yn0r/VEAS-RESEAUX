import os

from dotenv import load_dotenv

load_dotenv()


def _positive_int(name: str, default: int) -> int:
    value = int(os.getenv(name, default))
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _origins() -> list[str] | None:
    value = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
    return [origin.strip() for origin in value.split(",") if origin.strip()] or None


# Server configuration. Bind locally by default; expose it deliberately with HOST.
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
HOST = os.getenv("HOST", "127.0.0.1")
PORT = _positive_int("PORT", 5000)
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
CORS_ALLOWED_ORIGINS = _origins()

# Authentication. Required when HOST is not a loopback address.
# Create AUTH_PASSWORD_HASH with: python -m veas.auth
AUTH_USERNAME = os.getenv("AUTH_USERNAME", "")
AUTH_PASSWORD_HASH = os.getenv("AUTH_PASSWORD_HASH", "")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "")
# Bearer token for scripts and integrations (Authorization: Bearer <token>).
API_TOKEN = os.getenv("API_TOKEN", "")
# Only for deployments behind a reverse proxy that already authenticates users.
ALLOW_UNAUTHENTICATED = os.getenv("ALLOW_UNAUTHENTICATED", "false").lower() == "true"

# Network capture configuration
ARP_SCAN_COMMAND = os.getenv("ARP_SCAN_COMMAND", "arp-scan")
# Leave empty to follow the interface of the default IPv4 route.
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "").strip() or None
INTERFACE_REFRESH_INTERVAL = _positive_int("INTERFACE_REFRESH_INTERVAL", 60)
SNIFFER_CHECK_INTERVAL = _positive_int("SNIFFER_CHECK_INTERVAL", 5)
SCAN_INTERVAL = _positive_int("SCAN_INTERVAL", 30)
UPDATE_INTERVAL = _positive_int("UPDATE_INTERVAL", 2)
PORT_SCAN_WINDOW = _positive_int("PORT_SCAN_WINDOW", 60)
PORT_SCAN_THRESHOLD = _positive_int("PORT_SCAN_THRESHOLD", 20)
HOST_SWEEP_THRESHOLD = _positive_int("HOST_SWEEP_THRESHOLD", 20)
# The same alert (type + subject) is raised at most once per cooldown.
ALERT_COOLDOWN = _positive_int("ALERT_COOLDOWN", 3600)
BEACON_MIN_EVENTS = _positive_int("BEACON_MIN_EVENTS", 8)
BEACON_MAX_JITTER = float(os.getenv("BEACON_MAX_JITTER", "0.1"))
# Comma-separated; empty trusts the gateway (or the first DHCP server seen).
TRUSTED_DHCP_SERVERS = os.getenv("TRUSTED_DHCP_SERVERS", "")
# Comma-separated; empty disables the unapproved-resolver check.
ALLOWED_DNS_SERVERS = os.getenv("ALLOWED_DNS_SERVERS", "")
# Connections from one source to one authentication service (SSH, RDP, SMB...) within the window.
BRUTE_FORCE_THRESHOLD = _positive_int("BRUTE_FORCE_THRESHOLD", 20)
BRUTE_FORCE_WINDOW = _positive_int("BRUTE_FORCE_WINDOW", 60)
# Distinct LLMNR/NBT-NS names answered by one host before a poisoning alert (WPAD alerts at once).
NAME_POISONING_THRESHOLD = _positive_int("NAME_POISONING_THRESHOLD", 3)
RISKY_PORTS = os.getenv("RISKY_PORTS", "21:FTP,23:Telnet,139:NetBIOS,445:SMB,3389:RDP,5900:VNC")

# Correlation: alerts for one device within this window join the same incident.
INCIDENT_WINDOW = _positive_int("INCIDENT_WINDOW", 3600)
BASELINE_BUCKET_SECONDS = _positive_int("BASELINE_BUCKET_SECONDS", 300)
# Buckets observed before volume anomalies are reported (72 x 5 min = 6 h).
BASELINE_MIN_SAMPLES = _positive_int("BASELINE_MIN_SAMPLES", 72)
BASELINE_SIGMA = float(os.getenv("BASELINE_SIGMA", "4"))
BASELINE_MIN_ANOMALY_MB = _positive_int("BASELINE_MIN_ANOMALY_MB", 50)
BASELINE_LEARNING_HOURS = _positive_int("BASELINE_LEARNING_HOURS", 24)
# Devices with at most this many destinations are "quiet" and get new-destination alerts.
BASELINE_QUIET_DESTINATIONS = _positive_int("BASELINE_QUIET_DESTINATIONS", 30)

# Notifications for incidents at or above NOTIFY_MIN_SEVERITY.
NOTIFY_MIN_SEVERITY = os.getenv("NOTIFY_MIN_SEVERITY", "high")
NOTIFY_MAX_PER_HOUR = _positive_int("NOTIFY_MAX_PER_HOUR", 20)
NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "").strip()
NOTIFY_NTFY_URL = os.getenv("NOTIFY_NTFY_URL", "").strip()
NOTIFY_NTFY_TOKEN = os.getenv("NOTIFY_NTFY_TOKEN", "").strip() or None
NOTIFY_TELEGRAM_TOKEN = os.getenv("NOTIFY_TELEGRAM_TOKEN", "").strip()
NOTIFY_TELEGRAM_CHAT_ID = os.getenv("NOTIFY_TELEGRAM_CHAT_ID", "").strip()
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = _positive_int("SMTP_PORT", 587)
SMTP_USER = os.getenv("SMTP_USER", "").strip() or None
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "") or None
SMTP_FROM = os.getenv("SMTP_FROM", "veas@localhost")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
NOTIFY_EMAIL_TO = [address.strip() for address in os.getenv("NOTIFY_EMAIL_TO", "").split(",") if address.strip()]

# SIEM export (Wazuh, Elastic, Splunk, Graylog). Both sinks can be used together.
SIEM_SYSLOG_HOST = os.getenv("SIEM_SYSLOG_HOST", "").strip()
SIEM_SYSLOG_PORT = _positive_int("SIEM_SYSLOG_PORT", 514)
SIEM_SYSLOG_PROTOCOL = os.getenv("SIEM_SYSLOG_PROTOCOL", "udp").lower()
SIEM_SYSLOG_FORMAT = os.getenv("SIEM_SYSLOG_FORMAT", "json").lower()  # json or cef
# JSON Lines file (ECS fields) for a Wazuh agent, Filebeat, or Fluent Bit to read.
SIEM_JSON_FILE = os.getenv("SIEM_JSON_FILE", "").strip()
SIEM_JSON_MAX_MB = _positive_int("SIEM_JSON_MAX_MB", 50)
SIEM_JSON_BACKUPS = int(os.getenv("SIEM_JSON_BACKUPS", "5"))
SIEM_MIN_SEVERITY = os.getenv("SIEM_MIN_SEVERITY", "low")
SIEM_INCLUDE_INCIDENTS = os.getenv("SIEM_INCLUDE_INCIDENTS", "true").lower() == "true"

# Forensic analysis of uploaded captures (.pcap / .pcapng).
FORENSICS_DIR = os.getenv("FORENSICS_DIR", "data/forensics")
FORENSICS_MAX_MB = _positive_int("FORENSICS_MAX_MB", 200)
FORENSICS_MAX_REPORTS = _positive_int("FORENSICS_MAX_REPORTS", 20)
FORENSICS_MAX_PACKETS = _positive_int("FORENSICS_MAX_PACKETS", 2000000)

# Threat intelligence: every *.txt file in THREAT_INTEL_DIR is loaded (IPs, CIDRs,
# domains, or hosts-file lines). Optional comma-separated feed URLs are downloaded there.
THREAT_INTEL_DIR = os.getenv("THREAT_INTEL_DIR", "data/intel")
THREAT_INTEL_FEEDS = [url.strip() for url in os.getenv("THREAT_INTEL_FEEDS", "").split(",") if url.strip()]
THREAT_INTEL_REFRESH_HOURS = _positive_int("THREAT_INTEL_REFRESH_HOURS", 24)

# Device identity. A device is "active" if seen (scan or traffic) within this window.
DEVICE_ACTIVE_TIMEOUT = _positive_int("DEVICE_ACTIVE_TIMEOUT", 300)
# On a fresh install, new-device alerts stay silent while the network is learned.
NEW_DEVICE_LEARNING_PERIOD = int(os.getenv("NEW_DEVICE_LEARNING_PERIOD", 600))
# Optional path to an OUI vendor file (arp-scan ieee-oui.txt or Wireshark manuf format).
OUI_FILE = os.getenv("OUI_FILE", "").strip() or None

# In-memory limits
MAX_ALERTS = _positive_int("MAX_ALERTS", 100)
MAX_HISTORY = _positive_int("MAX_HISTORY", 5000)
MAX_DNS_CACHE = _positive_int("MAX_DNS_CACHE", 1000)
MAX_PACKET_HISTORY = _positive_int("MAX_PACKET_HISTORY", 1000)
MAX_ACTIVE_FLOWS = _positive_int("MAX_ACTIVE_FLOWS", 20000)
MAX_DNS_LOG = _positive_int("MAX_DNS_LOG", 2000)

# Persistence. Set DB_PATH to an empty value to run purely in memory.
DB_PATH = os.getenv("DB_PATH", "data/veas.db").strip()
RETENTION_DAYS = _positive_int("RETENTION_DAYS", 30)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
