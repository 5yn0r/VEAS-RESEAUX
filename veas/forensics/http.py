"""HTTP analysis: TCP stream reassembly, request/response pairing, statistics, and web attack detection.

Payloads are inspected to describe the attack; passwords and tokens are masked
before anything is stored in the report.
"""

from __future__ import annotations

import base64
import bisect
import hashlib
import posixpath
import re
import statistics
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from scapy.all import IP, TCP, IPv6

from veas.detectors import shannon_entropy
from veas.forensics.model import SEVERITY_ORDER, Frames, finding, ip_filter, mask_secret, top

MAX_STREAM_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
BODY_KEEP = 4096
# Request bodies are kept whole (up to this size) so uploaded files can be hashed and inspected.
REQUEST_BODY_KEEP = 1024 * 1024
WEBSHELL_MIN_CALLS = 5
OBFUSCATED_MIN_CALLS = 10
OBFUSCATED_ENTROPY = 4.5
ROTATING_AGENTS = 5
MAX_TRANSACTIONS = 2000
MAX_SAMPLES = 15
DIR_ENUM_404 = 20
BRUTE_FORCE_MIN = 10
SERVER_ERROR_MIN = 10

METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"PROPFIND")
REQUEST_LINE = re.compile(rb"([A-Z]{3,10}) (\S+) HTTP/(\d\.\d)\r?\n")
RESPONSE_LINE = re.compile(rb"HTTP/(\d\.\d) (\d{3})(?: ([^\r\n]*))?\r?\n")
RESYNC = re.compile(rb"(?:(?:" + b"|".join(METHODS) + rb") \S+ HTTP/\d\.\d|HTTP/\d\.\d \d{3})")
# Fields whose value is masked in the report; only PASSWORD_FIELD counts as a login.
SECRET_FIELD = re.compile(r"pass|pwd|motdepasse|mot_de_passe|secret|token|api[_-]?key", re.I)
PASSWORD_FIELD = re.compile(r"pass|pwd|motdepasse|mot_de_passe", re.I)
LOGIN_PATH = re.compile(r"login|log-in|signin|sign-in|logon|auth|session|connexion|account|admin|wp-login", re.I)
USER_FIELD = re.compile(r"^(user(name)?|login|email|e-mail|uname|usr|account|identifiant|log)$", re.I)
SECRET_IN_TEXT = re.compile(r"((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key)[\"']?\s*[=:]\s*[\"']?)([^&\s\"',}]+)", re.I)

FAILURE_STATUSES = {401, 403}
SUCCESS_STATUSES = {200, 201, 202, 204, 301, 302, 303, 307, 308}
DIRECTORY_FOUND_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}

SCANNERS = {
    "sqlmap": "sqlmap (injection SQL automatisée)", "nikto": "Nikto (scanner de vulnérabilités web)",
    "nmap": "Nmap (moteur de scripts NSE)", "masscan": "Masscan", "zgrab": "ZGrab", "gobuster": "Gobuster (énumération de répertoires)",
    "dirbuster": "DirBuster", "dirb": "DIRB (énumération de répertoires)", "wfuzz": "Wfuzz (fuzzing web)", "ffuf": "ffuf (fuzzing web)",
    "feroxbuster": "Feroxbuster", "hydra": "THC-Hydra (force brute)", "medusa": "Medusa (force brute)", "wpscan": "WPScan",
    "acunetix": "Acunetix", "nessus": "Nessus", "openvas": "OpenVAS", "nuclei": "Nuclei", "whatweb": "WhatWeb",
    "burp": "Burp Suite", "owasp zap": "OWASP ZAP", "zaproxy": "OWASP ZAP", "commix": "Commix (injection de commandes)",
    "jaeles": "Jaeles", "arachni": "Arachni", "skipfish": "Skipfish", "w3af": "w3af", "havij": "Havij (injection SQL)",
}
EXECUTABLE_TYPES = (
    "application/x-msdownload", "application/x-msdos-program", "application/x-dosexec", "application/x-executable",
    "application/x-elf", "application/x-sh", "application/x-shellscript", "application/vnd.microsoft.portable-executable",
    "application/java-archive", "application/x-python", "application/hta", "application/x-msi",
)
EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".scr", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".hta", ".jar", ".msi", ".sh", ".elf", ".py", ".bin")
SERVER_SCRIPT_EXTENSIONS = (".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cgi", ".pl")
WEBSHELL_CODE = {
    "eval()": re.compile(rb"\beval\s*\(", re.I),
    "assert()": re.compile(rb"\bassert\s*\(", re.I),
    "create_function()": re.compile(rb"create_function", re.I),
    "base64_decode()": re.compile(rb"base64_decode", re.I),
    "gzinflate/gzuncompress()": re.compile(rb"gz(inflate|uncompress|decode)", re.I),
    "str_rot13()": re.compile(rb"str_rot13", re.I),
    "exécution système (system, exec, shell_exec, passthru, popen)": re.compile(rb"\b(system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|\bexec\s*\(", re.I),
    "lecture directe de paramètres ($_POST, $_REQUEST, php://input)": re.compile(rb"\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[|php://input", re.I),
    "chaînes reconstruites par str_replace (obfuscation)": re.compile(rb"str_replace\s*\(\s*['\"][^'\"]{1,8}['\"]\s*,\s*['\"]['\"]", re.I),
    "Runtime.exec / ProcessBuilder (JSP)": re.compile(rb"Runtime\.getRuntime\(\)\.exec|ProcessBuilder", re.I),
}
HEX_MARKER = re.compile(rb"[0-9a-f]{12}")

ATTACKS = {
    "sql_injection": (
        re.compile(
            r"(\bunion\b[\s\S]{0,40}\bselect\b|\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|'\s*(or|and)\s+'|\bsleep\s*\(\s*\d|\bbenchmark\s*\("
            r"|information_schema|\bwaitfor\s+delay\b|;\s*(drop|insert|update|delete|exec)\s|'\s*--|'\s*#|\bextractvalue\s*\(|\bupdatexml\s*\(|\bload_file\s*\()",
            re.I,
        ),
        "high", "Injection SQL", ["T1190"],
        "L'attaquant glisse du code SQL dans un paramètre pour modifier la requête exécutée par la base de données : contourner une "
        "authentification, lire des tables (mots de passe, données clients), voire exécuter des commandes.",
        "Corriger l'application avec des requêtes préparées, vérifier les journaux de la base, et considérer les données comme exposées si "
        "une réponse anormale (erreur SQL, contenu volumineux) a été renvoyée.",
    ),
    "xss": (
        re.compile(r"(<script|javascript:|on(error|load|mouseover|focus)\s*=|<svg[^>]*\bon\w+\s*=|<iframe|document\.cookie|alert\s*\(|prompt\s*\()", re.I),
        "medium", "Cross-site scripting (XSS)", ["T1190"],
        "Du code JavaScript est injecté dans un paramètre. Si l'application le renvoie tel quel, il s'exécute dans le navigateur des "
        "visiteurs : vol de session, redirection, défiguration.",
        "Encoder les sorties côté application, activer une Content-Security-Policy et vérifier si le code injecté apparaît dans la réponse.",
    ),
    "path_traversal": (
        re.compile(r"(\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|win\.ini|boot\.ini|c:\\windows|/proc/self/environ|php://filter|file://)", re.I),
        "high", "Traversée de répertoires / inclusion de fichier", ["T1190", "T1083"],
        "En remontant l'arborescence avec « ../ », l'attaquant tente de lire des fichiers hors du site : comptes système, configuration, "
        "clés. Une réponse 200 qui contient le fichier demandé signifie que la faille est exploitée.",
        "Valider et normaliser les chemins côté application, restreindre les droits du service web et vérifier quels fichiers ont été renvoyés.",
    ),
    "command_injection": (
        re.compile(r"((;|\||`|\$\(|&&|%0a)\s*(id|whoami|uname|cat|ls|wget|curl|nc|ncat|bash|sh|ping|powershell|cmd|python|perl|ifconfig|ipconfig)\b|/bin/(ba)?sh|cmd\.exe|powershell\.exe)", re.I),
        "high", "Injection de commandes système", ["T1059", "T1190"],
        "L'attaquant ajoute une commande système (id, whoami, wget...) à un paramètre transmis à un shell par l'application. En cas de "
        "succès, il exécute ce qu'il veut sur le serveur avec les droits du service web.",
        "Considérer le serveur comme compromis si la réponse contient le résultat d'une commande ; corriger l'appel système et rechercher des fichiers déposés.",
    ),
    "webshell": (
        re.compile(r"((^|[?&/])(cmd|exec|command|execute|shell)=|shell\.php|c99\.php|r57\.php|b374k|wso\.php|webshell|cmd\.jsp|cmd\.aspx)", re.I),
        "high", "Utilisation d'un webshell", ["T1505.003"],
        "Un webshell est un script déposé sur le serveur qui exécute les commandes reçues en paramètre. Son utilisation montre que "
        "l'attaquant a déjà un accès persistant au serveur.",
        "Isoler le serveur, retrouver et supprimer le script, identifier comment il a été déposé et changer tous les secrets du serveur.",
    ),
    "log4shell": (
        re.compile(r"\$\{(jndi|\$\{|lower:|upper:|::-j)", re.I),
        "critical", "Exploitation Log4Shell (CVE-2021-44228)", ["T1190"],
        "La chaîne ${jndi:...} vise la faille Log4Shell de la bibliothèque Java Log4j : si un journal la traite, le serveur télécharge "
        "et exécute du code distant.",
        "Mettre à jour Log4j, rechercher des connexions sortantes LDAP/RMI du serveur juste après cette requête et l'examiner comme potentiellement compromis.",
    ),
    "shellshock": (
        re.compile(r"\(\)\s*\{\s*:?\s*;\s*\}\s*;"),
        "critical", "Exploitation Shellshock (CVE-2014-6271)", ["T1190", "T1059"],
        "La chaîne « () { :; }; » dans un en-tête exploite la faille Shellshock de bash via les scripts CGI : la commande qui suit est exécutée sur le serveur.",
        "Mettre à jour bash, désactiver les CGI inutiles et examiner le serveur.",
    ),
    "sensitive_file": (
        re.compile(
            r"(/\.env\b|/\.git/|/\.svn/|wp-config|phpmyadmin|/server-status|/\.htaccess|/\.htpasswd|/backup|\.sql\b|\.bak\b|\.old\b"
            r"|/admin\b|/administrator\b|/manager/html|/wp-login\.php|/xmlrpc\.php|/config\.(php|json|yml)|/\.aws/|/\.ssh/|/actuator)",
            re.I,
        ),
        "low", "Accès à des fichiers ou pages sensibles", ["T1595"],
        "Ces chemins (sauvegardes, fichiers de configuration, dépôt Git, pages d'administration) sont recherchés systématiquement par "
        "les attaquants car ils contiennent souvent des mots de passe ou donnent un accès privilégié.",
        "Vérifier qu'aucun de ces fichiers n'est accessible (réponse 200) et protéger les pages d'administration.",
    ),
}
SUCCESS_MARKERS = {
    "path_traversal": re.compile(rb"root:.?:0:0:|\[fonts\]|\[boot loader\]|\[extensions\]", re.I),
    "command_injection": re.compile(rb"uid=\d+\(\w+\)|nt authority\\|windows ip configuration|linux \S+ \d+\.\d+", re.I),
    "webshell": re.compile(rb"uid=\d+\(\w+\)|nt authority\\|volume serial number|total \d+\s+drwx", re.I),
    "sql_injection": re.compile(rb"sql syntax|mysql_fetch|ora-\d{5}|sqlstate|unclosed quotation|sqlite3?\.|pg_query|syntax error at or near|odbc", re.I),
}
SUCCESS_TEXT = {
    "path_traversal": "le contenu d'un fichier système a été renvoyé",
    "command_injection": "la réponse contient le résultat d'une commande système",
    "webshell": "la réponse contient le résultat d'une commande système",
    "sql_injection": "le serveur a renvoyé une erreur SQL (application vulnérable)",
}


def mask_secrets(text: str) -> str:
    return SECRET_IN_TEXT.sub(lambda match: match.group(1) + "***", text)


def decode(text: str) -> str:
    try:
        return unquote_plus(unquote_plus(text))
    except Exception:  # noqa: BLE001 - malformed escapes in hostile traffic
        return text


class StreamBuffer:
    """One direction of a TCP connection, reassembled by sequence number."""

    def __init__(self) -> None:
        self.segments: dict[int, tuple[bytes, int, float]] = {}
        self.size = 0
        self.base: int | None = None

    def add(self, seq: int, payload: bytes, frame: int, ts: float) -> None:
        if self.base is None:
            self.base = seq
        relative = (seq - self.base) % 2**32
        if relative in self.segments or self.size >= MAX_STREAM_BYTES:
            return
        self.segments[relative] = (payload, frame, ts)
        self.size += len(payload)

    def assemble(self) -> tuple[bytes, list[int], list[tuple[int, float]]]:
        data = bytearray()
        starts: list[int] = []
        marks: list[tuple[int, float]] = []
        for relative in sorted(self.segments):
            payload, frame, ts = self.segments[relative]
            if relative < len(data):
                payload = payload[len(data) - relative:]
            if not payload:
                continue
            starts.append(len(data))
            marks.append((frame, ts))
            data += payload
        return bytes(data), starts, marks


def parse_headers(block: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in block.split(b"\n"):
        name, separator, value = line.partition(b":")
        if separator and name and b" " not in name.strip():
            key = name.strip().decode("latin-1").lower()
            headers.setdefault(key, value.strip().decode("latin-1"))
    return headers


def read_chunked(data: bytes, position: int) -> tuple[bytes, int]:
    body = bytearray()
    while position < len(data):
        line_end = data.find(b"\r\n", position)
        if line_end == -1:
            break
        try:
            size = int(data[position:line_end].split(b";")[0], 16)
        except ValueError:
            break
        position = line_end + 2
        if size == 0:
            trailer = data.find(b"\r\n\r\n", position - 2)
            return bytes(body), (trailer + 4 if trailer != -1 else len(data))
        body += data[position:position + size]
        position += size + 2
    return bytes(body), len(data)


def parse_messages(data: bytes, kind: str, request_methods: list[str] | None = None) -> list[dict]:
    """Split a reassembled stream into HTTP messages (``kind`` is ``request`` or ``response``)."""
    pattern = REQUEST_LINE if kind == "request" else RESPONSE_LINE
    messages, position, index = [], 0, 0
    while position < len(data):
        match = pattern.match(data, position)
        if not match:
            following = RESYNC.search(data, position + 1)
            if not following:
                break
            position = following.start()
            continue
        header_end = data.find(b"\r\n\r\n", match.end() - 2)
        separator = 4
        if header_end == -1:
            header_end, separator = data.find(b"\n\n", match.end() - 1), 2
        if header_end == -1 or header_end - position > MAX_HEADER_BYTES:
            header_end, separator = len(data), 0
        headers = parse_headers(data[match.end():header_end])
        body_start = header_end + separator
        message = {"start": position, "headers": headers}
        if kind == "request":
            message.update(method=match.group(1).decode(), uri=match.group(2).decode("latin-1"), version=match.group(3).decode())
        else:
            status = int(match.group(2))
            message.update(status=status, reason=(match.group(3) or b"").decode("latin-1"), version=match.group(1).decode())
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body, end = read_chunked(data, body_start)
        elif headers.get("content-length", "").isdigit():
            end = min(body_start + int(headers["content-length"]), len(data))
            body = data[body_start:end]
        elif kind == "request":
            body, end = b"", body_start
        else:
            method = request_methods[index] if request_methods and index < len(request_methods) else "GET"
            if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
                body, end = b"", body_start
            else:
                following = RESPONSE_LINE.search(data, body_start)
                end = following.start() if following else len(data)
                body = data[body_start:end]
        message["body_length"] = len(body)
        message["body"] = body[:REQUEST_BODY_KEEP if kind == "request" else BODY_KEEP]
        message["body_sha256"] = hashlib.sha256(body).hexdigest() if body else None
        messages.append(message)
        if kind == "request" or not 100 <= message["status"] < 200:
            index += 1
        position = max(end, position + 1)
    return messages


def form_fields(body: bytes, content_type: str) -> list[tuple[str, str]]:
    if "json" in content_type:
        return [(key, value) for key, value in re.findall(r'"([^"]{1,40})"\s*:\s*"([^"]*)"', body.decode("utf-8", "replace"))]
    if "multipart" in content_type:
        return []
    try:
        return parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
    except ValueError:
        return []


def credentials(headers: dict, fields: list[tuple[str, str]]) -> dict | None:
    """Username and masked password from Basic auth or a login form; None when absent."""
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("basic "):
        try:
            user, _, password = base64.b64decode(authorization[6:].strip()).decode("utf-8", "replace").partition(":")
        except (ValueError, UnicodeDecodeError):
            return {"type": "Basic", "user": None, "password": "(illisible)"}
        return {"type": "Basic", "user": user, "password": mask_secret(password)}
    if authorization.lower().startswith("bearer "):
        return {"type": "Bearer", "user": None, "password": mask_secret(authorization[7:].strip())}
    secret = next((value for key, value in fields if PASSWORD_FIELD.search(key)), None)
    if secret is None:
        return None
    user = next((value for key, value in fields if USER_FIELD.match(key)), None)
    return {"type": "Formulaire", "user": user, "password": mask_secret(secret)}


def masked_body(fields: list[tuple[str, str]], body: bytes, content_type: str = "") -> str:
    if "multipart" in content_type:
        return f"(formulaire multipart, {len(body)} octets conservés)"
    if fields:
        text = "&".join(f"{key}={'***' if SECRET_FIELD.search(key) else value}" for key, value in fields)
    else:
        text = body[:300].decode("utf-8", "replace")
    return mask_secrets(text)[:300]


def scanner_signature(agent: str) -> str | None:
    lowered = agent.lower()
    return next((signature for signature in SCANNERS if signature in lowered), None)


def scanner_for(agent: str) -> str | None:
    signature = scanner_signature(agent)
    return SCANNERS[signature] if signature else None


def multipart_files(body: bytes, content_type: str) -> list[dict]:
    """Files carried by a multipart/form-data body."""
    match = re.search(r"boundary=\"?([^\";]+)", content_type)
    if not match:
        return []
    files = []
    for part in body.split(b"--" + match.group(1).encode("latin-1")):
        head, separator, content = part.partition(b"\r\n\r\n")
        name = re.search(rb'filename="([^"]*)"', head)
        if not separator or not name or not name.group(1):
            continue
        content = content[:-2] if content.endswith(b"\r\n") else content
        files.append({"filename": posixpath.basename(name.group(1).decode("utf-8", "replace").replace("\\", "/")), "content": content})
    return files


def webshell_indicators(content: bytes) -> list[str]:
    return [label for label, pattern in WEBSHELL_CODE.items() if pattern.search(content)]


def common_markers(bodies: list[bytes]) -> list[str]:
    """12-hex-digit tokens present in most bodies: the fixed key markers of tools such as Weevely."""
    counts: Counter = Counter()
    for body in bodies:
        counts.update(set(HEX_MARKER.findall(body)))
    needed = max(3, int(len(bodies) * 0.8))
    return [token.decode() for token, count in counts.most_common(4) if count >= needed]


class HttpAnalyzer:
    category = "http"

    def __init__(self) -> None:
        self.streams: dict[tuple, StreamBuffer] = {}
        self.transactions: list[dict] = []
        self.findings: list[dict] = []

    def process(self, packet, frame: int, ts: float) -> None:
        if TCP not in packet:
            return
        layer = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        if layer is None:
            return
        tcp = packet[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            return
        key = (layer.src, tcp.sport, layer.dst, tcp.dport)
        stream = self.streams.get(key)
        if stream is None:
            if not (payload.startswith(METHODS) or payload.startswith(b"HTTP/1.") or payload.startswith(b"HTTP/2")):
                return
            stream = self.streams[key] = StreamBuffer()
        stream.add(tcp.seq, payload, frame, ts)

    # Reassembly and pairing ------------------------------------------------

    def _messages(self) -> list[dict]:
        transactions = []
        handled = set()
        for key, stream in self.streams.items():
            if key in handled:
                continue
            data, starts, marks = stream.assemble()
            if not REQUEST_LINE.match(data):
                continue
            handled.add(key)
            requests = parse_messages(data, "request")
            for request in requests:
                frame, ts = marks[max(bisect.bisect_right(starts, request["start"]) - 1, 0)]
                request["frame"], request["ts"] = frame, ts
            reverse = (key[2], key[3], key[0], key[1])
            responses = []
            if reverse in self.streams:
                handled.add(reverse)
                rdata, rstarts, rmarks = self.streams[reverse].assemble()
                responses = parse_messages(rdata, "response", [request["method"] for request in requests])
                for response in responses:
                    frame, ts = rmarks[max(bisect.bisect_right(rstarts, response["start"]) - 1, 0)]
                    response["frame"], response["ts"] = frame, ts
            responses = [response for response in responses if not 100 <= response["status"] < 200]
            for index, request in enumerate(requests):
                transactions.append(
                    {"client": key[0], "client_port": key[1], "server": key[2], "server_port": key[3],
                     "request": request, "response": responses[index] if index < len(responses) else None}
                )
        transactions.sort(key=lambda item: item["request"]["ts"])
        return transactions

    # Report ----------------------------------------------------------------

    def report(self) -> dict:
        transactions = self._messages()
        methods, statuses, families, hosts, agents, paths, servers = (Counter() for _ in range(7))
        rows = []
        groups: dict[tuple, dict] = defaultdict(lambda: {"frames": Frames(), "samples": [], "statuses": Counter(), "successes": [], "tools": Counter(), "accepted": []})
        tools: dict[tuple, dict] = defaultdict(lambda: {"frames": Frames(), "agent": ""})
        not_found: dict[tuple, dict] = defaultdict(lambda: {"frames": Frames(), "found": {}})
        logins: dict[tuple, list] = defaultdict(list)
        creds: dict[tuple, dict] = defaultdict(lambda: {"frames": Frames(), "items": []})
        downloads: dict[tuple, dict] = defaultdict(lambda: {"frames": Frames(), "files": []})
        uploads: dict[tuple, dict] = defaultdict(lambda: {"frames": Frames(), "files": []})
        errors: dict[tuple, Frames] = defaultdict(Frames)
        uploaded_scripts: dict[tuple, dict] = {}

        for item in transactions:
            request, response = item["request"], item["response"]
            client, server = item["client"], item["server"]
            headers = request["headers"]
            host = headers.get("host", server)
            agent = headers.get("user-agent", "")
            content_type = headers.get("content-type", "").lower()
            path = urlsplit(request["uri"]).path or request["uri"]
            status = response["status"] if response else None
            frame, ts = request["frame"], request["ts"]
            fields = form_fields(request["body"], content_type)
            login = credentials(headers, fields)
            safe_uri = mask_secrets(request["uri"])[:500]

            methods[request["method"]] += 1
            hosts[host] += 1
            agents[agent or "(absent)"] += 1
            paths[path] += 1
            if response:
                statuses[status] += 1
                families[f"{status // 100}xx"] += 1
                if response["headers"].get("server"):
                    servers[response["headers"]["server"]] += 1
            if len(rows) < MAX_TRANSACTIONS:
                rows.append({
                    "frame": frame, "response_frame": response["frame"] if response else None, "time": ts,
                    "client": client, "server": server, "server_port": item["server_port"], "method": request["method"],
                    "host": host, "uri": safe_uri, "user_agent": agent[:200], "status": status,
                    "reason": response["reason"] if response else None,
                    "content_type": response["headers"].get("content-type") if response else None,
                    "response_size": response["body_length"] if response else None,
                    "request_size": request["body_length"],
                    "body": masked_body(fields, request["body"], content_type) if request["body_length"] else None,
                    "credentials": login,
                })

            # Attack patterns ------------------------------------------------
            tool = scanner_for(agent)
            inspected = decode(request["uri"]) + "\n" + decode(request["body"].decode("utf-8", "replace"))
            header_text = "\n".join(headers.get(name, "") for name in ("user-agent", "referer", "cookie", "x-forwarded-for", "x-api-version"))
            for kind, (pattern, *_rest) in ATTACKS.items():
                target_text = inspected + "\n" + header_text if kind in ("log4shell", "shellshock", "sql_injection", "xss") else inspected
                if not pattern.search(target_text):
                    continue
                group = groups[(kind, client, server)]
                group["frames"].add(frame, ts)
                group["statuses"][status] += 1
                if tool:
                    group["tools"][tool] += 1
                if status is not None and 200 <= status < 300 and len(group["accepted"]) < MAX_SAMPLES:
                    group["accepted"].append({"frame": frame, "uri": safe_uri, "status": status, "tool": tool})
                if len(group["samples"]) < MAX_SAMPLES:
                    group["samples"].append({"frame": frame, "method": request["method"], "uri": safe_uri, "status": status})
                marker = SUCCESS_MARKERS.get(kind)
                if response and marker and marker.search(response["body"]) and len(group["successes"]) < MAX_SAMPLES:
                    group["successes"].append({"frame": response["frame"], "uri": safe_uri, "status": status})

            if tool:
                entry = tools[(client, tool)]
                entry["frames"].add(frame, ts)
                entry["agent"] = agent[:200]
                entry["signature"] = scanner_signature(agent)
                entry.setdefault("servers", set()).add(server)

            if status == 404:
                not_found[(client, server)]["frames"].add(frame, ts)
            elif status in DIRECTORY_FOUND_STATUSES and request["method"] in ("GET", "HEAD"):
                # "/./", "//" and "/%2e/" are the same resource as "/": keep one entry per real path.
                normalized = posixpath.normpath(decode(path).replace("\\", "/")) if path else "/"
                not_found[(client, server)]["found"].setdefault(normalized.replace("//", "/") or "/", status)
            if status is not None and status >= 500:
                errors[(client, server)].add(frame, ts)

            if request["method"] == "POST" or login:
                logins[(client, server, path)].append(
                    {"frame": frame, "ts": ts, "status": status, "size": response["body_length"] if response else None,
                     "user": login["user"] if login else None, "has_credentials": login is not None,
                     "response_frame": response["frame"] if response else None,
                     "location": response["headers"].get("location") if response else None}
                )
            if login:
                entry = creds[(client, server)]
                entry["frames"].add(frame, ts)
                if len(entry["items"]) < 20:
                    entry["items"].append({"frame": frame, "uri": safe_uri, "type": login["type"], "user": login["user"], "password": login["password"], "status": status})

            if response and self._is_executable(path, response):
                entry = downloads[(server, client)]
                entry["frames"].add(response["frame"], response["ts"])
                entry["files"].append({"frame": response["frame"], "uri": safe_uri, "content_type": response["headers"].get("content-type"), "size": response["body_length"], "magic": self._magic(response["body"])})
            if request["method"] in ("POST", "PUT"):
                if "multipart" in content_type:
                    sent = multipart_files(request["body"], content_type)
                elif request["method"] == "PUT" or self._magic(request["body"]):
                    sent = [{"filename": posixpath.basename(path), "content": request["body"]}]
                else:
                    sent = []
                for item_file in sent:
                    content = item_file["content"]
                    indicators = webshell_indicators(content)
                    script = item_file["filename"].lower().endswith(SERVER_SCRIPT_EXTENSIONS)
                    magic = self._magic(content)
                    if not (script or indicators or magic in ("PE (Windows)", "ELF (Linux)")):
                        continue
                    record = {
                        "frame": frame, "time": ts, "uri": safe_uri, "client": client, "filename": item_file["filename"],
                        "size": len(content), "sha256": hashlib.sha256(content).hexdigest(), "type": magic or ("Script serveur" if script else None),
                        "webshell_indicators": indicators, "status": status,
                    }
                    entry = uploads[(client, server)]
                    entry["frames"].add(frame, ts)
                    entry["files"].append(record)
                    if script or indicators:
                        uploaded_scripts.setdefault((server, item_file["filename"].lower()), record)

        findings = self._attack_findings(groups) + self._tool_findings(tools) + self._enumeration_findings(not_found)
        findings += self._brute_force_findings(logins) + self._credential_findings(creds)
        findings += self._transfer_findings(downloads, uploads) + self._error_findings(errors)
        findings += self._webshell_findings(transactions, uploaded_scripts)
        return {
            "stats": {
                "transactions": len(transactions),
                "requests_without_response": sum(1 for item in transactions if item["response"] is None),
                "methods": dict(methods.most_common()),
                "status_families": dict(sorted(families.items())),
                "statuses": {str(code): count for code, count in statuses.most_common()},
            },
            "tables": {
                "transactions": rows,
                "hosts": top(hosts, 20, "host"),
                "user_agents": top(agents, 20, "user_agent"),
                "paths": top(paths, 30, "path"),
                "servers": top(servers, 10, "server"),
            },
            "findings": findings,
        }

    # Findings ----------------------------------------------------------------

    @staticmethod
    def _attack_findings(groups) -> list[dict]:
        findings = []
        for (kind, client, server), group in groups.items():
            _pattern, severity, title, mitre, explanation, recommendation = ATTACKS[kind]
            successes = group["successes"]
            total = group["frames"].count
            accepted = sum(count for status, count in group["statuses"].items() if status and 200 <= status < 300)
            from_tools = sum(group["tools"].values())
            description = f"{client} a envoyé {total} requête(s) de type « {title} » à {server}"
            if from_tools:
                names = ", ".join(tool.split(" (")[0] for tool in group["tools"])
                description += f", dont {from_tools} générée(s) automatiquement par {names}"
            description += f" ; {accepted} ont reçu une réponse 2xx." if accepted else " ; aucune n'a reçu de réponse 2xx."
            if successes:
                severity = "critical"
                description += f" Indice de réussite : {SUCCESS_TEXT[kind]} (trame {successes[0]['frame']})."
            elif kind == "sensitive_file" and accepted:
                severity = "medium"
            elif from_tools == total:
                # Probes from a known scanner that nothing confirms: lower the priority, keep the trace.
                severity = SEVERITY_ORDER[max(SEVERITY_ORDER.index(severity) - 1, 1)]
                if accepted:
                    description += " Les réponses 2xx sont à vérifier : un scanner reçoit souvent la page d'accueil quelle que soit la charge envoyée."
            item = finding(
                    "http", kind, severity, title, description,
                    explanation=explanation, recommendation=recommendation, mitre=mitre,
                    source=client, target=server, frames=group["frames"],
                    wireshark_filter=f"http.request && {ip_filter('ip.src', client)} && {ip_filter('ip.dst', server)}",
                    evidence={
                        "samples": group["samples"], "statuses": {str(key): value for key, value in group["statuses"].items()},
                        "success_evidence": successes, "accepted_requests": group["accepted"], "from_tools": dict(group["tools"]),
                    },
                )
            if from_tools == total and not successes:
                # Automated probes are reconnaissance, whatever technique they imitate.
                item["phase"] = "reconnaissance"
            findings.append(item)
        return findings

    @staticmethod
    def _tool_findings(tools) -> list[dict]:
        return [
            finding(
                "http", "attack_tool", "medium",
                f"Outil d'attaque identifié : {tool}",
                f"{client} a envoyé {entry['frames'].count} requête(s) avec l'User-Agent de {tool} vers {', '.join(sorted(entry['servers']))}.",
                explanation=(
                    "Beaucoup d'outils offensifs annoncent leur nom dans l'en-tête User-Agent par défaut. Cette trace révèle directement "
                    "l'outil utilisé et donc l'intention de l'attaquant (scan de vulnérabilités, injection, force brute)."
                ),
                recommendation="Bloquer la source ; un attaquant prudent change cet en-tête, donc rechercher aussi les autres requêtes de la même adresse.",
                mitre=["T1595"], source=client, target=sorted(entry["servers"])[0], frames=entry["frames"],
                wireshark_filter=f"{ip_filter('ip.src', client)} && http.user_agent matches \"(?i){entry['signature']}\"",
                evidence={"user_agent": entry["agent"]},
            )
            for (client, tool), entry in tools.items()
        ]

    @staticmethod
    def _enumeration_findings(not_found) -> list[dict]:
        findings = []
        for (client, server), entry in not_found.items():
            if entry["frames"].count < DIR_ENUM_404:
                continue
            found = [{"path": path, "status": status} for path, status in list(entry["found"].items())[:50]]
            findings.append(
                finding(
                    "http", "directory_enumeration", "medium",
                    "Énumération de répertoires et fichiers web",
                    f"{client} a reçu {entry['frames'].count} réponses 404 de {server} ; {len(entry['found'])} chemins existants ont été trouvés.",
                    explanation=(
                        "Des outils comme Gobuster, DirBuster ou ffuf testent des milliers de noms de pages tirés d'un dictionnaire. "
                        "Chaque 404 est un essai raté ; les chemins qui répondent autrement (200, 301, 403) sont ce que l'attaquant a découvert."
                    ),
                    recommendation="Vérifier que les chemins découverts ne divulguent rien, limiter le débit par client et bloquer la source.",
                    mitre=["T1595.003"], source=client, target=server, frames=entry["frames"],
                    wireshark_filter=f"http.response.code==404 && {ip_filter('ip.dst', client)} && {ip_filter('ip.src', server)}",
                    evidence={"not_found": entry["frames"].count, "discovered_paths": found},
                )
            )
        return findings

    @staticmethod
    def _brute_force_findings(logins) -> list[dict]:
        findings = []
        for (client, server, path), attempts in logins.items():
            if len(attempts) < BRUTE_FORCE_MIN:
                continue
            statuses = Counter(attempt["status"] for attempt in attempts)
            majority, _ = statuses.most_common(1)[0]
            # Repeated POSTs to an API are normal; require a login page, credentials, or refusals.
            if not (LOGIN_PATH.search(path) or any(attempt["user"] for attempt in attempts) or majority in FAILURE_STATUSES or attempts[0]["has_credentials"]):
                continue
            sizes = [attempt["size"] for attempt in attempts if attempt["size"] is not None]
            median = statistics.median(sizes) if sizes else None
            if majority in FAILURE_STATUSES:
                successes = [attempt for attempt in attempts if attempt["status"] in SUCCESS_STATUSES]
            else:
                successes = [
                    attempt for attempt in attempts
                    if attempt["status"] is not None and (
                        attempt["status"] != majority
                        or (median and attempt["size"] is not None and abs(attempt["size"] - median) > 0.25 * median)
                    )
                ]
            successes = [attempt for attempt in successes if attempt["status"] is not None and attempt["status"] < 500]
            frames = Frames()
            for attempt in attempts:
                frames.add(attempt["frame"], attempt["ts"])
            users = Counter(attempt["user"] for attempt in attempts if attempt["user"])
            description = f"{client} a fait {len(attempts)} tentatives de connexion sur {server}{path} (réponses : {', '.join(f'{code} x{count}' for code, count in statuses.most_common())})."
            if successes:
                first = successes[0]
                description += (
                    f" Une tentative se distingue (trame {first['frame']}, statut {first['status']}"
                    f"{', utilisateur ' + first['user'] if first['user'] else ''}) : connexion probablement réussie."
                )
            findings.append(
                finding(
                    "http", "web_brute_force", "critical" if successes else "high",
                    "Force brute sur une page de connexion web",
                    description,
                    explanation=(
                        "Les mêmes identifiants sont essayés en boucle sur la même page, avec un mot de passe différent à chaque fois. "
                        "Les échecs donnent tous la même réponse ; une réponse différente (redirection 302, taille inhabituelle, 200 après des 401) "
                        "trahit en général le bon mot de passe."
                    ),
                    recommendation=(
                        "Changer immédiatement le mot de passe du compte visé si une réussite est signalée, vérifier les actions faites ensuite "
                        "avec cette session, et mettre en place verrouillage, captcha ou authentification multifacteur."
                    ),
                    mitre=["T1110"], source=client, target=server, frames=frames,
                    wireshark_filter=f"http.request.method==\"POST\" && {ip_filter('ip.src', client)} && http.request.uri contains \"{path[:60]}\"",
                    evidence={"path": path, "attempts": len(attempts), "statuses": {str(key): value for key, value in statuses.items()},
                              "usernames": [{"user": name, "count": count} for name, count in users.most_common(10)],
                              "probable_success": [{key: attempt[key] for key in ("frame", "response_frame", "status", "size", "user", "location")} for attempt in successes[:5]]},
                )
            )
        return findings

    @staticmethod
    def _credential_findings(creds) -> list[dict]:
        return [
            finding(
                "http", "cleartext_credentials", "medium",
                "Identifiants transmis en clair (HTTP non chiffré)",
                f"{entry['frames'].count} envoi(s) d'identifiants de {client} vers {server} sans chiffrement.",
                explanation=(
                    "Sans HTTPS, n'importe qui sur le chemin réseau lit les identifiants : l'en-tête Basic n'est qu'un encodage base64, "
                    "et les formulaires partent tels quels. Les mots de passe sont masqués dans ce rapport, mais ils sont lisibles dans la capture."
                ),
                recommendation="Passer le site en HTTPS, changer les mots de passe exposés et protéger le fichier de capture, qui les contient.",
                mitre=["T1552"], source=client, target=server, frames=entry["frames"],
                wireshark_filter=f"(http.authorization || http.file_data contains \"pass\") && {ip_filter('ip.src', client)}",
                evidence={"credentials": entry["items"]},
            )
            for (client, server), entry in creds.items()
        ]

    @staticmethod
    def _transfer_findings(downloads, uploads) -> list[dict]:
        findings = [
            finding(
                "http", "executable_download", "high",
                "Téléchargement d'un exécutable ou d'un script",
                f"{client} a téléchargé {len(entry['files'])} fichier(s) exécutable(s) depuis {server} : {', '.join(item['uri'] for item in entry['files'][:3])}.",
                explanation=(
                    "Après un premier accès, l'attaquant rapatrie ses outils (charge malveillante, outil de contrôle à distance, script) "
                    "sur la machine compromise. Un exécutable récupéré en HTTP est donc un indice fort de la phase d'installation."
                ),
                recommendation="Extraire le fichier (Wireshark : Fichier > Exporter objets > HTTP), calculer son empreinte et l'analyser ; examiner la machine qui l'a téléchargé.",
                mitre=["T1105"], source=server, target=client, frames=entry["frames"],
                wireshark_filter=f"http.response && {ip_filter('ip.src', server)} && {ip_filter('ip.dst', client)}",
                evidence={"files": entry["files"][:20]},
            )
            for (server, client), entry in downloads.items()
        ]
        for (client, server), entry in uploads.items():
            files = entry["files"]
            armed = [item for item in files if item["webshell_indicators"]]
            names = ", ".join(f"{item['filename']} ({item['size']} octets)" for item in files[:3])
            description = f"{client} a envoyé {len(files)} fichier(s) exécutable(s) à {server} : {names}."
            if armed:
                description += f" Le code de {armed[0]['filename']} contient : {', '.join(armed[0]['webshell_indicators'][:4])}."
            findings.append(
                finding(
                    "http", "malicious_upload", "critical" if armed else "high",
                    "Téléversement d'un webshell" if armed else "Téléversement d'un script serveur ou d'un exécutable",
                    description,
                    explanation=(
                        "Envoyer un fichier .php, .jsp ou .aspx sur un serveur web est la façon la plus courante de déposer un webshell : "
                        "il suffit ensuite d'appeler ce fichier pour exécuter des commandes. Les fonctions repérées dans le code "
                        "(eval, create_function, base64_decode, system...) servent à exécuter du code reçu à distance et à le cacher."
                    ),
                    recommendation=(
                        "Retrouver le fichier sur le serveur (son empreinte SHA-256 est dans les preuves), le mettre en quarantaine, "
                        "vérifier s'il a été appelé ensuite, et corriger le formulaire d'envoi (extensions autorisées, dossier non exécutable)."
                    ),
                    mitre=["T1505.003", "T1105"], source=client, target=server, frames=entry["frames"],
                    wireshark_filter=f"http.request.method==\"POST\" && {ip_filter('ip.src', client)} && {ip_filter('ip.dst', server)} && mime_multipart",
                    evidence={"files": [{key: value for key, value in item.items() if key != "client"} for item in files[:20]]},
                )
            )
        return findings

    @staticmethod
    def _error_findings(errors) -> list[dict]:
        return [
            finding(
                "http", "server_errors", "low",
                "Rafale d'erreurs serveur (5xx)",
                f"{server} a renvoyé {frames.count} erreurs 5xx à {client}.",
                explanation="Des erreurs internes répétées en réponse au même client accompagnent souvent des tentatives d'exploitation (données malformées, injections).",
                recommendation="Consulter les journaux applicatifs aux mêmes horaires pour comprendre ce qui a provoqué ces erreurs.",
                source=client, target=server, frames=frames,
                wireshark_filter=f"http.response.code>=500 && {ip_filter('ip.dst', client)}",
            )
            for (client, server), frames in errors.items()
            if frames.count >= SERVER_ERROR_MIN
        ]

    @staticmethod
    def _webshell_findings(transactions, uploaded_scripts) -> list[dict]:
        """Calls to an uploaded script, and obfuscated command channels to a single script (Weevely style)."""
        calls: dict[tuple, list[dict]] = defaultdict(list)
        for item in transactions:
            request = item["request"]
            path = urlsplit(request["uri"]).path
            calls[(item["client"], item["server"], path)].append(item)

        findings = []
        for (client, server, path), items in calls.items():
            upload = uploaded_scripts.get((server, posixpath.basename(path).lower()))
            if upload:
                items = [item for item in items if item["request"]["frame"] > upload["frame"]]
            posts = [item for item in items if item["request"]["method"] == "POST" and item["request"]["body_length"]]
            bodies = [item["request"]["body"] for item in posts]
            entropy = sum(shannon_entropy(body.decode("latin-1")) for body in bodies) / len(bodies) if bodies else 0.0
            agents = {item["request"]["headers"].get("user-agent", "") for item in items}
            obfuscated = len(posts) >= OBFUSCATED_MIN_CALLS and entropy >= OBFUSCATED_ENTROPY
            if not ((upload and len(items) >= WEBSHELL_MIN_CALLS) or (obfuscated and len(agents) >= ROTATING_AGENTS)):
                continue
            responses = [item["response"] for item in items if item["response"]]
            markers = common_markers(bodies + [response["body"] for response in responses]) if obfuscated else []
            weevely = obfuscated and len(agents) >= ROTATING_AGENTS and bool(markers)
            frames = Frames()
            for item in items:
                frames.add(item["request"]["frame"], item["request"]["ts"])
            parts = [f"{client} a appelé {path} sur {server} {len(items)} fois ({len(posts)} POST)"]
            if upload:
                parts.append(f"ce script a été déposé à la trame {upload['frame']} ({upload['filename']}, SHA-256 {upload['sha256'][:16]}...)")
            if obfuscated:
                parts.append(f"les commandes sont obfusquées (entropie moyenne {entropy:.1f} bits/caractère)")
            if len(agents) >= ROTATING_AGENTS:
                parts.append(f"le User-Agent change presque à chaque requête ({len(agents)} valeurs différentes)")
            if weevely:
                parts.append(f"marqueurs fixes {', '.join(markers[:2])} présents dans les requêtes et les réponses : signature de Weevely")
            findings.append(
                finding(
                    "http", "webshell_activity", "critical",
                    "Webshell déployé et utilisé" if upload else "Canal de commande obfusqué vers un script (webshell probable)",
                    " ; ".join(parts) + ".",
                    explanation=(
                        "Chaque requête vers ce script transporte une commande de l'attaquant, chiffrée pour que ni un pare-feu ni un analyste "
                        "ne la lise ; la réponse contient le résultat, chiffré de la même façon. Weevely, par exemple, encadre chaque échange "
                        "entre deux marqueurs dérivés de son mot de passe et tire un User-Agent au hasard pour brouiller les journaux. "
                        "À ce stade, l'attaquant contrôle le serveur avec les droits du service web."
                    ),
                    recommendation=(
                        "Isoler le serveur, supprimer le script et rechercher d'autres fichiers déposés, examiner les processus et les "
                        "connexions sortantes, puis changer tous les secrets accessibles au service web (base de données, clés, comptes)."
                    ),
                    mitre=["T1505.003", "T1059", "T1071"], source=client, target=server, frames=frames,
                    wireshark_filter=f"http.request.uri contains \"{path[:80]}\" && {ip_filter('ip.dst', server)}",
                    evidence={
                        "path": path, "calls": len(items), "post_calls": len(posts), "average_body_entropy": round(entropy, 2),
                        "distinct_user_agents": len(agents), "markers": markers, "weevely_signature": weevely,
                        "uploaded": {key: upload[key] for key in ("frame", "filename", "size", "sha256", "webshell_indicators")} if upload else None,
                        "response_sizes": dict(Counter(response["body_length"] for response in responses).most_common(5)),
                        "first_frame": frames.numbers[0] if frames.numbers else None,
                    },
                )
            )
        return findings

    # Helpers -----------------------------------------------------------------

    @staticmethod
    def _magic(body: bytes) -> str | None:
        if body[:2] == b"MZ":
            return "PE (Windows)"
        if body[:4] == b"\x7fELF":
            return "ELF (Linux)"
        if body[:2] == b"#!":
            return "Script"
        if body[:4] == b"PK\x03\x04":
            return "Archive ZIP/JAR"
        return None

    @classmethod
    def _is_executable(cls, path: str, response: dict) -> bool:
        if response["status"] != 200:
            return False
        content_type = response["headers"].get("content-type", "").lower()
        if any(kind in content_type for kind in EXECUTABLE_TYPES):
            return True
        magic = cls._magic(response["body"])
        if magic in ("PE (Windows)", "ELF (Linux)"):
            return True
        return path.lower().endswith(EXECUTABLE_EXTENSIONS) and "text/html" not in content_type and response["body_length"] > 0
