// "Analyse forensique" view. Everything shown here comes from a capture that may be hostile,
// so the DOM is built with textContent only (never innerHTML).
(function () {
    "use strict";

    const SEVERITY = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible", info: "Info", none: "Aucune" };
    const STATUS = { queued: "En attente", running: "Analyse en cours", done: "Terminée", error: "Échec" };
    const TABS = [
        ["summary", "Synthèse"], ["findings", "Constats"], ["timeline", "Chronologie"],
        ["icmp", "ICMP"], ["tcp", "TCP"], ["http", "HTTP"], ["dns", "DNS"], ["arp", "ARP"],
    ];
    const state = { jobs: [], current: null, report: null, tab: "summary", poll: null };

    // DOM helpers -----------------------------------------------------------

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function section(title, ...children) {
        const wrapper = el("section");
        wrapper.append(el("h3", null, title), ...children.filter(Boolean));
        return wrapper;
    }

    function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString("fr-FR") : "-"; }
    function fmtClock(ts) { return ts ? new Date(ts * 1000).toLocaleTimeString("fr-FR") : "-"; }
    function fmtNumber(value) { return value === null || value === undefined ? "-" : Number(value).toLocaleString("fr-FR"); }
    function fmtDuration(seconds) {
        if (!seconds) return "0 s";
        if (seconds < 60) return `${seconds.toFixed(1)} s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
        return `${Math.floor(seconds / 3600)} h ${Math.round((seconds % 3600) / 60)} min`;
    }

    function badge(severity) {
        const level = severity || "info";
        return el("span", `severity ${level}`, SEVERITY[level] || level);
    }

    function table(columns, rows, emptyText) {
        const wrapper = el("div", "table-scroll");
        const tableNode = el("table");
        const head = el("thead");
        const headRow = el("tr");
        columns.forEach(([label]) => headRow.append(el("th", null, label)));
        head.append(headRow);
        const body = el("tbody");
        if (!rows.length) {
            const row = el("tr");
            const cell = el("td", "fx-note", emptyText || "Rien à afficher.");
            cell.colSpan = columns.length;
            row.append(cell);
            body.append(row);
        }
        rows.forEach((item) => {
            const row = el("tr");
            columns.forEach(([, render]) => {
                const cell = el("td");
                const value = render(item);
                if (value instanceof Node) cell.append(value); else cell.textContent = value === null || value === undefined || value === "" ? "-" : String(value);
                row.append(cell);
            });
            body.append(row);
        });
        tableNode.append(head, body);
        wrapper.append(tableNode);
        return wrapper;
    }

    function code(text) { return el("code", null, text); }

    function cards(items) {
        const grid = el("div", "fx-cards");
        items.forEach(([label, value]) => {
            const card = el("div", "fx-card");
            card.append(el("span", null, label), el("strong", null, value));
            grid.append(card);
        });
        return grid;
    }

    function keyValues(object) {
        return table([["Valeur", (pair) => pair[0]], ["Nombre", (pair) => fmtNumber(pair[1])]], Object.entries(object || {}));
    }

    async function copy(text, button) {
        try {
            await navigator.clipboard.writeText(text);
        } catch (error) {
            const area = el("textarea");
            area.value = text;
            document.body.append(area);
            area.select();
            document.execCommand("copy");
            area.remove();
        }
        const label = button.textContent;
        button.textContent = "Copié";
        setTimeout(() => { button.textContent = label; }, 1200);
    }

    function filterLine(filter) {
        const line = el("div", "fx-filter");
        const button = el("button", "button", "Copier");
        button.type = "button";
        button.addEventListener("click", () => copy(filter, button));
        line.append(code(filter), button);
        return line;
    }

    // Jobs list and upload --------------------------------------------------

    function setStatus(message, error = false, percent = null) {
        const status = document.getElementById("fx-upload-status");
        status.replaceChildren(el("div", null, message));
        status.classList.toggle("error", error);
        if (percent !== null) {
            const bar = el("div", "fx-progress");
            const fill = el("span");
            fill.style.width = `${percent}%`;
            bar.append(fill);
            status.append(bar);
        }
    }

    function upload(file) {
        if (!file) return;
        const form = new FormData();
        form.append("capture", file, file.name);
        const request = new XMLHttpRequest();
        request.open("POST", "/api/forensics");
        request.setRequestHeader("X-VEAS-Upload", "1");
        request.upload.addEventListener("progress", (event) => {
            if (event.lengthComputable) setStatus(`Envoi de ${file.name}...`, false, Math.round((event.loaded / event.total) * 100));
        });
        request.addEventListener("load", () => {
            let body = {};
            try { body = JSON.parse(request.responseText); } catch (error) { body = {}; }
            if (request.status === 202) {
                setStatus(`${file.name} envoyé : analyse en cours.`);
                state.current = body.id;
                refreshJobs();
            } else {
                setStatus(body.error || body.description || `Échec de l'envoi (HTTP ${request.status}).`, true);
            }
        });
        request.addEventListener("error", () => setStatus("Échec de l'envoi : serveur injoignable.", true));
        setStatus(`Envoi de ${file.name}...`, false, 0);
        request.send(form);
    }

    function threatCell(job) {
        if (!job.summary) return "-";
        const wrapper = el("span");
        wrapper.append(badge(job.summary.threat_level === "none" ? "info" : job.summary.threat_level), document.createTextNode(` ${job.summary.findings_total} constat(s)`));
        return wrapper;
    }

    function statusCell(job) {
        if (job.status === "running") {
            const wrapper = el("div");
            wrapper.append(el("span", null, `${STATUS.running} (${fmtNumber(job.frames)} trames)`));
            const bar = el("div", "fx-progress");
            const fill = el("span");
            fill.style.width = `${job.progress || 3}%`;
            bar.append(fill);
            wrapper.append(bar);
            return wrapper;
        }
        if (job.status === "error") {
            const node = el("span", "fx-status error", `${STATUS.error} : ${job.error || ""}`);
            return node;
        }
        return STATUS[job.status] || job.status;
    }

    function actionButton(label, handler, title) {
        const button = el("button", "button", label);
        button.type = "button";
        if (title) button.title = title;
        button.addEventListener("click", handler);
        return button;
    }

    function actionLink(label, href) {
        const link = el("a", "button", label);
        link.href = href;
        link.setAttribute("download", "");
        return link;
    }

    function actionsCell(job) {
        const actions = el("div", "fx-actions");
        if (job.status === "done") {
            actions.append(actionButton("Ouvrir", () => openReport(job.id)));
            actions.append(actionLink("JSON", `/api/forensics/${job.id}/export`));
        }
        actions.append(actionLink("pcap", `/api/forensics/${job.id}/pcap`));
        if (job.status !== "running") {
            actions.append(actionButton("Supprimer", async () => {
                if (!window.confirm(`Supprimer l'analyse de ${job.filename} et la capture associée ?`)) return;
                await fetch(`/api/forensics/${job.id}`, { method: "DELETE" });
                if (state.current === job.id) closeReport();
                refreshJobs();
            }));
        }
        return actions;
    }

    function renderJobs() {
        const body = document.getElementById("fx-jobs");
        body.replaceChildren();
        if (!state.jobs.length) {
            const row = el("tr");
            const cell = el("td");
            cell.colSpan = 6;
            cell.append(emptyNode("Aucune analyse. Déposez une capture pour commencer.", "file-search"));
            row.append(cell);
            body.append(row);
        }
        state.jobs.forEach((job) => {
            const row = el("tr");
            const name = el("td", "device-name");
            name.append(el("div", null, job.filename), el("small", "muted-line", `${job.format} - ${formatBytes(job.size || 0)}`));
            const cells = [fmtTime(job.created_at), job.summary ? fmtNumber(job.summary.packets) : "-", threatCell(job), statusCell(job), actionsCell(job)];
            row.append(name);
            cells.forEach((value) => {
                const cell = el("td");
                if (value instanceof Node) cell.append(value); else cell.textContent = value;
                row.append(cell);
            });
            body.append(row);
        });
        document.getElementById("fx-jobs-count").textContent = `${state.jobs.length} analyse${state.jobs.length > 1 ? "s" : ""}`;
        updateIcons();
    }

    async function refreshJobs() {
        try {
            state.jobs = await fetchJson("/api/forensics");
        } catch (error) {
            console.error("Erreur analyses:", error);
            return;
        }
        renderJobs();
        const busy = state.jobs.some((job) => job.status === "queued" || job.status === "running");
        const watched = state.jobs.find((job) => job.id === state.current);
        if (watched && watched.status === "done" && (!state.report || state.report.id !== watched.id)) {
            setStatus(`Analyse de ${watched.filename} terminée.`);
            openReport(watched.id);
        } else if (watched && watched.status === "error") {
            setStatus(`Analyse de ${watched.filename} impossible : ${watched.error}`, true);
        }
        clearTimeout(state.poll);
        const visible = document.querySelector('[data-view="forensics"]').classList.contains("active");
        if (busy && visible) state.poll = setTimeout(refreshJobs, 1500);
    }

    // Report ----------------------------------------------------------------

    function closeReport() {
        state.report = null;
        state.current = null;
        document.getElementById("fx-report").hidden = true;
    }

    async function openReport(id) {
        let data;
        try {
            data = await fetchJson(`/api/forensics/${id}`);
        } catch (error) {
            setStatus("Impossible de charger le rapport.", true);
            return;
        }
        if (!data.report) return;
        state.current = id;
        state.report = { id, job: data.job, ...data.report };
        state.tab = "summary";
        renderReport();
        document.getElementById("fx-report").scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function renderReport() {
        const report = state.report;
        const container = document.getElementById("fx-report");
        container.hidden = false;
        const head = document.getElementById("fx-report-head");
        head.replaceChildren();
        const title = el("div", "fx-report-title");
        title.append(el("h2", null, report.file.name), badge(report.summary.threat_level === "none" ? "info" : report.summary.threat_level));
        const overview = report.overview;
        head.append(
            title,
            el("div", "fx-meta", `${report.file.format} - ${report.file.link_type || "lien inconnu"} - ${formatBytes(report.file.size)} - SHA-256 ${report.file.sha256}`),
            el("div", "fx-meta", `Du ${fmtTime(overview.start)} au ${fmtTime(overview.end)} (${fmtDuration(overview.duration)}) - analysé en ${report.analysis_seconds} s`),
        );
        report.warnings.forEach((warning) => head.append(el("div", "fx-status error", warning)));

        const tabs = document.getElementById("fx-tabs");
        tabs.replaceChildren();
        TABS.forEach(([id, label]) => {
            const button = el("button", `fx-tab${state.tab === id ? " active" : ""}`, label);
            button.type = "button";
            button.setAttribute("role", "tab");
            button.setAttribute("aria-selected", String(state.tab === id));
            const count = tabCount(id);
            if (count !== null) button.append(el("span", "fx-count", count));
            button.addEventListener("click", () => { state.tab = id; renderReport(); });
            tabs.append(button);
        });

        const body = document.getElementById("fx-tab-body");
        body.replaceChildren(...(RENDERERS[state.tab] || renderSummary)(report));
        updateIcons();
    }

    function tabCount(id) {
        const report = state.report;
        if (id === "findings") return report.findings.length;
        if (id === "timeline") return report.timeline.filter((event) => event.kind === "finding").length;
        if (["icmp", "tcp", "http", "dns", "arp"].includes(id)) {
            const count = report.findings.filter((item) => item.category === id).length;
            return count || null;
        }
        return null;
    }

    function histogram(data) {
        const counts = data.counts || [];
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("class", "fx-hist");
        svg.setAttribute("viewBox", `0 0 ${Math.max(counts.length, 1) * 10} 90`);
        svg.setAttribute("preserveAspectRatio", "none");
        const max = Math.max(...counts, 1);
        counts.forEach((value, index) => {
            const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            const height = Math.max((value / max) * 86, value ? 2 : 0);
            rect.setAttribute("x", index * 10 + 1);
            rect.setAttribute("y", 90 - height);
            rect.setAttribute("width", 8);
            rect.setAttribute("height", height);
            const tip = document.createElementNS("http://www.w3.org/2000/svg", "title");
            tip.textContent = `${value} paquets`;
            rect.append(tip);
            svg.append(rect);
        });
        return svg;
    }

    function renderSummary(report) {
        const summary = report.summary;
        const overview = report.overview;
        const threat = el("div", `fx-threat ${summary.threat_level}`);
        threat.append(el("strong", null, `Niveau de menace : ${SEVERITY[summary.threat_level] || summary.threat_label}`));
        const counts = Object.entries(summary.findings_by_severity).filter(([, count]) => count).map(([level, count]) => `${SEVERITY[level]} ${count}`).join(", ");
        threat.append(el("p", null, summary.findings_total ? `${summary.findings_total} constat(s) : ${counts}.` : "Aucun comportement suspect détecté dans cette capture."));
        if (summary.mitre_tactics.length) threat.append(el("p", null, `Phases observées : ${summary.mitre_tactics.map((tactic) => tactic.label).join(" → ")}`));

        const blocks = [
            threat,
            cards([
                ["Paquets", fmtNumber(overview.packets)], ["Volume", formatBytes(overview.bytes)], ["Durée", fmtDuration(overview.duration)],
                ["Machines", fmtNumber(overview.endpoints_total)], ["Transactions HTTP", fmtNumber(report.protocols.http.stats.transactions)],
                ["Connexions TCP", fmtNumber(report.protocols.tcp.stats.connections)],
            ]),
        ];

        if (report.narrative.length) {
            const stories = el("div");
            stories.style.display = "grid";
            stories.style.gap = "12px";
            report.narrative.forEach((story) => {
                const box = el("div", "fx-story");
                box.append(el("p", null, story.summary));
                const list = el("ol", "fx-steps");
                story.steps.forEach((step) => {
                    const item = el("li", step.severity);
                    item.append(el("time", null, fmtClock(step.time)), el("span", "fx-phase", step.phase), el("strong", null, step.title));
                    if (step.frame) item.append(el("span", "fx-note", ` (trame ${step.frame})`));
                    item.append(el("div", "fx-note", step.description));
                    list.append(item);
                });
                box.append(list);
                stories.append(box);
            });
            blocks.push(section("Récit de l'attaque", stories));
        }

        if (report.actors.length) {
            blocks.push(section("Acteurs", table([
                ["Adresse", (actor) => code(actor.address)], ["Rôle", (actor) => actor.role], ["Gravité max.", (actor) => badge(actor.max_severity)],
                ["Constats (source / cible)", (actor) => `${actor.as_source} / ${actor.as_target}`], ["Système probable", (actor) => actor.os_guess],
                ["Réseau", (actor) => (actor.private ? "Privé" : "Public")], ["Paquets", (actor) => fmtNumber(actor.packets)],
            ], report.actors)));
        }

        if (summary.mitre_techniques.length) {
            blocks.push(section("Techniques MITRE ATT&CK", table([
                ["Technique", (technique) => {
                    const link = el("a", "mitre-tag technique", technique.id);
                    link.href = technique.url; link.target = "_blank"; link.rel = "noopener noreferrer";
                    return link;
                }],
                ["Nom", (technique) => technique.name], ["Tactiques", (technique) => technique.tactics.join(", ")], ["Constats", (technique) => technique.findings],
            ], summary.mitre_techniques)));
        }

        const traffic = el("div", "fx-grid2");
        traffic.append(
            section("Activité dans le temps", histogram(overview.histogram), el("div", "fx-note", `Une barre = ${fmtDuration(overview.histogram.bucket_seconds)}`)),
            section("Protocoles", keyValues(overview.protocols)),
        );
        blocks.push(traffic);
        const hosts = el("div", "fx-grid2");
        hosts.append(
            section("Machines les plus actives", table([
                ["Adresse", (endpoint) => code(endpoint.ip)], ["Envoyés", (endpoint) => fmtNumber(endpoint.packets_sent)],
                ["Reçus", (endpoint) => fmtNumber(endpoint.packets_received)], ["Volume", (endpoint) => formatBytes(endpoint.bytes_sent + endpoint.bytes_received)],
                ["Système probable", (endpoint) => endpoint.os_guess],
            ], overview.endpoints.slice(0, 12))),
            section("Conversations principales", table([
                ["Entre", (conversation) => `${conversation.a} ↔ ${conversation.b}`], ["Proto.", (conversation) => conversation.protocol],
                ["Paquets", (conversation) => fmtNumber(conversation.packets)], ["Volume", (conversation) => formatBytes(conversation.bytes)],
                ["Durée", (conversation) => fmtDuration(conversation.duration)],
            ], overview.conversations.slice(0, 12))),
        );
        blocks.push(hosts);
        return blocks;
    }

    function findingCard(item) {
        const card = el("article", `fx-finding ${item.severity}`);
        const head = el("div", "alert-head");
        head.append(el("strong", null, item.title), badge(item.severity));
        card.append(head, el("p", null, item.description));
        if (item.mitre.length) {
            const tags = el("div", "mitre-line");
            item.mitre.forEach((technique) => {
                const link = el("a", "mitre-tag technique", technique.id);
                link.href = technique.url; link.target = "_blank"; link.rel = "noopener noreferrer";
                link.title = `${technique.name} (${technique.tactics.join(", ")})`;
                tags.append(link);
            });
            card.append(tags);
        }
        card.append(el("span", "fx-label", "Explication"), el("p", null, item.explanation));
        card.append(el("span", "fx-label", "Que faire"), el("p", null, item.recommendation));
        if (item.frames.length) {
            card.append(el("span", "fx-label", `Trames (${fmtNumber(item.count)} au total, de ${fmtClock(item.first_seen)} à ${fmtClock(item.last_seen)})`));
            card.append(el("div", "fx-frames", item.frames.join(", ") + (item.count > item.frames.length ? " ..." : "")));
        }
        if (item.wireshark_filter) card.append(el("span", "fx-label", "Filtre Wireshark"), filterLine(item.wireshark_filter));
        if (item.evidence && Object.keys(item.evidence).length) {
            const details = el("details", "fx-details");
            details.append(el("summary", null, "Voir les preuves détaillées"), el("pre", null, JSON.stringify(item.evidence, null, 2)));
            card.append(details);
        }
        return card;
    }

    function renderFindings(report, category) {
        const items = category ? report.findings.filter((item) => item.category === category) : report.findings;
        if (!items.length) return [el("p", "fx-note", category ? "Aucun constat pour ce protocole." : "Aucun constat.")];
        const list = el("div");
        list.style.display = "grid";
        list.style.gap = "12px";
        items.forEach((item) => list.append(findingCard(item)));
        return [list];
    }

    function renderTimeline(report) {
        const list = el("ol", "fx-steps");
        report.timeline.forEach((event) => {
            const item = el("li", event.severity);
            item.append(el("time", null, fmtTime(event.time)));
            if (event.phase) item.append(el("span", "fx-phase", event.phase));
            item.append(el("strong", null, event.title));
            if (event.frame) item.append(el("span", "fx-note", ` (trame ${event.frame})`));
            if (event.description) item.append(el("div", "fx-note", event.description));
            list.append(item);
        });
        return [list];
    }

    function protocolStats(stats, labels) {
        return cards(labels.filter(([key]) => stats[key] !== undefined && typeof stats[key] !== "object").map(([key, label]) => [label, fmtNumber(stats[key])]));
    }

    function renderIcmp(report) {
        const data = report.protocols.icmp;
        const rtt = data.stats.rtt;
        const blocks = [protocolStats(data.stats, [
            ["messages", "Messages ICMP"], ["echo_requests", "Pings envoyés"], ["echo_answered", "Pings répondus"],
            ["echo_unanswered", "Sans réponse"], ["orphan_replies", "Réponses orphelines"], ["filtered_by_admin", "Filtrés (admin.)"],
        ])];
        if (rtt) blocks.push(el("p", "fx-note", `Temps de réponse : min ${rtt.min_ms.toFixed(2)} ms, moyen ${rtt.avg_ms.toFixed(2)} ms, max ${rtt.max_ms.toFixed(2)} ms.`));
        const grid = el("div", "fx-grid2");
        grid.append(
            section("Types de messages", table([["Type", (row) => row.type], ["Nombre", (row) => fmtNumber(row.count)], ["1re trame", (row) => row.first_frame]], data.tables.types, "Aucun message ICMP.")),
            section("Sources de pings", table([["Source", (row) => code(row.source)], ["Cibles", (row) => row.targets], ["Requêtes", (row) => fmtNumber(row.requests)]], data.tables.ping_sources, "Aucun ping.")),
        );
        return [...blocks, grid, section("Constats ICMP", ...renderFindings(report, "icmp"))];
    }

    function renderTcp(report) {
        const data = report.protocols.tcp;
        const grid = el("div", "fx-grid2");
        grid.append(
            section("États des connexions", keyValues(data.stats.states)),
            section("Drapeaux", table([["Drapeaux", (row) => row.flags], ["Segments", (row) => fmtNumber(row.count)]], data.tables.flags)),
        );
        return [
            protocolStats(data.stats, [["segments", "Segments"], ["connections", "Connexions"], ["retransmissions", "Retransmissions"]]),
            grid,
            section("Ports serveurs les plus sollicités", table([["Port", (row) => row.port], ["Service", (row) => row.service], ["Connexions", (row) => fmtNumber(row.connections)]], data.tables.server_ports, "Aucun port.")),
            section("Constats TCP", ...renderFindings(report, "tcp")),
            section("Connexions (les plus volumineuses)", table([
                ["Client", (row) => code(`${row.client}:${row.client_port}`)], ["Serveur", (row) => code(`${row.server}:${row.server_port}`)],
                ["Service", (row) => row.service], ["État", (row) => row.state], ["Envoyé", (row) => formatBytes(row.bytes_sent)],
                ["Reçu", (row) => formatBytes(row.bytes_received)], ["Durée", (row) => fmtDuration(row.duration)], ["1re trame", (row) => row.first_frame],
            ], data.tables.connections.slice(0, 200), "Aucune connexion.")),
        ];
    }

    function renderHttp(report) {
        const data = report.protocols.http;
        const grid = el("div", "fx-grid2");
        grid.append(
            section("Méthodes", keyValues(data.stats.methods)),
            section("Codes de réponse", keyValues(data.stats.statuses)),
            section("User-Agents", table([["User-Agent", (row) => row.user_agent], ["Requêtes", (row) => fmtNumber(row.count)]], data.tables.user_agents)),
            section("Chemins les plus demandés", table([["Chemin", (row) => code(row.path)], ["Requêtes", (row) => fmtNumber(row.count)]], data.tables.paths)),
        );
        const families = Object.entries(data.stats.status_families).map(([family, count]) => [`Réponses ${family}`, fmtNumber(count)]);
        const filter = el("input", "field-control");
        filter.type = "search";
        filter.placeholder = "Filtrer les transactions (URI, IP, code, User-Agent)";
        filter.style.width = "100%";
        const holder = el("div");
        const columns = [
            ["Trame", (row) => row.frame], ["Heure", (row) => fmtClock(row.time)], ["Client", (row) => code(row.client)],
            ["Méthode", (row) => row.method], ["URI", (row) => code(row.uri)], ["Code", (row) => row.status],
            ["Taille rép.", (row) => (row.response_size === null ? "-" : formatBytes(row.response_size))],
            ["Identifiants", (row) => (row.credentials ? `${row.credentials.type} : ${row.credentials.user || "?"} / ${row.credentials.password}` : "")],
            ["User-Agent", (row) => (row.user_agent || "").slice(0, 60)],
        ];
        const draw = () => {
            const query = filter.value.trim().toLowerCase();
            const rows = data.tables.transactions.filter((row) => !query || [row.uri, row.client, row.server, String(row.status), row.user_agent, row.method].join(" ").toLowerCase().includes(query));
            holder.replaceChildren(table(columns, rows.slice(0, 500), "Aucune transaction."), el("p", "fx-note", `${rows.length} transaction(s) affichée(s) sur ${data.stats.transactions}${rows.length > 500 ? " (500 premières visibles)" : ""}.`));
        };
        filter.addEventListener("input", draw);
        draw();
        return [
            cards([["Transactions", fmtNumber(data.stats.transactions)], ["Sans réponse", fmtNumber(data.stats.requests_without_response)], ...families]),
            section("Constats HTTP", ...renderFindings(report, "http")),
            grid,
            section("Transactions", filter, holder),
        ];
    }

    function renderDns(report) {
        const data = report.protocols.dns;
        const grid = el("div", "fx-grid2");
        grid.append(
            section("Types de requêtes", keyValues(data.stats.types)),
            section("Codes de réponse", keyValues(data.stats.response_codes)),
            section("Noms les plus demandés", table([["Nom", (row) => code(row.name)], ["Requêtes", (row) => fmtNumber(row.count)]], data.tables.top_names, "Aucune requête DNS.")),
            section("Échecs (NXDOMAIN) par client", table([["Client", (row) => code(row.client)], ["Échecs", (row) => fmtNumber(row.count)], ["Noms distincts", (row) => row.distinct_names]], data.tables.nxdomain_by_client, "Aucun échec.")),
        );
        return [protocolStats(data.stats, [["queries", "Requêtes"], ["responses", "Réponses"]]), section("Constats DNS", ...renderFindings(report, "dns")), grid];
    }

    function renderArp(report) {
        const data = report.protocols.arp;
        return [
            protocolStats(data.stats, [["packets", "Paquets ARP"], ["requests", "Requêtes"], ["replies", "Réponses"], ["gratuitous", "ARP gratuits"]]),
            section("Constats ARP", ...renderFindings(report, "arp")),
            section("Correspondances IP ↔ MAC", table([
                ["IP", (row) => code(row.ip)],
                ["Cartes réseau", (row) => row.macs.map((mac) => `${mac.mac} (${mac.packets} paquets, trame ${mac.first_frame})`).join(" ; ")],
            ], data.tables.ip_mac, "Aucun paquet ARP.")),
        ];
    }

    const RENDERERS = {
        summary: renderSummary,
        findings: (report) => renderFindings(report),
        timeline: renderTimeline,
        icmp: renderIcmp,
        tcp: renderTcp,
        http: renderHttp,
        dns: renderDns,
        arp: renderArp,
    };

    // Wiring ------------------------------------------------------------------

    function init() {
        const drop = document.getElementById("fx-drop");
        const input = document.getElementById("fx-file");
        if (!drop || !input) return;
        input.addEventListener("change", () => { upload(input.files[0]); input.value = ""; });
        ["dragenter", "dragover"].forEach((name) => drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.add("dragging"); }));
        ["dragleave", "drop"].forEach((name) => drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.remove("dragging"); }));
        drop.addEventListener("drop", (event) => upload(event.dataTransfer.files[0]));
        drop.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") input.click(); });
        drop.tabIndex = 0;
        if (document.querySelector('[data-view="forensics"]').classList.contains("active")) refreshJobs();
    }

    window.refreshForensics = refreshJobs;
    init();
})();
