
/*
 * INPA — Intelligent Network Packet Analyzer
 * Tableau de bord connecté aux données réelles du backend.
 * Les commentaires sont en français.
 */

document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    const $ = (id) => document.getElementById(id);

    const elements = {
        packets: $("stat-packets"),
        bytes: $("stat-bytes"),
        connections: $("stat-connections"),
        alerts: $("stat-alerts"),
        sidebarAlerts: $("sidebar-alert-count"),
        alertHeaderCount: $("alert-header-count"),
        chart: $("traffic-chart"),
        protocols: $("protocol-list"),
        packetTable: $("packet-table"),
        alertsList: $("alerts-list"),
        fact: $("analysis-fact"),
        interpretation: $("analysis-interpretation"),
        hypothesis: $("analysis-hypothesis"),
        interfaceName: $("interface-name"),
        captureState: $("capture-state"),
        sessionTime: $("session-time"),
        captureButton: $("capture-button"),
        captureText: $("capture-text"),
        captureIcon: $("capture-icon"),
        refreshButton: $("refresh-button"),
        historyList: $("history-list"),
        historyMessage: $("history-message"),
        historyRefreshButton: $("history-refresh-button"),
        historyAccessButton: $("history-access-button"),
        agentConfigButton: $("agent-config-button"),
        authOverlay: $("account-auth-overlay"),
        authForm: $("account-auth-form"),
        authKey: $("account-auth-api-key"),

        authError: $("account-auth-error"),
        authSubmit: $("account-auth-submit"),

        authCancel: $("account-auth-cancel"),
        exportCurrentJson: $("export-current-json"),
        exportCurrentCsv: $("export-current-csv")
    };

    let agentData = {};
    let analysisData = {};
    let lastInterfaceName = "";
    let isLoading = false;
    const sessionStart = Date.now();
    const accessTokenKey = "inpa-access-token";
    const sessionTokenKey = "inpa-session-token";
    let loginPromise = null;
    let resolveLogin = null;

    // Affiche une valeur sans provoquer d'erreur si l'élément n'existe pas.
    function setText(element, value) {
        if (element) {
            element.textContent = value == null ? "" : String(value);
        }
    }

    // Formate les nombres en français.
    function formatNumber(value) {
        const number = Number(value);
        return Number.isFinite(number)
            ? number.toLocaleString("fr-FR")
            : "0";
    }

    // Convertit les octets en une unité lisible.
    function formatBytes(value) {
        const bytes = Math.max(0, Number(value) || 0);

        if (bytes < 1024) {
            return `${formatNumber(bytes)} B`;
        }

        if (bytes < 1024 * 1024) {
            return `${(bytes / 1024).toLocaleString("fr-FR", {
                maximumFractionDigits: 1
            })} KB`;
        }

        if (bytes < 1024 * 1024 * 1024) {
            return `${(bytes / (1024 * 1024)).toLocaleString("fr-FR", {
                maximumFractionDigits: 2
            })} MB`;
        }

        return `${(bytes / (1024 * 1024 * 1024)).toLocaleString("fr-FR", {
            maximumFractionDigits: 2
        })} GB`;
    }

    // Formate une date en heure locale.
    function formatTime(value) {
        if (!value) return "—";

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return String(value);
        }

        return date.toLocaleTimeString("fr-FR", {
            hour12: false
        });
    }

    // Formate une durée en heures, minutes et secondes.
    function formatDuration(seconds) {
        const total = Math.max(0, Math.floor(Number(seconds) || 0));
        const hours = Math.floor(total / 3600);
        const minutes = Math.floor((total % 3600) / 60);
        const remainingSeconds = total % 60;

        return [hours, minutes, remainingSeconds]
            .map((value) => String(value).padStart(2, "0"))
            .join(":");
    }

    let sharedAgentConfigPromise = null;

    async function requestAccessToken() {
        const cached = localStorage.getItem(accessTokenKey);
        if (cached) return true;
        if (!sharedAgentConfigPromise) {
            sharedAgentConfigPromise = (async () => {
                const response = await fetch("/api/auth/access-key", {
                    method: "POST",
                    headers: { Accept: "application/json" },
                    cache: "no-store"
                });
                const result = await response.json();
                if (!response.ok || !result.access_key) {
                    throw new Error(result.detail || "Impossible de créer ton espace INPA.");
                }
                localStorage.setItem(accessTokenKey, result.access_key);
                return true;
            })();
        }
        try {
            return await sharedAgentConfigPromise;
        } finally {
            sharedAgentConfigPromise = null;
        }
    }

    function showAgentConfiguration(config) {
        const serverUrl = String(config?.server_url || "").trim();
        const agentToken = String(config?.agent_token || "").trim();
        if (!serverUrl || !agentToken) {
            throw new Error("Le serveur n’a pas fourni la configuration complète de l’agent.");
        }
        window.prompt(
            "Code individuel INPA. Il ouvre uniquement ton espace et connecte ton agent. Garde ce code pour toi."
                + "\n\nServeur : " + serverUrl
                + "\n\nCopie ce code dans INPA-Agent.exe pour connecter ce poste.",
            agentToken
        );
    }
    async function submitAccountAuth(event) {
        event.preventDefault();
        const key = elements.authKey?.value?.trim();
        if (!key) return;
        elements.authSubmit.disabled = true;
        setText(elements.authError, "");
        localStorage.setItem(accessTokenKey, key);
        try {
            const response = await fetch("/api/auth/validate-key", {
                method: "POST",
                headers: { "X-INPA-Token": key, Accept: "application/json" },
                cache: "no-store"
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.detail || "Clé API invalide.");
            sessionStorage.removeItem(sessionTokenKey);
            elements.authOverlay.hidden = true;
            loginPromise = null;
            resolveLogin?.(true);
            resolveLogin = null;
        } catch (error) {
            localStorage.removeItem(accessTokenKey);
            setText(elements.authError, error.message || "Clé API invalide.");
        } finally {
            if (elements.authSubmit) elements.authSubmit.disabled = false;
        }
    }
    function cancelAccountAuth() {
        if (!loginPromise) return;
        elements.authOverlay.hidden = true;
        loginPromise = null;
        resolveLogin?.(false);
        resolveLogin = null;
    }

    function formatDateTime(value) {
        if (!value) return "Date inconnue";
        const date = new Date(value);
        return Number.isNaN(date.getTime())
            ? String(value)
            : date.toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "medium" });
    }

    async function downloadReport(path) {
        const request = () => fetch(path, {
            headers: {
                Accept: "application/json, text/csv",
                ...(sessionStorage.getItem(sessionTokenKey)
                    ? { "X-INPA-Session": sessionStorage.getItem(sessionTokenKey) }
                    : {}),
                ...(localStorage.getItem(accessTokenKey)
                    ? { "X-INPA-Token": localStorage.getItem(accessTokenKey) }
                    : {})
            },
            cache: "no-store"
        });

        try {
            let response = await request();
            if (response.status === 401 && await requestAccessToken()) {
                response = await request();
            }
            if (!response.ok) {
                let detail = `Téléchargement impossible (HTTP ${response.status}).`;
                try { detail = (await response.json()).detail || detail; } catch (_) {}
                throw new Error(detail);
            }
            const blob = await response.blob();
            const disposition = response.headers.get("Content-Disposition") || "";
            const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1]
                || `inpa-rapport.${path.includes("format=csv") ? "csv" : "json"}`;
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (error) {
            setText(elements.fact, error?.message || "Échec du téléchargement du rapport.");
        }
    }

    function exportObservedPacket(packet, index) {
        const timestamp = String(packet?.timestamp ?? packet?.time ?? "")
            .replace(/[^0-9A-Za-z_-]/g, "-")
            .replace(/-+/g, "-")
            .replace(/^-|-$/g, "");
        const filename = `inpa-paquet-${String(index + 1).padStart(3, "0")}${timestamp ? `-${timestamp}` : ""}.json`;
        const blob = new Blob([JSON.stringify(packet, null, 2)], {
            type: "application/json;charset=utf-8"
        });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function addHistoryButton(parent, label, callback) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "small-button";
        button.textContent = label;
        button.addEventListener("click", callback);
        parent.appendChild(button);
    }

    async function showHistoryDetails(record, detailsNode) {
        if (detailsNode.dataset.loaded === "true") {
            detailsNode.hidden = !detailsNode.hidden;
            return;
        }
        try {
            const response = await fetchJSON(`/api/history/${encodeURIComponent(record.id)}`);
            const saved = response.analysis || {};
            const report = saved.report;
            const detail = document.createElement("div");
            detail.className = "history-details";
            if (!report) {
                detail.textContent = saved.status === "interrupted"
                    ? "La capture a été interrompue avant l’enregistrement d’un rapport."
                    : "Le rapport détaillé n’est pas disponible pour cette capture.";
            } else {
                const lines = [
                    `${formatNumber(report.summary?.captured_packet_count ?? report.summary?.packet_count)} capturé(s) · ${formatNumber(report.summary?.analyzed_packet_count ?? report.summary?.packet_count)} analysé(s) · ${formatNumber(report.summary?.communication_count)} communication(s) · ${formatBytes(report.summary?.total_bytes)}`,
                    `Protocoles : ${Object.entries(report.protocols || {}).map(([name, count]) => `${name} ${formatNumber(count)}`).join(", ") || "aucun"}`,
                    ...((report.communications || []).slice(0, 5).map((flow) =>
                        `${flow.protocol || "?"} ${(flow.sources || []).join(", ")}:${(flow.source_ports || []).join(", ")} ↔ ${(flow.destinations || []).join(", ")}:${(flow.destination_ports || []).join(", ")} · ${formatNumber(flow.packet_count)} paquet(s)`
                    )),
                    ...((report.observations || []).slice(0, 3).map((item) =>
                        `${item.title || item.type || "Observation"} — ${item.observed_fact || ""}`
                    ))
                ];
                detail.textContent = lines.join("\n");
            }
            detailsNode.replaceChildren(detail);
            detailsNode.dataset.loaded = "true";
            detailsNode.hidden = false;
        } catch (error) {
            const detail = document.createElement("div");
            detail.className = "history-details";
            detail.textContent = error.message;
            detailsNode.replaceChildren(detail);
            detailsNode.hidden = false;
        }
    }

    async function loadHistory() {
        if (!elements.historyList) return;
        try {
            const response = await fetchJSON("/api/history?limit=50");
            const analyses = Array.isArray(response.analyses) ? response.analyses : [];
            elements.historyList.replaceChildren();
            if (!analyses.length) {
                const empty = document.createElement("div");
                empty.className = "empty-state";
                empty.textContent = "Aucune analyse enregistrée pour l’instant.";
                elements.historyList.appendChild(empty);
            }

            for (const record of analyses) {
                const row = document.createElement("div");
                row.className = "history-row";
                const icon = document.createElement("div");
                icon.className = "history-icon";
                icon.textContent = "◈";
                const summary = document.createElement("div");
                const heading = document.createElement("strong");
                heading.textContent = `Analyse ${record.id.slice(0, 8)}`;
                const metadata = document.createElement("span");
                const duration = record.duration_seconds == null
                    ? (record.status === "in_progress" ? "en cours" : "durée indisponible")
                    : formatDuration(record.duration_seconds);
                const preview = record.main_observation?.observed_fact
                    ? ` · ${record.main_observation.observed_fact}`
                    : "";
                metadata.textContent = `${record.interface || "Interface inconnue"} · ${formatDateTime(record.started_at)} · ${formatNumber(record.packet_count)} paquet(s) · ${duration}${preview}`;
                summary.append(heading, metadata);

                const status = document.createElement("span");
                status.className = `history-status ${record.status === "in_progress" ? "status-running" : record.status === "interrupted" ? "status-interrupted" : ""}`;
                status.textContent = record.status === "in_progress"
                    ? "En cours"
                    : record.status === "interrupted" ? "Interrompue" : "Terminée";
                row.append(icon, summary, status);

                const actions = document.createElement("div");
                actions.className = "history-downloads";
                const details = document.createElement("div");
                details.hidden = true;
                addHistoryButton(actions, "Détails", () => showHistoryDetails(record, details));
                if (record.status === "completed") {
                    addHistoryButton(actions, "JSON", () => downloadReport(`/api/history/${encodeURIComponent(record.id)}/report?format=json`));
                    addHistoryButton(actions, "CSV", () => downloadReport(`/api/history/${encodeURIComponent(record.id)}/report?format=csv`));
                    for (const [section, label] of [
                        ["capture", "Capture"],
                        ["protocols", "Protocoles"],
                        ["communications", "Communications"],
                        ["observations", "Alertes"]
                    ]) {
                        addHistoryButton(actions, `${label} CSV`, () =>
                            downloadReport(`/api/history/${encodeURIComponent(record.id)}/report?format=csv&section=${section}`)
                        );
                    }
                }
                elements.historyList.append(row, actions, details);
            }
            setText(elements.historyMessage, `${analyses.length} analyse(s) enregistrée(s)`);
            if (elements.historyAccessButton) elements.historyAccessButton.hidden = true;
        } catch (error) {
            elements.historyList.replaceChildren();
            const message = document.createElement("div");
            message.className = "empty-state";
            message.textContent = error.message || "Impossible de charger l’historique.";
            elements.historyList.appendChild(message);
            setText(elements.historyMessage, error.status === 403
                ? "Accès local uniquement ou jeton serveur requis"
                : "Historique indisponible");
            if (elements.historyAccessButton) elements.historyAccessButton.hidden = error.status !== 401;
        }
    }

    // Récupère une réponse JSON depuis l'API.
    async function fetchJSON(url, options = {}) {
        const request = () => {
            const token = localStorage.getItem(accessTokenKey) || "";
            const sessionToken = sessionStorage.getItem(sessionTokenKey) || "";
            return fetch(url, {
                ...options,
                method: options.method ?? "GET",
                headers: {
                    Accept: "application/json",
                    ...(sessionToken ? { "X-INPA-Session": sessionToken } : {}),
                    ...(token ? { "X-INPA-Token": token } : {}),
                    ...(options.headers ?? {})
                },
                cache: "no-store"
            });
        };
        let response = await request();
        if (response.status === 401) {
            if (await requestAccessToken()) response = await request();
        }

        if (!response.ok) {
            let detail = "";
            try {
                detail = (await response.clone().json())?.detail || "";
            } catch (_) {
                // La réponse ne contient pas nécessairement du JSON.
            }
            const error = new Error(detail || `${url} : erreur HTTP ${response.status}`);
            error.status = response.status;
            throw error;
        }

        return response.json();
    }

    // Accepte plusieurs structures possibles de réponse pour l'agent.
    function unwrapAgent(payload) {
        return payload?.agent
            ?? payload?.data?.agent
            ?? payload
            ?? {};
    }

    // Accepte la réponse complète ou l'objet d'analyse seul.
    function unwrapAnalysis(payload) {
        return payload?.analysis
            ?? payload?.data?.analysis
            ?? payload?.data
            ?? payload
            ?? {};
    }

    // Récupère les paquets individuels, y compris ceux présents dans les flux.
    function getPackets(analysis) {
        if (Array.isArray(analysis?.packets)) {
            return analysis.packets;
        }

        const packets = [];
        const seen = new Set();
        const flows = Array.isArray(analysis?.flows)
            ? analysis.flows
            : [];

        for (const flow of flows) {
            const flowPackets = Array.isArray(flow?.packets)
                ? flow.packets
                : [];

            for (const packet of flowPackets) {
                const key = [
                    packet?.timestamp,
                    packet?.source,
                    packet?.destination,
                    packet?.protocol,
                    packet?.source_port,
                    packet?.destination_port,
                    packet?.size
                ].join("|");

                if (!seen.has(key)) {
                    seen.add(key);
                    packets.push(packet);
                }
            }
        }

        return packets;
    }

    // Récupère les statistiques de protocoles ou les calcule depuis les paquets.
    function getProtocols(analysis, packets) {
        const protocols = analysis?.protocols;

        if (
            protocols &&
            typeof protocols === "object" &&
            !Array.isArray(protocols)
        ) {
            return Object.entries(protocols)
                .map(([name, count]) => [name, Number(count) || 0])
                .sort((a, b) => b[1] - a[1]);
        }

        const counts = {};

        for (const packet of packets) {
            const name = String(
                packet?.observed_protocol
                ?? packet?.protocol
                ?? "INCONNU"
            ).toUpperCase();

            counts[name] = (counts[name] || 0) + 1;
        }

        return Object.entries(counts).sort((a, b) => b[1] - a[1]);
    }

    // Récupère les observations de toutes les catégories.
    function getObservations(analysis) {
        if (!analysis || typeof analysis !== "object") {
            return [];
        }

        const general = Array.isArray(analysis.observations)
            ? analysis.observations
            : [];

        const behavioral = Array.isArray(analysis.behavior_observations)
            ? analysis.behavior_observations
            : [];

        const comparison = analysis.baseline_comparison
            ?? analysis.baselineComparison
            ?? {};

        const baseline = Array.isArray(comparison.observations)
            ? comparison.observations
            : [];

        const combined = [...general, ...behavioral, ...baseline];
        const seen = new Set();

        return combined.filter((item) => {
            if (!item || typeof item !== "object") {
                return false;
            }

            const key = [
                item.type || "",
                item.title || "",
                item.observed_fact || item.observedFact || ""
            ].join("|");

            if (seen.has(key)) {
                return false;
            }

            seen.add(key);
            return true;
        });
    }

    // Met à jour les quatre cartes statistiques.
    function renderStatistics(agent, analysis) {
        const packetCount = Number(
            analysis?.packet_count
            ?? analysis?.summary?.packet_count
            ?? agent?.packet_count
            ?? 0
        );

        const totalBytes = Number(
            analysis?.total_bytes
            ?? analysis?.summary?.total_bytes
            ?? 0
        );

        const flows = Array.isArray(analysis?.flows)
            ? analysis.flows
            : [];

        // Seules les observations comportementales significatives
        // sont comptées comme alertes à examiner.
        const behavioralObservations = Array.isArray(
            analysis?.behavior_observations
        )
            ? analysis.behavior_observations
            : Array.isArray(analysis?.behaviorObservations)
                ? analysis.behaviorObservations
                : [];

        const uniqueAlerts = new Map();

        behavioralObservations.forEach((item) => {
            if (!item || typeof item !== "object") return;

            const severity = String(
                item.severity ?? item.level ?? ""
            ).toUpperCase();

            if (!["MEDIUM", "HIGH", "CRITICAL"].includes(severity)) {
                return;
            }

            const key = [
                item.type || "",
                item.title || "",
                item.observed_fact || item.observedFact || ""
            ].join("|");

            uniqueAlerts.set(key, item);
        });

        const alertCount = uniqueAlerts.size;

        setText(elements.packets, formatNumber(packetCount));
        setText(elements.bytes, formatBytes(totalBytes));
        setText(elements.connections, formatNumber(flows.length));
        setText(elements.alerts, formatNumber(alertCount));
        setText(elements.sidebarAlerts, formatNumber(alertCount));
        setText(elements.alertHeaderCount, formatNumber(alertCount));
    }

    // Affiche l'état réel de l'agent.
    function renderAgent(agent) {
        const running = Boolean(agent?.running);
        const remoteConnected = agent?.remote ? Boolean(agent.connected) : true;
        const agentError = String(agent?.last_error ?? "").trim();
        const droppedPackets = Number(agent?.dropped_packets ?? 0);
        const reportedInterface = agent?.interface
            ?? agent?.interface_name
            ?? agent?.capture_interface;

        if (reportedInterface && reportedInterface !== "Aucune") {
            lastInterfaceName = String(reportedInterface);
        }

        setText(
            elements.interfaceName,
            reportedInterface && reportedInterface !== "Aucune"
                ? reportedInterface
                : lastInterfaceName || reportedInterface || "Interface inconnue"
        );

        if (elements.captureState) {
            elements.captureState.textContent = running
                ? "EN COURS"
                : "ARRÊTÉE";

            elements.captureState.className = running
                ? "state-running"
                : "state-stopped";
        }

        if (elements.captureButton) {
            elements.captureButton.classList.toggle("active", running);
            elements.captureButton.title = running
                ? "Arrêter la capture INPA."
                : "Démarrer une capture réseau.";
        }

        setText(elements.captureIcon, running ? "●" : "○");
        setText(
            elements.captureText,
            running ? "Capture active" : "Capture arrêtée"
        );

        const connectionLabel = document.querySelector(".agent-status strong");
        if (connectionLabel) {
            connectionLabel.textContent = agentError
                ? "ERREUR AGENT"
                : remoteConnected ? "CONNECTÉ" : "AGENT HORS LIGNE";
        }

        const footer = document.querySelector(
            ".dashboard-footer span:last-child"
        );

        if (footer) {
            footer.textContent = agentError
                ? agentError
                : droppedPackets > 0
                    ? `${formatNumber(droppedPackets)} paquet(s) écarté(s) pendant une perte de connexion`
                    : !remoteConnected
                ? "INPA-Agent distant non connecté"
                : agent?.stopping
                    ? "Arrêt de la capture et synchronisation des paquets…"
                    : running
                        ? "Capture réelle · Agent connecté"
                        : "Agent arrêté · En attente de capture";
        }
    }

    // Garde le dernier résultat utile si l'API renvoie brièvement une analyse vide.
    function hasAnalysisData(analysis) {
        if (!analysis || typeof analysis !== "object") return false;

        const flows = Array.isArray(analysis.flows) ? analysis.flows : [];
        const protocols = analysis.protocols;
        const packetCount = Number(
            analysis.packet_count ?? analysis.summary?.packet_count ?? 0
        );
        const totalBytes = Number(
            analysis.total_bytes ?? analysis.summary?.total_bytes ?? 0
        );

        return packetCount > 0
            || totalBytes > 0
            || flows.length > 0
            || (protocols && Object.keys(protocols).length > 0);
    }

    // Affiche la durée de session.
    function renderSession(analysis) {
        const duration = analysis?.duration_seconds
            ?? analysis?.capture?.duration_seconds;

        if (duration != null) {
            setText(elements.sessionTime, formatDuration(duration));
            return;
        }

        const startedAt = analysis?.started_at ?? analysis?.start_time;

        if (startedAt) {
            const elapsed = Math.max(
                0,
                (Date.now() - new Date(startedAt).getTime()) / 1000
            );

            setText(elements.sessionTime, formatDuration(elapsed));
            return;
        }

        setText(
            elements.sessionTime,
            formatDuration((Date.now() - sessionStart) / 1000)
        );
    }

    // Dessine le graphique de trafic sans modifier le CSS global.
    function renderTrafficChart(packets) {
        if (!elements.chart) return;

        elements.chart.replaceChildren();

        if (!packets.length) {
            const message = document.createElement("div");
            message.className = "empty-state";
            message.textContent = "Aucun paquet disponible pour le graphique.";
            elements.chart.appendChild(message);
            return;
        }

        const buckets = new Array(24).fill(0);
        const now = Date.now();

        for (const packet of packets) {
            const timestamp = new Date(
                packet?.timestamp ?? packet?.time ?? now
            ).getTime();

            if (!Number.isFinite(timestamp)) continue;

            const secondsAgo = Math.max(0, (now - timestamp) / 1000);
            const bucket = Math.min(23, Math.floor(secondsAgo));
            buckets[23 - bucket] += 1;
        }

        const maximum = Math.max(1, ...buckets);

        buckets.forEach((count, index) => {
            const bar = document.createElement("div");
            bar.className = "chart-bar";

            const height = count === 0
                ? 2
                : Math.max(4, (count / maximum) * 100);

            bar.style.height = `${height}%`;
            bar.style.animationDelay = `${index * 0.015}s`;
            bar.title = `${count} paquet(s)`;

            elements.chart.appendChild(bar);
        });
    }

    // Affiche les protocoles et leur proportion.
    function renderProtocols(entries) {
        if (!elements.protocols) return;

        elements.protocols.replaceChildren();

        const total = entries.reduce(
            (sum, [, count]) => sum + count,
            0
        );

        if (!entries.length) {
            const empty = document.createElement("p");
            empty.className = "empty-state";
            empty.textContent = "Aucun protocole observé.";
            elements.protocols.appendChild(empty);
            return;
        }

        for (const [protocol, count] of entries) {
            const item = document.createElement("div");
            item.className = "protocol-item";

            const top = document.createElement("div");
            top.className = "protocol-top";

            const name = document.createElement("span");
            name.textContent = protocol;

            const percent = document.createElement("span");
            const ratio = total > 0 ? (count / total) * 100 : 0;
            percent.textContent = `${ratio.toFixed(1)}%`;

            top.append(name, percent);

            const progress = document.createElement("div");
            progress.className = "protocol-progress";

            const fill = document.createElement("span");
            fill.style.width = `${ratio}%`;
            progress.appendChild(fill);

            const countLabel = document.createElement("small");
            countLabel.textContent = `${formatNumber(count)} paquet(s)`;

            item.append(top, progress, countLabel);
            elements.protocols.appendChild(item);
        }
    }

    async function lookupVirusTotal(ip, row, button) {
        const consentKey = "inpa-virustotal-consent";
        if (!sessionStorage.getItem(consentKey)) {
            const accepted = window.confirm(
                "L’adresse IP publique " + ip + " sera envoyée à VirusTotal pour consulter sa réputation. Continuer ?"
            );
            if (!accepted) return;
            sessionStorage.setItem(consentKey, "accepted");
        }

        let resultRow = row.nextElementSibling;
        if (!resultRow?.classList.contains("virustotal-result-row")) {
            resultRow = document.createElement("tr");
            resultRow.className = "virustotal-result-row";
            const cell = document.createElement("td");
            cell.colSpan = 8;
            resultRow.appendChild(cell);
            row.after(resultRow);
        }

        const cell = resultRow.firstElementChild;
        cell.textContent = "Interrogation de VirusTotal…";
        button.disabled = true;
        try {
            const response = await fetchJSON(
                "/api/enrichment/virustotal/ip?ip=" + encodeURIComponent(ip)
            );
            const info = response.result || {};
            const malicious = Number(info.malicious || 0);
            const suspicious = Number(info.suspicious || 0);
            const reputation = info.reputation == null ? "indisponible" : info.reputation;
            cell.replaceChildren();
            const summary = document.createElement("span");
            summary.textContent = ip + " · Détections malveillantes : " + malicious
                + " · suspectes : " + suspicious + " · réputation : " + reputation;
            if (info.country || info.as_owner) {
                summary.textContent += " · " + [info.country, info.as_owner].filter(Boolean).join(" — ");
            }
            cell.appendChild(summary);
            const link = document.createElement("a");
            link.href = info.url;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.textContent = "Ouvrir le rapport VirusTotal";
            cell.append(" ");
            cell.appendChild(link);
        } catch (error) {
            cell.textContent = error.message || "Consultation VirusTotal impossible.";
        } finally {
            button.disabled = false;
        }
    }
    // Affiche les derniers paquets observés.
    function renderPackets(packets) {
        if (!elements.packetTable) return;

        elements.packetTable.replaceChildren();

        if (!packets.length) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 8;
            cell.textContent = "Aucun paquet détaillé disponible.";

            row.appendChild(cell);
            elements.packetTable.appendChild(row);
            return;
        }

        packets.slice(-100).reverse().forEach((packet, index) => {
            const row = document.createElement("tr");

            const source = packet?.source ?? packet?.src ?? "—";
            const destination = packet?.destination ?? packet?.dst ?? "—";
            const protocol = packet?.observed_protocol
                ?? packet?.protocol
                ?? "INCONNU";

            const port = packet?.destination_port
                ?? packet?.source_port
                ?? packet?.port
                ?? "—";

            const size = Number(packet?.size ?? packet?.length ?? 0);

            const status = Array.isArray(packet?.classifications)
                && packet.classifications.length
                ? packet.classifications.join(", ")
                : packet?.interpretation ?? "Observé";

            const values = [
                formatTime(packet?.timestamp ?? packet?.time),
                source,
                destination,
                protocol,
                port,
                `${formatNumber(size)} B`,
                status
            ];

            values.forEach((value, index) => {
                const cell = document.createElement("td");

                if (index === 3) {
                    const tag = document.createElement("span");
                    tag.className = "protocol-tag";
                    tag.textContent = String(value);
                    cell.appendChild(tag);
                } else {
                    cell.textContent = String(value);
                }

                row.appendChild(cell);
            });

            const exportCell = document.createElement("td");
            const exportButton = document.createElement("button");
            exportButton.type = "button";
            exportButton.className = "small-button";
            exportButton.textContent = "Exporter";
            exportButton.title = "Télécharger les détails de ce paquet en JSON";
            exportButton.addEventListener("click", () =>
                exportObservedPacket(packet, index)
            );
            exportCell.appendChild(exportButton);
            const looksLikeIp = (value) => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
                || (/^[0-9a-f:]+$/i.test(value) && value.includes(":"));
            [
                ["IP source", String(source)],
                ["IP destination", String(destination)]
            ].forEach(([label, ipAddress]) => {
                if (!looksLikeIp(ipAddress)) return;
                const lookupButton = document.createElement("button");
                lookupButton.type = "button";
                lookupButton.className = "small-button";
                lookupButton.textContent = label;
                lookupButton.title = "Consulter la réputation de cette IP publique";
                lookupButton.addEventListener("click", () =>
                    lookupVirusTotal(ipAddress, row, lookupButton)
                );
                exportCell.appendChild(lookupButton);
            });
            row.appendChild(exportCell);

            elements.packetTable.appendChild(row);
        });
    }

    // Affiche les observations réseau avec leurs faits et interprétations.

    // Classe les observations sans modifier les règles de détection du backend.
    function renderAlerts(analysis) {
        if (!elements.alertsList) return;

        elements.alertsList.replaceChildren();

        const general = Array.isArray(analysis?.observations)
            ? analysis.observations
            : [];

        const behavioral = Array.isArray(analysis?.behavior_observations)
            ? analysis.behavior_observations
            : Array.isArray(analysis?.behaviorObservations)
                ? analysis.behaviorObservations
                : [];

        const comparisonData = analysis?.baseline_comparison
            ?? analysis?.baselineComparison
            ?? {};

        const baseline = Array.isArray(comparisonData.observations)
            ? comparisonData.observations
            : [];

        const severityOf = (item) =>
            String(item?.severity ?? item?.level ?? "LOW").toUpperCase();

        const unique = (items) => {
            const seen = new Set();

            return items.filter((item) => {
                if (!item || typeof item !== "object") return false;

                const key = [
                    item.type || "",
                    item.title || "",
                    item.observed_fact || item.observedFact || ""
                ].join("|");

                if (seen.has(key)) return false;

                seen.add(key);
                return true;
            });
        };

        const allBehavioral = unique(behavioral);

        const priority = allBehavioral.filter((item) =>
            ["MEDIUM", "HIGH", "CRITICAL"].includes(severityOf(item))
        );

        const unusual = allBehavioral.filter((item) =>
            !["MEDIUM", "HIGH", "CRITICAL"].includes(severityOf(item))
        );

        const sections = [
            {
                title: "INFORMATIONS RÉSEAU",
                description: "Faits observés, pas nécessairement suspects.",
                items: unique(general)
            },
            {
                title: "COMPORTEMENTS À EXAMINER",
                description: "Signaux comportementaux nécessitant du contexte.",
                items: unusual
            },
            {
                title: "ALERTES PRIORITAIRES",
                description: "Sévérité moyenne, élevée ou critique.",
                items: priority
            },
            {
                title: "COMPARAISON AVEC LA RÉFÉRENCE",
                description: "Différences par rapport au profil réseau de référence.",
                items: unique(baseline)
            }
        ];

        const createText = (tagName, text) => {
            const element = document.createElement(tagName);
            element.textContent = text;
            return element;
        };

        let displayed = 0;

        sections.forEach((section) => {
            if (!section.items.length) return;

            const heading = document.createElement("div");
            heading.className = "alert-item";

            const headingBody = document.createElement("div");
            headingBody.append(
                createText("strong", section.title),
                createText("p", section.description)
            );

            heading.appendChild(headingBody);
            elements.alertsList.appendChild(heading);

            section.items.slice(0, 30).forEach((observation) => {
                if (displayed >= 30) return;

                const item = document.createElement("div");
                const level = severityOf(observation).toLowerCase();
                item.className = `alert-item alert-observation alert-observation--${level}`;

                const number = document.createElement("span");
                number.className = "alert-observation-number";
                number.textContent = String(displayed + 1).padStart(2, "0");
                const severity = document.createElement("span");

                severity.className = [
                    "alert-severity",
                    ["low", "medium", "high", "critical"].includes(level)
                        ? level
                        : ""
                ].filter(Boolean).join(" ");

                severity.title = `Sévérité : ${level}`;
                severity.setAttribute("aria-label", `Sévérité : ${level}`);

                const body = document.createElement("div");

                const title = createText(
                    "strong",
                    observation.title
                        ?? observation.name
                        ?? observation.type
                        ?? "Observation réseau"
                );

                const fact = observation.observed_fact
                    ?? observation.observedFact
                    ?? observation.description
                    ?? observation.message
                    ?? "Aucun fait détaillé disponible.";

                const cause = createText("p", fact);
                cause.className = "alert-cause";
                body.append(title, cause);

                const interpretation =
                    observation.interpretation
                    ?? observation.explanation;

                if (interpretation && interpretation !== fact) {
                    body.appendChild(createText("p", interpretation));
                }

                item.append(number, severity, body);
                elements.alertsList.appendChild(item);
                displayed++;
            });
        });

        if (displayed === 0) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent =
                "Aucune observation disponible. Cela ne garantit pas que le réseau est sans risque.";

            elements.alertsList.appendChild(empty);
        }
    }


    // Affiche le fait, l’interprétation et l’hypothèse de l’analyse.
    // Cette fonction manquait et provoquait l’erreur « renderAnalysis is not defined ».
    function renderAnalysis(agent, analysis, packets, observations) {
        const list = Array.isArray(observations) ? observations : [];

        // Prioriser les observations comportementales, puis les observations générales
        // et enfin les différences par rapport à la référence.
        const comparison = analysis?.baseline_comparison
            ?? analysis?.baselineComparison
            ?? {};
        const baseline = Array.isArray(comparison.observations)
            ? comparison.observations
            : [];
        const behavioral = Array.isArray(analysis?.behavior_observations)
            ? analysis.behavior_observations
            : Array.isArray(analysis?.behaviorObservations)
                ? analysis.behaviorObservations
                : [];
        const general = Array.isArray(analysis?.observations)
            ? analysis.observations
            : [];
        const ordered = [...behavioral, ...general, ...baseline, ...list];
        const seen = new Set();
        const observation = ordered.find((item) => {
            if (!item || typeof item !== "object") return false;
            const key = [
                item.type || "",
                item.title || "",
                item.observed_fact || item.observedFact || ""
            ].join("|");
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        if (!observation) {
            const packetCount = Number(
                analysis?.packet_count
                ?? analysis?.summary?.packet_count
                ?? agent?.packet_count
                ?? (Array.isArray(packets) ? packets.length : 0)
            );
            setText(
                elements.fact,
                packetCount > 0
                    ? `Analyse disponible : ${formatNumber(packetCount)} paquet(s) observé(s).`
                    : "Aucun fait d’analyse disponible pour le moment."
            );
            setText(
                elements.interpretation,
                packetCount > 0
                    ? "Aucune observation particulière n’a été renvoyée par les détecteurs."
                    : "Démarre une capture réseau pour obtenir des données à analyser."
            );
            setText(
                elements.hypothesis,
                "L’absence d’observation ne garantit pas que le réseau est sans risque."
            );
            return;
        }

        setText(
            elements.fact,
            observation.observed_fact
                ?? observation.observedFact
                ?? observation.description
                ?? observation.message
                ?? observation.title
                ?? "Une observation réseau a été enregistrée."
        );
        setText(
            elements.interpretation,
            observation.interpretation
                ?? observation.explanation
                ?? "Le moteur a identifié un élément nécessitant une interprétation contextuelle."
        );
        setText(
            elements.hypothesis,
            observation.hypothesis
                ?? "Cette observation ne constitue pas, à elle seule, une preuve d’attaque. Vérifie les détails et le contexte réseau."
        );
    }

    // Met à jour toutes les zones du tableau de bord.
    function renderDashboard(agent, analysis) {
        const packets = getPackets(analysis);
        const protocols = getProtocols(analysis, packets);
        const observations = getObservations(analysis);

        renderAgent(agent);
        renderSession(analysis);
        renderStatistics(agent, analysis);
        renderTrafficChart(packets);
        renderProtocols(protocols);
        renderPackets(packets);
        renderAlerts(analysis);
        renderAnalysis(agent, analysis, packets, observations);
    }

    // Charge les deux endpoints réels du backend.
    async function loadDashboard() {
        if (isLoading) return;

        isLoading = true;

        if (elements.refreshButton) {
            elements.refreshButton.disabled = true;
            elements.refreshButton.textContent = "Actualisation…";
        }

        try {
            const [agentResponse, analysisResponse] = await Promise.all([
                fetchJSON("/api/agent/status"),
                fetchJSON("/api/analyzer")
            ]);

            agentData = unwrapAgent(agentResponse);
            const nextAnalysis = unwrapAnalysis(analysisResponse);
            const stopped = !Boolean(agentData?.running);

            if (hasAnalysisData(nextAnalysis) || !stopped || !hasAnalysisData(analysisData)) {
                analysisData = nextAnalysis;
            }

            renderDashboard(agentData, analysisData);

            console.log("INPA : données API chargées.", {
                running: agentData?.running,
                interface: agentData?.interface,
                capturedPackets: agentData?.packet_count,
                analyzedPackets: analysisData?.packet_count,
                flows: analysisData?.flows?.length
            });
        } catch (error) {
            console.error("Erreur Dashboard :", error);

            setText(
                elements.fact,
                "Impossible de charger les données de l'API. Vérifie le serveur FastAPI."
            );

            setText(
                elements.interpretation,
                error?.message ?? "Erreur de communication avec le backend."
            );

            setText(
                elements.hypothesis,
                "Vérifie /api/agent/status et /api/analyzer dans ton navigateur."
            );
        } finally {
            isLoading = false;

            if (elements.refreshButton) {
                elements.refreshButton.disabled = false;
                elements.refreshButton.textContent = "Actualiser";
            }
        }
    }

    // Le bouton Actualiser recharge les données.
    if (elements.authForm) elements.authForm.addEventListener("submit", submitAccountAuth);
    if (elements.authCancel) elements.authCancel.addEventListener("click", cancelAccountAuth);
    const rotateAccessKeyButton = $("rotate-access-key");
    if (rotateAccessKeyButton) {
        rotateAccessKeyButton.addEventListener("click", async () => {
            if (!window.confirm("Renouveler le code ? L’ancien code cessera immédiatement de fonctionner et l’agent devra recevoir le nouveau.")) return;
            rotateAccessKeyButton.disabled = true;
            try {
                const response = await fetchJSON("/api/auth/access-key/rotate", { method: "POST" });
                localStorage.setItem(accessTokenKey, response.access_key);
                showAgentConfiguration(await fetchJSON("/api/auth/agent-config"));
                await loadDashboard();
            } catch (error) {
                setText(elements.fact, error.message || "Impossible de renouveler le code.");
            } finally {
                rotateAccessKeyButton.disabled = false;
            }
        });
    }
    const accessKeyButton = $("access-key-button");
    if (accessKeyButton) {
        accessKeyButton.addEventListener("click", async () => {
            if (!localStorage.getItem(accessTokenKey)) {
                if (!await requestAccessToken()) return;
            }
            try {
                showAgentConfiguration(await fetchJSON("/api/auth/agent-config"));
            } catch (error) {
                setText(elements.fact, error.message || "Impossible de charger la configuration de l'agent.");
            }
        });
    }
    if (elements.authOverlay) {
        elements.authOverlay.addEventListener("click", (event) => {
            if (event.target === elements.authOverlay) cancelAccountAuth();
        });
    }
    if (elements.refreshButton) {
        elements.refreshButton.addEventListener("click", loadDashboard);
    }

    if (elements.historyRefreshButton) {
        elements.historyRefreshButton.addEventListener("click", loadHistory);
    }
    if (elements.historyAccessButton) {
        elements.historyAccessButton.addEventListener("click", async () => {
            if (await requestAccessToken()) loadHistory();
        });
    }
    if (elements.agentConfigButton) {
        elements.agentConfigButton.addEventListener("click", async () => {
            try {
                const response = await fetchJSON("/api/auth/agent-config");
                showAgentConfiguration(response);
            } catch (error) {
                setText(elements.fact, error.message || "Impossible de charger la configuration de l'agent.");
            }
        });
    }
    if (elements.exportCurrentJson) {
        elements.exportCurrentJson.addEventListener("click", () =>
            downloadReport("/api/reports/current?format=json")
        );
    }
    if (elements.exportCurrentCsv) {
        elements.exportCurrentCsv.addEventListener("click", () =>
            downloadReport("/api/reports/current?format=csv")
        );
    }
    document.querySelectorAll("[data-report-section]").forEach((button) => {
        button.addEventListener("click", () => {
            const section = button.dataset.reportSection;
            downloadReport(`/api/reports/current?format=csv&section=${encodeURIComponent(section)}`);
        });
    });

    // Bascule la capture avec les interfaces réellement exposées par l'agent.
    async function toggleCapture() {
        if (elements.captureButton) elements.captureButton.disabled = true;
        try {
            if (agentData?.running) {
                await fetchJSON("/api/agent/capture/stop", { method: "POST" });
            } else {
                const response = await fetchJSON("/api/agent/interfaces");
                const interfaces = Array.isArray(response?.interfaces) ? response.interfaces : [];
                const usable = interfaces.filter((item) =>
                    item && item.capture_available && (item.scapy_name || item.name)
                );
                const selected = usable.find((item) =>
                    /wi-?fi/i.test(`${item.name ?? ""} ${item.type ?? ""}`)
                ) ?? usable[0];
                const interfaceName = selected?.scapy_name ?? selected?.name;
                if (!interfaceName) throw new Error("Aucune interface réseau capturable n'est disponible.");
                await fetchJSON("/api/agent/capture/start", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ interface: interfaceName })
                });
            }
            await loadDashboard();
            await loadHistory();
        } catch (error) {
            console.error("Erreur de capture :", error);
            setText(elements.fact, error?.message ?? "Impossible de modifier l'état de la capture.");
        } finally {
            if (elements.captureButton) elements.captureButton.disabled = false;
        }
    }

    if (elements.captureButton) {
        elements.captureButton.addEventListener("click", toggleCapture);
    }
    // Premier chargement, puis actualisation automatique toutes les 3 secondes.
    loadDashboard();
    loadHistory();
    window.setInterval(loadDashboard, 3000);
    window.setInterval(() => {
        if (agentData?.running || agentData?.stopping) loadHistory();
    }, 5000);
});
