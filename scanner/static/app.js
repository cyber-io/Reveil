const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_COLOR_VAR = {
    Critical: "var(--critical)",
    High: "var(--high)",
    Medium: "var(--medium)",
    Low: "var(--low)",
    Info: "var(--info)",
};

const form = document.getElementById("scanForm");
const runBtn = document.getElementById("runBtn");
const errorMsg = document.getElementById("errorMsg");
const statusPill = document.getElementById("statusPill");
const statusText = document.getElementById("statusText");
const mainArea = document.getElementById("mainArea");
const historyList = document.getElementById("historyList");

let currentScanId = null;

function setStatus(state, text) {
    statusPill.className = `status-pill mono ${state}`;
    statusText.textContent = text;
}

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorMsg.style.display = "none";
    runBtn.disabled = true;
    runBtn.textContent = "SCANNING...";
    setStatus("scanning", "scanning");

    const payload = {
        target: document.getElementById("target").value.trim(),
        login_url: document.getElementById("loginUrl").value.trim(),
        username: document.getElementById("username").value.trim(),
        password: document.getElementById("password").value,
        max_pages: parseInt(document.getElementById("maxPages").value, 10) || 25,
    };

    renderScanning(payload.target);

    try {
        const resp = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();

        if (!resp.ok) {
            throw new Error(data.error || "Scan failed");
        }

        currentScanId = data.scan.id;
        await playLogThenShowResults(data.log, data.scan);
        setStatus("done", "done");
        loadHistory();
    } catch (err) {
        errorMsg.textContent = "⚠ " + err.message;
        errorMsg.style.display = "block";
        setStatus("idle", "idle");
    } finally {
        runBtn.disabled = false;
        runBtn.textContent = "▶ RUN SCAN";
    }
});

function renderScanning(target) {
    mainArea.innerHTML = `
        <div class="result-header">
            <div class="result-target mono">${escapeHtml(target)}</div>
            <div class="result-meta">scan in progress...</div>
        </div>
        <div class="tabs-row">
            <div class="tabs"><div class="tab active">Live Log</div></div>
        </div>
        <div class="terminal" id="terminal"></div>
    `;
}

function playLogThenShowResults(log, scan) {
    return new Promise((resolve) => {
        const terminal = document.getElementById("terminal");
        let i = 0;
        function next() {
            if (i >= log.length) {
                setTimeout(() => {
                    renderResults(scan, log);
                    resolve();
                }, 250);
                return;
            }
            const entry = log[i];
            const line = document.createElement("div");
            const isFinding = entry.text.startsWith("[!]");
            line.className = "line" + (isFinding ? " finding" : "");
            line.innerHTML = `<span class="t-time">${entry.time}</span><span class="t-text">${escapeHtml(entry.text)}</span>`;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
            i++;
            setTimeout(next, isFinding ? 180 : 60);
        }
        next();
    });
}

function renderResults(scan, log) {
    const counts = scan.severity_counts;
    const total = scan.total_findings || 1;

    const barSegs = SEVERITY_ORDER.filter(s => counts[s] > 0).map(s => {
        const pct = (counts[s] / total) * 100;
        return `<div class="seg" style="width:${pct}%; background:${SEVERITY_COLOR_VAR[s]};"></div>`;
    }).join("");

    const legend = SEVERITY_ORDER.map(s => `
        <div class="leg"><span class="dot" style="background:${SEVERITY_COLOR_VAR[s]};"></span>${s}: ${counts[s]}</div>
    `).join("");

    const findingsHtml = scan.findings.length ? scan.findings.map((f, idx) => `
        <div class="finding-card sev-${f.severity}" data-idx="${idx}">
            <div class="finding-top" onclick="this.parentElement.classList.toggle('open')">
                <span class="sev-badge sev-${f.severity}">${f.severity}</span>
                <span class="finding-title">${escapeHtml(f.title)}</span>
                <span class="finding-chevron">▶</span>
            </div>
            <div class="finding-body">
                <div class="f-url">${escapeHtml(f.url)}</div>
                <div class="f-desc">${escapeHtml(f.description)}</div>
                ${f.evidence ? `<div class="f-evidence">${escapeHtml(f.evidence)}</div>` : ""}
            </div>
        </div>
    `).join("") : `<div class="no-findings">✓ No vulnerabilities detected on this target.</div>`;

    mainArea.innerHTML = `
        <div class="result-header">
            <div class="result-target mono">${escapeHtml(scan.target)}</div>
            <div class="result-meta">${new Date(scan.started_at).toLocaleString()} · ${scan.total_findings} finding(s)</div>
            <div class="severity-bar-wrap">
                <div class="severity-bar">${barSegs || '<div class="seg" style="width:100%;background:var(--border-bright);"></div>'}</div>
                <div class="severity-legend">${legend}</div>
            </div>
        </div>
        <div class="tabs-row">
            <div class="tabs">
                <div class="tab active" data-tab="findings">Findings</div>
                <div class="tab" data-tab="log">Live Log</div>
            </div>
            <button class="download-btn" onclick="downloadReport('${scan.id}')">⬇ Download HTML report</button>
        </div>
        <div id="tabContent">
            <div class="findings-list">${findingsHtml}</div>
        </div>
    `;

    const tabs = mainArea.querySelectorAll(".tab");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            const tabContent = document.getElementById("tabContent");
            if (tab.dataset.tab === "findings") {
                tabContent.innerHTML = `<div class="findings-list">${findingsHtml}</div>`;
            } else {
                const logHtml = log.map(entry => {
                    const isFinding = entry.text.startsWith("[!]");
                    return `<div class="line${isFinding ? " finding" : ""}" style="opacity:1;"><span class="t-time">${entry.time}</span><span class="t-text">${escapeHtml(entry.text)}</span></div>`;
                }).join("");
                tabContent.innerHTML = `<div class="terminal">${logHtml}</div>`;
            }
        });
    });
}

function downloadReport(scanId) {
    window.location.href = `/api/report/${scanId}/download`;
}

async function loadHistory() {
    const resp = await fetch("/api/history");
    const items = await resp.json();

    if (!items.length) {
        historyList.innerHTML = `<div class="history-empty">No scans yet this session.</div>`;
        return;
    }

    historyList.innerHTML = items.map(item => {
        const worst = SEVERITY_ORDER.find(s => item.severity_counts[s] > 0) || "Info";
        return `
        <div class="history-item ${item.id === currentScanId ? 'active' : ''}" onclick="loadHistoryItem('${item.id}')">
            <div class="h-target">${escapeHtml(item.target)}</div>
            <div class="h-meta">
                <span style="color:${SEVERITY_COLOR_VAR[worst]}">${item.total_findings} finding(s)</span>
                <span>${new Date(item.started_at).toLocaleTimeString()}</span>
            </div>
        </div>`;
    }).join("");
}

async function loadHistoryItem(scanId) {
    const resp = await fetch(`/api/history/${scanId}`);
    const data = await resp.json();
    currentScanId = scanId;
    renderResults(data.scan, data.log);
    loadHistory();
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

loadHistory();
