/**
 * Reveil Security Scanner - Interactive Controller
 */

(function () {
    'use strict';

    const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
    const SEVERITY_COLORS = {
        Critical: "var(--critical)",
        High: "var(--high)",
        Medium: "var(--medium)",
        Low: "var(--low)",
        Info: "var(--info)"
    };

    const VULN_METADATA = {
        sqli: {
            cwe: "CWE-89: SQL Injection",
            owasp: "OWASP A03:2021",
            remediation: "Use parameterized queries (prepared statements) with placeholder bindings. Never concatenate unsanitized user input directly into SQL commands."
        },
        xss: {
            cwe: "CWE-79: Cross-Site Scripting (XSS)",
            owasp: "OWASP A03:2021",
            remediation: "Contextually HTML-encode user input before rendering. Avoid Jinja2 `|safe` unless content is strictly sanitized with an HTML sanitizer."
        },
        idor: {
            cwe: "CWE-639: Insecure Direct Object Reference",
            owasp: "OWASP A01:2021",
            remediation: "Enforce server-side authorization checks on all record retrieval endpoints. Validate that the logged-in session user owns the requested record."
        },
        headers: {
            cwe: "CWE-693: Protection Mechanism Failure",
            owasp: "OWASP A05:2021",
            remediation: "Set standard security response headers at the reverse proxy or web server layer: CSP, X-Frame-Options, X-Content-Type-Options, and HSTS."
        },
        cookie: {
            cwe: "CWE-614 / CWE-1004: Insecure Cookie Flags",
            owasp: "OWASP A05:2021",
            remediation: "Configure session cookies with `HttpOnly=True` to prevent theft via JavaScript/XSS, `Secure=True` for TLS, and `SameSite='Lax'`."
        }
    };

    const state = {
        activeView: "config",
        currentScanId: null,
        currentScan: null,
        currentLog: [],
        activeSevFilter: "ALL",
        searchQuery: "",
        isScanning: false,
        autoscroll: true,
        discoveredEndpoints: []
    };

    const elements = {
        navTabs: document.querySelectorAll(".nav-tab"),
        viewPanels: document.querySelectorAll(".view-panel"),
        activeTargetBar: document.getElementById("activeTargetBar"),
        targetUrlChip: document.getElementById("targetUrlChip"),
        targetFindingsChip: document.getElementById("targetFindingsChip"),
        statusIndicator: document.getElementById("statusIndicator"),
        statusText: document.getElementById("statusText"),
        headerDownloadBtn: document.getElementById("headerDownloadBtn"),
        consolePulse: document.getElementById("consolePulse"),
        findingsCountBadge: document.getElementById("findingsCountBadge"),
        endpointsCountBadge: document.getElementById("endpointsCountBadge"),
        historyCountBadge: document.getElementById("historyCountBadge"),

        // Form
        scanForm: document.getElementById("scanForm"),
        targetInput: document.getElementById("target"),
        loginUrlInput: document.getElementById("loginUrl"),
        usernameInput: document.getElementById("username"),
        passwordInput: document.getElementById("password"),
        maxPagesInput: document.getElementById("maxPages"),
        maxPagesSlider: document.getElementById("maxPagesSlider"),
        maxPagesDisplay: document.getElementById("maxPagesDisplay"),
        runBtn: document.getElementById("runBtn"),
        errorMsg: document.getElementById("errorMsg"),
        errorText: document.getElementById("errorText"),
        clearTargetBtn: document.getElementById("clearTargetBtn"),
        togglePasswordBtn: document.getElementById("togglePasswordBtn"),
        authAccordionToggle: document.getElementById("authAccordionToggle"),
        authAccordionContent: document.getElementById("authAccordionContent"),

        // Console
        consoleTargetTitle: document.getElementById("consoleTargetTitle"),
        terminal: document.getElementById("terminal"),
        copyLogBtn: document.getElementById("copyLogBtn"),
        autoscrollToggleBtn: document.getElementById("autoscrollToggleBtn"),

        // Findings
        findingsEmptyState: document.getElementById("findingsEmptyState"),
        findingsReportLayout: document.getElementById("findingsReportLayout"),
        repScanId: document.getElementById("repScanId"),
        repTargetUrl: document.getElementById("repTargetUrl"),
        repTimestamp: document.getElementById("repTimestamp"),
        repPostureBadge: document.getElementById("repPostureBadge"),
        downloadReportBtn: document.getElementById("downloadReportBtn"),
        countCritical: document.getElementById("countCritical"),
        countHigh: document.getElementById("countHigh"),
        countMedium: document.getElementById("countMedium"),
        countLow: document.getElementById("countLow"),
        countInfo: document.getElementById("countInfo"),
        findingSearchInput: document.getElementById("findingSearchInput"),
        clearSearchBtn: document.getElementById("clearSearchBtn"),
        filterPills: document.querySelectorAll(".filter-pill"),
        pillCountAll: document.getElementById("pillCountAll"),
        pillCountCritical: document.getElementById("pillCountCritical"),
        pillCountHigh: document.getElementById("pillCountHigh"),
        pillCountMedium: document.getElementById("pillCountMedium"),
        pillCountLow: document.getElementById("pillCountLow"),
        expandAllFindingsBtn: document.getElementById("expandAllFindingsBtn"),
        collapseAllFindingsBtn: document.getElementById("collapseAllFindingsBtn"),
        findingsList: document.getElementById("findingsList"),
        noFilterMatches: document.getElementById("noFilterMatches"),
        resetFiltersBtn: document.getElementById("resetFiltersBtn"),

        // Endpoints
        surfaceEndpointsCount: document.getElementById("surfaceEndpointsCount"),
        surfaceFormsCount: document.getElementById("surfaceFormsCount"),
        surfaceVulnEndpointsCount: document.getElementById("surfaceVulnEndpointsCount"),
        surfaceTableBody: document.getElementById("surfaceTableBody"),

        // History
        historyCardsGrid: document.getElementById("historyCardsGrid"),
        refreshHistoryBtn: document.getElementById("refreshHistoryBtn"),

        toastContainer: document.getElementById("toastContainer")
    };

    function escapeHtml(str) {
        if (str === null || str === undefined) return "";
        const div = document.createElement("div");
        div.textContent = String(str);
        return div.innerHTML;
    }

    function showToast(message, type = "info", duration = 3000) {
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        const icon = type === "success" ? "✓" : type === "error" ? "⚠" : "ℹ";
        toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
        elements.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(10px)";
            toast.style.transition = "all 0.25s ease";
            setTimeout(() => toast.remove(), 250);
        }, duration);
    }

    function setStatus(statusClass, label) {
        elements.statusIndicator.className = `status-indicator ${statusClass}`;
        elements.statusText.textContent = label;
    }

    function switchView(viewName) {
        state.activeView = viewName;
        elements.navTabs.forEach(tab => {
            const isActive = tab.dataset.view === viewName;
            tab.classList.toggle("active", isActive);
            tab.setAttribute("aria-selected", isActive ? "true" : "false");
        });

        elements.viewPanels.forEach(panel => {
            const isTarget = panel.id === `view-${viewName}`;
            panel.classList.toggle("active", isTarget);
        });

        if (viewName === "history") {
            loadHistory();
        }
    }

    window.switchView = switchView;

    // --- Authentication Accordion Toggle ---
    if (elements.authAccordionToggle) {
        elements.authAccordionToggle.addEventListener("click", () => {
            const isHidden = elements.authAccordionContent.style.display === "none";
            elements.authAccordionContent.style.display = isHidden ? "block" : "none";
            elements.authAccordionToggle.querySelector(".accordion-chevron").innerHTML = isHidden ? "&#9662;" : "&#9656;";
        });
    }

    // --- Slider & Clear Controls ---
    elements.maxPagesSlider.addEventListener("input", (e) => {
        elements.maxPagesInput.value = e.target.value;
        elements.maxPagesDisplay.textContent = `${e.target.value} pages`;
    });

    elements.clearTargetBtn.addEventListener("click", () => {
        elements.targetInput.value = "";
        elements.targetInput.focus();
    });

    elements.togglePasswordBtn.addEventListener("click", () => {
        const isPass = elements.passwordInput.type === "password";
        elements.passwordInput.type = isPass ? "text" : "password";
        elements.togglePasswordBtn.textContent = isPass ? "🔒" : "👁";
    });

    // --- Scan Execution ---
    elements.scanForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (state.isScanning) return;

        let rawTarget = elements.targetInput.value.trim();
        if (!rawTarget) {
            elements.errorText.textContent = "Please provide a valid target URL.";
            elements.errorMsg.style.display = "block";
            return;
        }

        if (!rawTarget.startsWith("http://") && !rawTarget.startsWith("https://")) {
            rawTarget = "http://" + rawTarget;
            elements.targetInput.value = rawTarget;
        }

        elements.errorMsg.style.display = "none";
        state.isScanning = true;
        elements.runBtn.disabled = true;
        elements.runBtn.querySelector(".btn-text").textContent = "Scan in progress...";
        setStatus("scanning", "SCANNING");
        elements.consolePulse.style.display = "inline-block";

        elements.consoleTargetTitle.textContent = `TARGET: ${rawTarget}`;
        elements.terminal.innerHTML = "";

        switchView("console");
        showToast(`Audit started against ${rawTarget}`, "info");

        const payload = {
            target: rawTarget,
            login_url: elements.loginUrlInput.value.trim(),
            username: elements.usernameInput.value.trim(),
            password: elements.passwordInput.value,
            max_pages: parseInt(elements.maxPagesInput.value, 10) || 25
        };

        try {
            const resp = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const data = await resp.json();

            if (!resp.ok) {
                throw new Error(data.error || "Scan failed unexpectedly.");
            }

            state.currentScanId = data.scan.id;
            state.currentScan = data.scan;
            state.currentLog = data.log || [];

            await streamLogToTerminal(data.log || []);

            setStatus("idle", "COMPLETE");
            elements.consolePulse.style.display = "none";
            showToast(`Scan complete: ${data.scan.total_findings} finding(s) detected.`, "success");

            elements.activeTargetBar.style.display = "flex";
            elements.targetUrlChip.textContent = data.scan.target;
            elements.targetFindingsChip.textContent = `${data.scan.total_findings} Findings`;
            elements.headerDownloadBtn.style.display = "inline-flex";

            extractAttackSurface(data.scan, data.log);
            renderFindingsReport(data.scan);
            loadHistory();

            setTimeout(() => {
                switchView("findings");
            }, 600);

        } catch (err) {
            elements.errorText.textContent = err.message || "Failed to execute scan.";
            elements.errorMsg.style.display = "block";
            setStatus("idle", "ERROR");
            elements.consolePulse.style.display = "none";
            showToast(`Scan failed: ${err.message}`, "error");

            const errLine = document.createElement("div");
            errLine.className = "line";
            errLine.style.color = "var(--critical)";
            errLine.innerHTML = `<span class="t-time">${new Date().toLocaleTimeString()}</span><span class="t-text">[ERROR] ${escapeHtml(err.message)}</span>`;
            elements.terminal.appendChild(errLine);
        } finally {
            state.isScanning = false;
            elements.runBtn.disabled = false;
            elements.runBtn.querySelector(".btn-text").textContent = "Start Security Scan";
        }
    });

    function streamLogToTerminal(logLines) {
        return new Promise((resolve) => {
            if (!logLines || logLines.length === 0) {
                resolve();
                return;
            }

            let idx = 0;
            function nextLine() {
                if (idx >= logLines.length) {
                    resolve();
                    return;
                }

                const entry = logLines[idx];
                const line = document.createElement("div");
                const isFinding = entry.text && entry.text.startsWith("[!]");
                line.className = "line" + (isFinding ? " finding" : "");
                line.innerHTML = `<span class="t-time">${entry.time}</span><span class="t-text">${escapeHtml(entry.text)}</span>`;
                elements.terminal.appendChild(line);

                if (state.autoscroll) {
                    elements.terminal.scrollTop = elements.terminal.scrollHeight;
                }

                idx++;
                setTimeout(nextLine, isFinding ? 100 : 25);
            }

            nextLine();
        });
    }

    // --- Attack Surface Synthesis ---
    function extractAttackSurface(scan, log) {
        const endpointsMap = new Map();
        let targetBase = scan.target.replace(/\/$/, "");

        endpointsMap.set(targetBase, {
            url: targetBase,
            methods: new Set(["GET"]),
            params: new Set(),
            vulns: []
        });

        if (Array.isArray(log)) {
            log.forEach(item => {
                const txt = item.text || "";
                if (txt.includes("Missing on")) {
                    const match = txt.match(/Missing on \d+ page\(s\): ([^\+]+)/);
                    if (match) {
                        match[1].split(",").forEach(rawUrl => {
                            const clean = rawUrl.trim();
                            if (clean && clean.startsWith("http")) {
                                if (!endpointsMap.has(clean)) {
                                    endpointsMap.set(clean, { url: clean, methods: new Set(["GET"]), params: new Set(), vulns: [] });
                                }
                            }
                        });
                    }
                }
            });
        }

        if (scan.findings && scan.findings.length) {
            scan.findings.forEach(f => {
                const url = f.url || scan.target;
                if (!endpointsMap.has(url)) {
                    endpointsMap.set(url, { url: url, methods: new Set(["GET"]), params: new Set(), vulns: [] });
                }
                const entry = endpointsMap.get(url);
                entry.vulns.push({ title: f.title, severity: f.severity });

                if (f.title.includes("in '")) {
                    const match = f.title.match(/in '([^']+)'/);
                    if (match) entry.params.add(match[1]);
                }
                if (f.evidence && f.evidence.includes("username=")) {
                    entry.methods.add("POST");
                    entry.params.add("username");
                    entry.params.add("password");
                }
            });
        }

        const list = Array.from(endpointsMap.values());
        state.discoveredEndpoints = list;
        renderAttackSurface(list);
    }

    function renderAttackSurface(endpoints) {
        elements.surfaceEndpointsCount.textContent = endpoints.length;
        let totalForms = 0;
        let vulnEndpoints = 0;

        const rowsHtml = endpoints.map(ep => {
            const hasVuln = ep.vulns.length > 0;
            if (hasVuln) vulnEndpoints++;
            if (ep.methods.has("POST") || ep.params.size > 0) totalForms++;

            const statusBadge = hasVuln
                ? `<span class="table-status-pill vuln">${ep.vulns.length} VULN(S)</span>`
                : `<span class="table-status-pill clean">CLEAN</span>`;

            const methodsBadges = Array.from(ep.methods).map(m =>
                `<span class="method-tag ${m.toLowerCase()}">${m}</span>`
            ).join(" ");

            const paramsBadges = ep.params.size > 0
                ? Array.from(ep.params).map(p => `<span class="param-pill mono">${escapeHtml(p)}</span>`).join(" ")
                : `<span style="color:var(--text-dim);font-size:11px;">None</span>`;

            const vulnsBadges = ep.vulns.length > 0
                ? ep.vulns.map(v => `<span class="sev-badge sev-${v.severity}" style="font-size:10px;padding:1px 5px;margin-right:4px;">${v.severity}</span>`).join(" ")
                : `<span style="color:var(--text-dim);font-size:11px;">Clean</span>`;

            return `
                <tr>
                    <td>${statusBadge}</td>
                    <td><code class="endpoint-code mono">${escapeHtml(ep.url)}</code></td>
                    <td>${methodsBadges}</td>
                    <td>${paramsBadges}</td>
                    <td>${vulnsBadges}</td>
                    <td>
                        <button type="button" class="btn-subtle" onclick="filterFindingsByUrl('${escapeHtml(ep.url)}')">
                            Inspect
                        </button>
                    </td>
                </tr>
            `;
        }).join("");

        elements.surfaceFormsCount.textContent = totalForms;
        elements.surfaceVulnEndpointsCount.textContent = vulnEndpoints;
        elements.endpointsCountBadge.textContent = endpoints.length;
        elements.endpointsCountBadge.style.display = "inline-block";

        elements.surfaceTableBody.innerHTML = rowsHtml || `<tr><td colspan="6" class="table-empty-cell">No endpoint data available.</td></tr>`;
    }

    window.filterFindingsByUrl = function (url) {
        switchView("findings");
        elements.findingSearchInput.value = url;
        state.searchQuery = url.toLowerCase();
        elements.clearSearchBtn.style.display = "block";
        filterFindingsList();
    };

    // --- Findings Renderer ---
    function renderFindingsReport(scan) {
        elements.findingsEmptyState.style.display = "none";
        elements.findingsReportLayout.style.display = "block";

        elements.repScanId.textContent = `SCAN #${scan.id}`;
        elements.repTargetUrl.textContent = scan.target;
        elements.repTimestamp.textContent = new Date(scan.started_at).toLocaleString();

        const counts = scan.severity_counts || { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
        if (counts.Critical > 0) {
            elements.repPostureBadge.textContent = "CRITICAL RISK";
            elements.repPostureBadge.style.background = "var(--critical-dim)";
            elements.repPostureBadge.style.color = "var(--critical)";
            elements.repPostureBadge.style.borderColor = "var(--critical-border)";
        } else if (counts.High > 0) {
            elements.repPostureBadge.textContent = "HIGH RISK";
            elements.repPostureBadge.style.background = "var(--high-dim)";
            elements.repPostureBadge.style.color = "var(--high)";
            elements.repPostureBadge.style.borderColor = "var(--high-border)";
        } else {
            elements.repPostureBadge.textContent = "LOW RISK";
            elements.repPostureBadge.style.background = "var(--accent-dim)";
            elements.repPostureBadge.style.color = "var(--accent)";
            elements.repPostureBadge.style.borderColor = "rgba(16, 185, 129, 0.3)";
        }

        elements.countCritical.textContent = counts.Critical || 0;
        elements.countHigh.textContent = counts.High || 0;
        elements.countMedium.textContent = counts.Medium || 0;
        elements.countLow.textContent = counts.Low || 0;
        elements.countInfo.textContent = counts.Info || 0;

        elements.pillCountAll.textContent = scan.total_findings;
        elements.pillCountCritical.textContent = counts.Critical || 0;
        elements.pillCountHigh.textContent = counts.High || 0;
        elements.pillCountMedium.textContent = counts.Medium || 0;
        elements.pillCountLow.textContent = counts.Low || 0;

        elements.findingsCountBadge.textContent = scan.total_findings;
        elements.findingsCountBadge.style.display = "inline-block";

        filterFindingsList();
    }

    function getRemediationAndCWE(finding) {
        const title = (finding.title || "").toLowerCase();
        if (title.includes("sql injection") || title.includes("sqli")) {
            return VULN_METADATA.sqli;
        } else if (title.includes("xss")) {
            return VULN_METADATA.xss;
        } else if (title.includes("idor")) {
            return VULN_METADATA.idor;
        } else if (title.includes("header")) {
            return VULN_METADATA.headers;
        } else if (title.includes("cookie")) {
            return VULN_METADATA.cookie;
        }
        return {
            cwe: "General Web Vulnerability",
            owasp: "OWASP Top 10",
            remediation: "Review server response and request handling to apply defensive coding practices."
        };
    }

    function filterFindingsList() {
        if (!state.currentScan) return;
        const findings = state.currentScan.findings || [];
        const filterSev = state.activeSevFilter;
        const q = state.searchQuery.toLowerCase().trim();

        const filtered = findings.filter(f => {
            const matchSev = filterSev === "ALL" || f.severity.toLowerCase() === filterSev.toLowerCase();
            if (!matchSev) return false;
            if (!q) return true;

            const textSearch = (
                (f.title || "") + " " +
                (f.url || "") + " " +
                (f.description || "") + " " +
                (f.evidence || "")
            ).toLowerCase();

            return textSearch.includes(q);
        });

        if (filtered.length === 0) {
            elements.findingsList.innerHTML = "";
            elements.noFilterMatches.style.display = "block";
            return;
        }

        elements.noFilterMatches.style.display = "none";
        elements.findingsList.innerHTML = filtered.map((f, idx) => {
            const meta = getRemediationAndCWE(f);
            return `
                <article class="finding-card sev-${f.severity} ${idx === 0 ? 'open' : ''}">
                    <div class="finding-top">
                        <span class="sev-badge sev-${f.severity}">${f.severity}</span>
                        <div class="finding-header-content">
                            <div class="finding-title">${escapeHtml(f.title)}</div>
                            <div class="finding-endpoint-preview mono">${escapeHtml(f.url)}</div>
                        </div>
                        <span class="finding-chevron">▶</span>
                    </div>
                    <div class="finding-body">
                        <div class="detail-row">
                            <span class="detail-label">ENDPOINT:</span>
                            <div class="endpoint-box">
                                <span class="endpoint-code mono">${escapeHtml(f.url)}</span>
                                <button type="button" class="copy-mini-btn" onclick="copyText('${escapeHtml(f.url)}', 'URL copied!')" title="Copy URL">📋</button>
                            </div>
                        </div>
                        <div class="cwe-tag">${escapeHtml(meta.cwe)} &bull; ${escapeHtml(meta.owasp)}</div>
                        
                        <div class="desc-box">
                            <div class="section-label">DESCRIPTION & IMPACT</div>
                            <p class="desc-text">${escapeHtml(f.description)}</p>
                        </div>

                        ${f.evidence ? `
                        <div class="evidence-box">
                            <div class="evidence-top">
                                <span class="section-label">EVIDENCE & PAYLOAD</span>
                                <button type="button" class="btn-subtle" style="font-size:11px;" onclick="copyText('${escapeHtml(f.evidence)}', 'Evidence copied!')">Copy</button>
                            </div>
                            <pre class="evidence-code">${escapeHtml(f.evidence)}</pre>
                        </div>` : ''}

                        <div class="remediation-box">
                            <div class="section-label" style="color:#10B981;">RECOMMENDED REMEDIATION</div>
                            <p class="remediation-text">${escapeHtml(meta.remediation)}</p>
                        </div>
                    </div>
                </article>
            `;
        }).join("");

        elements.findingsList.querySelectorAll(".finding-card").forEach(card => {
            const top = card.querySelector(".finding-top");
            top.addEventListener("click", () => card.classList.toggle("open"));
        });
    }

    window.copyText = function (text, successMsg = "Copied to clipboard!") {
        navigator.clipboard.writeText(text).then(() => {
            showToast(successMsg, "success", 2000);
        }).catch(() => {
            showToast("Failed to copy", "error");
        });
    };

    // --- Search & Filters ---
    elements.findingSearchInput.addEventListener("input", (e) => {
        state.searchQuery = e.target.value;
        elements.clearSearchBtn.style.display = e.target.value ? "block" : "none";
        filterFindingsList();
    });

    elements.clearSearchBtn.addEventListener("click", () => {
        elements.findingSearchInput.value = "";
        state.searchQuery = "";
        elements.clearSearchBtn.style.display = "none";
        filterFindingsList();
    });

    elements.filterPills.forEach(pill => {
        pill.addEventListener("click", () => {
            elements.filterPills.forEach(p => p.classList.remove("active"));
            pill.classList.add("active");
            state.activeSevFilter = pill.dataset.sev;
            filterFindingsList();
        });
    });

    document.querySelectorAll(".metric-card").forEach(card => {
        card.addEventListener("click", () => {
            const sev = card.dataset.filterSev;
            state.activeSevFilter = sev;
            elements.filterPills.forEach(p => {
                p.classList.toggle("active", p.dataset.sev.toLowerCase() === sev.toLowerCase());
            });
            filterFindingsList();
            showToast(`Filtering by ${sev}`, "info", 1500);
        });
    });

    elements.expandAllFindingsBtn.addEventListener("click", () => {
        elements.findingsList.querySelectorAll(".finding-card").forEach(c => c.classList.add("open"));
    });

    elements.collapseAllFindingsBtn.addEventListener("click", () => {
        elements.findingsList.querySelectorAll(".finding-card").forEach(c => c.classList.remove("open"));
    });

    elements.resetFiltersBtn.addEventListener("click", () => {
        elements.findingSearchInput.value = "";
        state.searchQuery = "";
        elements.clearSearchBtn.style.display = "none";
        state.activeSevFilter = "ALL";
        elements.filterPills.forEach(p => p.classList.toggle("active", p.dataset.sev === "ALL"));
        filterFindingsList();
    });

    // --- Terminal Controls ---
    elements.copyLogBtn.addEventListener("click", () => {
        if (!state.currentLog || state.currentLog.length === 0) {
            showToast("No log content to copy.", "info");
            return;
        }
        const text = state.currentLog.map(l => `[${l.time}] ${l.text}`).join("\n");
        window.copyText(text, "Terminal log copied!");
    });

    elements.autoscrollToggleBtn.addEventListener("click", () => {
        state.autoscroll = !state.autoscroll;
        elements.autoscrollToggleBtn.textContent = `Autoscroll: ${state.autoscroll ? 'ON' : 'OFF'}`;
    });

    // --- Report Download ---
    function triggerDownloadReport() {
        if (!state.currentScanId) {
            showToast("No report loaded to export.", "info");
            return;
        }
        window.location.href = `/api/report/${state.currentScanId}/download`;
        showToast("Exporting assessment report...", "success");
    }

    elements.downloadReportBtn.addEventListener("click", triggerDownloadReport);
    elements.headerDownloadBtn.addEventListener("click", triggerDownloadReport);

    // --- History ---
    async function loadHistory() {
        try {
            const resp = await fetch("/api/history");
            const items = await resp.json();

            elements.historyCountBadge.textContent = items.length || 0;

            if (!items.length) {
                elements.historyCardsGrid.innerHTML = `
                    <div class="history-empty-card">
                        <h3>No Scans Recorded</h3>
                        <p>Completed scans will appear here for reference and export.</p>
                    </div>
                `;
                return;
            }

            elements.historyCardsGrid.innerHTML = items.map(item => {
                const worst = SEVERITY_ORDER.find(s => item.severity_counts && item.severity_counts[s] > 0) || "Info";
                const isSelected = item.id === state.currentScanId;

                const sevPills = SEVERITY_ORDER.filter(s => item.severity_counts && item.severity_counts[s] > 0).map(s => {
                    return `<span class="sev-badge sev-${s}">${s}: ${item.severity_counts[s]}</span>`;
                }).join(" ");

                return `
                    <div class="history-card ${isSelected ? 'active' : ''}" data-scan-id="${item.id}">
                        <div class="hist-top">
                            <span class="mono">SCAN #${item.id}</span>
                            <span class="mono">${new Date(item.started_at).toLocaleTimeString()}</span>
                        </div>
                        <div class="hist-target mono">${escapeHtml(item.target)}</div>
                        <div class="hist-findings-row">
                            <span style="font-weight:700;font-size:12px;color:${SEVERITY_COLORS[worst]};">${item.total_findings} Finding(s)</span>
                            ${sevPills}
                        </div>
                        <div class="hist-actions">
                            <button type="button" class="hist-btn" onclick="loadArchivedScan('${item.id}')">
                                Inspect
                            </button>
                            <button type="button" class="hist-btn" onclick="window.location.href='/api/report/${item.id}/download'">
                                Download
                            </button>
                        </div>
                    </div>
                `;
            }).join("");

        } catch (err) {
            console.error("Failed to load history:", err);
        }
    }

    window.loadArchivedScan = async function (scanId) {
        try {
            const resp = await fetch(`/api/history/${scanId}`);
            if (!resp.ok) throw new Error("Scan not found.");
            const data = await resp.json();

            state.currentScanId = scanId;
            state.currentScan = data.scan;
            state.currentLog = data.log || [];

            elements.activeTargetBar.style.display = "flex";
            elements.targetUrlChip.textContent = data.scan.target;
            elements.targetFindingsChip.textContent = `${data.scan.total_findings} Findings`;
            elements.headerDownloadBtn.style.display = "inline-flex";

            elements.consoleTargetTitle.textContent = `TARGET: ${data.scan.target}`;
            elements.terminal.innerHTML = (data.log || []).map(entry => {
                const isFinding = entry.text && entry.text.startsWith("[!]");
                return `<div class="line${isFinding ? ' finding' : ''}"><span class="t-time">${entry.time}</span><span class="t-text">${escapeHtml(entry.text)}</span></div>`;
            }).join("");

            extractAttackSurface(data.scan, data.log);
            renderFindingsReport(data.scan);
            switchView("findings");
            loadHistory();
            showToast(`Loaded scan #${scanId}`, "info");

        } catch (err) {
            showToast(`Failed to load scan: ${err.message}`, "error");
        }
    };

    elements.refreshHistoryBtn.addEventListener("click", () => {
        loadHistory();
        showToast("History refreshed", "info", 1500);
    });

    elements.navTabs.forEach(tab => {
        tab.addEventListener("click", () => {
            switchView(tab.dataset.view);
        });
    });

    window.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            if (!state.isScanning) {
                elements.scanForm.dispatchEvent(new Event("submit", { cancelable: true }));
            }
        }
        if (e.key === "/" && state.activeView === "findings" && document.activeElement !== elements.findingSearchInput) {
            e.preventDefault();
            elements.findingSearchInput.focus();
        }
        if (e.key === "Escape" && document.activeElement === elements.findingSearchInput) {
            elements.findingSearchInput.value = "";
            state.searchQuery = "";
            elements.clearSearchBtn.style.display = "none";
            filterFindingsList();
            elements.findingSearchInput.blur();
        }
    });

    loadHistory();

})();

