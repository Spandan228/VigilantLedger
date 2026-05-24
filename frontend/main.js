/* ============================================================================
   PROJECT: VigilantLedger
   FILE: main.js
   DESCRIPTION: Client-side operations engine for loading dashboard feeds,
                handling REST actions, rendering charts and terminal outputs.
   ============================================================================ */

// Global State
let activeReferenceDigest = null;
let cachedBlocks = [];
let blockPage = 0;
const blocksPerPage = 5;

// Simulated Persona profiles
const personas = {
    "auditor": {
        name: "Carol - Compliance Auditor",
        db_user: "UserAuditor",
        app_user: "CarolAudit",
        app_role: "ComplianceAuditor",
        app_region: "ALL",
        description: "Enterprise compliance auditor. Access to records in ALL regions. Granted UNMASK rights (SSN and Email details are fully visible)."
    },
    "manager": {
        name: "Bob - Financial Manager",
        db_user: "UserManager",
        app_user: "BobMgr",
        app_role: "FinancialManager",
        app_region: "ALL",
        description: "Regional Manager. Access to records in ALL regions. Granted UNMASK rights (SSN and Email details are fully visible)."
    },
    "accountant-east": {
        name: "Alice - Staff Accountant (East Region)",
        db_user: "UserAccountantEast",
        app_user: "AliceAcct",
        app_role: "StaffAccountant",
        app_region: "East",
        description: "Accountant for East region. Restricted by row security (can ONLY see Region = 'East'). Masked by column-level security (SSN and Email are redacted)."
    },
    "accountant-west": {
        name: "Dave - Staff Accountant (West Region)",
        db_user: "UserAccountantWest",
        app_user: "DaveAcct",
        app_role: "StaffAccountant",
        app_region: "West",
        description: "Accountant for West region. Restricted by row security (can ONLY see Region = 'West'). Masked by column-level security (SSN and Email are redacted)."
    },
    "admin": {
        name: "Administrator (Full DB Override)",
        db_user: "sa",
        app_user: "sa",
        app_role: "sa",
        app_region: "ALL",
        description: "Root database administrator. Bypasses all row filter boundaries and columns masking."
    }
};

// XSS HTML Sanitization Helper
function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ============================================================================
// SYSTEM BOOT & SYNC ACTIONS
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
    // 1. Run Initial Sync
    syncFeeds();
    
    // 2. Load default persona profile
    loadPersonaProfile();

    // 3. Register Event Listeners for Sandbox & Verifier Buttons
    document.getElementById("sync-btn").addEventListener("click", syncFeeds);
    document.getElementById("run-audit-btn").addEventListener("click", runCryptographicAudit);
    document.getElementById("send-query-btn").addEventListener("click", executePersonaQuery);
    document.getElementById("run-chrono-btn").addEventListener("click", executeChronoQuery);
    document.getElementById("fetch-history-btn").addEventListener("click", fetchLedgerHistory);
    document.getElementById("inject-backdoor-btn").addEventListener("click", runBackdoorInjection);
    document.getElementById("delete-logs-btn").addEventListener("click", runDeleteLogsTamper);
    document.getElementById("save-digest-btn").addEventListener("click", saveBaseDigest);
    document.getElementById("verify-forged-btn").addEventListener("click", runForgedDigestVerify);
    document.getElementById("scan-threats-btn").addEventListener("click", executeSentinelScan);
    document.getElementById("resolve-threats-btn").addEventListener("click", executeSentinelResolve);

    // Initial slider timestamp bind
    updateChronoSlider(document.getElementById("chrono-slider").value);
});

// Typing effect helper for consoles
function typeConsoleLines(elementId, lines, speedMs = 15, onComplete = null) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerHTML = "";
    let lineIdx = 0;
    
    function printNextLine() {
        if (lineIdx < lines.length) {
            const line = lines[lineIdx];
            el.innerHTML += (lineIdx > 0 ? "<br/>" : "") + line;
            el.scrollTop = el.scrollHeight;
            lineIdx++;
            setTimeout(printNextLine, speedMs * (line.length * 0.12 + 4));
        } else if (onComplete) {
            onComplete();
        }
    }
    printNextLine();
}

async function syncFeeds() {
    try {
        // Fetch status stats
        const response = await fetch("/api/status");
        if (!response.ok) throw new Error("Status endpoint unavailable.");
        const data = await response.json();

        // Update active digest in cache
        activeReferenceDigest = JSON.stringify(data.active_digest);

        // Update KPI metrics
        updateKPIs(data);

        // Render Gauge Chart
        renderIntegrityGauge(data.is_secure);

        // Render Sidebar Digest cache
        const sidebarBox = document.getElementById("sidebar-digest");
        sidebarBox.innerHTML = `
            <strong>Block ID:</strong> ${escapeHtml(data.active_digest.block_id)}<br/>
            <strong>Hash:</strong> <span style="color:#00f0ff;">${escapeHtml(data.active_digest.hash.slice(0, 16))}...</span>
        `;

        // Render Ledger tab digest view
        document.getElementById("tab-ledger-digest").innerText = JSON.stringify(data.active_digest, null, 2);

        // Sync auxiliary lists
        syncBlockchainFeeds();
        syncAlertsFeed();
        
    } catch (err) {
        console.error("Feed Sync Error:", err);
    }
}

function updateKPIs(data) {
    // 1. Block Height
    document.querySelector("#kpi-block-height h2").innerText = `#${data.block_height}`;
    
    // 2. Action Counts
    document.querySelector("#kpi-ledger-actions h2").innerText = data.transaction_count;

    // 3. Chain Integrity Status
    const integrityHeader = document.querySelector("#kpi-integrity");
    const integrityVal = document.querySelector("#kpi-integrity h2");
    const integrityBadge = document.getElementById("integrity-status-badge");
    
    integrityHeader.className = "kpi-card " + (data.is_secure ? "secure-state" : "threat-state");
    integrityVal.innerText = data.is_secure ? "HEALTHY" : "COMPROMISED";
    integrityVal.style.color = data.is_secure ? "#10b981" : "#ef4444";
    integrityBadge.className = data.is_secure ? "neon-badge-green" : "neon-badge-red";
    integrityBadge.innerText = data.is_secure ? "SECURE" : "ALERTED";

    // 4. Active Threats Alerts
    const threatHeader = document.querySelector("#kpi-active-threats");
    const threatVal = document.querySelector("#kpi-active-threats h2");
    const threatBadge = document.getElementById("active-threats-badge");

    threatHeader.className = "kpi-card " + (data.active_alerts === 0 ? "secure-state" : "threat-state");
    threatVal.innerText = `${data.total_alerts} Total`;
    threatBadge.className = data.active_alerts === 0 ? "neon-badge-green" : "neon-badge-red";
    threatBadge.innerText = data.active_alerts === 0 ? "CLEAN" : `${data.active_alerts} ACTIVE`;

    // 5. Sidebar State Badge
    const stateBadge = document.getElementById("db-state-badge");
    stateBadge.className = "state-label " + (data.is_secure ? "text-green" : "text-red");
    stateBadge.innerText = data.is_secure ? "SECURE" : "COMPROMISED";
}

async function syncBlockchainFeeds() {
    try {
        // Fetch blocks
        const resBlocks = await fetch("/api/ledger/blocks");
        const blocks = await resBlocks.json();
        
        // Render blockchain line chart
        renderBlockchainChart(blocks);

        // Render blockchain horizontal nodes map
        renderBlockchainNodesMap(blocks);

        // Fetch Raw transactions and populate table
        const resTxs = await fetch("/api/ledger/transactions");
        const txs = await resTxs.json();
        
        const tbody = document.querySelector("#transactions-table tbody");
        if (txs && txs.length > 0) {
            tbody.innerHTML = txs.map(t => `
                <tr>
                    <td>${escapeHtml(t.transaction_id)}</td>
                    <td>${escapeHtml(t.block_id)}</td>
                    <td>${escapeHtml(t.transaction_ordinal)}</td>
                    <td>${escapeHtml(new Date(t.commit_time).toLocaleString())}</td>
                    <td><code>${escapeHtml(t.principal_name)}</code></td>
                    <td><code class="text-cyan">${escapeHtml(t.table_hash)}</code></td>
                </tr>
            `).join("");
        } else {
            tbody.innerHTML = `<tr><td colspan="6" class="placeholder">No transactions recorded.</td></tr>`;
        }
    } catch (err) {
        console.error("Blockchain Feed Sync Error:", err);
    }
}

// ============================================================================
// SIDEBAR COLLAPSE ENGINE
// ============================================================================
function toggleSidebar() {
    const sidebar = document.querySelector(".sidebar");
    sidebar.classList.toggle("collapsed");
    
    const btn = document.getElementById("sidebar-toggle");
    if (sidebar.classList.contains("collapsed")) {
        btn.innerText = "▶";
    } else {
        btn.innerText = "◀";
    }
    
    // Trigger responsive Plotly gauge resize
    setTimeout(() => {
        const activeTab = document.querySelector(".tab-content.active").id;
        if (activeTab === "tab-ledger") {
            Plotly.Plots.resize("blockchain-chart");
        } else if (activeTab === "tab-chrono") {
            Plotly.Plots.resize("temporal-chart");
        } else if (activeTab === "tab-sentinel") {
            Plotly.Plots.resize("alerts-chart");
        }
        Plotly.Plots.resize("integrity-gauge");
    }, 305);
}

// ============================================================================
// BLOCKCHAIN MAP PAGINATION
// ============================================================================
function renderBlockchainNodesMap(blocks) {
    cachedBlocks = blocks || [];
    const row = document.getElementById("blockchain-map-row");
    
    if (cachedBlocks.length === 0) {
        row.innerHTML = `<div class="placeholder">No blocks logged in database ledger.</div>`;
        document.getElementById("block-prev-btn").disabled = true;
        document.getElementById("block-next-btn").disabled = true;
        document.getElementById("block-pager-info").innerText = "Page 0 of 0";
        return;
    }

    // Sort chronological (ascending)
    const sorted = [...cachedBlocks].sort((a,b) => a.block_id - b.block_id);
    const totalPages = Math.ceil(sorted.length / blocksPerPage);
    
    // Bound page index
    if (blockPage >= totalPages) blockPage = totalPages - 1;
    if (blockPage < 0) blockPage = 0;

    // Slice current page
    const startIdx = blockPage * blocksPerPage;
    const endIdx = startIdx + blocksPerPage;
    const sliced = sorted.slice(startIdx, endIdx);

    row.innerHTML = sliced.map((b, idx) => {
        const arrow = idx > 0 ? `<div class="chain-arrow">➔</div>` : '';
        return `
            ${arrow}
            <div class="block-node">
                <div class="block-node-header">
                    <span>📦 BLOCK #${escapeHtml(b.block_id)}</span>
                    <span style="color:#cbd5e1; font-size:11px;">Txs: ${escapeHtml(b.block_size)}</span>
                </div>
                <div class="block-node-body">
                    <strong>Root Hash:</strong><br/>
                    <span class="text-cyan">${escapeHtml(b.transactions_root_hash.slice(0, 16))}...</span><br/>
                    <strong>Prev Link:</strong><br/>
                    <span style="color:#cbd5e1;">${escapeHtml(b.previous_block_hash.slice(0, 16))}...</span>
                </div>
            </div>
        `;
    }).join("");

    // Update pager info UI
    document.getElementById("block-pager-info").innerText = `Page ${blockPage + 1} of ${totalPages}`;
    document.getElementById("block-prev-btn").disabled = (blockPage === 0);
    document.getElementById("block-next-btn").disabled = (blockPage >= totalPages - 1);
}

function prevBlockPage() {
    if (blockPage > 0) {
        blockPage--;
        renderBlockchainNodesMap(cachedBlocks);
    }
}

function nextBlockPage() {
    const totalPages = Math.ceil(cachedBlocks.length / blocksPerPage);
    if (blockPage < totalPages - 1) {
        blockPage++;
        renderBlockchainNodesMap(cachedBlocks);
    }
}

// ============================================================================
// TABLE SEARCH FILTER ENGINES
// ============================================================================
function filterTable(inputId, tableId) {
    const query = document.getElementById(inputId).value.toLowerCase();
    const rows = document.querySelectorAll(`#${tableId} tbody tr`);
    
    rows.forEach(r => {
        if (r.querySelector(".placeholder")) return;
        const text = r.innerText.toLowerCase();
        r.style.display = text.includes(query) ? "" : "none";
    });
}

function filterTransactionsTable() { filterTable("tx-search-input", "transactions-table"); }
function filterHistoryTable() { filterTable("history-search-input", "history-table"); }
function filterAlertsTable() { filterTable("alerts-search-input", "alerts-table"); }

async function syncAlertsFeed() {
    try {
        const res = await fetch("/api/sentinel/alerts");
        const alerts = await res.json();

        // Render Plotly pie chart
        renderAlertsPieChart(alerts);

        // Populate Alerts Table
        const tbody = document.querySelector("#alerts-table tbody");
        if (alerts && alerts.length > 0) {
            tbody.innerHTML = alerts.map(a => {
                const status = a.IsResolved ? `<span class="badge-active">✅ Resolved</span>` : `<span class="text-red">🚨 ACTIVE</span>`;
                let severityColor = "text-cyan";
                if (a.Severity === "CRITICAL") severityColor = "text-red";
                else if (a.Severity === "HIGH") severityColor = "text-orange";
                else if (a.Severity === "MEDIUM") severityColor = "text-orange";

                return `
                    <tr>
                        <td>${escapeHtml(a.AlertID)}</td>
                        <td>${escapeHtml(new Date(a.AlertTime).toLocaleString())}</td>
                        <td><span class="${severityColor}" style="font-weight:bold;">${escapeHtml(a.Severity)}</span></td>
                        <td><code>${escapeHtml(a.SourceUser)}</code></td>
                        <td style="max-width:350px; font-size:12px; line-height:1.4;">${escapeHtml(a.Details)}</td>
                        <td>${status}</td>
                    </tr>
                `;
            }).join("");
        } else {
            tbody.innerHTML = `<tr><td colspan="6" class="placeholder">No incidents recorded. System is clean.</td></tr>`;
        }
        filterAlertsTable(); // Re-apply current search query filter if any
    } catch (err) {
        console.error("Alerts Feed Sync Error:", err);
    }
}

// ============================================================================
// TAB VIEWPORT CONTROLLER
// ============================================================================
function switchTab(evt, tabId) {
    // Hide all contents
    const contents = document.querySelectorAll(".tab-content");
    contents.forEach(c => c.classList.remove("active"));

    // Remove active state from nav links
    const tabLinks = document.querySelectorAll(".tab-link");
    tabLinks.forEach(t => t.classList.remove("active"));

    // Show active tab pane & add active class to button
    document.getElementById(tabId).classList.add("active");
    evt.currentTarget.classList.add("active");

    // Re-render Plotly charts as they sometimes require dimension recalculation on unhide
    if (tabId === "tab-ledger") {
        syncBlockchainFeeds();
    } else if (tabId === "tab-chrono") {
        renderTemporalChart();
    } else if (tabId === "tab-sentinel") {
        syncAlertsFeed();
    }
}

// ============================================================================
// TAB 1 INTERACTION: CRYPTOGRAPHIC VERIFICATION
// ============================================================================
async function runCryptographicAudit() {
    const alertBox = document.getElementById("audit-result-alert");
    alertBox.style.display = "none";
    
    if (!activeReferenceDigest) {
        alertBox.className = "audit-alert alert-error";
        alertBox.innerText = "Error: Reference digest missing. Run Page Sync first.";
        alertBox.style.display = "block";
        return;
    }

    try {
        const res = await fetch("/api/ledger/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ digest: activeReferenceDigest, corrupt: false })
        });
        const data = await res.json();
        
        if (data.success) {
            alertBox.className = "audit-alert alert-success";
            alertBox.innerText = `✅ Success: ${data.message}`;
        } else {
            alertBox.className = "audit-alert alert-error";
            alertBox.innerText = `🚨 Cryptographic Mismatch: ${data.message}`;
        }
        alertBox.style.display = "block";
        syncFeeds(); // Reload stats to show latest status
    } catch (err) {
        alertBox.className = "audit-alert alert-error";
        alertBox.innerText = `System Error executing audit: ${err.message}`;
        alertBox.style.display = "block";
    }
}

// ============================================================================
// TAB 2 INTERACTION: IDENTITY GATEWAY SIMULATOR
// ============================================================================
function loadPersonaProfile() {
    const key = document.getElementById("persona-select").value;
    const p = personas[key];
    const box = document.getElementById("persona-profile");
    
    box.innerHTML = `
        <h5>${p.name}</h5>
        <p><strong>DB Impersonation Login:</strong> <code>${p.db_user}</code></p>
        <p><strong>App Session Role:</strong> <code>${p.app_role}</code></p>
        <p><strong>Regional Gate Limit:</strong> <code>${p.app_region}</code></p>
        <p class="desc">${p.description}</p>
    `;
}

async function executePersonaQuery() {
    const key = document.getElementById("persona-select").value;
    const p = personas[key];
    const consoleBox = document.getElementById("impersonation-console");
    consoleBox.className = "cyber-console";
    
    const lines = [
        `[~] Establishing secure tunnel gateway...`,
        `[~] Setting SESSION_CONTEXT values: AppUser='${p.app_user}', AppRole='${p.app_role}', AppRegion='${p.app_region}'`,
        `[~] Context binder stored procedure 'Core.sp_SetContext' completed successfully.`,
        `[~] Executing Impersonation context: EXECUTE AS USER = '${p.db_user}'...`,
        `[~] Logging database read access to immutable Ledger: Audit.AccessLogs... [OK]`,
        `[+] Dispatching query: SELECT CustomerID, CustomerName, SSN, Email, Region, Balance FROM Core.Accounts;`
    ];

    typeConsoleLines("impersonation-console", lines, 10, async () => {
        try {
            const res = await fetch("/api/persona/query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    db_user: p.db_user,
                    app_user: p.app_user,
                    app_role: p.app_role,
                    app_region: p.app_region
                })
            });
            
            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            
            consoleBox.innerHTML += `<br/>[+] Database returned ${escapeHtml(data.length)} records. RLS filter applied.`;
            consoleBox.scrollTop = consoleBox.scrollHeight;
            
            const tbody = document.querySelector("#persona-results-table tbody");
            if (data.length > 0) {
                tbody.innerHTML = data.map(row => {
                    const ssnClass = (row.SSN && (row.SSN.includes("XXX") || row.SSN.includes("xxx"))) ? "cell-masked" : "";
                    const emailClass = (row.Email && (row.Email.includes("XXX") || row.Email.includes("xxx"))) ? "cell-masked" : "";
                    const ssnVal = ssnClass ? `🔒 ${escapeHtml(row.SSN)}` : escapeHtml(row.SSN);
                    const emailVal = emailClass ? `🔒 ${escapeHtml(row.Email)}` : escapeHtml(row.Email);
                    
                    return `
                        <tr>
                            <td>${escapeHtml(row.CustomerID)}</td>
                            <td>${escapeHtml(row.CustomerName)}</td>
                            <td class="${ssnClass}">${ssnVal}</td>
                            <td class="${emailClass}">${emailVal}</td>
                            <td>${escapeHtml(row.Region)}</td>
                            <td>$${parseFloat(row.Balance).toLocaleString(undefined, {minimumFractionDigits: 2})}</td>
                            <td><code>${escapeHtml(row.LastUpdatedBy)}</code></td>
                            <td style="font-size:11px;">${escapeHtml(new Date(row.LastUpdateTime).toLocaleString())}</td>
                        </tr>
                    `;
                }).join("");
            } else {
                tbody.innerHTML = `<tr><td colspan="8" class="placeholder">Row-Level Security policy returned 0 rows for this region filter context.</td></tr>`;
            }
            
        } catch (err) {
            consoleBox.className = "cyber-console console-red";
            consoleBox.innerHTML += `<br/>[!] ERROR: Execution aborted by SQL Security gateway.<br/>[!] Detail: ${escapeHtml(err.message)}`;
            consoleBox.scrollTop = consoleBox.scrollHeight;
        }
    });
}

// ============================================================================
// TAB 3 INTERACTION: FORENSIC TIME TRAVEL
// ============================================================================
function updateChronoSlider(val) {
    document.getElementById("chrono-slider-val").innerText = val;
    
    // Calculate UTC timestamp relative to now
    const target = new Date();
    target.setMinutes(target.getMinutes() - parseInt(val));
    
    // Format to SQL datetime style
    const pad = (num) => String(num).padStart(2, '0');
    const timestampStr = `${target.getUTCFullYear()}-${pad(target.getUTCMonth()+1)}-${pad(target.getUTCDate())} ${pad(target.getUTCHours())}:${pad(target.getUTCMinutes())}:${pad(target.getUTCSeconds())}`;
    
    document.getElementById("chrono-timestamp").innerText = timestampStr;
}

async function executeChronoQuery() {
    const val = document.getElementById("chrono-slider").value;
    const tbody = document.querySelector("#chrono-results-table tbody");
    tbody.innerHTML = `<tr><td colspan="6" class="placeholder">Querying historical ledger snapshots...</td></tr>`;

    try {
        const res = await fetch("/api/ledger/temporal", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ minutes_ago: parseInt(val) })
        });
        const data = await res.json();
        
        if (data.records && data.records.length > 0) {
            tbody.innerHTML = data.records.map(row => `
                <tr>
                    <td>${escapeHtml(row.CustomerID)}</td>
                    <td>${escapeHtml(row.CustomerName)}</td>
                    <td>${escapeHtml(row.Region)}</td>
                    <td>$${parseFloat(row.Balance).toLocaleString(undefined, {minimumFractionDigits: 2})}</td>
                    <td><code>${escapeHtml(row.LastUpdatedBy)}</code></td>
                    <td style="font-size:11px;">${escapeHtml(new Date(row.LastUpdateTime).toLocaleString())}</td>
                </tr>
            `).join("");
        } else {
            tbody.innerHTML = `<tr><td colspan="6" class="placeholder">No records were active at the selected UTC coordinate: ${escapeHtml(data.query_time_utc)}.</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="placeholder text-red">Error during query execution: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function fetchLedgerHistory() {
    const tbody = document.querySelector("#history-table tbody");
    tbody.innerHTML = `<tr><td colspan="9" class="placeholder">Loading modification block logs...</td></tr>`;

    try {
        const res = await fetch("/api/ledger/history");
        const data = await res.json();
        
        if (data && data.length > 0) {
            tbody.innerHTML = data.map(row => {
                let opClass = "";
                if (row.ledger_operation_type_desc === 'INSERT') opClass = "text-green";
                else if (row.ledger_operation_type_desc === 'UPDATE') opClass = "text-orange";
                else if (row.ledger_operation_type_desc === 'DELETE') opClass = "text-red";
                
                return `
                    <tr>
                        <td>${escapeHtml(row.CustomerID)}</td>
                        <td>${escapeHtml(row.CustomerName)}</td>
                        <td>${escapeHtml(row.Region)}</td>
                        <td>$${parseFloat(row.Balance).toLocaleString(undefined, {minimumFractionDigits: 2})}</td>
                        <td><code>${escapeHtml(row.LastUpdatedBy)}</code></td>
                        <td style="font-size:11px;">${escapeHtml(new Date(row.LastUpdateTime).toLocaleString())}</td>
                        <td>${escapeHtml(row.ledger_transaction_id)}</td>
                        <td>${escapeHtml(row.ledger_sequence_number)}</td>
                        <td><span class="${opClass}" style="font-weight:bold;">${escapeHtml(row.ledger_operation_type_desc)}</span></td>
                    </tr>
                `;
            }).join("");
        } else {
            tbody.innerHTML = `<tr><td colspan="9" class="placeholder">No ledger modification records.</td></tr>`;
        }
        filterHistoryTable(); // Re-apply search filter query if any
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="9" class="placeholder text-red">Failed to read ledger logs: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// ============================================================================
// TAB 4 INTERACTION: CYBER SANDBOX VECTORS
// ============================================================================
async function runBackdoorInjection() {
    const amount = document.getElementById("backdoor-amount").value;
    const consoleBox = document.getElementById("backdoor-console");
    consoleBox.className = "cyber-console console-red";
    
    const lines = [
        `[!] Opening direct admin connection (bypassing application server)...`,
        `[!] Authenticating as 'sa' root database owner... [OK]`,
        `[!] Injecting backdoor UPDATE bypass statement...`
    ];

    typeConsoleLines("backdoor-console", lines, 10, async () => {
        try {
            const res = await fetch("/api/sandbox/backdoor", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ amount: parseFloat(amount) })
            });
            const data = await res.json();
            
            consoleBox.innerHTML += `
                <br/>[+] Direct update succeeded! Affected rows: ${escapeHtml(data.affected_rows)}
                <br/>[+] Balance injected successfully. LastUpdatedBy set to 'RogueDBA'.
                <br/>[!] ATTENTION: Run Sentinel scan inside Alerts panel to verify detection!
            `;
            consoleBox.scrollTop = consoleBox.scrollHeight;
            syncFeeds(); // Refresh status counters immediately
        } catch (err) {
            consoleBox.innerHTML += `<br/>[!] Injection vector aborted: ${escapeHtml(err.message)}`;
            consoleBox.scrollTop = consoleBox.scrollHeight;
        }
    });
}

async function runDeleteLogsTamper() {
    const consoleBox = document.getElementById("delete-logs-console");
    consoleBox.className = "cyber-console console-orange";
    
    const lines = [
        `[~] Connecting as administrative sa credentials...`,
        `[~] Attempting query: DELETE FROM Audit.AccessLogs;`
    ];

    typeConsoleLines("delete-logs-console", lines, 10, async () => {
        try {
            const res = await fetch("/api/sandbox/delete-logs", { method: "POST" });
            const data = await res.json();
            
            if (data.success) {
                consoleBox.innerHTML += `<br/>[+] Tamper Success: Access logs cleared.`;
            } else {
                consoleBox.innerHTML += `
                    <br/>[!] BLOCKED BY SQL SERVER KERNEL: updates and deletes are prohibited on append-only ledger tables.
                    <br/>[!] SQL Exception: ${escapeHtml(data.error.slice(0, 120))}...
                    <br/>[+] Immutability validation: PASSED. Log table is tamper-proof!
                `;
            }
            consoleBox.scrollTop = consoleBox.scrollHeight;
        } catch (err) {
            consoleBox.innerHTML += `<br/>[!] Execution error: ${escapeHtml(err.message)}`;
            consoleBox.scrollTop = consoleBox.scrollHeight;
        }
    });
}

async function saveBaseDigest() {
    const alertBox = document.getElementById("digest-save-alert");
    alertBox.style.display = "none";

    try {
        const res = await fetch("/api/ledger/digest");
        const data = await res.json();
        
        alertBox.className = "audit-alert alert-success";
        alertBox.innerHTML = `
            ✅ Baseline digest saved to session storage.<br/>
            <strong>Block ID:</strong> ${escapeHtml(data.block_id)} | <strong>Hash:</strong> <code>${escapeHtml(data.hash.slice(0,18))}...</code>
        `;
        alertBox.style.display = "block";
        syncFeeds(); // Refresh
    } catch (err) {
        alertBox.className = "audit-alert alert-error";
        alertBox.innerText = `Failed to generate digest: ${escapeHtml(err.message)}`;
        alertBox.style.display = "block";
    }
}

async function runForgedDigestVerify() {
    const consoleBox = document.getElementById("digest-forged-console");
    consoleBox.className = "cyber-console console-red";
    
    const lines = [
        `[~] Fetching saved baseline digest key...`,
        `[~] Forging hash signature byte values...`,
        `[~] Dispatching forged digest verification request...`
    ];

    typeConsoleLines("digest-forged-console", lines, 10, async () => {
        try {
            const res = await fetch("/api/ledger/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ corrupt: true })
            });
            const data = await res.json();
            
            consoleBox.innerHTML += `
                <br/>[!] CRYPTOGRAPHIC FAIL: Hash chain verification mismatch.
                <br/>[!] Details: ${escapeHtml(data.message)}
                <br/>[!] Sentinel Incident logged immediately!
            `;
            consoleBox.scrollTop = consoleBox.scrollHeight;
            syncFeeds();
        } catch (err) {
            consoleBox.innerHTML += `<br/>[!] Audit aborted: ${escapeHtml(err.message)}`;
            consoleBox.scrollTop = consoleBox.scrollHeight;
        }
    });
}

// ============================================================================
// TAB 5 INTERACTION: SENTINEL INCIDENT MANAGER
// ============================================================================
async function executeSentinelScan() {
    const alertBox = document.getElementById("sentinel-action-status");
    alertBox.style.display = "none";

    try {
        const res = await fetch("/api/sentinel/scan", { method: "POST" });
        const data = await res.json();
        
        if (data.new_threats_found > 0) {
            alertBox.className = "sentinel-status-alert alert-error";
            alertBox.innerText = `🚨 Threat Scan Complete: Detected ${data.new_threats_found} new database security anomalies! alert registry updated.`;
        } else {
            alertBox.className = "sentinel-status-alert alert-success";
            alertBox.innerText = "✅ Threat Scan Complete: No new anomalies detected. All database rules in healthy state.";
        }
        alertBox.style.display = "block";
        syncFeeds();
    } catch (err) {
        alertBox.className = "sentinel-status-alert alert-error";
        alertBox.innerText = `Sentinel scanning failure: ${err.message}`;
        alertBox.style.display = "block";
    }
}

async function executeSentinelResolve() {
    const alertBox = document.getElementById("sentinel-action-status");
    alertBox.style.display = "none";

    try {
        const res = await fetch("/api/sentinel/resolve", { method: "POST" });
        const data = await res.json();
        
        alertBox.className = "sentinel-status-alert alert-success";
        alertBox.innerText = `✅ Resolved and archived ${data.resolved_count} active security alert feeds.`;
        alertBox.style.display = "block";
        syncFeeds();
    } catch (err) {
        alertBox.className = "sentinel-status-alert alert-error";
        alertBox.innerText = `Failed to resolve threats: ${err.message}`;
        alertBox.style.display = "block";
    }
}

// ============================================================================
// CHART GENERATORS (PLOTLY.JS CLIENT RENDERERS)
// ============================================================================
function renderIntegrityGauge(isSecure) {
    const val = isSecure ? 100 : 0;
    const color = isSecure ? "#10b981" : "#ef4444";
    const titleText = isSecure ? "INTEGRITY SECURE" : "TAMPER ALARM";
    
    const data = [{
        type: "indicator",
        mode: "gauge+number",
        value: val,
        title: { text: titleText, font: { size: 12, color: color, family: "Orbitron", weight: "bold" } },
        gauge: {
            axis: { range: [0, 100], tickwidth: 1, tickcolor: "#94a3b8", tickvals: [0, 100] },
            bar: { color: color },
            bgcolor: "rgba(15, 23, 42, 0.5)",
            borderwidth: 1.5,
            bordercolor: "rgba(56, 189, 248, 0.2)",
            steps: [
                { range: [0, 50], color: "rgba(239, 68, 68, 0.08)" },
                { range: [50, 100], color: "rgba(16, 185, 129, 0.08)" }
            ]
        }
    }];
    
    const layout = {
        paper_bgcolor: "rgba(0,0,0,0)",
        plot_bgcolor: "rgba(0,0,0,0)",
        font: { color: "#e2e8f0" },
        height: 140,
        margin: { l: 15, r: 15, t: 30, b: 10 }
    };
    
    Plotly.newPlot("integrity-gauge", data, layout, {displayModeBar: false});
}

function renderBlockchainChart(blocks) {
    if (!blocks || blocks.length === 0) return;
    const sorted = [...blocks].sort((a,b) => a.block_id - b.block_id);
    const x = sorted.map(b => b.block_id);
    const y = sorted.map(b => b.block_size);
    
    const trace = {
        x: x,
        y: y,
        mode: "lines+markers",
        name: "Blocks",
        line: { color: "#38bdf8", width: 3 },
        marker: { size: 10, color: "#00f0ff", symbol: "hexagon" },
        type: "scatter"
    };
    
    const layout = {
        xaxis: { 
            title: { text: "Block Index", font: { color: "#94a3b8", family: "Orbitron", size: 11 } },
            tickmode: "linear", 
            gridcolor: "rgba(255, 255, 255, 0.03)",
            tickfont: { color: "#cbd5e1" }
        },
        yaxis: { 
            title: { text: "Tx Volume", font: { color: "#94a3b8", family: "Orbitron", size: 11 } },
            gridcolor: "rgba(255, 255, 255, 0.03)",
            tickfont: { color: "#cbd5e1" }
        },
        paper_bgcolor: "rgba(0,0,0,0)",
        plot_bgcolor: "rgba(0,0,0,0)",
        font: { color: "#cbd5e1" },
        height: 250,
        margin: { l: 45, r: 10, t: 10, b: 40 }
    };
    
    Plotly.newPlot("blockchain-chart", [trace], layout, {displayModeBar: false});
}

function renderAlertsPieChart(alerts) {
    const chartDiv = document.getElementById("alerts-chart");
    if (!alerts || alerts.length === 0) {
        chartDiv.innerHTML = `<div class="placeholder" style="line-height:200px;">No threats logged to chart.</div>`;
        return;
    }
    
    const severities = alerts.map(a => a.Severity);
    const unique = [...new Set(severities)];
    const counts = unique.map(s => severities.filter(x => x === s).length);
    
    const colors = {
        'CRITICAL': '#ef4444',
        'HIGH': '#f97316',
        'MEDIUM': '#f59e0b',
        'LOW': '#38bdf8'
    };
    
    const data = [{
        values: counts,
        labels: unique,
        hole: 0.45,
        type: "pie",
        marker: { colors: unique.map(s => colors[s] || '#94a3b8') },
        textinfo: "value",
        textfont: { size: 13, color: "#f1f5f9", family: "Orbitron" }
    }];
    
    const layout = {
        showlegend: true,
        legend: { font: { color: "#94a3b8", size: 11 }, orientation: "h", y: -0.1 },
        paper_bgcolor: "rgba(0,0,0,0)",
        plot_bgcolor: "rgba(0,0,0,0)",
        font: { color: "#cbd5e1" },
        height: 240,
        margin: { l: 10, r: 10, t: 10, b: 10 }
    };
    
    Plotly.newPlot("alerts-chart", data, layout, {displayModeBar: false});
}

async function renderTemporalChart() {
    try {
        const res = await fetch("/api/ledger/history");
        if (!res.ok) throw new Error("History feed unavailable.");
        const history = await res.json();
        
        if (!history || history.length === 0) {
            document.getElementById("temporal-chart").innerHTML = `<div class="placeholder" style="line-height:200px;">No historical balance changes to plot.</div>`;
            return;
        }

        // Sort history chronologically (ascending) by reversing the DESC order from server
        const sortedHistory = [...history].reverse();
        
        const customerData = {};
        sortedHistory.forEach(h => {
            const name = h.CustomerName;
            if (!customerData[name]) {
                customerData[name] = {
                    x: [],
                    y: [],
                    name: name,
                    mode: "lines+markers",
                    line: { width: 2.5 },
                    marker: { size: 7 }
                };
            }
            // Format time context for display
            const time = new Date(h.LastUpdateTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            customerData[name].x.push(time);
            customerData[name].y.push(parseFloat(h.Balance));
        });

        // Curated cyberpunk colors for lines
        const colorPalette = ["#00f0ff", "#a78bfa", "#f59e0b", "#10b981", "#ef4444", "#38bdf8"];
        const traces = Object.values(customerData);
        traces.forEach((trace, idx) => {
            trace.line.color = colorPalette[idx % colorPalette.length];
        });

        const layout = {
            paper_bgcolor: "rgba(0,0,0,0)",
            plot_bgcolor: "rgba(0,0,0,0)",
            font: { color: "#cbd5e1", family: "Inter" },
            legend: { font: { size: 10, color: "#94a3b8" }, orientation: "h", y: -0.2 },
            xaxis: { 
                gridcolor: "rgba(255, 255, 255, 0.03)",
                tickfont: { size: 9, color: "#94a3b8" }
            },
            yaxis: { 
                gridcolor: "rgba(255, 255, 255, 0.03)",
                tickfont: { size: 9, color: "#94a3b8" },
                title: { text: "Balance ($)", font: { size: 10, color: "#94a3b8" } }
            },
            height: 240,
            margin: { l: 55, r: 10, t: 10, b: 40 }
        };

        Plotly.newPlot("temporal-chart", traces, layout, {displayModeBar: false});
        
    } catch (err) {
        console.error("Temporal Chart Render Error:", err);
        document.getElementById("temporal-chart").innerHTML = `<div class="placeholder text-red" style="line-height:200px;">Failed to load dynamic chart: ${err.message}</div>`;
    }
}

// Window Resize Responsive Handler for Plotly charts
window.addEventListener("resize", () => {
    const activeTab = document.querySelector(".tab-content.active");
    if (activeTab) {
        const tabId = activeTab.id;
        if (tabId === "tab-ledger") {
            const ledgerChart = document.getElementById("blockchain-chart");
            if (ledgerChart && ledgerChart.querySelector(".plot-container")) {
                Plotly.Plots.resize("blockchain-chart");
            }
        } else if (tabId === "tab-chrono") {
            const temporalChart = document.getElementById("temporal-chart");
            if (temporalChart && temporalChart.querySelector(".plot-container")) {
                Plotly.Plots.resize("temporal-chart");
            }
        } else if (tabId === "tab-sentinel") {
            const alertsChart = document.getElementById("alerts-chart");
            if (alertsChart && alertsChart.querySelector(".plot-container")) {
                Plotly.Plots.resize("alerts-chart");
            }
        }
    }
    const integrityGauge = document.getElementById("integrity-gauge");
    if (integrityGauge && integrityGauge.querySelector(".plot-container")) {
        Plotly.Plots.resize("integrity-gauge");
    }
});
