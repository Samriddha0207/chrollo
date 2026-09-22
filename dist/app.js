const demoFindings = [
  {
    id: "DEMO-001", severity: "critical", title: "Unsanitized input reaches MongoDB query", tool: "Source scan",
    rule: "SEC-NOSQL", file: "app/routes/account.js", line: 42,
    explanation: "The route passes a request parameter directly into a MongoDB query. Convert it to the expected primitive type and validate it before querying.",
    evidence: "const user = await db.users.findOne({ username: req.body.username });",
    patch: ["- const user = await db.users.findOne({ username: req.body.username });", "+ const username = validateUsername(String(req.body.username ?? ''));", "+ const user = await db.users.findOne({ username });"],
    status: "open", decision: null,
  },
  {
    id: "DEMO-002", severity: "high", title: "Hard-coded credential", tool: "Secret scan",
    rule: "SECRET-GENERIC", file: "config/default.json", line: 9,
    explanation: "A credential appears in tracked source. Rotate it and read the replacement from a protected runtime variable.",
    evidence: "\"mongoPassword\": \"nodego…redacted…\"", patch: ["- hard-coded credential", "+ process.env.MONGO_PASSWORD"], status: "open", decision: null,
  },
  {
    id: "DEMO-003", severity: "high", title: "Vulnerable lodash dependency", tool: "Dependency audit",
    rule: "DEP-LODASH", file: "package-lock.json", line: 1,
    explanation: "The resolved lodash version is below the patched baseline. Upgrade the dependency and rerun the project test suite.",
    evidence: "\"lodash\": \"4.17.15\"", patch: ["- \"lodash\": \"4.17.15\"", "+ \"lodash\": \"4.17.21\""], status: "open", decision: null,
  },
];

let findings = structuredClone(demoFindings);
let selectedId = findings[0].id;
let activeFilter = "all";
let currentScanId = null;
let backendAvailable = false;
let backendRuntime = "static";
let integrations = { ai: false, github: false, persistence: { configured: false }, externalScanners: false };
let repositoryName = "OWASP / NodeGoat";
let currentSummary = demoSummary();
let scanHistory = [];

const list = document.querySelector("#findings-list");
const detail = document.querySelector("#detail-panel");
const toast = document.querySelector("#toast");
const scanButton = document.querySelector(".primary-button");

function demoSummary() {
  return { score: 47, open: 3, resolved: 0, critical: 1, high: 2, filesScanned: 214, durationMs: 38000, scanners: ["Source scan", "Secret scan", "Dependency audit"] };
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function visibleFindings() {
  if (activeFilter === "all") return findings;
  if (activeFilter === "resolved") return findings.filter((finding) => ["approved", "resolved"].includes(finding.status));
  return findings.filter((finding) => finding.severity === activeFilter && finding.status === "open");
}

function renderFindings() {
  const visible = visibleFindings();
  list.innerHTML = visible.length ? visible.map((finding) => `
    <article class="finding-row ${finding.id === selectedId ? "selected" : ""}" data-id="${escapeHtml(finding.id)}" tabindex="0" role="button" aria-label="Open ${escapeHtml(finding.title)}">
      <span class="severity-mark ${finding.status !== "open" ? "resolved" : finding.severity}"></span>
      <div><h3>${escapeHtml(finding.title)}</h3><p>${escapeHtml(finding.file)}:${finding.line}</p></div>
      <div class="finding-meta"><span>${escapeHtml(finding.status === "open" ? finding.severity : finding.status)}</span><b>${escapeHtml(finding.tool)}</b></div>
    </article>`).join("") : `<div class="empty-detail"><p>No findings match this filter.</p></div>`;
  list.querySelectorAll(".finding-row").forEach((row) => {
    const choose = () => { selectedId = row.dataset.id; renderFindings(); renderDetail(); };
    row.addEventListener("click", choose);
    row.addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key)) choose(); });
  });
}

function renderDetail() {
  const finding = findings.find((item) => item.id === selectedId);
  if (!finding) {
    detail.innerHTML = `<div class="empty-detail"><p>Select a finding to inspect its evidence and recommendation.</p></div>`;
    return;
  }
  const state = finding.status === "open" ? finding.severity : "resolved";
  detail.innerHTML = `
    <div class="detail-header">
      <span class="severity ${state}">${escapeHtml(finding.status === "open" ? finding.severity : finding.status)}</span>
      <h2>${escapeHtml(finding.title)}</h2>
      <p>${escapeHtml(finding.file)}:${finding.line} · ${escapeHtml(finding.rule)}</p>
    </div>
    <div class="detail-section"><h3>Analysis</h3><p>${escapeHtml(finding.aiExplanation || finding.explanation)}</p></div>
    <div class="detail-section"><h3>Evidence</h3><pre class="code-block">${escapeHtml(finding.evidence)}</pre></div>
    <div class="detail-section"><h3>Recommended change</h3><pre class="diff-block">${(finding.patch || []).map((line) => `<span class="${line.startsWith("+") ? "add" : line.startsWith("-") ? "remove" : ""}">${escapeHtml(line)}</span>`).join("\n")}</pre></div>
    <div class="detail-actions">
      <button class="action-button" id="reject-button" ${finding.status !== "open" ? "disabled" : ""}>Dismiss</button>
      <button class="action-button" id="explain-button" ${!integrations.ai || finding.status !== "open" ? "disabled" : ""}>Explain with AI</button>
      <button class="action-button approve" id="approve-button" ${finding.status !== "open" ? "disabled" : ""}>${finding.status === "approved" ? "Approved for remediation" : "Approve recommendation"}</button>
      ${finding.remediationPullRequest
        ? `<a class="action-button pr-action" href="${escapeHtml(finding.remediationPullRequest.url)}" target="_blank" rel="noopener">Open draft PR #${finding.remediationPullRequest.number}</a>`
        : `<button class="action-button pr-action" id="pr-button" ${!integrations.github || finding.decision !== "approve" ? "disabled" : ""}>Create draft remediation PR</button>`}
    </div>`;
  document.querySelector("#approve-button")?.addEventListener("click", () => decideFinding(finding.id, "approve"));
  document.querySelector("#reject-button")?.addEventListener("click", () => decideFinding(finding.id, "reject"));
  document.querySelector("#explain-button")?.addEventListener("click", () => explainFinding(finding.id));
  document.querySelector("#pr-button")?.addEventListener("click", () => createRemediationPullRequest(finding.id));
}

function updateMetrics() {
  const open = findings.filter((finding) => finding.status === "open").length;
  const resolved = findings.length - open;
  const critical = findings.filter((finding) => finding.status === "open" && finding.severity === "critical").length;
  document.querySelector("#open-count").textContent = open;
  document.querySelector("#resolved-count").textContent = resolved;
  document.querySelector("#critical-count").textContent = critical;
  document.querySelector("#score").textContent = Math.min(100, Number(currentSummary.score ?? 100) + resolved * 4);
  document.querySelector(".summary-title h2").textContent = repositoryName;
  document.querySelector(".metrics div:last-child dd").textContent = `${Math.max(1, Math.round((currentSummary.durationMs || 0) / 1000))}s`;
  document.querySelector(".scanner-list").innerHTML = `<h3>Scan coverage</h3>
    <div><span>Files scanned</span><strong>${Number(currentSummary.filesScanned || 0).toLocaleString()}</strong></div>
    ${(currentSummary.scanners || []).map((name) => `<div><span>${escapeHtml(name)}</span><strong>${findings.filter((item) => item.tool === name).length} findings</strong></div>`).join("")}`;
  const rescanButton = document.querySelector("#rescan-button");
  const jsonExport = document.querySelector("#json-export");
  const sarifExport = document.querySelector("#sarif-export");
  rescanButton.disabled = !backendAvailable || !currentScanId;
  for (const [link, format] of [[jsonExport, "json"], [sarifExport, "sarif"]]) {
    link.href = currentScanId ? `/api/scans/${encodeURIComponent(currentScanId)}?format=${format}` : "#";
    link.setAttribute("aria-disabled", currentScanId ? "false" : "true");
  }
  renderCharts();
}

function chartRows(items, classByName = false) {
  const maximum = Math.max(1, ...items.map((item) => item.value));
  return items.map((item) => `
    <div class="bar-row">
      <span>${escapeHtml(item.label)}</span>
      <div class="bar-track" aria-hidden="true"><div class="bar-fill ${classByName ? escapeHtml(item.label.toLowerCase()) : ""}" style="width:${Math.round(item.value / maximum * 100)}%"></div></div>
      <strong>${item.value}</strong>
    </div>`).join("");
}

function renderCharts() {
  const severityOrder = ["critical", "high", "medium", "low"];
  const severityItems = severityOrder.map((level) => ({ label: level, value: findings.filter((item) => item.severity === level && item.status === "open").length }));
  const scannerCounts = findings.reduce((counts, item) => counts.set(item.tool, (counts.get(item.tool) || 0) + 1), new Map());
  const scannerItems = [...scannerCounts].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
  document.querySelector("#severity-chart").innerHTML = chartRows(severityItems, true);
  document.querySelector("#scanner-chart").innerHTML = chartRows(scannerItems.length ? scannerItems : [{ label: "No findings", value: 0 }]);

  const history = (scanHistory.length ? [...scanHistory].reverse().slice(-10) : [{ summary: currentSummary }]);
  const width = 520, height = 160, left = 36, right = 14, top = 16, bottom = 28;
  const usableWidth = width - left - right, usableHeight = height - top - bottom;
  const points = history.map((scan, index) => ({
    score: Number(scan.summary?.score ?? 0),
    x: left + (history.length === 1 ? usableWidth / 2 : index * usableWidth / (history.length - 1)),
    y: top + (100 - Number(scan.summary?.score ?? 0)) / 100 * usableHeight,
  }));
  const grid = [0, 50, 100].map((score) => {
    const y = top + (100 - score) / 100 * usableHeight;
    return `<line class="chart-gridline" x1="${left}" y1="${y}" x2="${width - right}" y2="${y}"/><text class="chart-label" x="${left - 8}" y="${y + 4}" text-anchor="end">${score}</text>`;
  }).join("");
  const polyline = points.map((point) => `${point.x},${point.y}`).join(" ");
  const marks = points.map((point, index) => `<g><circle class="chart-hit" data-history-index="${index}" cx="${point.x}" cy="${point.y}" r="15" tabindex="0" role="button" aria-label="Show details for scan ${index + 1}, score ${point.score}"></circle><circle class="chart-point" cx="${point.x}" cy="${point.y}" r="4" aria-hidden="true"></circle></g>`).join("");
  const final = points.at(-1);
  document.querySelector("#score-chart").innerHTML = `
    <title id="score-chart-title">Security score trend</title><desc id="score-chart-description">Recent scan scores from zero to one hundred.</desc>
    ${grid}<line class="chart-axis" x1="${left}" y1="${height - bottom}" x2="${width - right}" y2="${height - bottom}"/>
    <polyline class="chart-line" points="${polyline}"/>${marks}
    <text class="chart-value" x="${Math.min(width - right - 4, final.x + 8)}" y="${Math.max(top + 10, final.y - 8)}" text-anchor="${final.x > width - 70 ? "end" : "start"}">${final.score}/100</text>
    <text class="chart-label" x="${left}" y="${height - 8}">Older</text><text class="chart-label" x="${width - right}" y="${height - 8}" text-anchor="end">Latest</text>`;
  const tooltip = document.querySelector("#score-tooltip");
  const panel = document.querySelector(".trend-panel");
  const showTooltip = (target, index) => {
    const scan = history[index];
    const summary = scan.summary || {};
    const repository = scan.repository ? `${scan.repository.owner} / ${scan.repository.name}` : repositoryName;
    const timestamp = scan.completedAt || scan.createdAt;
    const comparison = scan.comparison
      ? `${scan.comparison.fixedFindings} fixed · ${scan.comparison.newFindings} new`
      : "Baseline scan";
    tooltip.innerHTML = `<strong>${escapeHtml(repository)}</strong>
      <span>${escapeHtml(timestamp ? new Date(timestamp).toLocaleString() : "Current preview")}</span>
      <div class="tooltip-metrics">
        <span><b>${Number(summary.score ?? 0)}</b> score</span>
        <span><b>${Number(scan.findingCount ?? summary.open ?? 0)}</b> findings</span>
        <span><b>${Number(summary.critical ?? 0)}</b> critical</span>
        <span><b>${Number(summary.high ?? 0)}</b> high</span>
        <span><b>${Number(summary.filesScanned ?? 0)}</b> files</span>
        <span>${escapeHtml(comparison)}</span>
      </div>`;
    tooltip.hidden = false;
    const targetRect = target.getBoundingClientRect();
    const panelRect = panel.getBoundingClientRect();
    const half = Math.min(125, Math.max(80, panelRect.width / 3));
    tooltip.style.left = `${Math.max(half + 4, Math.min(panelRect.width - half - 4, targetRect.left + targetRect.width / 2 - panelRect.left))}px`;
    tooltip.style.top = `${Math.max(82, targetRect.top - panelRect.top)}px`;
  };
  const hideTooltip = () => { tooltip.hidden = true; };
  document.querySelectorAll("#score-chart .chart-hit").forEach((target) => {
    const index = Number(target.dataset.historyIndex);
    target.addEventListener("mouseenter", () => showTooltip(target, index));
    target.addEventListener("mouseleave", hideTooltip);
    target.addEventListener("focus", () => showTooltip(target, index));
    target.addEventListener("blur", hideTooltip);
    target.addEventListener("click", () => tooltip.hidden ? showTooltip(target, index) : hideTooltip());
  });
}

async function loadHistory() {
  if (!backendAvailable) { scanHistory = []; renderCharts(); return; }
  try {
    const response = await fetch("/api/scans");
    scanHistory = response.ok ? await response.json() : [];
  } catch { scanHistory = []; }
  renderCharts();
}

async function waitForScanJob(initial, timeoutMs = 180_000) {
  if (initial.scan) return initial.scan;
  if (initial.findings) return initial;
  const started = Date.now();
  let job = initial;
  while (!["complete", "failed"].includes(job.status)) {
    if (Date.now() - started > timeoutMs) throw new Error("The scan is still running. Its job ID is " + initial.id + ". Refresh the scan history shortly.");
    setProgress(Number(job.progress || 10), job.phase || "Scan queued", Math.min(3, Math.floor(Number(job.progress || 0) / 25)));
    await new Promise((resolve) => window.setTimeout(resolve, 900));
    const response = await fetch(`/api/jobs/${encodeURIComponent(initial.id)}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Unable to read scan job status.");
    job = payload;
  }
  if (job.status === "failed") throw new Error(job.error || "Scan failed.");
  return job.scan;
}

function setProgress(percent, label, phaseIndex) {
  document.querySelectorAll(".pipeline-step").forEach((step, index) => {
    step.classList.toggle("complete", index < phaseIndex);
    step.classList.toggle("active", index === phaseIndex);
  });
  document.querySelector("#progress-label").textContent = label;
  document.querySelector("#progress-percent").textContent = `${percent}%`;
  document.querySelector("#progress-bar").style.width = `${percent}%`;
}

async function runScan(repository) {
  scanButton.disabled = true;
  document.querySelector("#form-message").textContent = backendAvailable
    ? backendRuntime === "vercel-function" ? "Downloading a commit-pinned repository snapshot. Keep this page open while the scan runs." : "Cloning into an isolated temporary directory. This can take up to 90 seconds."
    : "Static demo mode: start the Node server for live repository scans.";
  const phases = [[12, "Validating repository", 0], [35, "Creating an isolated shallow clone", 1], [62, "Scanning source, secrets and dependencies", 2], [84, "Normalizing evidence and severity", 3]];
  let phase = 0;
  const timer = window.setInterval(() => { if (phase < phases.length) setProgress(...phases[phase++]); }, 700);
  try {
    if (!backendAvailable) {
      await new Promise((resolve) => setTimeout(resolve, 2600));
      findings = structuredClone(demoFindings);
      currentSummary = demoSummary();
      repositoryName = new URL(repository).pathname.split("/").filter(Boolean).join(" / ");
      currentScanId = null;
    } else {
      const response = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repositoryUrl: repository }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Scan failed.");
      const completed = await waitForScanJob(payload);
      findings = completed.findings;
      currentSummary = completed.summary;
      repositoryName = `${completed.repository.owner} / ${completed.repository.name}`;
      currentScanId = completed.id;
      document.querySelector("#comparison-summary").textContent = completed.comparison
        ? `${completed.comparison.fixedFindings} fixed · ${completed.comparison.newFindings} new · ${completed.comparison.unchangedFindings} unchanged · score ${completed.comparison.scoreChange >= 0 ? "+" : ""}${completed.comparison.scoreChange}`
        : "Baseline scan saved. Rescan after remediation to compare the results.";
    }
    selectedId = findings[0]?.id ?? null;
    activeFilter = "all";
    document.querySelectorAll(".filter").forEach((button) => button.classList.toggle("active", button.dataset.filter === "all"));
    setProgress(100, findings.length ? "Audit complete. Findings are ready for review" : "Audit complete. No matching findings found", 4);
    document.querySelector("#form-message").textContent = backendAvailable ? `Completed scan ${currentScanId}. The clone was deleted after analysis.` : "Showing representative results. Run npm start for real scans.";
    await loadHistory();
    renderFindings(); renderDetail(); updateMetrics();
    showToast(`Audit complete: ${findings.length} finding${findings.length === 1 ? "" : "s"}.`);
  } catch (error) {
    setProgress(0, "Scan failed", 0);
    document.querySelector("#form-message").textContent = error.message;
    showToast(error.message, true);
  } finally {
    window.clearInterval(timer);
    scanButton.disabled = false;
  }
}

async function decideFinding(id, action) {
  const finding = findings.find((item) => item.id === id);
  if (!finding) return;
  try {
    if (backendAvailable && currentScanId) {
      const response = await fetch(`/api/scans/${encodeURIComponent(currentScanId)}/findings/${encodeURIComponent(id)}/decision`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error);
      Object.assign(finding, payload);
    } else {
      finding.status = action === "approve" ? "approved" : "dismissed";
      finding.decision = action;
    }
    renderFindings(); renderDetail(); updateMetrics();
    showToast(action === "approve" ? "Recommendation approved. Apply it in a review branch, then rescan." : "Finding dismissed and retained in scan history.");
  } catch (error) { showToast(error.message, true); }
}

async function explainFinding(id) {
  if (!currentScanId) return;
  const button = document.querySelector("#explain-button");
  button.disabled = true;
  button.textContent = "Explaining…";
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(currentScanId)}/findings/${encodeURIComponent(id)}/explain`, { method: "POST" });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error);
    Object.assign(findings.find((item) => item.id === id), payload);
    renderDetail();
  } catch (error) { showToast(error.message, true); renderDetail(); }
}

async function createRemediationPullRequest(findingId) {
  if (!currentScanId) return;
  const button = document.querySelector("#pr-button");
  button.disabled = true;
  button.textContent = "Creating draft PR…";
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(currentScanId)}/findings/${encodeURIComponent(findingId)}/remediate`, { method: "POST" });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Pull request creation failed.");
    const finding = findings.find((item) => item.id === findingId);
    finding.remediationPullRequest = payload;
    renderDetail();
    showToast(`Draft remediation PR #${payload.number} created.`);
  } catch (error) { showToast(error.message, true); renderDetail(); }
}

async function rescanRepository() {
  if (!currentScanId) return;
  const button = document.querySelector("#rescan-button");
  button.disabled = true;
  button.textContent = "Rescanning…";
  setProgress(35, "Creating a fresh repository snapshot", 1);
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(currentScanId)}/rescan`, { method: "POST" });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Rescan failed.");
    const completed = await waitForScanJob(payload);
    findings = completed.findings;
    currentSummary = completed.summary;
    currentScanId = completed.id;
    selectedId = findings[0]?.id ?? null;
    const comparison = completed.comparison || {};
    document.querySelector("#comparison-summary").textContent = `${comparison.fixedFindings || 0} fixed · ${comparison.newFindings || 0} new · ${comparison.unchangedFindings || 0} unchanged · score ${(comparison.scoreChange || 0) >= 0 ? "+" : ""}${comparison.scoreChange || 0}`;
    setProgress(100, "Rescan complete", 4);
    await loadHistory();
    renderFindings(); renderDetail(); updateMetrics();
    showToast("Rescan complete. The comparison is ready.");
  } catch (error) { showToast(error.message, true); }
  finally { button.textContent = "Rescan repository"; updateMetrics(); }
}

function showToast(message, error = false) {
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  window.clearTimeout(toast.hideTimer);
  toast.hideTimer = window.setTimeout(() => toast.classList.remove("show"), 4000);
}

document.querySelector("#scan-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const repository = document.querySelector("#repo-url").value.trim();
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(repository)) {
    document.querySelector("#form-message").textContent = "Enter a public GitHub repository URL in the form https://github.com/owner/repository.";
    return;
  }
  runScan(repository);
});

document.querySelectorAll(".filter").forEach((button) => button.addEventListener("click", () => {
  activeFilter = button.dataset.filter;
  document.querySelectorAll(".filter").forEach((item) => item.classList.toggle("active", item === button));
  const visible = visibleFindings();
  if (!visible.some((finding) => finding.id === selectedId)) selectedId = visible[0]?.id ?? null;
  renderFindings(); renderDetail();
}));
document.querySelector("#rescan-button").addEventListener("click", rescanRepository);

async function detectBackend() {
  try {
    const response = await fetch("/api/health", { signal: AbortSignal.timeout(1500) });
    const payload = await response.json();
    backendAvailable = response.ok;
    backendRuntime = payload.runtime || "node-server";
    integrations = payload.integrations || integrations;
    const enabled = [integrations.ai && "AI", integrations.github && "GitHub", integrations.persistence?.configured && "Supabase"].filter(Boolean);
    document.querySelector("#mode-label").textContent = enabled.length ? `Live + ${enabled.join(" + ")}` : "Live scanner";
    document.querySelector("#form-message").textContent = payload.warnings?.length
      ? payload.warnings[0]
      : integrations.github ? "Ready for public or authorized private GitHub repositories." : "Ready for a live scan. Configure GitHub authentication to scan private repositories.";
    await loadHistory();
  } catch {
    document.querySelector("#mode-label").textContent = "Static demo";
  }
  renderDetail();
}

function registerWebMcpTools() {
  const context = document.modelContext;
  if (!context?.registerTool) return;
  try {
    context.registerTool({
      name: "list_security_findings", title: "List security findings", description: "Read findings currently visible in Chrollo.",
      inputSchema: { type: "object", properties: { severity: { type: "string", enum: ["all", "critical", "high", "medium", "resolved"] } }, additionalProperties: false },
      annotations: { readOnlyHint: true, untrustedContentHint: false },
      execute(input) { const level = input?.severity || "all"; return (level === "all" ? findings : findings.filter((item) => level === "resolved" ? item.status !== "open" : item.severity === level)).map(({ id, title, severity, status, tool, file, line }) => ({ id, title, severity, status, tool, location: `${file}:${line}` })); },
    });
  } catch { /* WebMCP is optional */ }
}

renderFindings(); renderDetail(); updateMetrics(); detectBackend(); registerWebMcpTools();
