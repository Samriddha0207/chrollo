import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export function scannerEnvironment(home) {
  const allowed = [
    "PATH", "Path", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
  ];
  const environment = { NO_COLOR: "1", HOME: home, USERPROFILE: home, XDG_CACHE_HOME: path.join(home, "cache"), GIT_CONFIG_NOSYSTEM: "1" };
  for (const name of allowed) if (process.env[name]) environment[name] = process.env[name];
  return environment;
}

function terminate(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGKILL");
  if (process.platform === "win32" && child.pid) {
    const killer = spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { shell: false, windowsHide: true, stdio: "ignore" });
    killer.unref();
  }
}

function execute(command, args, cwd, environment, timeoutMs = 120_000) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, shell: false, windowsHide: true, env: environment });
    let stdout = "";
    let stderr = "";
    const limit = 8_000_000;
    child.stdout.on("data", (chunk) => { if (stdout.length < limit) stdout += chunk; });
    child.stderr.on("data", (chunk) => { if (stderr.length < limit) stderr += chunk; });
    const timer = setTimeout(() => terminate(child), timeoutMs);
    child.on("error", (error) => { clearTimeout(timer); resolve({ ok: false, error: error.message }); });
    child.on("close", (code) => { clearTimeout(timer); resolve({ ok: code === 0 || code === 1, code, stdout, stderr }); });
  });
}

function severity(value) {
  const normalized = String(value || "medium").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(normalized)) return normalized;
  if (normalized === "error") return "high";
  if (normalized === "warning") return "medium";
  return "low";
}

function externalFinding({ id, level, title, tool, rule, file, line, explanation, evidence, patch }) {
  return {
    id,
    severity: severity(level),
    title,
    tool,
    rule,
    file: String(file || "unknown").replaceAll("\\", "/"),
    line: Number(line || 1),
    explanation,
    evidence: String(evidence || "Scanner evidence available in the exported report.").slice(0, 500),
    patch: patch || ["Review the scanner guidance and apply the smallest safe remediation."],
    status: "open",
    decision: null,
  };
}

async function semgrep(root, environment) {
  const result = await execute("semgrep", ["scan", "--json", "--config", "auto", "--metrics=off", "--quiet", "."], root, environment);
  if (!result.ok || !result.stdout.trim()) return { available: !/ENOENT|not recognized/i.test(result.error || ""), findings: [] };
  try {
    const payload = JSON.parse(result.stdout);
    return { available: true, findings: (payload.results || []).map((item, index) => externalFinding({
      id: `SEMGREP-${index}-${item.check_id}`,
      level: item.extra?.severity,
      title: item.extra?.message || item.check_id,
      tool: "Semgrep",
      rule: item.check_id,
      file: item.path,
      line: item.start?.line,
      explanation: item.extra?.metadata?.shortDescription || item.extra?.message || "Semgrep identified a security-sensitive code pattern.",
      evidence: item.extra?.lines,
      patch: item.extra?.fix ? [item.extra.fix] : undefined,
    })) };
  } catch { return { available: true, findings: [] }; }
}

async function gitleaks(root, environment) {
  const result = await execute("gitleaks", ["detect", "--source", ".", "--no-git", "--report-format", "json", "--report-path", "-"], root, environment);
  if (!result.ok || !result.stdout.trim()) return { available: !/ENOENT|not recognized/i.test(result.error || ""), findings: [] };
  try {
    const payload = JSON.parse(result.stdout);
    return { available: true, findings: payload.map((item, index) => externalFinding({
      id: `GITLEAKS-${index}-${item.RuleID}`,
      level: "critical",
      title: item.Description || "Secret detected in source",
      tool: "Gitleaks",
      rule: item.RuleID,
      file: item.File,
      line: item.StartLine,
      explanation: "Gitleaks matched a credential pattern. Rotate the credential before removing it from the repository history.",
      evidence: `Fingerprint: ${item.Fingerprint || "redacted"}`,
      patch: ["- committed secret", "+ protected runtime environment variable"],
    })) };
  } catch { return { available: true, findings: [] }; }
}

async function osv(root, environment) {
  const result = await execute("osv-scanner", ["scan", "source", "-r", ".", "--format", "json"], root, environment);
  if (!result.ok || !result.stdout.trim()) return { available: !/ENOENT|not recognized/i.test(result.error || ""), findings: [] };
  try {
    const payload = JSON.parse(result.stdout);
    const findings = [];
    for (const resultItem of payload.results || []) {
      for (const packageItem of resultItem.packages || []) {
        for (const vulnerability of packageItem.vulnerabilities || []) {
          findings.push(externalFinding({
            id: `OSV-${vulnerability.id}-${findings.length}`,
            level: vulnerability.database_specific?.severity || "high",
            title: `${vulnerability.id} affects ${packageItem.package?.name || "a dependency"}`,
            tool: "OSV-Scanner",
            rule: vulnerability.id,
            file: resultItem.source?.path || "dependency manifest",
            line: 1,
            explanation: vulnerability.summary || "OSV reports a known vulnerability in a resolved dependency.",
            evidence: `${packageItem.package?.name || "package"} ${packageItem.package?.version || "unknown version"}`,
            patch: ["Upgrade to a fixed version listed by the advisory, reinstall dependencies and run tests."],
          }));
        }
      }
    }
    return { available: true, findings };
  } catch { return { available: true, findings: [] }; }
}

export async function runExternalScanners(root) {
  if (process.env.CHROLLO_EXTERNAL_SCANNERS !== "true") return { enabled: false, tools: [], findings: [] };
  if (process.env.VERCEL) return {
    enabled: false,
    tools: ["Semgrep", "Gitleaks", "OSV-Scanner"].map((name) => ({ name, available: false, findingCount: 0, reason: "Use a container worker or Vercel Sandbox for executable scanners." })),
    findings: [],
  };
  const isolatedHome = await fs.mkdtemp(path.join(os.tmpdir(), "chrollo-scanner-"));
  try {
    const environment = scannerEnvironment(isolatedHome);
    const results = await Promise.all([semgrep(root, environment), gitleaks(root, environment), osv(root, environment)]);
    const names = ["Semgrep", "Gitleaks", "OSV-Scanner"];
    return {
      enabled: true,
      tools: results.map((result, index) => ({ name: names[index], available: result.available, findingCount: result.findings.length })),
      findings: results.flatMap((result) => result.findings),
    };
  } finally {
    await fs.rm(isolatedHome, { recursive: true, force: true });
  }
}
