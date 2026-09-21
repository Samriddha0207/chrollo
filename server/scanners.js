import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import crypto from "node:crypto";

const ignoredDirectories = new Set([".git", "node_modules", "vendor", "coverage", ".next", "build", "dist"]);
const textExtensions = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".env", ".py", ".go", ".java", ".rb", ".php", ".html", ".vue", ".svelte"]);
const manifestNames = new Set(["Dockerfile", "Gemfile", "Gemfile.lock", "package-lock.json", "requirements.txt", "go.sum", "composer.lock", "Cargo.lock"]);
const weights = { critical: 25, high: 14, medium: 7, low: 2 };

const sourceRules = [
  {
    id: "SEC-EVAL",
    severity: "high",
    title: "Dynamic code execution",
    pattern: /\beval\s*\((.+)/,
    explanation: "eval executes text as code. If any portion is user controlled, this can become remote code execution.",
    patch: ["- eval(value)", "+ Replace dynamic evaluation with an explicit parser or allow-listed command map."],
  },
  {
    id: "SEC-EXEC",
    severity: "critical",
    title: "Shell command built from request data",
    pattern: /(?:exec|execSync)\s*\([^\n]*(?:req\.|request\.|params|query|body)/,
    explanation: "Request data appears to reach a shell command. An attacker may be able to inject additional commands.",
    patch: ["- exec(commandFromRequest)", "+ Use spawn/execFile with a fixed executable and validated argument allow-list."],
  },
  {
    id: "SEC-NOSQL",
    severity: "critical",
    title: "Request object passed to a database query",
    pattern: /(?:findOne|find|updateOne|deleteOne)\s*\([^\n]*(?:req\.(?:body|query|params)|request\.)/,
    explanation: "An untrusted request value appears inside a database query. Convert it to the expected primitive type and validate it first.",
    patch: ["- collection.findOne({ field: req.body.field })", "+ const field = validateField(String(req.body.field ?? ''));", "+ collection.findOne({ field })"],
  },
  {
    id: "SEC-XSS",
    severity: "high",
    title: "Untrusted HTML assignment",
    pattern: /(?:innerHTML\s*=|document\.write\s*\()[^\n]*(?:req\.|location\.|searchParams|user)/i,
    explanation: "User-controlled content is written into an HTML sink. Render it as text or use context-aware escaping.",
    patch: ["- element.innerHTML = value", "+ element.textContent = value"],
  },
  {
    id: "SEC-TLS",
    severity: "medium",
    title: "TLS certificate verification disabled",
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/i,
    explanation: "Disabling certificate validation makes HTTPS connections vulnerable to interception.",
    patch: ["- rejectUnauthorized: false", "+ Use the default certificate verification and configure a trusted CA if required."],
  },
];

const multilineRules = [
  {
    id: "SEC-EXEC-FLOW", severity: "critical", title: "Request data may reach a shell command",
    pattern: /(?:req\.(?:body|query|params)|request\.(?:args|form|json))[\s\S]{0,500}(?:exec|execSync|spawn|subprocess\.(?:run|Popen)|Runtime\.getRuntime\(\)\.exec)\s*\(/i,
    explanation: "Request-controlled data and a process-execution sink occur in the same local code window. Confirm the data flow and replace shell construction with a fixed executable and validated arguments.",
    patch: ["- shell command assembled from request data", "+ fixed executable with an allow-listed argument array"],
  },
  {
    id: "SEC-QUERY-FLOW", severity: "high", title: "Request data may reach a database query",
    pattern: /(?:req\.(?:body|query|params)|request\.(?:args|form|json))[\s\S]{0,500}(?:findOne|updateOne|deleteOne|execute|query)\s*\(/i,
    explanation: "Request-controlled data and a database query occur in the same local code window. Use typed validation and parameterized queries.",
    patch: ["- query built from request data", "+ validated primitives and a parameterized query"],
  },
  {
    id: "SEC-PY-SHELL", severity: "critical", title: "Python subprocess enables a shell",
    pattern: /subprocess\.(?:run|Popen|call)\s*\([\s\S]{0,400}shell\s*=\s*True/i,
    explanation: "A Python subprocess enables shell parsing. Use an argument list with shell=False and validate every untrusted argument.",
    patch: ["- subprocess.run(command, shell=True)", "+ subprocess.run([executable, validated_argument], shell=False, check=True)"],
  },
  {
    id: "SEC-REACT-HTML", severity: "high", title: "Potential untrusted React HTML injection",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{[\s\S]{0,350}(?:user|message|content|query|param)/i,
    explanation: "Content is supplied to React's raw HTML escape hatch. Sanitize with a maintained allow-list sanitizer or render it as text.",
    patch: ["- dangerouslySetInnerHTML={{ __html: content }}", "+ render trusted structured elements or sanitized content"],
  },
];

const secretRules = [
  { id: "SECRET-AWS", title: "AWS access key committed to source", pattern: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { id: "SECRET-PRIVATE-KEY", title: "Private key committed to source", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "critical" },
  { id: "SECRET-GENERIC", title: "Hard-coded credential", pattern: /(?:api[_-]?key|secret|password|token)\s*[=:]\s*["'][A-Za-z0-9_\-/.+=]{12,}["']/i, severity: "high" },
];

function redact(line) {
  return line.replace(/(["'])([^"']{6})[^"']+(["'])/g, "$1$2…redacted…$3").slice(0, 260);
}

function finding(rule, file, line, evidence, tool) {
  const stableEvidence = String(evidence).replace(/\s+/g, " ").replace(/\b\d+\b/g, "#").trim().slice(0, 300);
  return {
    id: `${rule.id}-${Buffer.from(`${file}:${line}`).toString("hex").slice(-8)}`,
    severity: rule.severity,
    title: rule.title,
    tool,
    rule: rule.id,
    file: file.replaceAll("\\", "/"),
    line,
    explanation: rule.explanation ?? "A likely secret is present in tracked source. Rotate it and load the replacement from a protected runtime variable.",
    evidence: tool === "Secret scan" ? redact(evidence.trim()) : evidence.trim().slice(0, 500),
    patch: rule.patch ?? ["- hard-coded credential", "+ process.env.SECRET_NAME"],
    status: "open",
    decision: null,
    fingerprint: crypto.createHash("sha256").update(`${rule.id}:${file.replaceAll("\\", "/")}:${stableEvidence}`).digest("hex").slice(0, 24),
  };
}

async function collectFiles(root, maximum) {
  const files = [];
  async function visit(directory) {
    if (files.length >= maximum) return;
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      if (files.length >= maximum) break;
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await visit(absolute);
      } else if (entry.isFile()) {
        const extension = path.extname(entry.name).toLowerCase();
        if (textExtensions.has(extension) || manifestNames.has(entry.name)) files.push(absolute);
      }
    }
  }
  await visit(root);
  return files;
}

function compareVersions(left, right) {
  const a = String(left).replace(/^[^0-9]*/, "").split(".").map(Number);
  const b = String(right).split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const difference = (a[i] || 0) - (b[i] || 0);
    if (difference) return difference;
  }
  return 0;
}

function dependencyFindings(lock, relativePath) {
  const vulnerable = {
    lodash: { below: "4.17.21", severity: "high", advisory: "CVE-2021-23337" },
    minimist: { below: "1.2.6", severity: "high", advisory: "CVE-2021-44906" },
    axios: { below: "0.21.2", severity: "high", advisory: "CVE-2021-3749" },
  };
  const packages = lock.packages ?? lock.dependencies ?? {};
  const results = [];
  for (const [key, value] of Object.entries(packages)) {
    const name = key.startsWith("node_modules/") ? key.slice(13) : key;
    const policy = vulnerable[name];
    const version = value?.version;
    if (!policy || !version || compareVersions(version, policy.below) >= 0) continue;
    const rule = {
      id: `DEP-${name.toUpperCase()}`,
      severity: policy.severity,
      title: `Vulnerable ${name} dependency`,
      explanation: `${name} ${version} is below the patched baseline ${policy.below} (${policy.advisory}). Upgrade it and run the project test suite.`,
      patch: [`- \"${name}\": \"${version}\"`, `+ \"${name}\": \"${policy.below}\" or newer`],
    };
    results.push(finding(rule, relativePath, 1, `\"${name}\": \"${version}\"`, "Dependency audit"));
  }
  return results;
}

function dependencyInventory(lock) {
  const packages = lock.packages ?? lock.dependencies ?? {};
  return Object.entries(packages).flatMap(([key, value]) => {
    const name = key.startsWith("node_modules/") ? key.slice(13) : key;
    return name && value?.version ? [{ ecosystem: "npm", name, version: value.version }] : [];
  }).slice(0, 500);
}

export function manifestInventory(name, content) {
  try {
    if (name === "package-lock.json") return dependencyInventory(JSON.parse(content));
    if (name === "composer.lock") return [...(JSON.parse(content).packages || []), ...(JSON.parse(content)["packages-dev"] || [])]
      .flatMap((item) => item.name && item.version ? [{ ecosystem: "Packagist", name: item.name, version: String(item.version).replace(/^v/, "") }] : []);
  } catch { return []; }
  if (name === "requirements.txt") return content.split(/\r?\n/).flatMap((line) => {
    const match = line.trim().match(/^([A-Za-z0-9_.-]+)==([^\s;]+)/);
    return match ? [{ ecosystem: "PyPI", name: match[1], version: match[2] }] : [];
  });
  if (name === "go.sum") return [...new Map(content.split(/\r?\n/).flatMap((line) => {
    const match = line.match(/^(\S+)\s+v([^\s/]+)(?:\/go\.mod)?\s+h1:/);
    return match ? [[`${match[1]}@${match[2]}`, { ecosystem: "Go", name: match[1], version: match[2] }]] : [];
  })).values()];
  if (name === "Gemfile.lock") return content.split(/\r?\n/).flatMap((line) => {
    const match = line.match(/^\s{4}([A-Za-z0-9_.-]+) \(([^ )]+)\)/);
    return match ? [{ ecosystem: "RubyGems", name: match[1], version: match[2] }] : [];
  });
  if (name === "Cargo.lock") {
    const results = [];
    for (const block of content.split(/\[\[package\]\]/).slice(1)) {
      const packageName = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
      const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
      if (packageName && version) results.push({ ecosystem: "crates.io", name: packageName, version });
    }
    return results;
  }
  return [];
}

async function liveOsvFindings(inventory, relativePath, enabled = process.env.CHROLLO_LIVE_OSV !== "false") {
  if (!enabled) return null;
  if (!inventory.length) return [];
  try {
    const results = [];
    for (let offset = 0; offset < inventory.length; offset += 500) {
      const batch = inventory.slice(offset, offset + 500);
      const response = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: batch.map((item) => ({ package: { ecosystem: item.ecosystem, name: item.name }, version: item.version })) }),
        signal: AbortSignal.timeout(20_000),
      });
      if (!response.ok) return null;
      const payload = await response.json();
      for (let index = 0; index < batch.length; index += 1) {
        for (const vulnerability of payload.results?.[index]?.vulns || []) {
          const dependency = batch[index];
          const databaseSeverity = String(vulnerability.database_specific?.severity || "").toLowerCase();
          const level = databaseSeverity === "critical" ? "critical" : databaseSeverity === "moderate" || databaseSeverity === "medium" ? "medium" : "high";
          results.push(finding({
            id: vulnerability.id,
            severity: level,
            title: `${vulnerability.id} affects ${dependency.name}`,
            explanation: vulnerability.summary || `${dependency.name} ${dependency.version} is affected by a published OSV advisory.`,
            patch: ["Upgrade to a fixed version listed by the advisory, regenerate the lock file and run the full test suite."],
          }, relativePath, 1, `${dependency.ecosystem}:${dependency.name} ${dependency.version}`, "OSV.dev"));
        }
      }
    }
    return results;
  } catch { return null; }
}

function gitLog(root, maximumCommits) {
  return new Promise((resolve) => {
    const child = spawn("git", ["log", "-p", `-n${maximumCommits}`, "--no-ext-diff", "--format=commit:%H"], { cwd: root, shell: false, windowsHide: true });
    let output = "";
    const limit = 5_000_000;
    child.stdout.on("data", (chunk) => { if (output.length < limit) output += chunk; });
    const timer = setTimeout(() => child.kill(), 20_000);
    child.on("error", () => { clearTimeout(timer); resolve(""); });
    child.on("close", () => { clearTimeout(timer); resolve(output.slice(0, limit)); });
  });
}

async function historySecretFindings(root) {
  if (process.env.CHROLLO_HISTORY_SCAN === "false") return [];
  const history = await gitLog(root, Math.max(1, Math.min(200, Number(process.env.CHROLLO_HISTORY_COMMITS || 50))));
  const results = [];
  let file = "git-history";
  let commit = "unknown";
  for (const line of history.split(/\r?\n/)) {
    if (line.startsWith("commit:")) commit = line.slice(7, 19);
    else if (line.startsWith("+++ b/")) file = line.slice(6);
    else if (line.startsWith("+") && !line.startsWith("+++")) {
      for (const rule of secretRules) if (rule.pattern.test(line)) {
        const item = finding(rule, file, 1, line, "Secret scan");
        item.tool = "Git history";
        item.commit = commit;
        item.id = `${rule.id}-HISTORY-${Buffer.from(`${commit}:${file}`).toString("hex").slice(-10)}`;
        results.push(item);
      }
    }
  }
  return results;
}

export async function scanLocalRepository(root, options = {}) {
  const started = Date.now();
  const maximum = Number(options.maxFiles ?? 2500);
  const maximumBytes = Math.max(1, Number(options.maxBytes ?? 50_000_000));
  const maximumFileBytes = Math.max(1, Number(options.maxFileBytes ?? 512_000));
  const files = await collectFiles(root, maximum);
  const findings = [];
  let bytes = 0;
  let filesScanned = 0;
  let skippedLargeFiles = 0;
  let byteLimitReached = false;
  for (const absolute of files) {
    const stat = await fs.stat(absolute);
    if (stat.size > maximumFileBytes) { skippedLargeFiles += 1; continue; }
    if (bytes + stat.size > maximumBytes) { byteLimitReached = true; break; }
    bytes += stat.size;
    filesScanned += 1;
    const relative = path.relative(root, absolute);
    const content = await fs.readFile(absolute, "utf8");
    if (["package-lock.json", "requirements.txt", "go.sum", "Gemfile.lock", "composer.lock", "Cargo.lock"].includes(path.basename(absolute))) {
      try {
        const inventory = manifestInventory(path.basename(absolute), content);
        const live = await liveOsvFindings(inventory, relative, options.liveOsv ?? process.env.CHROLLO_LIVE_OSV !== "false");
        if (live === null && path.basename(absolute) === "package-lock.json") findings.push(...dependencyFindings(JSON.parse(content), relative));
        else findings.push(...(live || []));
      } catch { /* invalid lock files are ignored */ }
    }
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      for (const rule of sourceRules) if (rule.pattern.test(line)) findings.push(finding(rule, relative, index + 1, line, "Source scan"));
      for (const rule of secretRules) if (rule.pattern.test(line)) findings.push(finding(rule, relative, index + 1, line, "Secret scan"));
    }
    for (let index = 0; index < lines.length; index += 4) {
      const window = lines.slice(index, index + 8).join("\n");
      for (const rule of multilineRules) if (rule.pattern.test(window)) findings.push(finding(rule, relative, index + 1, window, "Context scan"));
    }
  }
  findings.push(...await historySecretFindings(root));
  const unique = [...new Map(findings.map((item) => [`${item.rule}:${item.file}:${item.line}`, item])).values()];
  const score = Math.max(0, 100 - unique.reduce((total, item) => total + weights[item.severity], 0));
  return {
    findings: unique,
    summary: {
      score,
      open: unique.length,
      resolved: 0,
      critical: unique.filter((item) => item.severity === "critical").length,
      high: unique.filter((item) => item.severity === "high").length,
      filesScanned,
      bytesScanned: bytes,
      skippedLargeFiles,
      durationMs: Date.now() - started,
      truncated: files.length >= maximum || byteLimitReached,
      truncationReason: byteLimitReached ? "byte-limit" : files.length >= maximum ? "file-limit" : null,
      scanners: ["Source scan", "Context scan", "Secret scan", "Git history", "OSV.dev"],
    },
  };
}
