import fs from "node:fs/promises";
import path from "node:path";

const ignoredDirectories = new Set([".git", "node_modules", "vendor", "coverage", ".next", "build", "dist"]);
const textExtensions = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".env", ".py", ".go", ".java", ".rb", ".php", ".html", ".vue", ".svelte"]);
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

const secretRules = [
  { id: "SECRET-AWS", title: "AWS access key committed to source", pattern: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { id: "SECRET-PRIVATE-KEY", title: "Private key committed to source", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "critical" },
  { id: "SECRET-GENERIC", title: "Hard-coded credential", pattern: /(?:api[_-]?key|secret|password|token)\s*[=:]\s*["'][A-Za-z0-9_\-/.+=]{12,}["']/i, severity: "high" },
];

function redact(line) {
  return line.replace(/(["'])([^"']{6})[^"']+(["'])/g, "$1$2…redacted…$3").slice(0, 260);
}

function finding(rule, file, line, evidence, tool) {
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
        if (textExtensions.has(extension) || ["Dockerfile", "Gemfile", "package-lock.json"].includes(entry.name)) files.push(absolute);
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

export async function scanLocalRepository(root, options = {}) {
  const started = Date.now();
  const maximum = Number(options.maxFiles ?? 2500);
  const files = await collectFiles(root, maximum);
  const findings = [];
  let bytes = 0;
  for (const absolute of files) {
    const stat = await fs.stat(absolute);
    if (stat.size > 512_000) continue;
    bytes += stat.size;
    const relative = path.relative(root, absolute);
    const content = await fs.readFile(absolute, "utf8");
    if (path.basename(absolute) === "package-lock.json") {
      try { findings.push(...dependencyFindings(JSON.parse(content), relative)); } catch { /* invalid lock files are ignored */ }
    }
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      for (const rule of sourceRules) if (rule.pattern.test(line)) findings.push(finding(rule, relative, index + 1, line, "Source scan"));
      for (const rule of secretRules) if (rule.pattern.test(line)) findings.push(finding(rule, relative, index + 1, line, "Secret scan"));
    }
  }
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
      filesScanned: files.length,
      bytesScanned: bytes,
      durationMs: Date.now() - started,
      truncated: files.length >= maximum,
      scanners: ["Source scan", "Secret scan", "Dependency audit"],
    },
  };
}
