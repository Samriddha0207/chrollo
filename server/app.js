import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ScanStore } from "./store.js";
import { AuditService } from "./service.js";
import { publicError, readJson, sendJson, validateGithubUrl } from "./utils.js";
import { loadEnv } from "./env.js";
import { createRemediationPullRequest, githubConfigured } from "./github.js";
import { cleanupStaleClones } from "./repository.js";
import { ScanQueue } from "./jobs.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.dirname(here);
await loadEnv(path.join(projectRoot, ".env"));
const staticRoot = path.join(projectRoot, "dist");
const dataDirectory = process.env.CHROLLO_DATA_DIR || path.join(projectRoot, "data");
const port = Number(process.env.PORT || 4173);
const store = new ScanStore(dataDirectory);
await store.initialize();
await cleanupStaleClones();
const service = new AuditService(store, {
  timeoutMs: process.env.CHROLLO_SCAN_TIMEOUT_MS,
  maxFiles: process.env.CHROLLO_MAX_FILES,
});
const scanQueue = new ScanQueue(service, {
  concurrency: process.env.CHROLLO_SCAN_CONCURRENCY || 2,
  maximumQueued: process.env.CHROLLO_MAX_QUEUED_SCANS || 20,
});
const requestWindows = new Map();
const rateLimit = Number(process.env.CHROLLO_RATE_LIMIT || 30);

const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

function routeMatch(pathname, pattern) {
  const match = pathname.match(pattern);
  return match ? match.slice(1).map(decodeURIComponent) : null;
}

function allowRequest(request) {
  const key = request.socket.remoteAddress || "local";
  const now = Date.now();
  const window = requestWindows.get(key) || { startedAt: now, count: 0 };
  if (now - window.startedAt > 60_000) { window.startedAt = now; window.count = 0; }
  window.count += 1;
  requestWindows.set(key, window);
  return window.count <= rateLimit;
}

function authorized(request, url) {
  const expected = process.env.CHROLLO_API_TOKEN;
  if (!expected || url.pathname === "/api/health") return true;
  const supplied = request.headers.authorization?.replace(/^Bearer\s+/i, "") || request.headers["x-chrollo-token"];
  if (!supplied || supplied.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
}

function validBrowserOrigin(request) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) return true;
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    const source = new URL(origin);
    const expected = new URL(`http://${request.headers.host || "localhost"}`);
    return source.protocol === expected.protocol && source.host === expected.host;
  } catch { return false; }
}

function toSarif(scan) {
  const rules = [...new Map(scan.findings.map((item) => [item.rule, {
    id: item.rule,
    name: item.title,
    shortDescription: { text: item.title },
    fullDescription: { text: item.explanation },
    defaultConfiguration: { level: item.severity === "critical" || item.severity === "high" ? "error" : item.severity === "medium" ? "warning" : "note" },
  }])).values()];
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { name: "Chrollo", version: "1.0.0", rules } },
      results: scan.findings.map((item) => ({
        ruleId: item.rule,
        level: item.severity === "critical" || item.severity === "high" ? "error" : item.severity === "medium" ? "warning" : "note",
        message: { text: item.title },
        locations: [{ physicalLocation: { artifactLocation: { uri: item.file }, region: { startLine: item.line } } }],
      })),
    }],
  };
}

async function handleApi(request, response, url) {
  if (request.method === "GET" && url.pathname === "/api/health") {
    return sendJson(response, 200, {
      status: "ok",
      version: "1.3.0",
      integrations: {
        ai: Boolean(process.env.GEMINI_API_KEY),
        github: githubConfigured(),
        persistence: store.status(),
        externalScanners: process.env.CHROLLO_EXTERNAL_SCANNERS === "true",
      },
      queue: scanQueue.stats(),
    });
  }

  if (request.method === "GET" && url.pathname === "/api/metrics") {
    const scans = await store.all();
    return sendJson(response, 200, {
      queue: scanQueue.stats(),
      scansStored: scans.length,
      findingsStored: scans.reduce((total, scan) => total + (scan.findings?.length || 0), 0),
      uptimeSeconds: Math.round(process.uptime()),
      memory: process.memoryUsage(),
    });
  }

  if (request.method === "GET" && url.pathname === "/api/scans") {
    const scans = await store.all();
    return sendJson(response, 200, scans.map(({ findings, ...scan }) => ({ ...scan, findingCount: findings.length })));
  }

  if (request.method === "POST" && url.pathname === "/api/scans") {
    const body = await readJson(request);
    const repository = validateGithubUrl(body.repositoryUrl);
    const job = scanQueue.enqueue(repository);
    response.setHeader("location", `/api/jobs/${job.id}`);
    return sendJson(response, 202, job);
  }

  const jobRoute = routeMatch(url.pathname, /^\/api\/jobs\/([^/]+)$/);
  if (request.method === "GET" && jobRoute) {
    const job = scanQueue.get(jobRoute[0]);
    return job ? sendJson(response, 200, job) : sendJson(response, 404, { error: "Scan job not found or expired." });
  }

  const scanRoute = routeMatch(url.pathname, /^\/api\/scans\/([^/]+)$/);
  if (request.method === "GET" && scanRoute) {
    const scan = await store.get(scanRoute[0]);
    if (!scan) return sendJson(response, 404, { error: "Scan not found." });
    if (url.searchParams.get("format") === "sarif") {
      response.setHeader("content-disposition", `attachment; filename=chrollo-${scan.id}.sarif`);
      return sendJson(response, 200, toSarif(scan));
    }
    if (url.searchParams.get("format") === "json") response.setHeader("content-disposition", `attachment; filename=chrollo-${scan.id}.json`);
    return sendJson(response, 200, scan);
  }

  const rescanRoute = routeMatch(url.pathname, /^\/api\/scans\/([^/]+)\/rescan$/);
  if (request.method === "POST" && rescanRoute) {
    const prior = await store.get(rescanRoute[0]);
    if (!prior) return sendJson(response, 404, { error: "Scan not found." });
    const repository = validateGithubUrl(prior.repository.url);
    const job = scanQueue.enqueue(repository, prior.id);
    response.setHeader("location", `/api/jobs/${job.id}`);
    return sendJson(response, 202, job);
  }

  const decisionRoute = routeMatch(url.pathname, /^\/api\/scans\/([^/]+)\/findings\/([^/]+)\/decision$/);
  if (request.method === "POST" && decisionRoute) {
    const body = await readJson(request);
    if (!["approve", "reject"].includes(body.action)) return sendJson(response, 400, { error: "Action must be approve or reject." });
    const finding = await service.decide(decisionRoute[0], decisionRoute[1], body.action);
    return finding ? sendJson(response, 200, finding) : sendJson(response, 404, { error: "Finding not found." });
  }

  const explainRoute = routeMatch(url.pathname, /^\/api\/scans\/([^/]+)\/findings\/([^/]+)\/explain$/);
  if (request.method === "POST" && explainRoute) {
    if (!process.env.GEMINI_API_KEY) return sendJson(response, 503, { error: "GEMINI_API_KEY is not configured." });
    const finding = await service.explain(explainRoute[0], explainRoute[1]);
    return finding ? sendJson(response, 200, finding) : sendJson(response, 404, { error: "Finding not found." });
  }

  const remediationRoute = routeMatch(url.pathname, /^\/api\/scans\/([^/]+)\/findings\/([^/]+)\/remediate$/);
  if (request.method === "POST" && remediationRoute) {
    if (!githubConfigured()) return sendJson(response, 503, { error: "GitHub authentication is not configured." });
    const scan = await store.get(remediationRoute[0]);
    const finding = scan?.findings.find((item) => item.id === remediationRoute[1]);
    if (!scan || !finding) return sendJson(response, 404, { error: "Finding not found." });
    if (finding.decision !== "approve") return sendJson(response, 409, { error: "Approve the recommendation before creating a remediation pull request." });
    if (finding.remediationPullRequest) return sendJson(response, 200, finding.remediationPullRequest);
    const pullRequest = await createRemediationPullRequest(scan, finding);
    finding.remediationPullRequest = pullRequest;
    scan.events ||= [];
    scan.events.push({ type: "remediation_pull_request", findingId: finding.id, pullRequest, createdAt: new Date().toISOString() });
    await store.save(scan);
    return sendJson(response, 201, pullRequest);
  }

  return sendJson(response, 404, { error: "API route not found." });
}

async function handleStatic(response, url) {
  const requested = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const normalized = path.normalize(requested).replace(/^(\.\.(\/|\\|$))+/, "");
  const file = path.join(staticRoot, normalized);
  const relative = path.relative(staticRoot, file);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return sendJson(response, 403, { error: "Forbidden." });
  try {
    const contents = await fs.readFile(file);
    response.writeHead(200, {
      "content-type": types[path.extname(file)] || "application/octet-stream",
      "content-length": contents.length,
      "cache-control": "no-cache",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-resource-policy": "same-origin",
      "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    });
    response.end(contents);
  } catch (error) {
    if (error.code === "ENOENT") return sendJson(response, 404, { error: "Not found." });
    throw error;
  }
}

const server = http.createServer(async (request, response) => {
  const requestId = crypto.randomUUID();
  const startedAt = Date.now();
  response.setHeader("x-request-id", requestId);
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=()");
  response.on("finish", () => console.log(JSON.stringify({
    type: "http_request", requestId, method: request.method, path: request.url?.split("?")[0], status: response.statusCode, durationMs: Date.now() - startedAt,
  })));
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/") && !authorized(request, url)) return sendJson(response, 401, { error: "Authentication required." });
    if (url.pathname.startsWith("/api/") && !validBrowserOrigin(request)) return sendJson(response, 403, { error: "Cross-origin state-changing requests are not allowed." });
    const hasRequestBody = Number(request.headers["content-length"] || 0) > 0 || Boolean(request.headers["transfer-encoding"]);
    if (url.pathname.startsWith("/api/") && hasRequestBody && ["POST", "PUT", "PATCH"].includes(request.method) && !String(request.headers["content-type"] || "").toLowerCase().startsWith("application/json")) {
      return sendJson(response, 415, { error: "State-changing API requests require application/json." });
    }
    if (url.pathname.startsWith("/api/") && !allowRequest(request)) return sendJson(response, 429, { error: "Rate limit exceeded. Try again in one minute." });
    if (url.pathname.startsWith("/api/")) await handleApi(request, response, url);
    else if (request.method === "GET" || request.method === "HEAD") await handleStatic(response, url);
    else sendJson(response, 405, { error: "Method not allowed." });
  } catch (error) {
    const status = error.statusCode || (/valid|supported|form|too large|JSON|limit/.test(error.message) ? 400 : 500);
    sendJson(response, status, { error: publicError(error) });
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Chrollo is running at http://127.0.0.1:${port}`);
});
