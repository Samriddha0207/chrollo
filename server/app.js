import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ScanStore } from "./store.js";
import { AuditService } from "./service.js";
import { publicError, readJson, sendJson, validateGithubUrl } from "./utils.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.dirname(here);
const staticRoot = path.join(projectRoot, "dist");
const dataDirectory = process.env.CHROLLO_DATA_DIR || path.join(projectRoot, "data");
const port = Number(process.env.PORT || 4173);
const store = new ScanStore(dataDirectory);
await store.initialize();
const service = new AuditService(store, {
  timeoutMs: process.env.CHROLLO_SCAN_TIMEOUT_MS,
  maxFiles: process.env.CHROLLO_MAX_FILES,
});

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

async function handleApi(request, response, url) {
  if (request.method === "GET" && url.pathname === "/api/health") {
    return sendJson(response, 200, { status: "ok", version: "1.0.0", aiEnabled: Boolean(process.env.GEMINI_API_KEY) });
  }

  if (request.method === "GET" && url.pathname === "/api/scans") {
    const scans = await store.all();
    return sendJson(response, 200, scans.map(({ findings, ...scan }) => ({ ...scan, findingCount: findings.length })));
  }

  if (request.method === "POST" && url.pathname === "/api/scans") {
    const body = await readJson(request);
    const repository = validateGithubUrl(body.repositoryUrl);
    const scan = await service.scan(repository);
    return sendJson(response, 201, scan);
  }

  const scanRoute = routeMatch(url.pathname, /^\/api\/scans\/([^/]+)$/);
  if (request.method === "GET" && scanRoute) {
    const scan = await store.get(scanRoute[0]);
    return scan ? sendJson(response, 200, scan) : sendJson(response, 404, { error: "Scan not found." });
  }

  const rescanRoute = routeMatch(url.pathname, /^\/api\/scans\/([^/]+)\/rescan$/);
  if (request.method === "POST" && rescanRoute) {
    const prior = await store.get(rescanRoute[0]);
    if (!prior) return sendJson(response, 404, { error: "Scan not found." });
    const repository = validateGithubUrl(prior.repository.url);
    const scan = await service.scan(repository, prior.id);
    return sendJson(response, 201, scan);
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

  return sendJson(response, 404, { error: "API route not found." });
}

async function handleStatic(response, url) {
  const requested = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const normalized = path.normalize(requested).replace(/^(\.\.(\/|\\|$))+/, "");
  const file = path.join(staticRoot, normalized);
  if (!file.startsWith(staticRoot)) return sendJson(response, 403, { error: "Forbidden." });
  try {
    const contents = await fs.readFile(file);
    response.writeHead(200, {
      "content-type": types[path.extname(file)] || "application/octet-stream",
      "content-length": contents.length,
      "cache-control": "no-cache",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    });
    response.end(contents);
  } catch (error) {
    if (error.code === "ENOENT") return sendJson(response, 404, { error: "Not found." });
    throw error;
  }
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) await handleApi(request, response, url);
    else if (request.method === "GET" || request.method === "HEAD") await handleStatic(response, url);
    else sendJson(response, 405, { error: "Method not allowed." });
  } catch (error) {
    const status = /valid|supported|form|too large|JSON/.test(error.message) ? 400 : 500;
    sendJson(response, status, { error: publicError(error) });
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Chrollo is running at http://127.0.0.1:${port}`);
});
