import crypto from "node:crypto";

export function scanId() {
  return `scan_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`;
}

export function validateGithubUrl(value) {
  let url;
  try {
    url = new URL(String(value ?? "").trim());
  } catch {
    throw new Error("Enter a valid GitHub repository URL.");
  }
  if (url.protocol !== "https:" || url.hostname !== "github.com") {
    throw new Error("Only HTTPS github.com repository URLs are supported.");
  }
  const parts = url.pathname.replace(/\.git$/, "").split("/").filter(Boolean);
  if (parts.length !== 2 || !parts.every((part) => /^[A-Za-z0-9_.-]+$/.test(part))) {
    throw new Error("Use a repository URL in the form https://github.com/owner/repository.");
  }
  return {
    owner: parts[0],
    repository: parts[1],
    cloneUrl: `https://github.com/${parts[0]}/${parts[1]}.git`,
    webUrl: `https://github.com/${parts[0]}/${parts[1]}`,
  };
}

export async function readJson(request, limit = 32_768) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) throw new Error("Request body is too large.");
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("Request body must be valid JSON.");
  }
}

export function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

export function publicError(error) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  return message.replace(/[\r\n]+/g, " ").slice(0, 500);
}
