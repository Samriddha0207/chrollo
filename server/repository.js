import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import crypto from "node:crypto";
import * as tar from "tar";
import { githubToken } from "./github.js";

export function gitProcessEnvironment(overrides = {}) {
  const allowed = [
    "PATH", "Path", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "GIT_SSL_CAINFO",
  ];
  const environment = {
    GIT_TERMINAL_PROMPT: "0",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : os.devNull,
    GIT_ALLOW_PROTOCOL: "https",
  };
  for (const name of allowed) if (process.env[name]) environment[name] = process.env[name];
  return { ...environment, ...overrides };
}

function terminate(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGKILL");
  if (process.platform === "win32" && child.pid) {
    const killer = spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { shell: false, windowsHide: true, stdio: "ignore" });
    killer.unref();
  }
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: false,
      windowsHide: true,
      env: gitProcessEnvironment(options.env),
    });
    let stdout = "";
    let stderr = "";
    const limit = 100_000;
    child.stdout.on("data", (chunk) => { if (stdout.length < limit) stdout += chunk; });
    child.stderr.on("data", (chunk) => { if (stderr.length < limit) stderr += chunk; });
    const timer = setTimeout(() => terminate(child), options.timeoutMs ?? 90_000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
      else reject(new Error(stderr.trim() || `${command} exited with code ${code}`));
    });
  });
}

function githubHeaders(token) {
  return {
    accept: "application/vnd.github+json",
    "user-agent": "chrollo-security-review",
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

async function repositoryMetadata(repository, token) {
  const response = await fetch(`https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repository)}`, {
    headers: githubHeaders(token),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(response.status === 404 ? "Repository not found or the configured GitHub identity cannot access it." : `GitHub repository check failed with HTTP ${response.status}`);
  const metadata = await response.json();
  const maximumRepositoryKb = Number(process.env.CHROLLO_MAX_REPO_KB || 250_000);
  if (Number(metadata.size || 0) > maximumRepositoryKb) throw new Error(`Repository size ${metadata.size} KB exceeds the configured ${maximumRepositoryKb} KB limit.`);
  if (metadata.archived && process.env.CHROLLO_ALLOW_ARCHIVED !== "true") throw new Error("Archived repositories are disabled by policy.");
  return metadata;
}

async function directorySize(root, maximumBytes) {
  let bytes = 0;
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop();
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) pending.push(target);
      else if (entry.isFile()) bytes += (await fs.stat(target)).size;
      if (bytes > maximumBytes) throw new Error(`Repository snapshot exceeds the configured ${maximumBytes} byte disk limit.`);
    }
  }
  return bytes;
}

async function downloadArchive(repository, metadata, token, root, timeoutMs) {
  const commitResponse = await fetch(`https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repository)}/commits/${encodeURIComponent(metadata.default_branch)}`, {
    headers: githubHeaders(token),
    signal: AbortSignal.timeout(15_000),
  });
  if (!commitResponse.ok) throw new Error(`GitHub commit lookup failed with HTTP ${commitResponse.status}`);
  const commit = (await commitResponse.json()).sha;
  if (!/^[0-9a-f]{40}$/i.test(commit || "")) throw new Error("GitHub returned an invalid commit identifier.");
  const archiveResponse = await fetch(`https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repository)}/tarball/${commit}`, {
    headers: githubHeaders(token),
    redirect: "follow",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!archiveResponse.ok || !archiveResponse.body) throw new Error(`GitHub archive download failed with HTTP ${archiveResponse.status}`);
  const maximumBytes = Math.max(1_000_000, Number(process.env.CHROLLO_MAX_CLONE_BYTES || 500_000_000));
  const archive = path.join(os.tmpdir(), `chrollo-${crypto.randomBytes(8).toString("hex")}.tgz`);
  let downloaded = 0;
  let declaredExtracted = 0;
  let entries = 0;
  let extractionLimitExceeded = false;
  const maximumEntries = Math.max(100, Number(process.env.CHROLLO_MAX_ARCHIVE_ENTRIES || 20_000));
  const limiter = new Transform({
    transform(chunk, encoding, callback) {
      downloaded += chunk.length;
      callback(downloaded > maximumBytes ? new Error(`Repository archive exceeds the configured ${maximumBytes} byte download limit.`) : null, chunk);
    },
  });
  try {
    await pipeline(Readable.fromWeb(archiveResponse.body), limiter, createWriteStream(archive, { mode: 0o600 }));
    await tar.x({
      cwd: root,
      file: archive,
      strip: 1,
      preservePaths: false,
      strict: true,
      signal: AbortSignal.timeout(timeoutMs),
      filter: (entryPath, entry) => {
        entries += 1;
        declaredExtracted += Number(entry.size || 0);
        const unsafe = ["SymbolicLink", "Link", "CharacterDevice", "BlockDevice", "FIFO"].includes(entry.type);
        if (entries > maximumEntries || declaredExtracted > maximumBytes) extractionLimitExceeded = true;
        return !unsafe && !extractionLimitExceeded;
      },
    });
    if (extractionLimitExceeded) throw new Error("Repository archive exceeds the configured extraction size or entry-count limit.");
  } finally {
    await fs.rm(archive, { force: true });
  }
  const cloneBytes = await directorySize(root, maximumBytes);
  return { directory: root, commit, branch: metadata.default_branch, sizeKb: Number(metadata.size || 0), cloneBytes, private: Boolean(metadata.private), historyAvailable: false, acquisition: "github-archive" };
}

export async function cloneRepository(repository, timeoutMs) {
  const root = path.join(os.tmpdir(), `chrollo-${crypto.randomBytes(8).toString("hex")}`);
  await fs.mkdir(root, { recursive: true });
  try {
    const token = await githubToken();
    const metadata = await repositoryMetadata(repository, token);
    const mode = process.env.CHROLLO_REPOSITORY_MODE || (process.env.VERCEL ? "archive" : "git");
    if (mode === "archive") return await downloadArchive(repository, metadata, token, root, timeoutMs);
    if (mode !== "git") throw new Error("CHROLLO_REPOSITORY_MODE must be git or archive.");
    const gitEnvironment = {
      GIT_CONFIG_COUNT: token ? "2" : "1",
      GIT_CONFIG_KEY_0: "http.sslBackend",
      GIT_CONFIG_VALUE_0: "openssl",
      ...(token ? { GIT_CONFIG_KEY_1: "http.extraHeader", GIT_CONFIG_VALUE_1: `Authorization: Bearer ${token}` } : {}),
    };
    const depth = Math.max(1, Math.min(200, Number(process.env.CHROLLO_GIT_DEPTH || 50)));
    await run("git", ["clone", `--depth=${depth}`, "--filter=blob:none", "--no-tags", "--no-recurse-submodules", "--", repository.cloneUrl, root], { timeoutMs, env: gitEnvironment });
    const maximumCloneBytes = Math.max(1_000_000, Number(process.env.CHROLLO_MAX_CLONE_BYTES || 500_000_000));
    const cloneBytes = await directorySize(root, maximumCloneBytes);
    const [{ stdout: commit }, { stdout: branch }] = await Promise.all([
      run("git", ["rev-parse", "HEAD"], { cwd: root, timeoutMs: 10_000 }),
      run("git", ["branch", "--show-current"], { cwd: root, timeoutMs: 10_000 }),
    ]);
    return { directory: root, commit, branch: branch || "HEAD", sizeKb: Number(metadata.size || 0), cloneBytes, private: Boolean(metadata.private), historyAvailable: true, acquisition: "git" };
  } catch (error) {
    await fs.rm(root, { recursive: true, force: true });
    throw error;
  }
}

export async function cleanupStaleClones(maximumAgeMs = 6 * 60 * 60 * 1000) {
  const temporaryRoot = os.tmpdir();
  const now = Date.now();
  for (const entry of await fs.readdir(temporaryRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith("chrollo-")) continue;
    const target = path.join(temporaryRoot, entry.name);
    const stat = await fs.stat(target);
    if (now - stat.mtimeMs > maximumAgeMs) await fs.rm(target, { recursive: true, force: true });
  }
}

export async function removeClone(directory) {
  if (!directory || !path.basename(directory).startsWith("chrollo-")) return;
  await fs.rm(directory, { recursive: true, force: true });
}
