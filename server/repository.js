import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { githubToken } from "./github.js";

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: false,
      windowsHide: true,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
      ...(options.env ? { env: { ...process.env, GIT_TERMINAL_PROMPT: "0", ...options.env } } : {}),
    });
    let stdout = "";
    let stderr = "";
    const limit = 100_000;
    child.stdout.on("data", (chunk) => { if (stdout.length < limit) stdout += chunk; });
    child.stderr.on("data", (chunk) => { if (stderr.length < limit) stderr += chunk; });
    const timer = setTimeout(() => child.kill(), options.timeoutMs ?? 90_000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
      else reject(new Error(stderr.trim() || `${command} exited with code ${code}`));
    });
  });
}

export async function cloneRepository(repository, timeoutMs) {
  const root = path.join(os.tmpdir(), `chrollo-${crypto.randomBytes(8).toString("hex")}`);
  await fs.mkdir(root, { recursive: true });
  try {
    const token = await githubToken();
    const metadataResponse = await fetch(`https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repository)}`, {
      headers: {
        accept: "application/vnd.github+json",
        "user-agent": "chrollo-security-review",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      signal: AbortSignal.timeout(15_000),
    });
    if (!metadataResponse.ok) throw new Error(metadataResponse.status === 404 ? "Repository not found or the configured GitHub identity cannot access it." : `GitHub repository check failed with HTTP ${metadataResponse.status}`);
    const metadata = await metadataResponse.json();
    const maximumRepositoryKb = Number(process.env.CHROLLO_MAX_REPO_KB || 250_000);
    if (Number(metadata.size || 0) > maximumRepositoryKb) throw new Error(`Repository size ${metadata.size} KB exceeds the configured ${maximumRepositoryKb} KB limit.`);
    if (metadata.archived && process.env.CHROLLO_ALLOW_ARCHIVED !== "true") throw new Error("Archived repositories are disabled by policy.");
    const gitEnvironment = {
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : os.devNull,
      GIT_ALLOW_PROTOCOL: "https",
      GIT_CONFIG_COUNT: token ? "2" : "1",
      GIT_CONFIG_KEY_0: "http.sslBackend",
      GIT_CONFIG_VALUE_0: "openssl",
      ...(token ? { GIT_CONFIG_KEY_1: "http.extraHeader", GIT_CONFIG_VALUE_1: `Authorization: Bearer ${token}` } : {}),
    };
    const depth = Math.max(1, Math.min(200, Number(process.env.CHROLLO_GIT_DEPTH || 50)));
    await run("git", ["clone", `--depth=${depth}`, "--filter=blob:none", "--no-tags", "--no-recurse-submodules", "--", repository.cloneUrl, root], { timeoutMs, env: gitEnvironment });
    const maximumCloneBytes = Math.max(1_000_000, Number(process.env.CHROLLO_MAX_CLONE_BYTES || 500_000_000));
    let cloneBytes = 0;
    const pending = [root];
    while (pending.length) {
      const directory = pending.pop();
      for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
        const target = path.join(directory, entry.name);
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) pending.push(target);
        else if (entry.isFile()) cloneBytes += (await fs.stat(target)).size;
        if (cloneBytes > maximumCloneBytes) throw new Error(`Cloned repository exceeds the configured ${maximumCloneBytes} byte disk limit.`);
      }
    }
    const [{ stdout: commit }, { stdout: branch }] = await Promise.all([
      run("git", ["rev-parse", "HEAD"], { cwd: root, timeoutMs: 10_000 }),
      run("git", ["branch", "--show-current"], { cwd: root, timeoutMs: 10_000 }),
    ]);
    return { directory: root, commit, branch: branch || "HEAD", sizeKb: Number(metadata.size || 0), cloneBytes, private: Boolean(metadata.private) };
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
