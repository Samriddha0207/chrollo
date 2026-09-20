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
    const gitEnvironment = {
      GIT_CONFIG_COUNT: token ? "2" : "1",
      GIT_CONFIG_KEY_0: "http.sslBackend",
      GIT_CONFIG_VALUE_0: "openssl",
      ...(token ? { GIT_CONFIG_KEY_1: "http.extraHeader", GIT_CONFIG_VALUE_1: `Authorization: Bearer ${token}` } : {}),
    };
    await run("git", ["clone", "--depth=1", "--filter=blob:none", "--no-tags", "--", repository.cloneUrl, root], { timeoutMs, env: gitEnvironment });
    const [{ stdout: commit }, { stdout: branch }] = await Promise.all([
      run("git", ["rev-parse", "HEAD"], { cwd: root, timeoutMs: 10_000 }),
      run("git", ["branch", "--show-current"], { cwd: root, timeoutMs: 10_000 }),
    ]);
    return { directory: root, commit, branch: branch || "HEAD" };
  } catch (error) {
    await fs.rm(root, { recursive: true, force: true });
    throw error;
  }
}

export async function removeClone(directory) {
  if (!directory || !path.basename(directory).startsWith("chrollo-")) return;
  await fs.rm(directory, { recursive: true, force: true });
}
