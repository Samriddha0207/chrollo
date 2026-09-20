import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import crypto from "node:crypto";

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: false,
      windowsHide: true,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
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
    await run("git", ["-c", "http.sslBackend=openssl", "clone", "--depth=1", "--filter=blob:none", "--no-tags", "--", repository.cloneUrl, root], { timeoutMs });
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
