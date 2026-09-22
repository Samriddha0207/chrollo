import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";

test("Vercel entry point restores the original API route without opening its own listener", async (context) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "chrollo-vercel-"));
  process.env.VERCEL = "1";
  process.env.CHROLLO_DATA_DIR = directory;
  context.after(async () => {
    delete process.env.VERCEL;
    delete process.env.CHROLLO_DATA_DIR;
    await fs.rm(directory, { recursive: true, force: true });
  });
  const { default: handler } = await import(`../api/index.js?test=${Date.now()}`);
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/index?_chrollo_path=health`);
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.runtime, "vercel-function");
  assert.equal(payload.status, "degraded");
  assert.ok(payload.warnings.some((warning) => warning.includes("SUPABASE_URL")));
});
