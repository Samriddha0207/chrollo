import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scanLocalRepository } from "../server/scanners.js";

test("normalizes source, secret and dependency findings", async (context) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "chrollo-test-"));
  context.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, "route.js"), [
    "const token = 'abcdefghijklmnopqrstuvwxyz';",
    "const record = await users.findOne({ name: req.body.name });",
  ].join("\n"));
  await fs.writeFile(path.join(root, "package-lock.json"), JSON.stringify({
    lockfileVersion: 3,
    packages: { "node_modules/lodash": { version: "4.17.15" } },
  }));

  const result = await scanLocalRepository(root);
  assert.equal(result.summary.filesScanned, 2);
  assert.ok(result.findings.some((finding) => finding.rule === "SEC-NOSQL"));
  assert.ok(result.findings.some((finding) => finding.rule === "SECRET-GENERIC"));
  assert.ok(result.findings.some((finding) => finding.rule === "DEP-LODASH"));
  assert.ok(result.findings.find((finding) => finding.rule === "SECRET-GENERIC").evidence.includes("redacted"));
});

test("does not follow ignored dependency directories", async (context) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "chrollo-test-"));
  context.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, "node_modules"));
  await fs.writeFile(path.join(root, "node_modules", "unsafe.js"), "eval(userInput)");
  await fs.writeFile(path.join(root, "safe.js"), "const value = 1;");
  const result = await scanLocalRepository(root);
  assert.equal(result.summary.filesScanned, 1);
  assert.equal(result.findings.length, 0);
});
