import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { manifestInventory, scanLocalRepository } from "../server/scanners.js";

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

  const result = await scanLocalRepository(root, { liveOsv: false });
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

test("detects security flows that span multiple lines and languages", async (context) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "chrollo-test-"));
  context.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, "worker.py"), [
    "command = request.args.get('command')",
    "if command:",
    "    audit(command)",
    "    subprocess.run(",
    "        command,",
    "        shell=True",
    "    )",
  ].join("\n"));
  const result = await scanLocalRepository(root, { liveOsv: false });
  assert.ok(result.findings.some((finding) => finding.rule === "SEC-PY-SHELL"));
  assert.ok(result.findings.some((finding) => finding.rule === "SEC-EXEC-FLOW"));
});

test("extracts exact dependency versions from multiple ecosystems", () => {
  assert.deepEqual(manifestInventory("requirements.txt", "flask==2.0.0\nrequests>=2"), [{ ecosystem: "PyPI", name: "flask", version: "2.0.0" }]);
  assert.deepEqual(manifestInventory("go.sum", "golang.org/x/text v0.3.0 h1:abc\ngolang.org/x/text v0.3.0/go.mod h1:def"), [{ ecosystem: "Go", name: "golang.org/x/text", version: "0.3.0" }]);
  assert.deepEqual(manifestInventory("Gemfile.lock", "    rack (2.0.1)"), [{ ecosystem: "RubyGems", name: "rack", version: "2.0.1" }]);
});

test("enforces aggregate scan byte limits", async (context) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "chrollo-test-"));
  context.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, "a.js"), "const a = '1234567890';");
  await fs.writeFile(path.join(root, "b.js"), "const b = '1234567890';");
  const result = await scanLocalRepository(root, { liveOsv: false, maxBytes: 25 });
  assert.equal(result.summary.truncated, true);
  assert.equal(result.summary.truncationReason, "byte-limit");
  assert.equal(result.summary.filesScanned, 1);
});
