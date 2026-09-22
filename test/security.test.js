import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scannerEnvironment } from "../server/external-scanners.js";
import { remediationDocument } from "../server/github.js";
import { gitProcessEnvironment } from "../server/repository.js";
import { ScanStore } from "../server/store.js";

test("external scanner environments exclude application credentials", () => {
  const previous = process.env.GITHUB_TOKEN;
  process.env.GITHUB_TOKEN = "must-not-leak";
  try {
    const environment = scannerEnvironment("C:/isolated-home");
    assert.equal(environment.GITHUB_TOKEN, undefined);
    assert.equal(environment.GEMINI_API_KEY, undefined);
    assert.equal(environment.SUPABASE_SERVICE_ROLE_KEY, undefined);
    assert.equal(environment.HOME, "C:/isolated-home");
  } finally {
    if (previous === undefined) delete process.env.GITHUB_TOKEN; else process.env.GITHUB_TOKEN = previous;
  }
});

test("Git environments expose only explicitly required credentials", () => {
  const previous = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = "must-not-leak";
  try {
    const environment = gitProcessEnvironment();
    assert.equal(environment.GEMINI_API_KEY, undefined);
    assert.equal(environment.GITHUB_TOKEN, undefined);
    assert.equal(environment.GIT_TERMINAL_PROMPT, "0");
  } finally {
    if (previous === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = previous;
  }
});

test("remediation documents keep untrusted evidence inside indented code", () => {
  const document = remediationDocument(
    { id: "scan", repository: { commit: "abc" } },
    { id: "finding", severity: "high", file: "a.js", line: 1, title: "Unsafe <script>", explanation: "Review", evidence: "```\n# injected", patch: ["```", "[click](javascript:alert(1))"] },
  );
  assert.match(document, /Unsafe &lt;script&gt;/);
  assert.match(document, /    ```\n    # injected/);
  assert.doesNotMatch(document, /\n```diff\n/);
});

test("atomic store mutations preserve concurrent finding decisions", async (context) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "chrollo-store-"));
  context.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = new ScanStore(directory);
  await store.initialize();
  await store.save({
    id: "scan-test", createdAt: new Date().toISOString(), repository: { url: "https://github.com/example/repo" },
    summary: { open: 2 }, findings: [{ id: "a", status: "open" }, { id: "b", status: "open" }],
  });
  await Promise.all([
    store.mutate("scan-test", async (scan) => { await new Promise((resolve) => setTimeout(resolve, 15)); scan.findings[0].status = "approved"; }),
    store.mutate("scan-test", (scan) => { scan.findings[1].status = "dismissed"; }),
  ]);
  const saved = await store.get("scan-test");
  assert.equal(saved.findings[0].status, "approved");
  assert.equal(saved.findings[1].status, "dismissed");
});
