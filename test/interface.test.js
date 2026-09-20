import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

test("results overview contains accessible chart and export surfaces", async () => {
  const html = await fs.readFile(path.join(root, "dist", "index.html"), "utf8");
  for (const id of ["severity-chart", "scanner-chart", "score-chart", "json-export", "sarif-export", "rescan-button"]) {
    assert.match(html, new RegExp(`id=["']${id}["']`));
  }
  assert.match(html, /aria-labelledby="score-chart-title score-chart-description"/);
});
