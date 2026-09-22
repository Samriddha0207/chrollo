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

test("Vercel configuration routes API traffic to a bounded Node function", async () => {
  const configuration = JSON.parse(await fs.readFile(path.join(root, "vercel.json"), "utf8"));
  assert.equal(configuration.functions["api/index.js"].maxDuration, 300);
  assert.equal(configuration.functions["api/index.js"].supportsCancellation, true);
  assert.ok(configuration.rewrites.some((rewrite) => rewrite.source === "/api/:path*" && rewrite.destination.includes("_chrollo_path")));
  assert.equal(configuration.outputDirectory, "dist");
  assert.ok(!configuration.rewrites.some((rewrite) => rewrite.source === "/"));
});
