import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadEnv } from "../server/env.js";
import { githubConfigured } from "../server/github.js";

test("loads environment configuration without overriding existing variables", async (context) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "chrollo-env-"));
  const file = path.join(directory, ".env");
  context.after(async () => {
    delete process.env.CHROLLO_TEST_NEW;
    delete process.env.CHROLLO_TEST_EXISTING;
    await fs.rm(directory, { recursive: true, force: true });
  });
  process.env.CHROLLO_TEST_EXISTING = "original";
  await fs.writeFile(file, "CHROLLO_TEST_NEW=loaded\nCHROLLO_TEST_EXISTING=replaced\n", "utf8");
  await loadEnv(file);
  assert.equal(process.env.CHROLLO_TEST_NEW, "loaded");
  assert.equal(process.env.CHROLLO_TEST_EXISTING, "original");
});

test("detects GitHub token or complete GitHub App configuration", () => {
  const previous = {
    token: process.env.GITHUB_TOKEN,
    app: process.env.GITHUB_APP_ID,
    key: process.env.GITHUB_APP_PRIVATE_KEY,
    installation: process.env.GITHUB_INSTALLATION_ID,
  };
  try {
    delete process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_APP_ID;
    delete process.env.GITHUB_APP_PRIVATE_KEY;
    delete process.env.GITHUB_INSTALLATION_ID;
    assert.equal(githubConfigured(), false);
    process.env.GITHUB_TOKEN = "test-token";
    assert.equal(githubConfigured(), true);
  } finally {
    for (const [name, value] of [["GITHUB_TOKEN", previous.token], ["GITHUB_APP_ID", previous.app], ["GITHUB_APP_PRIVATE_KEY", previous.key], ["GITHUB_INSTALLATION_ID", previous.installation]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});
