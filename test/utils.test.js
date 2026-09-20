import test from "node:test";
import assert from "node:assert/strict";
import { validateGithubUrl } from "../server/utils.js";

test("accepts a canonical public GitHub repository URL", () => {
  const repository = validateGithubUrl("https://github.com/OWASP/NodeGoat.git");
  assert.equal(repository.owner, "OWASP");
  assert.equal(repository.repository, "NodeGoat");
  assert.equal(repository.cloneUrl, "https://github.com/OWASP/NodeGoat.git");
});

test("rejects non-GitHub and nested URLs", () => {
  assert.throws(() => validateGithubUrl("https://example.com/org/repo"));
  assert.throws(() => validateGithubUrl("https://github.com/org/repo/issues"));
});
