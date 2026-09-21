import test from "node:test";
import assert from "node:assert/strict";
import { ScanQueue } from "../server/jobs.js";

async function waitFor(predicate, timeoutMs = 1000) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > timeoutMs) throw new Error("Timed out waiting for queue state");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

test("bounds scan concurrency and returns completed jobs", async () => {
  let active = 0;
  let maximumActive = 0;
  const service = { async scan(repository, previous, id, progress) {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    progress(50, "Scanning");
    await new Promise((resolve) => setTimeout(resolve, 20));
    active -= 1;
    return { id, status: "complete", repository, findings: [], summary: { score: 100 } };
  } };
  const queue = new ScanQueue(service, { concurrency: 1, maximumQueued: 3 });
  const repository = { webUrl: "https://github.com/example/repo" };
  const first = queue.enqueue(repository);
  const second = queue.enqueue(repository);
  await waitFor(() => queue.get(second.id)?.status === "complete");
  assert.equal(queue.get(first.id).status, "complete");
  assert.equal(queue.get(second.id).scan.id, second.id);
  assert.equal(maximumActive, 1);
});

test("rejects work when queue capacity is exhausted", () => {
  const service = { scan: () => new Promise(() => {}) };
  const queue = new ScanQueue(service, { concurrency: 1, maximumQueued: 1 });
  queue.enqueue({ webUrl: "https://github.com/example/repo" });
  assert.throws(() => queue.enqueue({ webUrl: "https://github.com/example/other" }), /queue is full/i);
});
