import { scanId } from "./utils.js";

export class ScanQueue {
  constructor(service, options = {}) {
    this.service = service;
    this.concurrency = Math.max(1, Math.min(8, Number(options.concurrency ?? 2)));
    this.maximumQueued = Math.max(this.concurrency, Number(options.maximumQueued ?? 20));
    this.jobs = new Map();
    this.pending = [];
    this.active = 0;
  }

  enqueue(repository, previousScanId = null) {
    if (this.pending.length + this.active >= this.maximumQueued) {
      const error = new Error("The scan queue is full. Try again after an active scan completes.");
      error.statusCode = 503;
      throw error;
    }
    const id = scanId();
    const now = new Date().toISOString();
    const job = {
      id,
      status: "queued",
      progress: 5,
      phase: "Waiting for an available scan worker",
      createdAt: now,
      updatedAt: now,
      repositoryUrl: repository.webUrl,
      previousScanId,
    };
    this.jobs.set(id, job);
    this.pending.push({ job, repository, previousScanId });
    queueMicrotask(() => this.drain());
    return this.publicJob(job);
  }

  get(id) {
    const job = this.jobs.get(id);
    return job ? this.publicJob(job) : null;
  }

  stats() {
    return {
      active: this.active,
      queued: this.pending.length,
      concurrency: this.concurrency,
      capacity: this.maximumQueued,
      completed: [...this.jobs.values()].filter((job) => job.status === "complete").length,
      failed: [...this.jobs.values()].filter((job) => job.status === "failed").length,
    };
  }

  publicJob(job) {
    const { result, internalError, ...safe } = job;
    return { ...safe, ...(result ? { scan: result } : {}), ...(internalError ? { error: internalError } : {}) };
  }

  update(job, progress, phase) {
    job.progress = progress;
    job.phase = phase;
    job.updatedAt = new Date().toISOString();
  }

  async drain() {
    while (this.active < this.concurrency && this.pending.length) {
      const entry = this.pending.shift();
      this.active += 1;
      this.run(entry).finally(() => {
        this.active -= 1;
        this.prune();
        this.drain();
      });
    }
  }

  async run({ job, repository, previousScanId }) {
    job.status = "running";
    this.update(job, 12, "Validating repository and creating an isolated clone");
    try {
      const result = await this.service.scan(repository, previousScanId, job.id, (progress, phase) => this.update(job, progress, phase));
      job.status = "complete";
      job.result = result;
      this.update(job, 100, "Audit complete");
    } catch (error) {
      job.status = "failed";
      job.internalError = String(error?.message || "Scan failed").replace(/[\r\n]+/g, " ").slice(0, 500);
      this.update(job, 100, "Scan failed");
    }
  }

  prune() {
    const cutoff = Date.now() - 60 * 60 * 1000;
    for (const [id, job] of this.jobs) {
      if (["complete", "failed"].includes(job.status) && Date.parse(job.updatedAt) < cutoff) this.jobs.delete(id);
    }
  }
}
