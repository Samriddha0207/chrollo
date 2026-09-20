import { cloneRepository, removeClone } from "./repository.js";
import { scanLocalRepository } from "./scanners.js";
import { explainFinding } from "./ai.js";
import { scanId } from "./utils.js";

export class AuditService {
  constructor(store, options = {}) {
    this.store = store;
    this.timeoutMs = Number(options.timeoutMs ?? 90_000);
    this.maxFiles = Number(options.maxFiles ?? 2500);
  }

  async scan(repository, previousScanId = null) {
    const id = scanId();
    const createdAt = new Date().toISOString();
    const clone = await cloneRepository(repository, this.timeoutMs);
    try {
      const result = await scanLocalRepository(clone.directory, { maxFiles: this.maxFiles });
      const scan = {
        id,
        createdAt,
        completedAt: new Date().toISOString(),
        status: "complete",
        previousScanId,
        repository: {
          owner: repository.owner,
          name: repository.repository,
          url: repository.webUrl,
          branch: clone.branch,
          commit: clone.commit,
        },
        ...result,
      };
      await this.store.save(scan);
      return scan;
    } finally {
      await removeClone(clone.directory);
    }
  }

  async decide(scanIdValue, findingId, action) {
    const scan = await this.store.get(scanIdValue);
    if (!scan) return null;
    const finding = scan.findings.find((item) => item.id === findingId);
    if (!finding) return null;
    finding.decision = action;
    finding.decidedAt = new Date().toISOString();
    finding.status = action === "reject" ? "dismissed" : "approved";
    scan.summary.open = scan.findings.filter((item) => item.status === "open").length;
    await this.store.save(scan);
    return finding;
  }

  async explain(scanIdValue, findingId) {
    const scan = await this.store.get(scanIdValue);
    const finding = scan?.findings.find((item) => item.id === findingId);
    if (!finding) return null;
    const explanation = await explainFinding(finding);
    if (explanation) {
      finding.aiExplanation = explanation;
      await this.store.save(scan);
    }
    return finding;
  }
}
