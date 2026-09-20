import { cloneRepository, removeClone } from "./repository.js";
import { scanLocalRepository } from "./scanners.js";
import { explainFinding } from "./ai.js";
import { runExternalScanners } from "./external-scanners.js";
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
      const external = await runExternalScanners(clone.directory);
      if (external.findings.length) {
        result.findings.push(...external.findings);
        const weights = { critical: 25, high: 14, medium: 7, low: 2 };
        result.summary.open = result.findings.length;
        result.summary.critical = result.findings.filter((item) => item.severity === "critical").length;
        result.summary.high = result.findings.filter((item) => item.severity === "high").length;
        result.summary.score = Math.max(0, 100 - result.findings.reduce((total, item) => total + weights[item.severity], 0));
        result.summary.scanners.push(...external.tools.filter((tool) => tool.available).map((tool) => tool.name));
      }
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
        externalScanners: external.tools,
      };
      if (previousScanId) {
        const previous = await this.store.get(previousScanId);
        if (previous) {
          const previousKeys = new Set(previous.findings.map((item) => `${item.rule}:${item.file}:${item.line}`));
          const currentKeys = new Set(scan.findings.map((item) => `${item.rule}:${item.file}:${item.line}`));
          scan.comparison = {
            scoreChange: scan.summary.score - previous.summary.score,
            newFindings: scan.findings.filter((item) => !previousKeys.has(`${item.rule}:${item.file}:${item.line}`)).length,
            fixedFindings: previous.findings.filter((item) => !currentKeys.has(`${item.rule}:${item.file}:${item.line}`)).length,
            unchangedFindings: scan.findings.filter((item) => previousKeys.has(`${item.rule}:${item.file}:${item.line}`)).length,
          };
        }
      }
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
