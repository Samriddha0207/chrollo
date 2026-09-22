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

  async scan(repository, previousScanId = null, requestedId = null, onProgress = () => {}) {
    const id = requestedId || scanId();
    const createdAt = new Date().toISOString();
    const clone = await cloneRepository(repository, this.timeoutMs);
    try {
      onProgress(45, "Scanning source, secrets, history and dependency manifests");
      const result = await scanLocalRepository(clone.directory, {
        maxFiles: this.maxFiles,
        maxBytes: Number(process.env.CHROLLO_MAX_SCAN_BYTES || 50_000_000),
        maxFileBytes: Number(process.env.CHROLLO_MAX_FILE_BYTES || 512_000),
        historyScan: clone.historyAvailable,
      });
      onProgress(75, "Running configured external scanners");
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
      const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
      const totalFindings = result.findings.length;
      const maximumFindings = Math.max(1, Number(process.env.CHROLLO_MAX_FINDINGS || (process.env.VERCEL ? 500 : 1_000)));
      result.findings.sort((left, right) => (severityRank[left.severity] ?? 4) - (severityRank[right.severity] ?? 4));
      if (result.findings.length > maximumFindings) result.findings = result.findings.slice(0, maximumFindings);
      result.summary.totalFindings = totalFindings;
      result.summary.findingsReturned = result.findings.length;
      result.summary.findingsTruncated = totalFindings > result.findings.length;
      result.summary.open = result.findings.length;
      result.summary.critical = result.findings.filter((item) => item.severity === "critical").length;
      result.summary.high = result.findings.filter((item) => item.severity === "high").length;
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
          sizeKb: clone.sizeKb,
          cloneBytes: clone.cloneBytes,
          private: clone.private,
          acquisition: clone.acquisition,
        },
        ...result,
        externalScanners: external.tools,
      };
      onProgress(90, "Normalizing findings and calculating comparison data");
      if (previousScanId) {
        const previous = await this.store.get(previousScanId);
        if (previous) {
          const key = (item) => item.fingerprint || `${item.rule}:${item.file}:${item.line}`;
          const previousKeys = new Set(previous.findings.map(key));
          const currentKeys = new Set(scan.findings.map(key));
          scan.comparison = {
            scoreChange: scan.summary.score - previous.summary.score,
            newFindings: scan.findings.filter((item) => !previousKeys.has(key(item))).length,
            fixedFindings: previous.findings.filter((item) => !currentKeys.has(key(item))).length,
            unchangedFindings: scan.findings.filter((item) => previousKeys.has(key(item))).length,
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
    return this.store.mutate(scanIdValue, (scan) => {
      const finding = scan.findings.find((item) => item.id === findingId);
      if (!finding) return null;
      finding.decision = action;
      finding.decidedAt = new Date().toISOString();
      finding.status = action === "reject" ? "dismissed" : "approved";
      scan.events ||= [];
      scan.events.push({ type: "finding_decision", findingId, action, createdAt: finding.decidedAt });
      scan.summary.open = scan.findings.filter((item) => item.status === "open").length;
      return structuredClone(finding);
    });
  }

  async explain(scanIdValue, findingId) {
    const scan = await this.store.get(scanIdValue);
    const finding = scan?.findings.find((item) => item.id === findingId);
    if (!finding) return null;
    const explanation = await explainFinding(finding);
    if (explanation) {
      return this.store.mutate(scanIdValue, (current) => {
        const currentFinding = current.findings.find((item) => item.id === findingId);
        if (!currentFinding) return null;
        currentFinding.aiExplanation = explanation;
        return structuredClone(currentFinding);
      });
    }
    return finding;
  }
}
