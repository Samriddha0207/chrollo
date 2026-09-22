import fs from "node:fs/promises";
import path from "node:path";

export class ScanStore {
  constructor(directory) {
    this.directory = path.resolve(directory);
    this.file = path.join(this.directory, "scans.json");
    this.queue = Promise.resolve();
    this.supabaseUrl = process.env.SUPABASE_URL?.replace(/\/$/, "");
    this.supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    this.lastRemoteError = null;
  }

  async initialize() {
    await fs.mkdir(this.directory, { recursive: true });
    try {
      await fs.access(this.file);
    } catch {
      await fs.writeFile(this.file, "[]\n", { encoding: "utf8", mode: 0o600 });
    }
    await fs.chmod(this.file, 0o600).catch(() => {});
  }

  async all() {
    if (this.supabaseUrl && this.supabaseKey) {
      try {
        const response = await fetch(`${this.supabaseUrl}/rest/v1/chrollo_scans?select=payload&order=created_at.desc&limit=50`, {
          headers: { apikey: this.supabaseKey, authorization: `Bearer ${this.supabaseKey}` },
          signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) throw new Error(`Supabase returned HTTP ${response.status}`);
        this.lastRemoteError = null;
        return (await response.json()).map((row) => row.payload);
      } catch (error) { this.lastRemoteError = error.message; }
    }
    const raw = await fs.readFile(this.file, "utf8");
    const scans = JSON.parse(raw);
    return scans.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async get(id) {
    return (await this.all()).find((scan) => scan.id === id) ?? null;
  }

  async save(scan) {
    const operation = this.queue.catch(() => {}).then(async () => {
      const scans = await this.all();
      const index = scans.findIndex((item) => item.id === scan.id);
      if (index >= 0) scans[index] = scan;
      else scans.unshift(scan);
      const temporary = `${this.file}.${process.pid}.tmp`;
      const retentionDays = Math.max(1, Number(process.env.CHROLLO_RETENTION_DAYS || 30));
      const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
      const retained = scans.filter((item) => Date.parse(item.createdAt) >= cutoff).slice(0, 50);
      await fs.writeFile(temporary, `${JSON.stringify(retained, null, 2)}\n`, "utf8");
      await fs.chmod(temporary, 0o600).catch(() => {});
      await fs.rename(temporary, this.file);
      if (this.supabaseUrl && this.supabaseKey) {
        try {
          const response = await fetch(`${this.supabaseUrl}/rest/v1/chrollo_scans?on_conflict=id`, {
            method: "POST",
            headers: {
              apikey: this.supabaseKey,
              authorization: `Bearer ${this.supabaseKey}`,
              "content-type": "application/json",
              prefer: "resolution=merge-duplicates,return=minimal",
            },
            body: JSON.stringify([{ id: scan.id, created_at: scan.createdAt, repository_url: scan.repository.url, payload: scan }]),
            signal: AbortSignal.timeout(10_000),
          });
          if (!response.ok) throw new Error(`Supabase returned HTTP ${response.status}`);
          this.lastRemoteError = null;
        } catch (error) { this.lastRemoteError = error.message; }
      }
    });
    this.queue = operation.catch(() => {});
    await operation;
    return scan;
  }

  async mutate(id, mutator) {
    let result = null;
    const operation = this.queue.catch(() => {}).then(async () => {
      const scans = await this.all();
      const scan = scans.find((item) => item.id === id);
      if (!scan) return;
      result = await mutator(scan);
      const temporary = `${this.file}.${process.pid}.tmp`;
      const retentionDays = Math.max(1, Number(process.env.CHROLLO_RETENTION_DAYS || 30));
      const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
      const retained = scans.filter((item) => Date.parse(item.createdAt) >= cutoff).slice(0, 50);
      await fs.writeFile(temporary, `${JSON.stringify(retained, null, 2)}\n`, "utf8");
      await fs.chmod(temporary, 0o600).catch(() => {});
      await fs.rename(temporary, this.file);
      if (this.supabaseUrl && this.supabaseKey) {
        try {
          const response = await fetch(`${this.supabaseUrl}/rest/v1/chrollo_scans?on_conflict=id`, {
            method: "POST",
            headers: { apikey: this.supabaseKey, authorization: `Bearer ${this.supabaseKey}`, "content-type": "application/json", prefer: "resolution=merge-duplicates,return=minimal" },
            body: JSON.stringify([{ id: scan.id, created_at: scan.createdAt, repository_url: scan.repository.url, payload: scan }]),
            signal: AbortSignal.timeout(10_000),
          });
          if (!response.ok) throw new Error(`Supabase returned HTTP ${response.status}`);
          this.lastRemoteError = null;
        } catch (error) { this.lastRemoteError = error.message; }
      }
    });
    this.queue = operation.catch(() => {});
    await operation;
    return result;
  }

  status() {
    return {
      configured: Boolean(this.supabaseUrl && this.supabaseKey),
      active: Boolean(this.supabaseUrl && this.supabaseKey && !this.lastRemoteError),
      fallback: "local-json",
      error: this.lastRemoteError,
    };
  }
}
