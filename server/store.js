import fs from "node:fs/promises";
import path from "node:path";

export class ScanStore {
  constructor(directory) {
    this.directory = path.resolve(directory);
    this.file = path.join(this.directory, "scans.json");
    this.queue = Promise.resolve();
  }

  async initialize() {
    await fs.mkdir(this.directory, { recursive: true });
    try {
      await fs.access(this.file);
    } catch {
      await fs.writeFile(this.file, "[]\n", "utf8");
    }
  }

  async all() {
    const raw = await fs.readFile(this.file, "utf8");
    const scans = JSON.parse(raw);
    return scans.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async get(id) {
    return (await this.all()).find((scan) => scan.id === id) ?? null;
  }

  async save(scan) {
    this.queue = this.queue.then(async () => {
      const scans = await this.all();
      const index = scans.findIndex((item) => item.id === scan.id);
      if (index >= 0) scans[index] = scan;
      else scans.unshift(scan);
      const temporary = `${this.file}.${process.pid}.tmp`;
      await fs.writeFile(temporary, `${JSON.stringify(scans.slice(0, 50), null, 2)}\n`, "utf8");
      await fs.rename(temporary, this.file);
    });
    await this.queue;
    return scan;
  }
}
