import fs from "node:fs/promises";

export async function loadEnv(file) {
  let raw;
  try { raw = await fs.readFile(file, "utf8"); }
  catch (error) { if (error.code === "ENOENT") return; throw error; }
  for (const sourceLine of raw.split(/\r?\n/)) {
    const line = sourceLine.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || process.env[key] !== undefined) continue;
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[key] = value.replace(/\\n/g, "\n");
  }
}
