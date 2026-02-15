import fs from "fs/promises";
import os from "os";
import path from "path";

export interface ScanIndexEntry {
  id: string;
  target: string;
  hostname: string;
  timestamp: string;
  jsonPath: string;
  pdfPath?: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

function getIndexPath(): string {
  return path.join(os.homedir(), ".kramscan", "scans", "index.json");
}

async function readIndex(): Promise<ScanIndexEntry[]> {
  const indexPath = getIndexPath();
  try {
    const raw = await fs.readFile(indexPath, "utf-8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed as ScanIndexEntry[];
    }
    return [];
  } catch {
    return [];
  }
}

async function writeIndex(entries: ScanIndexEntry[]): Promise<void> {
  const indexPath = getIndexPath();
  await fs.mkdir(path.dirname(indexPath), { recursive: true });
  await fs.writeFile(indexPath, JSON.stringify(entries, null, 2), "utf-8");
}

export async function addScanToIndex(entry: Omit<ScanIndexEntry, "id">): Promise<ScanIndexEntry> {
  const hostname = entry.hostname || "unknown";
  const id = `${new Date(entry.timestamp).getTime()}-${hostname}-${Math.random().toString(36).slice(2, 8)}`;
  const full: ScanIndexEntry = { ...entry, id };

  const existing = await readIndex();
  const merged = [full, ...existing]
    .filter((e, idx, arr) => arr.findIndex((x) => x.jsonPath === e.jsonPath) === idx)
    .slice(0, 500);

  await writeIndex(merged);
  return full;
}

export async function listScans(limit = 20): Promise<ScanIndexEntry[]> {
  const entries = await readIndex();
  return entries.slice(0, Math.max(1, limit));
}

export async function getLatestScan(): Promise<ScanIndexEntry | null> {
  const entries = await readIndex();
  return entries.length > 0 ? entries[0] : null;
}

