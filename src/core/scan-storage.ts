import fs from "fs/promises";
import os from "os";
import path from "path";

export interface ResolvedScanFile {
  filepath: string;
  filename: string;
  isLatest: boolean;
}

export function getKramScanHome(): string {
  return path.join(os.homedir(), ".kramscan");
}

export function getScansDirectory(): string {
  return path.join(getKramScanHome(), "scans");
}

export function getReportsDirectory(): string {
  return path.join(getKramScanHome(), "reports");
}

export async function ensureScansDirectory(): Promise<string> {
  const scanDir = getScansDirectory();
  await fs.mkdir(scanDir, { recursive: true });
  return scanDir;
}

export async function ensureReportsDirectory(): Promise<string> {
  const reportsDir = getReportsDirectory();
  await fs.mkdir(reportsDir, { recursive: true });
  return reportsDir;
}

export async function resolveScanFile(scanFile?: string): Promise<ResolvedScanFile> {
  if (scanFile) {
    const filepath = path.isAbsolute(scanFile)
      ? scanFile
      : path.join(process.cwd(), scanFile);
    return {
      filepath,
      filename: path.basename(filepath),
      isLatest: false,
    };
  }

  const scanDir = await ensureScansDirectory();
  const entries = await fs.readdir(scanDir, { withFileTypes: true });
  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
    .map((entry) => entry.name);

  if (files.length === 0) {
    throw new Error("No scan results found. Run 'kramscan scan <url>' first.");
  }

  const filesWithStats = await Promise.all(
    files.map(async (filename) => {
      const filepath = path.join(scanDir, filename);
      const stats = await fs.stat(filepath);
      return {
        filename,
        filepath,
        mtimeMs: stats.mtimeMs,
      };
    })
  );

  filesWithStats.sort((a, b) => b.mtimeMs - a.mtimeMs);
  const latest = filesWithStats[0];

  return {
    filepath: latest.filepath,
    filename: latest.filename,
    isLatest: true,
  };
}
