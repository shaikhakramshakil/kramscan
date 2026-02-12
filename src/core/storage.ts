import fs from "fs";
import path from "path";
import os from "os";
import { ScanResult } from "./types";

const ROOT_DIR = path.join(os.homedir(), ".openscan");
const SCANS_DIR = path.join(ROOT_DIR, "scans");
const LAST_SCAN_PATH = path.join(SCANS_DIR, "last.json");

function ensureDir(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

export function saveScanResult(result: ScanResult): string {
  ensureDir(SCANS_DIR);

  const filename = `${result.id}.json`;
  const filePath = path.join(SCANS_DIR, filename);
  const payload = JSON.stringify(result, null, 2);

  fs.writeFileSync(filePath, payload, "utf-8");
  fs.writeFileSync(LAST_SCAN_PATH, payload, "utf-8");

  return filePath;
}

export function loadLastScanResult(): ScanResult | null {
  if (!fs.existsSync(LAST_SCAN_PATH)) {
    return null;
  }

  const raw = fs.readFileSync(LAST_SCAN_PATH, "utf-8");
  return JSON.parse(raw) as ScanResult;
}

export function loadScanResultFromFile(filePath: string): ScanResult {
  const raw = fs.readFileSync(filePath, "utf-8");
  return JSON.parse(raw) as ScanResult;
}
