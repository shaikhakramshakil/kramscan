import { Finding } from "../skills/types";

export interface ScanTarget {
  url: string;
}

export interface ScanOptions {
  deep: boolean;
  timeoutSeconds: number;
  threads: number;
  skills?: string[];
  excludeSkills?: string[];
  proxy?: string;
  aiEnabled?: boolean;
  aiModel?: string;
}

export interface ScanResult {
  id: string;
  startedAt: string;
  finishedAt: string;
  target: ScanTarget;
  options: ScanOptions;
  skillsRun: string[];
  findings: Finding[];
  aiSummary?: string;
}
