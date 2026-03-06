import { Vulnerability, ScanResult } from "./vulnerability-detector";

export interface ScanDiff {
    newVulnerabilities: Vulnerability[];
    resolvedVulnerabilities: Vulnerability[];
    unchangedCount: number;
    previousTotal: number;
    currentTotal: number;
}

/**
 * Creates a unique fingerprint for a vulnerability to enable comparison.
 */
function vulnFingerprint(v: Vulnerability): string {
    return `${v.type}:${v.severity}:${v.title}:${new URL(v.url).pathname}`;
}

/**
 * Compares two scan results and produces a diff of new and resolved vulnerabilities.
 */
export function diffScanResults(
    previous: ScanResult,
    current: ScanResult
): ScanDiff {
    const prevFingerprints = new Map<string, Vulnerability>();
    const currFingerprints = new Map<string, Vulnerability>();

    for (const v of previous.vulnerabilities) {
        prevFingerprints.set(vulnFingerprint(v), v);
    }

    for (const v of current.vulnerabilities) {
        currFingerprints.set(vulnFingerprint(v), v);
    }

    const newVulnerabilities: Vulnerability[] = [];
    const resolvedVulnerabilities: Vulnerability[] = [];
    let unchangedCount = 0;

    // Find new vulnerabilities (in current but not in previous)
    for (const [fp, vuln] of currFingerprints) {
        if (!prevFingerprints.has(fp)) {
            newVulnerabilities.push(vuln);
        } else {
            unchangedCount++;
        }
    }

    // Find resolved vulnerabilities (in previous but not in current)
    for (const [fp, vuln] of prevFingerprints) {
        if (!currFingerprints.has(fp)) {
            resolvedVulnerabilities.push(vuln);
        }
    }

    return {
        newVulnerabilities,
        resolvedVulnerabilities,
        unchangedCount,
        previousTotal: previous.vulnerabilities.length,
        currentTotal: current.vulnerabilities.length,
    };
}
