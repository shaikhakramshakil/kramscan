import puppeteer from "puppeteer";
import { ScanResult } from "../core/vulnerability-detector";
import { ensureReportsDirectory } from "../core/scan-storage";
import path from "path";
import type { ScanError } from "../core/scanner";

export interface PdfGenerationOptions {
    filename?: string;
    format?: "A4" | "Letter" | "Legal";
    margin?: {
        top: string;
        bottom: string;
        left: string;
        right: string;
    };
}

export interface PdfReportData {
    scanResult: ScanResult;
    scanErrors?: ScanError[];
    pluginErrors?: Map<string, Array<{ url: string; error: string }>>;
}

function escapeHtml(text: string): string {
    return text
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function sanitizeFilenamePart(value: string): string {
    return value
        .replace(/[<>:"\/\\|?*\x00-\x1F]/g, "_")
        .replace(/\s+/g, "_")
        .replace(/_+/g, "_")
        .replace(/^_+|_+$/g, "");
}

function severityBadge(severity: string): string {
    const s = severity.toLowerCase();
    if (s === "critical") return "badge badge-critical";
    if (s === "high") return "badge badge-high";
    if (s === "medium") return "badge badge-medium";
    if (s === "low") return "badge badge-low";
    return "badge badge-info";
}

function buildPdfHtml(data: PdfReportData): string {
    const { scanResult, scanErrors = [], pluginErrors = new Map() } = data;
    
    const rows = scanResult.vulnerabilities
        .map((v, i) => {
            const sev = escapeHtml(v.severity.toUpperCase());
            const title = escapeHtml(v.title);
            const url = escapeHtml(v.url);
            const type = escapeHtml(v.type);
            const desc = escapeHtml(v.description);
            const evidence = v.evidence ? escapeHtml(v.evidence) : "";
            const remediation = v.remediation ? escapeHtml(v.remediation) : "";
            const cwe = v.cwe ? escapeHtml(v.cwe) : "";

            return `
      <div class="card">
        <div class="card-h">
          <div class="idx">${i + 1}.</div>
          <div class="title">${title}</div>
          <div class="${severityBadge(v.severity)}">${sev}</div>
        </div>
        <div class="meta">
          <div><span class="k">URL:</span> <span class="v mono">${url}</span></div>
          <div><span class="k">Type:</span> <span class="v mono">${type}</span></div>
          ${cwe ? `<div><span class="k">CWE:</span> <span class="v mono">${cwe}</span></div>` : ""}
        </div>
        <div class="section">
          <div class="k">Description</div>
          <div class="v">${desc}</div>
        </div>
        ${evidence ? `<div class="section"><div class="k">Evidence</div><div class="v mono pre">${evidence}</div></div>` : ""}
        ${remediation ? `<div class="section"><div class="k">Remediation</div><div class="v">${remediation}</div></div>` : ""}
      </div>`;
        })
        .join("\n");

    const summary = scanResult.summary;

    // Build errors section
    let errorsHtml = "";
    if (scanErrors.length > 0 || pluginErrors.size > 0) {
        const errorRows = scanErrors.map((e: ScanError) => `
            <tr>
                <td class="mono">${escapeHtml(e.url)}</td>
                <td>Crawl Error</td>
                <td>${escapeHtml(e.error)}</td>
            </tr>
        `).join("");

        const pluginErrorRows: string[] = [];
        pluginErrors.forEach((errors, pluginName) => {
            errors.forEach((e: { url: string; error: string }) => {
                pluginErrorRows.push(`
                    <tr>
                        <td class="mono">${escapeHtml(e.url)}</td>
                        <td>${escapeHtml(pluginName)}</td>
                        <td>${escapeHtml(e.error)}</td>
                    </tr>
                `);
            });
        });

        const totalErrors = scanErrors.length + pluginErrorRows.length;
        
        errorsHtml = `
        <div class="section-header">
            <h2>⚠️ Scan Errors & Skipped Items</h2>
            <span class="badge badge-warning">${totalErrors} items</span>
        </div>
        <div class="error-table-container">
            <table class="error-table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Source</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
                    ${errorRows}
                    ${pluginErrorRows.join("")}
                </tbody>
            </table>
        </div>`;
    }

    return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>KramScan Security Report</title>
    <style>
      :root {
        --bg: #0b1020;
        --panel: #111a33;
        --panel2: #0e1630;
        --text: #e9eefc;
        --muted: #a9b6e5;
        --line: rgba(233,238,252,0.14);
        --critical: #ff4d4f;
        --high: #ff7a45;
        --medium: #fadb14;
        --low: #40a9ff;
        --info: #8c8c8c;
        --warning: #faad14;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        padding: 28px;
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Noto Sans", "Helvetica Neue", sans-serif;
        color: var(--text);
        background: radial-gradient(1000px 600px at 20% 10%, rgba(64,169,255,0.20), transparent 60%),
                    radial-gradient(900px 500px at 70% 0%, rgba(255,77,79,0.18), transparent 55%),
                    linear-gradient(180deg, var(--bg), #070a14 70%);
      }
      .top {
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        gap: 16px;
        padding-bottom: 14px;
        border-bottom: 1px solid var(--line);
      }
      .brand {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .h1 { font-size: 22px; font-weight: 800; letter-spacing: 0.3px; }
      .sub { color: var(--muted); font-size: 12px; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
      .pill {
        padding: 6px 10px;
        border: 1px solid var(--line);
        border-radius: 999px;
        background: rgba(17,26,51,0.55);
        color: var(--muted);
        font-size: 12px;
        white-space: nowrap;
      }
      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr 1fr 1fr 1fr;
        gap: 10px;
        margin: 16px 0 10px;
      }
      .stat {
        border: 1px solid var(--line);
        background: rgba(17,26,51,0.55);
        border-radius: 12px;
        padding: 10px 12px;
      }
      .stat .k { color: var(--muted); font-size: 11px; }
      .stat .v { font-size: 18px; font-weight: 800; margin-top: 6px; }
      .cards { margin-top: 14px; display: flex; flex-direction: column; gap: 12px; }
      .card {
        border: 1px solid var(--line);
        background: linear-gradient(180deg, rgba(17,26,51,0.70), rgba(14,22,48,0.70));
        border-radius: 14px;
        padding: 12px 12px 10px;
        page-break-inside: avoid;
      }
      .card-h {
        display: grid;
        grid-template-columns: auto 1fr auto;
        align-items: center;
        gap: 10px;
      }
      .idx { color: var(--muted); font-weight: 700; }
      .title { font-weight: 800; }
      .badge {
        padding: 4px 8px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 800;
        border: 1px solid var(--line);
      }
      .badge-critical { background: rgba(255,77,79,0.18); color: #ffd1d1; border-color: rgba(255,77,79,0.45); }
      .badge-high { background: rgba(255,122,69,0.18); color: #ffe1d2; border-color: rgba(255,122,69,0.45); }
      .badge-medium { background: rgba(250,219,20,0.16); color: #fff3bf; border-color: rgba(250,219,20,0.40); }
      .badge-low { background: rgba(64,169,255,0.16); color: #d6ecff; border-color: rgba(64,169,255,0.40); }
      .badge-info { background: rgba(140,140,140,0.16); color: #eee; border-color: rgba(140,140,140,0.35); }
      .badge-warning { background: rgba(250,173,20,0.16); color: #fffbe6; border-color: rgba(250,173,20,0.40); }
      .meta { margin-top: 10px; display: grid; gap: 6px; }
      .section { margin-top: 10px; border-top: 1px dashed rgba(233,238,252,0.20); padding-top: 10px; }
      .section-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin: 24px 0 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid var(--line);
      }
      .section-header h2 { 
        margin: 0; 
        font-size: 16px; 
        color: var(--warning);
      }
      .error-table-container {
        border: 1px solid var(--line);
        border-radius: 12px;
        overflow: hidden;
        background: rgba(17,26,51,0.55);
      }
      .error-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
      }
      .error-table th {
        background: rgba(17,26,51,0.80);
        padding: 10px 12px;
        text-align: left;
        color: var(--muted);
        font-weight: 600;
        border-bottom: 1px solid var(--line);
      }
      .error-table td {
        padding: 8px 12px;
        border-bottom: 1px solid rgba(233,238,252,0.10);
        color: var(--text);
      }
      .error-table tr:last-child td {
        border-bottom: none;
      }
      .error-table tr:hover td {
        background: rgba(255,255,255,0.03);
      }
      .k { color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; }
      .v { margin-top: 6px; font-size: 12px; line-height: 1.45; }
      .pre { white-space: pre-wrap; }
      .footer { margin-top: 18px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--line); padding-top: 12px; }
    </style>
  </head>
  <body>
    <div class="top">
      <div class="brand">
        <div class="h1">KramScan Security Report</div>
        <div class="sub">Target: <span class="mono">${escapeHtml(scanResult.target)}</span></div>
        <div class="sub">Timestamp: <span class="mono">${escapeHtml(scanResult.timestamp)}</span></div>
      </div>
      <div class="pill">Automated PDF generated after scan</div>
    </div>

    <div class="grid">
      <div class="stat"><div class="k">Total</div><div class="v">${summary.total}</div></div>
      <div class="stat"><div class="k">Critical</div><div class="v">${summary.critical}</div></div>
      <div class="stat"><div class="k">High</div><div class="v">${summary.high}</div></div>
      <div class="stat"><div class="k">Medium</div><div class="v">${summary.medium}</div></div>
      <div class="stat"><div class="k">Low</div><div class="v">${summary.low}</div></div>
    </div>

    <div class="sub">Crawled URLs: <span class="mono">${scanResult.metadata.crawledUrls}</span> | Forms tested: <span class="mono">${scanResult.metadata.testedForms}</span> | Requests: <span class="mono">${scanResult.metadata.requestsMade}</span> | Duration: <span class="mono">${(scanResult.duration / 1000).toFixed(2)}s</span></div>

    <div class="cards">
      ${rows || `<div class="card"><div class="title">No vulnerabilities found</div><div class="v">The scanner did not detect issues in the tested scope.</div></div>`}
    </div>

    ${errorsHtml}

    <div class="footer">Generated by KramScan</div>
  </body>
</html>`;
}

export class PdfGenerator {
    async generate(
        data: PdfReportData,
        options: PdfGenerationOptions = {}
    ): Promise<string> {
        const reportsDir = await ensureReportsDirectory();

        const targetUrl = new URL(data.scanResult.target);
        const host = sanitizeFilenamePart(targetUrl.hostname || "unknown");
        const timestamp = new Date(data.scanResult.timestamp || new Date().toISOString())
            .toISOString()
            .replace(/[:.]/g, "-");

        const pdfFilename = options.filename || `scanreport_${host}_${timestamp}.pdf`;
        const pdfPath = path.join(reportsDir, pdfFilename);

        const browser = await puppeteer.launch({
            headless: true,
            args: ["--no-sandbox", "--disable-setuid-sandbox"],
        });

        try {
            const page = await browser.newPage();
            const html = buildPdfHtml(data);
            await page.setContent(html, { waitUntil: "networkidle0" });
            await page.pdf({
                path: pdfPath,
                format: options.format || "A4",
                printBackground: true,
                margin: options.margin || {
                    top: "12mm",
                    bottom: "12mm",
                    left: "10mm",
                    right: "10mm",
                },
            });
        } finally {
            await browser.close();
        }

        return pdfPath;
    }
}

export const pdfGenerator = new PdfGenerator();
