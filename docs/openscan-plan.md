# OpenScan Architecture Plan

Date: 2026-02-07

## Goals
- CLI-first web app security testing tool.
- Simple UX similar to OpenClaw.
- AI-assisted analysis (optional but supported).
- Report output in .docx and .txt.

## Tech Stack
- Runtime: Node.js + TypeScript.
- CLI: Commander (commands), Inquirer (prompts).
- UI: Chalk (colors), Ora (spinners).
- Scanner: Puppeteer + Axios.
- AI Engine: OpenAI and Anthropic providers.
- Reporter: DOCX + TXT.

## Scope (Now)
- Web application security testing only.
- CLI-only; no GUI, no gateway, no WebSocket.
- Manual dependency installation (user-managed).

## Non-Goals (Now)
- Network scanning beyond web apps.
- Long-running daemon services.
- Built-in dependency installers.

## User Experience
- `openscan onboard`: guided setup
- `openscan config set ai.provider openai`
- `openscan config set ai.apiKey sk-xxx`
- `openscan scan https://example.com`
- `openscan scan https://example.com --deep`
- `openscan scan https://example.com --skills sql,xss,headers`
- `openscan report`
- `openscan report --format word`
- `openscan report --format txt`
- `openscan report --ai-summary`
- `openscan doctor`
- `openscan skill list`

## CLI Commands (Proposed)
- `onboard`: interactive wizard for config and checks
- `config set|get|list`: manage settings
- `scan`: run skill-based scans for a target URL
- `report`: generate reports from last scan
- `doctor`: verify setup and dependencies
- `skill list|info`: available skills and metadata

## High-Level Architecture
- `src/commands`: CLI command handlers
- `src/core`: orchestration, config, logging, storage
- `src/skills`: skill registry and runner
- `src/ai`: AI provider interface and adapters
- `src/reports`: report renderers
- `templates/`: report templates (docx, txt)

## Data Flow
1. Parse CLI arguments and config.
2. Resolve target and selected skills.
3. Run skills and collect findings.
4. Optionally invoke AI for analysis/summaries.
5. Persist scan results (timestamped).
6. Generate reports from stored results.

## Skills Structure
- Each skill defines:
  - id, name, description
  - input requirements
  - checks and evidence collection
  - findings schema
- `skills/` contains skill definitions and test assets.
- Skill registry supports tags like `sql`, `xss`, `headers`.

## Skill Modules (Initial)
- SQLi Test (sqli-map)
- XSS Scan (payloads)
- Header Analysis (security headers)
- CSRF Test
- IDOR Scan
- JWT Analysis

## AI Integration
- Provider-agnostic interface in `src/ai`.
- Config keys: `ai.provider`, `ai.apiKey`, `ai.model`.
- Usage:
  - summarize findings
  - prioritize and explain risk
  - suggest remediation
- AI must never block non-AI scans.

## Reporting
- TXT: human-readable, CLI-friendly summary.
- DOCX: template-driven, professional report layout.
- Report includes:
  - target metadata
  - skills run
  - findings + severity
  - evidence snippets
  - AI summary (optional)

## Config and Storage
- Config stored in user home (path TBD).
- Scan results stored in `~/.openscan/scans/`.
- Allow `--output` to override report location.

## Testing Strategy
- Unit tests for core parsing and skills.
- Integration tests for report generation.
- Mock AI calls for deterministic tests.

## Milestones
1. CLI skeleton with `scan`, `report`, `doctor`.
2. Core storage + basic skills.
3. TXT report generation.
4. DOCX report generation.
5. AI provider integration.
6. Expanded skill library.
