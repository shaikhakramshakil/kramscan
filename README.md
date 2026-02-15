<div align="center">
  <img src="https://github.com/user-attachments/assets/6439c670-8d73-4bdd-b8fa-c74de949a31e" width="500" alt="KramScan Logo" />

  <h3 align="center">AI-Powered Web Application Security Testing CLI</h3>

  <br />

  [![npm version](https://img.shields.io/npm/v/kramscan?style=for-the-badge&logo=npm&logoColor=white&color=cb3837)](https://www.npmjs.com/package/kramscan)
  [![npm downloads](https://img.shields.io/npm/dm/kramscan?style=for-the-badge&logo=npm&logoColor=white&color=blue)](https://www.npmjs.com/package/kramscan)
  [![License](https://img.shields.io/github/license/shaikhakramshakil/kramscan?style=for-the-badge&logo=github&logoColor=white&color=green)](https://github.com/shaikhakramshakil/kramscan/blob/main/LICENSE)
  [![Stars](https://img.shields.io/github/stars/shaikhakramshakil/kramscan?style=for-the-badge&logo=github&logoColor=white&color=yellow)](https://github.com/shaikhakramshakil/kramscan)
  [![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178c6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
  [![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-brightgreen?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org)

  <br />

  ðŸ”¬ **A next-generation security auditing tool that combines automated vulnerability scanning with multi-provider AI analysis.**

  *Empowering developers and security researchers with institutional-grade insights and an interactive AI agent.*

  <br />

  [ðŸŒ NPM Package](https://www.npmjs.com/package/kramscan) Â· [ðŸ“– Documentation](#-usage) Â· [ðŸž Report Bug](https://github.com/shaikhakramshakil/kramscan/issues)

</div>

---

<br />

## ðŸš€ The Problem We Solve
Web security is complex and often fragmented. Developers rely on multiple disjointed tools for scanning, manual testing, and reporting. Traditional automated scanners generate noise without context, and manual pentesting is time-consuming and expensive.

**KramScan bridges this gap.** We provide a unified command-line interface that orchestrates headless browser scanning, scrapes critical security headers, and leverages **Generative AI** (OpenAI, Gemini, Anthropic) to analyze findings. It delivers actionable, human-readable insights alongside raw vulnerability dataâ€”all in seconds.

<br />

---

<br />

## âœ¨ Key Features
| Feature | Description |
| :--- | :--- |
| ðŸ” **Automated Vulnerability Engine** | Detects XSS, SQL Injection, CSRF, and insecure headers using Puppeteer-powered crawling. |
| ðŸ¤– **Interactive AI Agent** | A conversational security assistant that understands natural language commands like "scan example.com". |
| ðŸ§  **Multi-Provider AI Analysis** | Supports OpenAI, Anthropic, Google Gemini, Mistral, OpenRouter, and Kimi (Moonshot). |
| ðŸ“„ **Professional Reporting** | Generates detailed DOCX, TXT, and JSON reports with executive summaries and remediation steps. |
| ðŸŒ **Headless Browser Testing** | Renders modern SPAs (Single Page Applications) to find vulnerabilities in dynamic content. |
| âš¡ **CLI-First Architecture** | Optimized for speed, scriptability, and seamless integration into CI/CD pipelines. |

<br />

---

<br />

## ðŸ—ï¸ Architecture & Workflow

```mermaid
graph LR
    A[User Command] --> B{CLI Controller};
    B --> C[Scanner Module<br/>Puppeteer / Cheerio];
    B --> D[AI Agent<br/>NLP Processing];
    
    C --> E[Vulnerability Detection<br/>XSS / SQLi / Headers];
    C --> F[Data Aggregation];
    
    E & F --> G[AI Analysis Engine<br/>LLM Provider];
    
    G --> H[Risk Assessment<br/>Confidence Scoring];
    H --> I[Report Generator<br/>DOCX / JSON / TXT];
    I --> J((Final Output));
```

<br />

---

<br />

## ðŸ§ª Tech Stack
<div align="center">

| Component | Technology |
| :--- | :--- |
| **Runtime** | Node.js â‰¥ 18 |
| **Language** | TypeScript 5.4 |
| **CLI Framework** | Commander.js, Inquirer.js |
| **Browser Automation** | Puppeteer (Headless Chrome) |
| **AI Integration** | OpenAI SDK, Google Generative AI, Anthropic SDK |
| **Reporting** | Docx, Chalk|
| **Package Manager** | NPM / Yarn / PNPM |

</div>

<br />

---

<br />

## ðŸ§  Supported AI Providers

| Provider | SDK / Integration | Default Model |
| :--- | :--- | :--- |
| **OpenAI** | `openai` | `gpt-4` |
| **Anthropic** | `@anthropic-ai/sdk` | `claude-3-5-sonnet-20241022` |
| **Google Gemini** | `@google/generative-ai` | `gemini-2.0-flash` |
| **Mistral** | `@mistralai/mistralai` | `mistral-large-latest` |
| **OpenRouter** | OpenAI-compatible | `anthropic/claude-3.5-sonnet` |
| **Kimi** | OpenAI-compatible | `moonshot-v1-8k` |
| **Groq** | OpenAI-compatible | `llama-3.1-8b-instant` |

> Switch providers instantly with `kramscan onboard` or by editing `~/.kramscan/config.json`.

### API Key Environment Variables
You can provide API keys via environment variables (useful for CI/CD) instead of saving them locally:

| Provider | Env Var |
| :--- | :--- |
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Gemini | `GEMINI_API_KEY` |
| Mistral | `MISTRAL_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |
| Kimi | `KIMI_API_KEY` |
| Groq | `GROQ_API_KEY` |

### Model Preflight (Onboarding)
During `kramscan onboard`, KramScan will try to validate the model you entered against the provider's live model list (best-effort) and warn if the model is invalid.

<br />

---

<br />

## ðŸš€ Quick Start

### 1. Installation
Install KramScan globally using npm:

```bash
npm install -g kramscan
```

### 2. First-Time Setup
Initialize the configuration wizard to set up your AI provider and API keys:

```bash
kramscan onboard
```

### 3. Run a Scan
Execute a full security scan on a target URL:

```bash
kramscan scan https://example.com
```

<br />

---

<br />

## ðŸ“– Usage & Commands

| Command | Description | Status |
| :--- | :--- | :---: |
| `kramscan` | Launch the interactive dashboard menu. | âœ… Stable |
| `kramscan scan <url>` | Run a comprehensive vulnerability scan. | âœ… Stable |
| `kramscan agent` | Start the conversational AI security assistant. | âœ… Stable |
| `kramscan analyze` | Analyze previous scan results using the configured AI. | âœ… Stable |
| `kramscan report` | Generate a professional report from scan data. | âœ… Stable |
| `kramscan onboard` | Run the configuration and setup wizard. | âœ… Stable |
| `kramscan doctor` | Verify environment health and dependencies. | âœ… Stable |
| `kramscan config` | View and edit current configuration settings. | âœ… Stable |
| `kramscan scans` | List and inspect recent scans. | ✅ Stable |
| `kramscan ai` | AI helpers (model listing and connectivity test). | ✅ Stable |

<br />

### Scan Profiles and Limits
KramScan supports profiles for quick tuning:

```bash
kramscan scan https://example.com --profile quick
kramscan scan https://example.com --profile balanced
kramscan scan https://example.com --profile deep
```

You can also control crawl limits and URL scope:

```bash
kramscan scan https://example.com --max-pages 30 --max-links-per-page 50
kramscan scan https://example.com --exclude "logout|signout"
kramscan scan https://example.com --include "^https://example\.com/docs"
```

### Automatic PDF Report After Scan
After each scan, KramScan automatically generates a PDF report (no separate command required).

The file is saved to:

- JSON: `~/.kramscan/scans/scan-<timestamp>.json`
- PDF: `~/.kramscan/reports/scanreport_<hostname>_<timestamp>.pdf`

You can disable it with:

```bash
kramscan scan https://example.com --no-pdf
```

### Scan History
Every scan is indexed in `~/.kramscan/scans/index.json`.

```bash
kramscan scans list -n 10
kramscan scans latest
```

### AI Diagnostics
List models and test your configured provider/model:

```bash
kramscan ai models -n 10
kramscan ai test
```

### Example Agent Session
```bash
$ kramscan agent
> scan https://example.com

Agent: I'll perform a comprehensive security scan of https://example.com.
       Checking for XSS, SQLi, and missing headers...
       [Scanning...]
       
Agent: Scan complete! Found 2 High severity issues.
       Would you like me to generate a report?
```

<br />

---

<br />

## ðŸ—ºï¸ Roadmap

- [x] Core vulnerability scanner (XSS, SQLi, CSRF, headers)
- [x] Multi-provider AI analysis engine
- [x] Interactive AI agent mode
- [x] Professional report generation (DOCX, TXT, JSON)
- [x] Configuration wizard & management
- [ ] Plugin system for custom scan modules
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] PDF report generation
- [ ] Web-based dashboard UI

<br />

---

<br />

## ðŸ”’ Security & Privacy
- **Local Execution:** All scanning logic runs locally on your machine.
- **API Key Safety:** AI provider API keys are stored securely in your local home directory and are never sent to our servers.
- **Data Privacy:** Scan data is sent only to your chosen AI provider for analysis and is not stored by KramScan.

<br />

---

<br />

## ðŸ‘¤ Author
<div align="center">

**Akram Shaikh**

[![Website](https://img.shields.io/badge/Website-akramshaikh.me-blue?style=for-the-badge&logo=google-chrome&logoColor=white)](https://akramshaikh.me)
[![GitHub](https://img.shields.io/badge/GitHub-shaikhakramshakil-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/shaikhakramshakil)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/shaikhakramshakil/)

</div>

<br />

---

<br />

## ðŸ“„ License
This project is licensed under the **MIT License** â€” see the [LICENSE](LICENSE) file for details.

<div align="center">
  <sub>Made with â¤ï¸ by Akram Shaikh</sub>
</div>

