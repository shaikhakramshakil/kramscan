<p align="center">
  <img width="508" height="126" alt="KramScan" src="https://github.com/user-attachments/assets/6439c670-8d73-4bdd-b8fa-c74de949a31e" />
</p>

<h3 align="center">AI-Powered Web Application Security Testing CLI</h3>

<p align="center">
  <a href="https://www.npmjs.com/package/kramscan"><img src="https://img.shields.io/npm/v/kramscan?style=flat-square&color=cb3837&logo=npm&logoColor=white" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/kramscan"><img src="https://img.shields.io/npm/dm/kramscan?style=flat-square&color=blue" alt="npm downloads" /></a>
  <a href="https://github.com/shaikhakramshakil/kramscan/blob/main/LICENSE"><img src="https://img.shields.io/github/license/shaikhakramshakil/kramscan?style=flat-square&color=green" alt="license" /></a>
  <a href="https://github.com/shaikhakramshakil/kramscan"><img src="https://img.shields.io/github/stars/shaikhakramshakil/kramscan?style=flat-square&color=yellow" alt="stars" /></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square&logo=nodedotjs&logoColor=white" alt="node version" /></a>
  <a href="https://www.typescriptlang.org"><img src="https://img.shields.io/badge/TypeScript-5.4-3178c6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" /></a>
</p>

<p align="center">
  <b>Scan</b> · <b>Analyze</b> · <b>Report</b> — all from your terminal.
</p>

---

## ✨ Features

- 🔍 **Automated Vulnerability Scanning** — XSS, SQL Injection, CSRF, and insecure headers detection
- 🤖 **AI-Powered Agent** — Interactive security assistant with natural language understanding
- 🧠 **Multi-Provider AI Analysis** — OpenAI, Anthropic, Google Gemini, Mistral, OpenRouter & Kimi
- 📄 **Professional Reports** — Generate DOCX, TXT, or JSON security reports
- 🌐 **Headless Browser Testing** — Puppeteer-powered crawling for modern SPAs
- ⚡ **CLI-First Design** — Fast, scriptable, and CI/CD friendly

---

## 🚀 Quick Start

### Install globally

```bash
npm install -g kramscan
```

### Or run directly with npx

```bash
npx kramscan scan https://example.com
```

### First-time setup

```bash
kramscan onboard
```

> This walks you through configuring your AI provider, API key, default model, report format, and scan settings.

---

## 📖 Usage

```bash
# Launch the interactive dashboard
kramscan

# Scan a target URL
kramscan scan https://example.com

# Start the AI agent for conversational security testing
kramscan agent

# Analyze previous scan results with AI
kramscan analyze

# Generate a professional security report
kramscan report

# Check environment and dependency health
kramscan doctor
```

---

## 🛠️ Commands

| Command              | Description                              | Status       |
| :------------------- | :--------------------------------------- | :----------- |
| `kramscan`           | Launch interactive dashboard             | ✅ Active    |
| `kramscan agent`     | AI-powered interactive assistant         | ✅ Active    |
| `kramscan onboard`   | First-time setup wizard                  | ✅ Active    |
| `kramscan scan`      | Scan a target URL for vulnerabilities    | ✅ Active    |
| `kramscan analyze`   | AI-powered analysis of scan results      | ✅ Active    |
| `kramscan report`    | Generate a professional report           | ✅ Active    |
| `kramscan doctor`    | Check environment health                 | ✅ Active    |
| `kramscan config`    | View or update configuration             | ✅ Active    |
| `kramscan --help`    | Show all available commands              | ✅ Active    |

---

## 🤖 AI Agent

KramScan includes an AI-powered security assistant that understands natural language and executes security tasks through conversation.

```bash
kramscan agent
```

**Capabilities:**

| Skill             | Description                                              |
| :---------------- | :------------------------------------------------------- |
| 🔍 Web Scan       | Scan websites for XSS, SQLi, CSRF & header issues       |
| 🧠 Analyze        | AI analysis of discovered vulnerabilities                |
| 📄 Report         | Generate DOCX, TXT, or JSON security reports             |
| 🩺 Health Check   | Verify system configuration and dependencies             |

**Example session:**

```
You: scan https://example.com
Agent: I'll perform a comprehensive security scan of https://example.com.
       This will check for XSS, SQL injection, CSRF vulnerabilities, and security headers.

       Would you like me to proceed? [Y/n/details]: Y

       [Executing web_scan skill...]

Agent: Scan complete! Found 3 vulnerabilities:
       • 1 High: Missing CSRF token on login form
       • 1 Medium: Clickjacking vulnerability
       • 1 Low: Server version disclosure

You: create a report
Agent: ✓ Report saved to ~/.kramscan/reports/example.com-security-report-2025-...
```

**In-agent commands:** `help` · `status` · `skills` · `clear` · `exit`

**Single message mode:**

```bash
kramscan agent --message "scan https://example.com"
```

---

## 🧠 Supported AI Providers

| Provider     | SDK / Integration        | Default Model                     |
| :----------- | :----------------------- | :-------------------------------- |
| OpenAI       | `openai`                 | `gpt-4`                          |
| Anthropic    | `@anthropic-ai/sdk`      | `claude-3-5-sonnet-20241022`     |
| Google Gemini| `@google/generative-ai`  | `gemini-2.0-flash-exp`           |
| Mistral      | `@mistralai/mistralai`   | `mistral-large-latest`           |
| OpenRouter   | OpenAI-compatible        | `anthropic/claude-3.5-sonnet`    |
| Kimi         | OpenAI-compatible        | `moonshot-v1-8k`                 |

> Switch providers any time with `kramscan onboard` or by editing `~/.kramscan/config.json`.

---

## 🔧 Environment Variables

You can configure API keys via environment variables:

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `MISTRAL_API_KEY` | Mistral API key |
| `OPENROUTER_API_KEY` | OpenRouter API key |
| `KIMI_API_KEY` | Kimi API key |
| `KRAMSCAN_DEBUG` | Enable debug mode |

---

## ⚙️ Configuration

Run the setup wizard to configure your environment:

```bash
kramscan onboard
```

| Setting              | Description                            | Default      |
| :------------------- | :------------------------------------- | :----------- |
| AI Provider          | Choose from 6 supported providers      | `openai`     |
| API Key              | Your provider API key                  | —            |
| Default Model        | Model used for analysis                | `gpt-4`      |
| Report Format        | Output format for reports              | `word`       |
| Strict Scope         | Limit scanning to target domain only   | `true`       |
| Rate Limit           | Max requests per second                | `5`          |

Configuration is persisted to `~/.kramscan/config.json`.

---

## 🧪 Tech Stack

| Technology       | Purpose                                     |
| :--------------- | :------------------------------------------ |
| TypeScript       | Type-safe codebase                          |
| Node.js ≥ 18     | Runtime environment                         |
| Commander.js     | CLI framework & argument parsing            |
| Puppeteer        | Headless Chrome for browser automation      |
| Inquirer.js      | Interactive terminal prompts                |
| Docx             | Word document report generation             |
| Multi-provider AI| OpenAI, Anthropic, Gemini, Mistral & more   |

---

## 💻 Development

```bash
# Clone the repository
git clone https://github.com/shaikhakramshakil/kramscan.git
cd kramscan

# Install dependencies
npm install

# Build the project
npm run build

# Link for local testing
npm link

# Run locally
kramscan
```

---

## 🗺️ Roadmap

- [x] Core vulnerability scanner (XSS, SQLi, CSRF, headers)
- [x] AI-powered analysis with multiple providers
- [x] Interactive AI agent mode
- [x] Professional report generation (DOCX, TXT, JSON)
- [x] Configuration management & setup wizard
- [ ] Plugin system for custom scan modules
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] PDF report generation
- [ ] Dashboard web UI

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create your branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 👤 Author

**Akram Shaikh**

[![Website](https://img.shields.io/badge/Website-akramshaikh.me-blue?style=flat-square&logo=google-chrome&logoColor=white)](https://akramshaikh.me)
[![GitHub](https://img.shields.io/badge/GitHub-shaikhakramshakil-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/shaikhakramshakil)

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run linting
npm run lint

# Format code
npm run format
```

---

<p align="center">
  Made with ❤️ by <a href="https://akramshaikh.me">Akram Shaikh</a>
</p>
