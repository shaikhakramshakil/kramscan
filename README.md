# KramScan 🛡️
<img width="508" height="126" alt="image" src="https://github.com/user-attachments/assets/6439c670-8d73-4bdd-b8fa-c74de949a31e" />

KramScan is a powerful, AI-powered command-line interface (CLI) for web application security testing. It combines automated browser interactions (via Puppeteer) with AI analysis to identify vulnerabilities in modern web apps.

---

## 🚀 Quick Start

### Installation
Install KramScan globally via npm:

```bash
npm install -g kramscan
```

### Usage
Once installed, you can start using it immediately:

```bash
# Launch the interactive dashboard
kramscan

# Or run a scan directly
kramscan scan https://example.com
```

### Run with npx
You can also run it without installation:
```bash
npx kramscan scan https://example.com
```

---

## 🛠️ Commands

| Command            | Description                          | Status       |
|:-------------------|:-------------------------------------|:-------------|
| `kramscan`         | Launch interactive dashboard         | ✅ Active    |
| `kramscan agent`   | AI-powered interactive assistant     | ✅ Active    |
| `kramscan onboard` | First-time setup wizard              | ✅ Active    |
| `kramscan scan`    | Scan a target URL for vulnerabilities| ✅ Active    |
| `kramscan analyze` | AI-powered analysis of scan results  | ✅ Active    |
| `kramscan report`  | Generate a professional report       | ✅ Active    |
| `kramscan doctor`  | Check environment health             | ✅ Active    |
| `kramscan --help`  | Show all available commands          | ✅ Active    |

---

## 🤖 AI Agent (Interactive Mode)

The KramScan Agent is an AI-powered security assistant that can understand natural language commands and execute security testing tasks through conversation.

### Start the Agent

```bash
kramscan agent
```

### Agent Capabilities

The agent can perform the following security tasks:

- **🔍 Web Scan** - Scan websites for vulnerabilities (XSS, SQLi, CSRF, headers)
- **🧠 Analyze Findings** - AI-powered analysis of scan results
- **📄 Generate Reports** - Create professional DOCX, TXT, or JSON reports
- **🩺 Health Check** - Verify system configuration and dependencies

### Example Conversations

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
      
      Would you like me to analyze these findings? [Y/n]: Y

You: create a report
Agent: I'll generate a Word document report based on the previous scan results.
      
      ✓ Report saved to ~/.kramscan/reports/example.com-security-report-2025-...
```

### Agent Commands

While in the agent, you can use these commands:

- `help` - Show available commands
- `status` - Show session status
- `skills` - List available security skills
- `clear` or `/new` - Clear conversation history
- `exit` or `quit` - Exit the agent

### Single Message Mode

Send a one-off message without entering interactive mode:

```bash
kramscan agent --message "scan https://example.com"
```

---

## ⚙️ Setup Wizard

Run `kramscan onboard` to configure your environment:

1. **AI Provider** — OpenAI or Anthropic
2. **API Key** — Your provider API key
3. **Default Model** — e.g. `gpt-4` or `claude-3-opus`
4. **Report Format** — Word, TXT, or JSON
5. **Scope Enforcement** — Strict mode on/off
6. **Rate Limiting** — Requests per second

Configuration is securely saved to `~/.kramscan/config.json`.

---

## 💻 Development

If you want to contribute or build from source:

```bash
# Clone the repository
git clone https://github.com/shaikhakramshakil/kramscan.git
cd kramscan

# Install dependencies
npm install

# Build
npm run build

# Link for local testing
npm link
```

---

## 🧪 Tech Stack

- **TypeScript** + **Node.js**
- **Commander.js** — CLI framework
- **Inquirer.js** — Interactive prompts
- **Puppeteer** — Browser automation (Headless Chrome)
- **AI-Powered** — Integration with OpenAI & Anthropic for vulnerability analysis

---

## 👤 Author

**Akram Shaikh**
- Website: [akramshaikh.me](https://akramshaikh.me)
- GitHub: [@shaikhakramshakil](https://github.com/shaikhakramshakil)

---

## 📄 License

MIT
