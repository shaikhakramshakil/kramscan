# KramScan 🛡️

KramScan is a personal, AI-powered command-line interface (CLI) for web application security testing. It combines automated browser interactions (via Puppeteer) with AI analysis to identify vulnerabilities in modern web apps.

---

## Quick Start

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Link globally so you can use "kramscan" from anywhere
npm link

# Launch the interactive dashboard
kramscan
```

---

## Commands

| Command            | Description                          | Status       |
|:-------------------|:-------------------------------------|:-------------|
| `kramscan`         | Launch interactive dashboard         | ✅ Active    |
| `kramscan onboard` | First-time setup wizard              | ✅ Active    |
| `kramscan scan`    | Scan a target URL                    | 🔜 Coming   |
| `kramscan analyze` | AI-powered analysis of scan results  | 🔜 Coming   |
| `kramscan report`  | Generate a professional report       | 🔜 Coming   |
| `kramscan doctor`  | Check environment health             | 🔜 Coming   |
| `kramscan --help`  | Show all available commands          | ✅ Active    |

---

## Setup Wizard

Run `kramscan onboard` to configure:

1. **AI Provider** — OpenAI or Anthropic
2. **API Key** — Your provider API key
3. **Default Model** — e.g. `gpt-4`
4. **Report Format** — Word, TXT, or JSON
5. **Scope Enforcement** — Strict mode on/off
6. **Rate Limiting** — Requests per second

Configuration is saved to `~/.kramscan/config.json`.

---

## Development

```bash
# Run without building (using tsx)
npx tsx src/index.ts

# Run a specific command
npx tsx src/index.ts onboard

# Build
npm run build
```

---

## Tech Stack

- **TypeScript** + **Node.js**
- **Commander.js** — CLI framework
- **Inquirer.js** — Interactive prompts
- **Puppeteer** — Browser automation
- **ConfigStore** — Persistent configuration

---

## Author

**Akram** — *KramScan*

---

## License

ISC
