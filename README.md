---
title: ZeroFlaw Web
emoji: 🛡️
colorFrom: blue
colorTo: cyan
sdk: docker
pinned: false
---

# ZeroFlaw Web 🔍

Multi-language security scanner web app with AI-powered reports. Upload a ZIP or paste a GitHub URL — get a comprehensive security analysis with Bandit, Ruff, Semgrep, Trivy, and secrets detection.

![Terminal Demo](https://img.shields.io/badge/status-active-brightgreen)

## Features

| Feature | Description |
|---------|-------------|
| 📤 **Upload ZIP** | Drag-and-drop your project as a zip |
| 🔗 **GitHub URL** | Paste any public repo URL — auto-clones and scans |
| 🔬 **6+ Scanners** | Bandit, Ruff, Semgrep, Trivy, npm audit, pip audit |
| 🔑 **Secrets Detection** | Finds exposed API keys, tokens, passwords in your code |
| 🤖 **AI Reports** | Paste any OpenAI-compatible API key for AI-powered analysis |
| 🧠 **Auto-detect** | Works with OpenAI, DeepSeek, Claude, Groq, OpenRouter |
| 🌐 **Animated Terminal** | Real-time scan progress with typewriter-style output |
| 📊 **Beautiful Reports** | Dark-themed HTML reports with severity cards |
| ⬇ **Download Reports** | Save AI-enhanced reports as standalone HTML files |
| 🔧 **Auto-Fix** | Apply auto-fixable security issues and download the patched source |
| 🐳 **Docker Ready** | Single `docker run` to get started |

## Quick Start

```bash
# Clone
git clone https://github.com/lokesh-kashyap3440/zeroflaw-web.git
cd zeroflaw-web

# Build & run with Docker
docker build -t zeroflaw-web .
docker run -d --name zeroflaw-web -p 8555:8555 zeroflaw-web
```

Open **http://localhost:8555** in your browser.

## CLI Usage

### Option 1: Direct (no install)
```bash
# Windows
zeroflaw.bat scan <path>

# Linux/macOS
./zeroflaw.sh scan <path>
```

### Option 2: Install (recommended for frequent use)
```bash
pip install -e .
zeroflaw scan <path>
```
After install, the `zeroflaw` command works from anywhere.

### CLI Commands
```bash
zeroflaw scan <path>              # Run all security scans
zeroflaw scan <path> --quick      # Skip Semgrep and OWASP (faster)
zeroflaw scan <path> --bandit     # Bandit only
zeroflaw scan <path> --ruff       # Ruff only
zeroflaw scan <path> --semgrep    # Semgrep only
zeroflaw scan <path> --trivy      # Trivy only (dependencies)

# Auto-fix
zeroflaw fix <path> --scan        # Scan and auto-fix issues
zeroflaw fix <path> --results <file>  # Apply fixes from saved results
zeroflaw --help                   # Show help
```

## Usage

### Upload a ZIP
1. Click the upload area and select your project's `.zip` file
2. (Optional) Expand "Add API key" and paste your key for AI analysis
3. Click **Scan Upload**
4. Watch the animated terminal show real-time scan progress

### GitHub URL
1. Paste a public repository URL like `https://github.com/user/repo`
2. (Optional) Add your API key
3. Click **Scan URL**
4. The report loads with findings when complete

### Private Repos
Use a token in the URL:
```
https://<your_token>@github.com/yourname/private-repo
```

## API Key Support

| Provider | Key Prefix | Auto-detect |
|----------|-----------|-------------|
| OpenAI | `sk-...` | ✅ (default) |
| DeepSeek | `sk-...` | Select from dropdown |
| Anthropic Claude | `sk-ant-...` | ✅ |
| Groq | `gsk_...` | ✅ |
| OpenRouter | `sk-or-...` | ✅ |
| Fireworks | `fkey-...` | ✅ |

## Scanners

| Scanner | What it finds | Language |
|---------|--------------|----------|
| **Bandit** | Security vulnerabilities (SQL injection, hardcoded passwords, etc.) | Python |
| **Ruff** | Code quality issues, unused imports, style problems | Python |
| **Semgrep** | Multi-language SAST - OWASP Top 10, injection flaws | All languages |
| **Trivy** | CVE vulnerabilities in dependencies (PyPI, npm, etc.) | All |
| **npm audit** | Known vulnerabilities in npm packages | JavaScript |
| **pip audit** | Known vulnerabilities in PyPI packages | Python |
| **Secrets Scanner** | Exposed API keys, tokens, private keys, passwords | All |

## Deploy to Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://dashboard.render.com/)

1. Fork this repo to your GitHub account
2. Go to https://dashboard.render.com/
3. Click **New → Blueprint**
4. Connect your GitHub account and select `zeroflaw-web`
5. Click **Apply** — Render auto-detects `render.yaml`

Set environment variables:
- `DEEPSEEK_API_KEY` — enables AI report summaries
- `CODEQL_ENABLED` - enables CodeQL scanning
- `ZAP_ENABLED` - enables OWASP ZAP scanning

## Additional Security Tools

The application now includes enhanced security tools:
- CodeQL for advanced static analysis
- OWASP ZAP for dynamic application security testing

## CLI Version

A standalone CLI version is also available:

```bash
zeroflaw scan ./myproject --quick --output results.json --report
```

See the `zeroflaw.py` file for details.

## Tech Stack

- **Backend:** Python + FastAPI + httpx
- **Frontend:** Server-rendered HTML + vanilla JS + CSS animations
- **Scanning:** Bandit, Ruff, Semgrep, Trivy, npm/pip audit
- **Storage:** Backblaze B2 (S3-compatible, scan results persist across Render cold starts)
- **Container:** Docker (Python 3.11-slim)
- **AI:** OpenAI-compatible API (auto-detects provider from key prefix)

## Deployment

### Render (recommended)

1. Fork or push to GitHub, connect to Render
2. Create a **Backblaze B2** bucket (no credit card required, 10 GB free)
3. Set these env vars in Render dashboard:
   - `B2_APPLICATION_KEY_ID` and `B2_APPLICATION_KEY` — from B2 App Keys
   - `B2_BUCKET` — your bucket name (e.g. `zeroflaw-scans`)
4. Render's cron job pings `/health` every 15 min to prevent sleep

## Security

- Files are scanned in-memory and deleted after processing
- API keys are not stored — used only for the current scan
- No data leaves the server except the LLM API call (if you provide a key)
- Security headers (CSP, X-Frame-Options, etc.) on all responses
- Upload size limited to 50 MB
- URL validation restricts cloning to GitHub/GitLab/Bitbucket
