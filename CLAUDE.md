# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZeroFlaw Web is a multi-language security scanner web application. Upload a ZIP or paste a GitHub URL to get comprehensive security analysis with Bandit, Ruff, Semgrep, Trivy, npm/pip audit, and secrets detection. AI-powered reports are available with any OpenAI-compatible API key.

## Tech Stack

- **Backend:** Python 3.11 + FastAPI + httpx + Jinja2 templates
- **Frontend:** Single-page app with vanilla JS, CSS animations, Server-Sent Events for streaming terminal output
- **Scanning:** Bandit, Ruff, Semgrep, Trivy, npm audit, pip audit
- **AI:** OpenAI-compatible API (auto-detects provider from key prefix)
- **Storage:** Backblaze B2 (S3-compatible) — scan metadata and reports persist across Render cold starts
- **Deployment:** Docker, Render, supports Vercel via MCP server
- **MCP:** Model Context Protocol server for Claude Desktop integration

## Common Commands

### Development

```bash
# Install dependencies (from project root)
pip install -r requirements.txt

# Also install security scanning tools (bandit, ruff, semgrep, pip-audit, trivy)
pip install bandit ruff semgrep pip-audit
# Or install via apt/curl as shown in Dockerfile

# Run the web app (development)
uvicorn app:app --host 0.0.0.0 --port 8555 --reload

# Run the CLI scanner directly
python zeroflaw.py scan ./myproject
python zeroflaw.py scan ./myproject --quick    # Skip Semgrep and OWASP
python zeroflaw.py scan ./myproject --bandit   # Only Bandit

# Run the MCP server (for Claude Desktop integration)
python mcp_server.py --stdio                     # stdio transport
python mcp_server.py --port 8556 --host 0.0.0.0 # HTTP/SSE transport
```

### Production / Docker

```bash
docker build -t zeroflaw-web .
docker run -d --name zeroflaw-web -p 8555:8555 zeroflaw-web
```

### Testing & Validation

The codebase does not have a formal test suite. Instead:
- Manual test by uploading sample projects via the web UI
- Check that scanners execute and return results
- Verify AI report generation with test API keys
- Health endpoint: `GET /health` returns `{"status":"ok"}`

To test a single scanner manually:
```bash
python -c "from server import run_security_scan; print(run_security_scan('./test_project'))"
```

## Architecture

### Core Files

| File | Purpose |
|------|---------|
| `app.py` | FastAPI application: routes, middleware, upload handling, GitHub cloning, AI report generation, streaming responses |
| `server.py` | Core scanning logic: wrappers around Bandit, Ruff, Semgrep, Trivy, npm/pip audit, OWASP; path validation and sanitization utilities |
| `zeroflaw.py` | CLI interface that imports and calls server.py functions; colored terminal output |
| `mcp_server.py` | MCP server exposing scanning tools to Claude Desktop via stdio or HTTP/SSE |
| `templates/index.html` | Single-page frontend with HTML/CSS/JS; animated terminal output via EventSource |
| `Dockerfile` | Multi-stage build: installs system deps (git, nodejs, trivy) + Python tools + app code |

### Request Flow (Web App)

1. **Upload/ZIP**: User uploads file → `app.py` extracts to `./uploads/{uuid}` → calls scanner functions from `server.py` → streams output via `StreamingResponse` with Server-Sent Events → frontend displays in animated terminal.

2. **GitHub URL**: User submits URL → `app.py` validates URL (only github.com, gitlab.com, bitbucket.org) → clones via `git clone` into `./repos/{uuid}` → scans → stream response.

3. **AI Report**: User submits API key → `app.py` calls OpenAI-compatible API with scan results → streams AI-generated markdown → converted to HTML report → downloadable.

### Scanning Architecture (server.py)

- **Main entry**: `run_all_scans(target_path)` orchestrates all applicable scanners.
- **Individual scanners**:
  - `run_security_scan()`: Bandit (Python security vulnerabilities)
  - `run_code_linting()`: Ruff (Python linting, style, unused imports)
  - `run_universal_security_scan()`: Semgrep with OWASP rules (multi-language)
  - `scan_npm_dependencies()`: npm audit (JavaScript dependencies)
  - `scan_python_dependencies()`: pip-audit (Python dependencies)
  - `run_owasp_dependency_check()`: OWASP Dependency-Check (multi-language CVEs)
- **Safety utilities**:
  - `_validate_path_safety()`: blocks shell metacharacters, path traversal, sensitive system paths
  - `_should_skip_path()`: respects `.scannerignore`, auto-excludes (node_modules, .git, __pycache__, etc.)
  - `_sanitize_tool_output()`: strips absolute paths, truncates at 50MB
  - Timeouts: 120s for Bandit/Ruff/Semgrep, 300s for OWASP

### MCP Server (mcp_server.py)

Registers the same scanning tools as MCP tools (`@mcp.tool()` decorator). Claude Desktop can call them via:
- stdio transport: `python mcp_server.py --stdio`
- HTTP/SSE: `python mcp_server.py --port 8556`

Provides two main tools: `run_all_scans` and individual scanner tools.

## Important Patterns

### Path Validation

Always validate paths before scanning. The `_validate_path_safety()` function in `server.py` checks for:
- Shell metacharacters (`;&|` etc.) → command injection prevention
- Path traversal (`../`) → directory escape prevention
- Sensitive system paths (C:\Windows, /etc, /sys, etc.)

Never pass raw user input to subprocess calls without validation.

### Output Sanitization

All scanner output is passed through `_sanitize_tool_output()`:
- Strips absolute user paths (replaces with `~/...`)
- Truncates at 50MB to prevent memory issues
- Use this for any external tool output that may contain sensitive info

### Streaming Responses

The web app uses `StreamingResponse` with `text/event-stream` to send incremental output:
```python
yield f"data: {json.dumps(chunk)}\n\n"
```
Frontend uses `EventSource` or `fetch()` with reader to display real-time terminal.

### Auto-excluded Paths

Do not scan:
- Virtual environments: `.venv`, `venv`, `env`
- Build outputs: `dist`, `build`, `target`, `.next`, `.nuxt`
- Package managers: `node_modules`
- VCS: `.git`
- Caches: `__pycache__`, `.ruff_cache`, `.bandit_cache`, `.mypy_cache`, `.pytest_cache`
- Binary/media files: `*.pyc`, `*.exe`, `*.png`, `*.pdf` (see `AUTO_EXCLUDE_FILES`)

Custom exclusions via `.scannerignore` file in project root (similar to `.gitignore`).

## How to Add a New Scanner

1. Add the scanning function in `server.py` following existing patterns.
2. Use `_validate_path_safety()` and `_sanitize_tool_output()`.
3. Set appropriate timeout (default 120s) and respect `MAX_FILES` limit.
4. Add to `run_all_scans()` if it should run automatically.
5. Optionally expose as MCP tool in `mcp_server.py` with `@mcp.tool()`.
6. Update frontend if needed (usually not, as `run_all_scans` aggregates).
7. Add to README scanner table if it's a major scanner.

## Environment Variables

- `PORT`: Server port (default 8555 for web, 8556 for MCP HTTP)
- `DEEPSEEK_API_KEY`: Optional default AI provider key for hosted deployments (Render)
- No other env vars required for local development

## Deployment Notes

- **Render**: Uses `render.yaml` blueprint; health check at `/health`; cron job pings every 15 min to prevent sleep
- **Backblaze B2 Storage**: Set `B2_APPLICATION_KEY_ID`, `B2_APPLICATION_KEY`, and `B2_BUCKET` env vars in Render dashboard (no credit card required; 10 GB free forever)
  1. Sign up at backblaze.com (no credit card)
  2. Create a bucket named `zeroflaw-scans` (or your preferred name)
  3. Create an application key with read/write access
  4. Copy key ID and key into Render env vars
- **Docker**: Installs all security tools in image; runs uvicorn on port 8555

## Security Considerations

- All file uploads are scanned in-memory and deleted after processing
- API keys are never stored; used only per-request and discarded
- URL cloning restricted to known git hosts; size limited to 500MB
- Security headers: CSP, X-Frame-Options, X-XSS-Protection, Referrer-Policy
- Path validation prevents directory traversal and command injection
- Absolute paths in logs are sanitized to protect user privacy

## Known Limitations

- Scanning large repositories (>10,000 files) is aborted (see `MAX_FILES`)
- OWASP Dependency-Check may fail if NVD database download is blocked; consider bundling the DB in Docker for offline use
- GitHub cloning does not support private repos without token in URL
- Windows path handling tested but Linux/macOS primary target (Docker runs Linux)

## Troubleshooting

**Scanners not found**: Ensure bandit, ruff, semgrep, trivy, npm, pip-audit are in PATH. Docker image includes them.
**Slow scans**: Use `--quick` flag to skip Semgrep and OWASP (~15s vs 60s+).
**Out of memory**: Large outputs are truncated; check logs for `[truncated]` messages.
**Git clone fails**: Verify URL matches `github.com|gitlab.com|bitbucket.org` pattern; private repos need token in URL.
**MCP connection refused**: Ensure mcp_server.py is running on the expected port/transport.
