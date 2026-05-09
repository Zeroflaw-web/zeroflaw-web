# AGENTS.md

High-signal guidance for OpenCode sessions. See `CLAUDE.md` for full project details.

## Dev Commands
- `uvicorn app:app --host 0.0.0.0 --port 8555 --reload` (dev server)
- `python zeroflaw.py scan <path> [--quick | --bandit]` (CLI scan)
- `python -m ruff check app.py server.py zeroflaw.py mcp_server.py` (lint, ruff runs as module)
- No formal test suite: use web UI or `GET /health`

## Key Facts
- Core scanning: `server.py` (always use `_validate_path_safety()` + `_sanitize_tool_output()`)
- Streaming SSE format: `yield f"data: {json.dumps(chunk)}\n\n"` (app.py)
- MCP tools: `mcp_server.py` (stdio/HTTP for Claude Desktop)
- GitHub clone restricted to `github.com`/`gitlab.com`/`bitbucket.org`; private repos need token in URL
- OWASP Dependency-Check may fail without NVD DB; Docker bundles DB
- Large repos (>10k files) aborted (`MAX_FILES` in server.py)
