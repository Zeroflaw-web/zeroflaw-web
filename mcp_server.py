#!/usr/bin/env python3
"""
ZeroFlaw MCP Server — HTTP/SSE-based MCP server for Claude Desktop.

Run:
    python mcp_server.py

Claude Desktop config (claude_desktop_config.json):
{
  "mcpServers": {
    "zeroflaw": {
      "url": "http://localhost:8556/sse"
    }
  }
}

Or via stdio (simpler):
{
  "mcpServers": {
    "zeroflaw": {
      "command": "python",
      "args": ["C:/gemini/zeroflaw-web/mcp_server.py", "--stdio"]
    }
  }
}
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Add parent to path for imports
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# ── MCP Server Setup ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ZeroFlaw MCP Server")
    parser.add_argument("--stdio", action="store_true", help="Use stdio transport (for Claude Desktop)")
    parser.add_argument("--port", type=int, default=8556, help="Port for HTTP/SSE transport")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"), help="Host to bind to")
    args = parser.parse_args()

    if args.stdio:
        run_stdio()
    else:
        run_http(args.host, args.port)


def run_stdio():
    """Run MCP server over stdio for Claude Desktop."""
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("ZeroFlaw Security Scanner")

    register_tools(mcp)
    mcp.run(transport="stdio")


def run_http(host: str, port: int):
    """Run MCP server over HTTP/SSE for Claude Desktop (streamable HTTP)."""
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("ZeroFlaw Security Scanner")

    register_tools(mcp)
    print(f"ZeroFlaw MCP Server running at http://{host}:{port}/sse", flush=True)
    import uvicorn
    from starlette.middleware.cors import CORSMiddleware as _CORSMiddleware
    app = mcp.sse_app()
    app.add_middleware(_CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    # Allow any host header (needed behind Render's proxy)
    import starlette.middleware.trustedhost as _th
    app.add_middleware(_th.TrustedHostMiddleware, allowed_hosts=["*"])
    uvicorn.run(app, host=host, port=port, forwarded_allow_ips="*")


# ── Tool Registration ─────────────────────────────────────────────────

SCANNERS_CACHE = {}


def register_tools(mcp):
    from mcp.server.fastmcp import FastMCP

    @mcp.tool()
    def scan_health() -> str:
        """Check which security scanners are available on this server."""
        scanners = {
            "bandit": bool(shutil.which("bandit")),
            "ruff": bool(shutil.which("ruff")),
            "semgrep": bool(shutil.which("semgrep")),
            "trivy": bool(shutil.which("trivy")),
            "npm": bool(shutil.which("npm")),
            "pip": bool(shutil.which("pip")),
        }
        available = [k for k, v in scanners.items() if v]
        missing = [k for k, v in scanners.items() if not v]
        return f"Scanners available: {', '.join(available)}\nMissing: {', '.join(missing) if missing else 'none'}"

    @mcp.tool()
    def scan_url(repo_url: str, api_key: str = "") -> str:
        """Clone a GitHub/GitLab/Bitbucket URL and run all security scans.

        Args:
            repo_url: Full HTTPS URL to the repository (e.g. https://github.com/user/repo)
            api_key: Optional OpenAI-compatible API key for AI-powered report summary

        Returns:
            A markdown summary of scan results with findings organized by severity.
        """
        import urllib.parse

        repo_name = os.path.basename(urllib.parse.urlparse(repo_url).path) or "repo"
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        tmpdir = tempfile.mkdtemp()
        clone_to = os.path.join(tmpdir, "repo")

        try:
            git_path = shutil.which("git") or "git"
            result = subprocess.run(
                [git_path, "clone", "--depth", "1", "--", repo_url, clone_to],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                err = result.stderr[:300]
                if "could not read Username" in err or "Authentication failed" in err:
                    return f"❌ Clone failed — private repo needs a token. Use https://<token>@github.com/user/repo or try scan_directory with a local path."
                return f"❌ Clone failed: {err}"

            results = run_scans(clone_to, quick=True)
            summary = format_results_markdown(repo_name, results)
            return summary
        except subprocess.TimeoutExpired:
            return "❌ Clone timed out after 5 minutes. Try a smaller repo or use scan_directory with a local path."
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @mcp.tool()
    def scan_url_full(repo_url: str) -> str:
        """Clone a GitHub URL and run ALL security scans (including slow Semgrep + Trivy)."""
        import urllib.parse
        repo_name = os.path.basename(urllib.parse.urlparse(repo_url).path) or "repo"
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        tmpdir = tempfile.mkdtemp()
        clone_to = os.path.join(tmpdir, "repo")
        try:
            git_path = shutil.which("git") or "git"
            result = subprocess.run(
                [git_path, "clone", "--depth", "1", "--", repo_url, clone_to],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                return f"❌ Clone failed: {result.stderr[:300]}"
            results = run_scans(clone_to, quick=False)
            summary = format_results_markdown(repo_name, results)
            return summary
        except subprocess.TimeoutExpired:
            return "❌ Clone timed out"
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @mcp.tool()
    def scan_directory(path: str) -> str:
        """Run security scans on a local directory (quick mode, skips Semgrep + Trivy)."""
        if not os.path.isdir(path):
            return f"❌ Path does not exist or is not a directory: {path}"

        results = run_scans(path, quick=True)
        summary = format_results_markdown(os.path.basename(path), results)
        return summary

    @mcp.tool()
    def scan_zip(base64_zip: str, project_name: str = "upload") -> str:
        """Scan a base64-encoded zip file for security issues.
        Note: For large zips, prefer scan_url or scan_directory.

        Args:
            base64_zip: Base64-encoded zip file content
            project_name: Optional name for the project (for display)

        Returns:
            A markdown summary of scan results.
        """
        import base64

        tmpdir = tempfile.mkdtemp()
        try:
            zip_path = os.path.join(tmpdir, "project.zip")
            with open(zip_path, "wb") as f:
                f.write(base64.b64decode(base64_zip))

            extract_to = os.path.join(tmpdir, "project")
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_to)

            results = run_scans(extract_to)
            summary = format_results_markdown(project_name, results)
            return summary
        except Exception as e:
            return f"❌ Failed to process zip: {str(e)}"
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @mcp.tool()
    def fix_directory(path: str) -> str:
        """Run security scan and auto-fix issues in a local directory.

        Args:
            path: Local directory path to scan and fix

        Returns:
            A markdown summary of changes made (fixes applied).
        """
        import auto_fix

        if not os.path.isdir(path):
            return f"❌ Path does not exist or not a directory: {path}"

        results = run_scans(path, quick=True)
        changes = auto_fix.apply_fixes(path, {"scans": results})

        if not changes:
            return "✓ No issues to fix."

        lines = [f"## Applied {len(changes)} fix(es)\n"]
        for c in changes:
            lines.append(f"- **{c['file']}:{c['line']}** — {c['issue']}")
            lines.append(f"  - Fix: {c['fix']}")
        return "\n".join(lines)

    @mcp.tool()
    def fix_url(repo_url: str) -> str:
        """Clone a GitHub URL, scan, and auto-fix all issues.

        Args:
            repo_url: Full HTTPS URL to the repository

        Returns:
            A markdown summary of fixes applied.
        """
        import urllib.parse
        import auto_fix

        repo_name = os.path.basename(urllib.parse.urlparse(repo_url).path) or "repo"
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        tmpdir = tempfile.mkdtemp()
        clone_to = os.path.join(tmpdir, "repo")

        try:
            git_path = shutil.which("git") or "git"
            result = subprocess.run(
                [git_path, "clone", "--depth", "1", "--", repo_url, clone_to],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                return f"❌ Clone failed: {result.stderr[:300]}"

            results = run_scans(clone_to, quick=True)
            changes = auto_fix.apply_fixes(clone_to, {"scans": results})

            if not changes:
                return f"✓ No issues to fix in {repo_name}."

            lines = [f"## Applied {len(changes)} fix(es) to {repo_name}\n"]
            for c in changes:
                lines.append(f"- **{c['file']}:{c['line']}** — {c['issue']}")
                lines.append(f"  - Fix: {c['fix']}")
            return "\n".join(lines)
        except subprocess.TimeoutExpired:
            return "❌ Clone timed out"
        except Exception as e:
            return f"❌ Error: {str(e)}"
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ── Scan Engine ───────────────────────────────────────────────────────

def run_trivy(path: str) -> dict:
    """Run Trivy on a path."""
    trivy = shutil.which("trivy")
    if not trivy:
        return {"error": "Trivy not installed"}
    try:
        result = subprocess.run(
            [trivy, "fs", "--format", "json", "--quiet", "--", path],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):
            return {"error": f"Trivy failed"}
        data = json.loads(result.stdout) if result.stdout.strip() else {"Results": []}
        return data
    except subprocess.TimeoutExpired:
        return {"error": "Trivy timed out"}
    except Exception as e:
        return {"error": str(e)}


def run_scans(project_path: str, quick: bool = False) -> dict:
    """Run all scans on a project directory. Use quick=True to skip slow scanners."""
    from server import (
        run_security_scan,
        run_code_linting,
        run_universal_security_scan,
        scan_npm_dependencies,
        scan_python_dependencies,
    )

    results = {"scans": {}, "summary": {"total": 0}}

    # Detect project languages — skip Python scanners if no .py files
    _has_py = False
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in (".venv", "venv", "node_modules", ".git", "__pycache__")]
        for f in files:
            if f.endswith(".py"):
                _has_py = True
                break
        if _has_py:
            break

    from concurrent.futures import ThreadPoolExecutor, wait as _wait
    from concurrent.futures import TimeoutError as _TimeoutError
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {}
        # Only run Python scanners if Python files exist
        if _has_py:
            futures[pool.submit(run_security_scan, project_path)] = "bandit"
            futures[pool.submit(run_code_linting, project_path)] = "ruff"
        if not quick:
            futures[pool.submit(run_universal_security_scan, project_path)] = "semgrep"
            futures[pool.submit(run_trivy, project_path)] = "trivy"
        if not quick and os.path.isfile(os.path.join(project_path, "package.json")):
            futures[pool.submit(scan_npm_dependencies, project_path)] = "npm_audit"
        if not quick and os.path.isfile(os.path.join(project_path, "requirements.txt")):
            futures[pool.submit(scan_python_dependencies, project_path)] = "pip_audit"

        # Wait — 15s for quick, 60s for full
        timeout = 15 if quick else 60
        done, not_done = _wait(futures, timeout=timeout)
        # Mark timed-out scans as errors
        for future in not_done:
            key = futures[future]
            future.cancel()
            results["scans"][key] = {"error": "timed out after 60s"}

        for future in done:
            key = futures[future]
            try:
                results["scans"][key] = future.result()
            except Exception as e:
                results["scans"][key] = {"error": str(e)}

    # Secrets detection (fast, no subprocess)
    secret_findings = scan_secrets(project_path)
    results["scans"]["secrets"] = {"results": secret_findings}

    # Tally
    total = 0
    for scan_name, scan_data in results["scans"].items():
        if isinstance(scan_data, dict) and "results" in str(type(scan_data)):
            total += len(scan_data.get("results", []))
    results["summary"]["total"] = total

    return results


def scan_secrets(project_path: str) -> list:
    """Scan for exposed secrets in project files."""
    import re
    findings = []
    patterns = [
        (r'(?i)(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*["\']?(sk-[a-zA-Z0-9]{10,}|ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}|xox[bpras]-[a-zA-Z0-9]{10,}|AKIA[0-9A-Z]{16})["\']?',
         "Hardcoded API Key / Secret Token"),
        (r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key Exposed"),
        (r'(?i)password\s*[:=]\s*["\'][^"\']{3,}["\']', "Hardcoded Password"),
        (r'(?i)mongo(db)?[+srv]*://[^:]+:[^@]+@', "MongoDB Connection String with Password"),
        (r'https://[^:]+:[^@]+@github\.com', "GitHub URL with Token"),
    ]

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in (".venv", "venv", "node_modules", ".git", "__pycache__")]
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > 100 * 1024:
                    continue
                content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                for pattern, label in patterns:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count("\n") + 1
                        findings.append({
                            "file": os.path.relpath(fpath, project_path),
                            "line": line_num,
                            "severity": "HIGH",
                            "message": label,
                        })
            except Exception:
                pass
    return findings


def format_results_markdown(target_name: str, results: dict) -> str:
    """Format scan results as a concise markdown summary."""
    scans = results.get("scans", {})
    lines = [f"# 🔍 ZeroFlaw Security Scan: {target_name}", ""]

    total = 0
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for scan_name, data in scans.items():
        if not isinstance(data, dict):
            continue
        if "error" in data:
            lines.append(f"## {scan_name}")
            lines.append(f"⚠️ {data['error']}")
            lines.append("")
            continue

        findings = data.get("results", [])
        if not findings:
            continue

        lines.append(f"## {scan_name} ({len(findings)} findings)")
        for f in findings[:15]:  # Limit to 15 per scanner
            sev = (f.get("issue_severity") or f.get("severity", "LOW")).upper()
            if sev in sev_counts:
                sev_counts[sev] += 1
            filepath = f.get("filename", f.get("file", "?"))
            line = f.get("line_number", f.get("line", ""))
            msg = f.get("issue_text", f.get("message", ""))
            icon = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
            lines.append(f"- {icon} **[{sev}]** `{filepath}:{line}` — {msg[:120]}")
        if len(findings) > 15:
            lines.append(f"  *...and {len(findings) - 15} more*")
        lines.append("")

    total = sum(sev_counts.values())
    lines.append("---")
    lines.append(f"**Summary:** 💀 {sev_counts['CRITICAL']} critical · 🔴 {sev_counts['HIGH']} high · 🟡 {sev_counts['MEDIUM']} medium · 🔵 {sev_counts['LOW']} low")
    lines.append(f"**Total findings:** {total}")

    # Secrets
    secrets_data = scans.get("secrets", {})
    secret_findings = secrets_data.get("results", [])
    if secret_findings:
        lines.append("")
        lines.append(f"## 🔑 Secrets Detected ({len(secret_findings)})")
        for s in secret_findings[:10]:
            lines.append(f"- 🔴 `{s['file']}:{s['line']}` — {s['message']}")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
