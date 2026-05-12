#!/usr/bin/env python3
"""
ZeroFlaw Web — Deployable security scanner web app.

Usage:
    uvicorn app:app --host 0.0.0.0 --port 8000
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

import asyncio
import httpx
from weasyprint import HTML as WeasyHTML
from fastapi import FastAPI, File, Form, UploadFile, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

# ── Security middleware ───────────────────────────────────────────────

import auto_fix

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response


# ── Config ─────────────────────────────────────────────────────────────

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_CLONE_SIZE = 500 * 1024 * 1024  # 500 MB repo clone limit

def validate_repo_url(url: str) -> bool:
    """Validate that a repo URL is safe to clone."""
    import re
    # Only allow common git hosting URLs
    pattern = r'^https://([a-zA-Z0-9_-]+@)?(github\.com|gitlab\.com|bitbucket\.org|gist\.github\.com)/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(/.*)?$'
    return bool(re.match(pattern, url))

def mask_api_key(key: str) -> str:
    """Mask an API key for safe logging."""
    if len(key) < 8:
        return "***"
    return key[:4] + "****" + key[-4:]


def error_page(title: str, body: str = "", status_code: int = 400) -> HTMLResponse:
    """Return a dark-themed error page."""
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title} — ZeroFlaw</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #020617; color: #e2e8f0; line-height: 1.6; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; }}
  .card {{ background: #0F172A; border: 1px solid rgba(255,255,255,0.05); border-radius: 16px; padding: 32px; max-width: 520px; width: 100%; text-align: center; }}
  h2 {{ color: #ff7b72; font-size: 20px; margin-bottom: 12px; }}
  p {{ color: #94a3b8; font-size: 14px; margin-bottom: 16px; }}
  a {{ display: inline-block; padding: 10px 24px; background: #22d4ee; color: #020617; border-radius: 10px; text-decoration: none; font-size: 14px; font-weight: 600; }}
  a:hover {{ background: #1bb3cc; }}
</style></head><body><div class="card"><h2>{title}</h2>{body}</div></body></html>"""
    return HTMLResponse(content=html, status_code=status_code)


# ── Paths ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
UPLOAD_DIR = BASE_DIR / "uploads"
SCANNER_DIR = BASE_DIR

TEMP_SCANS_DIR = BASE_DIR / "temp_scans"
TEMP_SCANS_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(SCANNER_DIR))

import b2_store  # noqa: E402

from server import (  # noqa: E402
    run_security_scan,
    run_code_linting,
    run_universal_security_scan,
    scan_npm_dependencies,
    scan_python_dependencies,
)

# ── App ────────────────────────────────────────────────────────────────
app = FastAPI(title="ZeroFlaw Web", version="1.0.0")
app.add_middleware(SecurityHeadersMiddleware)

# Limit upload size
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB

@app.middleware("http")
async def limit_upload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_UPLOAD_SIZE:
        return error_page("Upload too large", "<p>Max upload size is 50 MB.</p><a href='/'>← Try Again</a>", 413)
    response = await call_next(request)
    return response

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
UPLOAD_DIR.mkdir(exist_ok=True)

# ── Provider auto-detection ──────────────────────────────────────────

def detect_provider(api_key: str, provider_hint: str = ""):
    """Detect LLM provider from API key prefix. Returns (base_url, model, display_name)."""
    key = api_key.strip()

    # If user explicitly selected a provider, use it
    explicit = {
        "openai":     ("https://api.openai.com/v1",                "gpt-4o",                    "OpenAI"),
        "deepseek":   ("https://api.deepseek.com/v1",              "deepseek-chat",              "DeepSeek"),
        "anthropic":  ("https://api.anthropic.com/v1",             "claude-sonnet-4-20250514",  "Anthropic Claude"),
        "groq":       ("https://api.groq.com/openai/v1",           "llama-3.3-70b-versatile",   "Groq"),
        "openrouter": ("https://openrouter.ai/api/v1",             "openai/gpt-4o",             "OpenRouter"),
        "nvidia":     ("https://integrate.api.nvidia.com/v1",      "meta/llama-3.1-70b-instruct", "NVIDIA"),
    }
    if provider_hint and provider_hint in explicit:
        return explicit[provider_hint]

    # Ordered by most specific prefix first
    providers = [
        ("sk-ant-",    "https://api.anthropic.com/v1",             "claude-sonnet-4-20250514", "Anthropic Claude"),
        ("sk-or-v1-",  "https://openrouter.ai/api/v1",             "openai/gpt-4o",            "OpenRouter"),
        ("sk-or-",     "https://openrouter.ai/api/v1",             "openai/gpt-4o",            "OpenRouter"),
        ("gsk_",       "https://api.groq.com/openai/v1",           "llama-3.3-70b-versatile",  "Groq"),
        ("fkey-",      "https://api.fireworks.ai/inference/v1",    "accounts/fireworks/models/llama-v3p1-70b-instruct", "Fireworks"),
        ("tgpv",       "https://api.together.xyz/v1",              "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "Together AI"),
        ("nvapi-",     "https://integrate.api.nvidia.com/v1",      "meta/llama-3.1-70b-instruct", "NVIDIA"),
        ("sk-",        "https://api.deepseek.com/v1",              "deepseek-chat",               "DeepSeek"),
    ]

    # Note: sk- keys match DeepSeek by default. Select "OpenAI" from the dropdown for OpenAI keys.

    # Check default env var keys
    env_keys = {
        "DEEPSEEK_API_KEY":  ("https://api.deepseek.com/v1",       "deepseek-chat",            "DeepSeek"),
        "ANTHROPIC_API_KEY": ("https://api.anthropic.com/v1",      "claude-sonnet-4-20250514", "Anthropic Claude"),
        "OPENAI_API_KEY":    ("https://api.openai.com/v1",         "gpt-4o",                   "OpenAI"),
        "GROQ_API_KEY":      ("https://api.groq.com/openai/v1",    "llama-3.3-70b-versatile",  "Groq"),
        "OPENROUTER_API_KEY":("https://openrouter.ai/api/v1",      "openai/gpt-4o",            "OpenRouter"),
        "NVIDIA_API_KEY":    ("https://integrate.api.nvidia.com/v1","meta/llama-3.1-70b-instruct", "NVIDIA"),
    }

    # 1. Check if this key matches a known prefix pattern
    for prefix, base, model, display in providers:
        if key.startswith(prefix):
            return base, model, display

    # 2. Check which env var this key matches (for fallback keys)
    for env_var, (base, model, display) in env_keys.items():
        stored = os.environ.get(env_var, "")
        if stored and key == stored:
            return base, model, display

    # 3. Default: assume OpenAI-compatible (sk-...)
    base_url = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
    return base_url, "gpt-4o", "OpenAI"


async def generate_ai_report_summary(api_key: str, target_name: str, results: dict, provider_hint: str = "") -> tuple:
    """Call an LLM API to generate an AI summary section.

    Auto-detects provider from API key. Falls back to env vars.
    Returns (html_summary, provider_name) — provider_name is empty if no key.
    """
    # Determine API key — use provided key, or check env vars in order
    effective_key = api_key or os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY") or ""
    if not effective_key:
        return "", ""

    base_url, model, provider_name = detect_provider(effective_key, provider_hint)
    scans = results.get("scans", {})

    findings_summary = []
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for scan_name, data in scans.items():
        if not isinstance(data, dict) or data.get("error"):
            continue
        for r in data.get("results", []):
            sev = (r.get("issue_severity") or "LOW").upper()
            if sev in sev_counts:
                sev_counts[sev] += 1
            findings_summary.append({
                "severity": sev, "scanner": scan_name,
                "file": r.get("filename", ""),
                "line": r.get("line_number", ""),
                "message": r.get("issue_text", ""),
            })
        for r in data.get("results", []):
            findings_summary.append({
                "severity": "LOW", "scanner": scan_name,
                "file": r.get("filename", ""),
                "line": str(r.get("location", {}).get("row", "")),
                "message": f"[{r.get('code','')}] {r.get('message','')}",
            })

    trivy = scans.get("trivy", {})
    if isinstance(trivy, dict) and "Results" in trivy:
        for r in trivy["Results"]:
            for v in r.get("Vulnerabilities", []):
                sev = v.get("Severity", "UNKNOWN")
                if sev in sev_counts:
                    sev_counts[sev] += 1
                findings_summary.append({
                    "severity": sev, "scanner": "trivy",
                    "file": v.get("PkgName", ""),
                    "line": v.get("InstalledVersion", ""),
                    "message": f"{v.get('VulnerabilityID','')} — {v.get('Title','')[:80]}",
                })

    total = len(findings_summary)
    if total == 0:
        return "", ""

    top_findings = findings_summary[:30]

    prompt_json = json.dumps({
        "target": target_name,
        "severity_counts": sev_counts,
        "total_findings": total,
        "top_findings": top_findings,
        "scanners_run": [k for k, v in scans.items() if isinstance(v, dict) and not v.get("error")],
    }, indent=2)

    system_prompt = (
        "You are a senior security engineer reviewing a code security scan report. "
        "Your task is to produce a concise, actionable AI summary in HTML format. "
        "Use ONLY <p>, <ul>, <li>, <strong>, <code> tags. No markdown, no triple backticks. "
        "Return ONLY the HTML block — no wrapping text, no <html>/<body> tags. "
        "The summary must include:\n"
        "1. An executive overview (1-2 sentences on overall security posture)\n"
        "2. Top 3 most critical issues (if any) with brief impact description\n"
        "3. Recommended next actions (as a short bullet list)\n"
        "4. A one-line overall verdict: PASS, PASS WITH CAVEATS, or REVIEW NEEDED\n\n"
        "Be direct, technical, and avoid generic advice."
    )

    user_prompt = (
        f"Here is the security scan data for project \"{target_name}\":\n\n"
        f"{prompt_json}\n\n"
        "Generate the AI summary HTML block as instructed."
    )

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            is_claude = "anthropic" in base_url

            if is_claude:
                # Anthropic/Claude uses a different API format
                resp = await client.post(
                    f"{base_url.rstrip('/')}/messages",
                    headers={
                        "x-api-key": effective_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "max_tokens": 1500,
                        "system": system_prompt,
                        "messages": [{"role": "user", "content": user_prompt}],
                        "temperature": 0.3,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                content = ""
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        content += block.get("text", "")
                content = content.strip()
            else:
                # OpenAI-compatible format
                resp = await client.post(
                    f"{base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {effective_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.3,
                        "max_tokens": 1500,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"].strip()

            content = content.replace("<html>", "").replace("</html>", "").replace("<body>", "").replace("</body>", "")
            return content, provider_name
    except Exception as e:
        return f'<p class="ai-error">⚠️ AI summary ({provider_name}) unavailable: {e}</p>', provider_name


def generate_html_report(target_name: str, results: dict, ai_summary: str = "", provider_name: str = "") -> str:
    """Generate a self-contained HTML report matching zeroflaw-full-production design."""
    scans = results.get("scans", {})

    sev_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    findings_list = []

    for scan_name, data in scans.items():
        if isinstance(data, dict) and data.get("error"):
            continue
        for r in data.get("results", []):
            sev = (r.get("issue_severity") or "LOW").upper()
            if sev in sev_map:
                sev_map[sev] += 1
            findings_list.append({
                "scan": scan_name, "severity": sev,
                "file": r.get("filename", ""),
                "line": r.get("line_number", ""),
                "message": r.get("issue_text", ""),
            })

    total = sum(sev_map.values())
    critical = sev_map["CRITICAL"]
    high = sev_map["HIGH"]
    medium = sev_map["MEDIUM"]
    low = sev_map["LOW"]

    # Build findings HTML
    findings_html = ""
    for f in findings_list[:100]:
        icon = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(f["severity"], "⚪")
        sev_class = f"sev-{f['severity'].lower()}"
        findings_html += f"""<div class="finding-row">
            <div class="finding-sev {sev_class}">{icon} {f['severity']}</div>
            <div class="finding-body">
                <div class="finding-meta"><span class="finding-scanner">{f['scan']}</span> <code>{f['file']}:{f['line']}</code></div>
                <div class="finding-msg">{f['message'][:150]}</div>
            </div>
        </div>"""
    if not findings_html:
        findings_html = '<div class="finding-row" style="justify-content:center;padding:32px;color:#3fb950;"><span style="font-size:24px;">\u2713</span> No issues found — your code is clean!</div>'

    # Build collapsible findings section
    onclick_toggle = "var b=this.nextElementSibling,a=this.querySelector('.collapse-arrow');b.classList.toggle('closed');a.classList.toggle('closed');"
    findings_section = (
        '<div class="section">'
        '<div class="section-title" onclick="' + onclick_toggle + '">'
        '\U0001f4cb Findings (' + str(total) + ')'
        '<span class="collapse-arrow">\u25bc</span></div>'
        '<div class="collapsible-body"><div class="findings-list">'
        + findings_html + '</div></div></div>'
    )

    # Trivy section
    trivy_rows_html = ""
    trivy_data = scans.get("trivy", {})
    if isinstance(trivy_data, dict) and "Results" in trivy_data:
        for r in trivy_data["Results"]:
            for v in r.get("Vulnerabilities", [])[:30]:
                sev = v.get("Severity", "UNKNOWN")
                sev_class = f"sev-{sev.lower()}"
                trivy_rows_html += f"""<div class="finding-row">
                    <div class="finding-sev {sev_class}">{sev}</div>
                    <div class="finding-body">
                        <div class="finding-meta"><strong>{v.get('VulnerabilityID','')}</strong> in <code>{v.get('PkgName','')}</code></div>
                        <div class="finding-msg">{v.get('InstalledVersion','')} \u2192 <span class="fixed-version">{v.get('FixedVersion','unknown')}</span></div>
                        <div class="finding-msg" style="color:#8b949e;font-size:12px;">{v.get('Title','')[:120]}</div>
                    </div>
                </div>"""

    trivy_section = ""
    if trivy_rows_html:
        trivy_section = (
            '<div class="section">'
            '<div class="section-title" onclick="' + onclick_toggle + '">'
            '\U0001f4e6 Dependency Vulnerabilities<span class="collapse-arrow">\u25bc</span></div>'
            '<div class="collapsible-body"><div class="findings-list">'
            + trivy_rows_html + '</div></div></div>'
        )

    ai_summary_section = ""
    if ai_summary:
        ai_summary_section = (
            '<div class="section"><div class="section-title" onclick="'
            + onclick_toggle + '">'
            '\U0001f916 AI Analysis<span class="collapse-arrow">\u25bc</span></div>'
            '<div class="collapsible-body"><div class="ai-section">'
            + ai_summary + '</div></div></div>'
        )

    risk_level = "low"
    risk_label = "Low Risk"
    if critical > 0:
        risk_level = "critical"
        risk_label = "Critical Risk"
    elif high > 0:
        risk_level = "high"
        risk_label = "High Risk"
    elif medium > 2:
        risk_level = "medium"
        risk_label = "Medium Risk"

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZeroFlaw Report — {target_name}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #020617; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1000px; margin: 0 auto; padding: 0; }}
  .report-header {{ background: linear-gradient(135deg, #0F172A 0%, #020617 100%); border-bottom: 1px solid rgba(255,255,255,0.05); padding: 32px 24px; }}
  .report-header .logo {{ display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }}
  .report-header .logo-icon {{ width: 44px; height: 44px; border-radius: 14px; background: rgba(34,211,238,0.1); border: 1px solid rgba(34,211,238,0.2); display: flex; align-items: center; justify-content: center; font-size: 22px; }}
  .report-header h1 {{ font-size: 22px; font-weight: 700; }}
  .report-header .subtitle {{ color: #94a3b8; font-size: 14px; }}
  .report-header .meta-row {{ display: flex; gap: 24px; margin-top: 12px; flex-wrap: wrap; }}
  .report-header .meta-item {{ color: #64748b; font-size: 13px; }}
  .report-header .meta-item strong {{ color: #94a3b8; }}
  .report-header .download-btn {{ display: inline-block; padding: 8px 20px; background: #22d4ee; color: #020617; border: none; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; }}
  .report-header .download-btn:hover {{ background: #1bb3cc; }}
  .report-header .download-btn.pdf {{ background: rgba(255,255,255,0.08); color: #e2e8f0; border: 1px solid rgba(255,255,255,0.1); }}
  .report-header .download-btn.pdf:hover {{ background: rgba(255,255,255,0.12); }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 24px; }}
  .stat-card {{ background: #0F172A; border: 1px solid rgba(255,255,255,0.05); border-radius: 16px; padding: 20px; text-align: center; }}
  .stat-card .num {{ font-size: 36px; font-weight: 800; line-height: 1; }}
  .stat-card .label {{ color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; margin-top: 8px; }}
  .stat-card .num.critical {{ color: #ff7b72; }} .stat-card .num.high {{ color: #d29922; }} .stat-card .num.medium {{ color: #d29922; }} .stat-card .num.low {{ color: #22d4ee; }}
  .risk-badge {{ display: inline-flex; align-items: center; gap: 8px; padding: 8px 20px; border-radius: 100px; font-weight: 600; font-size: 14px; margin: 24px; }}
  .risk-badge.critical {{ background: rgba(239,68,68,0.1); color: #ff7b72; border: 1px solid rgba(239,68,68,0.2); }}
  .risk-badge.high {{ background: rgba(234,179,8,0.1); color: #eab308; border: 1px solid rgba(234,179,8,0.2); }}
  .risk-badge.medium {{ background: rgba(234,179,8,0.08); color: #d29922; border: 1px solid rgba(234,179,8,0.15); }}
  .risk-badge.low {{ background: rgba(34,197,94,0.1); color: #3fb950; border: 1px solid rgba(34,197,94,0.2); }}
  .section {{ margin: 24px; }}
  .section-title {{ font-size: 16px; font-weight: 600; color: #22d4ee; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; }}
  .section-title:hover {{ opacity: 0.8; }}
  .collapse-arrow {{ font-size: 12px; transition: transform 0.2s; }}
  .collapse-arrow.closed {{ transform: rotate(-90deg); }}
  .collapsible-body {{ overflow: hidden; transition: max-height 0.3s; }}
  .collapsible-body.closed {{ max-height: 0 !important; }}
  .findings-list {{ display: flex; flex-direction: column; gap: 6px; }}
  .finding-row {{ display: flex; gap: 12px; padding: 12px 16px; background: #0F172A; border: 1px solid rgba(255,255,255,0.05); border-radius: 10px; }}
  .finding-sev {{ flex-shrink: 0; width: 100px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; padding-top: 2px; }}
  .finding-sev.sev-critical {{ color: #ff7b72; }} .finding-sev.sev-high {{ color: #eab308; }} .finding-sev.sev-medium {{ color: #d29922; }} .finding-sev.sev-low {{ color: #22d4ee; }}
  .finding-body {{ flex: 1; min-width: 0; }}
  .finding-meta {{ font-size: 12px; color: #64748b; margin-bottom: 4px; }}
  .finding-meta code {{ font-family: "SFMono-Regular", Consolas, monospace; background: rgba(255,255,255,0.05); padding: 1px 6px; border-radius: 4px; font-size: 11px; }}
  .finding-scanner {{ display: inline-block; padding: 1px 8px; border-radius: 4px; background: rgba(34,211,238,0.08); color: #22d4ee; font-size: 10px; font-weight: 600; text-transform: uppercase; margin-right: 6px; }}
  .finding-msg {{ font-size: 13px; color: #cbd5e1; }}
  .fixed-version {{ color: #22c55e; }}
  .ai-section {{ background: #0F172A; border: 1px solid rgba(34,211,238,0.15); border-radius: 12px; padding: 20px; margin: 24px; }}
  .ai-section h2 {{ color: #22d4ee; font-size: 16px; font-weight: 600; margin-bottom: 12px; }}
  .ai-section p {{ margin: 8px 0; font-size: 14px; line-height: 1.7; }}
  .ai-section ul {{ margin: 8px 0 8px 20px; }}
  .ai-section li {{ font-size: 14px; margin: 4px 0; }}
  .ai-section code {{ background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
  .verdict {{ display: inline-block; padding: 4px 16px; border-radius: 100px; font-size: 13px; font-weight: 600; margin-top: 8px; }}
  .verdict-pass {{ background: rgba(34,197,94,0.1); color: #3fb950; border: 1px solid rgba(34,197,94,0.2); }}
  .verdict-caveats {{ background: rgba(234,179,8,0.1); color: #eab308; border: 1px solid rgba(234,179,8,0.2); }}
  .verdict-review {{ background: rgba(239,68,68,0.1); color: #ff7b72; border: 1px solid rgba(239,68,68,0.2); }}
  @page {{ margin: 2cm 2.5cm; size: A4; }}
  @media (max-width: 600px) {{
    .container {{ padding: 0 12px; }}
    .report-header {{ padding: 20px 16px; }}
    .report-header h1 {{ font-size: 18px; }}
    .stats-grid {{ grid-template-columns: repeat(2, 1fr); gap: 8px; margin: 16px 12px; }}
    .stat-card {{ padding: 12px; }}
    .stat-card .num {{ font-size: 24px; }}
    .section {{ margin: 16px 12px; }}
    .finding-row {{ flex-direction: column; gap: 4px; padding: 10px 12px; }}
    .finding-sev {{ width: 100%; }}
    .meta-row {{ flex-direction: column; gap: 8px; }}
    .download-btn {{ width: 100%; text-align: center; }}
  }}
  @media print {{
    body {{ background: #fff !important; color: #1a1a1a !important; font-size: 11pt; line-height: 1.5; }}
    .container {{ max-width: 100%; padding: 0; }}
    .report-header {{ background: #f8f9fa !important; border-bottom: 2px solid #222 !important; padding: 24px 0 !important; }}
    .report-header h1 {{ font-size: 20pt; color: #000 !important; }}
    .report-header .subtitle {{ color: #555 !important; font-size: 10pt; }}
    .report-header .meta-item {{ color: #444 !important; font-size: 9pt; }}
    .report-header .meta-item strong {{ color: #222 !important; }}
    .report-header .download-btn {{ display: none !important; }}
    .stat-card {{ background: #f8f9fa !important; border: 1px solid #ddd !important; border-radius: 6px; padding: 12px; }}
    .stat-card .num {{ font-size: 28pt; }}
    .stat-card .num.critical {{ color: #b91c1c !important; }}
    .stat-card .num.high {{ color: #b45309 !important; }}
    .stat-card .num.medium {{ color: #a16207 !important; }}
    .stat-card .num.low {{ color: #15803d !important; }}
    .stat-card .label {{ color: #555 !important; }}
    .risk-badge {{ border: 1px solid #ccc !important; background: #f8f9fa !important; color: #000 !important; }}
    .risk-badge.critical {{ background: #fef2f2 !important; color: #b91c1c !important; border-color: #b91c1c !important; }}
    .risk-badge.high {{ background: #fffbeb !important; color: #b45309 !important; border-color: #b45309 !important; }}
    .risk-badge.medium {{ background: #fefce8 !important; color: #a16207 !important; border-color: #a16207 !important; }}
    .risk-badge.low {{ background: #f0fdf4 !important; color: #15803d !important; border-color: #15803d !important; }}
    .section-title {{ color: #000 !important; font-size: 13pt; border-bottom: 1px solid #ddd; padding-bottom: 6px; }}
    .finding-row {{ background: #fafafa !important; border: 1px solid #e5e5e5 !important; border-radius: 4px; break-inside: avoid; }}
    .finding-sev.sev-critical {{ color: #b91c1c !important; }}
    .finding-sev.sev-high {{ color: #b45309 !important; }}
    .finding-sev.sev-medium {{ color: #a16207 !important; }}
    .finding-sev.sev-low {{ color: #15803d !important; }}
    .finding-meta {{ color: #444 !important; }}
    .finding-meta code {{ background: #f0f0f0 !important; color: #333 !important; }}
    .finding-scanner {{ background: #e8f4f8 !important; color: #0369a1 !important; }}
    .finding-msg {{ color: #333 !important; font-size: 10pt; }}
    .fixed-version {{ color: #15803d !important; }}
    .ai-section {{ background: #f8f9fa !important; border: 1px solid #bbb !important; }}
    .ai-section h2 {{ color: #000 !important; }}
    .ai-section p {{ color: #333 !important; }}
    .ai-section code {{ background: #f0f0f0 !important; color: #333 !important; }}
    .verdict-pass {{ background: #f0fdf4 !important; color: #15803d !important; border-color: #15803d !important; }}
    .verdict-caveats {{ background: #fffbeb !important; color: #b45309 !important; border-color: #b45309 !important; }}
    .verdict-review {{ background: #fef2f2 !important; color: #b91c1c !important; border-color: #b91c1c !important; }}
    .back-row {{ display: none !important; }}
    .collapsible-body {{ max-height: none !important; }}
    .collapse-arrow {{ display: none !important; }}
    .footer {{ color: #666 !important; font-size: 8pt; text-align: center; padding: 16px 0; }}
    .stats-grid {{ gap: 8px; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="report-header">
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <div>
        <h1>ZeroFlaw Security Report</h1>
        <div class="subtitle">Automated security analysis for {target_name}</div>
      </div>
    </div>
    <div class="meta-row">
      <span class="meta-item"><strong>Target:</strong> {target_name}</span>
      <span class="meta-item"><strong>Generator:</strong> Yours Truly{'' if not provider_name else f' via {provider_name}'}</span>
    </div>
  </div>

  <div style="text-align:center;">
    <div class="risk-badge {risk_level}">⬤ {risk_label}</div>
  </div>

  <div class="stats-grid">
    <div class="stat-card"><div class="num critical">{critical}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="num high">{high}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="num medium">{medium}</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="num low">{low}</div><div class="label">Low</div></div>
  </div>

  {ai_summary_section}

  {findings_section}

  {trivy_section}

  <div class="back-row">
    <a href="/" class="back-btn">← Scan Another Project</a>
  </div>

  <div class="footer">
    Report auto-generated by ZeroFlaw Security Scanner
  </div>
</div>
</body>
</html>"""
    return report


def generate_pdf_report(target_name: str, results: dict, ai_summary: str = "", provider_name: str = "") -> bytes:
    """Generate a clean document-style PDF report (not a web-page conversion)."""
    from datetime import datetime
    scans = results.get("scans", {})
    sev_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    findings_rows = ""

    for scan_name, data in scans.items():
        if isinstance(data, dict) and data.get("error"):
            continue
        for r in data.get("results", []):
            sev = (r.get("issue_severity") or "LOW").upper()
            if sev in sev_map:
                sev_map[sev] += 1
            findings_rows += f"""<tr>
              <td class="sev-{sev.lower()}">{sev}</td>
              <td>{scan_name}</td>
              <td style="font-size:9pt">{r.get('filename', '')}:{r.get('line_number', '')}</td>
              <td style="font-size:9pt">{r.get('issue_text', '')[:120]}</td>
            </tr>"""

    total = sum(sev_map.values())
    critical, high, medium, low = sev_map["CRITICAL"], sev_map["HIGH"], sev_map["MEDIUM"], sev_map["LOW"]

    risk_level = "Low Risk"
    if critical > 0:
        risk_level = "CRITICAL RISK"
    elif high > 0:
        risk_level = "HIGH RISK"
    elif medium > 2:
        risk_level = "MEDIUM RISK"

    # Trivy rows
    trivy_rows = ""
    trivy_data = scans.get("trivy", {})
    if isinstance(trivy_data, dict) and "Results" in trivy_data:
        for r in trivy_data["Results"]:
            for v in r.get("Vulnerabilities", [])[:30]:
                sev = v.get("Severity", "UNKNOWN")
                trivy_rows += f"""<tr>
                  <td class="sev-{sev.lower()}">{sev}</td>
                  <td>{v.get('VulnerabilityID', '')}</td>
                  <td>{v.get('PkgName', '')}</td>
                  <td style="font-size:9pt">{v.get('Title', '')[:80]}</td>
                </tr>"""

    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  @page {{ margin: 2cm 2.2cm; size: A4; }}
  @page {{ @bottom-center {{ content: "Page " counter(page); font-size: 8pt; color: #888; font-family: Georgia, 'Times New Roman', serif; }} }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: Georgia, 'Times New Roman', serif; font-size: 10pt; color: #222; line-height: 1.5; }}
  h1 {{ font-size: 18pt; color: #000; margin-bottom: 2pt; letter-spacing: 0.5pt; }}
  .subtitle {{ font-size: 10pt; color: #555; margin-bottom: 12pt; }}
  .meta {{ font-size: 9pt; color: #666; margin-bottom: 18pt; border-bottom: 1.5pt solid #222; padding-bottom: 10pt; }}
  .risk-badge {{ display: inline-block; padding: 4pt 14pt; font-size: 11pt; font-weight: bold; letter-spacing: 1pt; margin-bottom: 16pt; }}
  .risk-critical {{ background: #b91c1c; color: #fff; }}
  .risk-high {{ background: #b45309; color: #fff; }}
  .risk-medium {{ background: #a16207; color: #fff; }}
  .risk-low {{ background: #15803d; color: #fff; }}
  .summary-grid {{ display: flex; gap: 16pt; margin-bottom: 18pt; }}
  .summary-item {{ text-align: center; }}
  .summary-item .num {{ font-size: 16pt; font-weight: bold; }}
  .summary-item .label {{ font-size: 8pt; color: #666; text-transform: uppercase; letter-spacing: 1pt; }}
  .num-critical {{ color: #b91c1c; }} .num-high {{ color: #b45309; }} .num-medium {{ color: #a16207; }} .num-low {{ color: #15803d; }}
  h2 {{ font-size: 12pt; color: #000; margin: 16pt 0 8pt 0; border-bottom: 0.5pt solid #ccc; padding-bottom: 4pt; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 14pt; font-size: 9pt; }}
  th {{ background: #333; color: #fff; text-align: left; padding: 5pt 6pt; font-size: 8pt; text-transform: uppercase; letter-spacing: 0.5pt; }}
  td {{ padding: 4pt 6pt; border-bottom: 0.5pt solid #ddd; vertical-align: top; }}
  tr:nth-child(even) td {{ background: #f8f9fa; }}
  .sev-critical {{ color: #b91c1c; font-weight: bold; }}
  .sev-high {{ color: #b45309; font-weight: bold; }}
  .sev-medium {{ color: #a16207; font-weight: bold; }}
  .sev-low {{ color: #15803d; }}
  .ai-box {{ border: 0.5pt solid #bbb; padding: 10pt 12pt; margin-bottom: 14pt; font-size: 9.5pt; }}
  .ai-box p {{ margin: 4pt 0; }}
  .ai-box ul {{ margin: 4pt 0 4pt 16pt; }}
  .ai-box li {{ margin: 2pt 0; }}
  .ai-box code {{ font-family: 'Courier New', monospace; font-size: 8.5pt; background: #f0f0f0; padding: 1pt 3pt; }}
  .footer {{ margin-top: 18pt; padding-top: 8pt; border-top: 0.5pt solid #ccc; font-size: 8pt; color: #888; text-align: center; }}
</style></head><body>
<h1>ZeroFlaw Security Report</h1>
<div class="subtitle">Automated security analysis for {target_name}</div>
<div class="meta">Target: {target_name} &nbsp;|&nbsp; Generated: {date_str} &nbsp;|&nbsp; Scanner: ZeroFlaw{'' if not provider_name else f' / {provider_name}'}</div>

<div class="risk-badge risk-{risk_level.split()[0].lower()}">{risk_level}</div>

<h2>Findings Summary</h2>
<div class="summary-grid">
  <div class="summary-item"><div class="num num-critical">{critical}</div><div class="label">Critical</div></div>
  <div class="summary-item"><div class="num num-high">{high}</div><div class="label">High</div></div>
  <div class="summary-item"><div class="num num-medium">{medium}</div><div class="label">Medium</div></div>
  <div class="summary-item"><div class="num num-low">{low}</div><div class="label">Low</div></div>
</div>

{f'<h2>AI Analysis</h2><div class="ai-box">{ai_summary}</div>' if ai_summary else ''}

<h2>Findings ({total})</h2>
<table>
  <tr><th>Severity</th><th>Scanner</th><th>Location</th><th>Description</th></tr>
  {findings_rows if findings_rows else '<tr><td colspan="4" style="color:#15803d;text-align:center;padding:12pt">No issues found.</td></tr>'}
</table>

{f'<h2>Dependency Vulnerabilities</h2><table><tr><th>Severity</th><th>ID</th><th>Package</th><th>Description</th></tr>{trivy_rows}</table>' if trivy_rows else ''}

<div class="footer">Report auto-generated by ZeroFlaw Security Scanner on {date_str}</div>
</body></html>"""
    try:
        return WeasyHTML(string=html).write_pdf()
    except Exception as e:
        print(f"PDF generation failed: {e}", file=sys.stderr)
        return b""


# ── Helpers ─────────────────────────────────────────────────────────────

def run_trivy_safe(path: str) -> dict:
    """Run Trivy on a path, returning structured results."""
    trivy = shutil.which("trivy")
    if not trivy:
        return {"error": "Trivy not installed"}
    try:
        result = subprocess.run(
            [trivy, "fs", "--format", "json", "--quiet", "--skip-db-update", "--", path],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):
            return {"error": f"Trivy failed: {result.stderr[:200]}"}
        data = json.loads(result.stdout) if result.stdout.strip() else {"Results": []}
        return data
    except subprocess.TimeoutExpired:
        return {"error": "Trivy timed out"}
    except Exception as e:
        return {"error": str(e)}


async def scan_project_stream(project_path: str, target_name: str):
    """Run all scans with progress events. Yields SSE-formatted messages."""
    results = {"scans": {}, "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}}

    # Detect project languages
    has_py = False
    has_js = False
    has_java = False
    has_go = False
    has_rs = False
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in (".venv", "venv", "node_modules", ".git", "__pycache__", "target", "build", "dist")]
        for f in files:
            if f.endswith(".py"):
                has_py = True
            if f.endswith((".js", ".ts", ".jsx", ".tsx")):
                has_js = True
            if f.endswith((".java", ".kt", ".kts")):
                has_java = True
            if f.endswith(".go"):
                has_go = True
            if f.endswith(".rs"):
                has_rs = True

    lang_tags = []
    if has_py:
        lang_tags.append("Python")
    if has_js:
        lang_tags.append("JS/TS")
    if has_java:
        lang_tags.append("Java")
    if has_go:
        lang_tags.append("Go")
    if has_rs:
        lang_tags.append("Rust")
    lang_str = "/".join(lang_tags) if lang_tags else "multi-language"

    scans_to_run = []
    py_label = "Python" if has_py else lang_str
    scans_to_run.append(("bandit", f"🐍 Bandit ({py_label} Security)", lambda: run_security_scan(project_path)))
    scans_to_run.append(("ruff", f"📐 Ruff ({py_label} Linting)", lambda: run_code_linting(project_path)))
    scans_to_run.append(("semgrep", f"🔬 Semgrep ({lang_str} SAST)", lambda: run_universal_security_scan(project_path)))

    # Check for dep files
    has_npm = os.path.isfile(os.path.join(project_path, "package.json"))
    has_pip = os.path.isfile(os.path.join(project_path, "requirements.txt"))

    yield f"data: {json.dumps({'type':'prompt','text':f'$ zeroflaw scan {target_name[:50]}'})}\n\n"
    await asyncio.sleep(0.3)

    # Pre-scan: reject huge repos before running any tools
    file_count = 0
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in (".venv", "venv", "node_modules", ".git", "__pycache__", "target", "build", "dist")]
        file_count += len(files)
        if file_count > 10_000:
            yield f"data: {json.dumps({'type':'error','text':'Repository has too many files (> 10,000). Try adding .scannerignore or scan a subdirectory.'})}\n\n"
            yield f"data: {json.dumps({'type':'done','results':{'error':'Too many files'}})}\n\n"
            return

    for key, label, scanner in scans_to_run:
        yield f"data: {json.dumps({'type':'running','text':f'{label}...'})}\n\n"
        await asyncio.sleep(0.1)
        try:
            result = scanner()
            if "error" in result:
                err_msg = result["error"][:60]
                yield f"data: {json.dumps({'type':'error','text':f'{label} — skipped ({err_msg})'})}\n\n"
            else:
                findings = len(result.get("results", []))
                status = "clean" if findings == 0 else f"{findings} issue(s)"
                yield f"data: {json.dumps({'type':'ok' if findings == 0 else 'warn','text':f'{label} — {status}'})}\n\n"
            results["scans"][key] = result
        except Exception as e:
            yield f"data: {json.dumps({'type':'error','text':f'{label} — failed ({str(e)[:60]})'})}\n\n"
            results["scans"][key] = {"error": str(e)}
        await asyncio.sleep(0.2)

    # Dependency scans
    if has_npm:
        yield f"data: {json.dumps({'type':'running','text':'📦 npm audit...'})}\n\n"
        await asyncio.sleep(0.1)
        npm_result = scan_npm_dependencies(project_path)
        npm_count = len(npm_result.get("vulnerabilities", {})) if isinstance(npm_result.get("vulnerabilities"), dict) else 0
        yield f"data: {json.dumps({'type':'warn' if npm_count > 0 else 'ok','text':f'📦 npm audit — {npm_count} vuln(s)'})}\n\n"
        results["scans"]["npm_audit"] = npm_result

    if has_pip:
        yield f"data: {json.dumps({'type':'running','text':'🐍 pip audit...'})}\n\n"
        await asyncio.sleep(0.1)
        pip_result = scan_python_dependencies(project_path)
        pip_count = len(pip_result.get("vulnerabilities", []))
        yield f"data: {json.dumps({'type':'warn' if pip_count > 0 else 'ok','text':f'🐍 pip audit — {pip_count} vuln(s)'})}\n\n"
        results["scans"]["pip_audit"] = pip_result

    # Trivy
    yield f"data: {json.dumps({'type':'running','text':'🔍 Trivy (Dependency Scan)...'})}\n\n"
    await asyncio.sleep(0.1)
    trivy_result = run_trivy_safe(project_path)
    trivy_count = 0
    if isinstance(trivy_result, dict) and "Results" in trivy_result:
        for r in trivy_result["Results"]:
            trivy_count += len(r.get("Vulnerabilities", []))
    yield f"data: {json.dumps({'type':'warn' if trivy_count > 0 else 'ok','text':f'🔍 Trivy — {trivy_count} vuln(s)'})}\n\n"
    results["scans"]["trivy"] = trivy_result

    # Secret scanning — detect exposed API keys, tokens, passwords in files
    yield f"data: {json.dumps({'type':'running','text':'🔑 Scanning for secrets (API keys, tokens)...'})}\n\n"
    await asyncio.sleep(0.1)
    secret_findings = []
    secret_patterns = [
        (r'(?i)(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*["\']?(sk-[a-zA-Z0-9]{10,}|ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}|ghu_[a-zA-Z0-9]{36,}|xox[bpras]-[a-zA-Z0-9]{10,}|AKIA[0-9A-Z]{16})["\']?', "Hardcoded API Key / Secret Token"),
        (r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key Exposed"),
        (r'(?i)password\s*[:=]\s*["\'][^"\']{3,}["\']', "Hardcoded Password"),
        (r'(?i)PGPASSWORD\s*[:=]\s*["\']?[^"\'\s]+', "Database Password"),
        (r'(?i)mongodb[+srv]*://[^:]+:[^@]+@', "MongoDB Connection String with Password"),
        (r'(?i)redis://[^:]+:[^@]+@', "Redis URL with Password"),
        (r'https://[^:]+:[^@]+@github\.com', "GitHub URL with Token"),
    ]
    scan_errors = []
    for root, dirs, files in os.walk(project_path):
        # Skip venv, node_modules, .git
        dirs[:] = [d for d in dirs if d not in (".venv", "venv", "node_modules", ".git", "__pycache__")]
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > 1024 * 100:  # skip files > 100KB
                    continue
                content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                for pattern, label in secret_patterns:
                    import re
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count("\n") + 1
                        secret_findings.append({
                            "file": os.path.relpath(fpath, project_path),
                            "line": line_num,
                            "severity": "HIGH",
                            "message": label,
                            "match": match.group(0)[:40] + "...",
                        })
            except Exception as e:
                scan_errors.append({"file": fpath, "error": str(e)[:100]})

    secret_count = len(secret_findings)
    results["scans"]["secrets"] = {"results": secret_findings, "count": secret_count, "scan_errors": scan_errors}
    yield f"data: {json.dumps({'type':'warn' if secret_count > 0 else 'ok','text':f'🔑 Secrets — {secret_count} potential secret(s) found'})}\n\n"
    
    # Additional security tools
    # CodeQL scan
    yield f"data: {json.dumps({'type':'running','text':'🔬 CodeQL Scan...'})}\n\n"
    await asyncio.sleep(0.1)
    from server import run_codeql_scan
    codeql_result = run_codeql_scan(project_path)
    codeql_count = len(codeql_result.get("results", []))
    yield f"data: {json.dumps({'type':'warn' if codeql_count > 0 else 'ok','text':f'🔬 CodeQL — {codeql_count} issue(s)'})}\n\n"
    results["scans"]["codeql"] = codeql_result
    
    # OWASP ZAP scan
    yield f"data: {json.dumps({'type':'running','text':'🕷️ OWASP ZAP Scan...'})}\n\n"
    await asyncio.sleep(0.1)
    from server import run_owasp_zap_scan
    zap_result = run_owasp_zap_scan(project_path)
    zap_count = len(zap_result.get("results", []))
    yield f"data: {json.dumps({'type':'warn' if zap_count > 0 else 'ok','text':f'🕷️ OWASP ZAP — {zap_count} issue(s)'})}\n\n"
    results["scans"]["zap"] = zap_result

    # Tally
    total = 0
    for scan_name, scan_data in results["scans"].items():
        if isinstance(scan_data, dict) and "results" in str(type(scan_data)):
            total += len(scan_data.get("results", []))
    results["summary"]["total"] = total

    yield f"data: {json.dumps({'type':'done','results':results})}\n\n"


# ── Background scan store ──────────────────────────────────────────
# Avoids Render's 60s response timeout: POST returns immediately with
# a redirect to a progress page; the scan runs in the background.

async def _run_scan_background(
    scan_id: str, project_path: str, target_name: str,
    api_key: str, provider: str,
):
    """Run scan in background and persist results to B2.
    
    Updates steps in real-time so the progress page sees each step
    as it happens, rather than all at once after the scan finishes.
    """
    try:
        b2_store.put(scan_id, {
            "status": "scanning", "target": target_name,
            "created_at": time.time(), "steps": [],
        })
    except Exception:
        pass  # B2 may not be configured; scan proceeds without persistence

    try:
        results = None
        async for event in scan_project_stream(project_path, target_name):
            if event.startswith("data: "):
                data = json.loads(event[6:].strip())
                entry = b2_store.get(scan_id) or {}
                steps = entry.get("steps", [])
                steps.append(data)
                entry["steps"] = steps
                try:
                    b2_store.put(scan_id, entry)
                except Exception:
                    pass  # best-effort persistence; stream continues regardless
                if data.get("type") == "done":
                    results = data["results"]

        if not results:
            entry = b2_store.get(scan_id) or {}
            entry["status"] = "error"
            entry["error"] = "Scan produced no results"
            try:
                b2_store.put(scan_id, entry)
            except Exception:
                pass  # best-effort persistence; error state already set
            return

        ai_summary, provider_name = await generate_ai_report_summary(
            api_key, target_name, results, provider
        )

        report = generate_html_report(target_name, results, ai_summary, provider_name)

        download_btns = f'<div class="meta-row"><a href="/download/{scan_id}?format=html" class="download-btn" download>\u2b07 Download HTML</a><a href="/download/{scan_id}?format=pdf" class="download-btn" download>\U0001f4c4 Download PDF</a><a href="/fix/run/{scan_id}" class="download-btn" style="background:rgba(34,211,238,0.15);border:1px solid rgba(34,211,238,0.3);">\U0001f527 Fix &amp; Download</a>'
        report = report.replace('<div class="meta-row">', download_btns, 1)

        try:
            b2_store.put_text(f"reports/{scan_id}.html", report, "text/html")
        except Exception:
            pass
        try:
            download_report = report.replace(
                '<div class="back-row">',
                '<div class="back-row" style="display:none">',
                1,
            )
            b2_store.put_text(f"reports/{scan_id}-download.html", download_report, "text/html")
        except Exception:
            pass
        try:
            pdf_bytes = generate_pdf_report(target_name, results, ai_summary, provider_name)
            if pdf_bytes:
                b2_store.put_file(f"reports/{scan_id}.pdf", pdf_bytes, "application/pdf")
        except Exception:
            pass

        source_dir = ""
        try:
            source_dir = os.path.join(BASE_DIR, "temp_scans", scan_id, "source")
            os.makedirs(source_dir, exist_ok=True)
            for item in os.listdir(project_path):
                src = os.path.join(project_path, item)
                dst = os.path.join(source_dir, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, symlinks=False, ignore=lambda s, n: {d for d in n if d in (".venv", "venv", "node_modules", ".git", "__pycache__", "target", "build", "dist")})
                else:
                    shutil.copy2(src, dst)
        except Exception:
            pass
        try:
            zip_buf = io.BytesIO()
            _skip = {".venv", "venv", "node_modules", ".git", "__pycache__", "target", "build", "dist", ".ruff_cache", ".bandit_cache", ".semgrep_logs", ".mypy_cache", ".pytest_cache", "__pycache__"}
            with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(project_path):
                    dirs[:] = [d for d in dirs if d not in _skip]
                    for fn in files:
                        path = os.path.join(root, fn)
                        zf.write(path, os.path.relpath(path, project_path))
            b2_store.put_file(f"reports/{scan_id}-source.zip", zip_buf.getvalue(), "application/zip")
        except Exception:
            pass

        entry = b2_store.get(scan_id) or {}
        entry["status"] = "done"
        entry["results"] = results
        if source_dir:
            entry["project_dir"] = source_dir
        b2_store.put(scan_id, entry)

    except Exception as e:
        entry = b2_store.get(scan_id) or {}
        entry["status"] = "error"
        entry["error"] = str(e)
        try:
            b2_store.put(scan_id, entry)
        except Exception:
            pass  # best-effort persistence; error already logged above
        print(f"Background scan {scan_id} failed: {e}", file=sys.stderr)


# ── Background fix ──────────────────────────────────────────────────────

async def _run_fix_background(scan_id: str, entry: dict):
    """Run auto-fix in background and store results in B2."""
    import tempfile as _tmp
    try:
        project_path = entry.get("project_dir", "")
        if not project_path or not os.path.isdir(project_path):
            source_zip = b2_store.get_file(f"reports/{scan_id}-source.zip")
            if not source_zip:
                upd = b2_store.get(scan_id) or {}
                upd["status"] = "error"
                upd["error"] = "Source not available"
                b2_store.put(scan_id, upd)
                return
            tmpdir = _tmp.mkdtemp(prefix="zeroflaw_fix_")
            with _tmp.NamedTemporaryFile(suffix=".zip", delete=False) as f:
                f.write(source_zip)
                zippath = f.name
            with zipfile.ZipFile(zippath, "r") as zf:
                zf.extractall(tmpdir)
            os.unlink(zippath)
            project_path = tmpdir

        results = entry.get("results")
        if not results and entry.get("steps"):
            for s in entry["steps"]:
                if s.get("type") == "done" and s.get("results"):
                    results = s["results"]
                    break
        if not results:
            upd = b2_store.get(scan_id) or {}
            upd["status"] = "error"
            upd["error"] = "No results found"
            b2_store.put(scan_id, upd)
            return

        changes = auto_fix.apply_fixes(project_path, results)
        if not changes:
            b2_store.put_text(f"reports/{scan_id}-fix-result.html", f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>No Fixable Issues</title><style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#020617;color:#e2e8f0;line-height:1.6;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}}.card{{background:#0F172A;border:1px solid rgba(255,255,255,0.05);border-radius:16px;padding:32px;max-width:520px;width:100%;text-align:center}}h2{{color:#3fb950;font-size:20px;margin-bottom:12px}}p{{color:#94a3b8;font-size:14px;margin-bottom:16px}}a{{display:inline-block;padding:10px 24px;background:#22d4ee;color:#020617;border-radius:10px;text-decoration:none;font-size:14px;font-weight:600}}</style></head><body><div class="card"><h2>✓ No Fixable Issues</h2><p>No auto-fixable security patterns were detected.</p><a href="/download/{scan_id}">← Back to Report</a></div></body></html>""")
            upd = b2_store.get(scan_id) or {}
            upd["status"] = "done_fix"
            upd["fix_count"] = 0
            b2_store.put(scan_id, upd)
            return

        with _tmp.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_zip:
            tmp_zip_path = tmp_zip.name
        auto_fix.create_fixed_zip(project_path, tmp_zip_path)
        with open(tmp_zip_path, "rb") as f:
            zip_data = f.read()
        os.unlink(tmp_zip_path)
        b2_store.put_file(f"reports/{scan_id}-fixed.zip", zip_data, "application/zip")

        fix_rows = ""
        for c in changes:
            fix_rows += f"""<tr><td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px;color:#22d4ee;">🔧</td><td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:13px;">{c['file']}:{c['line']}</td><td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px;color:#94a3b8;">{c['issue'][:80]}</td><td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px;color:#3fb950;">{c['fix']}</td></tr>"""

        b2_store.put_text(f"reports/{scan_id}-fix-result.html", f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Fixes Applied</title><style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#020617;color:#e2e8f0;line-height:1.6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}.card{{background:#0F172A;border:1px solid rgba(255,255,255,0.05);border-radius:16px;padding:32px;max-width:640px;width:100%}}h2{{color:#22d4ee;font-size:20px;margin-bottom:4px;display:flex;align-items:center;gap:8px}}.subtitle{{color:#64748b;font-size:13px;margin-bottom:20px}}table{{width:100%;border-collapse:collapse;margin-bottom:20px}}th{{text-align:left;color:#64748b;font-size:11px;padding:4px 8px;border-bottom:1px solid rgba(255,255,255,0.1);text-transform:uppercase;letter-spacing:1px}}.btn{{display:inline-block;padding:12px 24px;background:#22d4ee;color:#020617;border-radius:10px;text-decoration:none;font-size:14px;font-weight:600;margin-right:8px}}.btn-sec{{display:inline-block;padding:12px 24px;background:rgba(255,255,255,0.05);color:#e2e8f0;border:1px solid rgba(255,255,255,0.08);border-radius:10px;text-decoration:none;font-size:14px}}</style></head><body><div class="card"><h2>🛠 Fixes Applied ({len(changes)})</h2><p class="subtitle">The following changes were made to your project:</p><table><tr><th></th><th>Location</th><th>Issue</th><th>Fix</th></tr>{fix_rows}</table><div><a href="/download/{scan_id}?format=zip" class="btn" download>⬇ Download Fixed Source (.zip)</a><a href="/download/{scan_id}" class="btn-sec">← Back to Report</a></div></div></body></html>""")
        upd = b2_store.get(scan_id) or {}
        upd["status"] = "done_fix"
        upd["fix_count"] = len(changes)
        b2_store.put(scan_id, upd)
    except Exception as e:
        upd = b2_store.get(scan_id) or {}
        upd["status"] = "error"
        upd["error"] = str(e)
        b2_store.put(scan_id, upd)

# ── Routes ──────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/scan/upload")
async def scan_upload(file: UploadFile = File(...), api_key: str = Form(""), provider: str = Form("")):
    """Accept a zip upload or single file, scan in background, redirect to progress."""
    scan_id = str(uuid.uuid4())[:8]
    tmpdir = os.path.join(BASE_DIR, "temp_scans", scan_id)
    os.makedirs(tmpdir, exist_ok=True)

    target_name = file.filename or "upload"
    is_zip = file.filename and file.filename.endswith(".zip")

    if is_zip:
        zip_path = os.path.join(tmpdir, "project.zip")
        with open(zip_path, "wb") as f:
            content = await file.read()
            f.write(content)
        extract_to = os.path.join(tmpdir, "project")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_to)
    else:
        extract_to = os.path.join(tmpdir, "project")
        os.makedirs(extract_to)
        file_path = os.path.join(extract_to, file.filename or "upload.txt")
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

    try:
        b2_store.put(scan_id, {
            "status": "scanning", "type": "upload",
            "target": target_name, "created_at": time.time(),
            "tmpdir": tmpdir,
        })
    except Exception:
        pass  # B2 may not be configured; scan proceeds without initial metadata

    asyncio.create_task(_run_scan_background(scan_id, extract_to, target_name, api_key, provider))

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/progress/{scan_id}", status_code=303)


@app.post("/scan/url")
async def scan_url(repo_url: str = Form(...), api_key: str = Form(""), provider: str = Form("")):
    """Clone a git repo URL, scan in background, redirect to progress."""
    if not validate_repo_url(repo_url):
        return error_page("Invalid repository URL", "<p>Only GitHub, GitLab, and Bitbucket HTTPS URLs are allowed.</p><a href='/'>← Try Again</a>", 400)
    import urllib.parse
    repo_name = os.path.basename(urllib.parse.urlparse(repo_url).path) or "repo"
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    scan_id = str(uuid.uuid4())[:8]
    tmpdir = os.path.join(BASE_DIR, "temp_scans", scan_id)
    os.makedirs(tmpdir, exist_ok=True)
    clone_to = os.path.join(tmpdir, "repo")

    try:
        git_path = shutil.which("git") or "git"
        result = subprocess.run(
            [git_path, "clone", "--depth", "1", "--", repo_url, clone_to],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            shutil.rmtree(tmpdir, ignore_errors=True)
            err = result.stderr[:300]
            is_auth = "could not read Username" in err or "Authentication failed" in err or "403" in err
            hint = ""
            if is_auth:
                hint = '<p style="color:#eab308;margin-top:12px;font-size:13px;">This looks like a <strong>private repository</strong>. Use a token in the URL:<br><code style="background:#020617;padding:4px 8px;border-radius:4px;color:#22d4ee;">https://&lt;token&gt;@github.com/user/repo</code></p>'
            body = f"<pre style='background:#020617;padding:16px;border-radius:8px;color:#94a3b8;font-size:13px;overflow-x:auto;text-align:left;'>{err}</pre>{hint}<a href='/'>← Try Again</a>"
            return error_page("Clone failed", body, 400)
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return error_page("Clone timed out", "<p>The repository clone operation exceeded the time limit.</p><a href='/'>← Try Again</a>", 400)

    try:
        b2_store.put(scan_id, {
            "status": "scanning", "type": "url",
            "target": repo_name, "created_at": time.time(),
            "tmpdir": tmpdir,
        })
    except Exception:
        pass  # B2 may not be configured; scan proceeds without initial metadata

    asyncio.create_task(_run_scan_background(scan_id, clone_to, repo_name, api_key, provider))

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/progress/{scan_id}", status_code=303)


# ── Progress / Status endpoints ─────────────────────────────────────

PROGRESS_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scanning... - ZeroFlaw</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #020617; color: #e2e8f0; line-height: 1.6; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
  .card { background: #0F172A; border: 1px solid rgba(255,255,255,0.05); border-radius: 16px; padding: 32px; max-width: 560px; width: 100%; text-align: center; }
  .spinner { width: 36px; height: 36px; border: 3px solid rgba(34,211,238,0.15); border-top-color: #22d4ee; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 { font-size: 20px; color: #f1f5f9; margin-bottom: 4px; }
  .sub { color: #64748b; font-size: 13px; margin-bottom: 16px; }
  .terminal { text-align: left; font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; font-size: 12px; background: #020617; border-radius: 10px; padding: 16px; max-height: 300px; overflow-y: auto; margin-top: 8px; }
  .status-line { margin: 4px 0; display: flex; align-items: center; gap: 8px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; display: inline-block; }
  .dot.ok { background: #22c55e; box-shadow: 0 0 6px rgba(34,197,94,0.5); }
  .dot.warn { background: #eab308; box-shadow: 0 0 6px rgba(234,179,8,0.5); }
  .dot.err { background: #ef4444; box-shadow: 0 0 6px rgba(239,68,68,0.5); }
  .dot.busy { background: #22d4ee; box-shadow: 0 0 6px rgba(34,211,238,0.5); animation: pulse 0.8s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  .err { color: #ef4444; }
  .done { color: #22c55e; }
  a { color: #22d4ee; text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
<script>
var scanId = '{scan_id}';
function esc(s) { return (s||'').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function renderSteps(steps) {
  var html = '<p class="status-line" style="color:#64748b;">$ zeroflaw scan</p>';
  for (var i = 0; i < steps.length; i++) {
    var s = steps[i];
    if (s.type === 'prompt') {
      html += '<p class="status-line" style="color:#64748b;">' + esc(s.text) + '</p>';
    } else if (s.type === 'running') {
      html += '<p class="status-line"><span class="dot busy"></span> ' + esc(s.text) + '</p>';
    } else if (s.type === 'ok') {
      html += '<p class="status-line" style="color:#22c55e;"><span class="dot ok"></span> ' + esc(s.text) + '</p>';
    } else if (s.type === 'warn') {
      html += '<p class="status-line" style="color:#eab308;"><span class="dot warn"></span> ' + esc(s.text) + '</p>';
    } else if (s.type === 'error') {
      html += '<p class="status-line" style="color:#ef4444;"><span class="dot err"></span> ' + esc(s.text) + '</p>';
    } else if (s.type === 'fix') {
      html += '<p class="status-line" style="color:#22d4ee;"><span class="dot" style="background:#22d4ee;box-shadow:0 0 6px rgba(34,211,238,0.5);"></span> \U0001F527 ' + esc(s.text) + '</p>';
    } else if (s.type === 'done') {
      html += '<p class="status-line done">✓ Scan complete!</p>';
    }
  }
  return html;
}
function poll() {
  fetch('/scan/status/' + scanId)
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.status === 'done') {
        if (data.report_url) { window.location.href = data.report_url; return; }
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('terminal').innerHTML = '<p class="done">✓ Scan complete! <a href="/">← Home</a></p>';
        return;
      }
      if (data.status === 'error') {
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('terminal').innerHTML = '<p class="err">Scan failed: ' + esc(data.error || 'unknown error') + '</p><p style="margin-top:12px;"><a href="/">← Try Again</a></p>';
        return;
      }
      if (data.status === 'not_found') {
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('terminal').innerHTML = '<p class="err">Scan session expired or not found.</p><p style="margin-top:12px;"><a href="/">← Try Again</a></p>';
        return;
      }
      if (data.steps) {
        document.getElementById('terminal').innerHTML = renderSteps(data.steps);
        document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;
      }
      setTimeout(poll, 2000);
    })
    .catch(function() { setTimeout(poll, 3000); });
}
poll();
</script>
</head>
<body>
<div class="card">
  <div class="spinner" id="spinner"></div>
  <h1>Scanning <span id="target">{target}</span></h1>
  <p class="sub">Running security scanners. This may take a minute.</p>
  <div class="terminal" id="terminal"><p class="status-line" style="color:#64748b;">$ zeroflaw scan</p></div>
</div>
</body>
</html>"""


@app.get("/progress/{scan_id}", response_class=HTMLResponse)
async def scan_progress(scan_id: str):
    """Show auto-refreshing progress page, redirect to report when done."""
    entry = b2_store.get(scan_id)
    if not entry:
        return error_page("Scan not found", "<p>No scan was found with this ID. It may have expired.</p><a href='/'>← Home</a>", 404)
    status = entry["status"]
    steps = entry.get("steps", [])
    if status == "scanning" and any(s.get("type") == "done" for s in steps):
        status = "done"
    if status == "done":
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"/download/{scan_id}", status_code=302)
    if status == "done_fix":
        fix_html = b2_store.get_text(f"reports/{scan_id}-fix-result.html")
        if fix_html:
            return HTMLResponse(content=fix_html)
        return HTMLResponse(f"<html><body style='background:#020617;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif'><div style='text-align:center'><h2 style='color:#22d4ee'>✓ {entry.get('fix_count', 0)} Fix(es) Applied</h2><a href='/download/{scan_id}?format=zip' style='color:#22d4ee'>Download Fixed Source</a></div></body></html>")
    if status == "error":
        err = entry.get("error", "Unknown error")
        return error_page("Scan failed", f"<p>{err}</p><a href='/'>← Try Again</a>", 500)

    if status == "fixing":
        fix_page = PROGRESS_PAGE.replace("{scan_id}", scan_id).replace("{target}", "Fixing " + entry.get("target", "project"))
        fix_page = fix_page.replace("$ zeroflaw scan", "🔧 Applying fixes...")
        fix_page = fix_page.replace("Running security scanners", "Running auto-fix on project")
        return HTMLResponse(content=fix_page)

    page = PROGRESS_PAGE.replace("{scan_id}", scan_id).replace("{target}", entry.get("target", "project"))
    return HTMLResponse(content=page)


@app.get("/scan/status/{scan_id}")
async def scan_status(scan_id: str):
    """JSON endpoint for progress page polling."""
    entry = b2_store.get(scan_id)
    if not entry:
        return JSONResponse({"status": "not_found"})
    status = entry["status"]
    steps = entry.get("steps", [])
    has_done_step = any(s.get("type") == "done" for s in steps)
    if status == "scanning" and has_done_step:
        status = "done"
    resp = {"status": status, "target": entry.get("target", "")}
    if status == "done":
        resp["report_url"] = f"/download/{scan_id}"
    if status == "done_fix":
        resp["report_url"] = f"/progress/{scan_id}"
    if status == "error":
        resp["error"] = entry.get("error", "Unknown error")
    if steps:
        resp["steps"] = steps
    return JSONResponse(resp)


@app.post("/scan/json", response_class=JSONResponse)
async def scan_json(file: UploadFile = File(...)):
    """API endpoint — returns JSON results instead of HTML."""
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "project.zip")
        with open(zip_path, "wb") as f:
            content = await file.read()
            f.write(content)
        extract_to = os.path.join(tmpdir, "project")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_to)
        results = run_scans_sync(extract_to)
    return results


@app.get("/fix/run/{scan_id}")
async def fix_run(scan_id: str):
    """Run auto-fix on an already-scanned project and upload fixed zip to B2."""
    entry = b2_store.get(scan_id)
    if not entry:
        return error_page("Scan not found", "<p>No scan was found with this ID. It may have expired.</p><a href='/'>← Home</a>", 404)

    existing = b2_store.get_file(f"reports/{scan_id}-fixed.zip")
    if existing:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"/download/{scan_id}?format=zip", status_code=302)

    b2_store.put(scan_id, {"status": "fixing", "target": entry.get("target", "project"), "steps": [{"type": "running", "text": "Applying fixes..."}], "created_at": time.time()})
    asyncio.create_task(_run_fix_background(scan_id, entry))
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/progress/{scan_id}", status_code=303)

    fix_rows = ""
    for c in changes:
        fix_rows += f"""<tr>
          <td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px;color:#22d4ee;">🔧</td>
          <td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:13px;">{c['file']}:{c['line']}</td>
          <td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px;color:#94a3b8;">{c['issue'][:80]}</td>
          <td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:12px;color:#3fb950;">{c['fix']}</td>
        </tr>"""

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Fixes Applied — ZeroFlaw</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#020617;color:#e2e8f0;line-height:1.6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
  .card{{background:#0F172A;border:1px solid rgba(255,255,255,0.05);border-radius:16px;padding:32px;max-width:640px;width:100%}}
  h2{{color:#22d4ee;font-size:20px;margin-bottom:4px;display:flex;align-items:center;gap:8px}}
  .subtitle{{color:#64748b;font-size:13px;margin-bottom:20px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:20px}}
  th{{text-align:left;color:#64748b;font-size:11px;padding:4px 8px;border-bottom:1px solid rgba(255,255,255,0.1);text-transform:uppercase;letter-spacing:1px}}
  .btn{{display:inline-block;padding:12px 24px;background:#22d4ee;color:#020617;border-radius:10px;text-decoration:none;font-size:14px;font-weight:600;margin-right:8px}}
  .btn:hover{{background:#1bb3cc}}
  .btn-sec{{display:inline-block;padding:12px 24px;background:rgba(255,255,255,0.05);color:#e2e8f0;border:1px solid rgba(255,255,255,0.08);border-radius:10px;text-decoration:none;font-size:14px}}
  .btn-sec:hover{{background:rgba(255,255,255,0.08)}}
</style></head><body><div class="card">
  <h2>🛠 Fixes Applied ({len(changes)})</h2>
  <p class="subtitle">The following changes were made to your project:</p>
  <table>
    <tr><th></th><th>Location</th><th>Issue</th><th>Fix</th></tr>
    {fix_rows}
  </table>
  <div>
    <a href="/download/{scan_id}?format=zip" class="btn" download>⬇ Download Fixed Source (.zip)</a>
    <a href="/download/{scan_id}" class="btn-sec">← Back to Report</a>
  </div>
</div></body></html>""", status_code=200)


# ── Sync scan helpers (for MCP tools) ────────────────────────────────

def run_scans_sync(project_path: str) -> dict:
    """Run all scans in parallel. Returns results dict."""
    from server import (
        run_security_scan, run_code_linting, run_universal_security_scan,
        scan_npm_dependencies, scan_python_dependencies,
    )
    results = {"scans": {}}
    from concurrent.futures import ThreadPoolExecutor, wait as _wait
    # Only run Python scanners if .py files exist
    _has_py = any(f.endswith(".py") for _, _, fs in os.walk(project_path) for f in fs
                  if not any(d in _ for d in (".venv", "venv", "node_modules", ".git", "__pycache__")))
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {}
        if _has_py:
            futures[pool.submit(run_security_scan, project_path)] = "bandit"
            futures[pool.submit(run_code_linting, project_path)] = "ruff"
        futures[pool.submit(run_universal_security_scan, project_path)] = "semgrep"
        futures[pool.submit(run_trivy_safe, project_path)] = "trivy"
        if os.path.isfile(os.path.join(project_path, "package.json")):
            futures[pool.submit(scan_npm_dependencies, project_path)] = "npm_audit"
        if os.path.isfile(os.path.join(project_path, "requirements.txt")):
            futures[pool.submit(scan_python_dependencies, project_path)] = "pip_audit"
        done, not_done = _wait(futures, timeout=60)
        for future in not_done:
            future.cancel()
        for future in done:
            key = futures[future]
            try:
                results["scans"][key] = future.result()
            except Exception as e:
                results["scans"][key] = {"error": str(e)}
    return results


def format_results_markdown(target_name: str, results: dict) -> str:
    """Format scan results as concise markdown."""
    scans = results.get("scans", {})
    lines = [f"# ZeroFlaw Scan: {target_name}", ""]
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for scan_name, data in scans.items():
        if not isinstance(data, dict):
            continue
        if "error" in data:
            lines.append(f"## {scan_name}\n{data['error']}\n")
            continue
        findings = data.get("results", [])
        if not findings:
            continue
        lines.append(f"## {scan_name} ({len(findings)} findings)")
        for f in findings[:15]:
            sev = (f.get("issue_severity") or "LOW").upper()
            if sev in sev_counts:
                sev_counts[sev] += 1
            fp = f.get("filename", "?")
            ln = f.get("line_number", "")
            msg = f.get("issue_text", "")[:120]
            icon = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
            lines.append(f"- {icon} [{sev}] `{fp}:{ln}` — {msg}")
        if len(findings) > 15:
            lines.append(f"  ...+{len(findings)-15} more")
        lines.append("")
    total = sum(sev_counts.values())
    lines.append(f"---\n**{total} total:** 💀 {sev_counts['CRITICAL']} · 🔴 {sev_counts['HIGH']} · 🟡 {sev_counts['MEDIUM']} · 🔵 {sev_counts['LOW']}")
    return "\n".join(lines)


# ── MCP Server (served from same app to avoid Cloudflare 421) ─────────
from mcp.server.fastmcp import FastMCP as _FastMCP  # noqa: E402
_mcp = _FastMCP("ZeroFlaw Security Scanner")

from mcp_server import register_tools as _reg_mcp  # noqa: E402
_reg_mcp(_mcp)

import starlette.middleware.cors as _cors  # noqa: E402
import starlette.middleware.trustedhost as _th  # noqa: E402
_mcp_app = _mcp.sse_app()
_mcp_app.add_middleware(_cors.CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
_mcp_app.add_middleware(_th.TrustedHostMiddleware, allowed_hosts=["*"])
app.mount("/mcp", _mcp_app)


@app.get("/download/{report_id}")
async def download_report(report_id: str, format: str = "html"):
    """Serve a saved report from B2. Supports html, pdf, and zip formats."""
    entry = b2_store.get(report_id)
    if format == "pdf":
        pdf_data = b2_store.get_file(f"reports/{report_id}.pdf")
        if pdf_data:
            target_name = (entry.get("target", "project") if entry else "project").replace(".zip", "")
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in target_name)
            from fastapi.responses import StreamingResponse
            return StreamingResponse(
                io.BytesIO(pdf_data),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{safe_name}-report.pdf"'},
            )
    if format == "zip":
        zip_data = b2_store.get_file(f"reports/{report_id}-fixed.zip")
        if zip_data:
            target_name = (entry.get("target", "project") if entry else "project").replace(".zip", "")
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in target_name)
            from fastapi.responses import StreamingResponse
            return StreamingResponse(
                io.BytesIO(zip_data),
                media_type="application/zip",
                headers={"Content-Disposition": f'attachment; filename="{safe_name}-fixed.zip"'},
            )
    download_html = b2_store.get_text(f"reports/{report_id}-download.html")
    if download_html:
        return HTMLResponse(content=download_html)
    view_html = b2_store.get_text(f"reports/{report_id}.html")
    if view_html:
        return HTMLResponse(content=view_html)
    if entry:
        for step in entry.get("steps", []):
            if step.get("type") == "done" and step.get("results"):
                report = generate_html_report(entry.get("target", "project"), step["results"])
                btns = f'<div class="meta-row"><a href="/download/{report_id}?format=html" class="download-btn" download>⬇ Download HTML</a><a href="/download/{report_id}?format=pdf" class="download-btn pdf" download>📄 Download PDF</a><a href="/fix/run/{report_id}" class="download-btn" style="background:rgba(34,211,238,0.15);border:1px solid rgba(34,211,238,0.3);">🔧 Fix &amp; Download</a>'
                report = report.replace('<div class="meta-row">', btns, 1)
                return HTMLResponse(content=report)
    return error_page("Report not found", "<p>This report has expired or doesn't exist.</p><a href='/'>← Home</a>", 404)


@app.get("/health")
async def health():
    """Health check for Render."""
    return {"status": "ok", "scanners": {
        "bandit": bool(shutil.which("bandit")),
        "ruff": bool(shutil.which("ruff")),
        "semgrep": bool(shutil.which("semgrep")),
        "trivy": bool(shutil.which("trivy")),
        "npm": bool(shutil.which("npm")),
        "pip": bool(shutil.which("pip")),
    }}


# ── Main ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8555))
    uvicorn.run("app:app", host=os.environ.get("HOST", "0.0.0.0"), port=port)
