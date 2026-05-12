#!/mnt/c/gemini/code-security-server/.venv_wsl/bin/python3
"""
zeroflaw — Console-based security scanner.

Usage:
    zeroflaw scan <path>              Run all security scans on directory/file
    zeroflaw scan <path> --bandit     Run only Bandit (Python security)
    zeroflaw scan <path> --ruff       Run only Ruff (Python linting)
    zeroflaw scan <path> --semgrep    Run only Semgrep (multi-language)
    zeroflaw scan <path> --npm        Run only npm audit
    zeroflaw scan <path> --pip        Run only pip audit
    zeroflaw scan <path> --owasp      Run only OWASP Dependency-Check
    zeroflaw scan <path> --quick      Skip Semgrep and OWASP (faster)
    zeroflaw fix <path> --scan        Scan and auto-fix issues
    zeroflaw fix <path> --results <file>  Apply fixes from saved results
    zeroflaw --help                   Show this help
"""

import argparse
import json
import os
import sys
import textwrap
from datetime import datetime
from pathlib import Path
try:
    import auto_fix
except ModuleNotFoundError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    import auto_fix

# ── ANSI colors ──────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    @staticmethod
    def bold(s):      return f"{C.BOLD}{s}{C.RESET}"
    @staticmethod
    def red(s):       return f"{C.RED}{s}{C.RESET}"
    @staticmethod
    def green(s):     return f"{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def yellow(s):    return f"{C.YELLOW}{s}{C.RESET}"
    @staticmethod
    def blue(s):      return f"{C.BLUE}{s}{C.RESET}"
    @staticmethod
    def magenta(s):   return f"{C.MAGENTA}{s}{C.RESET}"
    @staticmethod
    def cyan(s):      return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def gray(s):      return f"{C.GRAY}{s}{C.RESET}"
    @staticmethod
    def white(s):     return f"{C.WHITE}{s}{C.RESET}"
    @staticmethod
    def dim(s):       return f"{C.DIM}{s}{C.RESET}"


# ── Import scans from server ─────────────────────────────────────────────
SERVER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SERVER_DIR))

from server import (  # noqa: E402
    run_security_scan,
    run_code_linting,
    run_universal_security_scan,
    scan_npm_dependencies,
    scan_python_dependencies,
    run_owasp_dependency_check,
)


# ── Display helpers ──────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "HIGH":   C.red,
    "MEDIUM": C.yellow,
    "LOW":    C.blue,
    "CRITICAL": C.magenta,
    "ERROR":  C.red,
    "WARNING": C.yellow,
    "INFO":   C.cyan,
    "UNDEFINED": C.gray,
}

SEVERITY_ICONS = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "ERROR":    "✗",
    "WARNING":  "⚠",
    "INFO":     "ℹ",
}


def severity_key(s):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "WARNING": 4, "INFO": 5, "UNDEFINED": 6, "ERROR": 7}
    return order.get(s.upper(), 99)


def print_header(text):
    width = 72
    pad = max(0, width - len(text) - 2)
    left = pad // 2
    right = pad - left
    print()
    print(C.bold(C.cyan("╭" + "─" * width + "╮")))
    print(C.bold(C.cyan("│")), " " * left + C.bold(text) + " " * right, C.bold(C.cyan("│")))
    print(C.bold(C.cyan("╰" + "─" * width + "╯")))
    print()


def print_scan_header(name, icon=""):
    print()
    print(f"  {C.bold(C.cyan(icon + ' ' + name))}")
    print(f"  {C.gray('─' * 70)}")


def print_finding(filepath, line, severity, message, code=""):
    sev_fn = SEVERITY_COLORS.get(severity.upper(), C.white)
    icon = SEVERITY_ICONS.get(severity.upper(), " ")
    sev_tag = sev_fn(f" [{severity.upper():>8}] ")
    loc = f"{C.dim(filepath)}{C.dim(':')}{C.yellow(str(line))}" if line else C.dim(filepath)
    print(f"    {icon} {sev_tag} {loc}")
    print(f"          {C.white(message)}")
    if code:
        for cl in code.split("\n"):
            print(f"          {C.dim('│')} {C.gray(cl)}")


def print_finding_from_bandit(item):
    fpath = item.get("filename", "?")
    line = item.get("line_number", item.get("line", ""))
    sev = item.get("issue_severity", item.get("severity", "UNDEFINED"))
    msg = item.get("issue_text", item.get("text", ""))
    code = item.get("code", "")
    if isinstance(code, (list, str)):
        code = "\n".join(code) if isinstance(code, list) else code
    print_finding(fpath, line, sev, msg, code)


def print_finding_from_ruff(item):
    fpath = item.get("filename", "?")
    line = item.get("location", {}).get("row", item.get("line", ""))
    sev = item.get("level", "WARNING").upper() if item.get("level") else "WARNING"
    code_str = item.get("code", "")
    msg = item.get("message", "")
    print_finding(fpath, line, sev, f"[{code_str}] {msg}")


def print_finding_from_semgrep(item):
    path_item = item.get("path", "")
    if isinstance(path_item, dict):
        fpath = path_item.get("value", "?")
    else:
        fpath = path_item
    start = item.get("start", {})
    if isinstance(start, dict):
        line = start.get("line", "")
    else:
        line = start
    sev = item.get("extra", {}).get("severity", "UNDEFINED")
    msg = item.get("extra", {}).get("message", item.get("message", ""))
    check_id = item.get("check_id", "")
    code_lines = item.get("extra", {}).get("lines", "")
    print_finding(fpath, line, sev, msg if msg else f"Rule: {check_id}", code_lines)


def print_summary_table(results, scan_name):
    """Print findings grouped by severity with counts."""
    sev_counts = {}
    for r in results:
        sev = r.get("severity", r.get("issue_severity", r.get("level", "UNDEFINED"))).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    total = sum(sev_counts.values())
    if total == 0:
        print(f"  {C.green('✓ No issues found.')}")
        return

    print(f"\n  {C.bold('Summary:')} {C.bold(C.white(str(total)))} {C.gray('finding(s)')}")
    for sev in sorted(sev_counts.keys(), key=severity_key):
        fn = SEVERITY_COLORS.get(sev, C.white)
        bar_len = int((sev_counts[sev] / total) * 30) if total > 0 else 0
        bar = "█" * bar_len
        print(f"    {fn(sev.upper()+':')} {C.bold(str(sev_counts[sev])):>4}  {fn(bar)}")
    print()


def print_dependency_vulns(vulns, source):
    print_scan_header(f"Dependency Vulnerabilities ({source})")
    if not vulns:
        print(f"  {C.green('✓ No vulnerabilities found.')}")
        return
    print_summary_table(vulns, source)
    for v in vulns:
        sev = (v.get("severity", "UNDEFINED") or "UNDEFINED").upper()
        pkg = v.get("package_name", v.get("name", "?"))
        desc = v.get("description", v.get("advisory", v.get("title", "")))
        fixed = v.get("fixed_version", v.get("patched_versions", ""))
        print_finding(pkg, "", sev, desc)
        if fixed:
            print(f"          {C.green(f'  ✓ Fixed in: {fixed}')}")



def run_trivy(project_path):
    """Run Trivy filesystem scan for dependency vulnerabilities."""
    import subprocess
    import shutil
    trivy_path = shutil.which("trivy") or shutil.which("trivy.exe")
    if not trivy_path:
        return {"error": "Trivy not found. Install: winget install aquasecurity.Trivy or brew install trivy"}
    try:
        result = subprocess.run(
            [trivy_path, "fs", "--format", "json", "--quiet", project_path],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0 and result.returncode != 1:
            return {"error": f"Trivy failed: {result.stderr[:200]}"}
        import json as _j
        data = _j.loads(result.stdout) if result.stdout.strip() else {"Results": []}
        return data
    except FileNotFoundError:
        return {"error": "Trivy not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"error": "Trivy timed out after 120s"}
    except Exception as e:
        return {"error": f"Trivy error: {str(e)}"}


def print_trivy_results(result):
    """Print Trivy scan results."""
    print_scan_header("Trivy (Dependency Vulnerabilities)")
    if "error" in result:
        print(f"  {C.yellow(chr(9888) + ' ' + result[chr(101)+chr(114)+chr(114)+chr(111)+chr(114)])}")
        return
    results_list = result.get("Results", [])
    total = 0
    all_vulns = []
    for r in results_list:
        target = r.get("Target", "?")
        vulns = r.get("Vulnerabilities", [])
        for v in vulns:
            total += 1
            sev = v.get("Severity", "UNKNOWN").upper()
            pkg = v.get("PkgName", v.get("Package", "?"))
            inst = v.get("InstalledVersion", "")
            fixed = v.get("FixedVersion", "")
            title = v.get("Title", "")
            cve = v.get("VulnerabilityID", v.get("CVE", ""))
            all_vulns.append({
                "target": target, "package": pkg, "severity": sev,
                "installed": inst, "fixed": fixed,
                "title": title, "cve": cve,
            })
    if total == 0:
        print(f"  {C.green(chr(10003) + ' No vulnerabilities found.')}")
        return
    # Severity counts
    sev_counts = {}
    for v in all_vulns:
        sev_counts[v["severity"]] = sev_counts.get(v["severity"], 0) + 1
    print(f"  {C.bold(str(total))} {C.gray('vulnerabilit(ies)')}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        c = sev_counts.get(sev, 0)
        if c > 0:
            fn = SEVERITY_COLORS.get(sev, C.white)
            print(f"    {fn(sev + ':')} {C.bold(str(c))}")
    print()
    for v in all_vulns:
        fn = SEVERITY_COLORS.get(v["severity"], C.white)
        icon = SEVERITY_ICONS.get(v["severity"], " ")
        sev = v["severity"]
        fixed = v["fixed"]
        title = v.get("title", "")
        cve = v.get(chr(99) + chr(118) + chr(101), title)
        print(f"    {icon} {fn(f'[{sev:>8}]')}  {C.white(cve)}")
        print(f"          {C.dim(v['package'])} {C.gray(v['installed'])} {C.green('-> ' + fixed if v['fixed'] else '')}")
        print(f"          {C.dim(v['target'])}")
        if v["title"]:
            print(f"          {C.gray(v['title'][:120])}")
        print()


def _md_to_html(md_text, target, timestamp):
    """Convert simple markdown to styled HTML page (no external deps)."""
    import html as _html
    text = md_text

    # Escape HTML entities first, then apply markdown formatting
    # Split into blocks and process
    lines = text.split("\n")
    html_lines = []
    in_code_block = False
    code_buffer = []
    in_table = False
    table_buffer = []

    for line in lines:
        # Code blocks
        if line.startswith("```"):
            if in_code_block:
                html_lines.append(f'<pre><code>{_html.escape(chr(10).join(code_buffer))}</code></pre>')
                code_buffer = []
                in_code_block = False
            else:
                in_code_block = True
            continue
        if in_code_block:
            code_buffer.append(line)
            continue

        # Horizontal rule
        if line.strip() in ("---", "***", "___"):
            html_lines.append("<hr>")
            continue

        # Empty line
        if not line.strip():
            if in_table and table_buffer:
                html_lines.append(_render_table(table_buffer))
                table_buffer = []
                in_table = False
            html_lines.append("")
            continue

        # Table detection
        if "|" in line and line.count("|") >= 3:
            table_buffer.append(line)
            in_table = True
            continue
        else:
            if in_table and table_buffer:
                html_lines.append(_render_table(table_buffer))
                table_buffer = []
                in_table = False

        # Headers
        if line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("#### "):
            html_lines.append(f"<h4>{line[5:]}</h4>")
        elif line.startswith("##### "):
            html_lines.append(f"<h5>{line[6:]}</h5>")
        elif line.startswith("###### "):
            html_lines.append(f"<h6>{line[7:]}</h6>")
        # Unordered list
        elif line.strip().startswith("- ") or line.strip().startswith("* "):
            content = _inline_md(line.strip()[2:])
            html_lines.append(f"<li>{content}</li>")
        # Ordered list
        elif line.strip() and line.strip()[0].isdigit() and ". " in line.strip()[:4]:
            content = _inline_md(line.strip().split(". ", 1)[1])
            html_lines.append(f"<li>{content}</li>")
        # Bold lead text (like "**Key:** value")
        elif "**" in line:
            html_lines.append(f"<p>{_inline_md(line)}</p>")
        # Regular paragraph
        elif line.strip():
            html_lines.append(f"<p>{_inline_md(line.strip())}</p>")
        else:
            html_lines.append(line)

    # Flush remaining table
    if in_table and table_buffer:
        html_lines.append(_render_table(table_buffer))

    body = chr(10).join(html_lines)

    sev_color = "green" if "GREEN" in text else ("orange" if "YELLOW" in text else "#e74c3c")

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZeroFlaw Security Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 40px 20px; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  .header {{ background: linear-gradient(135deg, #161b22, #0d1117); border: 1px solid #30363d; border-radius: 12px; padding: 30px; margin-bottom: 24px; text-align: center; }}
  .header h1 {{ color: #58a6ff; font-size: 28px; margin-bottom: 8px; }}
  .header .meta {{ color: #8b949e; font-size: 14px; }}
  .header .score {{ display: inline-block; margin-top: 12px; padding: 6px 20px; border-radius: 20px; font-weight: 600; font-size: 16px; background: {sev_color}; color: #fff; }}
  h1 {{ color: #58a6ff; font-size: 24px; margin: 24px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #21262d; }}
  h2 {{ color: #79c0ff; font-size: 20px; margin: 20px 0 10px; }}
  h3 {{ color: #a5d6ff; font-size: 16px; margin: 16px 0 8px; }}
  p {{ margin: 8px 0; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  ul, ol {{ margin: 8px 0 8px 24px; }}
  li {{ margin: 4px 0; }}
  pre {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; overflow-x: auto; font-size: 13px; margin: 12px 0; }}
  code {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
  pre code {{ background: none; padding: 0; }}
  hr {{ border: none; border-top: 1px solid #21262d; margin: 24px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 14px; }}
  th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
  th {{ background: #161b22; color: #58a6ff; font-weight: 600; }}
  tr:nth-child(even) {{ background: #161b22; }}
  .footer {{ text-align: center; color: #484f58; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #21262d; }}
  .severity-critical {{ color: #ff7b72; font-weight: 600; }}
  .severity-high {{ color: #d29922; font-weight: 600; }}
  .severity-medium {{ color: #d29922; }}
  .severity-low {{ color: #58a6ff; }}
  blockquote {{ border-left: 4px solid #30363d; padding: 8px 16px; margin: 12px 0; color: #8b949e; background: #161b22; border-radius: 0 8px 8px 0; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
  <h1>🔍 ZeroFlaw Security Report</h1>
  <div class="meta"><strong>Target:</strong> {_html.escape(target)} &nbsp;|&nbsp; <strong>Date:</strong> {_html.escape(timestamp)}</div>
  <div class="meta" style="margin-top:4px"><strong>Generator:</strong> DeepSeek AI</div>
</div>
{body}
<div class="footer">
  Report auto-generated by ZeroFlaw Security Scanner
</div>
</div>
</body>
</html>'''


def _inline_md(text):
    """Process inline markdown formatting."""
    import html as _h
    text = _h.escape(text)
    # Bold (**text**)
    import re as _re
    text = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # Italic (*text*)
    text = _re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    # Inline code (`code`)
    text = _re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    return text


def _render_table(rows):
    """Convert markdown table rows to HTML."""
    if len(rows) < 2:
        return ""
    # Skip separator row (---|---)
    data_rows = [rows[0]]
    for r in rows[1:]:
        if r.strip().replace("|", "").replace("-", "").replace(":", "").strip() == "":
            continue
        data_rows.append(r)

    html = "<table>"
    for i, row in enumerate(data_rows):
        cells = [c.strip() for c in row.split("|") if c.strip()]
        tag = "th" if i == 0 else "td"
        html += "<tr>" + "".join(f"<{tag}>{_inline_md(c)}</{tag}>" for c in cells) + "</tr>"
    html += "</table>"
    return html

def generate_report(results):
    """Generate a comprehensive security report using DeepSeek API."""
    import urllib.request
    import urllib.error
    import ssl

    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        print(f"  {C.red('✗')} DEEPSEEK_API_KEY not set. Skipping report.")
        return

    target = results.get("target", "unknown")
    timestamp = results.get("time", "")

    # Build a compact summary of findings for the LLM
    summary_lines = [f"Security scan report for: {target}"]
    summary_lines.append(f"Scan time: {timestamp}")
    summary_lines.append("")
    
    scans = results.get("scans", {})
    for scan_name, scan_data in scans.items():
        summary_lines.append(f"=== {scan_name} ===")
        findings = scan_data.get("findings", [])
        if not findings:
            summary_lines.append("  No issues found.")
            continue
        summary_lines.append(f"  Total: {len(findings)} finding(s)")
        # Group by severity
        by_sev = {}
        for f in findings:
            sev = f.get("severity", "UNDEFINED").upper()
            by_sev.setdefault(sev, []).append(f)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARNING", "UNDEFINED"]:
            items = by_sev.get(sev, [])
            if items:
                summary_lines.append(f"  [{sev}] {len(items)} finding(s)")
                for item in items[:5]:  # Top 5 per severity
                    filepath = item.get("file", "")
                    line = item.get("line", "")
                    msg = item.get("message", "")[:100]
                    summary_lines.append(f"    {filepath}:{line} - {msg}")
        summary_lines.append("")

    prompt = textwrap.dedent(f"""\
        You are a senior security engineer. Analyze the following security scan results and generate a comprehensive report.

        RULES:
        - Be specific about which files have issues and what the fix should be
        - Distinguish real vulnerabilities from false positives
        - Rate the overall security posture: GREEN (good), YELLOW (moderate), RED (poor)
        - Give actionable remediation steps prioritized by severity
        - Output in markdown format

        SCAN RESULTS:
        {chr(10).join(summary_lines)}

        Generate a comprehensive markdown report with:
        1. Executive Summary (overall score, total findings by severity)
        2. Critical & High Findings (with file paths, descriptions, remediation)
        3. Medium & Low Findings (grouped by category)
        4. False Positive Analysis
        5. Dependency Vulnerabilities (if any)
        6. Action Items Priority List
        7. Recommendations
    """)

    print(f"  {C.cyan('⟳')} Generating report via DeepSeek API...")

    try:
        # Use urllib to call DeepSeek API (std lib, no requests needed)
        import json as _json
        ctx = ssl.create_default_context()
        
        payload = _json.dumps({
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are a senior security engineer writing a comprehensive scan report."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 4000,
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.deepseek.com/v1/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

        resp = urllib.request.urlopen(req, context=ctx, timeout=120)
        body = resp.read().decode("utf-8")
        data = _json.loads(body)
        report_text = data["choices"][0]["message"]["content"]

        # Save report
        report_path = os.path.join(os.path.dirname(results.get("_report_output", ".")), "zeroflaw-report.md")
        if not os.path.isabs(report_path):
            report_path = os.path.join(os.getcwd(), report_path)
        
        full_report = f"""# ZeroFlaw Security Report

**Target:** {target}
**Scan Date:** {timestamp}
**Generator:** DeepSeek AI

---

{report_text}

---

*Report auto-generated by ZeroFlaw Security Scanner*
"""
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(full_report)
        print(f"  {C.green('✓')} Report saved to: {report_path}")

        # Also generate HTML version
        html_path = report_path.replace(".md", ".html")
        html_content = _md_to_html(full_report, target, timestamp)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"  {C.green('✓')} HTML report saved to: {html_path}")
        print(f"  {C.dim('Open zeroflaw-report.html in any browser.')}")

    except urllib.error.HTTPError as e:
        print(f"  {C.red('✗')} DeepSeek API error: {e.code} - {e.read().decode()[:200]}")
    except Exception as e:
        print(f"  {C.red('✗')} Report generation failed: {e}")


def print_owasp_results(result):
    print_scan_header("OWASP Dependency-Check")
    if "error" in result:
        print(f"  {C.yellow('⚠ ' + result['error'])}")
        return

    deps = result.get("dependencies", [])
    vuln_count = 0
    vulns_info = []
    for dep in deps:
        for v in dep.get("vulnerabilities", []):
            vuln_count += 1
            sev = v.get("severity", "UNDEFINED").upper()
            name = v.get("name", "?")
            desc = v.get("description", "")[:120]
            cve = v.get("cve", "")
            cvss = v.get("cvssScore", "")
            pkg = dep.get("fileName", "?")
            vulns_info.append({
                "package": pkg,
                "cve": cve,
                "severity": sev,
                "cvss": cvss,
                "name": name,
                "description": desc,
            })

    if vuln_count == 0:
        print(f"  {C.green('✓ No vulnerabilities found.')}")
    else:
        print(f"  {C.bold(C.red(str(vuln_count)))} {C.gray('vulnerabilities across')} {C.bold(str(len(deps)))} {C.gray('dependencies')}")
        print()
        for v in vulns_info:
            fn = SEVERITY_COLORS.get(v["severity"], C.white)
            icon = SEVERITY_ICONS.get(v["severity"], " ")
            cvss_str = f" CVSS:{v['cvss']}" if v["cvss"] else ""
            sev_str = v["severity"]
            print(f"    {icon} {fn(f'[{sev_str:>8}]{cvss_str}')}  {C.white(v['name'])}")
            if v["cve"]:
                print(f"          {C.cyan(v['cve'])}")
            print(f"          {C.dim(v['package'])}")
            if v["description"]:
                print(f"          {C.gray(v['description'][:120])}")
            print()


def print_scan_result(name, icon, result, findings_extractor, finding_printer):
    print_scan_header(f"{icon} {name}")
    if "error" in result:
        print(f"  {C.red('✗ ' + result['error'])}")
        return

    results = findings_extractor(result) if findings_extractor else []
    if not results:
        print(f"  {C.green('✓ No issues found.')}")
        return

    print_summary_table(results, name)
    for r in results:
        finding_printer(r)


def extract_bandit_findings(result):
    return result.get("results", [])


def extract_ruff_findings(result):
    return result.get("results", [])


def extract_semgrep_findings(result):
    return result.get("results", [])


def extract_npm_vulns(result):
    if "error" in result:
        return []
    vulnerabilities = result.get("vulnerabilities", {})
    vulns = []
    for pkg_name, info in vulnerabilities.items():
        via = info.get("via", [])
        for v in via:
            if isinstance(v, dict):
                vulns.append({
                    "package_name": pkg_name,
                    "severity": v.get("severity", info.get("severity", "UNDEFINED")),
                    "title": v.get("title", ""),
                    "description": v.get("title", ""),
                    "vulnerable_versions": info.get("range", ""),
                    "fixed_version": ", ".join(info.get("fixAvailable", {})) if isinstance(info.get("fixAvailable"), dict) else str(info.get("fixAvailable", "")),
                })
    return vulns


def extract_pip_vulns(result):
    if "error" in result:
        return []
    vulns = []
    for v in result.get("vulnerabilities", []):
        vulns.append({
            "package_name": v.get("name", v.get("package", "?")),
            "severity": v.get("severity", v.get("advisory", {}).get("severity", "UNDEFINED")),
            "description": v.get("description", v.get("advisory", ""))[:200],
            "version": v.get("version", "?"),
            "fixed_version": v.get("fixed_version", ""),
        })
    return vulns


# ── Main scan ────────────────────────────────────────────────────────────

def run_scan(target_path, args):
    """Run selected scans and display results."""
    width = 72
    print()
    print(C.bold(C.cyan("╔" + "═" * width + "╗")))
    print(C.bold(C.cyan("║")), C.bold(C.white("  🔍 ZeroFlaw Security Scan")), " " * (width - 31), C.bold(C.cyan("║")))
    print(C.bold(C.cyan("║")), f"  {C.dim('Target:')} {C.bold(target_path)}", " " * max(0, width - len(target_path) - 13), C.bold(C.cyan("║")))
    print(C.bold(C.cyan("║")), f"  {C.dim('Time:')}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", " " * (width - 41), C.bold(C.cyan("║")))
    print(C.bold(C.cyan("╚" + "═" * width + "╝")))
    print()

    # Validate target exists
    if not os.path.exists(target_path):
        print(f"  {C.red('✗ Error:')} Path does not exist: {target_path}")
        sys.exit(1)

    # Collect all results for report generation
    all_results = {
        "target": os.path.abspath(target_path),
        "time": datetime.now().isoformat(),
        "scans": {},
        "summary": {
            "total_findings": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
    }

    scan_list = []

    if args.bandit or args.all:
        scan_list.append(("Bandit (Python Security)", "🐍", run_security_scan, extract_bandit_findings, print_finding_from_bandit))
    if args.ruff or args.all:
        scan_list.append(("Ruff (Python Linting)", "📐", run_code_linting, extract_ruff_findings, print_finding_from_ruff))
    if args.semgrep or args.all:
        scan_list.append(("Semgrep (Multi-Language SAST)", "🔬", run_universal_security_scan, extract_semgrep_findings, print_finding_from_semgrep))

    has_error = False
    for name, icon, scanner, extractor, printer in scan_list:
        scan_results_entry = {"findings": []}
        try:
            result = scanner(target_path)
            if "error" in result:
                print_scan_header(f"{icon} {name}")
                print(f"  {C.yellow('⚠ ' + result['error'])}")
                all_results["scans"][name] = {"error": result["error"]}
                continue
            print_scan_result(name, icon, result, extractor, printer)
            # Collect findings for report
            findings = extractor(result) if extractor else []
            for f in findings:
                filepath = f.get("filename", f.get("path", f.get("file", "")))
                if isinstance(filepath, dict):
                    filepath = filepath.get("value", str(filepath))
                line = f.get("line_number", f.get("location", {}).get("row", f.get("start", {}).get("line", "")))
                sev = f.get("issue_severity", f.get("severity", f.get("extra", {}).get("severity", f.get("level", "UNDEFINED"))))
                msg = f.get("issue_text", f.get("message", f.get("extra", {}).get("message", "")))
                scan_results_entry["findings"].append({
                    "file": str(filepath),
                    "line": str(line),
                    "severity": str(sev).upper(),
                    "message": str(msg)[:200],
                })
            all_results["scans"][name] = scan_results_entry
        except Exception as e:
            print_scan_header(f"{icon} {name}")
            print(f"  {C.red('✗ Error:')} {str(e)}")
            has_error = True
            all_results["scans"][name] = {"error": str(e)}

    # Dependency scans
    resolved = os.path.abspath(os.path.normpath(target_path))
    if os.path.isdir(resolved):
        has_package_json = os.path.isfile(os.path.join(resolved, "package.json"))
        has_requirements = os.path.isfile(os.path.join(resolved, "requirements.txt"))

        if (args.npm or args.all) and has_package_json:
            npm_result = scan_npm_dependencies(target_path)
            vulns = extract_npm_vulns(npm_result)
            print_dependency_vulns(vulns, "npm audit")
            all_results["scans"]["npm_audit"] = {"vulnerabilities": vulns}

        if (args.pip or args.all) and has_requirements:
            pip_result = scan_python_dependencies(target_path)
            vulns = extract_pip_vulns(pip_result)
            print_dependency_vulns(vulns, "pip audit")
            all_results["scans"]["pip_audit"] = {"dependencies": [{"name": v.get("package", ""), "vulns": [v]} for v in vulns] if vulns else []}

        if args.owasp or args.all:
            print(f"  {C.yellow('⟳')} OWASP Dependency-Check running... (first run downloads NVD database, may take 5-10 min)")
            import time as _time
            _time.sleep(0.5)
            owasp_result = run_owasp_dependency_check(target_path)
            print_owasp_results(owasp_result)

        # Trivy (cross-platform, fast, scans all deps)
        if args.trivy or args.all:
            trivy_result = run_trivy(resolved)
            print_trivy_results(trivy_result)
            all_results["scans"]["Trivy"] = trivy_result

    # Footer
    print()
    print(C.bold(C.cyan("╔" + "═" * width + "╗")))
    status = C.green("✓ Scan Complete") if not has_error else C.yellow("⚠ Scan Complete (with errors)")
    print(C.bold(C.cyan("║")), f"  {status}", " " * (width - 23), C.bold(C.cyan("║")))
    print(C.bold(C.cyan("╚" + "═" * width + "╝")))
    print()

    # Save results if --output specified
    if args.output:
        output_path = args.output
        if not os.path.isabs(output_path):
            output_path = os.path.join(os.getcwd(), output_path)
        try:
            with open(output_path, "w") as f:
                json.dump(all_results, f, indent=2, default=str)
            # Also save a copy for report generation
            all_results["_report_output"] = output_path
            print(f"  {C.green('✓')} Results saved to: {output_path}")
        except Exception as e:
            print(f"  {C.red('✗')} Failed to save results: {e}")

    # Generate report if --report specified
    if args.report:
        generate_report(all_results)

    return all_results


# ── CLI entry point ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="zeroflaw",
        description="ZeroFlaw — Console-based security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              zeroflaw scan ./myapp              Run all scans
              zeroflaw scan ./myapp --bandit     Bandit only
              zeroflaw scan ./myapp --quick      Skip Semgrep and OWASP
              zeroflaw --version                 Show version
        """),
    )
    parser.add_argument("--version", action="store_true", help="Show version")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scans on a target")
    scan_parser.add_argument("target", help="File or directory to scan")
    scan_parser.add_argument("--all", action="store_true", help="Run all scans (default)")
    scan_parser.add_argument("--bandit", action="store_true", help="Run Bandit only")
    scan_parser.add_argument("--ruff", action="store_true", help="Run Ruff only")
    scan_parser.add_argument("--semgrep", action="store_true", help="Run Semgrep only")
    scan_parser.add_argument("--npm", action="store_true", help="Run npm audit only")
    scan_parser.add_argument("--pip", action="store_true", help="Run pip audit only")
    scan_parser.add_argument("--owasp", action="store_true", help="Run OWASP Dependency-Check only (slow, Java)")
    scan_parser.add_argument("--quick", action="store_true", help="Skip Semgrep and OWASP (faster)")
    scan_parser.add_argument("--output", type=str, default="", help="Save results to JSON file for report generation")
    scan_parser.add_argument("--trivy", action="store_true", help="Run Trivy dependency scan (cross-platform, fast)")
    scan_parser.add_argument("--report", action="store_true", help="Generate comprehensive report (requires DEEPSEEK_API_KEY)")

    # fix command
    fix_parser = subparsers.add_parser("fix", help="Apply automated fixes to scanned project")
    fix_parser.add_argument("target", help="Directory containing scan results (or project to scan and fix)")
    fix_parser.add_argument("--results", type=str, default="", help="Path to results JSON (from scan --output)")
    fix_parser.add_argument("--scan", action="store_true", help="Run scan first before fixing")

    args = parser.parse_args()

    if args.version:
        print("zeroflaw v1.0.0")
        sys.exit(0)

    if args.command == "scan":
        # Check if any specific scanner was requested
        scanner_flags = [args.bandit, args.ruff, args.semgrep, args.npm, args.pip, args.owasp]
        has_scanner = any(scanner_flags)
        
        if has_scanner:
            # Specific scanner(s) requested
            if args.quick:
                args.semgrep = False
                args.owasp = False
                args.trivy = True
        elif args.quick:
            # --quick with no specific scanner: quick defaults
            args.all = False
            args.bandit = True
            args.ruff = True
            args.trivy = True
        else:
            # No specific flags: run all
            args.all = True

        run_scan(args.target, args)
    elif args.command == "fix":
        target = args.target
        results = None
        results_file = "zeroflaw_results_temp.json"

        if args.results:
            with open(args.results, "r") as f:
                results = json.load(f)
        elif args.scan:
            print(f"{C.yellow('→')} Running scan first...")
            scan_args = argparse.Namespace(
                target=target,
                all=False, bandit=True, ruff=True, semgrep=False,
                npm=False, pip=False, owasp=False, quick=False,
                trivy=True, output=results_file, report=False
            )
            run_scan(target, scan_args)
            with open(results_file, "r") as f:
                results = json.load(f)
            try:
                os.remove(results_file)
            except Exception:
                pass  # temp file cleanup is best-effort
        else:
            print(f"{C.red('✗')} No results provided. Use --results <file> or --scan")
            sys.exit(1)

        if results:
            print(f"\n{C.bold(C.yellow('→ Copying project to temp directory for safe fixing...'))}")
            import tempfile
            import shutil as _shutil
            tmpdir = tempfile.mkdtemp(prefix="zeroflaw_fix_")
            fixed_dir = os.path.join(tmpdir, os.path.basename(os.path.rstrip(os.sep)))
            if os.path.isdir(target):
                _shutil.copytree(target, fixed_dir, symlinks=False, ignore=lambda s, n: {d for d in n if d in (".venv", "venv", "node_modules", ".git", "__pycache__", "target", "build", "dist")})
            else:
                _shutil.copy2(target, tmpdir)
                fixed_dir = tmpdir
            print(f"{C.green('✓')} Copied to {tmpdir}")
            print(f"\n{C.bold(C.yellow('→ Started fixing the issues...'))}")
            changes = auto_fix.apply_fixes(fixed_dir, results)
            print(f"\n{C.bold(f'Applied {len(changes)} fix(es) in {tmpdir}:')}")
            for c in changes:
                print(f"  {C.cyan(c['file'])}:{c['line']} — {c['issue']}")
                print(f"    {C.green('→')} {c['fix']}")
            print(f"\n{C.green('✓')} Fixed files are in: {tmpdir}")
            print(f"{C.yellow('→')} To create a zip: cd {tmpdir} && zip -r ../zeroflaw-fixed.zip .")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
