import re
import os
import zipfile
from typing import List, Optional


def apply_fixes(source_dir: str, results: dict) -> list[dict]:
    """Apply automated fixes to source code based on scan findings.

    Processes findings in ascending line order per file so that
    line insertions from earlier fixes correctly shift later fix targets.
    """
    changes: list[dict] = []
    by_file: dict[str, list[dict]] = {}
    scans = results.get("scans", {})

    for scan_name, data in scans.items():
        if not isinstance(data, dict) or data.get("error"):
            continue
        for r in data.get("results", []):
            filepath = r.get("filename") or r.get("file") or ""
            lineno = r.get("line_number") or r.get("line") or 0
            if not filepath or not lineno:
                continue
            try:
                lineno = int(lineno)
            except (ValueError, TypeError):
                continue
            msg = r.get("issue_text") or r.get("message") or ""
            sev = (r.get("issue_severity") or "").upper()
            by_file.setdefault(filepath, []).append({
                "line": lineno, "msg": msg, "sev": sev, "scan": scan_name,
            })

    for filepath, findings in by_file.items():
        full_path = os.path.join(source_dir, filepath)
        if not os.path.isfile(full_path):
            continue
        findings.sort(key=lambda x: x["line"])
        line_bias = 0
        for f in findings:
            adj_line = f["line"] + line_bias
            line_bias += _fix_file(full_path, adj_line, f["scan"], f["msg"], changes, filepath)

    return changes


def _find_next_non_blank(lines: list[str], start: int) -> Optional[int]:
    """Find the next line index at or after `start` that is non-blank and not a comment-only line."""
    for i in range(start, len(lines)):
        stripped = lines[i].strip()
        if stripped and not stripped.startswith("#"):
            return i
    return None


def _fix_file(path: str, lineno: int, scan: str, msg: str, changes: list, filepath: str) -> int:
    """Try all fix patterns on a single line. Returns the line count delta (0 or positive)."""
    lines = _read_lines(path)
    if not lines or lineno < 1 or lineno > len(lines):
        return 0
    idx = lineno - 1
    line = lines[idx].rstrip()

    # Fix 1: bare `except: pass` on one line
    m = re.match(r"^(\s*)except\s*:\s*pass\s*$", line)
    if m:
        indent = m.group(1)
        lines[idx] = f"{indent}except Exception:\n"
        lines.insert(idx + 1, f"{indent}    pass  # TODO: handle error appropriately\n")
        _write_lines(path, lines)
        changes.append({"file": filepath, "line": lineno, "issue": msg, "fix": "Replaced bare except:pass with specific exception handling"})
        return 1  # inserted 1 line

    # Fix 2: bare `except:` followed by `pass` (skips blank and comment-only lines)
    bare_except = re.match(r"^(\s*)except\s*:\s*$", line)
    if bare_except:
        next_idx = _find_next_non_blank(lines, idx + 1)
        if next_idx is not None:
            next_line = lines[next_idx].rstrip()
            if re.match(r"^\s*pass\s*$", next_line):
                indent = bare_except.group(1)
                lines[idx] = f"{indent}except Exception:\n"
                _write_lines(path, lines)
                changes.append({"file": filepath, "line": lineno, "issue": msg, "fix": "Replaced bare except: with except Exception:"})
                return 0

    # Fix 3: assert statement (condition only, excluding optional error message)
    m = re.match(r"^(\s*)assert\s+(.+?)(?:\s*,\s*.*)?$", line)
    if m:
        indent = m.group(1)
        condition = m.group(2).strip()
        sanitized = condition.replace('"', "'")
        lines[idx] = f"{indent}if not ({condition}):\n"
        lines.insert(idx + 1, f'{indent}    raise ValueError("Validation failed: {sanitized}")\n')
        _write_lines(path, lines)
        changes.append({"file": filepath, "line": lineno, "issue": msg, "fix": "Replaced assert with proper validation"})
        return 1  # inserted 1 line

    # Fix 4: `except Exception: pass` on one line (silent exception swallowing)
    m = re.match(r"^(\s*)except\s+Exception\s*:\s*pass\s*$", line)
    if m:
        indent = m.group(1)
        lines[idx] = f"{indent}except Exception:\n"
        lines.insert(idx + 1, f"{indent}    pass  # TODO: handle or log the exception\n")
        _write_lines(path, lines)
        changes.append({"file": filepath, "line": lineno, "issue": msg, "fix": "Added TODO to silent except Exception: pass"})
        return 1

    # Fix 5: `except Exception:` followed by `pass` (skips blank and comment-only lines)
    except_exc = re.match(r"^(\s*)except\s+Exception\s*:\s*$", line)
    if except_exc:
        next_idx = _find_next_non_blank(lines, idx + 1)
        if next_idx is not None:
            next_line = lines[next_idx].rstrip()
            if re.match(r"^\s*pass\s*$", next_line):
                indent = except_exc.group(1)
                lines[next_idx] = f"{indent}    pass  # TODO: handle or log the exception\n"
                _write_lines(path, lines)
                changes.append({"file": filepath, "line": lineno, "issue": msg, "fix": "Added TODO to silent except Exception: pass"})
                return 0

    # Fix 6: hardcoded password assignment — replace with env var
    m = re.match(r"^((\s*)(\w+)\s*=\s*['\"])PASSWORD=(.+?)(['\"])\s*$", line, re.IGNORECASE)
    if m:
        indent = m.group(2)
        var_name = m.group(3)
        lines[idx] = f"{indent}import os; {var_name} = os.environ.get('{var_name.upper()}', 'default')\n"
        _write_lines(path, lines)
        changes.append({"file": filepath, "line": lineno, "issue": msg, "fix": "Replaced hardcoded password with env var lookup"})
        return 0

    return 0


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.readlines()
    except Exception:
        return []


def _write_lines(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def create_fixed_zip(source_dir: str, output_path: str) -> str:
    """Create a zip of the source directory (excluding caches)."""
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for fn in files:
                if fn.endswith((".pyc", ".pyo", ".zip")):
                    continue
                path = os.path.join(root, fn)
                arcname = os.path.relpath(path, source_dir)
                zf.write(path, arcname)
    return output_path
