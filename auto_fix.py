import json
import re
import os
import zipfile
import xml.etree.ElementTree as ET
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

    _fix_requirements_txt(source_dir, results, changes)
    _fix_package_json(source_dir, results, changes)
    _fix_go_mod(source_dir, results, changes)
    _fix_pom_xml(source_dir, results, changes)
    _fix_cargo_toml(source_dir, results, changes)

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


def _trivy_pkgs_for_target(scans: dict, target_pattern: str) -> dict:
    """Collect vulnerable packages from trivy results for a specific target file."""
    pkgs = {}
    trivy_data = scans.get("trivy", {})
    if isinstance(trivy_data, dict) and "Results" in trivy_data:
        for r in trivy_data["Results"]:
            target = r.get("Target", "")
            if target_pattern not in target:
                continue
            for v in r.get("Vulnerabilities", []):
                pkg = v.get("PkgName", "").lower()
                fixed = v.get("FixedVersion", "")
                if pkg and fixed:
                    pkgs[pkg] = fixed.split(",")[0].strip()
    return pkgs


def _fix_requirements_txt(source_dir: str, results: dict, changes: list) -> None:
    """Pin vulnerable Python packages to first available fix version."""
    scans = results.get("scans", {})
    vuln_pkgs = {}

    pip_data = scans.get("pip_audit", {})
    if isinstance(pip_data, dict) and "dependencies" in pip_data:
        for dep in pip_data["dependencies"]:
            name = dep.get("name", "").lower()
            if not name:
                continue
            for v in dep.get("vulns", []):
                fix_versions = v.get("fix_versions", [])
                if fix_versions:
                    vuln_pkgs[name] = fix_versions[0]
                    break

    vuln_pkgs.update(_trivy_pkgs_for_target(scans, "requirements.txt"))

    if not vuln_pkgs:
        return

    req_path = os.path.join(source_dir, "requirements.txt")
    if not os.path.isfile(req_path):
        return

    with open(req_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    modified = False
    for line in lines:
        stripped = line.strip()
        m = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*([a-zA-Z0-9.*_.-]+)', stripped)
        if m:
            pkg_name = m.group(1).lower()
            if pkg_name in vuln_pkgs:
                fixed_ver = vuln_pkgs[pkg_name]
                new_lines.append(f"{pkg_name}=={fixed_ver}\n")
                modified = True
                changes.append({
                    "file": "requirements.txt",
                    "line": 1,
                    "issue": f"Vulnerable package {m.group(1)} ({m.group(3)})",
                    "fix": f"Pinned {m.group(1)} to {fixed_ver}"
                })
                continue
        new_lines.append(line)

    if modified:
        with open(req_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)


def _fix_package_json(source_dir: str, results: dict, changes: list) -> None:
    """Update vulnerable npm packages to fix version from audit."""
    scans = results.get("scans", {})
    vuln_pkgs = {}

    npm_data = scans.get("npm_audit", {})
    if isinstance(npm_data, dict):
        vulnerabilities = npm_data.get("vulnerabilities", {})
        if isinstance(vulnerabilities, dict):
            for name, info in vulnerabilities.items():
                if not isinstance(info, dict):
                    continue
                fix = info.get("fixAvailable")
                if fix is None:
                    continue
                if isinstance(fix, str):
                    vuln_pkgs[name.lower()] = fix
                elif isinstance(fix, dict):
                    ver = fix.get("version")
                    if ver:
                        vuln_pkgs[name.lower()] = ver

    vuln_pkgs.update(_trivy_pkgs_for_target(scans, "package"))

    if not vuln_pkgs:
        return

    pkg_path = os.path.join(source_dir, "package.json")
    if not os.path.isfile(pkg_path):
        return

    with open(pkg_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    modified = False
    for dep_type in ("dependencies", "devDependencies"):
        deps = pkg.get(dep_type, {})
        if not isinstance(deps, dict):
            continue
        for name, ver in list(deps.items()):
            name_lower = name.lower()
            if name_lower in vuln_pkgs:
                fixed = vuln_pkgs[name_lower]
                if not fixed.startswith("^") and not fixed.startswith("~") and not fixed.startswith(">="):
                    fixed = f"^{fixed}"
                deps[name] = fixed
                modified = True
                changes.append({
                    "file": "package.json",
                    "line": 1,
                    "issue": f"Vulnerable package {name} ({ver})",
                    "fix": f"Updated {name} to {fixed}"
                })

    if modified:
        with open(pkg_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)
            f.write("\n")


def _ensure_go_version(ver: str) -> str:
    """Ensure Go module version has a 'v' prefix."""
    v = ver.strip()
    if v and not v.startswith("v") and v[0].isdigit():
        return f"v{v}"
    return v


def _fix_go_mod(source_dir: str, results: dict, changes: list) -> None:
    """Update vulnerable Go module versions in go.mod."""
    scans = results.get("scans", {})
    vuln_pkgs = _trivy_pkgs_for_target(scans, "go.mod")

    if not vuln_pkgs:
        return

    mod_path = os.path.join(source_dir, "go.mod")
    if not os.path.isfile(mod_path):
        return

    with open(mod_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    modified = False
    in_require_block = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("require (") and stripped.endswith(")"):
            parts = stripped.split()
            if len(parts) >= 3:
                pkg = parts[1].lower()
                if pkg in vuln_pkgs:
                    fixed = _ensure_go_version(vuln_pkgs[pkg])
                    new_lines.append(f"require {parts[1]} {fixed}\n")
                    modified = True
                    changes.append({"file": "go.mod", "line": 1, "issue": f"Vulnerable module {parts[1]}", "fix": f"Updated {parts[1]} to {fixed}"})
                    continue
            new_lines.append(line)

        elif stripped == "require (":
            in_require_block = True
            new_lines.append(line)

        elif in_require_block:
            if stripped == ")":
                in_require_block = False
                new_lines.append(line)
            else:
                parts = stripped.split()
                if len(parts) >= 2:
                    pkg = parts[0].lower()
                    if pkg in vuln_pkgs:
                        fixed = _ensure_go_version(vuln_pkgs[pkg])
                        indent = line[:len(line) - len(line.lstrip())]
                        new_lines.append(f"{indent}{parts[0]} {fixed}\n")
                        modified = True
                        changes.append({"file": "go.mod", "line": 1, "issue": f"Vulnerable module {parts[0]}", "fix": f"Updated {parts[0]} to {fixed}"})
                        continue
                new_lines.append(line)

        elif stripped.startswith("require ") and not stripped.startswith("require ("):
            parts = stripped.split()
            if len(parts) >= 3:
                pkg = parts[1].lower()
                if pkg in vuln_pkgs:
                    fixed = _ensure_go_version(vuln_pkgs[pkg])
                    new_lines.append(f"require {parts[1]} {fixed}\n")
                    modified = True
                    changes.append({"file": "go.mod", "line": 1, "issue": f"Vulnerable module {parts[1]}", "fix": f"Updated {parts[1]} to {fixed}"})
                    continue
            new_lines.append(line)

        else:
            new_lines.append(line)

    if modified:
        with open(mod_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)


def _fix_pom_xml(source_dir: str, results: dict, changes: list) -> None:
    """Update vulnerable Maven dependency versions in pom.xml."""
    scans = results.get("scans", {})
    vuln_pkgs = _trivy_pkgs_for_target(scans, "pom.xml")

    if not vuln_pkgs:
        return

    pom_path = os.path.join(source_dir, "pom.xml")
    if not os.path.isfile(pom_path):
        return

    try:
        ET.parse(pom_path)
    except ET.ParseError:
        return

    with open(pom_path, "r", encoding="utf-8") as f:
        text = f.read()

    modified = False
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return

    ns = {"": "http://maven.apache.org/POM/4.0.0"}
    deps = root.findall(".//dependency", ns)

    for dep in deps:
        artifact = dep.find("artifactId", ns)
        if artifact is None or not artifact.text:
            continue
        key = artifact.text.lower()
        group = dep.find("groupId", ns)
        if group is not None and group.text:
            key = f"{group.text}:{artifact.text}".lower()

        if key not in vuln_pkgs:
            continue

        version_el = dep.find("version", ns)
        if version_el is None or not version_el.text:
            continue

        fixed = vuln_pkgs[key]
        old_ver = version_el.text
        version_el.text = fixed
        modified = True
        changes.append({
            "file": "pom.xml", "line": 1,
            "issue": f"Vulnerable dependency {artifact.text} ({old_ver})",
            "fix": f"Updated {artifact.text} to {fixed}"
        })

    if modified:
        ET.register_namespace("", "http://maven.apache.org/POM/4.0.0")
        ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
        xml_str = ET.tostring(root, encoding="unicode")
        text = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str
        with open(pom_path, "w", encoding="utf-8") as f:
            f.write(text)


def _fix_cargo_toml(source_dir: str, results: dict, changes: list) -> None:
    """Update vulnerable Rust crate versions in Cargo.toml."""
    scans = results.get("scans", {})
    vuln_pkgs = _trivy_pkgs_for_target(scans, "Cargo")

    if not vuln_pkgs:
        return

    cargo_path = os.path.join(source_dir, "Cargo.toml")
    if not os.path.isfile(cargo_path):
        return

    with open(cargo_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    modified = False
    in_deps = False
    in_deps_table = False
    dep_table_name = ""

    for line in lines:
        stripped = line.strip()
        indent = line[:len(line) - len(line.lstrip())]

        if stripped.startswith("["):
            in_deps = stripped.startswith("[dependencies]")
            in_deps_table = stripped.startswith("[dependencies.")
            if in_deps_table:
                dep_table_name = stripped[len("[dependencies."):-1].strip().lower()
            else:
                dep_table_name = ""
            new_lines.append(line)
            continue

        if in_deps_table:
            if stripped.startswith("version"):
                m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
                if m and dep_table_name in vuln_pkgs:
                    fixed = vuln_pkgs[dep_table_name]
                    old_ver = m.group(1)
                    new_lines.append(f'{indent}version = "{fixed}"\n')
                    modified = True
                    changes.append({
                        "file": "Cargo.toml", "line": 1,
                        "issue": f"Vulnerable crate {dep_table_name} ({old_ver})",
                        "fix": f"Updated {dep_table_name} to {fixed}"
                    })
                    continue
            new_lines.append(line)

        elif in_deps:
            m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', stripped)
            if m:
                name = m.group(1).lower()
                if name in vuln_pkgs:
                    fixed = vuln_pkgs[name]
                    old_ver = m.group(2)
                    new_lines.append(f'{name} = "{fixed}"\n')
                    modified = True
                    changes.append({
                        "file": "Cargo.toml", "line": 1,
                        "issue": f"Vulnerable crate {m.group(1)} ({old_ver})",
                        "fix": f"Updated {m.group(1)} to {fixed}"
                    })
                    continue

            m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*\{', stripped)
            if m:
                name = m.group(1).lower()
                if name in vuln_pkgs:
                    fixed = vuln_pkgs[name]
                    new_lines.append(f'{m.group(1)} = "^{fixed}"\n')
                    modified = True
                    changes.append({
                        "file": "Cargo.toml", "line": 1,
                        "issue": f"Vulnerable crate {m.group(1)}",
                        "fix": f"Updated {m.group(1)} to {fixed}"
                    })
                    continue
            new_lines.append(line)

        else:
            new_lines.append(line)

    if modified:
        with open(cargo_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)


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
