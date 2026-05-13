import json
import os
import re
import zipfile
import xml.etree.ElementTree as ET


def apply_fixes(source_dir: str, results: dict) -> list[dict]:
    """Apply safe automated fixes — upgrades vulnerable dependencies only.

    This will NEVER modify your source code logic. Only:
      - Pin vulnerable pip/npm/go/maven/rust deps to their first patched version
      - Remove stale lockfiles so the next install picks up fresh versions
    """
    changes: list[dict] = []
    scans = results.get("scans", {})

    _fix_requirements_txt(source_dir, scans, changes)
    _fix_package_json(source_dir, scans, changes)
    _fix_pnpm(source_dir, scans, changes)
    _fix_pyproject_toml(source_dir, scans, changes)
    _fix_go_mod(source_dir, scans, changes)
    _fix_pom_xml(source_dir, scans, changes)
    _fix_cargo_toml(source_dir, scans, changes)

    npm_lockfiles = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
    for lf in npm_lockfiles:
        lf_path = os.path.join(source_dir, lf)
        if os.path.isfile(lf_path):
            try:
                os.remove(lf_path)
                changes.append({
                    "file": lf, "line": 1,
                    "issue": "Stale lock file — may pin outdated sub-dependencies",
                    "fix": f"Removed {lf}. Run `npm install` to regenerate."
                })
            except OSError:
                pass

    return changes


# ── Helpers ──────────────────────────────────────────────────────────

def _trivy_pkgs_for_target(scans: dict, target_pattern: str) -> dict:
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


# ── requirements.txt ─────────────────────────────────────────────────

def _fix_requirements_txt(source_dir: str, scans: dict, changes: list) -> None:
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

    with open(req_path, encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    modified = False
    for line in lines:
        m = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=!~]+)\s*([a-zA-Z0-9.*_.-]+)', line.strip())
        if m:
            pkg_name = m.group(1).lower()
            if pkg_name in vuln_pkgs:
                fixed_ver = vuln_pkgs[pkg_name]
                new_lines.append(f"{pkg_name}=={fixed_ver}\n")
                modified = True
                changes.append({
                    "file": "requirements.txt", "line": 1,
                    "issue": f"Vulnerable package {m.group(1)} ({m.group(3)})",
                    "fix": f"Pinned to {fixed_ver}"
                })
                continue
        new_lines.append(line)

    if modified:
        with open(req_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)


# ── package.json (npm) ───────────────────────────────────────────────

def _npm_vulns(scans: dict) -> dict:
    pkgs = {}
    npm_data = scans.get("npm_audit", {})
    if not isinstance(npm_data, dict):
        return pkgs
    vulnerabilities = npm_data.get("vulnerabilities", {})
    if not isinstance(vulnerabilities, dict):
        return pkgs
    for name, info in vulnerabilities.items():
        if not isinstance(info, dict):
            continue
        fix = info.get("fixAvailable")
        if fix is None:
            continue
        if isinstance(fix, str):
            pkgs[name.lower()] = fix
        elif isinstance(fix, dict):
            ver = fix.get("version")
            if ver:
                pkgs[name.lower()] = ver
    return pkgs


def _fix_package_json(source_dir: str, scans: dict, changes: list) -> None:
    vuln_pkgs = _npm_vulns(scans)
    vuln_pkgs.update(_trivy_pkgs_for_target(scans, "package"))

    if not vuln_pkgs:
        return

    pkg_path = os.path.join(source_dir, "package.json")
    if not os.path.isfile(pkg_path):
        return

    with open(pkg_path, encoding="utf-8") as f:
        pkg = json.load(f)

    modified = False
    for dep_type in ("dependencies", "devDependencies"):
        deps = pkg.get(dep_type, {})
        if not isinstance(deps, dict):
            continue
        for name in list(deps):
            name_lower = name.lower()
            if name_lower in vuln_pkgs:
                fixed = vuln_pkgs[name_lower]
                if not fixed.startswith("^") and not fixed.startswith("~") and not fixed.startswith(">="):
                    fixed = f"^{fixed}"
                deps[name] = fixed
                modified = True
                changes.append({
                    "file": "package.json", "line": 1,
                    "issue": f"Vulnerable package {name} ({deps[name]})",
                    "fix": f"Updated to {fixed}"
                })

    if modified:
        with open(pkg_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)
            f.write("\n")


def _fix_pnpm(source_dir: str, scans: dict, changes: list) -> None:
    vuln_pkgs = _npm_vulns(scans)
    vuln_pkgs.update(_trivy_pkgs_for_target(scans, "pnpm"))

    if not vuln_pkgs:
        return

    pkg_path = os.path.join(source_dir, "package.json")
    if not os.path.isfile(pkg_path):
        return

    with open(pkg_path, encoding="utf-8") as f:
        pkg = json.load(f)

    modified = False
    for dep_type in ("dependencies", "devDependencies"):
        if dep_type not in pkg:
            continue
        for name in pkg[dep_type]:
            if name.lower() in vuln_pkgs:
                fixed_ver = vuln_pkgs[name.lower()]
                if pkg[dep_type][name] != fixed_ver:
                    pkg[dep_type][name] = fixed_ver
                    modified = True
                    changes.append({
                        "file": "package.json", "line": 1,
                        "issue": f"Vulnerable pnpm package {name}",
                        "fix": f"Updated to {fixed_ver}"
                    })

    if modified:
        with open(pkg_path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, indent=2)
            f.write("\n")


# ── pyproject.toml ───────────────────────────────────────────────────

def _fix_pyproject_toml(source_dir: str, scans: dict, changes: list) -> None:
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

    vuln_pkgs.update(_trivy_pkgs_for_target(scans, "pyproject.toml"))
    if not vuln_pkgs:
        return

    pyproj_path = os.path.join(source_dir, "pyproject.toml")
    if not os.path.isfile(pyproj_path):
        return

    with open(pyproj_path, encoding="utf-8") as f:
        content = f.read()

    modified = False
    for pkg_name, fixed_ver in vuln_pkgs.items():
        pattern = rf'(^|\n)({re.escape(pkg_name)}\s*=\s*["\']?)([=<>!~]+)?([0-9.*]+)?'
        match = re.search(pattern, content, re.MULTILINE)
        if match:
            indent = match.group(1)
            pkg = match.group(2).strip()
            content = content[:match.start()] + f'{indent}{pkg} = "^{fixed_ver}"' + content[match.end():]
            modified = True
            changes.append({
                "file": "pyproject.toml", "line": 1,
                "issue": f"Vulnerable Python package {pkg_name}",
                "fix": f"Updated to ^{fixed_ver}"
            })

    if modified:
        with open(pyproj_path, "w", encoding="utf-8") as f:
            f.write(content)


# ── go.mod ───────────────────────────────────────────────────────────

def _ensure_go_version(ver: str) -> str:
    v = ver.strip()
    if v and not v.startswith("v") and v[0].isdigit():
        return f"v{v}"
    return v


def _fix_go_mod(source_dir: str, scans: dict, changes: list) -> None:
    vuln_pkgs = _trivy_pkgs_for_target(scans, "go.mod")
    if not vuln_pkgs:
        return

    mod_path = os.path.join(source_dir, "go.mod")
    if not os.path.isfile(mod_path):
        return

    with open(mod_path, encoding="utf-8") as f:
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
                    changes.append({"file": "go.mod", "line": 1, "issue": f"Vulnerable module {parts[1]}", "fix": f"Updated to {fixed}"})
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
                        changes.append({"file": "go.mod", "line": 1, "issue": f"Vulnerable module {parts[0]}", "fix": f"Updated to {fixed}"})
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
                    changes.append({"file": "go.mod", "line": 1, "issue": f"Vulnerable module {parts[1]}", "fix": f"Updated to {fixed}"})
                    continue
            new_lines.append(line)
        else:
            new_lines.append(line)

    if modified:
        with open(mod_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)


# ── pom.xml (Maven) ──────────────────────────────────────────────────

def _fix_pom_xml(source_dir: str, scans: dict, changes: list) -> None:
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

    with open(pom_path, encoding="utf-8") as f:
        text = f.read()

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return

    ns = {"": "http://maven.apache.org/POM/4.0.0"}
    deps = root.findall(".//dependency", ns)
    modified = False

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
        version_el.text = fixed
        modified = True
        changes.append({
            "file": "pom.xml", "line": 1,
            "issue": f"Vulnerable dependency {artifact.text} ({version_el.text})",
            "fix": f"Updated to {fixed}"
        })

    if modified:
        ET.register_namespace("", "http://maven.apache.org/POM/4.0.0")
        ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
        xml_str = ET.tostring(root, encoding="unicode")
        with open(pom_path, "w", encoding="utf-8") as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str)


# ── Cargo.toml (Rust) ────────────────────────────────────────────────

def _fix_cargo_toml(source_dir: str, scans: dict, changes: list) -> None:
    vuln_pkgs = _trivy_pkgs_for_target(scans, "Cargo")
    if not vuln_pkgs:
        return

    cargo_path = os.path.join(source_dir, "Cargo.toml")
    if not os.path.isfile(cargo_path):
        return

    with open(cargo_path, encoding="utf-8") as f:
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
                    new_lines.append(f'{indent}version = "{fixed}"\n')
                    modified = True
                    changes.append({
                        "file": "Cargo.toml", "line": 1,
                        "issue": f"Vulnerable crate {dep_table_name} ({m.group(1)})",
                        "fix": f"Updated to {fixed}"
                    })
                    continue
            new_lines.append(line)

        elif in_deps:
            m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', stripped)
            if m:
                name = m.group(1).lower()
                if name in vuln_pkgs:
                    fixed = vuln_pkgs[name]
                    new_lines.append(f'{name} = "{fixed}"\n')
                    modified = True
                    changes.append({
                        "file": "Cargo.toml", "line": 1,
                        "issue": f"Vulnerable crate {m.group(1)} ({m.group(2)})",
                        "fix": f"Updated to {fixed}"
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
                        "fix": f"Updated to {fixed}"
                    })
                    continue
            new_lines.append(line)
        else:
            new_lines.append(line)

    if modified:
        with open(cargo_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)


# ── ZIP creation ─────────────────────────────────────────────────────

def create_fixed_zip(source_dir: str, output_path: str) -> str:
    _excluded_files = {".pyc", ".pyo", ".zip", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for fn in files:
                if fn in _excluded_files:
                    continue
                path = os.path.join(root, fn)
                arcname = os.path.relpath(path, source_dir)
                zf.write(path, arcname)
    return output_path
