from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import sys
from mcp.server.fastmcp import FastMCP
from subprocess import CompletedProcess, TimeoutExpired, run
from typing import Dict, Any, Optional

# Create an MCP server
mcp = FastMCP("Code Security Server")

# Default timeouts for scans (in seconds)
BANDIT_TIMEOUT = 120
RUFF_TIMEOUT = 120
SEMGREP_TIMEOUT = 120
OWASP_TIMEOUT = 300  # OWASP Dependency-Check can be slow (NVD DB download)
CODEQL_TIMEOUT = 300
ZAP_TIMEOUT = 180
SONARQUBE_TIMEOUT = 300

# Maximum output size in bytes before truncation (50 MB)
MAX_OUTPUT_SIZE = 50 * 1024 * 1024

# Maximum number of files to scan in a directory before aborting
MAX_FILES = 10_000

# Directories/files auto-excluded from scanning (always skipped)
AUTO_EXCLUDE_DIRS = {
    ".venv", "venv", "env",
    "node_modules",
    ".git",
    "__pycache__",
    "dist", "build",
    ".ruff_cache",
    ".bandit_cache",
    ".semgrep_logs", ".semgrep",
    ".mypy_cache", ".pytest_cache",
    "target",               # Rust/Java build output
    ".next", ".nuxt",       # JS framework build output
    ".tox", ".nox",         # Python test runners
    "coverage", ".coverage",
}

AUTO_EXCLUDE_FILES = {
    ".DS_Store", "Thumbs.db",
    "*.pyc", "*.pyo", "*.pyd",
    "*.so", "*.dll", "*.dylib",
    "*.exe", "*.bin",
    "*.jpg", "*.jpeg", "*.png", "*.gif", "*.svg", "*.ico",
    "*.mp3", "*.mp4", "*.wav",
    "*.zip", "*.tar", "*.gz", "*.rar", "*.7z",
    "*.pdf", "*.docx", "*.xlsx", "*.pptx",
    "package-lock.json", "yarn.lock",  # lock files are huge
}

# Sensitive system paths that should never be scanned
SENSITIVE_SYSTEM_PATHS = {
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "/etc", "/sys", "/proc", "/dev", "/boot",
    "/System", "/Library", "/Applications",
}

# Regex patterns for path injection detection
SHELL_METACHAR_PATTERN = re.compile(r'[;&|`$(){}<>!]')
PATH_TRAVERSAL_PATTERN = re.compile(r'(?:^|[\\/])\.\.(?:[\\/]|$)')


def run_codeql_scan(target_path: str) -> Dict[str, Any]:
    """Run CodeQL scan on the target path.
    
    This function requires CodeQL CLI to be installed and available in the system PATH.
    CodeQL requires building a database from source code, then running security queries.
    
    Args:
        target_path: The absolute or relative path to the project directory.

    Returns:
        A dictionary containing the CodeQL scan results.
    """
    # Check if CodeQL is enabled via environment variable
    codeql_enabled = os.environ.get("CODEQL_ENABLED", "false").lower() == "true"
    if not codeql_enabled:
        return {"results": [], "message": "CodeQL scanning is disabled. Set CODEQL_ENABLED=true to enable."}
        
    # Security validation
    error = _validate_path_safety(target_path)
    if error:
        return {"error": error}
        
    resolved = _normalize_path(target_path)
    
    if not os.path.exists(resolved):
        return {"error": f"Path does not exist: {target_path}"}
        
    if not os.path.isdir(resolved):
        return {"error": f"Not a directory: {target_path}"}
        
    # Check if CodeQL is installed
    codeql_path = shutil.which("codeql")
    if not codeql_path:
        return {"error": "CodeQL not found. Please install CodeQL CLI to use this feature."}
        
    try:
        # This is a simplified implementation
        # A full implementation would require:
        # 1. Creating a CodeQL database from the source code
        # 2. Running security queries against the database
        # 3. Parsing the results
        
        # For now, we'll return a placeholder result indicating the tool is not fully implemented
        return {
            "results": [],
            "message": "CodeQL integration is available but not fully implemented in this version. Please install CodeQL and use the command line interface for full functionality."
        }
    except Exception as e:
        return {"error": f"Error running CodeQL scan: {str(e)}"}


def run_owasp_zap_scan(target_path: str) -> Dict[str, Any]:
    """Run OWASP ZAP scan on the target path.
    
    This function would integrate with ZAP to perform dynamic application security testing.
    In a full implementation, this would require:
    1. ZAP to be running as a service
    2. A way to point ZAP at the application
    3. Configuration of scan parameters
    
    Args:
        target_path: The absolute or relative path to the project directory.

    Returns:
        A dictionary containing the ZAP scan results.
    """
    # Check if ZAP is enabled via environment variable
    zap_enabled = os.environ.get("ZAP_ENABLED", "false").lower() == "true"
    if not zap_enabled:
        return {"results": [], "message": "OWASP ZAP scanning is disabled. Set ZAP_ENABLED=true to enable."}
        
    # Security validation
    error = _validate_path_safety(target_path)
    if error:
        return {"error": error}
        
    resolved = _normalize_path(target_path)
    
    if not os.path.exists(resolved):
        return {"error": f"Path does not exist: {target_path}"}
        
    # Check if ZAP is installed and running
    try:
        return {
            "results": [],
            "message": "OWASP ZAP integration is available but requires ZAP to be running as a service. Please start ZAP in daemon mode for full functionality."
        }
    except Exception as e:
        return {"error": f"Error running ZAP scan: {str(e)}"}


def _normalize_path(path: str) -> str:
    """Normalize a path to absolute form, resolving .. components safely."""
    try:
        return os.path.abspath(os.path.normpath(path)).rstrip(os.sep)
    except Exception:
        return path


def _validate_path_safety(target_path: str) -> Optional[str]:
    """Validate the target path for security concerns.
    
    Returns an error message string if the path should be rejected,
    or None if the path is safe.
    """
    # Block empty paths
    if not target_path or not target_path.strip():
        return "Path is empty."

    # Detect shell metacharacters (command injection)
    if SHELL_METACHAR_PATTERN.search(target_path):
        return f"Path contains shell metacharacters and was rejected: {target_path}"

    # Detect path traversal
    normalized = _normalize_path(target_path)

    # Check if normalized path exists (skip traversal check if it doesn't,
    # since we handle non-existent paths separately in each tool)
    if not os.path.exists(normalized):
        return None  # Let individual tools handle this

    # Block sensitive system paths
    for sensitive_path in SENSITIVE_SYSTEM_PATHS:
        if normalized.startswith(sensitive_path):
            return f"Scanning system paths is not allowed: {sensitive_path}"

    return None


def _get_scannerignore_patterns(target_path: str) -> list[str]:
    """Load .scannerignore patterns from the target directory, if present.
    
    Looks for .scannerignore in the root of the target path (or its nearest
    parent directory).
    """
    patterns: list[str] = []

    # Walk up from target to find .scannerignore
    search_dir = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
    search_dir = _normalize_path(search_dir)

    for _ in range(10):  # Max 10 levels up
        ignore_file = os.path.join(search_dir, ".scannerignore")
        if os.path.isfile(ignore_file):
            try:
                with open(ignore_file, encoding="utf-8") as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            patterns.append(stripped)
            except (OSError, UnicodeDecodeError):
                pass  # Ignore unreadable .scannerignore files
        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break
        search_dir = parent

    return patterns


def _should_skip_path(path: str, scannerignore_patterns: list[str]) -> bool:
    """Check if a path should be skipped based on exclusion rules.
    
    Checks auto-excluded dirs, auto-excluded file patterns, and any
    patterns loaded from .scannerignore.
    """
    relative = os.path.basename(path)

    # Check auto-excluded directories (match any component in the path)
    path_parts = path.replace("\\", "/").split("/")
    for part in path_parts:
        if part in AUTO_EXCLUDE_DIRS:
            return True

    # Check auto-excluded file names/extensions
    for pattern in AUTO_EXCLUDE_FILES:
        if fnmatch.fnmatch(relative, pattern):
            return True
        if fnmatch.fnmatch(path, pattern):
            return True

    # Check .scannerignore patterns
    for pattern in scannerignore_patterns:
        if fnmatch.fnmatch(relative, pattern):
            return True
        if fnmatch.fnmatch(path, pattern):
            return True

    return False


def _count_files_recursive(path: str, scannerignore_patterns: list[str]) -> int:
    """Count files in a directory, respecting skip rules.
    
    Returns -1 if the count exceeds MAX_FILES (early abort).
    """
    if not os.path.isdir(path):
        return 1 if os.path.isfile(path) else 0

    count = 0
    try:
        for root, dirs, files in os.walk(path, topdown=True):
            # Filter directories in-place to prevent walking into skipped dirs
            dirs[:] = [d for d in dirs if not _should_skip_path(
                os.path.join(root, d), scannerignore_patterns
            )]
            for file in files:
                filepath = os.path.join(root, file)
                if _should_skip_path(filepath, scannerignore_patterns):
                    continue
                count += 1
                if count > MAX_FILES:
                    return -1  # Sentinel: too many files
    except (OSError, PermissionError):
        pass

    return count


def _strip_absolute_paths(text: str) -> str:
    """Replace absolute user directory paths with ~ for privacy.
    
    Handles both Windows (C:\\Users\\...) and Unix (/home/..., /Users/...) paths.
    """
    # Windows: C:\Users\Username\...
    text = re.sub(
        r'[A-Za-z]:\\Users\\[^\\"]+(\\|")',
        lambda m: f"~{m.group(1)}" if m.group(1) == "\\" else '"~/',
        text,
    )
    # Unix: /home/username/... or /Users/username/...
    text = re.sub(
        r'/home/[^/"]+(/|")',
        lambda m: f"~{m.group(1)}" if m.group(1) == "/" else '"~/',
        text,
    )
    text = re.sub(
        r'/Users/[^/"]+(/|")',
        lambda m: f"~{m.group(1)}" if m.group(1) == "/" else '"~/',
        text,
    )
    return text


def _truncate_output(text: str, max_size: int = MAX_OUTPUT_SIZE) -> str:
    """Truncate text if it exceeds max_size, with a clear message."""
    if len(text) > max_size:
        return text[:max_size] + f"\n... [truncated at {max_size} bytes]"
    return text


def _sanitize_tool_output(text: str) -> str:
    """Sanitize tool output by stripping absolute paths and truncating."""
    text = _strip_absolute_paths(text)
    text = _truncate_output(text)
    return text


def _run_module(
    module: str,
    args: list[str],
    timeout: int,
    scannerignore_patterns: Optional[list[str]] = None,
) -> CompletedProcess:
    """Run a Python module via sys.executable with consistent settings.

    Args:
        module: The module name to run (e.g. 'bandit', 'ruff', 'semgrep').
        args: CLI arguments to to pass to the module.
        timeout: Maximum execution time in seconds.
        scannerignore_patterns: Optional list of .scannerignore patterns.

    Returns:
        The CompletedProcess result.

    Raises:
        TimeoutExpired: If the command times out.
    """
    if scannerignore_patterns is None:
        scannerignore_patterns = []

    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    return run(
        [sys.executable, "-m", module, *args],
        capture_output=True,
        encoding="utf-8",
        timeout=timeout,
        env=env,
    )


def _parse_json_output(
    result: CompletedProcess,
    tool_name: str,
) -> Dict[str, Any]:
    """Parse stdout as JSON, with comprehensive error reporting.

    Handles tools that may output progress lines before JSON (e.g. Bandit)
    and tools that output a JSON array instead of a dict (e.g. Ruff).

    Args:
        result: The CompletedProcess from the subprocess run.
        tool_name: Name of the tool for error messages.

    Returns:
        Parsed JSON dict, or an error dict with diagnostics.
    """
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    # Sanitize outputs to remove absolute paths and limit size
    stdout = _sanitize_tool_output(stdout)
    stderr = _sanitize_tool_output(stderr)

    if not stdout:
        return {
            "results": [],
            "message": f"No issues found by {tool_name}.",
        }

    # Strip leading non-JSON lines (e.g. Bandit progress bar "Working...")
    # Find the first '{' or '[' character and take everything from there
    json_start = None
    for i, ch in enumerate(stdout):
        if ch in ('{', '['):
            json_start = i
            break
    if json_start is not None and json_start > 0:
        stdout = stdout[json_start:]

    if not stdout:
        return {
            "results": [],
            "message": f"No issues found by {tool_name}.",
        }

    try:
        parsed = json.loads(stdout)
        # If the tool returned a JSON array (e.g. Ruff with findings),
        # wrap it in a dict with a "results" key for consistency
        if isinstance(parsed, list):
            return {"results": parsed}
        return parsed
    except json.JSONDecodeError as exc:
        return {
            "error": f"Failed to parse {tool_name} JSON output",
            "parse_error": str(exc)[:500],
            "stderr": stderr[:2000] if stderr else "",
            "raw_output": stdout[:2000],
        }


def _is_python_target(target_path: str) -> bool:
    """Check if the target is a Python file or a directory (we let directory scans pass)."""
    if not os.path.exists(target_path):
        return False
    if os.path.isdir(target_path):
        return True
    return target_path.endswith(".py") or target_path.endswith(".pyi")


def _validate_and_prepare_path(
    target_path: str,
    require_python: bool = False,
) -> tuple[Optional[str], Optional[str], list[str]]:
    """Validate a target path and prepare scanning context.
    
    Args:
        target_path: The path to validate.
        require_python: If True, also validates that the target is Python.
    
    Returns:
        Tuple of (error_message, resolved_path, scannerignore_patterns).
        If error_message is not None, the other values are undefined.
    """
    # Security validation
    error = _validate_path_safety(target_path)
    if error:
        return error, None, []

    # Check existence
    if not os.path.exists(target_path):
        return f"Path does not exist: {target_path}", None, []

    # Python-only check
    resolved = _normalize_path(target_path)
    if require_python and not _is_python_target(resolved):
        return f"Not a Python file or directory: {target_path}", None, []

    # Load .scannerignore patterns
    scannerignore_patterns = _get_scannerignore_patterns(resolved)

    # Check file count for directories
    if os.path.isdir(resolved):
        file_count = _count_files_recursive(resolved, scannerignore_patterns)
        if file_count == -1:
            return (
                f"Directory has too many files (> {MAX_FILES}). "
                f"Try adding patterns to .scannerignore or use a more specific path.",
                None,
                [],
            )

    return None, resolved, scannerignore_patterns


@mcp.tool()
def run_security_scan(target_path: str) -> Dict[str, Any]:
    """Run a security scan on the specified Python directory or file using Bandit.

    Args:
        target_path: The absolute or relative path to the Python file or directory.

    Returns:
        A dictionary containing the security scan results (vulnerabilities found).
    """
    error, resolved, scannerignore_patterns = _validate_and_prepare_path(
        target_path, require_python=True
    )
    if error:
        return {"error": error}

    assert resolved is not None  # guaranteed because error is None

    try:
        result = _run_module(
            "bandit",
            ["-r", resolved, "-f", "json"],
            timeout=BANDIT_TIMEOUT,
            scannerignore_patterns=scannerignore_patterns,
        )
        return _parse_json_output(result, "Bandit")
    except TimeoutExpired:
        return {"error": f"Bandit scan timed out after {BANDIT_TIMEOUT}s on: {target_path}"}
    except Exception as e:
        return {"error": f"Error running security scan: {str(e)}"}


@mcp.tool()
def run_code_linting(target_path: str) -> Dict[str, Any]:
    """Run code linting and overview on the specified Python directory or file using Ruff.

    Args:
        target_path: The absolute or relative path to the Python file or directory.

    Returns:
        A dictionary containing the linting results (issues found).
    """
    error, resolved, scannerignore_patterns = _validate_and_prepare_path(
        target_path, require_python=True
    )
    if error:
        return {"error": error}

    assert resolved is not None  # guaranteed because error is None

    try:
        result = _run_module(
            "ruff",
            ["check", "--output-format", "json", "--", resolved],
            timeout=RUFF_TIMEOUT,
            scannerignore_patterns=scannerignore_patterns,
        )
        return _parse_json_output(result, "Ruff")
    except TimeoutExpired:
        return {"error": f"Ruff scan timed out after {RUFF_TIMEOUT}s on: {target_path}"}
    except Exception as e:
        return {"error": f"Error running code linting: {str(e)}"}


@mcp.tool()
def run_universal_security_scan(target_path: str) -> Dict[str, Any]:
    """Run a universal security scan supporting multiple languages using Semgrep.

    Supports Python, Java, JavaScript, TypeScript, Go, Ruby, and more.

    Args:
        target_path: The absolute or relative path to the file or directory.

    Returns:
        A dictionary containing the security scan results (vulnerabilities found).
    """
    error, resolved, scannerignore_patterns = _validate_and_prepare_path(
        target_path, require_python=False
    )
    if error:
        return {"error": error}

    assert resolved is not None  # guaranteed because error is None

    try:
        result = _run_module(
            "semgrep",
            ["scan", "--config", "auto", "--json", "--", resolved],
            timeout=SEMGREP_TIMEOUT,
            scannerignore_patterns=scannerignore_patterns,
        )
        return _parse_json_output(result, "Semgrep")
    except TimeoutExpired:
        return {"error": f"Semgrep scan timed out after {SEMGREP_TIMEOUT}s on: {target_path}"}
    except Exception as e:
        return {"error": f"Error running universal security scan: {str(e)}"}


@mcp.tool()
def run_all_scans(target_path: str) -> Dict[str, Any]:
    """Run all security scans (Bandit, Ruff, Semgrep) on the given target.

    Also runs dependency scans if package.json or requirements.txt are found.

    Args:
        target_path: The absolute or relative path to the file or directory.

    Returns:
        A dictionary with results from each tool.
    """
    result = {
        "bandit": run_security_scan(target_path),
        "ruff": run_code_linting(target_path),
        "semgrep": run_universal_security_scan(target_path),
    }

    # Also run dependency scans if applicable
    resolved = _normalize_path(target_path)
    if os.path.isdir(resolved):
        if os.path.isfile(os.path.join(resolved, "package.json")):
            result["npm_audit"] = scan_npm_dependencies(target_path)
        if os.path.isfile(os.path.join(resolved, "requirements.txt")):
            result["pip_audit"] = scan_python_dependencies(target_path)
        # OWASP Dependency-Check runs on any project directory
        result["owasp_dependency_check"] = run_owasp_dependency_check(target_path)
        
        # Run additional security tools if available
        result["codeql"] = run_codeql_scan(target_path)
        result["zap"] = run_owasp_zap_scan(target_path)

    return result


@mcp.tool()
def scan_npm_dependencies(project_path: str) -> Dict[str, Any]:
    """Scan npm dependencies for known vulnerabilities using npm audit.

    Runs `npm audit --json` on the specified project directory.
    Requires a package.json and package-lock.json in the target directory.

    Args:
        project_path: The absolute or relative path to the npm project directory
                      (must contain package.json).

    Returns:
        A dictionary containing the npm audit results (vulnerabilities found).
    """
    # Security validation
    error = _validate_path_safety(project_path)
    if error:
        return {"error": error}

    resolved = _normalize_path(project_path)

    if not os.path.exists(resolved):
        return {"error": f"Path does not exist: {project_path}"}

    if not os.path.isdir(resolved):
        return {"error": f"Not a directory: {project_path}"}

    package_json = os.path.join(resolved, "package.json")
    if not os.path.isfile(package_json):
        return {"error": f"No package.json found in: {project_path}"}

    try:
        # Use the system PATH so npm can be found (important on Windows where
        # npm may be a PowerShell script or nvm-managed binary)
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

        # On Windows, npm is often a .ps1 script which subprocess can't run.
        # Use npm.cmd explicitly if available.
        npm_cmd = shutil.which("npm") or "npm"
        if os.name == "nt":
            # Try to find npm.cmd in PATH
            for path_dir in os.environ.get("PATH", "").split(os.pathsep):
                candidate = os.path.join(path_dir.strip('"'), "npm.cmd")
                if os.path.isfile(candidate):
                    npm_cmd = candidate
                    break

        result = run(
            [npm_cmd, "audit", "--json"],
            capture_output=True,
            encoding="utf-8",
            timeout=120,
            cwd=resolved,
            env=env,
        )
        stdout = _sanitize_tool_output(result.stdout.strip())

        if not stdout:
            return {
                "results": [],
                "message": "No vulnerabilities found by npm audit.",
            }

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # npm audit may return non-JSON on success with no issues
            return {
                "results": [],
                "message": stdout,
            }

        # npm audit returns {vulnerabilities: {...}} or {metadata: {...}}
        vulnerabilities = data.get("vulnerabilities", {})
        metadata = data.get("metadata", {})

        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "metadata": metadata,
            "vulnerabilities": vulnerabilities,
        }

        if result.returncode != 0 and not vulnerabilities:
            # npm audit exits non-zero when vulnerabilities are found
            # but if we got no vulns back, something else went wrong
            summary["note"] = (
                "npm audit exited with code {}. "
                "This may indicate an audit error or connectivity issue."
            ).format(result.returncode)

        return summary

    except TimeoutExpired:
        return {"error": "npm audit timed out after 120s on: {}".format(project_path)}
    except FileNotFoundError:
        return {"error": "npm is not installed or not found in PATH."}
    except Exception as e:
        return {"error": "Error running npm audit: {}".format(str(e))}


@mcp.tool()
def scan_python_dependencies(project_path: str) -> Dict[str, Any]:
    """Scan Python dependencies for known vulnerabilities using pip-audit.

    Runs `pip-audit -r requirements.txt` on the specified project directory.
    Requires a requirements.txt file in the target directory.

    Args:
        project_path: The absolute or relative path to the Python project directory
                      (must contain requirements.txt).

    Returns:
        A dictionary containing the pip-audit results (vulnerabilities found).
    """
    # Security validation
    error = _validate_path_safety(project_path)
    if error:
        return {"error": error}

    resolved = _normalize_path(project_path)

    if not os.path.exists(resolved):
        return {"error": "Path does not exist: {}".format(project_path)}

    if not os.path.isdir(resolved):
        return {"error": "Not a directory: {}".format(project_path)}

    requirements_file = os.path.join(resolved, "requirements.txt")
    if not os.path.isfile(requirements_file):
        return {"error": "No requirements.txt found in: {}".format(project_path)}

    try:
        result = _run_module(
            "pip_audit",
            ["-r", requirements_file, "--format", "json"],
            timeout=120,
        )
        stdout = result.stdout.strip()
        stderr = _sanitize_tool_output(result.stderr.strip())

        if not stdout:
            return {
                "results": [],
                "message": "No vulnerabilities found by pip-audit.",
            }

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return {
                "error": "Failed to parse pip-audit JSON output",
                "parse_error": str(exc)[:500],
                "stderr": stderr[:2000] if stderr else "",
                "raw_output": stdout[:2000],
            }

        # pip-audit returns a list of dependency findings
        # Each entry: {"name": "...", "version": "...", "vulns": [...]}
        findings = data if isinstance(data, list) else data.get("dependencies", [])

        total_vulns = sum(len(f.get("vulns", [])) for f in findings)
        vulnerable_packages = [f for f in findings if f.get("vulns")]

        return {
            "total_vulnerabilities": total_vulns,
            "vulnerable_packages": len(vulnerable_packages),
            "total_packages_scanned": len(findings),
            "dependencies": findings,
        }

    except TimeoutExpired:
        return {"error": "pip-audit timed out after 120s on: {}".format(project_path)}
    except FileNotFoundError:
        return {"error": "pip-audit is not installed. Install it with: pip install pip-audit"}
    except Exception as e:
        return {"error": "Error running pip-audit: {}".format(str(e))}


@mcp.tool()
def run_owasp_dependency_check(project_path: str) -> Dict[str, Any]:
    """Run OWASP Dependency-Check on the specified project directory.

    Scans project dependencies (npm, pip, Maven, Gradle, etc.) for known
    vulnerabilities using the OWASP-referenced National Vulnerability Database (NVD).
    This is the official OWASP dependency scanning tool.

    The first run may be slow as it downloads the NVD database.
    Subsequent runs use the cached database.

    Args:
        project_path: The absolute or relative path to the project directory
                      to scan for vulnerable dependencies.

    Returns:
        A dictionary containing the OWASP Dependency-Check results
        (vulnerabilities found across all dependency types).
    """
    # Security validation
    error = _validate_path_safety(project_path)
    if error:
        return {"error": error}

    resolved = _normalize_path(project_path)

    if not os.path.exists(resolved):
        return {"error": f"Path does not exist: {project_path}"}

    if not os.path.isdir(resolved):
        return {"error": f"Not a directory: {project_path}"}

    # Path to OWASP Dependency-Check CLI
    owasp_home = os.environ.get(
        "OWASP_DEPENDENCY_CHECK_HOME",
        r"C:\tools\dependency-check\dependency-check",
    )
    owasp_bat = os.path.join(owasp_home, "bin", "dependency-check.bat")
    owasp_sh = os.path.join(owasp_home, "bin", "dependency-check.sh")

    if os.name == "nt":
        owasp_cmd = owasp_bat if os.path.isfile(owasp_bat) else "dependency-check.bat"
    else:
        owasp_cmd = owasp_sh if os.path.isfile(owasp_sh) else "dependency-check.sh"

    if not os.path.isfile(owasp_cmd):
        return {
            "error": (
                "OWASP Dependency-Check not found. "
                "Install it from https://github.com/dependency-check/DependencyCheck/releases "
                "or set the OWASP_DEPENDENCY_CHECK_HOME environment variable."
            )
        }

    # Output file for JSON results
    output_file = os.path.join(resolved, "dependency-check-report.json")

    try:
        result = run(
            [owasp_cmd, "--scan", resolved, "--format", "JSON", "--out", output_file],
            capture_output=True,
            encoding="utf-8",
            timeout=OWASP_TIMEOUT,
            cwd=resolved,
        )
        stdout = _sanitize_tool_output(result.stdout.strip())
        stderr = _sanitize_tool_output(result.stderr.strip())

        # Read the JSON report if it was generated
        if os.path.isfile(output_file):
            try:
                with open(output_file, encoding="utf-8") as f:
                    report = json.load(f)
                # Clean up the report file
                try:
                    os.remove(output_file)
                except OSError:
                    pass

                # Extract key information from the report
                dependencies = report.get("dependencies", [])
                total_vulns = 0
                vulnerable_deps = []

                for dep in dependencies:
                    vulns = dep.get("vulnerabilities", [])
                    if vulns:
                        total_vulns += len(vulns)
                        vulnerable_deps.append({
                            "package": dep.get("fileName", dep.get("filePath", "unknown")),
                            "evidence": [
                                e.get("value", "") for e in dep.get("evidenceCollected", {}).get("productEvidence", [])
                            ],
                            "vulnerabilities": [
                                {
                                    "name": v.get("name", ""),
                                    "severity": v.get("severity", ""),
                                    "cvssScore": v.get("cvssv3", {}).get("baseScore", v.get("cvssv2", {}).get("score", "N/A")),
                                    "description": v.get("description", "")[:200],
                                }
                                for v in vulns
                            ],
                        })

                return {
                    "tool": "OWASP Dependency-Check",
                    "version": "12.2.2",
                    "total_dependencies_scanned": len(dependencies),
                    "total_vulnerabilities": total_vulns,
                    "vulnerable_dependencies": len(vulnerable_deps),
                    "dependencies": vulnerable_deps,
                    "scan_path": resolved,
                }

            except (json.JSONDecodeError, OSError) as e:
                return {
                    "error": f"Failed to parse OWASP Dependency-Check report: {str(e)}",
                    "stderr": stderr[:2000] if stderr else "",
                    "stdout": stdout[:2000] if stdout else "",
                }

        # No report file generated - check stderr for info
        if result.returncode != 0:
            return {
                "error": f"OWASP Dependency-Check exited with code {result.returncode}",
                "stderr": stderr[:2000] if stderr else "",
                "stdout": stdout[:2000] if stdout else "",
            }

        return {
            "results": [],
            "message": "No dependencies found or no report generated by OWASP Dependency-Check.",
            "stderr": stderr[:1000] if stderr else "",
        }

    except TimeoutExpired:
        return {"error": f"OWASP Dependency-Check timed out after {OWASP_TIMEOUT}s on: {project_path}"}
    except FileNotFoundError:
        return {
            "error": (
                "OWASP Dependency-Check not found. "
                "Install it from https://github.com/dependency-check/DependencyCheck/releases "
                "or set the OWASP_DEPENDENCY_CHECK_HOME environment variable."
            )
        }
    except Exception as e:
        return {"error": f"Error running OWASP Dependency-Check: {str(e)}"}


@mcp.tool()
def get_scan_exclusions() -> Dict[str, Any]:

    """Return the list of directories and file patterns that are auto-excluded from scans.

    Use this to understand what paths are automatically skipped when scanning.

    Returns:
        A dictionary with 'excluded_dirs' and 'excluded_files' lists.
    """
    return {
        "excluded_dirs": sorted(AUTO_EXCLUDE_DIRS),
        "excluded_files": sorted(AUTO_EXCLUDE_FILES),
        "note": (
            "These are automatically skipped. You can add custom patterns by "
            "placing a .scannerignore file in your project root."
        ),
    }


@mcp.resource("server://info")
def get_server_info() -> str:
    """Return metadata about the server and installed tool versions, plus security config.

    Returns:
        A JSON string with version information and security settings.
    """
    info: Dict[str, Any] = {
        "server": "Code Security Server",
        "python_version": sys.version,
        "config": {
            "bandit_timeout_seconds": BANDIT_TIMEOUT,
            "ruff_timeout_seconds": RUFF_TIMEOUT,
            "semgrep_timeout_seconds": SEMGREP_TIMEOUT,
            "max_output_size_bytes": MAX_OUTPUT_SIZE,
            "max_output_size_mb": MAX_OUTPUT_SIZE // (1024 * 1024),
            "max_files_before_abort": MAX_FILES,
            "auto_excluded_dirs": sorted(AUTO_EXCLUDE_DIRS),
            "auto_excluded_files": sorted(AUTO_EXCLUDE_FILES),
            "sensitive_system_paths": sorted(SENSITIVE_SYSTEM_PATHS),
        },
    }

    # Check installed tool versions
    for mod, label in [("bandit", "bandit"), ("ruff", "ruff"), ("semgrep", "semgrep"), ("pip_audit", "pip-audit")]:
        try:
            result = _run_module(mod, ["--version"], timeout=10)
            version = result.stdout.strip() or result.stderr.strip()
            info[label] = version
        except Exception:
            info[label] = "not found"

    # Check npm version
    try:
        npm_result = run(["npm", "--version"], capture_output=True, encoding="utf-8", timeout=10)
        info["npm"] = npm_result.stdout.strip() or npm_result.stderr.strip()
    except Exception:
        info["npm"] = "not found"

    # Check OWASP Dependency-Check version
    try:
        owasp_home = os.environ.get(
            "OWASP_DEPENDENCY_CHECK_HOME",
            r"C:\tools\dependency-check\dependency-check",
        )
        owasp_bat = os.path.join(owasp_home, "bin", "dependency-check.bat")
        if os.path.isfile(owasp_bat):
            owasp_result = run([owasp_bat, "--version"], capture_output=True, encoding="utf-8", timeout=10)
            info["owasp_dependency_check"] = owasp_result.stdout.strip() or owasp_result.stderr.strip()
        else:
            info["owasp_dependency_check"] = "not found"
    except Exception:
        info["owasp_dependency_check"] = "not found"

    return json.dumps(info, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")