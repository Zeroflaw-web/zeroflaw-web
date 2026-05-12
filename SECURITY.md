# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | ✅ Active development |

## Reporting a Vulnerability

ZeroFlaw is a security scanning tool — we take security seriously. If you discover a vulnerability:

1. **DO NOT** open a public GitHub issue.
2. Report via email: **lokesh.kashyap3440@gmail.com** (or your preferred contact).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce (PoC preferred)
   - Affected versions/components
   - Potential impact

### Response Timeline

- **48 hours**: Acknowledgment of receipt
- **7 days**: Initial assessment and remediation plan
- **30 days**: Target fix release (depending on severity)

We'll keep you updated throughout the process and credit you in the release notes (unless you prefer to remain anonymous).

## Scope

- The web application (app.py, server.py)
- CLI tools (zeroflaw.py, auto_fix.py)
- MCP server (mcp_server.py)
- Docker build and runtime configuration

### Out of Scope

- Third-party dependencies (report via their respective maintainers)
- The scanners themselves (Bandit, Ruff, Semgrep, Trivy — report upstream)

## Safe Harbor

We participate in responsible disclosure. Research conducted in good faith on this project is protected — we won't pursue legal action against researchers who:

- Follow this policy
- Do not access or modify data beyond what's necessary
- Do not disrupt the service
- Report findings first to us before public disclosure
