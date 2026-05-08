# Graph Report - .  (2026-05-08)

## Corpus Check
- Corpus is ~15,498 words - fits in a single context window. You may not need a graph.

## Summary
- 198 nodes · 299 edges · 30 communities detected
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 10 edges (avg confidence: 0.81)
- Token cost: 85,000 input · 6,688 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Run Scan Python|Run Scan Python]]
- [[_COMMUNITY_Report Scan Html|Report Scan Html]]
- [[_COMMUNITY_Print Extract Scan|Print Extract Scan]]
- [[_COMMUNITY_Upload Endpoint Key|Upload Endpoint Key]]
- [[_COMMUNITY_Run Mcp Scan|Run Mcp Scan]]
- [[_COMMUNITY_Pattern Sanitization Auto|Pattern Sanitization Auto]]
- [[_COMMUNITY_Html Markdown Inline|Html Markdown Inline]]
- [[_COMMUNITY_Deployment Render Docker|Deployment Render Docker]]
- [[_COMMUNITY_Llm Providers Provider|Llm Providers Provider]]
- [[_COMMUNITY_Report Html Generator|Report Html Generator]]
- [[_COMMUNITY_Owasp Dependency Check|Owasp Dependency Check]]
- [[_COMMUNITY_Trivy|Trivy]]
- [[_COMMUNITY_Bandit|Bandit]]
- [[_COMMUNITY_Ruff Linter|Ruff Linter]]
- [[_COMMUNITY_Semgrep Universal|Semgrep Universal]]
- [[_COMMUNITY_Npm Audit|Npm Audit]]
- [[_COMMUNITY_Pip Audit|Pip Audit]]
- [[_COMMUNITY_Web Routes|Web Routes]]
- [[_COMMUNITY_Index Route|Index Route]]
- [[_COMMUNITY_Report Download|Report Download]]
- [[_COMMUNITY_Report Generator|Report Generator]]
- [[_COMMUNITY_Scan Project Stream|Scan Project Stream]]
- [[_COMMUNITY_Secrets|Secrets]]
- [[_COMMUNITY_Scannerignore Support|Scannerignore Support]]
- [[_COMMUNITY_Mcp Transport Layer|Mcp Transport Layer]]
- [[_COMMUNITY_Cli Interface|Cli Interface]]
- [[_COMMUNITY_Terminal Formatting|Terminal Formatting]]
- [[_COMMUNITY_Ansi Color|Ansi Color]]
- [[_COMMUNITY_Streaming Pattern|Streaming Pattern]]
- [[_COMMUNITY_Httpx|Httpx]]

## God Nodes (most connected - your core abstractions)
1. `run_scan()` - 22 edges
2. `print_owasp_results()` - 11 edges
3. `scan_project_stream()` - 10 edges
4. `_validate_and_prepare_path()` - 10 edges
5. `print_trivy_results()` - 10 edges
6. `_normalize_path()` - 9 edges
7. `run_all_scans()` - 9 edges
8. `scan_python_dependencies()` - 9 edges
9. `print_scan_header()` - 9 edges
10. `print_finding()` - 9 edges

## Surprising Connections (you probably didn't know these)
- `FastAPI Application` --uses--> `FastAPI`  [EXTRACTED]
  app.py → requirements.txt
- `FastAPI Application` --runs_on--> `Uvicorn`  [EXTRACTED]
  app.py → requirements.txt
- `Drag-and-Drop Upload` --submits_to--> `Upload Scan Endpoint`  [EXTRACTED]
  templates/index.html → app.py
- `Frontend UI` --uses--> `Server-Sent Events`  [EXTRACTED]
  templates/index.html → app.py
- `scan_project_stream()` --calls--> `run_security_scan()`  [INFERRED]
  app.py → server.py

## Hyperedges (group relationships)
- **Security Scanning Pipeline** — route_upload, route_url, scan_project_stream, run_security_scan, run_code_linting, run_universal_security_scan, scan_npm_dependencies, scan_python_dependencies, run_trivy_safe, scan_secrets, html_generator [EXTRACTED 1.00]
- **MCP Tool Suite** — mcp_server, mcp_tools, scan_health, scan_url, scan_directory, scan_zip, run_scans, scanner_bandit, scanner_ruff, scanner_semgrep, scanner_trivy, scanner_secrets [EXTRACTED 1.00]
- **Security & Validation Utilities** — path_validator, output_sanitizer, exclusion_manager, scannerignore_support, _validate_path_safety, _should_skip_path, _sanitize_tool_output, _get_scannerignore_patterns [EXTRACTED 1.00]

## Communities (30 total, 22 thin omitted)

### Community 0 - "Run Scan Python"
Cohesion: 0.09
Nodes (42): _count_files_recursive(), get_scan_exclusions(), _get_scannerignore_patterns(), get_server_info(), _is_python_target(), _normalize_path(), _parse_json_output(), Load .scannerignore patterns from the target directory, if present.          Loo (+34 more)

### Community 1 - "Report Scan Html"
Cohesion: 0.07
Nodes (34): BaseHTTPMiddleware, MCP Library, MCP Server, MCP Tools, Parallel Scanner Execution, detect_provider(), download_report(), format_results_markdown() (+26 more)

### Community 2 - "Print Extract Scan"
Cohesion: 0.14
Nodes (31): bold(), C, cyan(), dim(), extract_npm_vulns(), extract_pip_vulns(), generate_report(), gray() (+23 more)

### Community 3 - "Upload Endpoint Key"
Cohesion: 0.15
Nodes (17): Allowed Git Hosts, API Key Masking, API Key Toggle, FastAPI Application, Content Security Policy, FastAPI, Uvicorn, Drag-and-Drop Upload (+9 more)

### Community 4 - "Run Mcp Scan"
Cohesion: 0.2
Nodes (12): format_results_markdown(), main(), Run all scans on a project directory. Use quick=True to skip slow scanners., Scan for exposed secrets in project files., Format scan results as a concise markdown summary., Run MCP server over stdio for Claude Desktop., Run MCP server over HTTP/SSE for Claude Desktop (streamable HTTP)., register_tools() (+4 more)

### Community 5 - "Pattern Sanitization Auto"
Cohesion: 0.29
Nodes (7): Auto-Exclusion Pattern, Scanner Exclusions, Output Sanitization Pattern, Output Sanitization, Path Validation Pattern, Path Safety Validator, Security Architecture

### Community 6 - "Html Markdown Inline"
Cohesion: 0.4
Nodes (6): _inline_md(), _md_to_html(), Convert simple markdown to styled HTML page (no external deps)., Process inline markdown formatting., Convert markdown table rows to HTML., _render_table()

### Community 7 - "Deployment Render Docker"
Cohesion: 0.5
Nodes (4): Docker Deployment, Render Deployment, Render Blueprint, Health Check

## Knowledge Gaps
- **99 isolated node(s):** `BaseHTTPMiddleware`, `Validate that a repo URL is safe to clone.`, `Mask an API key for safe logging.`, `Detect LLM provider from API key prefix. Returns (base_url, model, display_name)`, `Call an LLM API to generate an AI summary section.      Auto-detects provider fr` (+94 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **22 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run_scan()` connect `Print Extract Scan` to `Run Scan Python`?**
  _High betweenness centrality (0.186) - this node is a cross-community bridge._
- **Why does `scan_project_stream()` connect `Report Scan Html` to `Run Scan Python`?**
  _High betweenness centrality (0.172) - this node is a cross-community bridge._
- **Why does `scan_python_dependencies()` connect `Run Scan Python` to `Report Scan Html`, `Print Extract Scan`?**
  _High betweenness centrality (0.100) - this node is a cross-community bridge._
- **Are the 3 inferred relationships involving `run_scan()` (e.g. with `scan_npm_dependencies()` and `scan_python_dependencies()`) actually correct?**
  _`run_scan()` has 3 INFERRED edges - model-reasoned connections that need verification._
- **Are the 5 inferred relationships involving `scan_project_stream()` (e.g. with `run_security_scan()` and `run_code_linting()`) actually correct?**
  _`scan_project_stream()` has 5 INFERRED edges - model-reasoned connections that need verification._
- **What connects `BaseHTTPMiddleware`, `Validate that a repo URL is safe to clone.`, `Mask an API key for safe logging.` to the rest of the system?**
  _99 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Run Scan Python` be split into smaller, more focused modules?**
  _Cohesion score 0.09 - nodes in this community are weakly interconnected._