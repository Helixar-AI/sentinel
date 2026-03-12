# sentinel

**MCP security scanner by Helixar**

sentinel scans Model Context Protocol (MCP) server configurations, live endpoints, and Docker containers for security misconfigurations. It surfaces findings with severity ratings, remediation guidance, and integrates into CI/CD pipelines via GitHub Actions.

> **sentinel detects misconfigurations. For runtime protection, see [Helixar](https://helixar.ai).**

---

## Features

- **Config scanner** — static analysis of MCP server config files (10 checks)
- **Probe scanner** — live endpoint security analysis (8 checks)
- **Container scanner** — Docker container/image inspection (8 checks)
- **26 detection rules** across all modules
- **4 output formats** — terminal (Rich), HTML, JSON, SARIF 2.1
- **GitHub Action** — drop-in CI integration with SARIF upload support
- **Fail-on threshold** — block PRs on HIGH/CRITICAL findings
- 👁️ **Watch mode** — continuous monitoring with configurable interval and change detection

---

## Installation

```bash
pip install helixar-sentinel
```

Or install from source:

```bash
git clone https://github.com/Helixar-AI/sentinel
cd sentinel
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Scan a config file
sentinel config mcp.json

# Probe a live endpoint
sentinel probe https://your-mcp-server.example.com

# Inspect a Docker container
sentinel container my-mcp-image:latest

# Run all scanners in one pass
sentinel scan --config mcp.json --endpoint https://mcp.example.com --container my-image:latest

# Continuously monitor — re-scan every 60s, alert on change
sentinel watch --config mcp.json --endpoint https://mcp.example.com --interval 60 --on-change

# Output as SARIF for GitHub Code Scanning
sentinel config mcp.json --format sarif --output sentinel.sarif.json
```

---

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| Terminal | `--format terminal` (default) | Local development |
| JSON | `--format json` | Custom tooling |
| SARIF | `--format sarif` | GitHub Code Scanning |
| HTML | `--format html` | Stakeholder reports |

---

## CI Integration

### GitHub Actions

```yaml
- uses: Helixar-AI/sentinel@v1
  with:
    config: ./mcp.json
    endpoint: ${{ secrets.MCP_ENDPOINT }}
    container: my-mcp-image:latest
    fail-on: high
    format: sarif
    output: sentinel.sarif.json

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif.json
```

### Fail-on threshold

```bash
# Exit 1 if any HIGH or CRITICAL findings (default)
sentinel config mcp.json --fail-on high

# Stricter: exit 1 on MEDIUM+
sentinel config mcp.json --fail-on medium

# Lenient: exit 1 on CRITICAL only
sentinel config mcp.json --fail-on critical
```

---

## Detection Rules

### Config module (10 rules)

| ID | Severity | Check |
|----|----------|-------|
| CFG-001 | CRITICAL | No authentication configured |
| CFG-002 | CRITICAL | Plaintext secrets in config |
| CFG-003 | HIGH | Wildcard tool permissions |
| CFG-004 | HIGH | No rate limiting |
| CFG-005 | MEDIUM | Debug mode enabled |
| CFG-006 | HIGH | No TLS configuration |
| CFG-007 | HIGH | Wildcard CORS origin |
| CFG-008 | MEDIUM | No input validation |
| CFG-009 | MEDIUM | Sensitive data logging |
| CFG-010 | LOW | No request timeout |

### Probe module (8 rules)

| ID | Severity | Check |
|----|----------|-------|
| PRB-001 | CRITICAL | TLS certificate invalid/expired |
| PRB-002 | HIGH | Weak TLS version (< TLS 1.2) |
| PRB-003 | CRITICAL | No authentication required |
| PRB-004 | MEDIUM | Server version disclosed in headers |
| PRB-005 | MEDIUM | Missing security headers |
| PRB-006 | HIGH | Tool listing publicly exposed |
| PRB-007 | LOW | Verbose error messages |
| PRB-008 | HIGH | No rate limiting detected |

### Container module (8 rules)

| ID | Severity | Check |
|----|----------|-------|
| CTR-001 | HIGH | Container running as root |
| CTR-002 | CRITICAL | Privileged container mode |
| CTR-003 | MEDIUM | No CPU/memory resource limits |
| CTR-004 | HIGH | Sensitive env vars exposed |
| CTR-005 | MEDIUM | Writable root filesystem |
| CTR-006 | LOW | No health check configured |
| CTR-007 | MEDIUM | Outdated base image |
| CTR-008 | HIGH | Dangerous ports exposed |

---

## Adding a New Rule

Rules are data, not code. Adding a rule takes three steps:

**1. Add to `sentinel/rules/rules.yaml`:**
```yaml
- id: CFG-011
  module: config
  severity: HIGH
  check_key: no_egress_filter
  title: No egress filtering configuration found
  rationale: Without egress filtering, MCP tools can make arbitrary outbound connections.
  remediation: Add an egress_filter block specifying allowed outbound destinations.
  reference: net-003
```

**2. Add detection logic in the appropriate module scanner.**

**3. Add a test.**

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

---

## Running Tests

```bash
# All unit tests
python -m pytest tests/unit/ -v

# With coverage
python -m pytest tests/unit/ --cov=sentinel --cov-report=html
```

---

## Roadmap (v0.2.0)

- `sentinel watch` — continuous monitoring mode
- Kubernetes manifest scanning
- Additional probe checks: JWT algorithm confusion, replay attacks
- `--diff` flag: compare scan results across runs
- Integration test suite

---

## License

MIT — see [LICENSE](LICENSE)

---

*sentinel by [Helixar Security Research](https://helixar.ai) · Runtime protection: [helixar.ai](https://helixar.ai)*
