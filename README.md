<div align="center">

# 🛡️ Sentinel MCP Scanner

**Security scanner for Model Context Protocol servers**

[![CI](https://github.com/Helixar-AI/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Helixar-AI/sentinel/actions/workflows/ci.yml)
[![GitHub Stars](https://img.shields.io/github/stars/Helixar-AI/sentinel?style=social)](https://github.com/Helixar-AI/sentinel/stargazers)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://pypi.org/project/helixar-sentinel)
[![PyPI](https://img.shields.io/pypi/v/helixar-sentinel?color=blue)](https://pypi.org/project/helixar-sentinel)
[![Marketplace](https://img.shields.io/badge/GitHub%20Action-Marketplace-2088FF?logo=github-actions&logoColor=white)](https://github.com/marketplace/actions/sentinel-mcp-security-scanner)

Sentinel scans MCP server configurations, live endpoints, and Docker containers for security misconfigurations — surfacing findings with severity ratings, remediation guidance, and CI/CD integration.

> **Sentinel detects misconfigurations. For 360° enterprise runtime protection, see [Helixar](https://helixar.ai).**

</div>

---

## Features

- 🔍 **Config scanner** — static analysis of MCP server config files (10 checks)
- 🌐 **Probe scanner** — live endpoint security analysis (8 checks)
- 🐳 **Container scanner** — Docker container/image inspection (8 checks)
- 📋 **26 detection rules** across all modules
- 🎨 **4 output formats** — terminal (Rich), HTML, JSON, SARIF 2.1
- ⚙️ **GitHub Action** — drop-in CI integration with SARIF upload support
- 🚦 **Fail-on threshold** — block PRs on HIGH/CRITICAL findings

---

## Installation

```bash
pip install helixar-sentinel
```

Or from source:

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

# Output as SARIF for GitHub Code Scanning
sentinel config mcp.json --format sarif --output sentinel.sarif.json
```

---

## GitHub Actions

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

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `config` | No | — | Path to MCP server config file |
| `endpoint` | No | — | Live MCP endpoint URL to probe |
| `container` | No | — | Docker container name or image |
| `fail-on` | No | `high` | Minimum severity to fail the build |
| `format` | No | `sarif` | Output format (`terminal`/`json`/`sarif`/`html`) |
| `output` | No | `sentinel.sarif.json` | Report output path |

---

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| Terminal | `--format terminal` (default) | Local development |
| JSON | `--format json` | Custom tooling |
| SARIF | `--format sarif` | GitHub Code Scanning |
| HTML | `--format html` | Stakeholder reports |

---

## Detection Rules

### Config module — 10 rules

| ID | Severity | Check |
|----|----------|-------|
| CFG-001 | 🔴 CRITICAL | No authentication configured |
| CFG-002 | 🔴 CRITICAL | Plaintext secrets in config |
| CFG-003 | 🟠 HIGH | Wildcard tool permissions |
| CFG-004 | 🟠 HIGH | No rate limiting |
| CFG-005 | 🟡 MEDIUM | Debug mode enabled |
| CFG-006 | 🟠 HIGH | No TLS configuration |
| CFG-007 | 🟠 HIGH | Wildcard CORS origin |
| CFG-008 | 🟡 MEDIUM | No input validation |
| CFG-009 | 🟡 MEDIUM | Sensitive data logging |
| CFG-010 | 🔵 LOW | No request timeout |

### Probe module — 8 rules

| ID | Severity | Check |
|----|----------|-------|
| PRB-001 | 🔴 CRITICAL | TLS certificate invalid/expired |
| PRB-002 | 🟠 HIGH | Weak TLS version (< TLS 1.2) |
| PRB-003 | 🔴 CRITICAL | No authentication required |
| PRB-004 | 🟡 MEDIUM | Server version disclosed in headers |
| PRB-005 | 🟡 MEDIUM | Missing security headers |
| PRB-006 | 🟠 HIGH | Tool listing publicly exposed |
| PRB-007 | 🔵 LOW | Verbose error messages |
| PRB-008 | 🟠 HIGH | No rate limiting detected |

### Container module — 8 rules

| ID | Severity | Check |
|----|----------|-------|
| CTR-001 | 🟠 HIGH | Container running as root |
| CTR-002 | 🔴 CRITICAL | Privileged container mode |
| CTR-003 | 🟡 MEDIUM | No CPU/memory resource limits |
| CTR-004 | 🟠 HIGH | Sensitive env vars exposed |
| CTR-005 | 🟡 MEDIUM | Writable root filesystem |
| CTR-006 | 🔵 LOW | No health check configured |
| CTR-007 | 🟡 MEDIUM | Outdated base image |
| CTR-008 | 🟠 HIGH | Dangerous ports exposed |

---

## Fail-on Threshold

```bash
sentinel config mcp.json --fail-on critical   # exit 1 on CRITICAL only
sentinel config mcp.json --fail-on high        # exit 1 on HIGH+ (default)
sentinel config mcp.json --fail-on medium      # exit 1 on MEDIUM+
sentinel config mcp.json --fail-on low         # exit 1 on any finding
```

---

## Adding a New Rule

Rules are data, not code — adding one takes three steps:

**1.** Add to `sentinel/rules/rules.yaml`
**2.** Add a `_check_<key>` method in the relevant module scanner
**3.** Add tests

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

---

## Running Tests

```bash
python -m pytest tests/unit/ -v
python -m pytest tests/ --cov=sentinel --cov-report=html
```

---

## Roadmap

- [ ] `sentinel watch` — continuous monitoring mode
- [ ] Kubernetes manifest scanning
- [ ] JWT algorithm confusion + replay attack probe checks
- [ ] `--diff` flag for regression detection across runs
- [ ] Additional output: JUnit XML for legacy CI systems

---

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

<div align="center">

Built by [Helixar Security Research](https://helixar.ai) &bull; Runtime protection: [helixar.ai](https://helixar.ai)

⭐ **Star this repo** if sentinel is useful to you — it helps others find it.

</div>
