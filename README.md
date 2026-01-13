<h1 align="center">CERT-X-GEN</h1>
<h4 align="center">A Polyglot Execution Engine for Vulnerability Detection</h4>

<p align="center">
Write security checks as real code — Python, Rust, Go, C, Shell, or YAML — and run them safely, reproducibly, and at scale.
</p>

<p align="center">
<a href="https://github.com/Bugb-Technologies/cert-x-gen/releases"><img src="https://img.shields.io/github/v/release/Bugb-Technologies/cert-x-gen?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen/actions"><img src="https://img.shields.io/github/actions/workflow/status/Bugb-Technologies/cert-x-gen/ci.yml?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates"><img src="https://img.shields.io/badge/templates-58-orange?style=flat-square"></a>
</p>

<p align="center">
<a href="#what-is-cert-x-gen">What is it</a> •
<a href="#installation">Install</a> •
<a href="#quick-start">Quick Start</a> •
<a href="#templates">Templates</a> •
<a href="#documentation">Docs</a> •
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates">Template Repo</a>
</p>

---


## What is CERT-X-GEN

Modern security scanning has outgrown static templates. Today's vulnerability detection often requires real programming logic, protocol-level control, data processing, and reuse of existing scripts — yet most scanners force everything into YAML-only abstractions.

CERT-X-GEN is a different kind of scanner. It is a **polyglot security execution engine** that treats vulnerability detection as code, not configuration. You write detection logic in the language that fits the problem — CERT-X-GEN handles orchestration, sandboxing, and output.

**What this means in practice:**

```bash
# Run a Python template for stateful protocol checks
cxg scan --scope 192.168.1.100:25 --templates smtp-open-relay.py

# Run a Go template for high-performance database probing
cxg scan --scope db.example.com:5432 --templates postgresql-default-credentials.go

# Mix multiple languages in one scan
cxg scan --scope targets.txt --templates redis*.py,docker*.go,system*.sh
```

### Highlights

- A **language-agnostic runtime** for vulnerability detection logic
- A **unified execution layer** for security checks across 12 languages
- A **bridge** between research scripts and production scanners
- A scanner **designed for CI, automation, and agentic systems**


---


## Why This Matters

<table>
<tr>
<td width="50%">

**The Problem**

YAML DSLs hit a wall when you need:
- Multi-step protocol conversations
- Binary protocol parsing
- Conditional branching logic
- Performance-critical operations
- Native library access

</td>
<td width="50%">

**The Solution**

CERT-X-GEN runs templates written in:
- **Python** — stateful protocols, data analysis
- **Go** — concurrent operations, binary protocols
- **Rust/C** — maximum performance
- **Shell** — native tool integration
- **YAML** — simple checks, compatibility

</td>
</tr>
</table>

### Real-World Examples

| Scenario | Template | Why It Can't Be YAML |
|----------|----------|---------------------|
| SMTP relay testing | [`smtp-open-relay.py`](https://github.com/Bugb-Technologies/cert-x-gen-templates/blob/main/templates/python/smtp-open-relay.py) | Multi-step conversation: EHLO → MAIL FROM → RCPT TO with branching |
| PostgreSQL auth check | [`postgresql-default-credentials.go`](https://github.com/Bugb-Technologies/cert-x-gen-templates/blob/main/templates/go/postgresql-default-credentials.go) | PostgreSQL wire protocol + MD5 challenge-response |
| SNMP community strings | [`snmp-default-community.sh`](https://github.com/Bugb-Technologies/cert-x-gen-templates/blob/main/templates/shell/snmp-default-community.sh) | Native `snmpwalk` integration |
| VNC no-auth detection | [`vnc-no-auth.c`](https://github.com/Bugb-Technologies/cert-x-gen-templates/blob/main/templates/c/vnc-no-auth.c) | RFB binary protocol handshake |

---


## Installation

### From Source (Recommended)

```bash
git clone https://github.com/Bugb-Technologies/cert-x-gen.git
cd cert-x-gen
make install
```

### Using Cargo

```bash
cargo install --git https://github.com/Bugb-Technologies/cert-x-gen.git
```

### Verify Installation

```bash
cxg --version
cxg template update  # Downloads official templates
```

---

## Quick Start

### Basic Scanning

```bash
# Scan a single target
cxg scan --scope example.com

# Scan with specific ports
cxg scan --scope example.com --ports 22,80,443,3306,5432,6379

# Scan a network range
cxg scan --scope 192.168.1.0/24 --top-ports 100

# Scan targets from a file
cxg scan --scope targets.txt --templates redis*.py
```

### Template Operations

```bash
# List available templates
cxg template list

# Search templates
cxg template search redis

# Validate a template
cxg template validate my-template.py

# Get template info
cxg template info smtp-open-relay.py
```

### Output Formats

```bash
# JSON output
cxg scan --scope target.com --format json -o results.json

# HTML report
cxg scan --scope target.com --format html -o report.html

# SARIF for CI/CD
cxg scan --scope target.com --format sarif -o results.sarif
```

---


## Templates

Templates are maintained in a separate repository for community contributions:

**[github.com/Bugb-Technologies/cert-x-gen-templates](https://github.com/Bugb-Technologies/cert-x-gen-templates)**

| Language | Count | Best For |
|----------|-------|----------|
| Python | 15 | Stateful protocols, HTTP APIs, data processing |
| Go | 5 | Binary protocols, high concurrency |
| C | 5 | Low-level protocols, maximum performance |
| Rust | 4 | Memory-safe performance, async I/O |
| Shell | 5 | Native tool integration, system checks |
| YAML | 24 | Simple HTTP checks, Nuclei compatibility |

Templates auto-download on first scan. Update with `cxg template update`.

### Writing Templates

All templates follow a simple contract:
1. Read `CERT_X_GEN_TARGET_HOST` and `CERT_X_GEN_TARGET_PORT` from environment
2. Perform detection logic
3. Output JSON with findings array

**Python example:**

```python
#!/usr/bin/env python3
# @id: redis-unauth
# @name: Redis Unauthenticated Access  
# @severity: high

import socket, json, os

host = os.environ['CERT_X_GEN_TARGET_HOST']
port = int(os.environ.get('CERT_X_GEN_TARGET_PORT', '6379'))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect((host, port))
sock.send(b'INFO\r\n')
response = sock.recv(4096).decode()

if 'redis_version' in response:
    print(json.dumps({"findings": [{
        "id": "redis-unauth",
        "severity": "high",
        "host": host,
        "port": port
    }]}))
```

---


## Design Principles

- **Code over configuration** — use real languages for real logic
- **Deterministic execution** — same input, same output
- **Sandboxed by default** — templates run with strict resource limits
- **Composable scans** — mix languages, reuse logic across templates
- **Automation-first** — built for CI, pipelines, and agentic systems

---

## Features

**Execution Engine**
- 12 supported languages (Python, Go, Rust, C, C++, Java, JavaScript, Ruby, Perl, PHP, Shell, YAML)
- Sandboxed execution with configurable resource limits
- Compilation caching for compiled languages
- Parallel template execution with rate limiting

**CLI**
- Unified `--scope` for targets (single, file, CIDR, URL)
- Smart `--templates` selection (glob patterns, tags, severity)
- Multiple output formats (JSON, HTML, CSV, Markdown, SARIF)
- Built-in template management and validation

**Integration**
- Git-based template repositories with auto-update
- CI/CD friendly (exit codes, SARIF output)
- Configurable via CLI, config file, or environment variables

---


## Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/USAGE_GUIDE.md) | Comprehensive CLI usage and examples |
| [Architecture](docs/ARCHITECTURE.md) | System design and internals |
| [Engine Guide](docs/ENGINES.md) | Language-specific execution details |
| [Sandbox Guide](docs/SANDBOX_GUIDE.md) | Security model and resource limits |
| [Contributing](CONTRIBUTING.md) | How to contribute code and templates |

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Priority areas:**
- New detection templates (any language)
- Protocol handler improvements
- Documentation and examples

```bash
# Development setup
git clone https://github.com/Bugb-Technologies/cert-x-gen.git
cd cert-x-gen
cargo build
cargo test
```

---

## License

CERT-X-GEN is licensed under [Apache License 2.0](LICENSE).

## Security

Report vulnerabilities to **security@bugb.io**. See [SECURITY.md](SECURITY.md).

---

<p align="center">
<b>Built with Rust</b> · <a href="https://github.com/Bugb-Technologies/cert-x-gen-templates">Templates</a> · <a href="https://github.com/Bugb-Technologies/cert-x-gen/discussions">Discussions</a>
</p>
