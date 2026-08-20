<h1 align="center">CERT-X-GEN</h1>
<h4 align="center">A Polyglot Execution Engine for Vulnerability Detection</h4>

<p align="center">
Write security checks as real code — Python, Rust, Go, C, Shell, or YAML — and run them reproducibly, at scale.
</p>

<p align="center">
<a href="https://github.com/Bugb-Technologies/cert-x-gen/releases"><img src="https://img.shields.io/github/v/release/Bugb-Technologies/cert-x-gen?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square"></a>
<a href="https://github.com/Bugb-Technologies/cert-x-gen/actions"><img src="https://img.shields.io/github/actions/workflow/status/Bugb-Technologies/cert-x-gen/ci.yml?style=flat-square"></a>
</p>

<p align="center">
<a href="#what-is-cert-x-gen">What is it</a> •
<a href="#two-surfaces">Surfaces</a> •
<a href="#installation">Install</a> •
<a href="#quick-start">Quick Start</a> •
<a href="#templates">Templates</a> •
<a href="https://docs.bugb.io/cxg/">Docs</a> •
<a href="https://github.com/Bugb-Technologies/cert-x-gen-templates">Template Repo</a>
</p>

---


## What is CERT-X-GEN

Modern security scanning has outgrown static templates. Today's vulnerability detection often requires real programming logic, protocol-level control, data processing, and reuse of existing scripts — yet most scanners force everything into YAML-only abstractions.

CERT-X-GEN is a different kind of scanner. It is a **polyglot security execution engine** that treats vulnerability detection as code, not configuration. You write detection logic in the language that fits the problem — CERT-X-GEN handles orchestration, execution, and output.

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

> **A note on execution privileges.** Templates execute as ordinary child processes with the
> invoking user's privileges and full network and filesystem access. Review templates before
> running them. There is no execution sandbox or resource limiting anywhere in cxg — no flag,
> no configuration key, no default. Run cxg inside a container or VM, and as a non-privileged
> user, if you need isolation. See the
> [dependency environments guide](https://docs.bugb.io/cxg/guides/manage-dependency-environments/), whose `cxg sandbox`
> command manages per-language *dependency* environments (not isolation).


---


## Two Surfaces

CERT-X-GEN ships two distinct workflows:

| Surface | Command | What it does |
|---------|---------|--------------|
| **Template scanning** | `cxg scan` | Runs polyglot detection templates against network/host targets (single host, file, CIDR, URL). This is the classic scanner. |
| **AI-driven whitebox pentest** | `cxg pentest` | Ranks guardlink source-code hypotheses against an operator goal, has a local AI CLI write JavaScript probe templates that read the target's source, and executes them in parallel **authenticated** Chromium contexts against a running web app or Electron desktop app. |

The full command set:

| Command | Purpose |
|---------|---------|
| `cxg scan` | Run a polyglot template security scan |
| `cxg pentest` | AI-driven whitebox pentest pipeline (web or Electron) |
| `cxg template` | Manage templates (list, search, info, validate, update) |
| `cxg search` | Search templates (full-text, regex, filters) |
| `cxg ai` | AI-powered template generation |
| `cxg mcp` | Run as an MCP (Model Context Protocol) server for AI agents |
| `cxg sandbox` | Manage per-language dependency environments |
| `cxg config` | Generate / validate / show configuration |
| `cxg update` | Update cxg to the latest released build |
| `cxg server` | REST API server — **not implemented** (returns an error) |
| `cxg version` | Display version information |

Run `cxg <command> --help` for the full reference on any of them.

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

### Cargo (crates.io) — recommended

The quickest cross-platform install if you have a Rust toolchain:

```bash
cargo install cert-x-gen
```

This builds and installs the `cxg` binary into `~/.cargo/bin`. Make sure that directory is on your `PATH`. To upgrade later, run `cargo install cert-x-gen --force` (or use the built-in `cxg update`).

### Homebrew (macOS/Linux)

```bash
brew tap bugb-technologies/cxg
brew install cxg
```

### Quick Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/Bugb-Technologies/cert-x-gen/main/install.sh | bash
```

### Docker

```bash
docker run --rm ghcr.io/bugb-technologies/cert-x-gen:latest --help

# Scan with Docker
docker run --rm ghcr.io/bugb-technologies/cert-x-gen:latest scan --scope example.com
```

### From Source

```bash
git clone https://github.com/Bugb-Technologies/cert-x-gen.git
cd cert-x-gen
make install
```

### From Git (latest main or a specific tag)

Build straight from the repository — useful for unreleased changes or pinning to a tag:

```bash
cargo install --git https://github.com/Bugb-Technologies/cert-x-gen.git
# or pin to a release:
cargo install --git https://github.com/Bugb-Technologies/cert-x-gen.git --tag v1.2.0
```

### Download Binary

Download pre-built binaries from [GitHub Releases](https://github.com/Bugb-Technologies/cert-x-gen/releases/latest):
- `cxg-linux-amd64` — Linux x86_64
- `cxg-linux-arm64` — Linux ARM64
- `cxg-darwin-amd64` — macOS Intel
- `cxg-darwin-arm64` — macOS Apple Silicon
- `cxg-windows-amd64.exe` — Windows x86_64

### Verify Installation

```bash
cxg --version
cxg template update  # Clones the official template library into ~/.cert-x-gen/templates/
```

---

## Quick Start

### Scanning (`cxg scan`)

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

### Whitebox Pentest (`cxg pentest`)

The pentest pipeline drives an authenticated browser (or Electron app), so it needs a captured
session and a guardlink source-code analysis (`whitebox/findings.sarif`) in the codebase.

```bash
# 1. Capture an authenticated session interactively (opens a real browser to log in)
cxg pentest auth --target https://app.example.com --profile admin

# 2. Run the pipeline: rank hypotheses, generate probes with your local AI CLI, execute them
cxg pentest run --codebase ./repo --target https://app.example.com \
  --auth admin --ai --ai-provider claude \
  --goal "test for IDOR in the records and transactions APIs"
```

For CI, capture the session once, export it as a Playwright `storage_state`, then replay it
without a browser:

```bash
cxg pentest auth import --profile pentest --target https://staging.app \
  --storage-state ./pentest.storage.json
cxg pentest auth verify --profile pentest           # exit 0 = alive, non-zero = expired
cxg pentest run --codebase ./repo --target https://staging.app --auth pentest --ci
```

`--ci` (or `CXG_CI=1`) makes a dead/expired session a hard failure (**exit code 5**) at
pre-flight, so a pipeline never silently probes unauthenticated. A profile bundle can also be
materialised from the base64 env var `CXG_AUTH_STATE_<NAME>` and pointed at with `--auth-dir`.
See the [pentest docs](#documentation) for the full pipeline, Electron target support, OAST
modes, and the `report.json` schema.

### Template Operations

```bash
# List available templates
cxg template list

# Search templates
cxg template search redis

# Get template info (by template ID)
cxg template info redis-unauthenticated
```

### Output Formats

`cxg scan` writes reports with `--output-format` (comma-separated for several at once) and
`-o`/`--output` for the destination basename. The output extension is derived from the format —
**any extension you put on `--output` is replaced**, so `--output report.txt --output-format json`
writes `report.json`.

```bash
# JSON output
cxg scan --scope target.com --output-format json -o results

# HTML report
cxg scan --scope target.com --output-format html -o report

# SARIF for CI/CD
cxg scan --scope target.com --output-format sarif -o results

# Several formats at once
cxg scan --scope target.com --output-format json,html,sarif -o report
```

Supported formats: **json, csv, sarif, html, markdown**.

---


## Templates

Runtime templates are **not shipped in this repository**. They are distributed separately in the
template library repo:

**[github.com/Bugb-Technologies/cert-x-gen-templates](https://github.com/Bugb-Technologies/cert-x-gen-templates)**

Fetch them with `cxg template update`, which clones the library into `~/.cert-x-gen/templates/`.
From there the scanner discovers them automatically. (Templates are not auto-downloaded by a bare
`cxg scan` — run `cxg template update`, or pass `--ut` / `--auto-update-templates` on a scan.)

Templates cover multiple languages — Python, Go, C, Rust, Shell, YAML and more — with the exact
inventory maintained in the template repository.

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
- **Composable scans** — mix languages, reuse logic across templates
- **Automation-first** — built for CI, pipelines, and agentic systems

---

## Features

**Execution Engine**
- 12 supported languages (Python, Go, Rust, C, C++, Java, JavaScript, Ruby, Perl, PHP, Shell, YAML)
- Compilation caching for compiled languages
- Parallel template execution with rate limiting

**CLI**
- Unified `--scope` for targets (single, file, CIDR, URL)
- Smart `--templates` selection (glob patterns, tags, severity)
- Multiple output formats (JSON, CSV, SARIF, HTML, Markdown)
- Built-in template management

**Integration**
- Git-based template repositories, updatable with `cxg template update`
- CI/CD friendly (exit codes, SARIF output)
- Configurable via CLI flags and a config file (`--config`)
- MCP server (`cxg mcp`) for AI-agent integration

### AI providers (pentest)

`cxg pentest` generates probes with a local AI CLI or an HTTP API. `--ai-provider` accepts:
`auto | bridge | claude | codex | gemini | anthropic | openai`. The **`bridge`** provider posts
each prompt to `$BUGB_BRIDGE_URL` (with `Authorization: Bearer $BUGB_BRIDGE_TOKEN` when set) and
reads the completion back — an editor/CI integration point rather than a local CLI. When
`--ai-provider auto` is used, the bridge is preferred whenever `$BUGB_BRIDGE_URL` is set.

Findings in `report.json` carry a `threat_id` linking each finding back to the originating
guardlink hypothesis (`null` for AI/mutation-synthesised probes).

---


## Documentation

Full documentation is at **<https://docs.bugb.io/cxg/>**. It is generated against a released
binary, and every command it shows was run and its real output pasted in.

| | |
|---|---|
| [Install cxg](https://docs.bugb.io/cxg/get-started/installation/) | Three install methods, and where templates come from |
| [Run your first scan](https://docs.bugb.io/cxg/get-started/first-scan/) | A real finding on a target you control |
| [Scan a target](https://docs.bugb.io/cxg/guides/scanning-a-target/) | Scope, template selection, output formats, exit codes |
| [Write your first template](https://docs.bugb.io/cxg/guides/write-your-first-template/) | A detection that follows one response to choose its next request |
| [Run a pentest](https://docs.bugb.io/cxg/guides/pentest/) | The whitebox pipeline, auth, OAST, Electron, CI |
| [CLI reference](https://docs.bugb.io/cxg/reference/cli/) | Every command, flag, and default, generated from `--help` |
| [Why polyglot templates](https://docs.bugb.io/cxg/concepts/why-polyglot-templates/) | When a check should be code, and what that costs |
| [Template trust model](https://docs.bugb.io/cxg/concepts/template-trust-model/) | What running a template actually grants it |

### In this repository

Contributor documentation stays here, because it describes the code rather than
the product.

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design and internals |
| [Engine architecture](docs/ENGINE_ARCHITECTURE.md) | How an engine is structured and added |
| [Pentest architecture](pentest/docs/ARCHITECTURE.md) | Pipeline, substrate, and the runtime intelligence layer |
| [Probe templates](pentest/docs/TEMPLATES.md) | The JavaScript probe format and its primitives |
| [Contributing](CONTRIBUTING.md) | How to contribute code and templates |

`pentest/docs/TEMPLATES.md` and `pentest/docs/ARCHITECTURE.md` are referenced by
`cxg pentest run --help` and by the pipeline's own code, so they live with the
code they describe.

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
