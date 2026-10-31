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
> running them. cxg provides no OS sandbox, CPU quota, or memory containment. Template
> execution timeouts and the built-in network client's request timeouts are available, but
> they do not isolate template code or constrain its own network clients. Run cxg inside a
> container or VM, and as a non-privileged user, if you need isolation. See the
> [dependency environments guide](https://docs.bugb.io/cxg/guides/manage-dependency-environments/), whose `cxg sandbox`
> command manages per-language *dependency* environments (not isolation).


---


## Two Surfaces

CERT-X-GEN ships two distinct workflows:

| Surface | Command | What it does |
|---------|---------|--------------|
| **Template scanning** | `cxg scan` | Runs polyglot detection templates against network/host targets (single host, file, CIDR, URL) or local CLI binaries (`cli://`). |
| **AI-driven whitebox pentest** | `cxg pentest` | Ranks guardlink source-code hypotheses against an operator goal, has a local AI CLI write JavaScript probe templates that read the target's source, and executes them in anonymous or authenticated Chromium contexts against a running web app or Electron desktop app. Also maps Tauri IPC and capabilities from source, with optional in-process command proof. |

The full command set:

| Command | Purpose |
|---------|---------|
| `cxg scan` | Run a polyglot template security scan |
| `cxg build` | Build a compiled target with sanitizer instrumentation, so a scan can earn its verdict |
| `cxg pentest` | Whitebox pentest pipeline (web, Electron, or Tauri) |
| `cxg template` | Manage templates (list, search, info, validate, update) |
| `cxg search` | Search templates (full-text, regex, filters) |
| `cxg ai` | AI-powered template generation |
| `cxg mcp` | Run as an MCP (Model Context Protocol) server for AI agents |
| `cxg sandbox` | Manage per-language dependency environments |
| `cxg config` | Generate / validate / show configuration |
| `cxg update` | Update a directly installed cxg to the latest release (see [Updating](#updating)) |
| `cxg server` | REST API server — **not implemented** (returns an error) |
| `cxg version` | Display version information |

For everyday code changes, use the [GuardLink developer loop](#guardlink-developer-loop):
translate the relevant annotations into scanner templates, review and validate them, then
execute selected tests. Translation is authoring only; it is separate from the deeper
browser/runtime pentest and creates no Bravos ledger or managed approval record.

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

This builds and installs the `cxg` binary into `~/.cargo/bin`. Make sure that directory is on your `PATH`. To upgrade later, run `cargo install cert-x-gen --force`.

Homebrew, crates.io and container binary upgrades refresh the per-user pentest
pipeline offline on the first pentest action. Previous files, including local
edits, are retained under `~/.cert-x-gen/pentest-backups/`. Use
`cxg pentest status --json` to inspect freshness or `cxg pentest update` to refresh
explicitly. Source-derived installs require `update --from-embedded` to opt in.
Upgrade between runs when migrating from older clients without execution leases.
Python dependencies and browsers still require explicit setup; see the
[pentest upgrade guide](pentest/README.md#pipeline-upgrades-and-status).

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
cargo install --git https://github.com/Bugb-Technologies/cert-x-gen.git --tag v1.7.0
```

### Download Binary

Download pre-built binaries from [GitHub Releases](https://github.com/Bugb-Technologies/cert-x-gen/releases/latest):
- `cxg-linux-amd64` — Linux x86_64
- `cxg-linux-arm64` — Linux ARM64
- `cxg-darwin-amd64` — macOS Intel
- `cxg-darwin-arm64` — macOS Apple Silicon
- `cxg-windows-amd64.exe` — Windows x86_64

### Updating

`cxg update` replaces a directly installed binary (the install script, a downloaded
release binary, or a previous `cxg update`) with the latest release, after checking it
against the release's `SHA256SUMS`. `cxg update --check` only reports whether a newer
release exists; `--version vX.Y.Z` installs a specific release; `--yes` skips the prompt.

A cxg that a package manager owns is left alone: `cxg update` prints the manager's own
command and exits with status 3, because replacing the file behind the manager's back
leaves it believing the old version is installed. Pass `--force` to replace it anyway.

| Installed by | Upgrade with |
|--------------|--------------|
| Homebrew | `brew upgrade cxg` |
| `cargo install` | `cargo install cert-x-gen --force` |
| Docker image | `docker pull ghcr.io/bugb-technologies/cert-x-gen:latest` |

`cxg update` in 1.5.0 and 1.6.0 fails on a macOS Homebrew install with "No such file or
directory (os error 2)". Those releases run their own updater, so upgrade them once
through Homebrew (or a fresh download); later releases answer as above.

### Verify Installation

```bash
cxg --version
cxg template update  # Clones the official template library into ~/.cert-x-gen/templates/
```

---

## Quick Start

### GuardLink developer loop

Keep security annotations current with the code in the same change. Validate/lint the
annotations, then use `guardlink translate` with instructions or feature selection scoped
to that change. Review the generated code and its target, identity, and proof requirements;
translation generates tests and does not execute them or require a browser session.

For scanner templates written under `.guardlink/cxg-templates/`:

```bash
# Static validation of the reviewed output directory
cxg template validate .guardlink/cxg-templates/

# Execute one reviewed template against an authorized target
cxg scan --scope http://127.0.0.1:8080 \
  --template-dir .guardlink/cxg-templates/ --templates YOUR_REVIEWED_TEMPLATE_ID
```

Use the repository's configured runner for tests authored for that runner. Retain useful
tests as regression coverage, including after a fix removes the original translation
candidate. Before opening or updating a pull request, run the repository's root `security/`
suite with its configured runner; report missing prerequisites, failures, skips, or an
absent suite explicitly. Check execution coverage and evidence as well as the exit code.
An independent result does not create a Bravos ledger verdict or approval record.

The [whitebox pentest](#whitebox-pentest-cxg-pentest) below is the deeper source-aware
browser/runtime route. Its JavaScript `cxgProbe` templates have a different contract from
scanner templates; `cxg pentest run --template-dir` is not the scanner-directory command.

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

The web/Electron pentest pipeline uses a running target and GuardLink source-code analysis
(`whitebox/findings.sarif`) in the codebase. Omit `--auth` for a first-class anonymous run;
authenticated checks require captured identities. Missing required identities are recorded
as not run, not as refuted. Tauri source mapping needs no captured session or live target;
see the [Tauri guide](pentest/README.md#tauri-source-map-and-in-process-proof).

```bash
# 1. Capture an authenticated session interactively (opens a real browser to log in)
cxg pentest auth --target https://app.example.com --profile admin

# 2. Run the pipeline: rank hypotheses, generate probes with your local AI CLI, execute them
cxg pentest run --codebase ./repo --target https://app.example.com \
  --auth admin --ai --ai-provider claude \
  --goal "test for IDOR in the records and transactions APIs"
```

For authenticated web checks in CI, capture the session once and export it as Playwright
`storage_state`. Importing that state needs no interactive browser; the pentest still runs
browser contexts:

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

### Testing CLI binaries and Tauri apps

For a **local CLI binary**, fetch the detection library and select the CLI Security
Baseline pack explicitly (default repository configuration):

```bash
cxg template update
cxg scan --scope cli:///absolute/path/to/my-tool \
  --template-dir ~/.cert-x-gen/templates/official/templates/cli-baseline \
  --require-instrumentation
```

The [CLI Security Baseline templates](https://github.com/Bugb-Technologies/cert-x-gen-templates/tree/main/templates/cli-baseline)
live in the separate detection-template repository; this repository's `templates/`
contains skeletons. Probe templates can consume structured argv, stdin, seed inputs
and target environment. The instrumentation preflight records unsupported checks as
skipped; templates with build-independent oracles can still run on interpreted CLIs.
See the [CLI usage guide](docs/USAGE_GUIDE.md#testing-a-local-cli-binary) for inputs,
oracles and build options.

For a **Tauri app**, map the Rust IPC surface and correlate it with the GuardLink
threat model, without launching the app:

```bash
cxg pentest run --target-type tauri --codebase /path/to/app-repo
# Opt in to building and exercising commands in process:
cxg pentest run --target-type tauri --codebase /path/to/app-repo --tauri-prove
```

The default report carries `enumerated_not_live_probed`: commands and capability
grants are source facts, and empty findings do not mean the app is safe. The optional
proof uses Tauri's test runtime to exercise command dispatch and handler logic; it
does not drive a live webview. See the [Tauri usage guide](docs/USAGE_GUIDE.md#testing-a-tauri-app)
for prerequisites and the [pentest guide](pentest/README.md#tauri-source-map-and-in-process-proof)
for evidence and coverage limits.

### Writing Templates

Scanner templates follow a simple contract:

1. Read `CERT_X_GEN_TARGET_HOST` and `CERT_X_GEN_TARGET_PORT` from the environment
2. Perform detection logic
3. Write a JSON findings array (`[...]`) or an object containing it (`{"findings": [...]}`)
   to stdout. Use `[]` or `{"findings": []}` for a completed check with no finding; send
   diagnostics to stderr and fail on execution errors. The scanner also accepts empty
   stdout as no findings, but explicit empty JSON makes the output contract clear.

These are scanner templates for `cxg scan`, not the browser pentest's `cxgProbe` contract.

A template can also drive a **local binary** rather than a network host
(`cxg scan --scope cli:///path/to/binary`), take its probe input from cxg
(`--arg`, `--stdin-file`, `--input`, `--target-env`), and declare its own
verdict so a refutation is recorded rather than inferred. Passing
`--require-instrumentation` makes cxg skip the templates a build could not
have shown the defect for, instead of reporting a refutation it did not earn;
templates whose oracles work on any build (`exit`, `signal`, `timeout`,
`exception`) still run. Build an instrumented target with
[`cxg build --instrument`](#two-surfaces), or declare one you built yourself
with `cxg scan --instrumented-manifest <path>`. The full contract is in
[`docs/ENGINE_ARCHITECTURE.md`](docs/ENGINE_ARCHITECTURE.md#the-probe-contract).
Note that `CERT_X_GEN_TARGET_PORT` is meaningless when `CERT_X_GEN_TARGET_KIND`
is `cli` — ignore it there.

**Python example:** save as `redis-unauth.py`. It uses only the Python standard library,
closes the socket, and emits an empty array when the response does not show unauthenticated
Redis INFO access. A connection or read error fails the check instead of becoming a negative.

```python
#!/usr/bin/env python3
# @id: redis-unauth
# @name: Redis Unauthenticated Access
# @author: CERT-X-GEN contributors
# @severity: high
# @description: Detect unauthenticated access to Redis INFO.
# @tags: redis,unauthenticated,network
# @cwe: CWE-306

import json
import os
import socket
import sys


def main():
    host = os.environ["CERT_X_GEN_TARGET_HOST"]
    port = int(os.environ.get("CERT_X_GEN_TARGET_PORT", "6379"))

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(b"INFO\r\n")
        response = sock.recv(4096).decode("utf-8", errors="replace")

    findings = []
    if "redis_version:" in response:
        findings.append({
            "id": "redis-unauth",
            "template_id": "redis-unauth",
            "template_name": "Redis Unauthenticated Access",
            "host": host,
            "matched_at": f"{host}:{port}",
            "title": "Redis INFO accessible without authentication",
            "severity": "high",
            "description": "The server returned Redis version information to an unauthenticated INFO request.",
            "evidence": {"response": response},
        })
    print(json.dumps(findings))


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        print(f"Redis check failed: {exc}", file=sys.stderr)
        sys.exit(1)
```

```bash
cxg template validate redis-unauth.py
# Execute only against a Redis instance you are authorized to test
cxg scan --scope 127.0.0.1:6379 --templates ./redis-unauth.py
```

---


## Design Principles

- **Code over configuration** — use real languages for real logic
- **Repeatable execution** — reuse template code and explicit inputs; live target, session, and network state can change results
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

The Rust CLI advertises `--ai-provider` in this order:
`auto | bridge | claude | codex | gemini | crush | anthropic | openai`; its default is
`claude`. For the default JavaScript pentest path, select an installed `claude`, `codex`,
`gemini`, or `crush` CLI explicitly. The current JS generator does not resolve `auto` or
use HTTP/bridge providers, and the bundled Python argument parser rejects explicit
`bridge`. The direct Python entry point defaults to `auto`, so pass a supported CLI there
too for JS generation.

The legacy Python provider selector's `auto` order is bridge → Claude → Codex → Gemini →
Anthropic API → OpenAI API; `crush` is never auto-picked. Its bridge posts prompts to
`$BUGB_BRIDGE_URL`, using `Authorization: Bearer $BUGB_BRIDGE_TOKEN` when set. See the
[pentest provider reference](pentest/README.md#ai-provider) for the Crush configuration
trust boundary and the distinction between advertised options and execution paths.

Pentest findings in `report.json` carry the identity of the exposure they tested — the annotation's
`{file, line}`, its `asset` and `threat`, and guardlink's `threat_id` — so
`guardlink hypothesis confirm --from-scan report.json` joins each confirmation straight back to
the claim it settles. A probe with no originating guardlink exposure carries none and is left
unmatched (an AI-synthesised template, or one generated for a hypothesis cxg minted itself from
Electron IPC or `--discover-routes`); a mutated retry inherits its parent's. See
[pentest architecture](pentest/docs/ARCHITECTURE.md) § "The exposure identity a finding carries"
for the join, its measured bounds, and the `identity_withdrawn` record. This is not a
promise that arbitrary scanner templates carry those identities. Review import results:
unmatched or ambiguous evidence is not recorded confirmation, and a standalone cxg result
is not a Bravos-managed ledger verdict.

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

Report vulnerabilities to **security@bugb.report**. See [SECURITY.md](SECURITY.md).

---

<p align="center">
<b>Built with Rust</b> · <a href="https://github.com/Bugb-Technologies/cert-x-gen-templates">Templates</a> · <a href="https://github.com/Bugb-Technologies/cert-x-gen/discussions">Discussions</a>
</p>
