<p align="center">
  <h1 align="center">CERT-X-GEN</h1>
  <p align="center">
    <b>The Polyglot Security Scanner</b><br>
    Write vulnerability detection templates in 12 programming languages
  </p>
</p>

<p align="center">
  <a href="https://github.com/Bugb-Technologies/cert-x-gen/releases"><img src="https://img.shields.io/github/v/release/Bugb-Technologies/cert-x-gen?style=flat-square" alt="Release"></a>
  <a href="https://github.com/Bugb-Technologies/cert-x-gen/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square" alt="License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.70%2B-orange?style=flat-square" alt="Rust"></a>
  <a href="https://github.com/Bugb-Technologies/cert-x-gen/actions"><img src="https://img.shields.io/github/actions/workflow/status/Bugb-Technologies/cert-x-gen/ci.yml?style=flat-square" alt="CI"></a>
</p>

<p align="center">
  <a href="#-why-cert-x-gen">Why CERT-X-GEN?</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-supported-languages">Languages</a> •
  <a href="#-documentation">Docs</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## 🎯 Why CERT-X-GEN?

Traditional vulnerability scanners limit you to YAML-only templates. **CERT-X-GEN breaks this barrier** by letting you write security templates in **12 programming languages** — Python, JavaScript, Rust, C, C++, Go, Java, Ruby, Perl, PHP, Shell, and YAML.

**Write templates in the language you know. Solve problems that YAML can't.**

```bash
# Run a Python template
cert-x-gen scan --scope example.com --templates redis-check.py

# Run a C template for high-performance scanning  
cert-x-gen scan --scope 192.168.1.0/24 --templates network-probe.c

# Mix languages in the same scan
cert-x-gen scan --scope target.com --template-language python,rust,yaml
```

### When to Use CERT-X-GEN

| Use Case | Why CERT-X-GEN Wins |
|----------|---------------------|
| Complex detection logic | Use Python/Rust instead of wrestling with YAML DSL |
| High-performance scanning | Write templates in C/Rust for maximum speed |
| Existing codebases | Integrate your Python/Go security scripts directly |
| Custom protocols | Full socket access in any compiled language |
| Data processing | Use pandas, numpy, or any library you need |


## ✨ Key Features

- **🌐 12 Languages** — Python, JavaScript, Rust, C, C++, Go, Java, Ruby, Perl, PHP, Shell, YAML
- **⚡ High Performance** — Built in Rust with async execution and compilation caching
- **🔒 Sandboxed Execution** — Safe template execution with resource limits
- **🤖 AI-Powered** — Generate templates from natural language descriptions
- **📦 Smart CLI** — Unified `--scope`, `--ports`, `--templates` options that auto-detect input types
- **🔄 Git Integration** — Sync templates from Git repositories
- **📊 Multiple Outputs** — JSON, CSV, SARIF, HTML, Markdown

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Bugb-Technologies/cert-x-gen.git
cd cert-x-gen

# Build and install
make install

# Or with cargo directly
cargo install --path .
```

### Your First Scan

```bash
# Basic scan
cert-x-gen scan --scope example.com

# Scan with specific templates
cert-x-gen scan --scope example.com --templates redis-unauthenticated

# Scan with port specification
cert-x-gen scan --scope example.com --ports 80,443,8080

# Scan a CIDR range
cert-x-gen scan --scope 192.168.1.0/24 --top-ports 100
```

### Template Search

```bash
# Search for templates
cert-x-gen search --query "redis"

# Filter by language and severity
cert-x-gen search --language python --severity critical

# List all templates
cert-x-gen template list
```


## 🛠 Supported Languages

### Interpreted Languages
| Language | Extension | Runtime | Best For |
|----------|-----------|---------|----------|
| Python | `.py` | python3 | HTTP APIs, data processing, complex logic |
| JavaScript | `.js` | node | Web scanning, JSON manipulation |
| Ruby | `.rb` | ruby | Rapid prototyping, elegant syntax |
| Perl | `.pl` | perl | Text processing, regex-heavy checks |
| PHP | `.php` | php | Web application testing |
| Shell | `.sh` | bash | System commands, quick scripts |

### Compiled Languages
| Language | Extension | Compiler | Best For |
|----------|-----------|----------|----------|
| Rust | `.rs` | rustc | Maximum performance, memory safety |
| C | `.c` | gcc/clang | Low-level protocols, speed-critical |
| C++ | `.cpp` | g++/clang++ | Complex systems, OOP patterns |
| Go | `.go` | go | Concurrency, network operations |
| Java | `.java` | javac | Enterprise libraries, portability |

### Declarative
| Language | Extension | Engine | Best For |
|----------|-----------|--------|----------|
| YAML | `.yaml` | Built-in | Simple checks, Nuclei compatibility |

## 📝 Writing Templates

All templates follow a simple pattern: read environment variables, perform checks, output JSON.

### Python Example

```python
#!/usr/bin/env python3
# @id: redis-unauth
# @name: Redis Unauthenticated Access
# @severity: high

import socket
import json
import os

def main():
    host = os.getenv('CERT_X_GEN_TARGET_HOST')
    port = int(os.getenv('CERT_X_GEN_TARGET_PORT', '6379'))
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.send(b'INFO\r\n')
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        
        if 'redis_version' in response:
            print(json.dumps({
                "findings": [{
                    "id": "redis-unauth",
                    "name": "Redis Unauthenticated Access",
                    "severity": "high",
                    "evidence": {"response": response[:500]}
                }]
            }))
    except Exception:
        pass
    finally:
        sock.close()

if __name__ == "__main__":
    main()
```


### YAML Example (Nuclei-Compatible)

```yaml
id: http-server-header
info:
  name: HTTP Server Header Detection
  author: cert-x-gen
  severity: info
  tags:
    - http
    - recon

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        part: header
        regex:
          - "Server: .+"
    extractors:
      - type: regex
        part: header
        regex:
          - "Server: (.+)"
```

## 🤖 AI Template Generation

Generate templates from natural language using local or cloud LLMs:

```bash
# Configure AI (supports Ollama, OpenAI, Anthropic, DeepSeek)
cert-x-gen ai setup

# Generate a template
cert-x-gen ai generate "detect exposed MongoDB without authentication" --language python

# Check provider status
cert-x-gen ai status
```

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/USAGE_GUIDE.md) | Comprehensive usage examples |
| [Architecture](docs/ARCHITECTURE.md) | System design and internals |
| [Engines](docs/ENGINES.md) | Language-specific documentation |
| [Contributing](docs/CONTRIBUTING.md) | How to contribute |
| [Sandbox](docs/SANDBOX_GUIDE.md) | Secure execution environment |


## 🔧 Configuration

CERT-X-GEN can be configured via:

1. **CLI flags** — Highest priority
2. **Config file** — `cert-x-gen.yaml`
3. **Environment variables** — For secrets and CI/CD

```bash
# Generate a config file
cert-x-gen config generate --output cert-x-gen.yaml

# Use a config file
cert-x-gen scan --config cert-x-gen.yaml --scope example.com
```

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

### Quick Contribution Guide

```bash
# Fork and clone
git clone https://github.com/Bugb-Technologies/cert-x-gen.git

# Create a branch
git checkout -b feature/my-feature

# Make changes and test
cargo test
cargo clippy

# Submit a PR
```

### Template Contributions

We especially welcome new security templates! Templates can be in any of the 12 supported languages.

## 📜 License

CERT-X-GEN is licensed under the [Apache License 2.0](LICENSE).

## 🔒 Security

Found a security issue? Please report it responsibly. See [SECURITY.md](SECURITY.md).

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) 🦀
- Inspired by the security research community
- Template format compatible with [Nuclei](https://github.com/projectdiscovery/nuclei)

---

<p align="center">
  <b>Ready to scan smarter?</b><br>
  <code>cargo install cert-x-gen</code>
</p>
