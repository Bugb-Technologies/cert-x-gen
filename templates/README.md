# Template Skeletons

This directory contains **skeleton templates** that are embedded into the `cxg` binary at compile time.

These skeletons are used by:
- `cxg template create` - Scaffold new templates in any of the 12 supported languages
- `cxg ai generate` - Provide format guidance to LLMs when generating templates

## In-tree packs

| Directory | What it is |
|---|---|
| `skeleton/` | The per-language skeletons described above |
| `cli-baseline/` | **CLI Security Baseline** — fourteen black-box checks for a command-line tool, plus their shared probe library. See [`cli-baseline/README.md`](cli-baseline/README.md) |

`cli-baseline/` is the one detection pack that lives here rather than in the
templates repository below, because it is the reference implementation of a
published specification and this repository's own test suite proves it: every
class must confirm on a flawed synthetic twin and refute on the fixed one
(`cargo test --test cli_baseline_pack`). A pack whose correctness is a build
gate has to ship with the build.

## Detection Templates

Detection templates (the actual security checks) are maintained in a separate repository:

**📦 [cert-x-gen-templates](https://github.com/Bugb-Technologies/cert-x-gen-templates)**

### Getting Templates

```bash
# Auto-download on first scan
cxg scan --scope example.com

# Manual download/update
cxg template update

# Check template status
cxg template list
```

### For Developers

```bash
# Clone the templates repo
git clone https://github.com/Bugb-Technologies/cert-x-gen-templates.git

# Use local templates for development
cxg scan --scope example.com --template-dir /path/to/cert-x-gen-templates/templates
```

## Skeleton Files

| File | Language | Used For |
|------|----------|----------|
| `python-template-skeleton.py` | Python | AI generation, scaffolding |
| `javascript-template-skeleton.js` | JavaScript | AI generation, scaffolding |
| `rust-template-skeleton.rs` | Rust | AI generation, scaffolding |
| `c-template-skeleton.c` | C | AI generation, scaffolding |
| `cpp-template-skeleton.cpp` | C++ | AI generation, scaffolding |
| `go-template-skeleton.go` | Go | AI generation, scaffolding |
| `java-template-skeleton.java` | Java | AI generation, scaffolding |
| `ruby-template-skeleton.rb` | Ruby | AI generation, scaffolding |
| `perl-template-skeleton.pl` | Perl | AI generation, scaffolding |
| `php-template-skeleton.php` | PHP | AI generation, scaffolding |
| `shell-template-skeleton.sh` | Shell/Bash | AI generation, scaffolding |
| `yaml-template-skeleton.yaml` | YAML | AI generation, scaffolding |

The `*-ai-notes.md` files provide additional context for AI template generation.
