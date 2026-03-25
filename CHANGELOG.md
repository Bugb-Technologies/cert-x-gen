# Changelog

All notable changes to CERT-X-GEN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] - 2026-03-25

### Added

**MCP Server (Model Context Protocol)**
- 12-tool MCP server for AI agent integration via `cxg mcp serve`
  - `cxg_search`, `cxg_template_list`, `cxg_template_info`, `cxg_scan`
  - `cxg_template_validate`, `cxg_template_create`, `cxg_template_write`
  - `cxg_template_get_notes`, `cxg_ai_generate`, `cxg_template_test`
  - `cxg_template_stats`, `cxg_template_update`
- `cxg mcp install` — auto-configure 6 AI coding agents (Claude Desktop, Cursor, Windsurf, Cline, Roo Code, Claude Code)

**AI Template Generation**
- `cxg ai generate` — natural-language to template generation (dual-mode: scaffold or full)
- Multi-provider support: Ollama (local-first default), OpenAI, Anthropic, DeepSeek
- `--api-key` flag for session-only cloud provider authentication

**Parameterised Template Metadata**
- 5 new metadata fields for Bravos pipeline routing: `context_vars`, `batch_group`, `confidence`, `execution_mode`, `pipeline_stage`
- `@field:` annotation parsing across all 12 supported languages
- `context` and `batch_group` parameters added to `cxg_scan` MCP tool

**Template CLI Extensions**
- `cxg template search` — search templates by query, language, severity, or tags
- `cxg template pwd` — display template directory paths with existence status
- `cxg template skeleton` — view scaffold template for any supported language
- `cxg template add` — copy a local template file into the user template directory

### Fixed

- Auto-migrate official template repository URL on org rename (`BugB-Tech` → `Bugb-Technologies`)
- Detect remote URL drift during `cxg template update` and re-clone when necessary
- `cargo fmt` formatting in skeleton template error path

### Changed

- Template count updated from 58 to 147 across 9 categories and 12 languages
- MCP server instructions updated to reflect current template count

## [1.0.0] - 2025-01-13

### Added

**Core Engine**
- Polyglot template execution supporting 12 programming languages
  - Interpreted: Python, JavaScript, Ruby, Perl, PHP, Shell
  - Compiled: Rust, C, C++, Go, Java
  - Declarative: YAML (Nuclei-compatible)
- Sandboxed execution with configurable resource limits
- Compilation caching for compiled language templates
- Parallel template execution with rate limiting

**CLI (`cxg`)**
- Unified `--scope` option for target specification (single host, file, CIDR, URL)
- Smart `--templates` selection with glob patterns, tags, and severity filtering
- Template management commands: `list`, `update`, `validate`, `info`, `search`
- Multiple output formats: JSON, HTML, CSV, Markdown, SARIF
- Configuration via CLI flags, config file, or environment variables

**Template System**
- Git-based template repository management with auto-update
- Official templates repository with 58 templates across 6 languages
- Template validation and metadata extraction
- Skeleton templates for all supported languages

**Output & Reporting**
- HTML reports with dark theme (Antigravity style)
- SARIF output for CI/CD integration
- JSON Lines (JSONL) streaming output
- Structured finding format with evidence capture

**Integration**
- Cookie passthrough for authenticated scanning
- Proxy support
- Rate limiting (global, per-host, per-protocol)

### Security
- Sandboxed template execution
- Template signature verification (planned)
- Safe defaults for all operations

---

[Unreleased]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.0.0...v1.1.1
[1.0.0]: https://github.com/Bugb-Technologies/cert-x-gen/releases/tag/v1.0.0
