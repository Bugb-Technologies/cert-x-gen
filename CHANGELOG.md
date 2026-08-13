# Changelog

All notable changes to CERT-X-GEN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2026-08-13

### Added

**Desktop application pentesting**
- `cxg pentest run --target-type electron` — launch, isolate, and probe Electron desktop
  applications. cxg starts N isolated app instances (via `--app-cmd` or `--app-binary`),
  drives their renderers over CDP, and additionally probes IPC channels, renderer security
  configuration, and local data at rest. Add `--host-scan-path` to also scan an existing
  installation directory. Tauri is explicitly **unsupported** — it exposes no CDP endpoint on
  macOS or Linux.

**Out-of-band (OAST) callback confirmation**
- `--oast-interactsh [<server>]` — cxg registers an interactsh session it **owns** and polls it,
  so a callback becomes a genuine `confirmed=true` finding with the interaction recorded as
  evidence. This is different from `--oast <host>`, which only **injects** a callback URL that
  cxg **cannot read back** (e.g. Burp Collaborator or a canary you host): under `--oast`, blind
  probes (SSRF, blind SQLi/XXE/cmd-injection) fall back to status-code and timing heuristics and
  findings stay **unconfirmed** — reading the callback is the operator's job, in their own
  tooling. The two flags **conflict at the CLI level deliberately**: two canaries would leave
  "was this confirmed?" with no single answer per finding.

**Crash recovery for desktop targets**
- `--no-restart` — do not relaunch a desktop target that dies mid-scan (the run ends with a
  truncation caveat and exit code 3).
- `--stall-timeout <secs>` — idle-time bound that catches a frozen app (electron only).
- `--template-timeout <secs>` — absolute per-template dispatch ceiling (a backstop).

**Non-interactive CI authentication**
- `cxg pentest auth import` — write an auth profile from a session captured once and exported as
  a Playwright `storage_state`, with no browser. The state can come from a file, from stdin
  (`--storage-state -`), or from the base64 environment variable `CXG_AUTH_STATE_<NAME>`.
- `cxg pentest auth verify` — liveness-check a saved session (exit 0 alive / non-zero dead)
  before a run spends any AI budget.
- `cxg pentest run --ci` (also enabled by `CXG_CI=1`) — a dead or expired auth session becomes a
  hard failure with **exit code 5** at pre-flight, so a pipeline never silently probes
  unauthenticated.
- `--auth-dir <dir>` — read/write auth profiles from a directory other than `~/.cert-x-gen/auth`,
  so CI can restore a bundle of imported profiles and point the run at it.

**AI generation**
- `bridge` AI provider — posts each prompt to `$BUGB_BRIDGE_URL` (with
  `Authorization: Bearer $BUGB_BRIDGE_TOKEN` when set) and reads the completion back; an
  editor/CI integration point rather than a local CLI. It is preferred first by
  `--ai-provider auto` whenever `$BUGB_BRIDGE_URL` is set.

**Reporting**
- `threat_id` on findings in `report.json`, linking each finding back to the originating
  guardlink hypothesis (`null` for AI- or mutation-synthesised probes).
- `review_only_threats` in `report.json` (electron): routeless guardlink threats that have no IPC
  channel to test, surfaced for manual review rather than silently dropped.
- Engine-stamped actor provenance — every request now records which captured identity issued it,
  which feeds cross-identity (IDOR / privilege-escalation) triage in the report and audit log.

**Templates**
- `@requires_capability` template header — a probe declares a substrate capability it needs; the
  engine skips any template whose capability the running substrate does not provide, instead of
  recording an undefined-namespace error as a refutation.

**Environment**
- `CXG_NO_NAG` — opt out of the occasional one-line post-scan GitHub-star request (which prints
  only on an interactive terminal and at most once a week).

### Changed
- `--help` restructured into functional groups, with a two-tier split: `-h` shows one terse line
  per flag, `--help` shows the full explanation. `cxg scan -h` went from **375 lines to 95**.
- The ASCII banner is now suppressed whenever stdout is **not** a terminal. `cxg --version` is a
  single, parseable line, and piped output is clean — previously the banner corrupted
  `cxg search --format json | jq`. Explicit overrides remain: `CXG_NO_BANNER`, `--quiet`/`-q`.
- Configuration sections are now optional. A partial config file loads, with omitted sections and
  omitted keys taking their compiled-in defaults.
- A configuration file that still contains a `sandbox` section **still loads**. cxg now prints
  a warning on load, and `cxg config validate` reports the file as loadable-with-obsolete-sections
  rather than valid, stating that the settings never took effect and that template execution is
  not confined. Silently ignoring the keys would leave operators believing they are hardened.
- `cxg sandbox` — the command that manages per-language dependency environments — is unaffected
  and unchanged in behaviour. Its help text and docs no longer describe it as providing
  "isolation" or "security": it separates packages, not privileges.
- A started Docker environment with `auto_start` no longer implies the running command is
  contained by it. cxg now says explicitly that the command executes on the host; use
  `cxg sandbox enter` to work inside the container.
- `docs/SANDBOX_GUIDE.md` renamed to `docs/DEPENDENCY_ENVIRONMENTS.md`, matching what it
  documents.

### Fixed
- `cert-x-gen.example.yaml` now loads through the config parser. It previously failed to load on a
  required field that had no default; a regression test now loads it on every build.
- Fewer false "confirmed" pentest findings: the empty-evidence guard no longer mistakes a finding
  carrying only bookkeeping keys for one that the AI confirmed with real evidence.
- Documentation was aligned with actual behaviour across `README.md` and the `--help` tree — false
  and stale claims were removed or corrected (see Notes below).

### Removed

**The `sandbox` configuration section, which never took effect.**

- Removed the `sandbox` section from the configuration schema: `sandbox.enabled`,
  `sandbox.memory_limit_mb`, `sandbox.cpu_limit_percent`, `sandbox.network_access` and
  `sandbox.filesystem_access`, along with the `NetworkAccess` and `FilesystemAccess` enums.

  **These settings never did anything.** No code path has ever read them to confine, throttle,
  or restrict template execution. Their only consumer was `ResourceManager`, which was never
  constructed outside its own unit test. A configuration setting `sandbox.enabled: true` with
  `filesystem_access: readonly` and `network_access: none` produced a run identical to one with
  no sandbox configuration at all: the template read the process uid and username, listed the
  user's home directory, confirmed `.ssh` was readable, spawned a child process, and made an
  outbound DNS query. **Any configuration relying on these keys was not protected by them**, and
  `cxg config validate` reported such a file as simply valid.

  Templates execute as ordinary child processes with the invoking user's privileges and full
  network and filesystem access. Review templates before running them. For isolation, run cxg
  itself inside a container or VM, as a non-privileged user.

- Removed `ResourceManager` from `src/scheduler.rs`, and the now-unreachable `Error`
  variants `ResourceLimitExceeded` and `SandboxViolation` (with the `Error::resource_limit`
  constructor) — no cxg error path can report a limit or a violation, because no limit or
  confinement is enforced anywhere.

**Dead configuration keys.**

- **36 dead configuration keys** and the unused metrics module. Every one of these keys was parsed
  but had **no effect**. Existing config files that still set them **continue to load** — the keys
  are simply ignored.
  - (a) Removed, no plan to reinstate: `global.{verbosity,color,log_level,log_file,debug}`,
    `templates.{use_system_templates,use_user_templates,use_local_templates,auto_update,cache_dir}`,
    `network.{http2,dns_servers,follow_redirects}`,
    `execution.{threads,passive_mode,safe_mode,cache_enabled}`, `output.stream`,
    `metrics.{enabled,export_port,export_format}`, `plugins.{enabled,directories,plugins}`,
    `ai.fallback_providers`, `ai.cost_tracking.*`, `ai.cache.*`.
    (`network.follow_redirects` was removed as a config key only; the `--follow-redirects` flag is
    unaffected.)
  - (b) Removed, but plausible candidates to reinstate wired up later — these describe things a
    config file could reasonably control, and were removed because they lied, not because the
    capability is unwanted: `output.min_severity`, `output.formats`, `output.output_dir`,
    `output.output_file`, `templates.enabled_languages`.

### Notes — accepted-and-ignored surface

Stated plainly so it produces no more false leads:

- **Template execution is NOT sandboxed.** Despite earlier "sandboxed by default" claims in this
  changelog and the README, no execution path isolates or resource-limits templates: they run as
  ordinary child processes with the invoking user's privileges and full network and filesystem
  access. Run cxg inside a container or VM if you need isolation. (`cxg sandbox` manages
  per-language *dependency* environments — it does not confine template execution.) The
  `sandbox` config section that appeared to configure confinement is removed in this release,
  and a config still carrying it now warns rather than loading silently — see **Removed**.
- Nine `cxg scan` flags are accepted and silently ignored: `--protocol`, `--protocols`,
  `--threads`, `--stream`, `--resume`, `--distributed`, `--coordinator`, `--worker-id`,
  `--profile`. They are now grouped under a "Not Implemented" heading in `--help`.
- `cxg server` is not implemented — it exits with an error; its `--tls*`, `--port`, `--bind`, and
  `--auth-token` flags are accepted but do nothing.
- Runtime templates are distributed separately, in the
  [cert-x-gen-templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) repository, and
  installed to `~/.cert-x-gen/templates/`. No template count is stated here.

## [1.2.0] - 2026-08-01

### Added

**AI-driven whitebox pentest pipeline (`cxg pentest`)**
- New subsystem that reads guardlink's `whitebox/findings.sarif`, LLM-ranks threats against an
  operator goal, and has a local AI CLI (claude / codex / gemini, or the Anthropic / OpenAI HTTP
  APIs) write JavaScript probe templates that read the target's source to craft code-aware
  payloads. Those templates run in N parallel **authenticated** Chromium contexts, emitting
  confirmed / refuted / ambiguous findings to `report.json` plus a JSONL audit log of every HTTP
  request.
- Interactive auth capture for SSO/MFA flows (`cxg pentest auth`), chained-auth probes for
  cross-user IDOR (`--auth-numbers 2+`), scope enforcement (URL/method allowlist, per-endpoint
  budget, 5xx hard-kill), validator-guarded code generation, and retry-with-mutation on ambiguous
  triage.
- Operator-supplied identity metadata — `--tier`, `--persona`, `--cohort`, and free-form `--tag`
  — fed to the AI ranker so it selects the right identity per probe.
- The Python orchestrator is embedded in the binary (via `include_dir!`) and installed on demand,
  for a self-contained distribution.
- `cxg update` — self-update the `cxg` binary to the latest released build.

### Fixed
- SPA dashboards are no longer false-flagged as dead sessions during pentest pre-flight and
  session-health checks.
- Template config-directory resolution is now cross-platform (fixes Windows).
- `AIManager` provider tests are isolated from any on-disk AI config.

### Security
- Cleared dependency advisories: openssl 0.10.73 → 0.10.81 (8 advisories),
  bytes 1.10.1 → 1.12.1 (integer overflow), git2 0.18 → 0.20.4 (GHSA-j39j-6gw9-jw6h),
  prometheus 0.13 → 0.14 (protobuf advisory). TLS/HTTP stacks were consolidated onto reqwest.

## [1.1.1] - 2026-03-25

### Added

**MCP Server (Model Context Protocol)**
- 12-tool MCP server for AI agent integration via `cxg mcp` (there is no `serve` subcommand — the
  server is the bare `cxg mcp` invocation)
  - `cxg_search`, `cxg_template_list`, `cxg_template_info`, `cxg_scan`
  - `cxg_template_validate`, `cxg_template_create`, `cxg_template_write`
  - `cxg_template_get_notes`, `cxg_ai_generate`, `cxg_template_test`
  - `cxg_template_stats`, `cxg_template_update`
- `cxg mcp install` — auto-configure 6 AI coding agents (Claude Desktop, Claude Code, Cursor,
  Windsurf, VS Code, Zed), matching `src/mcp/installer.rs`

**AI Template Generation**
- `cxg ai generate` — natural-language to template generation (dual-mode: scaffold or full)
- Multi-provider support: Ollama (local-first default), OpenAI, Anthropic, DeepSeek
- `--api-key` flag for session-only cloud provider authentication

**Parameterised Template Metadata**
- 5 new metadata fields on the template struct: `context_vars`, `vuln_class`, `hypothesis_tags`,
  `batch_group`, `auto_probe` (an earlier revision of this entry listed `confidence`,
  `execution_mode`, and `pipeline_stage`, which do not exist)
- `@field:` annotation parsing across all 12 supported languages
- `context` and `batch_group` parameters added to the `cxg_scan` MCP tool

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

- Template library and MCP server template metadata refreshed. (An earlier revision of this entry
  cited specific template counts — 58 and 147 — that did not correspond to any shipped template
  population; templates are maintained in the separate cert-x-gen-templates repository, so no count
  is stated here.)

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

> Note: the "sandboxed execution" claims in this 1.0.0 entry never reflected the shipped binary —
> template execution has never been isolated or resource-limited. See the 1.3.0 Notes.

---

[Unreleased]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.0.0...v1.1.1
[1.0.0]: https://github.com/Bugb-Technologies/cert-x-gen/releases/tag/v1.0.0
