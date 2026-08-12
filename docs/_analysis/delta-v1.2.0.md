# cert-x-gen — Documentation Rebuild Analysis (post-v1.2.0)

**Scope:** analysis only, no documentation written, no source modified.
**Repo state:** branch `main` @ **`78226a7`** (PR #53, HEAD == `origin/main`, 0 commits behind
— confirmed via `git fetch origin && git log --oneline HEAD..origin/main | wc -l` → `0`),
tag `v1.2.0` @ `3b58895` (2026-08-01). Prior revision base: `46582a5` (PR #50).
**Binary used for empirical checks:** freshly built `target/release/cxg` @ `78226a7`
(`md5 40be823a…`, built 2026-08-12 17:20) — **not** the stale `~/.cargo/bin/cxg`
(`md5 70caa4aa…`, 2026-08-04), which was explicitly avoided. Every **[verified]** mark below
was re-run against this fresh binary; none were carried forward on faith.

> **Revision 3 — 2026-08-12.** Full re-run against current `origin/main` (`78226a7`), which
> is now the true HEAD. The delta since the Revision 2 base (`46582a5`) is **8 commits, 12
> files, +1,620/−4, and contains ZERO Rust changes** — `git diff --stat 46582a5..HEAD -- src/`
> is empty. Every Rust-derived section (§2 CLI, §3 schema, §4.1–4.4 execution, §5 config,
> §6.1–6.8) is therefore **re-verified unchanged at the source level**, and every `file:line`
> reference into `src/` that held at `46582a5` still holds byte-for-byte at `78226a7`. All
> movement is in the Python `pentest/` half (§1). This revision also (a) corrects two Rev 2
> errors found by deeper analysis — `--stream` is inert, and `-o results.json` does **not**
> double the extension; (b) adds the full dead-config-key inventory (§6.3); (c) resolves the
> template-count anomaly (§6.7); (d) resolves the `pentest/payloads/` question (§6.11); and
> (e) adds §9, the Documentation Truth Ledger. See §0.1 for the section-by-section map.

Findings marked **[verified]** were confirmed by running the freshly built binary, not by
reading code alone. Everything else is sourced to `file:line` at `78226a7` (identical to
`46582a5` for all of `src/`).

---

## 0. Executive summary

The cumulative delta since **v1.2.0** is 117 commits, and it is almost entirely one new
subsystem: **desktop/Electron pentest targets**, plus out-of-band confirmation via
interactsh, crash recovery, and threat correlation. The Rust side moved only in the v1.2.0→
`46582a5` window (`src/cli.rs` +656, `src/main.rs` +60); everything else — the scan engine,
template parser, matcher, config, and types — is untouched since the tag.

**The delta since the Revision 2 base (`46582a5`) is small and entirely Python.** 8 commits,
12 files, +1,620/−4. `git diff --stat 46582a5..HEAD -- src/` is **empty** — not one Rust line
changed. The new work is all in `pentest/`: engine-stamped actor/identity provenance on every
request, an empty-evidence guard fix, and a non-interactive saved-session auth path for CI
(§1). Because no Rust changed, every Tier-0 correctness defect from revisions 1–2 reproduces
**identically** against the fresh `78226a7` binary — re-confirmed, not assumed (§6.1, §6.2,
§6.4, §9).

Six things should drive the rebuild (all unchanged in substance since Rev 2; item 4's count
is corrected upward to **9** inert scan flags, see §2.3 and §6.3):

1. **`cert-x-gen.example.yaml` still does not load.** Rejected by both `cxg config validate`
   and `cxg scan --config`, identical error to revision 1. **[verified @ 46582a5]**
2. **`templates/skeleton/yaml-template-skeleton.yaml` still does not load.** 11 of the 12
   shipped skeletons load through the engine; YAML is the one that fails. **[verified @ 46582a5]**
3. **The sandbox is not enforced.** The entire `sandbox:` config block has zero runtime
   effect on template execution, while README claims "Sandboxed by default — templates
   run with strict resource limits." *(Tracked as a separate workstream.)*
4. **9 documented `scan` flags are inert** (Rev 2 said 8; `--stream` is the ninth — its
   `stream_finding` sink is dead code, never called), several with worked examples in `--help`.
5. **`cxg server` is a stub** that returns "API server not yet implemented", yet ships
   with full help text, examples, and TLS flags.
6. **An entire new product surface is invisible outside `pentest/docs/`.** Desktop
   targeting, OAST confirmation, and 11 new CLI flags have zero README or CHANGELOG
   presence. CHANGELOG still ends at 1.1.1 — now **two** releases and 117 commits behind.

**The documentation pattern is now sharply bimodal, which is the most useful new finding.**
The two *large* new subsystems (Electron, OAST) shipped with substantial `pentest/docs/`
updates — they are genuinely well documented. The two *small* features from PRs #46–#48
(`bridge` provider, `threat_id`) shipped with **none**, and remain undocumented in every
file in the repo. See §1.2.

### 0.1 What changed between revision 2 and revision 3

`git diff --stat 46582a5..HEAD -- src/` is **empty**. Every section below whose evidence is
`src/*.rs` is therefore *re-verified unchanged at the source level* — the label means the
underlying code is byte-identical to the Revision 2 base and every empirical `[verified]`
claim was **re-run against the fresh `78226a7` binary** and reproduced.

| Section | Status | Evidence / reason |
|---------|--------|-------------------|
| §1 Release delta | **Rewritten** | New window: 8 commits / 12 files / +1,620 since `46582a5`, all Python `pentest/`. Cumulative since tag is now 117 commits. |
| §2 CLI surface | **Re-verified unchanged** + **1 correction** | `git diff 46582a5..HEAD -- src/cli.rs` empty; `src/cli.rs` is still 2906 lines. Every flag re-confirmed. **Correction:** `--stream` reclassified ✅→❌ inert (§2.3); `-o` double-extension claim corrected (§6.7). |
| §3 Template schema | **Re-verified unchanged** | `src/types.rs`, `src/engine/`, `src/matcher.rs` in the empty `src/` diff. All `[verified]` load-behaviour re-run on the fresh binary. |
| §4 Execution model | **Re-verified unchanged (Rust)**; §4.5/4.6 **revised (Python)** | Rust↔Python boundary (§4.1–4.4) byte-identical. The substrate seam and pipeline gained actor provenance + CI session-auth — see §1 and §4.6. |
| §5 Config | **Re-verified unchanged** | `src/config.rs`, `src/ai/config.rs` in the empty `src/` diff. Example config **still fails to load**, re-confirmed on the fresh binary (§6.1). |
| §6 Doc debt | **Revised + extended** | Every prior finding reproduces on the fresh binary. §6.3 extended to the full dead-key inventory (Item A); §6.7 template count **resolved** (Item B); §6.11 `pentest/payloads/` **resolved** (Item C). §6.8 still lint-clean (0 warnings, re-run). |
| §9 Documentation Truth Ledger | **New** | One row per user-facing claim across README, all `--help`, and `cert-x-gen.example.yaml`, categorised ABSENT/INERT/STUB/WRONG/MISSING/OK. |

**Verification that §2–§6 Rust claims are safe to carry forward unchanged:**
`git diff --stat 46582a5..HEAD -- src/` returns **nothing**. The 12 changed files are all under
`pentest/` and `.github/` (`pentest/auth.py`, `cxg_pentest.py`, `js_engine.py`,
`js_generator.py`, `mutator.py`, `targets/base.py`, five new `pentest/tests/*`, and
`ci.yml`). No file under `src/` is touched.

---

## 1. Release delta

Two horizons. **§1.0** is the delta since the Revision 2 base (`46582a5`) — the new material
in this revision. **§1.1 onward** is the cumulative delta since the **v1.2.0** tag, carried
forward from Revision 2 (still accurate; the Rust half is byte-identical).

### 1.0 New since the Revision 2 base (`46582a5..78226a7`)

**8 commits · 12 files · +1,620 / −4. Zero Rust changes** (`git diff --stat 46582a5..HEAD
-- src/` is empty). Two merged PRs (#52 engine-stamped actor, #53 staging→Track B) plus a
direct integrate commit. All of it is in the Python `pentest/` half.

| # | Change | Commits | What it is | User-facing? | Documented? |
|---|--------|---------|------------|--------------|-------------|
| A | **Engine-stamped actor provenance** | `9b713a4` (#52) | Every request now records *which captured identity issued it*, stamped by the JS engine rather than inferred later. Feeds cross-identity (IDOR/privesc) triage. `pentest/js_engine.py` +109, `js_generator.py` +22. | Indirectly — richer `report.json`/`audit.jsonl` provenance | No — internal |
| B | **Empty-evidence guard fix** | `7ec80a6` | `mutator._classify_core`'s confirmed branch guarded on `if not finding.get("evidence")`, which only recognised `{}`; any bookkeeping key made the dict truthy and a finding with no real evidence was wrongly read as "AI confirmed + supplied evidence." Now `evidence={}` → ambiguous. `pentest/mutator.py`. | Yes — fewer false-confirmed findings | No |
| C | **Track B: non-interactive saved-session auth for CI** | `012f60c` (B1), `fcde8eb` (B2), `a7c5594`, `bd9651d` | Browser-free session import + injection so a session captured once locally can be replayed by every CI run. New Python surface: `auth import --storage-state <path\|->`, `auth verify --profile`, `run --ci` / `CXG_CI=1` (dead session → hard fail exit 5), `--auth-dir`, `CXG_AUTH_STATE_<NAME>` (base64), plus `auth_provenance` in the run manifest (sha256 of storage_state, never the cookie). `pentest/auth.py` +290, `cxg_pentest.py` +70, 4 new test modules (+1,109). | **Intended to be** — but see the reachability gap below | Only in commit bodies + `pentest/` |

> 🔴 **New headline finding — the entire Track B surface is UNREACHABLE through the `cxg`
> binary.** Because `src/cli.rs` was not touched (the `src/` diff is empty), the Rust clap
> wrapper that builds the Python argv knows nothing about the new subcommands and flags.
> Verified against the fresh `78226a7` binary: **[verified @ 78226a7]**
>
> | Invocation intended by Track B | What `cxg` actually does |
> |---|---|
> | `cxg pentest auth import …` | `error: unexpected argument 'import' found` — `pentest auth` is a flat clap command with no subcommands |
> | `cxg pentest auth verify …` | `error: unexpected argument 'verify' found` |
> | `cxg pentest run --ci` | `error: unexpected argument '--ci' found` |
> | `cxg pentest run --auth-dir …` | `error: unexpected argument '--auth-dir' found` |
>
> The features are fully implemented and tested on the Python side
> (`pentest/cxg_pentest.py:1217` `--auth-dir`, `:1222` `--ci`; `pentest/auth.py` `import`/
> `verify` subcommands; `CXG_CI` at `cxg_pentest.py:705`). The **only** way to invoke them
> today is to bypass `cxg` and run the orchestrator directly:
> `python3 ~/.cert-x-gen/pentest/cxg_pentest.py …` — which is not a documented interface.
> The Rust wrapper needs matching `Import`/`Verify` variants and `--ci`/`--auth-dir` flags
> before any of Track B is usable via the shipped binary. This is the single most important
> input to a rebuild: **the newest, best-tested feature in the repo cannot be run as
> documented in its own commit messages.**

Nothing in §1.0 touches the scan engine, the CLI clap surface, config, or the template
schemas, so §2–§6's Rust findings are unaffected.

### 1.a Cumulative delta since v1.2.0 (carried forward from Revision 2)

**117 commits since the `v1.2.0` tag** (109 through the Rev 2 base + 8 in §1.0).
The material below is unchanged from Revision 2; subsection numbers §1.1–§1.6 are preserved
from that revision.

The delta is dominated by one thing: **`cxg pentest` gained a second target type.** Until
v1.2.0 it could only drive an authenticated browser against an HTTP app. It can now launch,
isolate, and probe **Electron desktop applications** — their IPC channels, renderer
security configuration, and local data at rest.

Distribution of the change:

| Area | Files | Share |
|------|-------|-------|
| `pentest/` implementation | 20 | new substrate layer, OAST, Electron surface extraction, probes |
| `pentest/tests/` + fixtures | 44 | 25 test modules, 4 Electron fixture apps |
| `.claude/superpowers/` specs & plans | 10 | +5,370 lines of design docs (new in-repo convention) |
| `pentest/docs/` | 4 | +1,179 lines |
| Rust (`src/cli.rs`, `src/main.rs`) | 2 | +716 |
| CI / build | 3 | Python test job, `requirements.txt`, `pytest.ini` |

### 1.1 The six themes

| # | Theme | PR / merge | What it is | User-facing? | Documented? |
|---|-------|-----------|------------|--------------|-------------|
| 1 | **Desktop / Electron target substrate** | `e013308` (direct merge of `feat/desktop-target-substrate`, ~45 commits) | A `Substrate` protocol (`pentest/targets/base.py`) with `web` and `electron` implementations. Electron launches N isolated app instances with per-identity `--user-data-dir`, attaches over CDP, and drives renderers with Playwright. Adds `electron_surface.py` (IPC channel + config-claim extraction), `config_probes.py` (renderer hardening checks), `host_probes.py` (data at rest, update channel). | **Yes** — `--target-type electron` and 3 supporting flags on both `auth` and `run` | **Yes** — all 4 `pentest/docs/` files updated |
| 2 | **AI-generated IPC templates** | #41 `bf20377` | Teaches the generator to emit `cxg.ipc` probes; adds a `@requires_capability` template header the validator enforces; reclassifies triage from prose-matching to structural outcome. | **Yes** — new template capability + header | **Yes** — `TEMPLATES.md`, `ARCHITECTURE.md` |
| 3 | **Constant-named channels + routeless threats** | #49 `703d486` | Resolves constant-referenced `ipcMain`/preload channel names instead of only literals; adds `threat_correlation.py` to map threats with no route to candidate IPC channels; reports unreachable ones as `review_only_threats`. | **Yes** — new `review_only_threats` key in `report.json` | Partially — in specs, thinner in `pentest/docs/` |
| 4 | **Crash recovery** | `28db2d8` … `3f57279` (in #47 range) | Detects a dead or frozen target instead of reporting a false-clean scan. Restarts it (max 2/instance, 3/run), reports the crash as a `denial_of_service` finding, quarantines the suspect channel. Adds a stall watchdog on heartbeat. | **Yes** — `--no-restart`, `--stall-timeout`, `--template-timeout`; new report keys | **Yes** — spec + `pentest/docs/` |
| 5 | **OAST that actually confirms** | #50 `46582a5` | `pentest/oast.py` (+598) makes cxg an **interactsh client**: it registers the session, holds the correlation id, polls it, and turns a callback into a genuine `confirmed=true` finding. This splits the old `--oast` into two modes with different epistemics. | **Yes** — new `--oast-interactsh`; **`--oast`'s meaning narrowed** | **Yes** — all 4 `pentest/docs/` files |
| 6 | **Bridge provider + `threat_id`** | #46, #47, #48 | The three PRs analysed in revision 1: the `bridge` AI provider, the `SIETE_`→`BUGB_` env rename, and `threat_id` propagation into `report.json`. | **Yes** | **No — still zero coverage.** See §1.2 |

**Detail on theme 5, because it is a semantic change rather than an addition.** Revision 1
recorded `--oast` as providing "definitive blind-vuln confirmation" — that was accurate to
the help text at `c4866fa`, and it is now explicitly contradicted by the current help
(`src/cli.rs:640-686`):

| Mode | Who owns the canary | Can cxg read callbacks? | Finding outcome |
|------|--------------------|------------------------|-----------------|
| `--oast <HOST>` | Operator (Burp Collaborator, self-hosted) | **No** — inject-only | Stays `confirmed=false`; operator reads hits in their own tooling |
| `--oast-interactsh [SERVER_URL]` | **cxg** — it registers the session | **Yes** — `cxg.oast.poll(label)` reads in-band | Genuine `confirmed=true`, interaction recorded as evidence |

The two are `conflicts_with` at the clap level, deliberately: two canaries would split
payloads between a readable and an unreadable host, leaving "was this confirmed?" with no
single answer per finding (`src/cli.rs:676`).

### 1.2 Still undocumented: the `bridge` provider and `threat_id`

This is the sharpest finding of revision 2. Themes 1–5 all shipped with documentation.
Theme 6 did not, and **nine months of subsequent work has not backfilled it.**

Grep across the entire repo at `46582a5`:

```
grep -rn "BUGB_BRIDGE|ai-provider bridge|`bridge`" pentest/docs/ pentest/README.md README.md CHANGELOG.md
  → 0 hits
grep -rln "threat_id" pentest/docs/ pentest/README.md README.md CHANGELOG.md
  → 0 files
```

For contrast, the same grep for the newer features hits all four `pentest/docs/` files:
`oast`, `interactsh`, `electron`, `target-type` each appear in ARCHITECTURE, OPERATOR_GUIDE,
TEMPLATES and TROUBLESHOOTING; `requires_capability` in two.

| Item | Where it lives | Gap |
|------|----------------|-----|
| `--ai-provider bridge` | `pentest/ai_generator.py:173-208`, registry `:212` | `cxg pentest run --help` still lists `auto \| claude \| codex \| gemini \| anthropic \| openai`. **`bridge` absent.** **[verified @ 46582a5]** |
| `bridge` first in `auto` order | `pentest/ai_generator.py:225` | `--ai-provider auto` prefers the editor bridge over CLI tools whenever `$BUGB_BRIDGE_URL` is set. Undocumented behaviour change. The flag's *default* is `claude`, not `auto`, so most users won't hit it. |
| `BUGB_BRIDGE_URL` | `pentest/ai_generator.py:186,194` | Gates `bridge` availability. Absent from README, CHANGELOG, `--help`, `pentest/docs/`. |
| `BUGB_BRIDGE_TOKEN` | `pentest/ai_generator.py:195` | Sent as `Authorization: Bearer`. Same absence. |
| Bridge wire format | `pentest/ai_generator.py:196-208` | `POST {"prompt","tag":"cxg","cwd"}` → `200 {"completion": str}`, or a `text/plain` body taken verbatim. 900s timeout. An undocumented contract a third party must implement. |
| `threat_id` on findings | `pentest/browser_engine.py:42`, serialised via `to_dict()` | Key in `report.json`; `null` for AI/mutation-synthesised probes. No `report.json` schema doc exists anywhere. |
| `// @threat_id:` template header | `pentest/js_generator.py:229-238` | Injected deterministically post-generation; survives `--template-dir` replay. **Still not in `pentest/docs/TEMPLATES.md`**, which does now document `@requires_capability`. |
| `Hypothesis.threat_id` | `pentest/guardlink.py:69-72` | Read from SARIF `properties.threatId`, falling back to `partialFingerprints["guardlink/threatId"]`. |

### 1.3 CHANGELOG is now two releases and 117 commits behind

`CHANGELOG.md` ends at `[1.1.1] - 2026-03-25`. There is **no `1.2.0` section**, and
`[Unreleased]` is empty. Link refs still compare `v1.1.1...HEAD`. `Cargo.toml` says
`1.2.0` and the binary reports `cxg 1.2.0`, so 117 commits of work — including a whole new
target type and an unreachable CI-auth subsystem — currently ship under a version string
with no changelog entry.

### 1.4 New in-repo convention: specs and plans

`.claude/superpowers/specs/` and `.claude/superpowers/plans/` are new since v1.2.0 —
10 files, +5,370 lines, one spec + one plan per theme. They are the most detailed
design record in the repo and are **not referenced from any user-facing doc**. Worth a
decision during the rebuild: surface them, or explicitly mark them internal.

### 1.5 Test infrastructure is new

`pentest/` went from **1 test file to 25**, plus `pytest.ini`, `requirements.txt`, and
4 fixture Electron apps (`vuln-`, `hardened-`, `leaky-isolation-`, `electron-styles`).
CI gained a `Pentest (Python)` job on a 3.12/3.13 matrix (`.github/workflows/ci.yml:69`).
Revision 1's observation that "pytest isn't installed" is now obsolete.

### 1.6 Uncommitted working-tree change (unchanged since revision 1)

`README.md` is still modified but not committed: it adds a `cargo install cert-x-gen`
(crates.io) section and reworks "Using Cargo" into "From Git". Not part of any merged PR
— flagging so the rebuild doesn't lose or double-count it.

---

## 2. CLI surface — full inventory

Source: `src/cli.rs` (**2906 lines**, byte-identical at `46582a5` and `78226a7` —
`git diff 46582a5..HEAD -- src/cli.rs` is empty). Every flag below is transcribed from the
clap definitions. "Help" = has `help =` or a `///` doc comment that clap surfaces.

**What changed since revision 2:** the clap surface is **unchanged** — no flag added,
removed, or rewired. This was re-derived, not assumed: the full `--help` tree of the fresh
`78226a7` binary was walked and matches Rev 2 exactly. **[verified @ 78226a7]** Two
corrections come from deeper analysis, not from code movement:
- **`--stream` is inert (§2.3), not ✅ as Rev 2 recorded.** This brings the inert-`scan`-flag
  count to **9**.
- The `-o` "double extension" claim in §6.7 is corrected: `Path::with_extension` *replaces*
  the trailing extension, it does not append.

**Critical wiring gap surfaced this revision:** the newest Python features (Track B CI-auth —
`auth import`, `auth verify`, `run --ci`, `--auth-dir`) have **no clap representation** and
are rejected by the binary. See §1.0 and §2.11.

### 2.1 Global options (`src/cli.rs:72-121`)

All are `global = true`, so they are accepted on every subcommand.

| Flag | Short | Type | Default | Help? | Notes |
|------|-------|------|---------|-------|-------|
| `--verbose` | `-v` | count | `0` | Yes | `-v` info+warn, `-vv` +trace, `-vvv` +debug |
| `--no-color` | — | bool | `false` | Yes (doc only) | |
| `--config <FILE>` | `-c` | path | none | Yes (doc only) | **Only** way to load a config file — no auto-discovery (§5.1) |
| `--ut` | — | bool | `false` | Yes | visible alias `--update-templates` |
| `--auto-update-templates` | — | bool | `false` | Yes | |
| `--disable-update-check` | — | bool | `false` | Yes | Nuclei `-duc` equivalent |
| `--update-templates-on-startup` | — | bool | `false` | Yes | `conflicts_with = disable_update_check` |

### 2.2 Commands (`src/cli.rs:123-177`)

| Command | Status | Notes |
|---------|--------|-------|
| `scan` | Working | §2.3 |
| `template` | Working | §2.4 |
| `ai` | Working | §2.5 |
| `search` | Working | §2.6 |
| `server` | **STUB** | `src/main.rs:2774-2779` — returns `"API server not yet implemented"`. Ships with full `about`/`long_about`/examples and 6 flags. |
| `config` | Working | §2.8 |
| `sandbox` | Working (env mgmt only — does *not* sandbox template execution, §6.3) | §2.9 |
| `mcp` | Working | §2.10 |
| `pentest` | Working | §2.11 |
| `update` | Working | Self-update from GitHub releases |
| `version` | Working | |

### 2.3 `cxg scan` (`src/cli.rs:938-1253`) — 39 flags

**Wiring status legend:** ✅ read and applied · ⚠️ partially wired · ❌ **inert — parsed
but never read anywhere in the codebase**.

| Flag | Short/aliases | Type | Default | Help? | Wired |
|------|---------------|------|---------|-------|-------|
| `--scope` | `-s`, `-t`; aliases `--target(s)`, `--target-file`, `--domain(s)`, `--domain-file`, `--cidr` | `Vec<String>`, `,`-delim | — | Yes | ✅ |
| `--ports` | `-p`; aliases `--port`, `--port-file`, `--add-ports` | `Vec<String>`, `,`-delim | — | Yes | ✅ |
| `--top-ports` | — | `u16` | none | Yes | ✅ |
| `--override-ports` | — | `String` | none | Yes | ✅ |
| `--protocol` | — | `String` | none | Yes | ❌ **inert** |
| `--protocols` | — | `String` | none | Yes | ❌ **inert** |
| `--templates` | aliases `--template`, `--template-file` | `Vec<String>`, `,`-delim | — | Yes | ✅ |
| `--template-dir` | — | path | none | Yes | ✅ |
| `--tags` | — | `String` | none | Yes | ✅ |
| `--severity` | — | `Vec<SeverityArg>` enum | none | Yes | ✅ |
| `--exclude-templates` | — | `String` | none | Yes | ✅ |
| `--template-language` | — | `Vec<LanguageArg>` enum | none | Yes | ✅ |
| `--threads` | — | `usize` | `num_cpus::get()` | Yes | ✅ (advisory only — see help text at `:1045`) |
| `--parallel-targets` | — | `usize` | `50` | Yes | ✅ |
| `--parallel-templates` | — | `usize` | `10` | Yes | ✅ |
| `--timeout` | — | `String` | `"30s"` | Yes | ✅ |
| `--retry` | — | `u32` | `1` | Yes | ✅ |
| `--rate-limit` | — | `u32` | none | Yes | ✅ |
| `--aggressive` | — | bool | `false` | Yes | ✅ |
| `--stealth` | — | bool | `false` | Yes | ✅ |
| `--passive` | — | bool | `false` | Yes | ✅ |
| `--safe` | — | bool | `false` | Yes | ✅ |
| `--proxy` | — | `String` | none | Yes | ✅ |
| `--user-agent` | — | `String` | none | Yes | ✅ |
| `--header` | — | `Vec<String>` | none | Yes | ✅ |
| `--cookie` | — | `Vec<String>` | none | Yes | ✅ |
| `--follow-redirects` | — | bool | `false` (flag) | Yes | ✅ — **help says "Default: Enabled"** (`:854`) but the clap default is `false`; config default is `true` (`src/config.rs:195`) |
| `--max-redirects` | — | `usize` | `5` | Yes | ✅ |
| `--output` | `-o` | `String` | `"scan-results"` | Yes | ✅ — a **basename**, not a path; extension appended per format |
| `--output-format` | — | `String` | `"json"` | Yes | ✅ (`src/main.rs:1109`) |
| `--stream` | — | bool | `false` | Yes | ❌ **inert (corrected from Rev 2's ✅)** — `apply_scan_args` writes `config.output.stream = args.stream` (`src/main.rs:1275`) but **nothing ever reads it**, and the sink `OutputManager::stream_finding` (`src/output.rs:1137`) has **zero callers**. Help promises "results shown as they're found" (`src/cli.rs:891`); scan output is batch-only. **[verified @ 78226a7]** |
| `--quiet` | `-q` | bool | `false` | Yes | ⚠️ **banner-only.** The clap field is never read; `--quiet`/`-q` is matched as a raw argv string at `src/main.rs:34` and only suppresses the ASCII banner. Help claims "only critical info and errors" — scan output is unchanged. **[verified]** |
| `--resume <SCAN-ID>` | — | `String` | none | Yes + example | ❌ **inert** — a bogus ID is silently ignored, scan runs normally **[verified]** |
| `--distributed` | — | bool | `false` | Yes + example | ❌ **inert** |
| `--coordinator <URL>` | — | `String` | none | Yes + example | ❌ **inert** |
| `--worker-id <ID>` | — | `String` | none | Yes + example | ❌ **inert** |
| `--profile <NAME>` | — | `String` | none | Yes + example | ❌ **inert** |
| `--context <JSON>` | — | `String` | none | Yes | ✅ → `CERT_X_GEN_CONTEXT` |
| `--batch-group <GROUP>` | — | `String` | none | Yes | ✅ |

> **Inert-flag verification (updated for Rev 3 — now 9, not 8).** `grep -rn "\.<field>\b"
> src/main.rs` returns zero *read* hits for `protocol`, `protocols`, `quiet`, `resume`,
> `distributed`, `coordinator`, `worker_id`, `profile`. `--stream` is the ninth: its only
> `main.rs` hit is a *write* (`config.output.stream = args.stream`, `:1275`) with no reader,
> and its formatter sink `stream_finding` is dead code. `ScanArgs` is consumed only by
> `main.rs`, so these are dead. The eight legacy ones are documented in `scan`'s `after_help`
> (`src/cli.rs:615-936`), five with worked examples; `--stream`'s help is on the flag itself
> (`:891`). **All 9 re-verified against the fresh `78226a7` binary.**

**Also note:** `--output-format`'s help advertises `xml` (`src/cli.rs:1174`, and `724-729`),
but no XML formatter is registered. See §6.4.

### 2.4 `cxg template` (`src/cli.rs:1317-1447`)

| Subcommand | Args | Help? |
|------------|------|-------|
| `list` | `--language <LANG>`, `--severity <LEVEL>`, `--tags <TAG,…>`, `--batch-group <GROUP>` | Yes |
| `validate` | `<path>` (positional), `-r/--recursive`, `--json` | Yes |
| `update` | `-f/--force` | Yes |
| `info` | `<template_id>` (positional) | Yes |
| `create` | `--id <ID>`, `--language <LANG>`, `--name <NAME>`, `-o/--output <DIR>` (default `.`) | Yes |
| `test` | `<template>` (positional path), `--target <HOST>`, `--debug` | Yes |
| `search` | `<query>` (positional), `--language`, `--severity`, `--tags`, `--content`, `--detailed`, `--limit` (default `50`) | Yes |
| `pwd` | none | Yes |
| `skeleton` | `<language>` (positional enum) | Yes |
| `add` | `<file>` (positional), `<dest>` (positional, optional) | Yes |

`validate` and the engine **do not agree** — see §6.2.

### 2.5 `cxg ai` (`src/cli.rs:2108-2272`)

| Subcommand | Flag | Short | Default | Help? |
|------------|------|-------|---------|-------|
| `generate` | `<prompt>` positional | — | — | Yes |
| | `--language` | `-l` | `yaml` | Yes |
| | `--provider` | `-p` | none (falls back to config default `ollama`) | Yes |
| | `--model` | `-m` | none | Yes |
| | `--output` | `-o` | auto (`~/.cert-x-gen/templates/ai-generated/<name>.<ext>`) | Yes |
| | `--test` | — | `false` | Yes |
| | `--test-target` | — | none (`requires = test`) | Yes |
| | `--force` | `-f` | `false` | Yes |
| | `--estimate-cost` | — | `false` | Yes |
| | `--api-key` | — | none | Yes — session-only, not persisted |
| `providers list` | `--detailed` | `-d` | `false` | Yes |
| `providers test` | `<provider>` positional | — | — | Yes |
| `providers status` | none | — | — | Yes |

### 2.6 `cxg search` (`src/cli.rs:1526-1594`)

| Flag | Short | Type | Default | Help? |
|------|-------|------|---------|-------|
| `--query` | `-q` | `String` | none | Yes |
| `--language` | — | enum | none | Yes |
| `--severity` | — | enum | none | Yes |
| `--tags` | — | `String` | none | Yes |
| `--author` | — | `String` | none | Yes |
| `--cwe` | — | `String` | none | Yes |
| `--content` | — | bool | `false` | Yes |
| `--case-sensitive` | — | bool | `false` | Yes |
| `--regex` | — | bool | `false` | Yes |
| `--limit` | — | `usize` | `50` | Yes |
| `--format` | — | `SearchFormat` | `table` | Yes |
| `--output` | `-o` | path | stdout | Yes |
| `--detailed` | — | bool | `false` | Yes |
| `--sort` | — | `SearchSort` | `relevance` | Yes |
| `--reverse` | — | bool | `false` | Yes |
| `--ids-only` | — | bool | `false` | Yes |
| `--stats` | — | bool | `false` | Yes |

> Note `cxg search` uses `--query`, but `cxg template search` takes the query as a
> **positional**. Both are documented, but the asymmetry is a common trip-hazard worth
> calling out in the rebuild.

### 2.7 `cxg server` (`src/cli.rs:1615-1639`) — **stub**

`--port` (`-p`, `8080`), `--bind` (`-b`, `127.0.0.1`), `--auth-token`, `--tls`,
`--tls-cert` (`requires = tls`), `--tls-key` (`requires = tls`). All have help.
**All are inert** — `run_server` is unimplemented (`src/main.rs:2774-2779`).

### 2.8 `cxg config` (`src/cli.rs:1665-1685`)

| Subcommand | Args | Default |
|------------|------|---------|
| `generate` | `-o/--output <FILE>`, `-f/--format <FORMAT>` | `cert-x-gen.yaml`, `yaml` |
| `validate` | `<config>` positional | — |
| `show` | none | — |

### 2.9 `cxg sandbox` (`src/cli.rs:1743-1899`) — 17 subcommands

Two distinct generations coexist, documented in the enum doc comment at `src/cli.rs:1722-1741`.

| Generation | Subcommands |
|------------|-------------|
| Package sandbox (legacy) | `init` (`-f/--force`, `-l/--languages`, `-d/--directory`), `status`, `install <language> <packages…>`, `clean` (`-l`, `-f`), `shell` (`-l`, default `bash`), `path`, `update` (`-l`), `export` (`-o` default `sandbox-export.yaml`, `-d`, `-a`), `import <file>` (`-f`), `templates`, `use-template <template>`, `list <language>` |
| Docker sandbox (recommended) | `create <name>` (`-l/--languages`, `-p/--persist` default `true`, `-a/--auto-start` default `true`), `delete <name>` (`-f`), `enter [name]`, `set-default [name]`, `info`, `build` (`-d/--dockerfile`) |

All have help text. **Neither generation isolates template execution** (§6.3).

### 2.10 `cxg mcp` (`src/cli.rs:1905-1926`)

| Invocation | Behaviour |
|------------|-----------|
| `cxg mcp` (no subcommand) | Starts the MCP server over stdio (`src/main.rs:161-166`) |
| `cxg mcp install [--client <list>]` | Configure AI coding agents |
| `cxg mcp uninstall [--client <list>]` | Remove configuration |
| `cxg mcp status` | Show configuration status |

> **`cxg mcp serve` does not exist.** CHANGELOG 1.1.1 documents the server as
> `cxg mcp serve`; `McpAction` has no `Serve` variant. The bare `cxg mcp` form is
> the real one.
>
> The `--client` help lists `claude-desktop,claude-code,cursor,windsurf,vscode,zed`
> (`src/cli.rs:1914`); CHANGELOG 1.1.1 lists a different set
> ("Claude Desktop, Cursor, Windsurf, Cline, Roo Code, Claude Code"). Reconcile against
> `src/mcp/installer.rs` when writing the reference page.

### 2.11 `cxg pentest` (`src/cli.rs:207-761`)

Best-documented surface in the repo — extensive `///` docs with examples, capabilities,
and exit codes, plus `// @g.comment` rationale annotations on most new flags. Rust builds
an argv and execs the Python orchestrator (§4.4).

**This is where all CLI growth since v1.2.0 landed: 11 new flags (3 on `auth`, 8 on `run`).**

| Subcommand | Purpose |
|------------|---------|
| `install` | `--force` — copy Python orchestrator to `~/.cert-x-gen/pentest/` |
| `auth` | Capture an authenticated session — browser **or desktop app** (17 flags). **Flat command — no subcommands.** |
| `auth-list` | List saved profiles |
| `scope-init` | `-o/--output` (default `scope.yaml`) |
| `run` | Full pipeline (**35 flags**, up from 24) |

> 🔴 **Rev 3 — the Rust clap surface has NOT kept up with the Python orchestrator.** The
> newest Python work (Track B, §1.0) added an `auth import` and `auth verify` subcommand and
> `run --ci` / `--auth-dir` flags to `pentest/cxg_pentest.py` and `pentest/auth.py`, but
> `src/cli.rs` is byte-identical to `46582a5`, so none of them exist in the binary. Against
> the fresh `78226a7` binary: **[verified @ 78226a7]**
>
> - `cxg pentest auth import …` → `error: unexpected argument 'import' found`
> - `cxg pentest auth verify …` → `error: unexpected argument 'verify' found`
> - `cxg pentest run --ci` → `error: unexpected argument '--ci' found`
> - `cxg pentest run --auth-dir …` → `error: unexpected argument '--auth-dir' found`
>
> The clap `PentestAction::Auth` is a leaf with fixed flags (`src/cli.rs:255-370`); it has no
> `Import`/`Verify` variants and `PentestAction::Run` (`:242-760`) has no `--ci`/`--auth-dir`.
> These are **not** in the flag inventory below because they are unreachable via `cxg`. A
> rebuild must either wire them into clap or document `python3 cxg_pentest.py …` as the entry
> point. See §9 for the ledger rows.

#### `pentest auth` (`src/cli.rs:255-370`)

Unchanged: `--target` (req), `--profile` (req), `--auth-numbers` (`1`), `--creds`,
`--creds-file`, `--login-path` (`/api/auth/login`), `--label`, `--verify-url`,
`--header NAME:VALUE` (repeatable), `--tier`, `--persona`, `--cohort`, `--tag NAME=VALUE`
(repeatable). `--header` still carries an explicit **SECURITY** note about plaintext
storage in `~/.cert-x-gen/auth/<profile>.meta.json`.

**New (desktop capture):**

| Flag | Default | Constraint | Notes |
|------|---------|-----------|-------|
| `--target-type` | `web` | `value_parser = ["web","electron"]`, `requires_if("electron","app_cmd")` | `electron` captures the app's session state instead of a browser's. **Tauri explicitly unsupported** — no CDP endpoint on macOS/Linux |
| `--app-cmd` | none | `conflicts_with = "app_binary"` | e.g. `"npm run electron:dev"`. cxg appends `--remote-debugging-port` and a per-identity `--user-data-dir` |
| `--app-binary` | none | `conflicts_with = "app_cmd"` | e.g. `/Applications/Foo.app` |

#### `pentest run` (`src/cli.rs:242-760`)

Unchanged flags (24): `--codebase` (req), `--target` (req), `--auth` (`""`),
`--interactive-auth` (`0`), `--auth-profile` (`pentest`), `--auth-numbers`, `--creds-file`,
`--template-lang` (`js`; `py` marked legacy), `--goal`, `--template-dir`,
`--max-templates` (`8`), `--mutation-retries` (`2`), `--ai-provider` (`claude`), `--ai`,
`--headed`, `--scope-file`, `--destructive-ok`, `--attestation`, `--session-dir`,
`--output`/`-o`, `--mitigation-mode` (`any`), `--me-path` (`/api/me`),
`--generation-timeout` (`240`), `--skip-health-check`.

> `--ai-provider` help still reads `auto | claude | codex | gemini | anthropic | openai` —
> **`bridge` remains absent.** **[verified @ 46582a5]** (§1.2)

**New (8):**

| Flag | Default | Constraint | Notes |
|------|---------|-----------|-------|
| `--oast-interactsh [SERVER_URL]` | none | `num_args = 0..=1`, `default_missing_value = ""`, `conflicts_with = "oast"` | Three states: absent (`None`), bare (`Some("")` = interactsh public servers), explicit (`Some(url)`). **The only mode that yields `confirmed=true`** (§1.1) |
| `--target-type` | `web` | `["web","electron"]`, `requires_if("electron","app_cmd")` | `electron` launches N isolated instances, drives renderers over CDP, probes IPC + renderer config + data at rest |
| `--app-cmd` | none | `conflicts_with = "app_binary"` | As above |
| `--app-binary` | none | `conflicts_with = "app_cmd"` | As above |
| `--host-scan-path` | none | — | Opt in to scanning a **real** install dir for data at rest. Default: host probes read only cxg-created user-data dirs |
| `--template-timeout <f64>` | `900`s (Python-side) | — | Absolute per-template dispatch ceiling. **Backstop only.** `0` disables, letting a wedged app hang the scan indefinitely |
| `--stall-timeout <f64>` | `90`s (Python-side) | — | **Idle** time with no completed dispatch before the surface is corroborated against peers and declared stalled. A long-running probe that keeps getting answers is never killed. `electron` only |
| `--no-restart` | `false` | — | Opt out of crash recovery. Default restarts a dead target (max 2/instance, 3/run), reports the crash as a `denial_of_service` finding, re-probes the suspect channel once, then quarantines it |

> **Clap-constraint subtlety worth preserving in the docs.** `--target-type` uses
> `requires_if("electron", "app_cmd")` rather than `required_if_eq` on `app_cmd`. The
> comment at `src/cli.rs:702-706` explains why: `required_if_eq`'s validation path skips
> the `conflicts_with` escape hatch, so pairing it with `app_cmd`'s `conflicts_with` would
> wrongly demand `--app-cmd` even when `--app-binary` alone was supplied. There is a
> regression test for exactly this (`desktop_flag_tests::electron_with_app_binary_alone_parses`).

Documented exit codes (`src/cli.rs:434-438`): `0` clean · `1` no templates · `2` confirmed
findings · `3` hard-killed. Note `3` now also covers "dead target with `--no-restart`"
(`src/cli.rs:756`), which the exit-code list does not yet mention.

#### New: clap unit tests

`src/cli.rs:2442-2901` is a new `#[cfg(test)]` block covering `--target-type` defaulting,
unknown-value rejection, the `--app-cmd`/`--app-binary` conflict matrix, the three
`--oast-interactsh` states, and the `--oast`/`--oast-interactsh` conflict. This is the
first CLI-level test coverage in the repo and is a useful precedent for the proposed
`--help` snapshot test.

### 2.12 Environment variables

Complete inventory. Rust side from `grep -rn 'env::var("' src/` (byte-identical at
`78226a7`); Python side from `pentest/`. **The Rust-side table is unchanged.** The Rev 2→3
window added **two Python-only env vars** that the Rust binary never reads (they only matter
if the orchestrator is invoked directly, since Track B is unreachable via `cxg` — §1.0):
`CXG_CI` (`pentest/cxg_pentest.py:705` — non-interactive hard-fail mode) and
`CXG_AUTH_STATE_<NAME>` (base64 `storage_state` for single-profile CI import). Both are
**undocumented** outside commit bodies.

| Var | Read at | Purpose | Documented? |
|-----|---------|---------|-------------|
| `CXG_NO_BANNER` | `src/main.rs:36` | Suppress ASCII banner | No |
| `CXG_PYTHON` | `src/main.rs:487` | Override `python3` discovery for pentest | Only in an error string (`:501`) |
| `CXG_SOURCE` | `src/main.rs:563` | Point `pentest install` at a dev source tree | Only in an error string (`:587`) |
| `CERT_X_GEN_SANDBOX` | `src/sandbox/docker.rs:714` | Set inside the Docker image; detects "am I in a sandbox" | No |
| `CERT_X_GEN_SANDBOX_NAME` | `src/sandbox/docker.rs:719` | Sandbox name inside container | No |
| `CERT_X_GEN_MODE` | *written* — `src/engine/common.rs:376` | Always `engine`; tells templates to emit JSON | README §Writing Templates (partially) |
| `CERT_X_GEN_TARGET_HOST` | *written* — `common.rs:377` | Target address | Yes (README) |
| `CERT_X_GEN_TARGET_PORT` | *written* — `common.rs:379` | Target port, defaults to `80` if unset | Yes (README) |
| `CERT_X_GEN_ADD_PORTS` | *written* — `common.rs:391` | Comma list; only set when non-empty | No |
| `CERT_X_GEN_OVERRIDE_PORTS` | *written* — `common.rs:400` | Comma list; only set when `--override-ports` given | No |
| `CERT_X_GEN_CONTEXT` | *written* — `common.rs:407` | `--context` JSON; **only set when non-empty** | Partially (`--context` help) |
| `OPENAI_API_KEY` | `src/ai/config.rs:284` (via `${…}` expansion), `pentest/ai_generator.py` | OpenAI auth | Yes (`cxg ai --help`) |
| `ANTHROPIC_API_KEY` | `src/ai/config.rs:298`, `pentest/ai_generator.py` | Anthropic auth | Yes (`cxg ai --help`) |
| `DEEPSEEK_API_KEY` | `src/ai/config.rs:312` | DeepSeek auth | Yes (`cxg ai --help`) |
| `BUGB_BRIDGE_URL` | `pentest/ai_generator.py:186,194` | Editor host-model bridge endpoint | **No** — new in #47 |
| `BUGB_BRIDGE_TOKEN` | `pentest/ai_generator.py:195` | Bearer token for the bridge | **No** — new in #47 |
| `CXG_CI` | `pentest/cxg_pentest.py:705` (Python only) | Non-interactive CI mode: dead session → hard-fail exit 5; refuses a world-accessible `--auth-dir`. **Rust binary never reads it** | **No** — new in #53, Python-only |
| `CXG_AUTH_STATE_<NAME>` | `pentest/auth.py` (Python only) | base64 `storage_state` materialised by `auth import` for the single-profile case | **No** — new in #53, Python-only |
| `SHELL` | `src/main.rs:3270` | `cxg sandbox shell` fallback (`/bin/bash`) | No |
| `APPDATA` / `ProgramData` | `src/template/paths.rs` | Windows path resolution | No |

---

## 3. Template schema — as the engine actually parses it

> **Revision 2: re-verified unchanged.** `src/types.rs`, `src/engine/common.rs`,
> `src/engine/yaml/mod.rs`, and `src/matcher.rs` are untouched since v1.2.0
> (`git diff --stat v1.2.0..HEAD -- src/` lists only `cli.rs` and `main.rs`). Every line
> reference and empirical result below still holds at `46582a5`, re-confirmed with the
> freshly built binary.
>
> **Scope note:** this section covers the **scan** template schema — the 12-language
> polyglot format `cxg scan` executes. `cxg pentest` uses a *third*, unrelated template
> format (JavaScript probes with `// @key:` meta headers). That one gained
> `@requires_capability` and `@threat_id` in this delta; see §3.6.

**The single most important structural fact:** cert-x-gen has **two entirely separate
template schemas**, not one.

| | Annotation schema | YAML schema |
|---|---|---|
| Languages | Python, JavaScript, Rust, Shell, C, C++, Java, Go, Ruby, Perl, PHP (**11**) | YAML (**1**) |
| Parsed by | `parse_metadata_from_comments` (`src/engine/common.rs:156-232`) | `serde_yaml::from_str` into `YamlTemplateData` (`src/engine/yaml/mod.rs:55`, struct `:107-129`) |
| Mechanism | Regex over `@field:` comment lines | serde struct deserialization |
| Missing field | Silently defaults | **Hard error**, template fails to load |
| Unknown field | Ignored | Ignored (no `deny_unknown_fields`) **[verified]** |
| Scan window | **First 50 lines only** (`common.rs:160`) | Whole document |

A YAML template's `# @id:` comments are **decorative** — the YAML engine never calls
`parse_metadata_from_comments`. The shipped skeleton carries both, which is misleading
(§6.2).

### 3.1 Annotation schema — the 11 non-YAML languages

The parser is **fully language-agnostic**: one regex, applied identically to all 11
languages. There is **no per-language variation in which fields are supported.**

Recogniser (`src/engine/common.rs:242-256`):
```
(?m)^[\s]*(?:#|//!?|\*)?[\s]*@<field>[\s]*:[\s]*(.+?)[\s]*$
```
Accepted comment prefixes: `#`, `//`, `//!`, `*`, or none. `/*` is *not* in the
alternation — it works only because the field usually sits on a continuation `*` line.
**First match wins** (`re.captures`, singular); duplicates are ignored. Empty values are
discarded by the `.filter(|s| !s.is_empty())`.

| Annotation | Type | Required? | Default when absent | Parsed at | Notes |
|------------|------|-----------|---------------------|-----------|-------|
| `@id` | string | Recommended | file stem (`common.rs:567-574`) | `:164` | Only "required" for the validator's `missing_required_fields`; the engine always falls back |
| `@name` | string | Recommended | file stem with `-`/`_` → spaces (`:575-577`) | `:165` | |
| `@author` | string | Recommended | `"Unknown"` (`:578`) | `:166` | Becomes `AuthorInfo{name, email: None, github: None}` — email/github are **never** populated from annotations |
| `@severity` | enum | Recommended | `Medium` (`:582`) | `:167` | `critical\|high\|medium\|low\|info\|informational`; **any unrecognised value silently becomes `Medium`** (`:360-368`) |
| `@description` | string | Recommended | `"<lang> template: <stem>"` (`:583-585`) | `:168` | |
| `@tags` | comma list | Recommended | code-scan fallback (§3.2), then language tag | `:172-174` | **Lowercased**. Language tag is always appended if absent (`:588-596`) |
| `@version` | string | Optional | `"1.0.0"` (`:626`) | `:169` | Note: `TemplateMetadata`'s serde default is `"1.0"` (`types.rs:607`) — inconsistent |
| `@cwe` | comma list | Optional | `[]` | `:177-179` | Lowercased — `CWE-89` becomes `cwe-89` |
| `@cvss` | `f32` | Optional | `None` | `:187-189` | Unparseable → `None`, silently |
| `@confidence` | `u8` | Optional | `Some(50)` (`:627`) | `:192-194` | Unparseable → falls back to `50` |
| `@references` | comma list | Optional | — | `:182-184` | ⚠️ **Parsed then discarded** — `create_metadata` never reads `parsed.references`; `TemplateMetadata` has no `references` field. Dead annotation (§6.5) |
| `@context_vars` | spec list | Optional | `[]` | `:204-209` | See §3.3 |
| `@vuln_class` | string | Optional | `None` | `:212` | Coarse routing class |
| `@hypothesis_tags` | comma list | Optional | `[]` | `:215-221` | Lowercased |
| `@batch_group` | string | Optional | `None` | `:224` | Matched **case-insensitively** by `--batch-group` (`src/template/engine.rs:300`) |
| `@auto_probe` | bool | Optional | `false` | `:227-229` | True only for `true`/`yes`/`1` (case-insensitive) |

**Annotations that do NOT exist** despite appearing in docs or being plausible:
`@cve` (never parsed — `cve_ids` is hardcoded `Vec::new()` at `common.rs:618`),
`@remediation`, `@ports`, `@protocol`, `@created`, `@updated`, `@execution_mode`,
`@pipeline_stage`. See §6.6.

### 3.2 Tag fallback — the one genuinely language-specific behaviour

Only when `@tags` is absent, `extract_tags_from_code` (`common.rs:275-345`) scrapes the
whole file. **All 6 patterns are tried against every language** — the labels below are
the author's intent, not a restriction.

| # | Regex | Intended language | Line |
|---|-------|-------------------|------|
| 1 | `(?:self\.)?tags\s*=\s*\[([^\]]+)\]` | Python, Ruby | `:280` |
| 2 | `tags\s*:\s*\[([^\]]+)\]` | JavaScript, JSON | `:291` |
| 3 | `Tags\s*:\s*\[\]string\{([^}]+)\}` | Go | `:302` |
| 4 | `(?:Arrays\.asList\|List\.of)\s*\(([^)]+)\)` | Java | `:313` |
| 5 | `tags\s*=>\s*\[([^\]]+)\]` | Perl | `:324` |
| 6 | `TAGS\s*=\s*["']([^"']+)["']` | Shell | `:335` |

**No fallback pattern exists for C, C++, PHP, or Rust.** Templates in those four
languages that omit `@tags` get only the auto-appended language tag.

### 3.3 `@context_vars` grammar (`src/engine/common.rs:18-57`)

```
# @context_vars: auth_token:required, endpoints[]:required, user_id:optional
```
Per token (`ContextVarSpec::parse`, `:34-56`):

| Element | Rule |
|---------|------|
| Name | Text before the first `:`; trailing `[]` sets `is_array` and is stripped |
| Qualifier | After the first `:`. **`required`, `req`, `r`** (case-insensitive) ⇒ required. **Everything else — including a typo like `requried` — silently means optional.** |
| No `:` | Defaults to `optional` (`:43`) |
| Empty name | Token dropped |

Re-serialised into `TemplateMetadata.context_vars` as `Vec<String>` of
`"name[]:required"` / `"name:optional"` (`common.rs:628-640`) — the structured form is
lost after parsing.

### 3.4 YAML schema (`src/engine/yaml/mod.rs`)

`YamlTemplateData` (`:107-129`) `#[serde(flatten)]`s `TemplateMetadata` (`src/types.rs:527-588`)
at the document root, then adds the execution blocks.

**Root metadata keys** — required/optional verified empirically by feeding minimal
documents through `cxg scan --template-dir`. **[verified]**

| Key | Type | Required? | Default | Evidence |
|-----|------|-----------|---------|----------|
| `id` | string | **Required** | — | `types.rs:529` (no `default`) |
| `name` | string | **Required** | — | `:531` |
| `author` | **object** `{name, email?, github?}` | **Required** | — | `:533`. **A plain string fails:** `invalid type: string "…", expected struct AuthorInfo` **[verified]** |
| `severity` | enum lowercase | **Required** | — | `missing field 'severity'` **[verified]** |
| `description` | string | **Required** | — | `:537` |
| `language` | enum lowercase | **Required** | — | `missing field 'language'` **[verified]** |
| `cve_ids` | `[string]` | Optional | `[]` | `:539-540` `#[serde(default)]` |
| `cwe_ids` | `[string]` | Optional | `[]` | `:542-543` |
| `cvss_score` | float | Optional | `null` | `:545` `Option<T>` **[verified omissible]** |
| `tags` | `[string]` | Optional | `[]` | `:547-548` |
| `file_path` | path | Optional | `""` | `:552-553` — engine overwrites; not author-facing |
| `created` | datetime | Optional | now | `:555-556` |
| `updated` | datetime | Optional | now | `:558-559` |
| `version` | string | Optional | `"1.0"` | `:561-562` |
| `confidence` | `u8` | Optional | `null` | `:564` **[verified omissible]** |
| `context_vars` | `[string]` | Optional | `[]` | `:570-571` — flat `"name:required"` strings, **not** the annotation grammar |
| `vuln_class` | string | Optional | `null` | `:573-574` |
| `hypothesis_tags` | `[string]` | Optional | `[]` | `:577-579` |
| `batch_group` | string | Optional | `null` | `:581-583` |
| `auto_probe` | bool | Optional | `false` | `:585-587` |

**Execution blocks** (all optional — a metadata-only YAML template loads fine **[verified]**):

| Key | Type | Shape |
|-----|------|-------|
| `http` | `[HttpRequestSpec]` | `method` (default `"GET"`, `:156`), `path: [string]`, `headers: {k:v}` (default `{}`), `body`, `matchers`, `matchers-condition` |
| `network` | `[NetworkRequestSpec]` | `protocol` (default `"tcp"`, `:182`), **`port` (required, `u16`)**, `payloads: [string]` (default `[]`), `matchers`, `matchers-condition` |
| `matchers` | `[MatcherType]` | Root-level matchers |
| `matchers-condition` | `and`/`or` | Root-level condition |
| `flows` | `[Flow]` | Multi-step; see `src/flows.rs` |

**Matcher types** — internally tagged on `type` (`src/matcher.rs:12-13`), lowercase:
`status`, `word`, `regex`, `binary`, `time`, `size`, `hash`, `tls`, `dns`, `diff`, `custom`.

> ⚠️ **There is no `dsl` matcher.** Nuclei users will reach for it; the engine rejects the
> whole template with `unknown variant 'dsl'`. This is exactly what breaks the shipped
> skeleton (§6.2). **[verified]**

**Keys silently ignored in YAML templates** (no `deny_unknown_fields`): `references`,
`remediation`, `metadata`, `info`, and any Nuclei-style block. They parse without warning
and have no effect. **[verified]** — a document with `totally_bogus_key: 42` loads clean.

### 3.5 Protocol detection (YAML only)

`detect_protocols` (`yaml/mod.rs:195-256`): `http` block ⇒ `Http` + `Https`; each `network`
entry maps its `protocol` string to `Tcp`/`Udp`/`Dns`/`Ssh`/`Ftp`/`Smtp`/`Smb`/`Rdp`, with
anything else becoming `Protocol::Custom(s)`; `flows` containing an `HttpRequest` step adds
HTTP/HTTPS. **If nothing is detected it warns and defaults to HTTP/HTTPS** (`:245-253`).

Non-YAML templates don't declare protocols at all — `Template::supported_protocols` has a
blanket default of `[Http, Https]` (`src/template/engine.rs:25-27`).

### 3.6 The *third* template format — pentest JS probes (NEW detail)

`cxg pentest` templates are JavaScript files with `// @key: value` meta headers, parsed by
`parse_template` in `pentest/js_engine.py` — a completely separate implementation from the
Rust annotation parser in §3.1. Headers are read **regardless of line position** (not
limited to the first 50 lines), which is what lets the generator inject them post-hoc.

Meta keys the engine actually reads (`pentest/js_engine.py:102-131`, `:1209`):

| Header | Type | Default | Added | Notes |
|--------|------|---------|-------|-------|
| `@id` | string | file stem | pre-v1.2.0 | |
| `@vuln_class` | string | `"unknown"` | pre-v1.2.0 | |
| `@severity` | string | `"medium"` | pre-v1.2.0 | |
| `@requires_auth_count` | int | `1` | pre-v1.2.0 | Chained-auth arity |
| `@destructive_priority` | int | `0` | pre-v1.2.0 | Ordering hint (`:1209`) |
| `@requires_capability` | string | `""` | **#41** | Enforced by `pentest/validator.py`; required on any template calling `cxg.ipc` |
| `@threat_id` | string | `None` | **#48** | Injected deterministically by `js_generator.py`, not by the model. **Undocumented** (§1.2) |

Template-visible bridge namespaces, for reference: `cxg.*` (HTTP/cookie primitives),
`cxg.oast.url(label, scheme?)` / `cxg.oast.poll(label)` (§1.1), and `cxg.ipc.*` (Electron
IPC, gated on `@requires_capability`). Documented in `pentest/docs/TEMPLATES.md` **except**
`@threat_id`.

---

## 4. Protocol / execution model

### 4.1 Discovery → load → filter → execute

```
PathResolver::all_template_dirs()          src/template/paths.rs:67
  ├─ /usr/local/share/cert-x-gen/templates    (system)
  ├─ ~/.cert-x-gen/templates                  (user)
  └─ ./templates                              (local)
        ↓  --template-dir overrides
TemplateLoader::load_templates_from_dir     src/template/engine.rs:121-187
  ├─ extension gate  is_valid_template_file  :98-118
  ├─ skip dirs: target, node_modules, .git, __pycache__, _disabled, skeleton   :156-168
  └─ first engine whose supports_file() returns true wins   :87-95
        ↓
TemplateFilter::matches                     src/template/engine.rs:225-306
        ↓
Scheduler → Executor → Engine::execute      src/scheduler.rs, src/executor.rs
```

**Load failures are non-fatal in directory mode** — `load_templates_from_dir` logs
`tracing::warn!` and continues (`engine.rs:150-152`). A broken template is invisible at
default verbosity; you need `-vv` to see it. In *direct-path* mode (`--templates ./x.yaml`)
a failure is a hard error instead (`src/main.rs:770-778`). Inconsistent, and worth
documenting.

### 4.2 Extension → engine dispatch

Registration order (`src/core.rs:39-58`) determines precedence; extensions don't overlap.

| Engine | Extensions | Invocation | Compiled? |
|--------|-----------|------------|-----------|
| YAML | `.yaml`, `.yml` | In-process (serde + matcher + `NetworkClient`) | — |
| Python | `.py` | `python3 <script>` | No |
| Rust | `.rs` | `cargo build --release` if `Cargo.toml` present, else `rustc -O` | Yes |
| Shell | `.sh`, `.bash` | `<shell> <script> <host> <port> --json` | No |
| JavaScript | `.js` | `node <script>` | No |
| C | `.c` | `gcc -O2 -std=c11` | Yes |
| C++ | `.cpp`, `.cc`, `.cxx` | `g++ -O2 -std=c++17 -lcurl` | Yes |
| Java | `.java` | `javac -d <cache>` then `java` | Yes |
| Go | `.go` | `go build -o` | Yes |
| Ruby | `.rb` | `ruby <script>` | No |
| Perl | `.pl` | `perl <script>` | No |
| PHP | `.php` | `php <script>` | No |

Compile cache: `/tmp/cert-x-gen-cache/<language>/` (`common.rs:705-707`), keyed by a
`DefaultHasher` over path + file length + mtime (`:710-726`). **Not content-addressed** —
a same-length edit preserving mtime would serve a stale binary.

### 4.3 The language boundary — process contract

**This is the real "protocol", and it is not uniform.**

| Direction | Mechanism |
|-----------|-----------|
| Host → template (all languages) | Environment variables (`build_env_vars`, `common.rs:372-411`) |
| Host → template (Shell **only**) | **Also** positional argv: `<script> <host> <port> --json` (`src/engine/shell/mod.rs:40-45`) |
| Template → host | JSON on **stdout** |
| Errors | Non-zero exit ⇒ `Error::Execution` with stderr attached (`common.rs:685-688`). **No timeout is applied** — `templates.timeout_secs` is not enforced in `execute_command` |

Every other language (Python, JS, Ruby, Perl, PHP, and all compiled ones) receives
**only the script/binary path** and reads everything from the environment
(e.g. `src/engine/python/mod.rs:39-45`). README's universal "read
`CERT_X_GEN_TARGET_HOST`/`CERT_X_GEN_TARGET_PORT` from environment" contract is correct,
but omits Shell's extra argv convention.

**Result parsing** (`parse_findings`, `common.rs:414-444`) tries three shapes in order:

1. A bare `Vec<Finding>` (full `types::Finding` schema).
2. `{"findings": [...], "metadata": {...}}` — tries full `Finding`, then the simplified shape.
3. A bare array in the simplified shape.

Simplified-shape field mapping (`parse_simple_findings`, `:446-549`):

| JSON key | Maps to | Default if absent |
|----------|---------|-------------------|
| `template_id` | `template_id` | the template's own id |
| `severity` | `severity` | `medium`; **anything unrecognised ⇒ `Info`** (`:470`) — note this differs from the annotation parser's `Medium` fallback |
| `confidence` | `confidence` | `50` |
| `title` | `title` | `"Unknown"` |
| `description` | `description` | `""` |
| `evidence.{request,response,matched_patterns,data}` | `Evidence` | empty |
| `cwe` | `cwe_ids` | ⚠️ **always produces a 1-element vec containing `""`** when absent (`:522-526`) |
| `cvss_score` | `cvss_score` | `null` |
| `remediation` | `remediation` | `null` |
| `references` | `references` | `[]` |
| — | `cve_ids` | **always `[]`** — no JSON key is read (`:521`) |
| — | `tags` | **always `[]`** — no JSON key is read (`:542`) |

Empty stdout ⇒ zero findings, not an error (`:415-417`).

### 4.4 Pentest boundary — Rust as a launcher

`cxg pentest` is a **thin argv translator**, not an implementation:

1. `pentest install` copies bundled Python to `~/.cert-x-gen/pentest/` (`src/main.rs:505+`);
   source located via `CXG_SOURCE`, else discovery (`:563-587`).
2. Every other action requires `~/.cert-x-gen/pentest/cxg_pentest.py` to exist, else a hard
   error telling you to run `cxg pentest install` (`src/main.rs:305-315`).
3. Rust builds an argv vector from the clap struct (`src/main.rs:318+`) and execs
   `<python3> cxg_pentest.py <subcommand> …` (`:474`).
4. **The child's exit code is propagated verbatim** via `std::process::exit` (`:480`) —
   this is how the documented `0/1/2/3` codes reach the shell.

Everything downstream — SARIF parsing, LLM ranking, template generation, Playwright
execution, triage, mutation, `report.json`/`audit.jsonl` — is Python. The
`threat_id` pipeline from PR #48 lives **entirely** in this Python half; Rust never sees it.

The Rust half stayed thin through this delta: `src/main.rs` gained only +60 lines, all of
it forwarding the 11 new flags into the argv vector (`--target-type`, `--app-cmd`,
`--app-binary`, `--host-scan-path`, `--template-timeout`, `--stall-timeout`,
`--no-restart`, and the tri-state `--oast-interactsh`, which pushes the flag alone when the
value is empty). No new logic crossed into Rust.

### 4.5 The substrate seam (NEW — this is the delta's central abstraction)

Before v1.2.0, `js_engine.py` opened Playwright browser contexts directly. The desktop work
extracted that into a **`Substrate` protocol** (`pentest/targets/base.py:63-90`) with two
implementations, so the orchestrator is target-agnostic:

```
Substrate (Protocol)                    pentest/targets/base.py:63
  ├─ open(profiles, *, headless) -> list[Surface]
  ├─ install_bridge(surface, bridge_ctx, ...)
  ├─ verify(surface) -> Liveness
  ├─ close()
  └─ describe() -> dict

RestartableSubstrate(Substrate)         :93
  └─ restart(index) -> Surface          ← crash recovery hook

  implementations:
    targets/web.py       (87)   — the pre-existing browser path
    targets/electron.py  (687)  — launch, isolate, CDP-attach N app instances
    targets/bridge.py    (472)  — bridge/BridgeContext plumbing shared by both
```

Supporting types: `Surface` (`:21`) — one drivable renderer; `Liveness` (`:34`) — the
three-state health result crash recovery depends on; `BridgeContext` (`:41`) — carries the
optional OAST session, deliberately duck-typed as `Any` so `targets/` never imports the
networked OAST module (`:54`).

**Language-boundary implication for the docs:** the Rust↔Python boundary is unchanged
(argv + exit code), but the Python side now has a *second* internal boundary — the
substrate seam — and that is where web and desktop behaviour diverge. Anything written
about "how a pentest runs" now needs to say which substrate it means.

### 4.6 Revised pentest pipeline

```
guardlink.py            SARIF → Hypothesis (+ threat_id, PR #48)
electron_surface.py     [electron] extract IPC channels + config claims as hypotheses
threat_correlation.py   map routeless threats → candidate IPC channels;
                          unreachable ones → review_only_threats
ai_generator.py /       LLM → JS templates   (providers: bridge, claude, codex,
js_generator.py           gemini, anthropic, openai — §5.3)
validator.py            static gate (+ @requires_capability enforcement, PR #41)
targets/*.py            substrate.open() → Surfaces; install_bridge()
js_engine.py            dispatch templates; cxg / cxg.ipc / cxg.oast namespaces
config_probes.py        [electron] renderer hardening claims, confirmed live
host_probes.py          [electron] data at rest, update channel (page-less)
oast.py                 [--oast-interactsh] register + poll; callback ⇒ confirmed=true
mutator.py              retry-with-mutation on AMBIGUOUS
session_health.py       liveness; stall watchdog; restart (max 2/instance, 3/run)
scope.py                URL/method allowlist, budgets, 5xx kill
  ↓
report.json + audit.jsonl
```

`report.json` gained several keys in the cumulative delta (`pentest/cxg_pentest.py`):
`caveats` (with `affects` and `empty_findings_means` — an explicit "absence of findings does
NOT mean clean" envelope), `review_only_threats`, `restarts_performed`,
`restarted_profiles`, `dead_profiles_recovered`/`dead_profiles_still_dead`, and per-finding
`threat_id`. **No `report.json` schema document exists anywhere in the repo** — this is now
a materially larger gap than it was at revision 1.

**Rev 3 additions (§1.0 window, all Python).** Two more provenance surfaces landed since the
Rev 2 base:
- **Per-request actor identity** — the JS engine now stamps *which captured identity issued
  each request* (`pentest/js_engine.py`, PR #52), so cross-identity triage no longer infers
  the actor after the fact. Surfaces in `audit.jsonl`.
- **`auth_provenance` in the run manifest** — one record per profile: a sha256 fingerprint of
  the `storage_state` (never the cookie value), plus `captured_at`/`expires_at` and whether
  pre-flight found it fresh (PR #53, B2). `auth_profiles` stays a plain name list so the
  existing dashboard parse is untouched. Written only when the CI path runs — which today
  means only via direct `python3 cxg_pentest.py` invocation (§1.0).
- **Empty-evidence triage fix** (`pentest/mutator.py`, `7ec80a6`): `evidence={}` is now
  correctly classified AMBIGUOUS instead of "confirmed with evidence," so confirmed-finding
  counts in `report.json` are slightly more conservative than at the Rev 2 base.

---

## 5. Config

> **Revision 3: re-verified unchanged.** `src/config.rs` and `src/ai/config.rs` are in the
> empty `46582a5..HEAD -- src/` diff — untouched since v1.2.0. `cert-x-gen.example.yaml` is
> unchanged and **still fails to load** — re-confirmed against the freshly built `78226a7`
> binary with the identical error (`missing field 'passive_mode' at line 73 column 3`, §6.1).
> Every key, default, and required/optional determination below still holds byte-for-byte.
>
> **New in Rev 3: §6.3 now carries the full dead-config-key inventory** (Item A). The headline:
> of the **51 leaf keys in `Config`, only 17 have any behavioural effect** — 34 are parsed and
> inert; and of `AIConfig`'s keys, `fallback_providers`, all of `cost_tracking`, and all of
> `cache` are dead. `cert-x-gen.example.yaml` documents many of the inert ones as if live.

### 5.1 File locations and precedence

**There is no config auto-discovery.** `src/main.rs:720-724`:

```rust
let mut config = if let Some(path) = config_path {
    Config::from_file(path)?
} else {
    Config::default()
};
```

| Rank | Source | Notes |
|------|--------|-------|
| 1 (highest) | CLI flags | `apply_scan_args_to_config` (`src/main.rs:727`) overwrites after load |
| 2 | `--config <FILE>` / `-c` | **Explicit path only** |
| 3 | `Config::default()` | Compiled-in defaults (`src/config.rs`) |

Consequences worth documenting loudly:
- `~/.cert-x-gen/cert-x-gen.yaml` is **never** read. Neither is `./cert-x-gen.yaml`.
- `cxg config generate` defaults to writing `cert-x-gen.yaml` in the CWD — a file nothing
  will subsequently load unless passed with `--config`.
- **No environment variable configures scan behaviour.** README's "Configurable via CLI,
  config file, or environment variables" (README:302) is inaccurate; the env vars in §2.12
  are operational toggles, not configuration.

Format is chosen by **extension** (`src/config.rs:37-45`): `.yaml`/`.yml`, `.toml`, `.json`.
Any other extension ⇒ `"Unsupported config file format"`.

**Related but separate paths:**

| Path | Purpose | Source |
|------|---------|--------|
| `~/.cert-x-gen/` | User config root | `paths.rs:55-59` |
| `~/.cert-x-gen/templates/` | User templates | `paths.rs:43-47` |
| `~/.cert-x-gen/cache/` | Template cache | `paths.rs:62` |
| `~/.cert-x-gen/ai-config.yaml` | **AI config — separate file, auto-loaded** | `src/ai/config.rs:201-205` |
| `~/.cert-x-gen/cache/ai-responses/` | AI response cache | `ai/config.rs:208-212` |
| `~/.cert-x-gen/auth/<profile>.json` | Pentest auth profiles | `src/cli.rs:226` |
| `~/.cert-x-gen/sessions/pentest-<ts>/` | Pentest artifacts | `src/cli.rs:544` |
| `~/.cert-x-gen/pentest/` | Python orchestrator | `src/main.rs:285` |
| `/usr/local/share/cert-x-gen/templates` | System templates | `paths.rs:11-14` |
| `./templates` | Local templates | `paths.rs:50-51` |
| `/tmp/cert-x-gen-cache/<lang>/` | Compile cache | `common.rs:705-707` |

### 5.2 Main config — every key

Authoritative source: `cxg config generate` output (serialises the real struct) — the
values below round-trip cleanly through `cxg config validate`. **[verified]**

⚠️ **Any key without a `#[serde(default)]` is REQUIRED** — omitting it is a hard load
error, not a fallback. This is what breaks the shipped example (§6.1).

#### `global` (`src/config.rs:87-110`)

| Key | Type | Default | Required in file? |
|-----|------|---------|-------------------|
| `verbosity` | `u8` (0-3) | `1` | Yes |
| `color` | bool | `true` | Yes |
| `log_level` | string | `"info"` | Yes |
| `log_file` | path \| null | `null` | Yes (may be `null`) |
| `debug` | bool | `false` | Yes |

#### `templates` (`src/config.rs:119-159`)

| Key | Type | Default | Required in file? |
|-----|------|---------|-------------------|
| `directories` | `[path]` | `[]` (empty ⇒ use discovery) | Yes |
| `use_system_templates` | bool | `true` | **No** (`default = "default_true"`) |
| `use_user_templates` | bool | `true` | **No** |
| `use_local_templates` | bool | `true` | **No** |
| `auto_update` | bool | `false` | Yes |
| `cache_dir` | path | `~/.cert-x-gen/cache` | Yes |
| `enabled_languages` | `[enum]` | `[yaml, python, rust, shell]` | Yes |
| `timeout_secs` | `u64` | `30` | Yes |

> Two notes: the default `enabled_languages` covers only **4 of 12** languages; and
> `timeout_secs` is **not enforced** by `execute_command` (§4.3).

#### `network` (`src/config.rs:163-206`)

| Key | Type | Default | Required in file? |
|-----|------|---------|-------------------|
| `timeout_secs` | `u64` | `10` | Yes |
| `user_agent` | string | `cert-x-gen/<CARGO_PKG_VERSION>` | Yes |
| `follow_redirects` | bool | `true` | Yes |
| `max_redirects` | `usize` | `5` | Yes |
| `connection_pool_size` | `usize` | `100` | Yes |
| `http2` | bool | `true` | Yes |
| `proxy` | string \| null | `null` | Yes (may be `null`) |
| `dns_servers` | `[string]` | `[]` | Yes |
| `rate_limit` | `u32` \| null | `100` | Yes |
| `headers` | `[[k,v]]` | `[]` | **No** (`#[serde(default)]`) |
| `cookies` | `[[k,v]]` | `[]` | **No** |

> `network.timeout_secs` default is `10`, but `scan --timeout` defaults to `30s`. Different
> defaults for the same concept.

#### `execution` (`src/config.rs:210-248`)

| Key | Type | Default | Required in file? |
|-----|------|---------|-------------------|
| `threads` | `usize` | `num_cpus::get()` | Yes |
| `parallel_targets` | `usize` | `50` | Yes |
| `parallel_templates` | `usize` | `10` | Yes |
| `max_retries` | `u32` | `1` | Yes |
| `retry_delay_secs` | `u64` | `1` | Yes |
| `aggressive_mode` | bool | `false` | Yes |
| `stealth_mode` | bool | `false` | Yes |
| `passive_mode` | bool | `false` | **Yes — missing from the shipped example** |
| `safe_mode` | bool | `false` | **Yes — missing from the shipped example** |
| `cache_enabled` | bool | `true` | Yes |

Validated at `src/config.rs:68-82`: `threads`, `parallel_targets`, and
`network.timeout_secs` must all be `> 0`.

#### `output` (`src/config.rs:252-275`)

| Key | Type | Default | Required in file? |
|-----|------|---------|-------------------|
| `formats` | `[string]` | `["json"]` | Yes |
| `output_dir` | path | `results` | Yes |
| `output_file` | string | `"scan-results"` | Yes |
| `stream` | bool | `false` | Yes |
| `min_severity` | enum | `info` | Yes |

Valid `formats` values (registered at `src/output.rs:1099-1105`): `json`, `csv`,
`markdown`, `sarif`, `html`. **`xml` is not registered** (§6.4). Output filename is
`<output_file>.<format>` verbatim — `markdown` yields `.markdown`, not `.md`. **[verified]**

#### `sandbox` (`src/config.rs:279-302`) — ⚠️ **entirely inert, see §6.3**

| Key | Type | Default | Required in file? |
|-----|------|---------|-------------------|
| `enabled` | bool | `true` | Yes |
| `memory_limit_mb` | `usize` | `512` | Yes |
| `cpu_limit_percent` | `usize` | `80` | Yes |
| `network_access` | `none\|controlled\|full` | `controlled` | Yes |
| `filesystem_access` | `none\|readonly\|full` | `readonly` | Yes |

#### `metrics` (`src/config.rs:330-347`)

| Key | Type | Default | Required in file? |
|-----|------|---------|-------------------|
| `enabled` | bool | `true` | Yes |
| `export_port` | `u16` | `9090` | Yes |
| `export_format` | `prometheus\|json` | `prometheus` | Yes |

#### `plugins` (`src/config.rs:361-378`)

| Key | Type | Default | Required in file? |
|-----|------|---------|-------------------|
| `enabled` | bool | `false` | Yes |
| `directories` | `[path]` | `["plugins"]` | Yes |
| `plugins` | `[string]` | `[]` | Yes |

### 5.3 AI provider config — `~/.cert-x-gen/ai-config.yaml`

**Separate file, separate lifecycle.** Unlike the main config this **is** auto-loaded, and
`AIConfig::load()` **writes a default file on first run if none exists**
(`src/ai/config.rs:158-166`).

#### Top level (`src/ai/config.rs:14-33`)

| Key | Type | Default | Required? |
|-----|------|---------|-----------|
| `default_provider` | string | `"ollama"` (`:100-102`) | No |
| `fallback_providers` | `[string]` | `["ollama"]` (`:128`) | No |
| `providers` | map of `ProviderConfig` | the 4 below | No |
| `cost_tracking` | object | see below | No |
| `cache` | object | see below | No |

All top-level keys carry `#[serde(default)]` — an empty AI config file is valid.

#### `providers.<name>` (`ProviderConfig`, `src/ai/config.rs:38-65`)

| Key | Type | Default | Required? |
|-----|------|---------|-----------|
| `enabled` | bool | `true` (`default_true`) | No |
| `endpoint` | string | provider-specific (below) | No |
| `api_key` | string | provider-specific | No |
| `model` | string | — | **Yes** — no default, no `#[serde(default)]` |
| `max_tokens` | `u32` | provider-specific | No |
| `temperature` | `f32` | provider-specific | No |
| `timeout_secs` | `u64` | provider-specific | No |

#### Shipped provider defaults (`src/ai/config.rs:261-321`)

| Provider | `enabled` | `endpoint` | `api_key` | `model` | `max_tokens` | `temperature` | `timeout_secs` |
|----------|-----------|------------|-----------|---------|--------------|---------------|----------------|
| `ollama` | `true` | `http://localhost:11434` | `null` | `codellama:13b` | `4000` | `0.7` | `300` |
| `openai` | `false` | `null` → `https://api.openai.com/v1` (`providers/openai.rs:78`) | `${OPENAI_API_KEY}` | `gpt-4` | `4000` | `0.7` | `60` |
| `anthropic` | `false` | `null` → `https://api.anthropic.com/v1` (`providers/anthropic.rs:86`) | `${ANTHROPIC_API_KEY}` | `claude-3-5-sonnet-20241022` | `4000` | `0.7` | `60` |
| `deepseek` | `false` | `null` → `https://api.deepseek.com/v1` (`providers/deepseek.rs:47`) | `${DEEPSEEK_API_KEY}` | `deepseek-coder` | `4000` | `0.7` | `60` |

**`${VAR}` expansion** (`src/ai/config.rs:215-238`): a key of the exact form `${NAME}` is
replaced with `$NAME` if set and non-empty — and doing so **auto-enables the provider**
(`:227`), overriding `enabled: false`. Partial interpolation (`sk-${SUFFIX}`) is **not**
supported; the whole value must be `${…}`.

Resolution order for `cxg ai generate`: `--api-key` (session-only, never persisted,
`src/cli.rs:2188-2196`) → `${…}` env expansion → literal `api_key` in the file.

#### `cost_tracking` (`src/ai/config.rs:69-80`)

| Key | Type | Default |
|-----|------|---------|
| `enabled` | bool | `true` |
| `warn_threshold` | `f64` | `1.0` (USD) |
| `max_per_month` | `f64` | `50.0` (USD) |

#### `cache` (`src/ai/config.rs:85-96`)

| Key | Type | Default |
|-----|------|---------|
| `enabled` | bool | `true` |
| `ttl_hours` | `u32` | `24` |
| `max_size_mb` | `u32` | `100` |

#### Pentest AI providers — a **third**, unrelated configuration

`cxg pentest run --ai-provider` does **not** read `ai-config.yaml`. It uses the Python
registry at `pentest/ai_generator.py:211-220`:

| Name | Class | Availability gate |
|------|-------|-------------------|
| `bridge` | `BridgeProvider` | `$BUGB_BRIDGE_URL` set — **new, undocumented** |
| `claude` | `ClaudeCliProvider` | `claude` on PATH |
| `codex` | `CodexCliProvider` | `codex` on PATH |
| `gemini` | `GeminiCliProvider` | `gemini` on PATH |
| `anthropic` / `anthropic-api` | `AnthropicApiProvider` | `$ANTHROPIC_API_KEY` (both names are valid aliases) |
| `openai` / `openai-api` | `OpenAiApiProvider` | `$OPENAI_API_KEY` (both aliases valid) |

`auto` order (`:225`): `bridge → claude → codex → gemini → anthropic-api → openai-api`.
The flag's default is `claude`, **not** `auto` (`src/cli.rs:501`).

---

## 6. Doc debt

### 6.1 🔴 `cert-x-gen.example.yaml` does not load **[verified]**

```
$ cxg config validate cert-x-gen.example.yaml
Error: Configuration error: Invalid YAML config:
       execution: missing field `passive_mode` at line 73 column 3
```
Same failure via `cxg scan --config`. The file has drifted from `ExecutionConfig`
(`src/config.rs:210-231`), which gained `passive_mode` and `safe_mode` without
`#[serde(default)]`. Its `output.formats` comment also advertises `xml` (line 97), which
doesn't work (§6.4). Fix by regenerating from `cxg config generate`, whose output does
round-trip. **[verified]**

### 6.2 🔴 The YAML skeleton does not load **[verified]**

`templates/skeleton/yaml-template-skeleton.yaml` — what `cxg template skeleton yaml`
hands users — fails engine deserialization on **two** independent counts:

```
$ cxg scan --template-dir <dir-with-skeleton> ...
WARN Failed to load template …/yaml-template-skeleton.yaml: YAML parse error:
     http[0].matchers[4].type: unknown variant `dsl`,
     expected one of `status`, `word`, `regex`, `binary`, `time`, `size`,
     `hash`, `tls`, `dns`, `diff`, `custom` at line 67 column 15
```

1. Uses a **`dsl` matcher**, which the engine does not implement (`src/matcher.rs:13-106`).
2. Declares `author: CERT-X-GEN Security Team` as a **plain string**, but the schema
   requires an `AuthorInfo` object — `invalid type: string, expected struct AuthorInfo`.
   **[verified independently]**

**And `cxg template validate` reports it as passing** (`✓ … Success Rate: 100%`), because
`validate` runs a separate linter rather than the engine's serde path. Two code paths
disagree about what a valid template is — the rebuild should not describe them as one.

The skeleton additionally carries a `# @id:` comment header that the YAML engine ignores
entirely (§3), and a `references:` key that is silently dropped (§3.4).

**Revision 2 — scope of the problem measured.** Loading all 12 shipped skeletons through
the engine at once gives a precise result: **11 load, 1 fails.** **[verified @ 46582a5]**

```
$ cxg scan --scope 127.0.0.1 --template-dir <all-12-skeletons> -vv
WARN  Failed to load template ./sk/yaml-template-skeleton.yaml: … unknown variant `dsl` …
INFO  Loaded 11 templates from ./sk
```

So the 11 annotation-language skeletons are sound; YAML is the sole failure. Note the
`dsl` error aborts parsing before the `author` type error is reached, so **fixing only the
matcher will surface a second failure** — both must be fixed together.

### 6.3 🔴 The sandbox does not sandbox

README:279 — "**Sandboxed by default** — templates run with strict resource limits."
README:289 / CHANGELOG 1.0.0 — "Sandboxed execution with configurable resource limits."

**No template execution path applies any isolation.** Templates run as ordinary child
processes via `tokio::process::Command` (`src/engine/common.rs:667-692`) with the host's
full network and filesystem access.

Evidence:
- `grep -rn "sandbox" src/engine/ src/executor.rs src/core.rs` → only hits in
  `src/engine/README.md` prose. Zero code references.
- The only consumer of `config.sandbox` is `ResourceManager::new` (`src/scheduler.rs:143-151`),
  and **`ResourceManager` is never constructed outside its own unit test** —
  `grep -rn "ResourceManager"` outside `scheduler.rs` returns nothing.
- `max_cpu_percent` is explicitly `#[allow(dead_code)]` (`src/scheduler.rs:133`).
- `sandbox.enabled`, `network_access`, and `filesystem_access` have **zero** consumers
  anywhere in `src/`.

The `cxg sandbox` command tree is real, but it manages **dependency environments**
(venv/npm/gem, or a Docker dev container you `enter`) — it does not confine template
execution. The rebuild must not repeat the "sandboxed by default" claim.

#### 6.3.1 🔴 Item A — full DEAD CONFIG KEY inventory

The sandbox block is one instance of a wider class: **most of `Config` is parsed and then
never read.** Method — for every leaf key in `Config` (`src/config.rs`) and `AIConfig`
(`src/ai/config.rs`), grep for any *read* consumer outside those two files
(`grep -rn "\.<field>\b" --include=*.rs src/`, then discard writes and same-struct hits, and
follow getters like `default_provider_name()`). "Consumer" = a read that reaches behaviour;
a write in `apply_scan_args_to_config` with no corresponding read is **not** a consumer.
All determinations below are at `78226a7` (`src/` byte-identical to `46582a5`).

**Headline: of 51 leaf keys in `Config`, only 17 have any behavioural effect.**

**`Config` — LIVE keys (17):**

| Key | Consumer | Effect |
|-----|----------|--------|
| `templates.directories` | `core.rs:77,82`, `main.rs:798` | Template discovery roots (when non-empty) |
| `templates.timeout_secs` | `executor.rs:191,197`, `main.rs:1248`, `mcp/server.rs` | Per-template execution timeout |
| `network.timeout_secs` | `network.rs:42` | HTTP client timeout |
| `network.user_agent` | `network.rs:43` | UA header |
| `network.follow_redirects` | `network.rs:55` | Redirect policy |
| `network.max_redirects` | `network.rs:57` | Redirect cap |
| `network.connection_pool_size` | `network.rs:44` | Pool size |
| `network.proxy` | `network.rs:64` | Proxy |
| `network.rate_limit` | `network.rs:75` | Rate limiter |
| `network.headers` | `core.rs:246` | Injected request headers |
| `network.cookies` | `core.rs:247` | Injected cookies |
| `execution.parallel_targets` | `executor.rs:32,99` | Target concurrency |
| `execution.parallel_templates` | `executor.rs:165` | Template concurrency |
| `execution.max_retries` | `network.rs:113,219`, `core.rs:245` | Retry count |
| `execution.retry_delay_secs` | `network.rs:162,189` | Retry backoff |
| `execution.aggressive_mode` | `main.rs:1195-1200`, `core.rs:241` | Doubles concurrency, drops rate limit |
| `execution.stealth_mode` | `network.rs:121,227` | Adds request jitter/delay |

**`Config` — DEAD keys (34) — parsed, no behavioural consumer:**

| Key | Consumers outside config.rs | Effect of setting it |
|-----|-----------------------------|----------------------|
| `global.verbosity` | none — log level comes from the CLI `--verbose` count | **None** |
| `global.color` | none | **None** (color from `--no-color`) |
| `global.log_level` | none | **None** |
| `global.log_file` | none | **None** — no file logging is wired |
| `global.debug` | none | **None** |
| `templates.use_system_templates` | none | **None** — discovery walks all roots regardless |
| `templates.use_user_templates` | none | **None** |
| `templates.use_local_templates` | none | **None** |
| `templates.auto_update` | none | **None** — auto-update is driven by CLI flags, not this key |
| `templates.cache_dir` | none — each compiled engine computes its own via `get_cache_dir()` | **None** |
| `templates.enabled_languages` | none | **None** — every extension's engine is always registered |
| `network.http2` | none — `network.rs:47` explicitly comments it is *not* applied | **None** |
| `network.dns_servers` | none | **None** — no custom resolver is built |
| `execution.threads` | write-only (`main.rs:1185`) | **None** — no thread pool is sized from it |
| `execution.passive_mode` | copied to `ScanContext` (`core.rs:243`) but `context.passive_mode` (`types.rs:258`) is never read | **None** (⚠️ Rev 2 marked `--passive` ✅ — corrected: the context field is dead) |
| `execution.safe_mode` | copied to `ScanContext` (`core.rs:244`), `context.safe_mode` (`types.rs:260`) never read | **None** (⚠️ same correction as `--passive`) |
| `execution.cache_enabled` | none | **None** |
| `output.formats` | none — `run_scan` uses `args.output_format` (`main.rs:1170`) | **None** |
| `output.output_dir` | none — output path is `args.output` | **None** |
| `output.output_file` | none | **None** |
| `output.stream` | write-only (`main.rs:1275`); sink `stream_finding` never called | **None** (matches the `--stream` flag correction, §2.3) |
| `output.min_severity` | none | **None** — no severity gate on output |
| `sandbox.enabled` | none | **None** (§6.3) |
| `sandbox.memory_limit_mb` | only `ResourceManager::new` (`scheduler.rs:145`), which is constructed **only in a `#[test]`** (`scheduler.rs:267`) | **None** |
| `sandbox.cpu_limit_percent` | only `ResourceManager::new` (`scheduler.rs:147`), test-only; field is `#[allow(dead_code)]` | **None** |
| `sandbox.network_access` | none | **None** |
| `sandbox.filesystem_access` | none | **None** |
| `metrics.enabled` | none — `src/metrics.rs` is a complete Prometheus collector that is **never referenced** from anywhere in `src/` (no `metrics::` use outside the file; no collector is constructed) | **None** |
| `metrics.export_port` | none — no metrics HTTP server exists | **None** |
| `metrics.export_format` | none | **None** |
| `plugins.enabled` | none — `PluginManager::new()` takes no config (`plugin.rs:53`) | **None** |
| `plugins.directories` | none | **None** |
| `plugins.plugins` | none | **None** |

**`AIConfig` — LIVE (7):** `default_provider` (via `default_provider_name()`, `ai/manager.rs:59`,
`149`), and per-provider `enabled` (`is_provider_enabled()`), `endpoint`, `api_key`, `model`,
`max_tokens`, `temperature`, `timeout_secs` (all read by `ai/manager.rs` + `ai/providers/*`).

**`AIConfig` — DEAD (7):**

| Key | Consumers outside ai/config.rs | Effect of setting it |
|-----|-------------------------------|----------------------|
| `fallback_providers` | none — the getter `fallback_providers()` and the priority helpers `get_best_provider`/`get_enabled_providers`/`get_providers_in_priority` have **zero callers** | **None** — no fallback chain runs |
| `cost_tracking.enabled` | validated for sign only (`validate()`); `record_cost`/`would_exceed_limit`/`CostTrackingData` have **no external callers** | **None** — cost is never tracked or enforced during generation |
| `cost_tracking.warn_threshold` | none (validate-only) | **None** |
| `cost_tracking.max_per_month` | none (validate-only) | **None** |
| `cache.enabled` | none — `AIConfig::cache_dir()` (`ai/config.rs:208`) has **no callers**; no AI-response caching is implemented | **None** |
| `cache.ttl_hours` | none (validate-only) | **None** |
| `cache.max_size_mb` | none (validate-only) | **None** |

**Confirmation of the task's known-inert list:** `enabled_languages`, `use_system_templates`,
`use_user_templates`, `use_local_templates`, `cache_enabled`, `dns_servers`, `min_severity`,
`export_port`, `export_format`, and the five sandbox keys are all confirmed dead above.
**Newly found dead beyond that list:** `global.{verbosity,color,log_level,log_file,debug}`,
`templates.{auto_update,cache_dir}`, `network.http2`, `execution.{threads,passive_mode,
safe_mode}`, `output.{formats,output_dir,output_file,stream}`, `metrics.enabled`,
`plugins.{enabled,directories,plugins}`, and on the AI side `fallback_providers`, all of
`cost_tracking`, all of `cache`.

**Dead-key count: 34 of 51 `Config` leaf keys, plus 7 `AIConfig` keys = 41 dead.**

### 6.4 🟠 `xml` output format is advertised but unregistered **[verified]**

```
$ cxg scan … --output-format xml,markdown,json --output out
WARN Unknown output format: xml
INFO Writing markdown output to out.markdown
INFO Writing json output to out.json
$ ls out.*    →    out.json  out.markdown
```
`xml` is advertised in `--output-format` help (`src/cli.rs:1174`), in the `scan`
`after_help` (`:729`), and in `cert-x-gen.example.yaml:97`. Unknown formats produce a
`tracing::warn!` only (`src/output.rs:1130`) — **no error, no file, exit code 0**. In a CI
pipeline this fails silently.

Conversely **`markdown` is registered and works but is not advertised** in
`--output-format`'s help, which lists only `json, csv, sarif, html, xml`.

### 6.5 🟠 `@references` is parsed and thrown away

`parse_metadata_from_comments` populates `ParsedMetadata.references`
(`src/engine/common.rs:182-184`), but `create_metadata` never reads it (`:608-645`) and
`TemplateMetadata` has no `references` field (`src/types.rs:527-588`). Every skeleton ships
a `@references:` line (e.g. `templates/skeleton/python-template-skeleton.py:12`), so
template authors are being taught an annotation that has no effect.

Same class of issue: `@cve` is never parsed at all — `cve_ids` is hardcoded to
`Vec::new()` (`common.rs:618`), and the runtime `parse_simple_findings` path also always
emits `cve_ids: []` (`:521`).

### 6.6 🟠 CHANGELOG 1.1.1 describes fields that don't exist

CHANGELOG lists "5 new metadata fields for Bravos pipeline routing: `context_vars`,
`batch_group`, `confidence`, `execution_mode`, `pipeline_stage`".

The actual struct (`src/types.rs:566-587`) has `context_vars`, `vuln_class`,
`hypothesis_tags`, `batch_group`, `auto_probe`. **`execution_mode` and `pipeline_stage`
do not exist**; `vuln_class`, `hypothesis_tags`, and `auto_probe` are undocumented.

### 6.7 🟠 Other README ↔ code disagreements

| README | Reality |
|--------|---------|
| `--format json -o results.json` (README:206-215) | **No `--format` flag on `scan`** — `error: unexpected argument '--format' found`. **[verified @ 78226a7]** It's `--output-format`. **Correction to Rev 2:** `-o` is a path stem whose *trailing extension is replaced* (`base_path.with_extension(format)`, `output.rs:1124`), it is **not** appended. So `-o results.json --output-format json` → `results.json` (not `results.json.json`); `-o report.txt --output-format json` → **`report.json`** (the `.txt` is silently overwritten); `-o results.tar.gz` → `results.tar.json`. **[verified @ 78226a7]** |
| "Multiple output formats (JSON, HTML, CSV, Markdown, SARIF)" (README:296) | Correct — but `--output-format` help omits `markdown` and adds a non-existent `xml` (§6.4) |
| "Configurable via CLI, config file, or environment variables" (README:302) | No env var configures scan behaviour; no config auto-discovery (§5.1) |
| "Sandboxed by default … strict resource limits" (README:279, 289) | Not enforced (§6.3) |
| Template counts: Python 15, Go 5, C 5, Rust 4, Shell 5, YAML 24 (**58 total**, README:226-234) | Badge says **147** (README:12); CHANGELOG 1.1.1 says **147**; the installed binary now reports **1819** (was 1840 at Rev 2 — the number *drifts upward with use*). **Resolved in §6.7.1 (Item B):** the binary count is machine-local cruft, not shipped content. The per-language table also omits C++, Java, JavaScript, Ruby, Perl, PHP |
| `cxg template info smtp-open-relay.py` (README:201) | `info` takes a template **ID**, not a filename (`src/cli.rs:1359-1362`) |
| No mention of `pentest`, `ai`, `mcp`, `sandbox`, `update`, `server` | Six top-level commands absent from README; `pentest` is the largest subsystem in the repo |

`cxg scan --scope targets.txt` (README:185) **is** correct — bare paths work because
`expand_scope_entry` accepts any existing path, not just `@`-prefixed ones
(`src/main.rs:1378`). **[verified @ 78226a7]**

#### 6.7.1 🟠 Item B — the template-count anomaly, resolved

The four-way disagreement (README table **58**, badge/CHANGELOG **147**, binary **1819**) is
not four measurements of one thing — they measure **three different populations**, and the
binary's number is mostly local cruft. Method: `cxg template pwd` + `cxg template list`, then
group every reported `File:` path by its source root. **[verified @ 78226a7]**

`cxg template pwd` discovery chain:

```
[✓] Local (project)  ./templates                        (this repo's working tree)
[✓] User             ~/.cert-x-gen/templates            (populated by `template update` etc.)
[✗] System           /usr/local/share/cert-x-gen/templates   (absent)
```

**Where the 1819 actually come from** (`cxg template list`, grouped by root):

| Source directory | Count | What it is | Shipped? |
|------------------|-------|------------|----------|
| `~/.cert-x-gen/templates/bravos/validation/` | **1622** (all `.py`) | AI-generated PoC validation artifacts named `poc-<class>-wb-…-<timestamp>.py`, timestamps Mar–Jul 2026. A machine-local accumulation from prior `bravos`/validation runs. **Not git-tracked in this repo, not in the official template repo.** | ❌ No |
| `~/.cert-x-gen/templates/official/` | **~151** (58 py, 44 yaml, 16 go, 9 sh, 6 js, 5 rs, 5 c, 4 java, 1 each rb/pl/php/cpp) | A **git clone** of `github.com/Bugb-Technologies/cert-x-gen-templates.git` (has its own `.git/`, `LICENSE`, `VERSION` = `1.1.0`). This is the real, versioned template library. | ✅ Yes (separate repo) |
| `~/.cert-x-gen/templates/session-*/` | **46** (all `.js`) | Pentest AI-generated JS probes cached from prior `cxg pentest run` sessions (44 dirs, `session-2026080*`). An AI-generated cache being walked by scan discovery. | ❌ No |
| `./templates` (this repo's working tree) | **0 loadable** | Only the 12 language skeletons (loader-skipped, `_disabled`/`skeleton/` dirs) + `README.md`. No runtime templates ship in the main repo. | n/a |

So the **1682 Python** figure from Rev 2 = **1622 (`bravos/validation/` PoC cache) + ~60
(`official/` clone)**. It is *not* Electron fixtures (those live in `pentest/tests/fixtures/`,
which scan discovery does not walk) — it **is** an AI-generated cache: the `bravos/validation/`
dump plus the pentest `session-*/` JS. The count drifts (1840 → 1819) purely because these
local caches change between runs.

**What the canonical shipped number should be:** there is **no single number that matches any
of the four current claims**, because the main repo ships **zero** runtime templates — the
library is the *separate* `cert-x-gen-templates` repo, cloned on demand into `~/.cert-x-gen/
templates/official/`. That clone's own `VERSION` is `1.1.0` and its `TEMPLATE_REGISTRY.json`
is itself internally inconsistent (`"total_templates": 32` while its `templates` array lists
**21** entries), and neither matches the ~151 files actually on disk in the clone. The rebuild
should (a) stop printing a raw recursive count that includes local PoC/session caches — filter
`template list` to the official root, or exclude `bravos/`/`session-*/`; and (b) source the one
true number from the template repo's registry (and fix that registry so its `total_templates`,
array length, and file count agree). Until then, **58, 147, 1819, 32, and 21 are all "true" of
different things**, which is exactly why the docs disagree.

### 6.8 🟡 Rust doc coverage — actually good

`src/lib.rs:9-14` sets `#![warn(missing_docs, …)]`, and **`cargo check --lib` produces
zero warnings**. **[verified]** Doc debt is confined to:

**Modules with no `//!` header** (3 of 92 files):

| File | Note |
|------|------|
| `src/main.rs` | Binary crate — not covered by the lib's lints at all |
| `src/template/version.rs` | |
| `src/template/auto_update.rs` | |

**Modules that suppress the lint:**

| File | Directive |
|------|-----------|
| `src/engine/common.rs` | `#![allow(missing_docs)]` (`:3`) — despite this, all 13 public items *are* documented |
| `src/ai/validator/mod.rs` | `#![allow(missing_docs)]` (`:10`) |

**Undocumented public items** (the complete list — 6 total, all inside the two
lint-suppressed modules):

| File:line | Item |
|-----------|------|
| `src/ai/validator/mod.rs:63` | `pub fn error(code, message) -> Self` |
| `src/ai/validator/mod.rs:73` | `pub fn warning(code, message) -> Self` |
| `src/ai/validator/mod.rs:83` | `pub fn info(code, message) -> Self` |
| `src/ai/validator/mod.rs:93` | `pub fn with_location(line, column) -> Self` |
| `src/ai/validator/shell.rs:6` | `pub fn validate(code) -> Result<Vec<TemplateDiagnostic>>` |
| `src/ai/validator/yaml.rs:29` | `pub fn validate(code) -> Result<Vec<TemplateDiagnostic>>` |

Removing the two `allow(missing_docs)` directives and writing 6 doc comments would make
the crate fully clean under its own declared lint policy.

**Revision 2: re-verified unchanged.** `src/ai/validator/` and `src/engine/common.rs` were
not touched by the delta, and `cargo check --lib` still emits **0 warnings** at `46582a5`.
**[verified]** All 6 items and both `allow` directives are exactly as listed.

### 6.9 🟡 Docs directory inventory

| File | Linked from README? |
|------|---------------------|
| `docs/USAGE_GUIDE.md` | Yes |
| `docs/ARCHITECTURE.md` | Yes |
| `docs/ENGINES.md` | Yes |
| `docs/SANDBOX_GUIDE.md` | Yes — **describes a security model that isn't enforced (§6.3); needs review before reuse** |
| `docs/ENGINE_ARCHITECTURE.md` | No — orphaned |
| `docs/TODO.md` | No — orphaned |
| `src/engine/README.md` | No — in-tree engine notes |
| `templates/README.md` | No |
| `pentest/README.md` | No — **+198 lines in this delta** |
| `pentest/docs/{ARCHITECTURE,OPERATOR_GUIDE,TEMPLATES,TROUBLESHOOTING}.md` | No — **the only good docs for the largest subsystem, unreachable from the README. +1,179 lines in this delta** |
| `.claude/superpowers/specs/*.md` (6 files) | No — new; +1,565 lines of design rationale |
| `.claude/superpowers/plans/*.md` (4 files) | No — new; +4,134 lines of implementation plans |

**Revision 2 assessment.** The gap is now *inverted* from what a reader would expect: the
newest and most complex subsystem (`pentest`, including desktop targeting and OAST) has by
far the best documentation in the repo, and **none of it is reachable from the README**.
Meanwhile the README documents only `cxg scan`, the oldest and least-changed surface.

### 6.10 🟠 NEW — the delta's user-facing surface has no top-level documentation

Independent of the `bridge`/`threat_id` gap (§1.2), the *documented* new features are
documented **only** inside `pentest/docs/`. Nothing at the repo's top level tells a user
that cxg can now pentest desktop applications.

| Surface | `pentest/docs/` | README | CHANGELOG | `--help` |
|---------|----------------|--------|-----------|----------|
| Electron / `--target-type` | ✅ all 4 files | ❌ | ❌ | ✅ |
| OAST two-mode split | ✅ all 4 files | ❌ | ❌ | ✅ (extensive) |
| Crash recovery flags | ✅ | ❌ | ❌ | ✅ |
| `@requires_capability` | ✅ 2 files | ❌ | ❌ | n/a |
| `review_only_threats` | partial | ❌ | ❌ | n/a |
| `bridge` provider | ❌ | ❌ | ❌ | ❌ |
| `threat_id` | ❌ | ❌ | ❌ | n/a |

### 6.11 🟡 NEW — minor drift found in revision 2

| Item | Detail |
|------|--------|
| Exit code `3` under-documented | `src/cli.rs:434-438` describes `3` as "hard-killed (5xx streak, scope violation, etc.)". Crash recovery added a third cause: dead target with `--no-restart` (`:756`). The exit-code list wasn't updated |
| Version string vs. reality | `Cargo.toml` and the binary both report `1.2.0`, but `main` is now **117 commits** past the `v1.2.0` tag with a new target type. Any doc that cites `cxg --version` as a capability indicator will mislead |
| `pentest/payloads/` still referenced | **Resolved in Rev 3 (Item C): it exists and is LIVE.** See §6.11.1 |

#### 6.11.1 🟢 Item C — `pentest/payloads/` still exists and is still live

The `--ai` help (`src/cli.rs:505`, `:550`) says "without `--ai`, only built-in probes from
`pentest/payloads/` run." **Confirmed true at `78226a7`:**

- The directory exists and is git-tracked — **8 files**: `__init__.py`, `csrf.py`, `idor.py`,
  `metrics_disclosure.py`, `privilege_escalation.py`, `rate_limit.py`, `sensitive_data.py`,
  `session_replay.py`.
- It survived the substrate refactor **live**, not orphaned: `pentest/cxg_pentest.py:23`
  does `from payloads import ALL_PROBES`, and `payloads/__init__.py` assembles `ALL_PROBES`
  = **7 probe instances** (`IdorProbe`, `CsrfProbe`, `PrivEscProbe`, `SessionReplayProbe`,
  `SensitiveDataProbe`, `MetricsDisclosureProbe`, `RateLimitProbe`). This is the non-AI
  dispatch path.
- The `--ai` help claim is therefore **OK** (§9), one of the few cross-checked runtime claims
  that matches.

> Side finding while confirming this: the **Python** `--ai-provider` argparse
> (`cxg_pentest.py:1067`) has `choices=["auto","claude","codex","gemini","anthropic","openai"]`
> with **default `auto`** and a help string claiming the auto order is `claude > codex >
> gemini`. This disagrees with the Rust flag (default `claude`) *and* with
> `ai_generator.py`'s actual `auto` order, which is **`bridge` first** (§1.2/§5.3). So `bridge`
> is missing from *both* provider help surfaces, and the two layers disagree on the default.
> Recorded in §9.

---

## 7. Suggested rebuild priorities

Reordered in revision 2. The biggest change: **the README no longer describes the product.**
It documents `cxg scan` only, while the repo's centre of gravity has moved decisively to
`cxg pentest` — which now has two target types and 35 flags on `run` alone.

| # | Action | Why |
|---|--------|-----|
| 1 | Fix `cert-x-gen.example.yaml` and the YAML skeleton | Both are broken artifacts users copy first. Note the skeleton needs **two** fixes — the `dsl` matcher masks an `author` type error behind it (§6.1, §6.2) |
| 2 | Add regression tests: example config through `Config::from_file`, all 12 skeletons through the **engine** loader | Both defects are trivially test-detectable and have survived at least 109 commits (§6.1, §6.2) |
| 3 | Decide the sandbox story — implement, or stop claiming it | Security-relevant false claim (§6.3) *(separate workstream)* |
| 4 | **Restructure the README around two products, not one** | Six of eleven commands are absent; desktop pentesting is invisible above `pentest/docs/` (§6.9, §6.10) |
| 5 | Auto-generate the CLI reference from clap | `src/cli.rs` grew 28% in one delta. Prevents §2 drift recurring; the new tests at `src/cli.rs:2442` are a precedent |
| 6 | Auto-generate the config reference from `Config` + `AIConfig` | Prevents §5/§6.1 drift recurring |
| 7 | Write the **three** template schemas as separate pages | Scan-annotation, scan-YAML, and pentest-JS are unrelated formats (§3, §3.6) |
| 8 | Add a `report.json` schema page | Now has caveats, `review_only_threats`, restart accounting, `threat_id` — and zero documentation (§4.6) |
| 9 | Document `bridge`, `BUGB_BRIDGE_*`, and `threat_id` | The only part of the delta with no coverage anywhere (§1.2) |
| 10 | Backfill CHANGELOG 1.2.0 + Unreleased | Two releases and 117 commits missing (§1.3) |
| 11 | Resolve the **9** inert `scan` flags — implement, hide, or mark experimental | Documented with worked examples; now includes `--stream` (§2.3, §6.3) |
| 12 | Reconcile template counts to one generated number, sourced from the template repo registry; stop counting `bravos/`+`session-*/` caches | Five conflicting values, all "true" of different populations (§6.7.1) |
| 13 | Decide whether `.claude/superpowers/` specs are public | +5,370 lines of the best design rationale in the repo, currently unreferenced (§1.4, §6.9) |
| **0** | **Wire Track B into clap (or document the Python entry point)** | **Highest priority: the newest, best-tested feature (`auth import`/`verify`, `run --ci`, `--auth-dir`) is completely unreachable via `cxg` (§1.0, §2.11).** |
| 14 | Prune or wire the **41 dead config keys**; regenerate `cert-x-gen.example.yaml` so it only documents keys with effect | Two-thirds of `Config` is inert but documented as configurable (§6.3.1) |

---

## 8. Revision history

| Rev | Date | Base commit | Notes |
|-----|------|-------------|-------|
| 1 | 2026-08-10 | `c4866fa` | Initial analysis. Base was 103 commits behind `origin/main`; §1 undercounted the delta as 6 commits / 3 PRs |
| 2 | 2026-08-10 | `46582a5` | Full re-run against current `main`. §1 rewritten (109 commits / 6 PRs / 5 themes); §2, §4, §6 revised; §3, §5, §6.8 re-verified unchanged; all empirical claims re-confirmed against a freshly built binary |
| 3 | 2026-08-12 | `78226a7` | Re-run against current `origin/main` (HEAD == origin/main, 0 behind). Delta since Rev 2 base is **8 commits / 12 files / +1,620, zero Rust** — all Python `pentest/`. Headline: **Track B CI-auth (`auth import`/`verify`, `run --ci`, `--auth-dir`) is unreachable via the `cxg` binary** — implemented in Python, never wired into clap. §1 rewritten; §2/§3/§4.1–4.4/§5/§6.1–6.8 **re-verified unchanged** with every `[verified]` claim re-run on a freshly built binary (`md5 40be823a…`, not `~/.cargo/bin`). Corrections: `--stream` is inert (Rev 2 said ✅); `-o` replaces the extension, does not append. Added: §6.3 full dead-key inventory (**41 dead**); §6.7.1 template-count resolution; §6.11.1 payloads confirmation; **§9 Documentation Truth Ledger** |

---

## 9. Documentation Truth Ledger

**Purpose.** One row per user-facing claim, across `README.md`, the full `--help` tree (every
command and subcommand), and `cert-x-gen.example.yaml` comments. This is the mechanical input
the next task consumes — **OK rows are included** so "verified correct" is distinguishable from
"not yet checked." All rows verified against the fresh `78226a7` binary; `file:line` for
`src/` is byte-identical to `46582a5`.

**Category legend:** `ABSENT` — claimed, does not exist · `INERT` — exists, parsed, no effect ·
`STUB` — exists, returns "not implemented" · `WRONG` — exists but the claim misdescribes it ·
`MISSING` — exists and works, documented nowhere · `OK` — claim matches reality.

README line numbers are the **working-tree** file (which carries the uncommitted +15-line
crates.io/From-Git edit, §1.6); subtract accordingly against `HEAD:README.md`.

### 9.1 README.md

| Surface | Location | Claim | Reality | Category |
|---------|----------|-------|---------|----------|
| README | README.md:5 | "run them safely … at scale" (safely ⇒ sandboxed) | No template isolation exists (§6.3) | INERT |
| README | README.md:12 | badge "templates-147" | No source agrees; official repo `VERSION` 1.1.0, registry says 32 (array 21), disk ~151, binary 1819 (§6.7.1) | WRONG |
| README | README.md:31 | "handles orchestration, sandboxing, and output" | Sandboxing not enforced (§6.3) | INERT |
| README | README.md:37 | `cxg scan --scope 192.168.1.100:25 --templates smtp-open-relay.py` | `scan`/`--scope`/`--templates` all real and working; `host:port` scope parses | OK |
| README | README.md:40 | `--templates postgresql-default-credentials.go` | `--templates` accepts a filename | OK |
| README | README.md:43 | `--templates redis*.py,docker*.go,system*.sh` | Comma-list + glob accepted | OK |
| README | README.md:49 | "unified execution layer … across 12 languages" | Engine dispatches all 12 (§4.2) | OK |
| README | README.md:164 | `cxg --version` | Works; prints `cxg 1.2.0` — but that string is 117 commits stale (§6.11) | OK |
| README | README.md:165 | `cxg template update  # Downloads official templates` | `template update` exists and clones the official repo | OK |
| README | README.md:176 | `cxg scan --scope example.com` | Works | OK |
| README | README.md:179 | `cxg scan --scope example.com --ports 22,80,443,…` | `--ports` comma-list works | OK |
| README | README.md:182 | `cxg scan --scope 192.168.1.0/24 --top-ports 100` | CIDR + `--top-ports` work | OK |
| README | README.md:185 | `cxg scan --scope targets.txt --templates redis*.py` | Bare file path works (`expand_scope_entry`, `main.rs:1378`) **[verified]** | OK |
| README | README.md:192 | `cxg template list` | Works (but lists local caches, §6.7.1) | OK |
| README | README.md:195 | `cxg template search redis` | Works (positional query) | OK |
| README | README.md:198 | `cxg template validate my-template.py` | Command runs — **but its verdict disagrees with the engine loader** (validate passes templates the engine rejects, §6.2) | WRONG |
| README | README.md:201 | `cxg template info smtp-open-relay.py` | `info` takes a template **ID**, not a filename → `❌ No template found matching: smtp-open-relay.py` **[verified]** | WRONG |
| README | README.md:208 | `cxg scan … --format json -o results.json` | **No `--format` flag** → `error: unexpected argument '--format' found` **[verified]** | ABSENT |
| README | README.md:211 | `cxg scan … --format html -o report.html` | Same — `--format` does not exist **[verified]** | ABSENT |
| README | README.md:214 | `cxg scan … --format sarif -o results.sarif` | Same **[verified]** | ABSENT |
| README | README.md:226-234 | Template table: Python 15/Go 5/C 5/Rust 4/Shell 5/YAML 24 = **58** | Counts belong to no shipped population; main repo ships 0 runtime templates (§6.7.1); table omits C++/Java/JS/Ruby/Perl/PHP | WRONG |
| README | README.md:235 | "Templates auto-download on first scan" | Auto-update is opt-in via `--ut`/`--auto-update-templates`/`--update-templates-on-startup`; a bare `cxg scan` does **not** silently fetch. Closest working mechanism is `cxg template update` | WRONG |
| README | README.md:240 | "Read `CERT_X_GEN_TARGET_HOST`/`_PORT` from environment" | Correct for all 12 languages; omits that Shell **also** gets them as argv (§4.3) | OK |
| README | README.md:246-270 | Python template example (`# @id/@name/@severity`, prints `{"findings":[…]}`) | Annotation parse (§3.1) + simplified findings parse (§4.3) both accept this shape | OK |
| README | README.md:279 | "**Sandboxed by default** — templates run with strict resource limits" | No isolation on any execution path (§6.3) | INERT |
| README | README.md:288 | "12 supported languages (Python, Go, Rust, C, C++, Java, JavaScript, Ruby, Perl, PHP, Shell, YAML)" | Matches the engine registry (§4.2) | OK |
| README | README.md:289 | "Sandboxed execution with configurable resource limits" | `sandbox` config block is entirely inert (§6.3/§6.3.1) | INERT |
| README | README.md:290 | "Compilation caching for compiled languages" | Real (`/tmp/cert-x-gen-cache/<lang>/`, §4.2) — though not content-addressed | OK |
| README | README.md:291 | "Parallel template execution with rate limiting" | `parallel_templates` + `rate_limit` both live (§6.3.1) | OK |
| README | README.md:294 | "Unified `--scope` for targets (single, file, CIDR, URL)" | All four forms parse | OK |
| README | README.md:295 | "Smart `--templates` selection (glob patterns, tags, severity)" | Glob via `--templates`; tags/severity via `--tags`/`--severity` | OK |
| README | README.md:296 | "Multiple output formats (JSON, HTML, CSV, Markdown, SARIF)" | All 5 registered and work — more accurate than the CLI's own `--output-format` help, which drops `markdown` and adds `xml` (§6.4) | OK |
| README | README.md:297 | "Built-in template management and validation" | `template` subtree exists; caveat §6.2 | OK |
| README | README.md:300 | "Git-based template repositories with auto-update" | Official templates are a git clone (§6.7.1) | OK |
| README | README.md:301 | "CI/CD friendly (exit codes, SARIF output)" | SARIF formatter + exit codes real | OK |
| README | README.md:302 | "Configurable via CLI, config file, or **environment variables**" | No env var configures scan behaviour; no config auto-discovery (§5.1); and 34/51 config keys are inert (§6.3.1) | WRONG |
| README | (whole file) | README documents only `cxg scan`/`template` | `pentest`, `ai`, `mcp`, `sandbox`, `update`, `server` all work and appear **nowhere** in README (§6.10) | MISSING |
| README | (whole file) | — | `--ai-provider bridge`, `BUGB_BRIDGE_URL/TOKEN`, `threat_id` work but are documented nowhere (§1.2) | MISSING |

### 9.2 `--help` (every command / subcommand)

| Surface | Location | Claim | Reality | Category |
|---------|----------|-------|---------|----------|
| `scan --protocol` | cli.rs:~1180 | selects protocol | Never read (§2.3) | INERT |
| `scan --protocols` | cli.rs (after_help) | selects protocols | Never read | INERT |
| `scan --quiet/-q` | cli.rs:1346 | "Minimal output: only critical info and errors" | Only suppresses the ASCII banner; scan output unchanged **[verified]** | WRONG |
| `scan --stream` | cli.rs:891, 1335 | "real-time streaming output … results shown as they're found" | Write-only config; `stream_finding` never called; output is batch-only **[verified]** | INERT |
| `scan --resume <SCAN-ID>` | cli.rs:1023-1027 | "Resume a previously interrupted scan" | Bogus ID silently ignored, scan runs normally, exit 0 **[verified]** | INERT |
| `scan --distributed` | cli.rs:1029 | "Enable distributed scanning mode" | Never read **[verified]** | INERT |
| `scan --coordinator <URL>` | cli.rs:1035 | coordinator URL | Never read | INERT |
| `scan --worker-id <ID>` | cli.rs:1041 | worker id in distributed mode | Never read | INERT |
| `scan --profile <NAME>` | cli.rs:1059 | named scan profile | Never read | INERT |
| `scan --follow-redirects` | cli.rs:1010 | "Default: Enabled" | clap default is `false`; the config default is `true` — help contradicts the flag | WRONG |
| `scan --output-format` | cli.rs:1331, 881, 886 | lists `xml` ("xml=enterprise", "Structured format for enterprise tools") | No XML formatter registered; `Unknown output format: xml`, silent warn, no file, exit 0 **[verified]** | ABSENT |
| `scan --output-format` | cli.rs:1331 | lists json/csv/sarif/html/xml — **omits `markdown`** | `markdown` formatter is registered and works, but is not advertised here **[verified]** | MISSING |
| `scan --threads` | cli.rs:1045 | worker thread count | Advisory only; `execution.threads` never sizes a pool (§6.3.1) | INERT |
| `server` (command) | main.rs:2774-2779 | "Run as API server" + 6 flags (`--port/--bind/--auth-token/--tls/--tls-cert/--tls-key`) | `Error: Not implemented: API server not yet implemented` **[verified]** | STUB |
| `mcp serve` | CHANGELOG 1.1.1 | invocation `cxg mcp serve` | No `Serve` variant; the real form is bare `cxg mcp` (§2.10) | ABSENT |
| `mcp install --client` | cli.rs:1914 | client set `claude-desktop,claude-code,cursor,windsurf,vscode,zed` | Differs from CHANGELOG 1.1.1's list (Cline/Roo Code); reconcile against installer | WRONG |
| `pentest run --ai-provider` | cli.rs (Options line) | `auto \| claude \| codex \| gemini \| anthropic \| openai` | `bridge` provider exists and is first in `auto` order but is **absent** from the list **[verified]** | WRONG |
| `pentest run` exit codes | cli.rs:434-438 | `0/1/2/3`, `3` = "hard-killed (5xx/scope)" | `3` also covers "dead target with `--no-restart`" (`:756`), not listed | WRONG |
| `pentest --ai` | cli.rs:505, 550 | "without `--ai`, only built-in probes from `pentest/payloads/` run" | True — `ALL_PROBES` (7 probes) imported at `cxg_pentest.py:23` and dispatched **[verified]** (§6.11.1) | OK |
| `pentest auth import` | (Python `cxg_pentest.py`/`auth.py`) | Track B: import a saved session | Not in clap → `error: unexpected argument 'import' found` **[verified]** (§1.0) | ABSENT |
| `pentest auth verify` | (Python) | Track B: liveness gate | Not in clap → `error: unexpected argument 'verify' found` **[verified]** | ABSENT |
| `pentest run --ci` | cxg_pentest.py:1222 | CI hard-fail mode | Not in clap → `error: unexpected argument '--ci' found` **[verified]** | ABSENT |
| `pentest run --auth-dir` | cxg_pentest.py:1217 | redirect profile store | Not in clap → `error: unexpected argument '--auth-dir' found` **[verified]** | ABSENT |
| `pentest` (Python help) `--ai-provider` | cxg_pentest.py:1067 | default `auto`, "auto: claude > codex > gemini" | Disagrees with Rust default (`claude`) and with `ai_generator.py`'s real order (bridge first); `bridge` absent here too | WRONG |
| `pentest auth --header` | cli.rs (auth) | SECURITY note: plaintext stored in `<profile>.meta.json` | Accurate | OK |
| `scan --scope` (+ aliases) | cli.rs:938+ | targets/CIDR/file/URL | Works | OK |
| `pentest run --oast-interactsh` | cli.rs:640-686 | cxg-owned canary → `confirmed=true` | Matches implementation (`oast.py`, §1.1) | OK |
| `template skeleton yaml` | cli.rs (template) | emits a usable YAML template | The emitted skeleton **fails the engine loader** (`dsl` matcher + string `author`, §6.2) **[verified]** | WRONG |

### 9.3 `cert-x-gen.example.yaml` comments

The file **does not load at all** (`missing field 'passive_mode' at line 73`, §6.1) — so every
comment below describes a key in a file the tool rejects wholesale. Categories reflect the key's
behaviour *were the file loadable*.

| Surface | Location | Claim (comment) | Reality | Category |
|---------|----------|-----------------|---------|----------|
| example.yaml | :1-2 | "Copy this file to `cert-x-gen.yaml` and customize" | File fails to load; and `cert-x-gen.yaml` is never auto-discovered anyway (§5.1) **[verified]** | WRONG |
| example.yaml | :5 `verbosity` | "Verbosity level (0-3)" | `global.verbosity` never read (§6.3.1) | INERT |
| example.yaml | :8 `color` | "Enable colored output" | Never read | INERT |
| example.yaml | :11 `log_level` | "Log level: trace…error" | Never read | INERT |
| example.yaml | :14 `log_file` | "Log file path" | Never read; no file logging wired | INERT |
| example.yaml | :17 `debug` | "Enable debug mode" | Never read | INERT |
| example.yaml | :22 `directories` | "Template directories to search" | **Live** (§6.3.1) | OK |
| example.yaml | :26 `auto_update` | "Auto-update templates from remote" | `templates.auto_update` never read | INERT |
| example.yaml | :29 `cache_dir` | "Template cache directory" | Never read; engines compute own cache | INERT |
| example.yaml | :32 `enabled_languages` | "Enabled template languages" | Never read; all engines always registered | INERT |
| example.yaml | :39 `timeout_secs` | "Template execution timeout" | **Live** (`executor.rs`) | OK |
| example.yaml | :43 `network.timeout_secs` | "Request timeout" | **Live** | OK |
| example.yaml | :46 `user_agent` | "User agent string" | **Live** | OK |
| example.yaml | :49 `follow_redirects` | "Follow HTTP redirects" | **Live** | OK |
| example.yaml | :52 `max_redirects` | "Maximum number of redirects" | **Live** | OK |
| example.yaml | :55 `connection_pool_size` | "Connection pool size" | **Live** | OK |
| example.yaml | :58 `http2` | "Enable HTTP/2" | Never applied — `network.rs:47` explicitly declines it | INERT |
| example.yaml | :61 `proxy` | "Proxy URL" | **Live** | OK |
| example.yaml | :65 `dns_servers` | "Custom DNS servers" | Never read | INERT |
| example.yaml | :68 `rate_limit` | "Rate limit (rps)" | **Live** | OK |
| example.yaml | :72 `threads` | "worker threads (0 = auto)" | Never sizes a pool (§6.3.1) | INERT |
| example.yaml | :75 `parallel_targets` | "Parallel target scanning" | **Live** | OK |
| example.yaml | :78 `parallel_templates` | "Parallel template execution" | **Live** | OK |
| example.yaml | :81 `max_retries` | "Maximum retries" | **Live** | OK |
| example.yaml | :84 `retry_delay_secs` | "Retry delay" | **Live** | OK |
| example.yaml | :87 `aggressive_mode` | "more invasive checks" | **Live** (concurrency multiplier) | OK |
| example.yaml | :90 `stealth_mode` | "slower, less detectable" | **Live** (request jitter) | OK |
| example.yaml | :93 `cache_enabled` | "Enable result caching" | Never read | INERT |
| example.yaml | — (:71 block) | file omits `passive_mode`/`safe_mode` entirely | Both are **required** (no `#[serde(default)]`) — this omission is the load failure; and even set, both are inert (§6.3.1) | WRONG |
| example.yaml | :97 | "Output formats: json, csv, markdown, sarif, html, **xml**" | `xml` unregistered (§6.4); and `output.formats` itself is never read — `--output-format` drives output | INERT |
| example.yaml | :101 `output_dir` | "Output directory" | `output.output_dir` never read | INERT |
| example.yaml | :104 `output_file` | "Output file basename" | Never read; `-o`/`args.output` drives it | INERT |
| example.yaml | :107 `stream` | "Stream output in real-time" | Never read (§2.3) | INERT |
| example.yaml | :110 `min_severity` | "Minimum severity to report" | Never read; no output gate | INERT |
| example.yaml | :113-127 `sandbox.*` | "Enable sandbox … memory/cpu/network/filesystem limits" | Entire block inert (§6.3) | INERT |
| example.yaml | :129-137 `metrics.*` | "metrics collection … Prometheus port/format" | `src/metrics.rs` never referenced; no server (§6.3.1) | INERT |
| example.yaml | :139-148 `plugins.*` | "Enable plugin system … directories … loaded plugins" | `PluginManager::new()` takes no config; all three keys inert | INERT |

### 9.4 Ledger totals by category

Counts below are mechanical (`grep -oE "\| (OK|INERT|…) \|$"` over the three tables).

| Category | Count | README | `--help` | example.yaml |
|----------|-------|--------|----------|--------------|
| **OK** | 42 | 23 | 4 | 15 |
| **INERT** | 33 | 4 | 9 | 20 |
| **WRONG** | 15 | 6 | 7 | 2 |
| **ABSENT** | 9 | 3 | 6 | 0 |
| **MISSING** | 3 | 2 | 1 | 0 |
| **STUB** | 1 | 0 | 1 | 0 |
| **Total rows** | **103** | **38** | **28** | **37** |

**Reading of the totals:** 42 OK against 61 not-OK (33 INERT + 15 WRONG + 9 ABSENT + 3
MISSING + 1 STUB). The largest failure class is **INERT (33)** — features that parse and are
documented but do nothing — and it is dominated by `cert-x-gen.example.yaml`, where 20 of 37
commented keys have no effect. The next task can treat the 42 OK rows as a verified baseline
and focus remediation on the 61 not-OK rows, starting with the 9 ABSENT (which includes the
four unreachable Track B arguments — the highest-value rows here).

> Counting note: the four Track B rows (`auth import`, `auth verify`, `run --ci`,
> `--auth-dir`) are tallied under ABSENT because clap rejects each argument; conceptually they
> are "implemented in Python, absent from the binary." If the rebuild wires them into clap they
> flip to OK; if it documents the `python3 cxg_pentest.py` entry point instead, they become a
> MISSING-interface note. Either way they are the highest-value rows in this ledger.
