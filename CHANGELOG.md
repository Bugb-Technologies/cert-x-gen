# Changelog

All notable changes to CERT-X-GEN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**cxg reads the annotation forms guardlink TEACHES, and some of what it accepts**

Three separate claims, because they are separately true. guardlink's `CLAUDE.md` Quick Syntax
block is a TEACHING SUBSET; `guardlink gal` is the authoritative grammar. This change does not
make cxg read guardlink's grammar, and nothing here should be read as saying it does.

- **(a) Teaching examples: 1 of 14 → 12 of 14.** guardlink's `CLAUDE.md` teaches fourteen
  Quick Syntax forms; the installed cxg parser read exactly one of them, the one-line
  `@comment`. A customer who followed guardlink's documentation wrote annotations cxg could
  not see, and nothing said so. `parse_inline` now reads twelve. The two it does not are
  `@actor`, which that block marks `(definitions file)` and which names no code, and
  `@flows`, whose widening was WITHDRAWN — see "What this change withdrew" below. Customer
  source is unchanged; the work is entirely inside cxg.
- **(b) Additional `gal` forms this change adds**, beyond the teaching subset: `@boundary`'s
  PRIMARY spellings `A and B (#id)` and `A | B` (cxg previously read only `between A and B`,
  which `gal` calls the alternate).
- **(c) `gal` forms this change DELIBERATELY LEAVES UNREAD.** `@mitigates`' control clause is
  optional in `gal` and `with` is accepted as a synonym for `using`, so
  `@mitigates db.users against Token Theft -- "Rotation implemented in v2"` — `gal`'s own
  second example — validates and parses on the installed binary and cxg still reads nothing
  for it. This is a decision, not a to-do: nothing consumes `@mitigates` (see the consumer
  table below), so widening it would add annotations no reader reads. Filed as **GAP-44**,
  blocked on **GAP-43**, which is where "should an inline declaration with no SARIF result
  behind it become a hypothesis?" gets settled.
- **The grammar was widened to what the INSTALLED guardlink accepts**, not to what an
  instruction file describes: `guardlink validate` over a fixture carrying all thirteen
  source-legal examples reports 0 errors. Assets may be a dotted path (`App.API`) or a bare
  capitalised identifier; severities accept guardlink's word spellings (all 88 severities in
  guardlink's own model are word form and NOT ONE is a `[P0]` code, so the only spelling cxg
  admitted was the one the corpus never writes). `@flows` IS UNCHANGED FROM origin/main — see
  "What this change withdrew".
- **Eight verbs cxg had no reader for at all** — `@confirmed`, `@boundary`, `@handles`,
  `@validates`, `@assumes`, `@transfers`, `@feature`, `@owns` — are read. They are not eight
  new parsers: `@assumes`, `@transfers`, `@boundary`, `@handles` and `@validates` reach the
  generation prompt as intent context, labelled with the verb their author wrote, and
  `@confirmed`, `@feature` and `@owns` are **recognised and consumed by nothing**, which is a
  stated contract rather than an omission. `@exposes`, `@mitigates` and `@audit` are in that
  same unconsumed group — six of the thirteen verbs in all, splitting three deliberate
  (`@confirmed`, `@feature`, `@owns`) and three actionable (`@exposes`, `@mitigates`,
  `@audit`, unconsumed because of GAP-43 rather than by decision). Hypotheses come from the SARIF,
  not from inline annotations, so an exposure declared inline with no matching SARIF result
  is invisible to cxg today; that is GAP-43 and is not decided here. Promoting `@confirmed` — a human asserting an
  exploit is real — into the context that decides whether a finding is a real vulnerability
  is an evidence-standard product call, not a parser change.
- **`.gal` sidecars are read.** `guardlink init` writes EXTERNAL annotation mode by default,
  putting annotations in `.guardlink/annotations/<path>.gal` and leaving source files bare.
  `.gal` is not a source extension, so on a repository set up the way guardlink's own
  instructions describe, cxg read zero annotations and lost every intent note in guardlink's
  DEFAULT mode. Annotations are attributed to the source file and line their `@source` header
  names, never to the sidecar — matching what the installed binary emits.


**What this change withdrew, and why**

`@flows` is byte-for-byte origin/main's behaviour on this head: the same pattern, the same
`attach_flows_to_hypotheses`, the same `derive_chain_edges`. Verified on twelve shapes —
plain, trailing period, trailing hyphen, a bare source, a fan-out, multi-hop, via-less, bare
endpoints, a leading-digit endpoint, a multi-word mechanism and an arrow inside one — every
one identical to main.

The `@flows` widening was attempted and withdrawn after six rounds. It is not that the
widening was wrong: via-less flows, bare and dotted endpoints and multi-word mechanisms all
worked. What did not converge was TRIMMING cxg back to what guardlink accepts. cert-x-gen
accepts a SUPERSET of guardlink's endpoint grammar and always has — `3rdparty`, `123`,
`a..b` and `.lead` are hard `Malformed` on the installed binary and origin/main reads all
four — and each round trimmed one dimension of that superset while holding another constant,
so every fix was right about the case in front of it and wrong about the dimension nobody
varied. Twice the result read a form guardlink rejects; twice it refused one guardlink
accepts.

The minimal withdrawal was measured rather than assumed: reverting only the endpoint
trimming leaves `# @flows #api -> #cache.` reading a destination `#cache.` that does not
exist, and that record reaches `derive_chain_edges` as a real chain edge. A consumer-side
check cannot cover it, because the junk is absorbed INTO the field rather than left over.
So the withdrawal is total.

Everything downstream of the widening went with it, so nothing in the tree is left describing
a flow this head cannot read. The consumer-side refusal of half-read declarations is INERT on
main's `@flows` — it requires a `via` clause and a `#`-prefixed destination, so no input can
produce the half-read record that refusal existed to act on (measured: 0 of 8 shapes) — and
the `partial` flag that fed it went with it, producer included. VIA-LESS flows went the same
way: `derive_chain_edges` skips a flow with no mechanism, so every derived edge carries one,
and the endpoint-derived artifact name (`edge_<digest>`), the absent-channel branches in
`apply_chain_edges`, `_chain_block` and `generate_all`'s console line, and the tests pinning
them are all gone. Keeping any of it would have shipped machinery no input can reach — the
same defect this branch spent two days filing against other code.

Filed as **GAP-54** with the six rounds of evidence, the `edge_6705daf7` trace showing an
invented id reaching a real chain edge, and the cross-product derivation
`{#-prefixed, bare, dotted} × trailing characters × verbs` that the next attempt should
START from rather than arrive at. The measurement that motivated the work stands: 37 of the
123 flows in guardlink's own repository can never become a chain edge.

### Fixed

- **A verb written inside a note's own description is no longer read as an annotation.** A
  human explaining which mitigation they deliberately did NOT write had that mitigation
  recorded as real. The example is from guardlink's own `tests/fixtures/expense-api`:
  `@comment -- "Written first as @mitigates #api against #malformed-input using
  #auth-required, which nothing rejected even though the control and the threat have nothing
  to do with each other"`. This is one defect in three places — on a continuation line, on a
  line that opens a description running off its end, and on a line where the note opens and
  closes — and this closes the last two. Widening the verb set from five to thirteen is what
  made it necessary rather than tidy. It was the only annotation the bound removed across all
  three annotated repositories, and a genuine annotation written after a closed note on the
  same line is still read. `@feature` carries its own arm in the span pattern, being the one
  verb with a quoted argument before the `--`; without it a feature note registered no span
  and the bound did not reach it, so `@feature "SSO Login" -- "we rejected @exposes App.API
  to #idor here"` emitted the exposure the sentence says was rejected.
- **The CONTINUATION-line case is NOT closed and is carried as an open bound** (board card
  GAP-32). The join refuses to run past such a line, but `parse_inline` visits it again on its
  own turn with no span, so a verb in a wrapped note's prose is still emitted. The smallest
  closure was prototyped and measured: it removes 9 fabrications in cert-x-gen but loses 191
  descriptions in siete and overturns a standing PR-74 decision, so it is filed rather than
  attempted. `pentest/docs/ARCHITECTURE.md` carries the measurement.
- **A hyphen is refused in a bare or dotted reference.** `@exposes User-Store to #sqli`,
  `@exposes App-Name.API to #sqli`, `@assumes App.API-v2`, `@transfers #ddos from App-X to
  Ext.CF`, `@handles user-data on App.API` and `@boundary internal-network and #db` are every
  one a hard `Malformed` error on the installed guardlink 2.0.0, and cxg read all six as live
  annotations — `@assumes`, `@boundary` and `@handles` carrying their descriptions into the
  generation prompt as the author's stated intent, so a note guardlink calls malformed arrived
  labelled as one a human wrote. A hyphen after `#` stays legal (`#prepared-stmts` is
  guardlink's own spelling), as does `@owns`' owner token (`security-team`, likewise). The flow
  endpoint keeps its hyphen as a stated backward-compatibility tolerance, because cxg read
  `user-agent` and `3rdparty` before this widening. Measured at 0 of 2,133 reference values
  across guardlink, siete and cert-x-gen — the narrowing costs no annotation anywhere.
- **A `.gal` `@source` header is recognised only at the start of a line.** Matched anywhere, a
  note whose own description quoted the header text was consumed as a header — losing its own
  annotation and silently re-attributing every note below it to the quoted path, so a "this is
  by design" note could reach a hypothesis in a different file. Leading whitespace still opens
  a block, because the installed guardlink parses an indented header.
- **A chain edge names the mechanism its declaration was written over.** The generation
  prompt named the artifact but described every edge identically, so the `via` a human wrote
  was not passed on. The declared channel is now named to the model
  (`PROVIDES 'coupon_code' (declared over coupon.code)`) and on the console line an operator
  reads to check what chaining derived. Every derived edge carries one — `via` is mandatory
  in `_RE_FLOWS` — so there is no absent-channel case to describe.

**What went wrong repeatedly here, and why it was predictable**

Review of this change turned up **six** defects where a written claim exceeded what the code
does — the consumer table, the closed-severity set, the "one defect closed in three places"
claim, the endpoint grammar, the chain-block note on where artifact names come from, and the
headline itself — plus **two false guards**: tests whose assertions passed identically whether
or not the thing they guarded had regressed. These are not unrelated tidy-ups, and the
structural reason is worth stating because it predicts the defect rather than regretting it:
**a change to what a parser ACCEPTS falsifies documentation at a higher rate than most
changes, because the documentation's whole subject is what it accepts** — every widening
invalidates some sentence describing the old bound, including sentences in files the diff does
not touch. Both false guards were found by asking of each test the same question: would it
still fail if the thing it guards were deleted? A guard that cannot fail is worse than no
guard, because it reports coverage it does not have.

One more, and it is the cheaper lesson of the two: **a finding that keeps returning in new
shapes is a cause that has not been named.** The multi-hop `@flows` declaration produced FIVE
findings across five rounds — a hypothesis both providing and requiring one artifact; a
declared hop ordering never applied; two providers silently overwriting one artifact key; an
artifact name that depended on which hypothesis the run iterated first; and finally a
legitimate SINGLE-hop declaration losing its chain edge because a chain was annotated nearer
the same hypothesis. Each fix produced the next, and the fifth was a regression against main on
a path this change was supposed to leave alone. The cause under all five is that a flow
record's IDENTITY and its skip-or-name decision were keyed on different tuples: the dedup keys
on `(src, dst, channel)` while the added `hops` field decided the outcome, so the record that
survived the dedup decided the answer. Multi-hop reading is therefore withdrawn entirely rather
than patched a fifth time, and filed as GAP-49 so whoever picks it up starts from that cause
instead of rediscovering four symptoms. When the same declaration produces a third finding,
stop fixing it and go looking for what makes it produce findings.

**The instrumentation component — building a target that can earn its verdict**
- **`cxg build --instrument`** — a new verb that produces an *instrumented* build of a
  compiled target, so the CLI Security Baseline's low-level classes reach real
  `confirmed`/`refuted` verdicts instead of an honest skip. It detects the build system,
  asks **rustc** what the target can do rather than guessing, builds into a private target
  directory, **re-reads the binary it just produced**, and prints one JSON manifest.
  Cargo/Rust is the only back end; every other recognised build system skips with
  `build-system-not-implemented`.
  `cxg scan` is untouched: it still inspects and refuses, and never builds anything.
  Building runs the project's own build system as the invoking user and costs minutes and
  gigabytes, which is why it is a verb rather than a scan flag.
- **There is no path from "I could not instrument this" to "here is a binary."** Every
  precondition failure is a `skipped` with a machine-readable reason —
  `unknown-build-system`, `build-system-not-implemented(...)`,
  `nightly-toolchain-unavailable(...)`, `sanitizer-unsupported-on-target`,
  `sanitizer-not-verifiable(...)`, `binary-target-ambiguous(pass --bin NAME)`,
  `rust-src-missing(...)`, `instrumented-build-failed(exit=N)` with the last 20 log lines,
  and **`build-produced-no-instrumentation(wanted=… detected=…)`** for a build that reported
  success and produced an artefact carrying none of what it was asked for.
- **`rust-overflow-checks` instrumentation label and the `overflow` oracle.** Rust has no
  UBSan — `-Zsanitizer=undefined` does not exist on any target — so the integer class
  (CWE-190) is carried by `-C overflow-checks=on`, which cxg passes on every instrumented
  build. The detector reads it from the symbol table
  (`core::panicking::panic_const::panic_const_*_overflow`), and `overflow` is a
  *build-dependent* oracle, so a template's overflow branch cannot claim a verdict on a
  build where the check was compiled out.
- **`cxg scan --instrumented-manifest <path>`** — provenance beats inspection. Where cxg
  built the binary itself it already read the artefact back, and that record is used in
  preference to re-sniffing the file, for the binary the manifest names and no other. A
  manifest recording a *skipped* build is an error rather than a silent no-op. Omit the flag
  and a scan behaves exactly as it did before.
- Toolchain cost, stated plainly: **nightly Rust is required** for `-Zsanitizer`
  (`rustup toolchain install nightly`). There is no stable equivalent. Where it is missing,
  `cxg build` skips with an actionable reason and the proof tests explain themselves and
  pass rather than failing a build over it.

**The probe contract — driving a local binary and recording an honest verdict**
- `--scope cli:///path/to/binary` — a scan target can be a locally-built executable rather
  than a network host. `CERT_X_GEN_TARGET_HOST` carries the binary path and the new
  `CERT_X_GEN_TARGET_KIND` says which kind it is. `CERT_X_GEN_TARGET_PORT` is meaningless
  when `KIND=cli` and should be ignored there. A `cli:` scope entry is taken verbatim, so a
  path containing a comma is not split.
- **Execution ledger.** Every (template, target) pair now produces a row in
  `ScanResults.executions` carrying `confirmed` / `refuted` / `errored` / `skipped` /
  `timed-out`, the finding count, the exit code and a reason — so a refutation is
  first-class and observable in the result JSON instead of being indistinguishable from a
  template that did nothing. A new **Execution Status** block reports it in the terminal.
  cxg infers the status from what it observed; a template may override it with
  `{"metadata": {"status": ..., "detail": ...}}`, and `declared_by_template` records which
  happened.
- `# @allow_nonzero_exit: true` — a probe template that provokes a crash in its target
  naturally exits non-zero. cxg now keeps its stdout instead of discarding the finding, the
  sanitizer report and the exit code along with it.
- `--arg` (repeatable, hyphen-leading values allowed), `--stdin-file`, `--input` and
  `--target-env` — cxg supplies the probe's argv, stdin, seed corpus and target environment,
  delivered as `CERT_X_GEN_ARGV`, `CERT_X_GEN_STDIN_FILE`, `CERT_X_GEN_INPUT_DIR` and
  `CERT_X_GEN_TARGET_ENV`. Each is absent unless its flag was passed.
- `--require-instrumentation` — inspect a `cli://` build for sanitizer, coverage and
  debug-info markers before running anything against it, and record `skipped` with a reason
  (`no-instrumentation-detected`, `target-not-found`, `oracle-unavailable(...)`) rather than
  running a probe and reporting a refutation the build could not have earned. The detected
  set is exported to templates as `CERT_X_GEN_TARGET_INSTRUMENTATION`.
- `# @oracles:` and `# @target_kinds:` template annotations. A declared target-kind mismatch
  is recorded as `skipped` rather than run. An absent `@target_kinds` accepts every kind, so
  no existing template changes behaviour.
- `# @oracles: exception` — the one oracle cxg implements itself. A Python traceback or a Node
  unhandled rejection exits 1 with no crash signal, so `signal` never fires and `exit` fires on
  every correct non-zero exit too. A template that declares `exception` hands the target's
  output back in `{"metadata": {"target_output": ..., "target_exit_code": ...}}` and cxg
  matches the per-language shape of an escaped exception (CPython, Node, JVM, Go, Rust),
  recording `confirmed` with `oracle=exception(<kind>)` and a finding carrying the evidence.
  Both new metadata fields are optional, and a template that declares no `exception` oracle is
  unaffected.

### Changed
- **This repository's own inline annotations now use GuardLink's bare verbs.** Every
  annotation here was written to the grammar of Giggs, a discontinued predecessor, which
  prefixes each verb `@g.` — a form the `guardlink` binary reads as nothing at all, so the
  whole corpus was absent from its threat model (`annotations_parsed: 0`). 3,202 `@g.comment`
  verbs across 115 files became `@comment`; no description text, asset, severity or layout
  changed. `guardlink parse` now reads 1,511 of them (0 before). cxg's own `parse_inline` is
  unaffected — it accepts both forms and reads the same 3,256 annotations before and after.
  Two verbs are deliberately left in the old form because they do not map onto GuardLink's
  grammar: `@g.sink` (7), which has no `@sink` counterpart, and `@g.source` (9), whose bare
  `@source` is an unrelated `file:line` anchor directive that fails `guardlink validate`.

### Fixed
- **`--scope-file` failed open.** It is how an operator tells `cxg pentest` what a scan is
  allowed to touch, and every way of failing to read it left the run going on the built-in
  defaults: a path that did not exist returned them **silently**, and an unparseable file —
  or a machine without PyYAML — printed one warning line that scrolled past while the scan
  proceeded. The operator believed the blast radius was bounded and it was not.
  `ScopeConfig.load` now **refuses**: a missing path, an unopenable file, invalid YAML, a
  document that is not a mapping of settings, an empty file, an empty flag value, or PyYAML
  being absent all raise `ScopeFileError`, and `run_pentest` stops with **exit 4** (a
  mis-specified run, not 2, which means "vulnerabilities found") before it resolves the
  codebase or runs guardlink. The empty-value refusal covers direct invocation of the
  orchestrator; `cxg pentest run --scope-file "$SCOPE"` with `SCOPE` unset never reaches it,
  because clap rejects an empty value as a usage error (exit 2) before forwarding argv.
  The message names the path, the reason, and the next action. Passing **no** `--scope-file`
  is unchanged and is not an error — absent is not unreadable, and an operator who set no
  bound still gets the documented defaults.
- Reading a scope file requires **PyYAML**, which no install path checked for: `cxg pentest
  install` verified only playwright and anthropic. It now verifies PyYAML too and names it
  in the `pip3 install` line it prints, it is pinned in `pentest/requirements.txt`, and it
  is named in the refusal — so a machine without it is told what to install instead of
  scanning unbounded. Measured on a host where no interpreter on PATH could import `yaml`:
  before this change every `--scope-file`, valid or not, was ignored.
- `--scope-file` is refused with exit 4 on `--template-lang py`, and the refusal now runs in
  pre-flight, before `--interactive-auth` capture and `--creds-file` re-auth. The legacy
  Python probe path enforces no scope at all, so a file accepted there was read and
  discarded; and an operator who mistyped the path used to complete every interactive login
  first and be refused afterwards.
- A template that outran its execution timeout kept running unsupervised: the timeout stopped
  awaiting the child but never killed it. `execute_command` now sets `kill_on_drop`.
- `--require-instrumentation` skipped **every** template against a target carrying no
  instrumentation, including templates whose oracles need nothing from the build. An
  interpreted CLI can never detect instrumentation, so the flag made cxg refuse to test one at
  all. A template declaring only build-independent oracles (`exit`, `signal`, `timeout`,
  `exception`) now runs and reaches a real verdict; one declaring a sanitizer oracle, or
  declaring none, is still skipped with `no-instrumentation-detected`.
- The instrumentation marker scan read any file, so a shebang script or JS bundle that merely
  *mentioned* `__asan_init` — in a comment or its own documentation — was classified as an
  instrumented build and the preflight passed. The scan now runs only on compiled objects
  (ELF, Mach-O, PE, static archives); everything else reports `none`.
- `cxg pentest` read almost none of the inline `@comment` intent notes an annotated codebase
  carries, so the design decisions those notes exist to explain reached the ranking and
  probe-writing model as unexplained code. Two independent causes, both fixed: the `@g.` verb
  prefix (`@g.comment`) that agent instruction files then taught was not accepted at all, and a
  description wrapped onto a second comment line was read as no annotation rather than as one
  joined note. Measured across three annotated repositories before the fix, 8,098 notes on disk
  read as 140. The bounds that remain — the `\"` escaping rule, the continuation-line cap, and
  the trailing-comment opener that is deliberately not joined — are documented under "Inline
  annotations" in `pentest/docs/ARCHITECTURE.md`.

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
