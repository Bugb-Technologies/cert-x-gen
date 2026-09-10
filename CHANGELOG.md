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

- **(a) Teaching examples: 1 of 14 → 13 of 14.** guardlink's `CLAUDE.md` teaches fourteen
  Quick Syntax forms; the installed cxg parser read exactly one of them, the one-line
  `@comment`. A customer who followed guardlink's documentation wrote annotations cxg could
  not see, and nothing said so. `parse_inline` now reads thirteen — the fourteenth is
  `@actor`, which that block marks `(definitions file)` and which names no code. Customer
  source is unchanged; the work is entirely inside cxg.
- **(b) Additional `gal` forms this change adds**, beyond the teaching subset: `@boundary`'s
  PRIMARY spellings `A and B (#id)` and `A | B` (cxg previously read only `between A and B`,
  which `gal` calls the alternate), and multi-word `@flows` mechanisms such as `via TLS 1.3`
  — `gal`'s own example, which cxg truncated to `TLS` and whose description it then dropped
  entirely.
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
  admitted was the one the corpus never writes); `@flows` takes an optional `via` and a
  widened destination (37 of the 123 flows in guardlink's own repository could never become a
  chain edge, every one failing on a bare destination). A multi-hop chain is NOT read — see
  below.
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
- **A flow endpoint is no longer narrowed to the asset grammar.** The widening had replaced
  `@flows`' endpoints with the asset reference, which refuses a bare lowercase word — so
  `@flows browser -> #api via https` and the same with `s3`, `user-agent` or `3rdparty`
  stopped being read at all, having been read for as long as cxg has had the verb. A flow that
  does not match is not a flow with an unread src, it is nothing. Endpoints are bounded on
  both sides by structure, so the wider shape is restored there and `@audit`/`@assumes` keep
  the narrow one. The endpoint is `#?(?:[\w.]|-(?!>))*(?:\w|-(?!-*>))`: a hyphen reads inside an
  endpoint (`user-agent`, `#api-cache`) but is refused immediately before `>`, so `@flows #a --> #b`
  reads as nothing rather than as `#a-` → `#b` — which is also what the installed guardlink
  does with it. Without that exception a greedy endpoint absorbs the first hyphen of an
  unspaced `->`, and because every group after the chain is optional the match never
  backtracks: `@flows #a->#b->#c via sql -- "d"` SUCCEEDED with a fabricated destination
  `#b-` and no channel and no description at all.
- **A flow operand no longer absorbs trailing junk into the value it reports.** The endpoint
  must END on a word character OR A HYPHEN, and each `via` token takes the same arrow rule the
  endpoint does. That admitted set is DERIVED rather than chosen: 31 candidate trailing
  characters were put to the installed guardlink 2.0.0, one id per character, and exactly two
  came back as part of the id — `-` and `_`, the second only because it is already a `\w` —
  against 29 hard `Malformed` errors (`. ~ : + @ / ! ? * & % $ = < > ^ # , ) ] } ; ' | \ ( [
  { "`). Before this, `@flows #api -> #cache.` reported the destination `#cache.` and
  `@flows User -> App.API.` reported `App.API.` — asset ids no human wrote, reaching
  `h.raw['cxg_flows']` and `report.json` verbatim, both lines hard `Malformed @flows` errors
  on the installed guardlink 2.0.0 — and `@flows #api -> #cache via redis -> db` reported the
  mechanism `redis -`, a value matching neither the installed binary (which returns the whole
  `redis -> db`) nor the single-token run this branch replaced (which returned `redis`). It
  fires on real code, not only on fixtures: guardlink's own
  `tests/dashboard-determinism.test.ts` writes a destination interpolated as `App.${name}`,
  read as the fabricated asset id `App.`. Both rules are TRUNCATIONS, not refusals, **in both
  endpoint positions** — the operand stops where the author's token stops and the rest is left
  as a residue, which is what the chain-edge refusal below acts on. The SOURCE position needed
  a second piece to make that true: the characters the run hands back have somewhere to go
  after a destination, but after a source the pattern needs `->` next, so
  `@flows #a. -> #b via x -- "d"` failed outright and lost the channel and the description with
  it. `_FLOW_ENDPOINT_RESIDUE` consumes exactly what the endpoint hands back — the endpoint's
  own class minus its word characters — so it now reads `#a` → `#b` with the mechanism and the
  description intact and the record flagged. The HYPHEN arm of the terminator is the other half
  of the same loss and needed no residue: `@flows #api -> #cache- via redis -- "d"` was coming
  back as a bare flagged pair with the mechanism and the description DROPPED, because a residue
  in the destination position sits where `via` must start — while the installed binary parses
  that line and returns the target `#cache-`. cxg was narrowing past the tool it exists to
  widen to, on a form that tool accepts; it now returns `#cache-` too. The terminal hyphen
  carries a wider arrow lookahead than the internal one (`-(?!-*>)` against `-(?!>)`), without
  which the first hyphen of an unspaced `-->` would be absorbed and report the id `#a-` for a
  line whose author wrote `#a-->`. What is still refused outright: a SPACED `@flows #a --> #b`, because the
  residue class admits no whitespace, and a multi-hop declaration; the installed guardlink
  2.0.0 calls both `Malformed`. Two further consequences, stated because they are changes
  rather than repairs: an unspaced `via HTTP->gRPC` reported `HTTP-` before this branch as well
  and now reports `HTTP` (reading such a mechanism whole, as guardlink does, is **GAP-53** and
  is deliberately not attempted), and an unspaced `@flows #a--> #b via x` read as nothing
  before the source allowance and now reads `#a` → `#b` flagged.
- **A half-read `@flows` declaration builds no chain edge.** Two residues flag a record and
  `derive_chain_edges` skips a flagged one: an unread operand consumed BEFORE the arrow, which
  flags unconditionally because nothing else can sit between an endpoint and the arrow after
  it, and text left behind by a match that read neither a mechanism nor a description.
  `@flows Browser -> App.API, App.Worker`,
  `@flows #api -> #cache, s3`, `@flows #api -> #cache (redis)` and
  `@flows Browser -> App.API for login` are every one a hard `Malformed @flows` error on the
  installed guardlink 2.0.0, and each was becoming a declared chain hand-off shown to the model
  under a header calling it the codebase's own declaration rather than a guess. Both endpoint
  values are the author's own words; the RELATIONSHIP between them is what would be invented.
  **The parser still emits a partial record for those lines** — a stated limitation, carried in
  `pentest/docs/ARCHITECTURE.md`, not a defect: only chain-edge construction refuses one.
  The REGION the TRAILING test applies to was measured against the installed binary rather than
  reasoned about, and the measurement overturned the obvious rule: once `via` is present that binary
  reads the rest of the line as the mechanism, so `via redis, s3` and `via TLS/5432` parse
  clean, and cxg truncating such a mechanism is no evidence the endpoints were misread.
  Flagging on a residue after a mechanism was tried first and would have been a live regression
  — 76 declarations across the three annotated repositories, among them guardlink's own
  `via TLS/5432` and siete's `via GET./health`, every one a clean pair whose chain edge
  origin/main derives. Scoped to a bare pair it marks 18, all prose or fixtures. What ends a
  bare pair cleanly is end of line or the enclosing block comment's terminator; a lint pragma
  does NOT, because `@flows #api -> #cache # FIXME` and `... # noqa: E501` are themselves hard
  `Malformed` errors on that binary. A general parse-time version of this test, across all
  thirteen verbs, was built and **withdrawn** — it dropped everyday code such as `@comment`
  followed by `# noqa: E501`, `# pylint: disable` or `NOSONAR` for a harm only `@flows` has,
  `@flows` being the only verb cxg turns into a claim about a relationship.
- **A multi-hop `@flows` declaration is not read.** `#api -> #cache -> #db via redis` yields
  nothing — not a chain, and not a truncated first hop either: because `via` is optional a
  plain pair pattern would match `#api -> #cache` and stop, reporting an edge with no channel
  and no description that no human declared, so the pattern refuses a second arrow outright.
  It was read for four rounds and withdrawn, because it produced five defects and reached no
  consumer that could justify them — `@flows` is not an intent kind, so a multi-hop
  description never entered any prompt, and the attacher's records carry no description field
  at all. **Reading a chain wrongly is worse than not reading it**: a wrongly derived chain is
  a false attack finding, the one output this product must never produce. The whole feature —
  parsing, getting a description to a consumer, and chain edges — is board card GAP-49.
  Single-hop chaining is byte-for-byte what it was, verified in both declaration orders. Two
  providers on one artifact remains reachable for single-hop flows and is not closed here:
  `src_ids` is the id set of every hypothesis on the src asset, so two hypotheses on one asset
  both provide — the ordinary case, one SARIF result per exposure and several per asset — and
  two separate declarations sharing a transport name do the same (GAP-47).
- **A same-channel CHAIN keeps its middle hand-off.** Merging separate declarations onto one
  transport name puts two different shapes on one edge and they were getting one answer. A
  CYCLE (`#a -> #b via tok` plus `#b -> #a via tok`) leaves every provider also a requirer, so
  no probe can run first; a CHAIN (`#a -> #b via tok` plus `#b -> #c via tok`, the shape our
  own docs steer people toward since multi-hop is not read) puts the MIDDLE hypothesis on both
  sides legitimately. Subtracting src from dst answered the cycle by destroying the chain — the
  middle hypothesis's `requires` vanished with nothing logged, and the last was told an earlier
  probe provides an artifact either of two may have put. The merged record is now tested for a
  PURE PROVIDER, a src that is not also a dst: a cycle has none and is dropped whole at any
  length, a chain has one and is kept untouched, which is what origin/main derives. The
  per-flow rule that no SINGLE declaration may put one hypothesis on both sides is unchanged.
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
- **A via-less flow's artifact name no longer shares a namespace with a channel's.** Slugging
  the endpoint pair the way a channel is slugged made `@flows #a -> #b` and an unrelated flow
  declared `via a-b` both come out as `a_b` and MERGE onto one artifact — the consumer of one
  reading whatever the producer of the other put there, on a record reporting `channel: null`
  while listing a flow that did declare one. Via-less flows also collided with each other over
  hyphenated ids (`#order -> #api-cache` and `#order-api -> #cache` both slugged to
  `order_api_cache`). Endpoint-derived names are now `edge_<digest of the pair>`, still pure
  so both halves of an edge compute one name from one string.
- **A `.gal` `@source` header is recognised only at the start of a line.** Matched anywhere, a
  note whose own description quoted the header text was consumed as a header — losing its own
  annotation and silently re-attributing every note below it to the quoted path, so a "this is
  by design" note could reach a hypothesis in a different file. Leading whitespace still opens
  a block, because the installed guardlink parses an indented header.
- **A via-less edge is no longer described to the model as having a channel.** The generation
  prompt named the artifact but described every edge identically, so a declared `via` was not
  passed on and an absent one could not be distinguished from it. A declared channel is now
  named (`PROVIDES 'coupon_code' (declared over coupon.code)`) and an absent one is not
  mentioned at all.

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
