# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

## CI gates that are easy to miss locally

- **`cargo fmt --all -- --check` is enforced.** Parts of the tree have historically been
  left unformatted, so a change can be format-clean in isolation and still fail. Run
  `cargo fmt --all` before pushing.
- **The suite runs on Windows.** Integration tests that exec a shell fixture fail there
  (`os error 3`), so gate any such test file with `#![cfg(unix)]` — see
  `tests/probe_contract.rs` and `tests/cli_baseline_pack.rs`.
- **Clippy has a non-zero baseline.** Compare the count against the merge-base rather than
  expecting zero: `cargo clippy --all-targets 2>&1 | grep -c '^warning: '`.

## Inline annotations this repo writes about itself

- Annotations here are **bare GuardLink verbs** (`@comment`, `@exposes`, …). Write new ones
  that way. The `@g.` prefix is the dialect of Giggs, a discontinued predecessor, and the
  estate was converted off it — the installed `guardlink` reads no `@g.` verb at all, so the
  whole corpus was invisible to it.
- **Two readers, and they do not read the same set.** `pentest/guardlink.py`'s `parse_inline`
  is cxg's own reader — thirteen verbs since 2026-09-09, when it was widened to the forms
  guardlink's Quick Syntax block TEACHES (a subset; `guardlink gal` is the grammar, and cxg
  does not read all of it — `@mitigates`' optional control clause and its `with` synonym are
  deliberately unread, GAP-44) — and it still ACCEPTS `@g.` on purpose, so the
  tolerance tests in `pentest/tests/test_inline_annotation_forms.py` keep their `@g.` fixtures
  and must not be "converted". `pentest/docs/ARCHITECTURE.md` ("Inline annotations") is the
  authority on what it accepts, including which verbs have a CONSUMER: `@confirmed`,
  `@feature` and `@owns` are recognised and deliberately consumed by nothing, and that is a
  stated contract, not an omission. The installed `guardlink` binary is the other reader;
  `guardlink gal` is its grammar.
- **Widen to what the installed guardlink ACCEPTS, never to what an instruction file teaches.**
  The two disagree: guardlink rejects `@exposes Dotted.Path (#id) to #threat` and bare
  `@source (#id)` as hard `validate` errors (SPEC 2.3 reserves the parenthesised id for
  definition verbs — board card GAP-36), so cxg must not read them either. Check a form by
  running `guardlink validate` over a fixture before building a reader for it.
- **A verb written inside a note's own description is not an annotation.** Prose explaining a
  verb, or recording a mitigation deliberately NOT written, must not be read as one — the real
  case is in guardlink's `tests/fixtures/expense-api`. This is one defect in three places
  (continuation line, opening line, and a note that opens and closes on one line); the LAST is
  closed outright, the OPENING line only where the description JOINS — the narrowing sits inside
  `parse_inline`'s join branch, so an opener that never closes anywhere still emits a verb quoted
  in its prose — and any new verb widens the surface of all three. **The CONTINUATION line, and
  an opener whose join FAILS, are OPEN BOUNDS — board card GAP-32.** The join stopping at a
  continuation line is not the fix: `parse_inline` reaches that line again on its own turn and
  emits. Do not attempt the closure
  without re-reading the measurement in `pentest/docs/ARCHITECTURE.md` — the obvious one loses
  191 descriptions in siete and overturns a standing PR-74 decision. Until it is closed, prose
  in this estate must spell a verb apart from its arguments (`` `@flows` `` then
  `` `#p -> #q` ``), because this parser reads its own source. GAP-32 is one specific way a
  broader root cause fires: cxg reads a verb ANYWHERE in a comment where guardlink requires it
  to open one (**GAP-48**). Cite GAP-32 for the continuation line and GAP-48 for the general
  case; do not merge them, and note that GAP-48's proposed anchor has a `.gal` trap — sidecar
  lines carry no comment marker, so a naive anchor drops every sidecar annotation.
- **`@source` and `@sink` are still in the Giggs form, deliberately.** guardlink has no
  `@sink` verb, and its `@source` is an unrelated `file:line` anchor directive — a bare
  `@source (#id) -- "…"` is a hard `guardlink validate` error, not a working annotation. Both
  need re-expressing in guardlink's grammar, not de-prefixing.
- **guardlink does not join a wrapped description; `parse_inline` does.** A note whose
  description runs onto a second comment line is reported by `guardlink validate` as "looks
  like prose" and is not in its model. That is a guardlink bound, not a defect in the note.
- **Escape a quote inside a note as `\"`.** An unescaped one truncates a single-line
  description at that point, and on a wrapped note's continuation line it loses the whole
  annotation silently — no error, the note simply stops being read.
- Any change there must be measured through the real `parse_inline` over a fixture, never by
  asserting on a regex's source; `pentest/tests/test_inline_annotation_forms.py` is the pattern,
  including the tests that pin what must NOT match.
- **A fix round may not weaken a test to make its own change pass.** If an existing test
  fails, either the change is wrong or the test was wrong, and which one it is must be argued
  explicitly — never settled by editing the test and moving on. A test relabelled "tolerated"
  by the round that broke it is a regression with paperwork. This happened here: a round
  moved a verb off position 0 in a fixture so its new stop stopped firing, and shipped green
  while silently losing a whole wrapped note.
- **A test's meaning depends on the code around it.** A later change that adds an early exit
  can silently empty a test that used to matter, and nothing goes red to say so. The only
  defence is to ask whether the guard would still FAIL if the thing it guards were removed;
  if deleting the guarded code leaves the test green, the test is not guarding it. This is a
  different species from a weakened fixture — nobody edited the test. The nested-annotation
  stop added an early exit that a 4,000-opener performance fixture hit before the continuation
  cap was ever approached, so it stopped testing its subject and stayed green.
- **A correction is itself a generator of false claims.** The sentence written to fix a false
  sentence is written at the moment the author feels most certain they finally understand the
  thing, which is exactly when they stop checking. It happened here: the edit that removed
  "neither closable from cxg" from bound 3 introduced "filed rather than built here" in the same
  paragraph, and no card had been filed. Prefer DELETING a false sentence to REPLACING it. When a
  replacement is necessary, make it a statement verifiable at the instant of writing — never one
  whose truth depends on a future act by anyone, including the author.
- **An asymmetry justifies COMPLETING something, not BUILDING something.** "The same note
  reads on one line and vanishes when wrapped" is evidence of an oversight only where closing
  it adds no new discrimination — the `/**` opener was an incomplete marker set and was
  completed. Where closing it needs new logic, especially logic that weakens an existing
  safety check, the asymmetry is evidence of a BOUND: document it and file it, do not remove
  it. The trailing-comment opener is that case (GAP-34); `pentest/guardlink.py`'s
  `_line_comment_marker` carries the reasoning.

## Templates

- Detection templates live in a separate repository; `templates/` holds only the
  per-language skeletons embedded into the binary at compile time. See `templates/README.md`.
- A test that needs a real detection pack vendors its own copy under `tests/fixtures/`
  (see `tests/fixtures/cli-baseline/pack/`) rather than reaching for one in another
  repository, so this repository's suite is green on its own contents.
- A file's **extension** decides whether cxg loads it as a template, and there are two
  independent allow-lists that must agree: the scan loader (`src/template/engine.rs`) and
  the `template validate` walk (`src/main.rs`). A helper that must not be run as a check
  needs an extension in neither.
- `cxg template validate` gates `cxg ai generate`'s save path and `cxg template add`, but
  **not** `cxg scan` — a template can run fine and still fail validation.

## Measuring the pentest orchestrator end to end

- `cxg pentest run` shells out to `~/.cert-x-gen/pentest/cxg_pentest.py`, which is a COPY
  installed by `cxg pentest install` — it can be older than the checkout. To measure your
  own changes, run the checkout's script directly; the Rust side only forwards argv.
- The Python entry point's subcommand is `pentest`, not `run`
  (`python3 pentest/cxg_pentest.py pentest --target … --codebase …`). `run` is the Rust
  spelling and argparse rejects it.
- `main()` runs a profile-kind pre-flight that exits 4 before `run_pentest` is ever called,
  so a measurement needs a real profile in `~/.cert-x-gen/auth/<name>.json` or it will exit
  on that instead of on the thing being measured.
- **PyYAML is needed for `--scope-file` and is only CHECKED, never installed.**
  `cxg pentest install` verifies it alongside playwright and anthropic and prints a pip
  line; it is pinned in `pentest/requirements.txt`. Without it every `--scope-file` is
  refused — see `pentest/README.md` § `cxg pentest scope-init`.
- `--scope-file` fails CLOSED: an unreadable file refuses the run with exit 4 and never
  degrades to defaults, while omitting the flag is a normal run on defaults. Absent is not
  unreadable, and the two must not be conflated. It is refused on `--template-lang py` too,
  which enforces no scope at all. The load runs twice on purpose — once in `main()`'s
  pre-flight, so the refusal beats `--interactive-auth` and `--creds-file`, and once in
  `run_pentest`, which is the config the scan enforces and keeps direct invocation correct.
  `pentest/docs/ARCHITECTURE.md` § `scope.py` is the authority;
  `pentest/tests/test_scope_file_refusal.py` pins every half.

## The finding -> exposure join (`guardlink hypothesis confirm --from-scan`)

- `pentest/docs/ARCHITECTURE.md` § "The exposure identity a finding carries" is the authority:
  what report.json puts on the wire, why the key is `{file, line}` and not `(asset, threat, file)`,
  and the residue that is still open. `pentest/tests/fixtures/shared-threat-name/README.md` carries
  the collision the key exists for.
- **Re-measuring the join needs a COPY of the target repository.** `importScan` writes
  `.guardlink/hypotheses.json` into the root it is pointed at, and `--from-scan` refuses a report
  outside that root, so a measurement against a real corpus copies the repo (`git archive HEAD |
  tar -x`) and puts the report inside the copy. Delete the ledger between shapes or the second
  measurement starts from the first one's outcome.
- **cxg cannot confirm what `guardlink sarif` does not emit.** The SARIF omits an exposure that
  carries a declared `@mitigates`, so that exposure never becomes a hypothesis and stays
  `untested` however well the join works. Measured on temporal: 1 of 142. `--mitigation-mode`
  selects among the hypotheses cxg was given; it cannot recover one it never received.
- `parse_sarif` also reads guardlink's `confirmed-exploitable` results as hypotheses. Their
  location is the `@confirmed` line, which is not an `@exposes` line, so findings derived from
  them cannot join by location and fall to the `(asset, threat)` tier. Measured on temporal: 7 of
  148 results, of which 4 joined on the fallback and 3 were refused as ambiguous.
- **A stale exposure location does not MISS, it lands on the wrong claim.** The ingest joins on
  location before it consults asset and threat, so a template whose stamped line has drifted
  confirms whatever exposure sits at that line today. `_cache_key` cannot be taught about the
  location — the digest is the on-disk template filename and siete recomputes it through cxg's
  own `_cache_key`, so changing the formula orphans every operator's cache and silently loses
  correlation — so the drift is answered by DROPPING the identity of any loaded template the run's
  hypotheses do not corroborate. That withdrawal is the LIVE defence and it runs on BOTH the
  generating and the replay branch; do not narrow it to the replay branch on the reasoning that a
  generating run has already re-stamped its reuses. `_reuse_cached_template`'s re-stamp is
  DEFENSIVE: `generate_all` makes a fresh `session-<timestamp>` directory unless its caller passes
  a `session_dir`, which the orchestrator does not, so nothing on the production generating path is
  cached to re-stamp. Keep it anyway — it is the write side of the same rule.
  `pentest/docs/ARCHITECTURE.md` § "Drift in a reused template" is the authority.
- **An ambiguous provenance gets NO identity, not a precise wrong one.** `_dedupe_by_probe_shape`
  collapses every hypothesis sharing one probe shape onto a single template, so where the group
  does not agree on one `(file, line, asset, threat)` the survivor's five identity keys are
  withheld and its findings are left unmatched. The criterion is the DISAGREEMENT, not the
  `[merged classes: …]` note, which is only a symptom; the dropped members land in
  `not_selected_threats`, whose remedy is not a bigger `--max-templates`. Every site that attaches
  an identity, with the proof beside it, is tabulated in `pentest/docs/ARCHITECTURE.md`
  § "Every site that attaches an exposure identity, and its proof" — a new site belongs in that
  table or it does not belong in the code.
- **Only a hypothesis `parse_sarif` built is stamped with an exposure identity.** The gate is the
  POSITIVE `Hypothesis.from_sarif`, never a list of the synthesisers to exclude — cxg mints
  hypotheses of its own (Electron IPC, `--discover-routes`) whose file and line name no annotation,
  and a negative list is correct only until the next one is added. When the identity is withdrawn
  from an uncorroborated template, `@threat_id` goes with the four headers: guardlink derives it
  from asset, threat and file with no line, so it names a file's surviving sibling just as wrongly.
  A reused template's re-stamp moves the same five. **A run holding no `from_sarif` hypothesis
  withdraws nothing** — that is the absence of a check, not a disproof, and it is the SARIF SUBSET
  that decides, never the length of `hyps`: a desktop run appends `electron_surface.extract` and
  `--discover-routes` appends its own, so the list is non-empty while nothing in it can corroborate
  an annotation location. The same subset is the only thing allowed to corroborate a stamp, because
  only guardlink's own exposures are stamped. Every withdrawal is recorded in report.json under
  `identity_withdrawn` — every template LOADED whose stamp was refused, which is not the same as
  every template that ran — and it is the only trace of the one drift case cxg cannot detect.
  THREE measured bounds are stated in `pentest/docs/ARCHITECTURE.md` § "The exposure identity a
  finding carries". The second needs a **guardlink** change (`guardlink sarif` does not export
  the anchor hash) and must not be approximated here. The third is cxg's own: a run that loaded
  no model withdraws nothing, so its stamps reach report.json UNCHECKED and can still join
  wrongly later — the abstain is right, and what is missing is a marker saying no check was made,
  since an empty `identity_withdrawn` reads the same as "checked, nothing refused".
- **`.gitignore` ignores `*.json` tree-wide.** A fixture that needs a JSON file needs `git add -f`
  or an allow-list line; `.sarif` is not affected.

## Instrumentation preflight

- `detect_instrumentation` (`src/engine/common.rs`) reads the **symbol table**, never the
  file's bytes. A binary that merely *names* a sanitizer is not an instrumented build --
  cxg's own binary carries `INSTRUMENTATION_MARKERS` as string literals, and the byte scan
  this replaced reported an ordinary `cargo build` of cxg as carrying all seven sanitizers,
  which made `--require-instrumentation` pass on a build that could show nothing.
- A fixture for anything in that path must therefore be a **real compiled object**, not a
  magic number followed by a marker string. `engine::common::object_fixtures` builds them
  with `cc`; every test that uses one is `#[cfg(unix)]`, because the suite runs on Windows
  and there is no `cc` there.

## The instrumented build assist (`cxg build --instrument`)

- **Nightly Rust is a real dependency** (`-Zsanitizer` is unstable, no stable equivalent).
  `tests/build_instrument.rs` explains itself and passes when nightly is missing rather than
  failing the build; do not turn that into a hard failure. `src/build/cargo.rs`'s module doc
  is the authority on the four load-bearing build flags.
- The proof toy's manifest is checked in as
  `tests/fixtures/build-instrument/cargo-manifest.toml`, **not** `Cargo.toml`, and the test
  materialises it into a temp directory. Renaming it to `Cargo.toml` nests a package inside
  the package under test and breaks `cargo build` and `cargo fmt --all`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
