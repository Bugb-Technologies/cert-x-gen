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
- **A verb must OPEN a comment body, and one written inside a note's own description is not an
  annotation.** Prose explaining a verb, or recording a mitigation deliberately NOT written,
  must not be read as one — the real case is in guardlink's `tests/fixtures/expense-api`.
  **GAP-48 is CLOSED** (2026-09-12): a verb is read only where a comment body begins, matching
  the installed guardlink. `pentest/docs/ARCHITECTURE.md` § "A verb must OPEN the comment body"
  is the authority — the two places a body begins, the `.gal` half, and the measurement.
  A body opens after a comment opener ANYWHERE on the line — narrowing to line-start DROPPED
  223 annotations over guardlink f3b36ce, siete 7df5848 and cert-x-gen 4b342e6, a cost PAID in
  a0bd9ba and not one a later round would pay, all 223 classified as string literals or generated
  markup rather than notes — and after the block-comment `*`
  marker at the start of a trimmed line, and nowhere else. The openers include `<!--`, because
  guardlink reads an HTML-comment annotation in a `.html` file and narrowing PAST the binary is
  forbidden as firmly as widening past it — WITHIN THE DOMAIN THE TWO SHARE, which is the files
  cxg actually opens. Where guardlink reads a language `_TEXT_EXTS` does not carry, being narrower
  is meaningless rather than wrong: board card **GAP-57**, six SPEC 2.9 comment styles cxg does
  not honour, is that case and is a stated bound, not a gap to close.
  `pentest/docs/ARCHITECTURE.md` carries the measurement; extend `_TEXT_EXTS` and the opener set
  together or neither. **A third start, chaining a body wherever a description had CLOSED, was
  tried and REMOVED — do not rebuild it.** Any quoted word followed by a verb
  satisfied it, so `#`-prose-quote-verb read in cxg and as nothing in guardlink, and guardlink
  calls a chained comment a hard `Malformed` error: cxg may extend where the authority is SILENT
  and may not read what it REFUSES. Removing it DOES cost: the 22 siete notes recorded as its
  justification reproduce exactly on siete 7df5848, and guardlink reads ZERO from every one of
  them, so they were notes only cxg could see. **What that removed is a body start at a closed
  description QUOTE, so a second annotation no longer chains off a quote alone — but a second
  comment OPENER inside the same comment still opens one, so a marker written before the second
  verb still yields both, in all four spellings.** guardlink reads zero from every such line, so
  cxg reads more than the binary there; that is the GAP-52 mechanism, not a separate defect. A
  sentence here once claimed at most one annotation per comment and was measured false; the bound
  the parser implements is per line and per verb KIND. **GAP-56 is CLOSED as obsolete**: the rule
  that created the trailing-comment asymmetry was removed, so a trailing comment and a whole-line
  comment now behave identically — that identity is why the card closed, not a residue of it. Do
  not re-file or re-investigate it. Extending the refusal to the whole line is separate and is not
  authorised. One residue is filed rather than closed: **GAP-52**, display markup where a real `#`
  or `//` sits immediately before a verb and still reads, which the mid-line opener rule that keeps
  trailing comments working is what admits.
- **Closing GAP-48 did NOT close GAP-32, though the card predicted it would.** A verb on a
  CONTINUATION line does open that line's comment body, so the rule admits it and must; the
  continuation line remains an open bound. What GAP-48 did close, besides prose generally, is
  the opener whose join FAILS — that verb sits mid-line and is now refused. The join stopping at
  a continuation line is still not the fix: `parse_inline` reaches that line again on its own
  turn and emits. Do not attempt the closure without re-reading the measurement in
  `pentest/docs/ARCHITECTURE.md` — the obvious one loses 191 descriptions in siete and overturns
  a standing PR-74 decision. Prose in this estate has two rules, because this parser reads its
  own source: do not BEGIN a comment line with a verb followed by its arguments, and do not write
  a comment marker immediately before a verb you are only NAMING — `# the form is: # @audit #x --
  "y"` reads as a live audit, which is the GAP-52 residue above. Spelling the verb apart from its
  arguments (`` `@flows` `` then `` `#p -> #q` ``) is the habit that survives both; no position in
  a sentence is safe on its own.
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
