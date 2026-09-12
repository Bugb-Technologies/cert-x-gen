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
- **guardlink's grammar is a TABLE in its source, and that is the authority to derive from.**
  `guardlink gal` teaches by example and enumerates no character class; the grammar itself is
  the `PATTERNS` table in `src/parser/parse-line.ts`, built from ~10 named constants
  (`TAG_SEGMENT`, `ASSET_REF`, `ID_DEF`, …), with `comment-strip.ts` defining what is stripped
  before matching. Find the checkout with `readlink -f $(which guardlink)` — the installed
  binary is a symlink into it — then VERIFY before trusting it: `dist/parser/parse-line.js`
  must carry the same constants as `src`, since only `dist` is what runs. One derivation from
  that table explained every dimension six rounds of hand-trimming had missed one at a time.
  Do not hand-write a grammar, and do not derive one axis while holding another constant.
- **Every `PATTERNS` entry is anchored `^…$` (28 of 28, checked over `dist`), so cxg carries an
  END BOUND** (`_TAIL_RULES` in `pentest/guardlink.py`): an annotation must consume the
  rest of its line, bar a comment terminator WHOSE OPENER IS ON THAT LINE (guardlink strips one
  only through anchored patterns that require it, so a free-floating terminator reads forms the
  binary calls Malformed; `-}` and `*)` are dropped outright, since no extension cxg walks uses
  `{-` or `(*`), a further at-token, or an unclosed description —
  plus, for `@comment` ALONE, a separated trailing code comment. That one-verb limit is the
  binary's: with ` # noqa` appended, `@comment` is the only verb it leaves SILENT and the other
  twelve are hard `Malformed` errors, so extending there is allowed and extending elsewhere is
  reading a form guardlink refuses. Keep it — a lint pragma must not cost an author their
  intent note. `@flows` is EXEMPT from the bound entirely, because its `via` clause is unbounded
  in guardlink; that exemption is WIDER than its justification (a flow WITH a description and a
  trailing pragma is `Malformed` there and read here) and is a stated divergence, not a gap.
- **The bound is only ever as right as the clause in front of it.** Every tail it refuses is a
  clause cxg declined to read, so a clause NARROWER than the shared grammar turns valid work
  into a silent zero. That is not hypothetical: landing the bound over a `#`-only threat
  reference and a hard-coded `cwe:`-then-`owasp:` tail cost 72 shapes guardlink models. Before
  adding or tightening a clause, measure the OTHER direction.
- **The cross-product is re-runnable; use it rather than reasoning about either parser.**
  `test_no_form_the_installed_guardlink_refuses_is_read_as_a_declaration` and
  `…_accepts_is_refused_outside_a_stated_bound` put 9,152 cells of {endpoint form} ×
  {trailing character} × {verb × operand position} × {threat/control operand} × {ext-ref tail}
  to the installed binary and fail on drift, skipping where guardlink is absent. Any change to a
  verb pattern should be measured through it. Check a candidate rule in BOTH directions: reading
  more than guardlink and refusing what it accepts are the same defect, and the second is the one
  derivations keep committing. **A cross-product does not eliminate the blind spot; it relocates
  it to the choice of which dimensions to cross** — so read what the grid does NOT cross, written
  beside its tables, before trusting a claim it supports. The severity bracket is the one it
  still holds constant, and `_SEV` is a known surviving superset there.
  `pentest/docs/ARCHITECTURE.md` § "The END BOUND" carries the derivation and the numbers.
- **ANY CORPUS FIGURE THAT SHIPS MUST NAME THE CORPUS COMMIT.** A count measured against an
  unnamed or stale checkout is not a measurement, it is an anecdote with a number on it. A round
  here nearly shipped "66 annotations lost in siete" measured on a checkout twelve days stale,
  whose `origin/main` predated the PR that converted the estate off the `@g.` prefix — the real
  figure at siete `main` 733c0fb is 97, and every `@g.`-prefixed example cited alongside it no
  longer exists. Name the corpus commit, the cxg base and head, and the guardlink version, or do
  not ship the number.
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
  191 descriptions in siete and overturns a standing PR-74 decision. The END BOUND NARROWED
  both without closing either: a continuation line whose quoted verb leaves a TAIL no longer
  emits, one that ends the line still does. Until they are closed, prose
  in this estate must spell a verb apart from its arguments (`` `@flows` `` then
  `` `#p -> #q` ``), because this parser reads its own source — and BACKTICKING the verb is what
  actually protects it, the pattern then needing whitespace where the backtick sits.
  **THE WALK AND THE JOIN NOW DISAGREE ABOUT WHAT AN ANNOTATION IS**, and that is the headline,
  not any one note it loses. `_annotations_on_line` requires the END BOUND; the join's
  nested-annotation stop is still the raw `_VERB_RULES` patterns with no tail check. The two were
  IDENTICAL before the bound landed, and `_VERB_RULES` exists precisely so the walk, the join and
  the opener cannot diverge — so a line the walk refuses to read can still kill a wrapped note.
  Head is not worse than base (base fabricated an `@audit` and lost the note; head is merely
  silent), so nothing regresses against `origin/main`, but a different symptom will surface next
  time. Filed on GAP-32 and declined for this branch: the remedy reaches into its parked
  measurement. GAP-32 is one specific way a
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
