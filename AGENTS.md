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

- Every file here carries `@g.*` annotations (see `CLAUDE.md`). `pentest/guardlink.py`'s
  `parse_inline` is what READS them, and the `@g.` prefix and multi-line descriptions were
  invisible to it until they were made optional/joined — cert-x-gen's own 3,118 notes read as 1.
  `pentest/docs/ARCHITECTURE.md` ("Inline annotations") is the authority on what it accepts.
- **Escape a quote inside a note as `\"`.** An unescaped one truncates a single-line
  description at that point, and on a wrapped note's continuation line it loses the whole
  annotation silently — no error, the note simply stops being read.
- Any change there must be measured through the real `parse_inline` over a fixture, never by
  asserting on a regex's source; `pentest/tests/test_inline_annotation_forms.py` is the pattern,
  including the tests that pin what must NOT match.

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
