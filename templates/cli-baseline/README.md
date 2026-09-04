# CLI Security Baseline — the template pack

Fourteen black-box security checks for a **command-line tool**, expressed as
ordinary `cxg scan` shell templates.

A web application gets a one-command baseline (`zap-baseline.py`). A CLI tool
gets a reading list. This pack is the one-command baseline for the CLI.

```bash
cxg scan --scope cli:///usr/local/bin/yourtool \
         --templates templates/cli-baseline/cli-baseline-b01-argument-injection.sh \
         --templates templates/cli-baseline/cli-baseline-b03-path-traversal.sh
         # ... or point --templates at each class you want
```

The taxonomy these checks implement — with each class's definition, detection
method, observable, CWE mapping and detectability tier — is the **CLI Security
Baseline** specification. This directory is its reference implementation.

## The fourteen classes

| # | Class | CWE | Oracle | Detectability |
|---|---|---|---|---|
| B01 | Argument injection | CWE-88 | `property` | Clean |
| B02 | OS command injection | CWE-78 | `property` | Clean |
| B03 | Path traversal in a file argument | CWE-22 | `property` | Clean |
| B04 | Archive extraction traversal (zip-slip) | CWE-22, CWE-409 | `property` | Clean |
| B05 | Credentials exposed in the process table | CWE-214 | `property` | Clean |
| B06 | Insecure temporary file creation | CWE-377 | `property` | Clean |
| B07 | Untrusted search path / `PATH` hijack | CWE-426, CWE-427 | `property` | Clean |
| B08 | Terminal escape injection | CWE-150, CWE-117 | `property` | Clean |
| B09 | Unvalidated trust in environment variables | CWE-454, CWE-526 | `property` | Clean |
| B10 | Insecure config / credential file handling | CWE-732, CWE-276 | `property` | Clean |
| B11 | Memory-safety defect | CWE-787, CWE-125, CWE-416 | `asan`, `ubsan`, `msan` | **Partial** — needs instrumentation |
| B12 | Crash or hang on malformed input | CWE-20, CWE-400 | `signal`, `timeout`, `exception` | **Partial** |
| B13 | TOCTOU / symlink race | CWE-367 | `property` | **Partial** — probabilistic |
| B14 | Format-string defect | CWE-134 | `property`, `signal` | **Hint** |

## The honesty line

**B01–B10 are cleanly black-box-detectable. B11–B14 are suggestive only.**
That split is the pack's most important content, not a caveat on it.

For B01–B10 a probe produces an observable no correct implementation can
produce — a canary file that appears, a random nonce echoed back, a raw `0x1b`
byte. Those are facts, and a template that sees one is right.

For B11–B14 a quiet run is *not* evidence, and the pack refuses to pretend
otherwise. Three mechanisms enforce that:

1. **Each template declares the oracle it genuinely reads.** B11 declares
   `asan, ubsan, msan`, none of which a build can provide without a sanitizer,
   so cxg skips it with `no-instrumentation-detected` rather than letting it
   report a refutation it did not earn. B12–B14 declare build-independent
   oracles because they genuinely use them, so they still run — declaring a
   sanitizer oracle a template never consults would buy a false negative for
   nothing.
2. **`cxg_refute` will not fire without a delivered probe.** A refutation
   asserts the target was exercised. A template that found no attack surface
   downgrades itself to `skipped(no-probe-delivered)`.
3. **Discovery failure is a skip, never a clean bill of health.** No candidate
   subcommand, no working control invocation, no advertised environment
   variable — all produce `skipped` with the reason.

**Fourteen passing classes means fourteen classes were tested. It does not mean
the tool is secure.** The Detectability column is how that gets said in the
product rather than in a footnote.

## How a template finds its way in

A baseline is pointed at a binary, not at a hand-written invocation, so each
template discovers its own attack surface:

* **`--help` parsing.** `cxg_subcommands` reads the near-universal
  "`  name   description`" shape of a help listing. Each class then selects the
  subcommands whose names fit what it probes, and tries **all** of them — a
  baseline probes the surface it found rather than the first plausible guess.
* **A seeded corpus.** `cxg_seed_corpus` plants a few benign, conventionally
  named files so a file-oriented target has something valid to work on, and
  `cxg_working_arg` finds one the target actually accepts. That accepted
  invocation is the class's control: without it, a quiet probe means nothing.
* **The operator override.** `cxg_operator_argv` reads `CERT_X_GEN_ARGV`
  (`cxg scan --arg`), substituting the payload for a token, for a target whose
  invocation cannot be guessed.

## Files

```
cli-baseline.lib                 the shared probe library (see below)
cli-baseline-b01-…b14-….sh       the fourteen checks
```

`cli-baseline.lib` is **not a template**. Its extension is deliberately not one
cxg recognises, so neither `cxg scan`'s loader (`src/template/engine.rs`) nor
the `cxg template validate` walk (`src/main.rs`) picks it up as a check to run.
Templates source it as their first act, which works because the shell engine
runs a template in place (`bash <template-path> …`), so `$0` is the template's
own path and the library is its sibling.

The library owns the pack's contract: the four statuses and what each promises,
the JSON emission (via `json.dumps`, never string interpolation — the pack
deliberately sends control bytes at targets), lab setup and teardown, canary
nonces, target invocation with a timeout, and surface discovery.

## Safety

Every probe is confined to a `mktemp -d` lab removed on exit. The payloads are
the most boring thing that still produces the observable:

* command injection creates **one empty file** in the pack's own lab;
* `PATH` shims write a canary and `exit 0`, and shadow nothing the template did
  not create;
* archive members escape **into the lab**, never further;
* B14 sends `%x` and `%s` and **deliberately never `%n`** — the write primitive
  of that class is not needed to establish that a format string is
  caller-controlled;
* credentials in probes are random nonces, redacted from the evidence.

Nothing here reproduces a CVE, downloads anything, opens a socket, or writes
outside its lab.

## Proving it both ways

`tests/cli_baseline_pack.rs` runs every class against a benign synthetic
flawed/fixed twin pair and requires **confirmed on the flawed build, refuted on
the fixed one**. A class that fails either direction fails the build.

```bash
cargo test --test cli_baseline_pack
```

The fixtures are in `tests/fixtures/cli-baseline/`: `notekeeper.py` (twelve
classes), and `memtoy.c` built with AddressSanitizer for B11 and B14. One
source per program — a flawed and a fixed twin that could drift apart would be
worth nothing as a refutation test — with the twins materialised by `build.sh`.
