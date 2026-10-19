# Usage guide

The general usage guide lives at **<https://docs.bugb.io/cxg/get-started/first-scan/>**.

Installing, running a first scan, choosing a scope, selecting templates, and every output format.

The documentation site covers released commands. The repository guidance below
describes CLI and Tauri testing in this source tree.

| Page | |
| --- | --- |
| Install cxg | <https://docs.bugb.io/cxg/get-started/installation/> |
| Run your first scan | <https://docs.bugb.io/cxg/get-started/first-scan/> |
| Scan a target | <https://docs.bugb.io/cxg/guides/scanning-a-target/> |
| CLI reference | <https://docs.bugb.io/cxg/reference/cli/> |

Architecture and contributor documentation stays in this repository. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) if you are changing cxg
itself rather than using it.

## Testing a local CLI binary

Use `cli://<binary>` as the scope, with an absolute executable path, to select a
local process target instead of a network host. With the default repository
configuration, fetch templates first and select
the CLI Security Baseline pack:

```bash
cxg template update
cxg scan --scope cli:///absolute/path/to/my-tool \
  --template-dir ~/.cert-x-gen/templates/official/templates/cli-baseline \
  --require-instrumentation
```

The pack is published under
[`templates/cli-baseline/`](https://github.com/Bugb-Technologies/cert-x-gen-templates/tree/main/templates/cli-baseline)
in the detection-template repository. This repository's `templates/` holds only
skeletons; `tests/fixtures/cli-baseline/pack/` is the vendored copy used by tests.
The baseline checks CLI classes such as argument/command injection, path and archive
traversal, credential handling, terminal escapes, memory safety and crashes/hangs.
A template can skip when it cannot find a suitable operation or establish a working
control; a skipped check provides no refutation.

### Structured probe input

For a probe template that consumes the input contract:

```bash
cxg scan --scope cli:///absolute/path/to/my-tool \
  --templates /path/to/probe.sh \
  --arg --format --arg json \
  --stdin-file ./case.bin --input ./corpus \
  --target-env ASAN_OPTIONS=abort_on_error=1 \
  --require-instrumentation
```

| Flag | What the template receives |
| --- | --- |
| `--arg <ARG>` (repeatable) | `CERT_X_GEN_ARGV`: JSON string array, preserving argument boundaries and hyphen-leading values |
| `--stdin-file <PATH>` | `CERT_X_GEN_STDIN_FILE`: canonical path to a readable file whose bytes the template can feed to stdin |
| `--input <DIR>` | `CERT_X_GEN_INPUT_DIR`: canonical seed corpus directory; cxg does not mutate or minimise it |
| `--target-env <KEY=VALUE>` (repeatable) | `CERT_X_GEN_TARGET_ENV`: JSON object for the target process; repeated keys take the last value |

These variables are absent when their flags are omitted. The template must consume
them; cxg does not automatically adapt every template to a tool's command syntax.
`CERT_X_GEN_TARGET_KIND` is `cli`, `CERT_X_GEN_TARGET_HOST` is the binary path,
and `CERT_X_GEN_TARGET_PORT` has no meaning for this kind.

### Oracles and instrumentation

Templates declare their decision mechanisms with `@oracles` and report probe
verdicts (`confirmed`, `refuted`, `skipped`, `errored` or `timed-out`) in JSON
metadata. An oracle can observe a signal, timeout, exit, exception, output property
or sanitizer diagnostic. A nonzero exit alone does not establish an unhandled
exception: the `exception` oracle recognises runtime exception output returned by
the template, including Python tracebacks and Rust panics.

With `--require-instrumentation`, cxg inspects compiled binaries for instrumentation
markers and checks each template's oracle requirements. It records unsupported
executions as skipped (`no-instrumentation-detected`, `oracle-unavailable(...)`,
or `target-not-found`) instead of earning a refutation from an incapable build.
Templates declaring only build-independent oracles, such as `exit`, `signal`,
`timeout`, `exception` or `property`, can still run with instrumentation `none`.
Interpreted scripts always detect `none`; strings naming sanitizers in source do
not count as binary instrumentation. Target-kind declarations are enforced even
without the instrumentation flag.

A scan does not compile the target. Build it separately with its instrumented
profile or use `cxg build --instrument --help` to choose the build-assist options
for your project. `--instrumented-manifest <PATH>` on the scan accepts build
provenance for the binary it names. See the
[full probe contract](ENGINE_ARCHITECTURE.md#the-probe-contract) for oracle
requirements, build assist and template result metadata.

## Testing a Tauri app

Install the pentest orchestrator and generate GuardLink SARIF in the app repository:

```bash
cxg pentest install
cd /path/to/app-repo
guardlink sarif . -p my-app -o whitebox/findings.sarif
cxg pentest run --target-type tauri --codebase .
```

This maps `#[tauri::command]` handlers, their `generate_handler!` registration,
parameter shapes and command names; it also collects JSON capability grants and
security fields from `tauri.conf.json`. Registered commands are correlated with
routeless GuardLink threats by source file; threats without a command match remain
`review_only_threats`. Capability grants are facts to review, not tested findings.
No `--target`, captured `--auth` profile or app launch command is needed.

The default `report.json` has status `tauri_surface_mapped` and the
`enumerated_not_live_probed` caveat. It enumerates commands without invoking them;
an empty findings list means no command was tested. Tauri exposes no CDP endpoint
on macOS or Linux for cxg to drive its webview as it does an Electron renderer.

To opt in to command proof, use a Rust toolchain and the app's build prerequisites:

```bash
cxg pentest run --target-type tauri --codebase . \
  --tauri-prove --tauri-prove-timeout 1200
```

This copies the app into the session's `tauri-harness/` directory, adds a test module
and runs `cargo test` with Tauri's `test` feature. It sends hostile arguments through
`get_ipc_response` in a headless `MockRuntime`. The deterministic probes cover
sentinel-based path traversal and renderer-controlled authorization arguments.
A confirmed result proves the probe's observed behavior in that harness; a refutation
applies only to the attempted arguments. Live navigation, DOM behavior and
clickjacking are outside its coverage, and the mock context does not reproduce the
running app's full setup or capability configuration.

Read `caveats`, `ambiguous` and `tauri_skipped_commands` alongside findings. Build
failures and commands without probeable arguments do not establish safety. The
[Tauri pentest reference](../pentest/README.md#tauri-source-map-and-in-process-proof)
describes the report and proof limits in more detail. Tauri uses the default `js`
pipeline; `--template-lang py` is refused.
