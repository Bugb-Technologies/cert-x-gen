# 🏗️ Template Engine Architecture

## Modular Design Overview

CERT-X-GEN implements a **polyglot template engine architecture** that supports **12 programming languages** for maximum flexibility in security scanning template development.

### Engine Hierarchy

```
TemplateEngine trait (interface)
    ├── Interpreted Engines
    │   ├── PythonEngine      (.py)       → python3/python
    │   ├── JavaScriptEngine  (.js, .mjs) → node
    │   ├── RubyEngine        (.rb)       → ruby
    │   ├── PerlEngine        (.pl)       → perl
    │   ├── PhpEngine         (.php)      → php
    │   └── ShellEngine       (.sh)       → bash/sh
    │
    ├── Compiled Engines
    │   ├── RustEngine        (.rs)       → rustc → binary
    │   ├── CEngine           (.c)        → gcc/clang → binary
    │   ├── CppEngine         (.cpp)      → g++/clang++ → binary
    │   ├── JavaEngine        (.java)     → javac → .class
    │   └── GoEngine          (.go)       → go build → binary
    │
    └── Declarative Engine
        └── YamlTemplateEngine (.yaml, .yml) → built-in parser
```

---

## File Organization

### Engine Module Structure

```
src/engine/
├── mod.rs              # Engine registry & exports
├── common.rs           # Shared utilities
├── yaml.rs             # YAML declarative engine
├── python.rs           # Python interpreted engine
├── javascript.rs       # JavaScript/Node.js engine
├── rust.rs             # Rust compiled engine
├── shell.rs            # Shell script engine
├── c.rs                # C compiled engine
├── cpp.rs              # C++ compiled engine
├── java.rs             # Java compiled engine
├── go.rs               # Go compiled engine
├── ruby.rs             # Ruby interpreted engine
├── perl.rs             # Perl interpreted engine
└── php.rs              # PHP interpreted engine
```

### Template Directory Structure

```
templates/
├── skeleton/           # Template skeletons for all languages
│   ├── c-template-skeleton.c
│   ├── cpp-template-skeleton.cpp
│   ├── java-template-skeleton.java
│   ├── go-template-skeleton.go
│   ├── python-template-skeleton.py
│   ├── javascript-template-skeleton.js
│   ├── rust-template-skeleton.rs
│   ├── shell-template-skeleton.sh
│   ├── ruby-template-skeleton.rb
│   ├── perl-template-skeleton.pl
│   ├── php-template-skeleton.php
│   └── yaml-template-skeleton.yaml
├── c/                  # C templates
├── cpp/                # C++ templates
├── java/               # Java templates
├── go/                 # Go templates
├── python/             # Python templates
├── javascript/         # JavaScript templates
├── rust/               # Rust templates
├── shell/              # Shell templates
├── ruby/               # Ruby templates
├── perl/               # Perl templates
├── php/                # PHP templates
└── yaml/               # YAML templates
    ├── http/           # HTTP-based templates
    └── network/        # Network service templates
```

---

## Engine Implementation Details

### 1. Common Utilities (`src/engine/common.rs`)

Shared functionality across all engines:

- **`build_env_vars()`** - Build environment variables for templates
- **`parse_findings()`** - Parse JSON output from templates
- **`create_metadata()`** - Generate template metadata from file
- **`get_ports_to_scan()`** - Extract port configuration from context

### 2. Interpreted Language Engines

#### Python Engine (`src/engine/python.rs`)
- **Interpreter**: `python3` (fallback to `python`)
- **Extension**: `.py`
- **Libraries**: `requests`, `urllib`, `json`
- **Execution**: Direct script execution with environment variables

#### JavaScript Engine (`src/engine/javascript.rs`)
- **Interpreter**: `node`
- **Extension**: `.js`, `.mjs`
- **Libraries**: Built-in `http`, `https`, `fs`
- **Execution**: Direct script execution with environment variables

#### Ruby Engine (`src/engine/ruby.rs`)
- **Interpreter**: `ruby`
- **Extension**: `.rb`
- **Libraries**: `net/http`, `json`
- **Execution**: Direct script execution with environment variables

#### Perl Engine (`src/engine/perl.rs`)
- **Interpreter**: `perl`
- **Extension**: `.pl`
- **Libraries**: `LWP::UserAgent`, `JSON`
- **Execution**: Direct script execution with environment variables

#### PHP Engine (`src/engine/php.rs`)
- **Interpreter**: `php`
- **Extension**: `.php`
- **Libraries**: Built-in `curl`, `json`
- **Execution**: Direct script execution with environment variables

#### Shell Engine (`src/engine/shell.rs`)
- **Interpreter**: `bash` (fallback to `sh`)
- **Extension**: `.sh`
- **Tools**: `curl`, `wget`, `nc`, `jq`
- **Execution**: Direct script execution with environment variables

### 3. Compiled Language Engines

#### C Engine (`src/engine/c.rs`)
- **Compiler**: `gcc` (fallback to `clang`)
- **Extension**: `.c`
- **Compilation**: `gcc -O2 -std=c11 -lcurl -ljson-c -o binary source.c`
- **Cache Directory**: `/tmp/cert-x-gen-cache/c/`
- **Execution**: Compiled binary with environment variables

#### C++ Engine (`src/engine/cpp.rs`)
- **Compiler**: `g++` (fallback to `clang++`)
- **Extension**: `.cpp`, `.cc`, `.cxx`
- **Compilation**: `g++ -O2 -std=c++17 -lcurl -o binary source.cpp`
- **Cache Directory**: `/tmp/cert-x-gen-cache/cpp/`
- **Execution**: Compiled binary with environment variables

#### Java Engine (`src/engine/java.rs`)
- **Compiler**: `javac`
- **Runtime**: `java`
- **Extension**: `.java`
- **Compilation**: `javac -d cache_dir source.java`
- **Cache Directory**: `/tmp/cert-x-gen-cache/java/`
- **Execution**: `java -cp cache_dir ClassName`

#### Go Engine (`src/engine/go.rs`)
- **Compiler**: `go build`
- **Extension**: `.go`
- **Compilation**: `go build -o binary source.go`
- **Cache Directory**: `/tmp/cert-x-gen-cache/go/`
- **Execution**: Compiled binary with environment variables

#### Rust Engine (`src/engine/rust.rs`)
- **Compiler**: `rustc` (via `cargo`)
- **Extension**: `.rs`
- **Compilation**: `cargo build --release --bin template_name`
- **Cache Directory**: `/tmp/cert-x-gen-cache/rust/`
- **Execution**: Compiled binary with environment variables

### 4. Declarative Engine

#### YAML Engine (`src/engine/yaml.rs`)
- **Parser**: Built-in YAML parser
- **Extension**: `.yaml`, `.yml`
- **Features**: HTTP requests, network probes, flow control
- **Execution**: Native Rust implementation

---

## Communication Protocol

### Environment Variables

All templates receive configuration via environment variables:

```bash
# Target configuration
CERT_X_GEN_TARGET_HOST=example.com
CERT_X_GEN_TARGET_PORT=80
CERT_X_GEN_ADD_PORTS=8080,9090,3000
CERT_X_GEN_OVERRIDE_PORTS=80,443

# Context information
CERT_X_GEN_MODE=scan
CERT_X_GEN_TEMPLATE_ID=redis-unauthenticated
CERT_X_GEN_TEMPLATE_NAME="Redis Unauthenticated Access"
CERT_X_GEN_TEMPLATE_AUTHOR="CERT-X-GEN Team"

# Target kind: http | https | tcp | udp | ... | cli
CERT_X_GEN_TARGET_KIND=https

# Additional configuration
CERT_X_GEN_TIMEOUT=30
CERT_X_GEN_RETRY_COUNT=3
CERT_X_GEN_USER_AGENT="CERT-X-GEN/1.0"
```

---

## The probe contract

The probe contract is what lets a template drive a **local binary** with input
cxg supplies, and report a verdict cxg can record. Everything in it is
optional: a template that ignores all of it behaves exactly as before, and a
scan that passes none of the flags produces exactly the environment it always
did.

### `cli://` targets

A target can be a locally-built executable rather than a network host:

```bash
cxg scan --scope cli:///abs/path/to/binary      # canonical
cxg scan --scope cli:/abs/path/to/binary        # also parses
```

For such a target:

| Variable | Value |
| --- | --- |
| `CERT_X_GEN_TARGET_HOST` | the **binary path**, canonicalised |
| `CERT_X_GEN_TARGET_KIND` | `cli` |
| `CERT_X_GEN_TARGET_PORT` | **meaningless — ignore it when `KIND=cli`.** It is still emitted (as `80`) so the environment stays uniform across kinds, but it names nothing |

A `cli:` scope entry is taken verbatim: it is never split on commas and never
read as a file of targets, so a binary path containing a comma survives.

### Probe input flags

Each variable is **absent** unless its flag was passed, so a template must
treat every one as optional and fall back to its own default probe.

| Scan flag | Environment variable | Shape | Meaning |
| --- | --- | --- | --- |
| `--arg <ARG>` (repeatable) | `CERT_X_GEN_ARGV` | JSON array of strings | argument vector for the target. Hyphen-leading values are accepted, so the target's own flags can be passed |
| `--stdin-file <PATH>` | `CERT_X_GEN_STDIN_FILE` | path | file whose bytes are the target's stdin |
| `--input <DIR>` | `CERT_X_GEN_INPUT_DIR` | path | seed corpus directory. cxg hands it over unmodified; it does not mutate or minimise |
| `--target-env <K=V>` (repeatable) | `CERT_X_GEN_TARGET_ENV` | JSON object | environment for the **target** process, not for the template. Splits on the first `=` only, so `ASAN_OPTIONS=abort_on_error=1` survives |
| — | `CERT_X_GEN_TARGET_INSTRUMENTATION` | comma list or `none` | what a `cli://` build can reveal, e.g. `asan,debug-info`. Always set for a `cli://` target |

Paths are validated and canonicalised before the scan starts: a `--stdin-file`
that is not a readable file, an `--input` that is not a directory, and a
`--target-env` without a `KEY=VALUE` shape are all hard errors rather than
silently dropped input.

```bash
cxg scan --scope cli://$BIN --templates probe.sh \
    --arg --label --arg "$(cat case.txt)" \
    --stdin-file ./case.bin \
    --input ./corpus/ \
    --target-env ASAN_OPTIONS=abort_on_error=1
```

### Instrumentation preflight

```bash
cxg scan --scope cli://$BIN --require-instrumentation
```

Without this, a build that carries no sanitizer runs the probe, sees nothing,
and is reported as a **refutation it did not earn** — a false negative
indistinguishable from a real one. With it, cxg inspects the binary for
sanitizer, coverage and debug-info markers first, and records every
(template, target) execution as `skipped` with a machine-readable reason
instead:

| Reason | Meaning |
| --- | --- |
| `no-instrumentation-detected` | the build carries no marker cxg can read, so it could not have shown the defect. Applied **per template**: one that declares only build-independent oracles still runs |
| `target-not-found` | there is no binary at that path at all |
| `oracle-unavailable(asan)` | the template's only oracles are sanitizers this build does not carry (see `@oracles`) |
| `target-kind-mismatch(kind=…, accepts=…)` | the template declared `@target_kinds` and this is not one of them (applies with or without the flag) |

`no-instrumentation-detected` is decided per template, not per target. A
template that declares only oracles needing nothing from the build — `exit`,
`signal`, `timeout`, `exception` — runs anyway and reaches a real verdict; one
that declares a sanitizer oracle, or declares none at all, is still skipped. An
absent declaration says nothing about how the template decides, and the flag
exists to stop cxg guessing.

The marker scan runs on **compiled objects only** — ELF, Mach-O, PE, static
archives. A shebang script, a JS bundle, a Python console-script wrapper or a
source file reports `none` however many marker strings it contains: those
strings are symbol names in an object and prose everywhere else, and reading
prose as instrumentation would let the preflight pass on a build that can show
nothing. An **interpreted CLI therefore always detects `none`** — see
`@oracles` below for how a template whose oracles do not need a sanitizer still
runs against one.

`cxg scan` **inspects and refuses; it never builds the target.** Building runs
the project's own build system — `build.rs`, `configure`, arbitrary `Makefile`
recipes — as the invoking user, which is a different trust decision from
reading a file, and it costs minutes and gigabytes. Both belong to a verb an
operator types, not a flag a scan turns on. Build the target with your
language's instrumented profile — for C/C++, `-fsanitize=address -g` — or use
the build assist below.

### `cxg build --instrument`

```bash
cxg build --instrument --project . --bin cxg --sanitizer address --manifest /tmp/m.json
```

The deliberate opt-in on the other side of that line. It detects the build
system, asks **rustc** what the target can do rather than guessing, builds into
a private target directory, **re-reads the produced binary**, and prints one
JSON manifest. Cargo/Rust is the only back end today; every other recognised
build system skips with `build-system-not-implemented`.

**There is no path from "I could not instrument this" to "here is a binary."**
Every precondition failure is a `skipped` carrying a machine-readable reason:

| Reason | Meaning |
| --- | --- |
| `unknown-build-system` | no marker file matched, and the tree is not guessed at. The manifest lists what was looked for |
| `build-system-not-implemented(cmake)` | recognised, no back end yet |
| `nightly-toolchain-unavailable(install: …)` | `-Zsanitizer` is nightly-only and there is no stable equivalent |
| `sanitizer-unsupported-on-target` | rustc's own `supported-sanitizers` for this triple does not list it — MSan and LSan are absent on `aarch64-apple-darwin`. Asking for **UBSan** lands here with a note: `-Zsanitizer=undefined` does not exist on *any* Rust target |
| `sanitizer-not-verifiable(cfi)` | rustc supports it, but no symbol marker distinguishes the build, and cxg does not report instrumentation it cannot read back out of the artefact |
| `binary-target-ambiguous(pass --bin NAME)` | several binary targets and no way to know which is the CLI under test |
| `instrumented-build-failed(exit=N)` | with the last 20 lines of the build log |
| **`build-produced-no-instrumentation(wanted=… detected=…)`** | the build reported success and the artefact does not carry what was asked for |

That last row is the one the design turns on. A build that accepted the flags
and silently dropped them — a `Makefile` that assigns rather than appends
`CFLAGS`, or a shell that exported `CARGO_ENCODED_RUSTFLAGS` — still links,
still runs, and is indistinguishable from an instrumented build until you look
at the artefact. So cxg looks, with the same symbol-table scan the preflight
uses, and skips rather than handing a scan a binary it could not vouch for.

**Rust specifics.** `-Zsanitizer` needs nightly; `--target <host triple>` is
passed even when not cross-compiling, so `RUSTFLAGS` does not reach the build
scripts and proc-macro crates cargo compiles *and runs* on the host; the target
directory is never the project's own, because `RUSTFLAGS` is part of cargo's
fingerprint. Rust has **no UBSan**, so the integer class is carried by
`-C overflow-checks=on`, which cxg passes on every instrumented build and which
the detector reports as the `rust-overflow-checks` label (see the `overflow`
oracle below). Budget several gigabytes per instrumented project.

### `--instrumented-manifest`: provenance beats inspection

```bash
cxg scan --scope cli://$BIN --require-instrumentation --instrumented-manifest /tmp/m.json
```

Where cxg built the binary it does not have to re-derive what the binary
carries: it passed the flags and read the artefact back before it was willing
to call the build instrumented. That record is better evidence than a second
sniff of the same file — it survives stripping and a copy away from the build
tree — so a manifest is believed in preference to inspection, for the binary it
names and no other. A manifest recording a *skipped* build is an error, not a
silent no-op. **Omit the flag and a scan behaves exactly as it did before this
existed.**

### Template annotations

Parsed exactly like the existing `@`-annotations, all optional:

| Annotation | Example | Effect |
| --- | --- | --- |
| `@allow_nonzero_exit` | `true` | The template exits non-zero on purpose. A probe that successfully provokes a crash naturally does; without this cxg discards its stdout and the finding is lost |
| `@oracles` | `asan, signal, exit` | How the template decides something is wrong. Vocabulary: `asan` `ubsan` `msan` `tsan` `overflow` `signal` `exit` `exception` `assert` `timeout` `diff` `property` `detector` |
| `@target_kinds` | `cli` | Which kinds the template accepts. **Absent means every kind** — do not add it for completeness, only when the template genuinely cannot handle other kinds |

#### The `exception` oracle

Every oracle but this one is the template's own observation. `exception` is
cxg's: an unhandled language-level exception escaping the target is a defect
that neither `signal` nor `exit` can name — a Python traceback or a Node
unhandled rejection exits **1** with no crash signal, so `signal` never fires
and `exit` fires just as loudly on a program correctly reporting a bad
argument.

A template that declares it runs the target, then hands the output back:

```json
{"findings": [], "metadata": {"target_output": "...", "target_exit_code": 1}}
```

cxg matches that output against the shape of an escaped exception — a CPython
`Traceback (most recent call last):` block, a Node stack carrying
`UnhandledPromiseRejection` or the runtime's own `node:internal/` frames, a JVM
`Exception in thread "..."`, a Go `panic:` with a goroutine dump, a Rust
`thread '...' panicked at` — and, when one matches, records the execution
`confirmed` with `oracle=exception(<kind>)` and a finding carrying the output
as evidence. The match is on the output only, never the exit status.

It applies only when the template declared `@oracles: exception`, reported no
findings of its own, and declared no status of its own: a template that reached
its own verdict keeps it. It needs nothing from the build, so it also runs
under `--require-instrumentation` against a target whose instrumentation is
`none` — which is every interpreted CLI.

#### The `overflow` oracle — the Rust integer class

**Rust has no UBSan.** `-Zsanitizer=undefined` is not in rustc's vocabulary on
any target, on any nightly, so a baseline class that declares `ubsan` is
declaring something unreachable on every Rust build there will ever be. The
equivalent check is `-C overflow-checks=on`, which turns an integer wrap into a
panic; compile it out and the same program returns the same wrong number and
exits **0**.

That makes it exactly as build-dependent as a sanitizer, so `overflow` is a
build-dependent oracle mapped to the `rust-overflow-checks` instrumentation
label. A template's overflow branch is therefore gated the same way an ASan
branch is and cannot claim a verdict on a build where the check was never
compiled in.

The label is read from the symbol table like every other: the check compiles in
a call to `core::panicking::panic_const::panic_const_{add,sub,mul,neg,shl,shr}_overflow`,
and those symbols are present if and only if the flag was passed. (`div` and
the by-zero panics are emitted either way — they are hard errors, not overflow
checks.) A build with the check on but no fallible arithmetic left after
const-folding carries no such symbol and reads as uninstrumented, which is the
safe direction: the template skips rather than claims.

Reaching instead for a build-*independent* oracle such as `exception` would
make the whole template read as build-independent and let it run — and refute —
on an uninstrumented build, quietly undoing the preflight. That is why the
integer class needs its own build-dependent oracle rather than borrowing one.

### Declaring an execution status

Every (template, target) pair produces one row in `ScanResults.executions`.
cxg infers the status from what it observed — findings > 0 is `confirmed`,
0 is `refuted`, a timeout is `timed-out`, any other error is `errored` — and a
template may override it in the JSON wrapper `parse_findings` already accepts:

```json
{"findings": [],
 "metadata": {"status": "refuted", "detail": "target handled probe input cleanly (exit=0)"}}
```

`status` is one of `confirmed` `refuted` `errored` `skipped` `timed-out`. An
unrecognised value is reported as `unrecognised-status(<value>)`, never
silently ignored.

Declaring it is how a template says *"I ran, I exercised the target, and there
is no defect"* rather than leaving that indistinguishable from a template that
did nothing. Each row records `declared_by_template`, so an operator can
always tell a template's considered verdict from cxg's default guess:

```json
{"target": "/path/toy_defective", "target_kind": "cli",
 "template_id": "cli-probe-contract", "status": "confirmed",
 "declared_by_template": true, "findings": 1, "exit_code": 3,
 "detail": "oracle=asan exit=134 input=cxg-argv", "duration_ms": 597}
```

The ledger appears in the JSON output and in an **Execution Status** block in
the terminal summary. Other output formats (SARIF, CSV, HTML, Markdown) do not
carry it: a non-result has no natural SARIF representation, and forcing one is
its own design question.

### Which engines implement it

The shell engine implements the probe contract today. The other engines
inherit a default `Template::execute_with_status` that delegates to `execute`
and declares nothing, so they compile and behave exactly as before; their
templates still get the full environment above, and cxg still records an
inferred status for them.

---

### JSON Output Format

All templates must output findings in this simplified JSON format:

```json
{
  "findings": [
    {
      "id": "redis-unauthenticated-access",
      "name": "Redis Unauthenticated Access",
      "severity": "critical",
      "description": "Redis instance is accessible without authentication",
      "evidence": {
        "type": "http_response",
        "data": "PONG"
      },
      "tags": ["redis", "unauthenticated", "database"],
      "cwe": "CWE-306",
      "references": ["https://redis.io/topics/security"]
    }
  ]
}
```

---

## Engine Registration

Engines are registered in `src/core.rs`:

```rust
impl CertXGen {
    pub async fn new(config: Config) -> Result<Self> {
        let mut template_loader = TemplateLoader::new();
        
        // Register interpreted language engines
        template_loader.register_engine(Box::new(crate::engine::PythonEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::JavaScriptEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::RubyEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::PerlEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::PhpEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::ShellEngine::new()));
        
        // Register compiled language engines
        template_loader.register_engine(Box::new(crate::engine::RustEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::CEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::CppEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::JavaEngine::new()));
        template_loader.register_engine(Box::new(crate::engine::GoEngine::new()));
        
        // Register declarative engine
        template_loader.register_engine(Box::new(crate::engine::YamlTemplateEngine::new()));
        
        // ... rest of initialization
    }
}
```

---

## Template Interface

### TemplateEngine Trait

All engines implement the `TemplateEngine` trait:

```rust
#[async_trait]
pub trait TemplateEngine: Send + Sync {
    fn name(&self) -> &str;
    fn language(&self) -> TemplateLanguage;
    fn supports_file(&self, path: &Path) -> bool;
    
    async fn load_template(&self, path: &Path) -> Result<Box<dyn Template>>;
    async fn execute_template(
        &self,
        template: &dyn Template,
        target: &Target,
        context: &Context,
    ) -> Result<Vec<Finding>>;
}
```

### Template Trait

Individual templates implement the `Template` trait:

```rust
pub trait Template: Send + Sync {
    fn metadata(&self) -> &TemplateMetadata;
    fn file_path(&self) -> &Path;
    fn language(&self) -> TemplateLanguage;
}
```

---

## Compilation Caching

### Compiled Language Caching

Compiled languages (C, C++, Java, Go, Rust) implement intelligent caching:

1. **Source Hash**: Calculate SHA-256 hash of source file
2. **Cache Key**: `{language}/{hash}`
3. **Cache Check**: Look for existing binary/class file
4. **Compilation**: Only compile if cache miss
5. **Cache Storage**: Store in `/tmp/cert-x-gen-cache/{language}/`

### Cache Invalidation

- **Source Change**: Hash mismatch triggers recompilation
- **Dependency Change**: Compiler version changes invalidate cache
- **Manual Cleanup**: `make clean` removes all cached binaries

---

## Error Handling

### Graceful Degradation

- **Missing Compiler**: Engine reports as unavailable, skips templates
- **Compilation Failure**: Log error, continue with other templates
- **Runtime Error**: Capture stderr, return error finding
- **Timeout**: Kill process, return timeout finding

### Error Types

```rust
pub enum EngineError {
    CompilerNotFound(String),
    CompilationFailed(String),
    ExecutionFailed(String),
    Timeout,
    InvalidOutput(String),
}
```

---

## Performance Considerations

### Interpreted Languages
- **Startup Time**: Higher due to interpreter initialization
- **Memory Usage**: Higher due to interpreter overhead
- **Execution Speed**: Slower but more flexible

### Compiled Languages
- **Startup Time**: Lower after initial compilation
- **Memory Usage**: Lower due to native binaries
- **Execution Speed**: Faster, especially for complex operations

### YAML Engine
- **Startup Time**: Lowest (native Rust)
- **Memory Usage**: Lowest
- **Execution Speed**: Fastest for simple operations

---

## Testing Strategy

### Unit Tests
- **Engine Registration**: Verify all engines are registered
- **File Support**: Test file extension detection
- **Template Loading**: Test metadata extraction
- **Environment Variables**: Test variable passing

### Integration Tests
- **End-to-End Execution**: Test complete template execution
- **Compilation Caching**: Verify cache behavior
- **Error Handling**: Test failure scenarios
- **Multi-Language**: Test templates from all languages

### Performance Tests
- **Compilation Time**: Measure compilation overhead
- **Execution Time**: Compare language performance
- **Memory Usage**: Monitor resource consumption
- **Cache Efficiency**: Measure cache hit rates

---

## Best Practices

### Template Development
1. **Use Appropriate Language**: Choose based on requirements
2. **Follow Skeleton Structure**: Use provided skeletons as starting points
3. **Handle Errors Gracefully**: Always check for failures
4. **Output Valid JSON**: Ensure proper JSON formatting
5. **Use Environment Variables**: Don't hardcode configuration

### Engine Selection
- **Simple HTTP Requests**: YAML or Python
- **Complex Logic**: Python or JavaScript
- **Performance Critical**: Rust, C, or Go
- **System Integration**: Shell scripts
- **Rapid Prototyping**: Python or Shell

### Performance Optimization
- **Use Compiled Languages**: For frequently executed templates
- **Minimize Dependencies**: Reduce compilation time
- **Cache Effectively**: Leverage compilation caching
- **Profile Templates**: Identify bottlenecks

---

## Future Enhancements

### Planned Features
- **WASM Support**: WebAssembly template execution
- **Plugin System**: Dynamic engine loading
- **Remote Execution**: Distributed template execution
- **Template Marketplace**: Community template sharing

### Language Additions
- **C#**: .NET template support
- **Kotlin**: JVM-based templates
- **Swift**: macOS/iOS template support
- **Lua**: Lightweight scripting support

---

## Conclusion

The CERT-X-GEN template engine architecture provides unprecedented flexibility in security scanning template development. By supporting 12 programming languages, developers can choose the most appropriate tool for their specific use case while maintaining a unified interface and communication protocol.

The modular design ensures maintainability, the compilation caching system optimizes performance, and the comprehensive error handling provides reliability. This architecture positions CERT-X-GEN as the most flexible and powerful polyglot security scanning framework available.