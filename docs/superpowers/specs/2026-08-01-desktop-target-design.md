# Desktop apps as a cxg pentest target type

**Status:** design approved, not implemented
**Date:** 2026-08-01
**Scope:** Electron and CEF desktop applications

## Context

`cxg pentest` today tests exactly one kind of target: an authenticated web
application reachable over HTTP. Every probe runs as JavaScript inside a
Playwright-driven Chromium context, seeded by guardlink hypotheses read from
the application's source tree.

That pipeline has capabilities worth preserving. Source-derived hypotheses mean
probes are written against the actual route handler rather than a generic
payload list. Multiple simultaneous authenticated identities make cross-identity
IDOR and privilege-escalation testing real rather than theoretical. A
deterministic triage layer separates confirmed findings from refuted ones and
from ambiguity the AI cannot resolve by retrying. Scope enforcement and a
per-request audit log make runs defensible to a client.

Desktop applications are currently untestable. Electron and CEF apps are the
highest-value gap: they are Chromium underneath, so most of the existing
machinery can be reused, and they carry an attack surface — IPC channels,
preload bridges, protocol handlers, local credential storage — that no web
scanner reaches.

The goal is to support them without forking the pipeline. A second engine
running beside the first would duplicate the bridge, the run loop, the
mutation and retry logic, and the health monitor, and the two copies would
drift within a release or two.

## Decisions

Settled during design; recorded so implementation does not relitigate them.

| Decision | Rationale |
|---|---|
| Electron in v1; Tauri deferred | Tauri is WKWebView on macOS and WebKitGTK on Linux — no CDP. Only WebView2 on Windows is Chromium. A WebKit-inspector substrate is a later addition the seam accommodates. |
| CEF apps are partially covered, not a claimed target | A CEF app exposing CDP connects through the same substrate, so renderer and HTTP probe classes work. IPC and configuration checks are Electron-specific (`ipcMain`, `contextBridge`, `webPreferences`) and will find nothing. `--target-type` therefore offers `web` and `electron` only; no `cef` value that would overpromise. |
| Multi-identity via N isolated app instances | Preserves every existing probe class, including cross-identity IDOR and privilege escalation. |
| `--codebase` stays the source tree | Consistent with cxg's whitebox identity. No asar unpacking; extracted bundles are usually minified, which degrades hypothesis quality. |
| `--target` stays required, meaning the backend HTTP origin | Still drives scope enforcement and every existing HTTP probe class. An `app://local` sentinel was considered and rejected as a new concept serving a rare case. |
| Host probes read only cxg-created directories by default | Containment is structural rather than a promise. Those directories are populated by a genuine interactive login, so they are equally representative. |
| No outbound traffic to the update feed | Fetching a third-party host while authorized to test a different target is a scope violation waiting to happen. The config value alone is sufficient evidence. |

## Architecture

One new concept: a **substrate**, which hands the engine N authenticated,
bridge-equipped surfaces. `js_engine` stops knowing what a browser is.

```
pentest/
  targets/
    __init__.py        # registry: "web" | "electron" -> Substrate
    base.py            # Substrate protocol, Surface dataclass
    bridge.py          # base cxg bridge, moved verbatim from js_engine
    web.py             # today's chromium.launch() + storage_state
    electron.py        # N instances, isolated user-data-dirs, connect_over_cdp
  electron_surface.py  # source scan -> Hypothesis (IPC channels, config claims)
  host_probes.py       # page-less checks: data at rest, update channel
```

### The seam

```python
@dataclass
class Surface:
    """One authenticated execution surface the engine runs templates in."""
    page: Page                      # bridge already installed
    context: BrowserContext
    profile: AuthProfile
    index: int
    capabilities: frozenset[str]    # {"http"} | {"http", "ipc", "host_fs"}

@dataclass
class Liveness:
    alive: bool
    reason: str

class Substrate(Protocol):
    name: str                                              # "web" | "electron"
    async def open(self, profiles, *, headless, scope, audit) -> list[Surface]
    async def verify(self, surface) -> Liveness
    async def close(self) -> None
    def describe(self) -> dict                             # into report metadata
```

`JsEngine.run()` currently launches Chromium, builds contexts, injects the
bridge, then loops templates. The refactor splits that in half: the substrate
owns everything up to "here are N live surfaces"; the engine owns everything
after. The template loop, health monitor, mutation and retry logic, triage,
audit and report code are not modified.

`capabilities` generalizes the existing `requires_auth_count` gate. A template
declares `// @requires_capability: ipc`; the engine skips it with a logged
reason when the substrate cannot provide it, reusing the skip path at
`js_engine.py:631`.

### Auth profiles for desktop

Electron keeps its session inside its `userData` directory, so a desktop auth
profile is a persistent user-data-dir rather than a `storage_state` JSON.

- `AuthProfile` gains `kind: "storage_state" | "user_data_dir"` and a
  `user_data_dir` path.
- Desktop profiles live at `~/.cert-x-gen/auth/desktop/<name>/`.
- `auth.py` gains `capture_desktop_multi()`: launch instance, operator logs in,
  ENTER, the directory is the artifact.
- `profile_inspect.py`'s landing test navigates to `--target` and looks for a
  login redirect, which cannot work for a desktop renderer. Liveness therefore
  sits on `Substrate.verify()`.

### Bridge composition

`js_engine._inject_cxg_bridge` (lines 170–374) moves to `targets/bridge.py`
verbatim. `web.py` installs the base; `electron.py` installs base plus one
namespace. Composition, not conditionals.

```js
await cxg.ipc.invoke(channel, ...args)        // this identity
await cxg.ipc.invokeAs(idx, channel, ...args) // another identity
cxg.ipc.channels()                            // channels discovered from source
```

`invokeAs` is the desktop IDOR primitive: instance A asks the app for an object
belonging to instance B. It flows into the existing `idor` vuln_class and the
existing triage.

Every IPC call routes through the existing guards, calling
`__cxg_scope_check("IPC", "ipc://<channel>")` and `__cxg_audit(...)` exactly as
`fetch` does. `ScopeGuard.check_request(method, path)` (`scope.py:96`) and
`AuditLog.request(...)` (`scope.py:179`) are pure string operations with no
HTTP-specific logic, so IPC calls consume the per-endpoint budget, respect
`scope.yaml` blocklists, and appear in `audit.jsonl` alongside HTTP requests.
No parallel accounting.

**Execution order for `invoke` is a security decision, not a fallback chain:**

1. Through the app's own `contextBridge` surface, when the preload exposes one.
   This is the realistic attacker path — what a compromised renderer or an XSS
   actually has. Most faithful evidence.
2. `require('electron').ipcRenderer` directly, only when contextIsolation is off
   or nodeIntegration is on — which is itself a finding.
3. Unreachable: the finding is `refuted` with reason "channel not reachable from
   renderer". Failure to exploit is the mitigation verification, landing in the
   existing `mitigation_verifications` bucket with no new machinery.

## Hypothesis extraction

New module `pentest/electron_surface.py`, exporting:

```python
def extract(codebase: Path) -> list[Hypothesis]
```

It imports `Hypothesis` from `guardlink.py` rather than redefining it, and
requires no schema change — `http_method` and `http_path` are already
`Optional[str]`. It is a separate module because `guardlink.py`'s job is parsing
guardlink SARIF and inline annotations; this is source scanning. Different job,
same output type.

`cxg_pentest.py` concatenates:

```python
hyps = sarif + inline_enriched
if substrate == "electron":
    hyps += electron_surface.extract(cb)
```

Two kinds of hypothesis, deliberately kept apart:

**Reachable entry points** — `http_method="IPC"`, `http_path="ipc://<channel>"`.
Scraped from `ipcMain.handle` / `ipcMain.on`, cross-referenced with
`contextBridge.exposeInMainWorld` to determine which channels the renderer can
actually reach and under what name. These behave exactly like routes: grouped by
class, handed to `js_generator`, probed with hostile arguments.

**Configuration claims** — `http_method="CONFIG"`,
`http_path="config://webPreferences.nodeIntegration"`. From `new BrowserWindow`,
`registerSchemesAsPrivileged`, `setWindowOpenHandler` / `will-navigate`
presence, `shell.openExternal` call sites, `autoUpdater.setFeedURL`.

Configuration claims must **not** reach the AI template generator. Asking a
model to write `cxg.fetch` calls for "nodeIntegration is true" produces exactly
the plausible-but-wrong findings the triage layer exists to kill. They route
instead to deterministic built-in checks that confirm the claim from inside the
running renderer: `typeof require === 'function'` proves nodeIntegration;
prototype reachability proves contextIsolation is off; a cross-origin read
attempt proves webSecurity is disabled.

Source produces the hypothesis; runtime produces the proof. A config claim not
reproducible at runtime lands as `refuted`, not `confirmed`.

## Host probes

`pentest/host_probes.py`. Python, no page, no identity, no bridge. Gated on the
substrate advertising `host_fs`, so the web path never invokes it.

Default scan scope is the isolated user-data-dirs cxg created itself.
`--host-scan-path` is required to read a real install.

| Check | Evidence |
|---|---|
| Session tokens or auth cookies stored plaintext rather than via `safeStorage` | matched bytes in `Cookies`, `Local Storage/leveldb`, `electron-store` JSON |
| Secrets in `userData/logs/*` | matched line, redacted |
| userData directory permissions not `0700` | `stat` mode |
| `autoUpdater` feed over `http://`, or provider configured without signature verification | config value from `app-update.yml` or main-process source |

Findings use `endpoint="file:///…"` and method `FS`. `Finding` needs no schema
change. Entries land in `audit.jsonl` beside HTTP and IPC calls.

Placement: after surfaces are open and verified, so the directories are
populated post-login. Results merge into `results.confirmed_findings` — one
report, one triage path, one audit stream.

## CLI surface

`cxg pentest run` gains four flags:

| Flag | Meaning |
|---|---|
| `--target-type <web\|electron>` | Default `web`. Selects the substrate. |
| `--app-cmd <string>` | Launch command, e.g. `"npm run electron:dev"` |
| `--app-binary <path>` | Or a built app, e.g. `/Applications/Foo.app` |
| `--host-scan-path <path>` | Opt in to scanning a real install directory |

`--app-cmd` and `--app-binary` are mutually exclusive; one is required when
`--target-type electron`. Enforced in clap via `conflicts_with` and
`required_if_eq` so failures are immediate and match the error style operators
already see.

`cxg pentest auth` takes the same `--target-type` / `--app-cmd` / `--app-binary`
and routes to `capture_desktop_multi()`. `--auth-numbers 2` keeps its exact
current meaning; it produces two user-data-dirs instead of two `storage_state`
files.

```bash
cxg pentest auth --target-type electron --app-cmd "npm run electron:dev" \
  --profile desktop --auth-numbers 2

cxg pentest run --target-type electron --app-cmd "npm run electron:dev" \
  --codebase ./app-repo --target https://api.example.com \
  --auth desktop-1,desktop-2 --ai
```

`src/cli.rs` gains the four fields in the existing doc-comment-plus-examples
style (`cli.rs:359-544`); `src/main.rs::run_pentest_command` forwards them using
the existing `args.push` pattern. No changes are needed to `pentest_install` —
both `copy_dir_recursive` and `extract_embedded_dir` are fully recursive, so the
new `targets/` subpackage ships automatically.

Per repository convention, every new or changed Rust and Python item carries a
`@g.comment`. The substrate launch path, which spawns an operator-supplied
command, additionally carries `@g.source` and `@g.sink` annotations, as it is a
genuine trust boundary.

## Error handling

**Single-instance lock is the expected failure.** Many Electron apps call
`app.requestSingleInstanceLock()`, so launch #2 exits immediately and focuses
#1, silently destroying the N-identity model.

Detection: if the second process exits within the 90s boot window, or no new CDP
target appears within it, the substrate returns fewer surfaces than requested
and logs why. Templates needing two identities then hit the existing
`need > len(contexts)` skip at `js_engine.py:631`. They are **skipped, never
refuted** — a refutation would be a false negative claiming the app is safe from
IDOR when it merely could not be tested. This matches
`mutator._ENV_BOUND_SIGNALS`, which already treats "only one identity" as
environment-bound and un-retryable.

| Failure | Behaviour |
|---|---|
| CDP connect fails or port not honoured | Hard error, non-zero exit. No silent fallback to the web substrate: a report that looks like a desktop pentest but is not is worse than no report. |
| App slow to boot | Poll for a CDP page target, 90s limit, then error naming the app command and port |
| Renderer navigates, bridge lost | Already handled by `_reinstall_bridge_if_needed` (`js_engine.py:382`) |
| Crash, Ctrl-C, or `HardKillSignal` | `Substrate.close()` in a `finally`; instances spawned in their own process group and killed as a group. PIDs written to the session directory for manual cleanup. |

Orphaned Electron processes are the one genuinely new operational hazard this
feature introduces, so process-group teardown is a requirement.

## Testing

**Step 0 is a de-risking spike, before any refactor.** The design rests on one
unverified assumption: that `connect_over_cdp` plus `expose_function` plus
`add_init_script` work against a real Electron renderer. Nothing else is built
until a throwaway script proves it. If it fails, the substrate seam survives but
`electron.py` implements the bridge over raw CDP instead.

Pure unit tests, no app required:

- `electron_surface.extract()` against fixture source trees — IPC channels,
  `contextBridge` cross-reference, `webPreferences` config claims
- `validator.py` new rules — `@requires_capability`, raw-`ipcRenderer` ban
- `host_probes` against a synthetic userData directory with a planted token and
  `0777` permissions
- Rust clap arg-shape tests alongside existing `#[cfg(test)]` modules

One integration fixture: a deliberately vulnerable minimal Electron app at
`pentest/tests/fixtures/vuln-electron/` with `nodeIntegration: true`, an
unvalidated `ipcMain.handle('file:read')`, and a plaintext token in userData.
An end-to-end run must confirm traversal, nodeIntegration, and the at-rest
token.

The same fixture contains a **properly guarded channel as a control** — one that
validates `event.senderFrame` and rejects traversal. The run must refute it.
Without a control, an integration test proves only that the tool finds things;
it cannot prove the tool does not hallucinate, which is the failure mode the
triage layer exists to prevent.

## Out of scope

- Tauri on macOS and Linux (no CDP; needs a WebKit-inspector substrate)
- Native thick clients with no embedded webview (needs a proxy substrate)
- asar extraction from packaged builds
- Outbound verification of update feeds
- Attaching to an already-running app instance

## Validation

1. Spike passes: a Playwright script connects over CDP to an Electron app,
   installs a binding, and evaluates it in the renderer.
2. `cargo test` and the Python unit suite pass.
3. Against `vuln-electron`: traversal, nodeIntegration, and at-rest token are
   confirmed; the guarded control channel is refuted.
4. An existing web-target run produces the same findings as before the refactor,
   proving the seam changed structure and not behaviour.
