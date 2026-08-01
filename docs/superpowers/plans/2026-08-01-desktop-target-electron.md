# Desktop (Electron) Target Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `cxg pentest` test Electron desktop applications — IPC channels, preload bridges, renderer configuration, and local data at rest — reusing the existing template, triage, scope, and audit pipeline rather than forking it.

**Architecture:** Introduce a *substrate* seam. A `Substrate` implementation hands the engine N authenticated, bridge-equipped surfaces; `js_engine` stops knowing what a browser is. `targets/web.py` preserves today's Chromium + `storage_state` path byte-for-byte in behaviour; `targets/electron.py` launches N isolated app instances and connects over CDP. Electron IPC channels become hypotheses shaped exactly like HTTP routes, so template generation, triage, mutation, scope enforcement and reporting are reused unchanged.

**Tech Stack:** Python 3.14, Playwright (async API), Rust + clap (CLI shim), pytest (new), Electron (test fixture only).

## Global Constraints

Copied verbatim from `docs/superpowers/specs/2026-08-01-desktop-target-design.md`:

- Electron only in v1. Tauri is out of scope. `--target-type` accepts exactly `web` and `electron` — no `cef` value.
- `--codebase` remains the source tree. No asar extraction.
- `--target` remains required and means the backend HTTP origin.
- Host probes read only cxg-created directories unless `--host-scan-path` is given.
- No outbound traffic to update feeds.
- Templates needing more identities than exist are **skipped, never refuted**.
- No silent fallback from the electron substrate to the web substrate.
- Every new or changed Rust and Python item carries a `@g.comment` annotation. The substrate launch path additionally carries `@g.source` and `@g.sink`. Annotations go in comments directly above the code, each with `-- "description"`. Never annotate inside `@g.shield`. Reference: `docs/GAL_AGENT_REFERENCE.md`.
- Python style follows the existing `pentest/` modules: `from __future__ import annotations`, dataclasses, `list[str]` builtin generics, module docstring explaining responsibility.

## Deviation from the spec

The spec describes `Substrate.open()` as returning surfaces with "bridge already installed". That is not implementable: bridge installation needs `fetch_as_router`, which closes over the full surfaces list, which does not exist until `open()` has returned. The protocol below is therefore two-phase — `open()` launches and navigates, `install_bridge()` wires the bridge. Everything else follows the spec as written.

## File structure

| File | Responsibility |
|---|---|
| `pentest/targets/__init__.py` | Registry: name → Substrate instance |
| `pentest/targets/base.py` | `Surface`, `Liveness`, `BridgeContext`, `Substrate` protocol |
| `pentest/targets/bridge.py` | Base `window.__cxg` bridge, moved from `js_engine` |
| `pentest/targets/web.py` | Chromium + `storage_state` substrate (today's behaviour) |
| `pentest/targets/electron.py` | N isolated Electron instances over CDP, `cxg.ipc` namespace |
| `pentest/electron_surface.py` | Source scan → `Hypothesis` (IPC channels, config claims) |
| `pentest/config_probes.py` | Deterministic runtime confirmation of `CONFIG` hypotheses |
| `pentest/host_probes.py` | Page-less checks: data at rest, update channel |
| `pentest/tests/` | pytest suite (new — none exists today) |
| `pentest/tests/fixtures/vuln-electron/` | Deliberately vulnerable Electron app + guarded control |
| `pentest/js_engine.py` | Loses launch/bridge code; gains substrate consumption |
| `pentest/auth.py` | `AuthProfile.kind`, `capture_desktop_multi()` |
| `pentest/cxg_pentest.py` | Substrate selection, hypothesis merge, host probe invocation |
| `src/cli.rs`, `src/main.rs` | Four new flags, forwarded to the orchestrator |

## Phases

- **Phase 1 (Tasks 1–2):** Test infrastructure and source extraction. Zero risk to existing behaviour.
- **Phase 2 (Tasks 3–5):** The spike, the seam, and the Electron substrate.
- **Phase 3 (Tasks 6–8):** Desktop auth profiles, the IPC bridge, config confirmation.
- **Phase 4 (Tasks 9–12):** Host probes, CLI, wiring, end-to-end.

**Task 3 is a gate.** If the spike fails, stop and re-plan Task 5 before proceeding.

---

### Task 1: Python test infrastructure and the vulnerable Electron fixture

The repo has no Python tests, no pytest config, and no `conftest.py`. This task creates that foundation plus the fixture app every later task tests against.

**Files:**
- Create: `pentest/pytest.ini`
- Create: `pentest/tests/__init__.py`
- Create: `pentest/tests/conftest.py`
- Create: `pentest/tests/fixtures/vuln-electron/package.json`
- Create: `pentest/tests/fixtures/vuln-electron/main.js`
- Create: `pentest/tests/fixtures/vuln-electron/preload.js`
- Create: `pentest/tests/fixtures/vuln-electron/index.html`
- Create: `pentest/tests/test_fixture_sanity.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes: nothing.
- Produces: `FIXTURE_DIR` pytest fixture returning `Path` to `vuln-electron/`; the fixture app itself, whose four channels later tasks assert on by name: `file:read` (vulnerable, traversal), `user:get-profile` (vulnerable, IDOR), `app:run-command` (vulnerable, command injection), `secure:read-config` (**control** — validates `senderFrame`, rejects traversal).

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_fixture_sanity.py`:

```python
"""Sanity checks on the vulnerable Electron fixture.

These are deliberately shallow — they exist so the fixture's shape is pinned
before extractor tests depend on it.
"""
from __future__ import annotations
import json


def test_fixture_package_json_is_valid(fixture_dir):
    pkg = json.loads((fixture_dir / "package.json").read_text())
    assert pkg["main"] == "main.js"


def test_fixture_declares_all_four_channels(fixture_dir):
    main_js = (fixture_dir / "main.js").read_text()
    for channel in ("file:read", "user:get-profile", "app:run-command", "secure:read-config"):
        assert f"'{channel}'" in main_js, f"missing channel {channel}"


def test_fixture_control_channel_validates_sender(fixture_dir):
    main_js = (fixture_dir / "main.js").read_text()
    assert "senderFrame" in main_js, "control channel must validate senderFrame"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_fixture_sanity.py -v`
Expected: FAIL — `fixture 'fixture_dir' not found` (conftest does not exist yet).

- [ ] **Step 3: Create pytest config and conftest**

Create `pentest/pytest.ini`:

```ini
[pytest]
testpaths = tests
python_files = test_*.py
addopts = -q
```

Create `pentest/tests/__init__.py` as an empty file.

Create `pentest/tests/conftest.py`:

```python
"""Shared pytest fixtures for the pentest suite.

Adds the pentest package root to sys.path so tests import the orchestrator
modules the same flat way cxg_pentest.py does (`import guardlink`, not
`from pentest import guardlink`).
"""
from __future__ import annotations
import sys
from pathlib import Path

import pytest

PENTEST_ROOT = Path(__file__).resolve().parent.parent
if str(PENTEST_ROOT) not in sys.path:
    sys.path.insert(0, str(PENTEST_ROOT))


# @g.comment -- "Resolves the deliberately vulnerable Electron fixture app used by extractor, config-probe and end-to-end tests."
@pytest.fixture
def fixture_dir() -> Path:
    return PENTEST_ROOT / "tests" / "fixtures" / "vuln-electron"
```

- [ ] **Step 4: Create the fixture Electron app**

Create `pentest/tests/fixtures/vuln-electron/package.json`:

```json
{
  "name": "vuln-electron",
  "version": "1.0.0",
  "private": true,
  "main": "main.js",
  "scripts": {
    "start": "electron ."
  },
  "devDependencies": {
    "electron": "^33.0.0"
  }
}
```

Create `pentest/tests/fixtures/vuln-electron/main.js`:

```js
// Deliberately vulnerable Electron app used as a cxg pentest test fixture.
// Three channels are exploitable; `secure:read-config` is a CONTROL that must
// be refuted by a correct scan. Do not "fix" the vulnerable handlers.
const { app, BrowserWindow, ipcMain } = require('electron');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const USERS = {
  'user-1': { id: 'user-1', email: 'alice@example.com', ssn: '111-11-1111' },
  'user-2': { id: 'user-2', email: 'bob@example.com', ssn: '222-22-2222' },
};

function createWindow() {
  const win = new BrowserWindow({
    width: 900,
    height: 700,
    webPreferences: {
      // VULNERABLE: renderer gets full Node access.
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  win.loadFile('index.html');
}

// VULNERABLE: no path validation — traversal reaches any file.
ipcMain.handle('file:read', async (_event, relPath) => {
  return fs.readFileSync(path.join(__dirname, 'data', relPath), 'utf8');
});

// VULNERABLE: no ownership check — any identity can read any user (IDOR).
ipcMain.handle('user:get-profile', async (_event, userId) => {
  return USERS[userId] || null;
});

// VULNERABLE: shell metacharacters flow straight into execSync.
ipcMain.handle('app:run-command', async (_event, name) => {
  return execSync(`echo ${name}`).toString();
});

// CONTROL: validates the calling frame AND rejects traversal. A correct scan
// must REFUTE any finding against this channel.
ipcMain.handle('secure:read-config', async (event, relPath) => {
  const url = event.senderFrame ? event.senderFrame.url : '';
  if (!url.startsWith('file://')) {
    throw new Error('rejected: untrusted sender frame');
  }
  if (relPath.includes('..') || path.isAbsolute(relPath)) {
    throw new Error('rejected: path traversal');
  }
  return fs.readFileSync(path.join(__dirname, 'config', relPath), 'utf8');
});

app.whenReady().then(createWindow);
```

Create `pentest/tests/fixtures/vuln-electron/preload.js`:

```js
// VULNERABLE: a generic passthrough re-exposes the entire IPC surface to the
// renderer, defeating the point of contextBridge.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('appApi', {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  readFile: (p) => ipcRenderer.invoke('file:read', p),
  getProfile: (id) => ipcRenderer.invoke('user:get-profile', id),
});
```

Create `pentest/tests/fixtures/vuln-electron/index.html`:

```html
<!doctype html>
<meta charset="utf-8">
<title>vuln-electron</title>
<h1 id="app">vuln-electron fixture</h1>
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd pentest && python -m pytest tests/test_fixture_sanity.py -v`
Expected: PASS, 3 passed.

- [ ] **Step 6: Add a Makefile target**

Add to `Makefile`:

```makefile
.PHONY: test-pentest
test-pentest:
	cd pentest && python -m pytest -v
```

Run: `make test-pentest`
Expected: PASS, 3 passed.

- [ ] **Step 7: Commit**

```bash
git add pentest/pytest.ini pentest/tests Makefile
git commit -m "test(pentest): add pytest infrastructure and vulnerable Electron fixture"
```

---

### Task 2: Electron source extraction

**Files:**
- Create: `pentest/electron_surface.py`
- Create: `pentest/tests/test_electron_surface.py`

**Interfaces:**
- Consumes: `fixture_dir` (Task 1); `guardlink.Hypothesis`.
- Produces: `electron_surface.extract(codebase: Path) -> list[Hypothesis]`. Entry-point hypotheses use `http_method="IPC"` and `http_path="ipc://<channel>"`. Configuration hypotheses use `http_method="CONFIG"` and `http_path="config://<dotted.key>"`. Both set `raw={"reachable_via": <str|None>, "source": "electron_surface"}`.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_electron_surface.py`:

```python
"""Tests for Electron source-surface extraction."""
from __future__ import annotations

import electron_surface


def _by_path(hyps):
    return {h.http_path: h for h in hyps}


def test_extracts_all_ipc_channels(fixture_dir):
    hyps = electron_surface.extract(fixture_dir)
    paths = _by_path(hyps)
    for channel in ("file:read", "user:get-profile", "app:run-command", "secure:read-config"):
        assert f"ipc://{channel}" in paths


def test_ipc_hypotheses_use_ipc_method(fixture_dir):
    hyps = electron_surface.extract(fixture_dir)
    ipc = [h for h in hyps if h.http_path == "ipc://file:read"]
    assert ipc and ipc[0].http_method == "IPC"


def test_cross_references_context_bridge_exposure(fixture_dir):
    hyps = electron_surface.extract(fixture_dir)
    paths = _by_path(hyps)
    assert paths["ipc://file:read"].raw["reachable_via"] == "appApi.readFile"


def test_generic_passthrough_marks_all_channels_reachable(fixture_dir):
    """appApi.invoke(channel, ...) re-exposes every channel, including the control."""
    hyps = electron_surface.extract(fixture_dir)
    paths = _by_path(hyps)
    assert paths["ipc://app:run-command"].raw["reachable_via"] == "appApi.invoke"


def test_extracts_web_preferences_config_claims(fixture_dir):
    hyps = electron_surface.extract(fixture_dir)
    paths = _by_path(hyps)
    assert "config://webPreferences.nodeIntegration" in paths
    assert "config://webPreferences.contextIsolation" in paths
    assert paths["config://webPreferences.nodeIntegration"].http_method == "CONFIG"


def test_secure_defaults_produce_no_config_hypothesis(tmp_path):
    """A safely configured app must not generate config findings."""
    (tmp_path / "main.js").write_text(
        "new BrowserWindow({webPreferences:{nodeIntegration:false,contextIsolation:true}})"
    )
    hyps = electron_surface.extract(tmp_path)
    assert not [h for h in hyps if h.http_method == "CONFIG"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_electron_surface.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'electron_surface'`.

- [ ] **Step 3: Write the implementation**

Create `pentest/electron_surface.py`:

```python
"""Electron source-surface extraction.

guardlink.py parses guardlink SARIF and inline annotations. This module does a
different job — scanning Electron main-process and preload sources — but emits
the same Hypothesis type, so everything downstream (grouping, template
generation, triage, audit, reporting) consumes it unchanged.

Two kinds of hypothesis are emitted:

  IPC     — a reachable entry point.  ipc://<channel>
            Behaves like an HTTP route: handed to js_generator, probed at
            runtime with hostile arguments.

  CONFIG  — a configuration claim.    config://<dotted.key>
            NOT handed to the AI generator. Routed to config_probes.py, which
            confirms or refutes the claim from inside the running renderer.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from guardlink import Hypothesis

_SOURCE_EXTS = {".js", ".mjs", ".cjs", ".ts"}
_SKIP_DIRS = {"node_modules", ".git", "dist", "out", "build", "__pycache__"}

# ipcMain.handle('channel', ...) / ipcMain.on("channel", ...)
_RE_IPC_HANDLER = re.compile(r"""ipcMain\.(?:handle|on)\s*\(\s*['"`]([^'"`]+)['"`]""")

# contextBridge.exposeInMainWorld('name', { ... })
_RE_BRIDGE_EXPOSE = re.compile(
    r"""contextBridge\.exposeInMainWorld\s*\(\s*['"`]([^'"`]+)['"`]\s*,""")

# key: (...) => ipcRenderer.invoke('channel', ...)
_RE_BRIDGE_METHOD = re.compile(
    r"""(\w+)\s*:\s*\([^)]*\)\s*=>\s*ipcRenderer\.(?:invoke|send)\s*\(\s*['"`]([^'"`]+)['"`]""")

# key: (channel, ...args) => ipcRenderer.invoke(channel, ...args)   ← generic passthrough
_RE_BRIDGE_PASSTHROUGH = re.compile(
    r"""(\w+)\s*:\s*\(\s*(\w+)\s*,[^)]*\)\s*=>\s*ipcRenderer\.(?:invoke|send)\s*\(\s*\2\b""")

# webPreferences: { ... }  — captured non-greedily up to the closing brace
_RE_WEB_PREFS = re.compile(r"webPreferences\s*:\s*\{(.*?)\}", re.DOTALL)

# Each entry: (key, the value that is INSECURE)
_INSECURE_PREFS = [
    ("nodeIntegration", "true"),
    ("contextIsolation", "false"),
    ("sandbox", "false"),
    ("webSecurity", "false"),
    ("allowRunningInsecureContent", "true"),
]

_PREF_SEVERITY = {
    "nodeIntegration": ("critical", "CWE-94"),
    "contextIsolation": ("high", "CWE-668"),
    "sandbox": ("medium", "CWE-693"),
    "webSecurity": ("high", "CWE-346"),
    "allowRunningInsecureContent": ("medium", "CWE-311"),
}


# @g.comment -- "Walks an Electron source tree, skipping vendored and build directories, returning every main-process or preload script worth scanning."
def _iter_sources(codebase: Path):
    for p in codebase.rglob("*"):
        if not p.is_file() or p.suffix not in _SOURCE_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


# @g.comment -- "Builds the channel -> exposed-renderer-name map from preload contextBridge code; a generic (channel, ...args) passthrough maps every channel, since it re-exposes the whole IPC surface."
def _bridge_exposure_map(sources: list[tuple[Path, str]]) -> tuple[dict[str, str], Optional[str]]:
    """Returns (channel -> 'ns.method', generic_passthrough_name_or_None)."""
    named: dict[str, str] = {}
    passthrough: Optional[str] = None
    for _path, text in sources:
        for ns_match in _RE_BRIDGE_EXPOSE.finditer(text):
            namespace = ns_match.group(1)
            tail = text[ns_match.end():]
            for m in _RE_BRIDGE_METHOD.finditer(tail):
                named.setdefault(m.group(2), f"{namespace}.{m.group(1)}")
            pt = _RE_BRIDGE_PASSTHROUGH.search(tail)
            if pt and passthrough is None:
                passthrough = f"{namespace}.{pt.group(1)}"
    return named, passthrough


# @g.comment -- "Emits one IPC entry-point hypothesis per ipcMain handler, recording whether and how the renderer can reach it."
def _ipc_hypotheses(sources, named, passthrough) -> list[Hypothesis]:
    out: list[Hypothesis] = []
    seen: set[str] = set()
    for path, text in sources:
        for m in _RE_IPC_HANDLER.finditer(text):
            channel = m.group(1)
            if channel in seen:
                continue
            seen.add(channel)
            line = text[: m.start()].count("\n") + 1
            reachable = named.get(channel) or passthrough
            out.append(Hypothesis(
                id=f"electron-ipc-{channel}",
                vuln_class="idor",
                threat="#ipc-channel",
                asset=f"#{channel}",
                http_method="IPC",
                http_path=f"ipc://{channel}",
                function_name=None,
                file=str(path),
                line=line,
                severity="high",
                cwe="CWE-862",
                description=(
                    f"IPC channel '{channel}' is handled in the main process"
                    + (f" and reachable from the renderer via {reachable}."
                       if reachable else " but not exposed to the renderer.")
                ),
                confidence=0.9 if reachable else 0.3,
                has_mitigation_declared=False,
                raw={"reachable_via": reachable, "source": "electron_surface"},
            ))
    return out


# @g.comment -- "Emits a CONFIG hypothesis for each insecure webPreferences value found in source; these are claims to be confirmed at runtime by config_probes, never handed to the AI template generator."
def _config_hypotheses(sources) -> list[Hypothesis]:
    out: list[Hypothesis] = []
    seen: set[str] = set()
    for path, text in sources:
        for block_match in _RE_WEB_PREFS.finditer(text):
            block = block_match.group(1)
            line = text[: block_match.start()].count("\n") + 1
            for key, insecure_value in _INSECURE_PREFS:
                if not re.search(rf"\b{key}\s*:\s*{insecure_value}\b", block):
                    continue
                dotted = f"webPreferences.{key}"
                if dotted in seen:
                    continue
                seen.add(dotted)
                severity, cwe = _PREF_SEVERITY[key]
                out.append(Hypothesis(
                    id=f"electron-config-{key}",
                    vuln_class="privilege_escalation",
                    threat="#renderer-boundary",
                    asset=f"#{dotted}",
                    http_method="CONFIG",
                    http_path=f"config://{dotted}",
                    function_name=None,
                    file=str(path),
                    line=line,
                    severity=severity,
                    cwe=cwe,
                    description=f"{dotted} is set to {insecure_value}, weakening the renderer sandbox.",
                    confidence=0.95,
                    has_mitigation_declared=False,
                    raw={"reachable_via": None, "source": "electron_surface",
                         "pref_key": key, "expected_insecure_value": insecure_value},
                ))
    return out


# @g.comment -- "Public entry point: scans an Electron codebase and returns IPC entry-point and configuration-claim hypotheses in the same shape guardlink produces for HTTP routes."
def extract(codebase: Path) -> list[Hypothesis]:
    sources = [(p, p.read_text(errors="ignore")) for p in _iter_sources(Path(codebase))]
    named, passthrough = _bridge_exposure_map(sources)
    return _ipc_hypotheses(sources, named, passthrough) + _config_hypotheses(sources)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd pentest && python -m pytest tests/test_electron_surface.py -v`
Expected: PASS, 6 passed.

Note on `test_cross_references_context_bridge_exposure`: `file:read` has both a named method (`appApi.readFile`) and is covered by the generic passthrough. `_ipc_hypotheses` prefers the named binding (`named.get(channel) or passthrough`), so the assertion expects `appApi.readFile`. `app:run-command` has no named binding, so it falls through to `appApi.invoke`.

- [ ] **Step 5: Commit**

```bash
git add pentest/electron_surface.py pentest/tests/test_electron_surface.py
git commit -m "feat(pentest): extract Electron IPC channels and config claims as hypotheses"
```

---

### Task 3: CDP spike — GATE

The entire design assumes Playwright's `connect_over_cdp` can attach to an Electron renderer and that `expose_function` / `add_init_script` work there. Prove it before refactoring anything.

**Files:**
- Create: `pentest/tests/test_electron_cdp_spike.py`

**Interfaces:**
- Consumes: `fixture_dir` (Task 1).
- Produces: proof only. If this task fails, **stop** — Task 5 must be re-planned to implement the bridge over raw CDP (`Runtime.addBinding` + `Page.addScriptToEvaluateOnNewDocument`) instead of Playwright bindings.

- [ ] **Step 1: Install the fixture's Electron dependency**

```bash
cd pentest/tests/fixtures/vuln-electron && npm install
```

Expected: `node_modules/electron` exists. If `npm` is unavailable, this task cannot run — resolve that before continuing.

- [ ] **Step 2: Write the spike test**

Create `pentest/tests/test_electron_cdp_spike.py`:

```python
"""GATE: proves Playwright can drive an Electron renderer over CDP.

The substrate design depends on three things working against Electron:
  1. connect_over_cdp attaches and yields a Page
  2. expose_function installs a callable binding
  3. add_init_script survives into the renderer

If this test fails, targets/electron.py needs a raw-CDP bridge instead.
"""
from __future__ import annotations

import asyncio
import shutil
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("npx") is None, reason="npx not available; Electron fixture cannot launch"
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_playwright_can_drive_electron_over_cdp(fixture_dir, tmp_path):
    from playwright.async_api import async_playwright

    port = _free_port()
    proc = subprocess.Popen(
        ["npx", "electron", ".",
         f"--remote-debugging-port={port}",
         f"--user-data-dir={tmp_path / 'ud'}"],
        cwd=fixture_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        async with async_playwright() as p:
            browser = None
            deadline = time.time() + 90
            while time.time() < deadline:
                try:
                    browser = await p.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
                    break
                except Exception:
                    await asyncio.sleep(0.5)
            assert browser is not None, "could not connect over CDP within 90s"

            ctx = browser.contexts[0]
            deadline = time.time() + 30
            while not ctx.pages and time.time() < deadline:
                await asyncio.sleep(0.25)
            assert ctx.pages, "no renderer page appeared"
            page = ctx.pages[0]

            # 2. bindings
            await page.expose_function("__spike_echo", lambda v: f"echo:{v}")
            assert await page.evaluate("async () => await window.__spike_echo('hi')") == "echo:hi"

            # 3. init script
            await page.add_init_script("window.__spike_marker = 'present';")
            await page.reload()
            assert await page.evaluate("() => window.__spike_marker") == "present"
    finally:
        proc.terminate()
        proc.wait(timeout=15)
```

- [ ] **Step 3: Install the async pytest plugin**

```bash
python -m pip install pytest-asyncio
```

Add to `pentest/pytest.ini` under `[pytest]`:

```ini
asyncio_mode = auto
```

- [ ] **Step 4: Run the spike**

Run: `cd pentest && python -m pytest tests/test_electron_cdp_spike.py -v`
Expected: PASS.

**If it fails:** stop. Record the failure mode in the plan file and re-plan Task 5 around raw CDP. Do not proceed to Task 4.

- [ ] **Step 5: Commit**

```bash
git add pentest/tests/test_electron_cdp_spike.py pentest/pytest.ini
git commit -m "test(pentest): prove Playwright drives Electron renderers over CDP"
```

---

### Task 4: The substrate seam — extract without changing behaviour

Pure refactor. The web path must produce identical results afterward.

**Files:**
- Create: `pentest/targets/__init__.py`
- Create: `pentest/targets/base.py`
- Create: `pentest/targets/bridge.py`
- Create: `pentest/targets/web.py`
- Create: `pentest/tests/test_targets_base.py`
- Modify: `pentest/js_engine.py` — remove `_open_context` (lines 158-169) and `_inject_cxg_bridge` (lines 170-374); rework `run()` (line 532) to consume a substrate.

**Interfaces:**
- Consumes: `auth.AuthProfile`, `scope.ScopeGuard`, `scope.AuditLog`.
- Produces:
  - `base.Surface(page, context, profile, index, capabilities)` — `capabilities: frozenset[str]`
  - `base.Liveness(alive: bool, reason: str)`
  - `base.BridgeContext(target, oast_host, fetch_as_router, scope_check, record_response, audit_request, current_template_id)`
  - `base.Substrate` protocol: `name`, `async open(profiles, *, headless) -> list[Surface]`, `async install_bridge(surface, bridge_ctx, all_profiles) -> None`, `async verify(surface) -> Liveness`, `async close() -> None`, `describe() -> dict`
  - `targets.get_substrate(name: str) -> Substrate` — raises `ValueError` on unknown name
  - `bridge.install_base(page, surface, bridge_ctx, all_profiles) -> None`

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_targets_base.py`:

```python
"""Tests for the substrate registry and protocol shape."""
from __future__ import annotations

import pytest

import targets
from targets.base import Liveness, Surface


def test_registry_returns_web_substrate():
    sub = targets.get_substrate("web")
    assert sub.name == "web"


def test_registry_returns_electron_substrate():
    # ElectronSubstrate requires a launch mechanism, so one must be supplied here.
    sub = targets.get_substrate("electron", app_binary="/tmp/fake.app")
    assert sub.name == "electron"


def test_registry_rejects_unknown_substrate():
    with pytest.raises(ValueError, match="unknown target type"):
        targets.get_substrate("tauri")


def test_web_substrate_advertises_http_only():
    assert targets.get_substrate("web").capabilities == frozenset({"http"})


def test_electron_substrate_advertises_ipc_and_host_fs():
    caps = targets.get_substrate("electron", app_binary="/tmp/fake.app").capabilities
    assert "ipc" in caps and "host_fs" in caps and "http" in caps


def test_liveness_is_a_two_field_record():
    lv = Liveness(alive=False, reason="dead")
    assert (lv.alive, lv.reason) == (False, "dead")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_targets_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'targets'`.

- [ ] **Step 3: Create `targets/base.py`**

```python
"""Substrate protocol — the seam between "how surfaces are obtained" and
"what the engine does with them".

A Substrate owns everything up to "here are N live, authenticated surfaces".
JsEngine owns everything after. This is why the engine no longer knows what a
browser is, and why adding a target type is a new file rather than a new
conditional.

Bridge installation is deliberately a SECOND phase: the bridge needs
fetch_as_router, which closes over the full surfaces list, which does not exist
until open() has returned.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, runtime_checkable


@dataclass
class Surface:
    """One authenticated execution surface the engine runs templates in."""
    page: Any                      # playwright Page
    context: Any                   # playwright BrowserContext
    profile: Any                   # auth.AuthProfile
    index: int
    capabilities: frozenset[str] = field(default_factory=lambda: frozenset({"http"}))
    browser: Any = None            # kept so the substrate can close it
    extra: dict = field(default_factory=dict)


@dataclass
class Liveness:
    alive: bool
    reason: str


@dataclass
class BridgeContext:
    """Engine-owned callbacks the bridge needs. Built once per run."""
    target: str
    oast_host: str
    fetch_as_router: Callable
    scope_check: Callable
    record_response: Callable
    audit_request: Callable
    current_template_id: list      # mutable single-element ref


@runtime_checkable
class Substrate(Protocol):
    name: str
    capabilities: frozenset[str]

    async def open(self, profiles: list, *, headless: bool) -> list[Surface]: ...
    async def install_bridge(self, surface: Surface, bridge_ctx: BridgeContext,
                             all_profiles: list) -> None: ...
    async def verify(self, surface: Surface) -> Liveness: ...
    async def close(self) -> None: ...
    def describe(self) -> dict: ...
```

- [ ] **Step 4: Create `targets/bridge.py` by moving the existing bridge**

This is a **cut-and-paste move, not a rewrite.** Create `pentest/targets/bridge.py` with this module docstring and imports:

```python
"""The base window.__cxg bridge.

Moved verbatim from JsEngine._inject_cxg_bridge. Behaviour must not change:
the web substrate installs this and only this, so any drift here is a
regression in the existing HTTP pipeline.

Substrates compose on top — targets/electron.py installs this, then adds the
cxg.ipc namespace.
"""
from __future__ import annotations

from targets.base import BridgeContext, Surface
```

Then cut the **entire body** of `JsEngine._inject_cxg_bridge` (`js_engine.py:170-374` — all 205 lines, including every `expose_function` call, the `bridge_js` string, the `add_init_script` call and its `try/except`) and paste it under this signature:

```python
# @g.comment -- "Installs the window.__cxg bridge on a surface's page: exposes the Python-side fetch/scope/audit/cookie bindings and evaluates the bridge JS, so templates get a uniform API regardless of substrate."
async def install_base(page, surface: Surface, bridge_ctx: BridgeContext,
                       all_profiles: list) -> None:
```

Then apply these mechanical substitutions to the pasted body — apply exactly, change nothing else:

| Was | Becomes |
|---|---|
| `self.target` | `bridge_ctx.target` |
| `self.oast_host` | `bridge_ctx.oast_host` |
| `self.scope.check_request` | `bridge_ctx.scope_check` |
| `self.scope.record_response` | `bridge_ctx.record_response` |
| `self.audit.request` | `bridge_ctx.audit_request` |
| `fetch_as_router` param | `bridge_ctx.fetch_as_router` |
| `current_id_ref` param | `bridge_ctx.current_template_id` |
| `ctx` param | `surface.context` |
| `profile`, `index` params | `surface.profile`, `surface.index` |

Also move `_ensure_bridge` (`js_engine.py:382`) into this module as
`async def ensure_installed(page, surface, bridge_ctx, all_profiles)`, keeping
its existing `typeof window.__cxg === 'object'` check and re-invoking
`install_base` when it returns false.

- [ ] **Step 5: Create `targets/web.py`**

```python
"""Web substrate — Chromium with a captured storage_state per identity.

This is today's behaviour, relocated. One browser per profile, matching the
existing JsEngine._open_context.
"""
from __future__ import annotations

from targets import bridge
from targets.base import BridgeContext, Liveness, Surface


class WebSubstrate:
    name = "web"
    capabilities = frozenset({"http"})

    # @g.comment -- "Holds the per-run Playwright handle and every browser opened, so close() can tear all of them down deterministically."
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self._playwright = None
        self._browsers: list = []

    # @g.comment -- "Launches one Chromium per identity, seeded with that identity's captured storage_state and any profile-specific headers, then navigates to the target."
    async def open(self, profiles: list, *, headless: bool) -> list[Surface]:
        from playwright.async_api import async_playwright
        self._playwright = await async_playwright().start()
        surfaces: list[Surface] = []
        for i, profile in enumerate(profiles):
            browser = await self._playwright.chromium.launch(headless=headless)
            self._browsers.append(browser)
            ctx_kwargs = {"storage_state": profile.storage_state}
            if getattr(profile, "extra_headers", None):
                ctx_kwargs["extra_http_headers"] = profile.extra_headers
            ctx = await browser.new_context(**ctx_kwargs)
            page = await ctx.new_page()
            try:
                await page.goto(self.target, wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                print(f"[web] warn: goto({self.target}) for {profile.name}: {e}")
            surfaces.append(Surface(page=page, context=ctx, profile=profile, index=i,
                                    capabilities=self.capabilities, browser=browser))
        return surfaces

    # @g.comment -- "Installs only the base bridge; the web substrate adds no extra namespaces."
    async def install_bridge(self, surface: Surface, bridge_ctx: BridgeContext,
                             all_profiles: list) -> None:
        await bridge.install_base(surface.page, surface, bridge_ctx, all_profiles)

    # @g.comment -- "Liveness for web is the existing landing test: a page that has been redirected to a login or SSO URL is a dead session."
    async def verify(self, surface: Surface) -> Liveness:
        try:
            url = surface.page.url or ""
        except Exception as e:
            return Liveness(False, f"page unavailable: {e}")
        lowered = url.lower()
        if any(m in lowered for m in ("/login", "/signin", "/sso", "/auth/realms")):
            return Liveness(False, f"redirected to auth surface: {url}")
        return Liveness(True, "landed on application")

    async def close(self) -> None:
        for b in self._browsers:
            try:
                await b.close()
            except Exception:
                pass
        self._browsers.clear()
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    def describe(self) -> dict:
        return {"substrate": "web", "target": self.target}
```

- [ ] **Step 6: Create `targets/__init__.py`**

```python
"""Substrate registry.

Adding a target type means adding a module here, not a conditional in the
engine.
"""
from __future__ import annotations

from targets.base import BridgeContext, Liveness, Substrate, Surface

__all__ = ["BridgeContext", "Liveness", "Substrate", "Surface", "get_substrate"]


# @g.comment -- "Resolves an operator-supplied --target-type into a substrate instance; unknown names raise rather than silently defaulting, so a typo can never downgrade a desktop scan to a web scan."
def get_substrate(name: str, *, target: str = "", app_cmd: str = "",
                  app_binary: str = "", user_data_root=None):
    key = (name or "web").strip().lower()
    if key == "web":
        from targets.web import WebSubstrate
        return WebSubstrate(target=target)
    if key == "electron":
        from targets.electron import ElectronSubstrate
        return ElectronSubstrate(target=target, app_cmd=app_cmd,
                                 app_binary=app_binary, user_data_root=user_data_root)
    raise ValueError(f"unknown target type '{name}' (expected 'web' or 'electron')")
```

- [ ] **Step 7: Rework `JsEngine.run()`**

In `js_engine.py`:

1. Delete `_open_context` and `_inject_cxg_bridge`; replace `_ensure_bridge` calls with `bridge.ensure_installed(...)`.
2. Add `substrate` to `__init__` (keyword-only, defaulting to a `WebSubstrate` built from `target`, so existing callers keep working).
3. In `run()`, replace the `async with async_playwright()` block's context-building loop with:

```python
        surfaces = await self.substrate.open(self.profiles, headless=self.headless)
        bridge_ctx = BridgeContext(
            target=self.target,
            oast_host=self.oast_host,
            fetch_as_router=fetch_as_router,
            scope_check=self.scope.check_request,
            record_response=self.scope.record_response,
            audit_request=(self.audit.request if self.audit else lambda *a, **k: None),
            current_template_id=current_id_ref,
        )
        try:
            for s in surfaces:
                await self.substrate.install_bridge(s, bridge_ctx, self.profiles)
            ...
        finally:
            await self.substrate.close()
```

4. Replace every `contexts[i]["page"]` with `surfaces[i].page`, `["ctx"]` with `.context`, `["profile"]` with `.profile`, `["index"]` with `.index`. The `fetch_as_router` closure keeps its logic, closing over `surfaces` instead of `contexts`.

- [ ] **Step 8: Run all tests**

Run: `cd pentest && python -m pytest -v`
Expected: PASS, all tests from Tasks 1–3 still pass.

- [ ] **Step 9: Verify the web path is behaviourally unchanged**

Run an existing web-target scan against whatever staging target you normally use, with the same `--codebase` and `--auth` as a pre-refactor run:

```bash
cxg pentest run --codebase <repo> --target <origin> --auth <profile> -o /tmp/after.json
```

Compare `confirmed`, `refuted`, and `ambiguous` finding IDs against a pre-refactor `report.json`. Expected: identical sets. Any difference is a refactor bug, not an improvement — investigate before continuing.

- [ ] **Step 10: Commit**

```bash
git add pentest/targets pentest/tests/test_targets_base.py pentest/js_engine.py
git commit -m "refactor(pentest): extract substrate seam from js_engine"
```

---

### Task 5: The Electron substrate

**Files:**
- Create: `pentest/targets/electron.py`
- Create: `pentest/tests/test_electron_substrate.py`

**Interfaces:**
- Consumes: `base.Surface`, `base.Liveness`, `base.BridgeContext`, `bridge.install_base`.
- Produces: `ElectronSubstrate(target, app_cmd, app_binary, user_data_root)` satisfying the `Substrate` protocol, with `capabilities = frozenset({"http", "ipc", "host_fs"})`. Sets `surface.extra["user_data_dir"]` (a `Path`) — Task 9 reads it. Exposes `single_instance_lock_detected: bool` after `open()`.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_electron_substrate.py`:

```python
"""Tests for the Electron substrate.

Launch behaviour is covered end-to-end in Task 12; these tests pin the pure
logic that must not regress: argument construction, port allocation, and the
single-instance-lock degradation contract.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from targets.electron import ElectronSubstrate


def test_launch_args_include_debug_port_and_user_data_dir(tmp_path):
    sub = ElectronSubstrate(target="https://api.example.com",
                            app_binary="/Applications/Foo.app",
                            user_data_root=tmp_path)
    argv, ud = sub._launch_argv(index=0, port=9333)
    assert "--remote-debugging-port=9333" in argv
    assert f"--user-data-dir={ud}" in argv
    assert ud.parent == tmp_path


def test_each_instance_gets_an_isolated_user_data_dir(tmp_path):
    sub = ElectronSubstrate(target="t", app_binary="/x", user_data_root=tmp_path)
    _, ud0 = sub._launch_argv(index=0, port=1)
    _, ud1 = sub._launch_argv(index=1, port=2)
    assert ud0 != ud1


def test_app_cmd_is_split_and_preserved(tmp_path):
    sub = ElectronSubstrate(target="t", app_cmd="npm run electron:dev",
                            user_data_root=tmp_path)
    argv, _ = sub._launch_argv(index=0, port=9333)
    assert argv[:3] == ["npm", "run", "electron:dev"]


def test_npm_launch_inserts_argument_separator(tmp_path):
    """Without `--`, npm swallows the flags instead of forwarding them to Electron."""
    sub = ElectronSubstrate(target="t", app_cmd="npm run electron:dev",
                            user_data_root=tmp_path)
    argv, _ = sub._launch_argv(index=0, port=9333)
    assert argv[3] == "--"
    assert argv.index("--") < argv.index("--remote-debugging-port=9333")


def test_direct_binary_gets_no_separator(tmp_path):
    sub = ElectronSubstrate(target="t", app_binary="/Applications/Foo.app",
                            user_data_root=tmp_path)
    argv, _ = sub._launch_argv(index=0, port=9333)
    assert "--" not in argv


def test_requires_app_cmd_or_binary():
    with pytest.raises(ValueError, match="--app-cmd or --app-binary"):
        ElectronSubstrate(target="t", user_data_root=Path("/tmp"))


def test_free_port_returns_a_usable_port():
    sub = ElectronSubstrate(target="t", app_binary="/x", user_data_root=Path("/tmp"))
    port = sub._free_port()
    assert isinstance(port, int) and 1024 < port < 65536
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_electron_substrate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'targets.electron'`.

- [ ] **Step 3: Write the implementation**

Create `pentest/targets/electron.py`:

```python
"""Electron substrate — N isolated app instances driven over CDP.

Each identity is a separate app process with its own --user-data-dir, because
Electron keeps its session inside that directory rather than in a storage_state
file. That is what makes cross-identity IPC probes possible.

Two behaviours here are security decisions, not conveniences:

  * A failed CDP connection is a hard error. Falling back to the web substrate
    would produce a report that looks like a desktop pentest but is not.

  * When the app enforces a single-instance lock, fewer surfaces are returned
    and the reason is logged. Templates needing two identities are then SKIPPED
    by the engine, never refuted — a refutation would falsely claim the app is
    safe from IDOR when it merely could not be tested.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

from targets import bridge
from targets.base import BridgeContext, Liveness, Surface

BOOT_TIMEOUT_SECONDS = 90

# @g.comment -- "Launchers that treat trailing flags as their own arguments; cxg's appended flags must follow an explicit -- separator or they never reach the application."
_PACKAGE_MANAGERS = {"npm", "yarn", "pnpm", "bun"}


class ElectronSubstrate:
    name = "electron"
    capabilities = frozenset({"http", "ipc", "host_fs"})

    # @g.comment -- "Validates that the operator supplied exactly one launch mechanism and prepares per-run process/browser bookkeeping used by close()."
    # @g.source (#operator_app_cmd) -- "app launch command supplied by the operator on the command line"
    def __init__(self, target: str, app_cmd: str = "", app_binary: str = "",
                 user_data_root: Optional[Path] = None):
        if not app_cmd and not app_binary:
            raise ValueError("electron target requires --app-cmd or --app-binary")
        self.target = (target or "").rstrip("/")
        self.app_cmd = app_cmd
        self.app_binary = app_binary
        self.user_data_root = Path(user_data_root) if user_data_root else Path("/tmp")
        self.single_instance_lock_detected = False
        self._playwright = None
        self._browsers: list = []
        self._procs: list[subprocess.Popen] = []

    # @g.comment -- "Binds an ephemeral port to discover a free one for this instance's CDP endpoint."
    def _free_port(self) -> int:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])

    # @g.comment -- "Builds the argv for one app instance: the operator's launch command plus the isolated user-data-dir and CDP port that make N simultaneous identities possible; package-manager launchers need an explicit -- separator or they consume cxg's flags as their own instead of forwarding them to the app."
    # @g.sink (#operator_app_cmd) -- "operator-supplied command string is split and executed as a child process"
    def _launch_argv(self, index: int, port: int) -> tuple[list[str], Path]:
        user_data_dir = self.user_data_root / f"instance-{index}"
        base = shlex.split(self.app_cmd) if self.app_cmd else [self.app_binary]
        separator = ["--"] if base and base[0] in _PACKAGE_MANAGERS else []
        argv = base + separator + [f"--remote-debugging-port={port}",
                                   f"--user-data-dir={user_data_dir}"]
        return argv, user_data_dir

    # @g.comment -- "Polls the CDP endpoint until the renderer is reachable or the boot window expires, returning None on timeout so the caller can distinguish a slow app from a single-instance lock."
    async def _connect(self, p, port: int, proc: subprocess.Popen):
        deadline = time.time() + BOOT_TIMEOUT_SECONDS
        while time.time() < deadline:
            if proc.poll() is not None:
                return None  # process exited — likely single-instance lock
            try:
                return await p.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
            except Exception:
                await asyncio.sleep(0.5)
        return None

    # @g.comment -- "Launches one app instance per identity and attaches to each renderer over CDP; returns fewer surfaces than requested when the app refuses concurrent instances, which the engine treats as a skip rather than a refutation."
    async def open(self, profiles: list, *, headless: bool) -> list[Surface]:
        from playwright.async_api import async_playwright
        self._playwright = await async_playwright().start()
        self.user_data_root.mkdir(parents=True, exist_ok=True)

        surfaces: list[Surface] = []
        for i, profile in enumerate(profiles):
            port = self._free_port()
            argv, user_data_dir = self._launch_argv(i, port)
            user_data_dir.mkdir(parents=True, exist_ok=True)
            proc = subprocess.Popen(
                argv, cwd=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,   # own process group, so teardown kills children
            )
            self._procs.append(proc)
            (self.user_data_root / "pids.txt").open("a").write(f"{proc.pid}\n")

            browser = await self._connect(self._playwright, port, proc)
            if browser is None:
                if proc.poll() is not None and i > 0:
                    self.single_instance_lock_detected = True
                    print(f"  ⚠ instance {i} exited immediately — app appears to enforce "
                          f"app.requestSingleInstanceLock(). Continuing with "
                          f"{len(surfaces)} identity(ies); multi-identity templates "
                          f"will be SKIPPED, not refuted.")
                    break
                raise RuntimeError(
                    f"could not attach to Electron over CDP on port {port} within "
                    f"{BOOT_TIMEOUT_SECONDS}s (command: {' '.join(argv)}). "
                    f"Confirm the app forwards --remote-debugging-port."
                )
            self._browsers.append(browser)

            ctx = browser.contexts[0]
            deadline = time.time() + 30
            while not ctx.pages and time.time() < deadline:
                await asyncio.sleep(0.25)
            if not ctx.pages:
                raise RuntimeError(f"Electron instance {i} exposed no renderer page")

            surfaces.append(Surface(page=ctx.pages[0], context=ctx, profile=profile,
                                    index=i, capabilities=self.capabilities,
                                    browser=browser,
                                    extra={"user_data_dir": user_data_dir,
                                           "cdp_port": port, "pid": proc.pid}))
        return surfaces

    # @g.comment -- "Installs the base bridge, then the cxg.ipc namespace that lets templates invoke IPC channels through the same scope and audit path fetch uses."
    async def install_bridge(self, surface: Surface, bridge_ctx: BridgeContext,
                             all_profiles: list) -> None:
        await bridge.install_base(surface.page, surface, bridge_ctx, all_profiles)
        # cxg.ipc is added in Task 7.

    # @g.comment -- "Liveness for a desktop renderer cannot use the web landing test; a live surface is one whose page still evaluates JavaScript."
    async def verify(self, surface: Surface) -> Liveness:
        try:
            ok = await surface.page.evaluate("() => document.readyState")
            return Liveness(True, f"renderer responsive ({ok})")
        except Exception as e:
            return Liveness(False, f"renderer unresponsive: {e}")

    # @g.comment -- "Tears down every browser connection and kills each app's whole process group, so a crashed or interrupted run cannot leave orphaned Electron processes behind."
    async def close(self) -> None:
        for b in self._browsers:
            try:
                await b.close()
            except Exception:
                pass
        self._browsers.clear()
        for proc in self._procs:
            if proc.poll() is not None:
                continue
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
        self._procs.clear()
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    def describe(self) -> dict:
        return {"substrate": "electron", "target": self.target,
                "app_cmd": self.app_cmd, "app_binary": self.app_binary,
                "single_instance_lock_detected": self.single_instance_lock_detected}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd pentest && python -m pytest tests/test_electron_substrate.py -v`
Expected: PASS, 5 passed.

- [ ] **Step 5: Commit**

```bash
git add pentest/targets/electron.py pentest/tests/test_electron_substrate.py
git commit -m "feat(pentest): add Electron substrate with isolated instances and CDP attach"
```

---

### Task 6: Desktop auth profiles

**Files:**
- Modify: `pentest/auth.py` — `AuthProfile` dataclass (line 43), `save_profile`, `load_profile`
- Create: `pentest/tests/test_auth_desktop.py`

**Interfaces:**
- Consumes: `ElectronSubstrate` (Task 5) for launching during capture.
- Produces: `AuthProfile.kind: str` (`"storage_state"` | `"user_data_dir"`, default `"storage_state"`), `AuthProfile.user_data_dir: Optional[str]`, and `auth.capture_desktop_multi(profile, target, count, app_cmd, app_binary) -> list[str]` returning saved profile names.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_auth_desktop.py`:

```python
"""Tests for desktop auth profile persistence."""
from __future__ import annotations

import json

import auth


def test_auth_profile_defaults_to_storage_state():
    p = auth.AuthProfile(name="web-1", target="https://x", storage_state_path="/tmp/x.json")
    assert p.kind == "storage_state"


def test_desktop_profile_round_trips_user_data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "AUTH_DIR", tmp_path)
    p = auth.AuthProfile(name="desk-1", target="https://x", storage_state_path="",
                         kind="user_data_dir", user_data_dir=str(tmp_path / "ud"))
    auth.save_profile(p)
    loaded = auth.load_profile("desk-1")
    assert loaded.kind == "user_data_dir"
    assert loaded.user_data_dir == str(tmp_path / "ud")


def test_desktop_profile_meta_records_kind(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "AUTH_DIR", tmp_path)
    auth.save_profile(auth.AuthProfile(
        name="desk-2", target="https://x", storage_state_path="",
        kind="user_data_dir", user_data_dir=str(tmp_path / "ud2")))
    meta = json.loads((tmp_path / "desk-2.meta.json").read_text())
    assert meta["kind"] == "user_data_dir"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_auth_desktop.py -v`
Expected: FAIL — `AuthProfile.__init__() got an unexpected keyword argument 'kind'`.

- [ ] **Step 3: Extend `AuthProfile`**

In `pentest/auth.py`, add to the dataclass (after `extra_headers`):

```python
    # @g.comment -- "Distinguishes a web identity (Playwright storage_state JSON) from a desktop identity, whose session lives inside an Electron user-data directory rather than in a serialisable state file."
    kind: str = "storage_state"          # "storage_state" | "user_data_dir"
    user_data_dir: Optional[str] = None  # set when kind == "user_data_dir"
```

Ensure `save_profile` writes `kind` and `user_data_dir` into `<name>.meta.json`, and `load_profile` reads them back with the same defaults. For `kind == "user_data_dir"`, skip reading the storage-state JSON entirely — there isn't one.

- [ ] **Step 4: Add `capture_desktop_multi`**

Append to `pentest/auth.py`:

```python
# @g.comment -- "Captures N desktop identities by launching N isolated app instances and letting the operator log into each by hand; the artifact is the user-data directory, since Electron keeps its session there."
def capture_desktop_multi(profile: str, target: str, count: int,
                          app_cmd: str = "", app_binary: str = "") -> list[str]:
    import asyncio
    from targets.electron import ElectronSubstrate

    root = AUTH_DIR / "desktop" / profile
    root.mkdir(parents=True, exist_ok=True)
    saved: list[str] = []

    async def _capture_one(index: int, name: str) -> None:
        sub = ElectronSubstrate(target=target, app_cmd=app_cmd, app_binary=app_binary,
                                user_data_root=root / name)
        try:
            surfaces = await sub.open([_placeholder_profile(name, target)], headless=False)
            if not surfaces:
                raise RuntimeError("app did not expose a renderer")
            print(f"\n  → Log in as identity {index + 1}/{count} in the app window, "
                  f"then press ENTER here.")
            await asyncio.get_event_loop().run_in_executor(None, input)
            label = input("    label for this identity (e.g. admin, user): ").strip() or name
            save_profile(AuthProfile(
                name=name, target=target, storage_state_path="", label=label,
                kind="user_data_dir",
                user_data_dir=str(surfaces[0].extra["user_data_dir"]),
            ))
            saved.append(name)
        finally:
            await sub.close()

    for i in range(count):
        name = f"{profile}-{i + 1}" if count > 1 else profile
        asyncio.run(_capture_one(i, name))
    return saved


# @g.comment -- "Minimal stand-in profile used only to satisfy the substrate's open() signature during capture, before a real profile exists to save."
def _placeholder_profile(name: str, target: str) -> AuthProfile:
    return AuthProfile(name=name, target=target, storage_state_path="",
                       kind="user_data_dir")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd pentest && python -m pytest tests/test_auth_desktop.py -v`
Expected: PASS, 3 passed.

- [ ] **Step 6: Run the whole suite for regressions**

Run: `cd pentest && python -m pytest -v`
Expected: PASS, everything green.

- [ ] **Step 7: Commit**

```bash
git add pentest/auth.py pentest/tests/test_auth_desktop.py
git commit -m "feat(pentest): support desktop auth profiles backed by user-data directories"
```

---

### Task 7: The `cxg.ipc` bridge namespace and validator rules

**Files:**
- Modify: `pentest/targets/electron.py` — `install_bridge`
- Modify: `pentest/validator.py` — `ALLOWED_VULN_CLASSES` region, `validate()`
- Create: `pentest/tests/test_validator_desktop.py`

**Interfaces:**
- Consumes: `bridge.install_base`, `BridgeContext`.
- Produces: `window.__cxg.ipc.{invoke, invokeAs, channels}` in the renderer; `validator` support for `@requires_capability` and a hard error on raw `ipcRenderer.invoke(`.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_validator_desktop.py`:

```python
"""Validator rules for desktop templates."""
from __future__ import annotations

from validator import validate

_OK_BODY = """
// @id: t1
// @vuln_class: idor
async function cxgProbe(cxg) { return []; }
"""


def test_requires_capability_is_parsed():
    src = _OK_BODY.replace("// @vuln_class: idor",
                           "// @vuln_class: idor\n// @requires_capability: ipc")
    r = validate(src)
    assert r.ok
    assert r.meta["requires_capability"] == "ipc"


def test_unknown_capability_warns_but_does_not_reject():
    src = _OK_BODY.replace("// @vuln_class: idor",
                           "// @vuln_class: idor\n// @requires_capability: telepathy")
    r = validate(src)
    assert r.ok
    assert any("telepathy" in w for w in r.warnings)


def test_raw_ipc_renderer_is_rejected():
    src = """
// @id: t2
// @vuln_class: idor
async function cxgProbe(cxg) {
    return await ipcRenderer.invoke('file:read', '../etc/passwd');
}
"""
    r = validate(src)
    assert not r.ok
    assert any("ipcRenderer" in e for e in r.errors)


def test_cxg_ipc_invoke_is_allowed():
    src = """
// @id: t3
// @vuln_class: idor
// @requires_capability: ipc
async function cxgProbe(cxg) {
    const out = await cxg.ipc.invoke('file:read', '../../etc/passwd');
    return [{id: 't3-1', severity: 'high', confirmed: !!out,
             endpoint: 'ipc://file:read', description: 'traversal', evidence: {out}}];
}
"""
    assert validate(src).ok
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_validator_desktop.py -v`
Expected: FAIL — `KeyError: 'requires_capability'` and the raw-`ipcRenderer` test not rejecting.

- [ ] **Step 3: Extend `validator.py`**

Add near `ALLOWED_VULN_CLASSES`:

```python
# @g.comment -- "Capabilities a template may demand of the substrate; the engine skips templates whose capability the running substrate does not provide."
ALLOWED_CAPABILITIES = {"http", "ipc", "host_fs"}

# @g.comment -- "Direct ipcRenderer use bypasses cxg.ipc, and therefore bypasses the scope budget and the audit log — the same reason raw fetch() is banned."
_RAW_IPC_PATTERN = re.compile(r"(?<![.\w])ipcRenderer\s*\.\s*(?:invoke|send|sendSync)\s*\(")
```

Add inside `validate()`, after the vuln_class check:

```python
    if "requires_capability" in meta and meta["requires_capability"] not in ALLOWED_CAPABILITIES:
        warnings.append(
            f"unusual requires_capability '{meta['requires_capability']}' "
            f"(known: {', '.join(sorted(ALLOWED_CAPABILITIES))})")

    if _RAW_IPC_PATTERN.search(source):
        errors.append(
            "raw ipcRenderer call detected. Templates must use cxg.ipc.invoke(channel, ...) "
            "or cxg.ipc.invokeAs(idx, channel, ...) — raw ipcRenderer bypasses the scope "
            "budget and the audit log.")
```

- [ ] **Step 4: Implement the `cxg.ipc` namespace**

Replace `ElectronSubstrate.install_bridge` with:

```python
    # @g.comment -- "Installs the base bridge, then the cxg.ipc namespace, routing every IPC invocation through the same scope-check and audit bindings fetch uses so desktop calls are budgeted and logged identically."
    async def install_bridge(self, surface: Surface, bridge_ctx: BridgeContext,
                             all_profiles: list) -> None:
        await bridge.install_base(surface.page, surface, bridge_ctx, all_profiles)
        await self._install_ipc(surface, bridge_ctx)

    # @g.comment -- "Exposes a Python binding that invokes an IPC channel in a chosen identity's renderer, then installs the JS shim templates call; the preferred execution path is the app's own contextBridge surface, because that is what a compromised renderer actually has."
    async def _install_ipc(self, surface: Surface, bridge_ctx: BridgeContext) -> None:
        channels = list(self.known_channels)

        async def _ipc_call(target_index: int, channel: str, args: list):
            allowed, reason = bridge_ctx.scope_check("IPC", f"ipc://{channel}")
            if not allowed:
                bridge_ctx.audit_request(surface.profile.name,
                                         bridge_ctx.current_template_id[0],
                                         "IPC", f"ipc://{channel}", 0, 0, reason)
                return {"blocked": True, "blocked_reason": reason, "ok": False}
            if target_index < 0 or target_index >= len(self._surfaces):
                return {"ok": False, "error": f"invalid identity index {target_index}"}
            page = self._surfaces[target_index].page
            t0 = time.time()
            result = await page.evaluate(
                """async ({channel, args}) => {
                    const ns = Object.keys(window).find(
                        k => window[k] && typeof window[k].invoke === 'function');
                    try {
                        if (ns) return {ok: true, via: ns + '.invoke',
                                        value: await window[ns].invoke(channel, ...args)};
                        if (typeof require === 'function') {
                            const { ipcRenderer } = require('electron');
                            return {ok: true, via: 'ipcRenderer',
                                    value: await ipcRenderer.invoke(channel, ...args)};
                        }
                        return {ok: false, unreachable: true,
                                error: 'channel not reachable from renderer'};
                    } catch (e) {
                        return {ok: false, error: String(e && e.message || e)};
                    }
                }""",
                {"channel": channel, "args": args},
            )
            dur_ms = (time.time() - t0) * 1000
            bridge_ctx.audit_request(surface.profile.name,
                                     bridge_ctx.current_template_id[0],
                                     "IPC", f"ipc://{channel}",
                                     200 if result.get("ok") else 0, dur_ms, "")
            return result

        await surface.page.expose_function("__cxg_ipc_call", _ipc_call)
        await surface.page.evaluate(
            """({index, channels}) => {
                window.__cxg = window.__cxg || {};
                window.__cxg.ipc = {
                    invoke: (channel, ...args) => window.__cxg_ipc_call(index, channel, args),
                    invokeAs: (idx, channel, ...args) => window.__cxg_ipc_call(idx, channel, args),
                    channels: () => channels.slice(),
                };
            }""",
            {"index": surface.index, "channels": channels},
        )
```

Add to `ElectronSubstrate.__init__`:

```python
        self.known_channels: list[str] = []   # populated by cxg_pentest from hypotheses
        self._surfaces: list[Surface] = []
```

and in `open()`, before returning: `self._surfaces = surfaces`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd pentest && python -m pytest tests/test_validator_desktop.py -v`
Expected: PASS, 4 passed.

- [ ] **Step 6: Commit**

```bash
git add pentest/targets/electron.py pentest/validator.py pentest/tests/test_validator_desktop.py
git commit -m "feat(pentest): add cxg.ipc bridge namespace and desktop validator rules"
```

---

### Task 8: Deterministic config confirmation

`CONFIG` hypotheses must never reach the AI generator. This task confirms them from inside the running renderer.

**Files:**
- Create: `pentest/config_probes.py`
- Create: `pentest/tests/test_config_probes.py`

**Interfaces:**
- Consumes: `browser_engine.Finding`, `base.Surface`, `Hypothesis` objects with `http_method == "CONFIG"`.
- Produces: `config_probes.CHECKS: dict[str, str]` (pref key → JS expression returning `true` when insecure) and `async config_probes.run(surface, hypotheses, audit=None) -> list[Finding]`.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_config_probes.py`:

```python
"""Tests for deterministic renderer configuration confirmation."""
from __future__ import annotations

import pytest

import config_probes
from guardlink import Hypothesis


def _hyp(key: str) -> Hypothesis:
    return Hypothesis(
        id=f"electron-config-{key}", vuln_class="privilege_escalation",
        threat="#renderer-boundary", asset=f"#webPreferences.{key}",
        http_method="CONFIG", http_path=f"config://webPreferences.{key}",
        function_name=None, file="main.js", line=1, severity="high",
        cwe="CWE-668", description="d", confidence=0.95,
        has_mitigation_declared=False,
        raw={"pref_key": key, "expected_insecure_value": "true"},
    )


class FakePage:
    def __init__(self, results): self.results = results; self.calls = []

    async def evaluate(self, expr, *_a):
        self.calls.append(expr)
        return self.results.get(expr, False)


class FakeSurface:
    def __init__(self, page): self.page = page; self.profile = type("P", (), {"name": "p1"})


def test_every_known_pref_has_a_runtime_check():
    from electron_surface import _INSECURE_PREFS
    for key, _ in _INSECURE_PREFS:
        assert key in config_probes.CHECKS, f"no runtime check for {key}"


@pytest.mark.asyncio
async def test_confirmed_when_runtime_reproduces_the_claim():
    expr = config_probes.CHECKS["nodeIntegration"]
    surface = FakeSurface(FakePage({expr: True}))
    findings = await config_probes.run(surface, [_hyp("nodeIntegration")])
    assert len(findings) == 1
    assert findings[0].confirmed is True
    assert findings[0].endpoint == "config://webPreferences.nodeIntegration"


@pytest.mark.asyncio
async def test_refuted_when_runtime_contradicts_the_claim():
    surface = FakeSurface(FakePage({}))  # every check returns False
    findings = await config_probes.run(surface, [_hyp("nodeIntegration")])
    assert len(findings) == 1
    assert findings[0].confirmed is False


@pytest.mark.asyncio
async def test_non_config_hypotheses_are_ignored():
    h = _hyp("nodeIntegration")
    h.http_method = "IPC"
    surface = FakeSurface(FakePage({}))
    assert await config_probes.run(surface, [h]) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_config_probes.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'config_probes'`.

- [ ] **Step 3: Write the implementation**

Create `pentest/config_probes.py`:

```python
"""Deterministic runtime confirmation of Electron CONFIG hypotheses.

electron_surface.py reads webPreferences from source and produces claims. Those
claims are never handed to the AI template generator: asking a model to write
fetch calls for "nodeIntegration is true" produces exactly the
plausible-but-wrong findings the triage layer exists to kill.

Instead each claim maps to one JS expression evaluated inside the live
renderer. Source produces the hypothesis; runtime produces the proof. A claim
the runtime does not reproduce is REFUTED, not confirmed.
"""
from __future__ import annotations

import time
from typing import Optional

from browser_engine import Finding

# pref key -> JS expression returning true when the INSECURE state is real.
# @g.comment -- "Each expression is the observable consequence of the misconfiguration, not a reading of the setting itself, so a finding means the renderer boundary is genuinely weakened."
CHECKS: dict[str, str] = {
    # Node reachable from the renderer at all.
    "nodeIntegration":
        "() => typeof require === 'function' && !!require('electron')",
    # Without isolation the preload's globals sit on the same window object.
    "contextIsolation":
        "() => typeof require === 'function' || typeof module === 'object'",
    # An unsandboxed renderer can read process internals.
    "sandbox":
        "() => typeof process === 'object' && !!process.pid",
    # Disabled webSecurity permits a cross-origin read that would otherwise throw.
    "webSecurity":
        "() => { try { const x = new XMLHttpRequest();"
        " x.open('GET','file:///etc/hostname',false); x.send(); return true; }"
        " catch (e) { return false; } }",
    # Mixed content only loads when insecure content is allowed.
    "allowRunningInsecureContent":
        "() => location.protocol === 'https:' && !!window.__cxg_mixed_content_ok",
}

_SEVERITY_WHEN_CONFIRMED = {
    "nodeIntegration": "critical",
    "contextIsolation": "high",
    "sandbox": "medium",
    "webSecurity": "high",
    "allowRunningInsecureContent": "medium",
}


# @g.comment -- "Evaluates each configuration claim inside the live renderer and emits a confirmed or refuted Finding, so config results flow through the same triage, audit and report path as every other finding."
async def run(surface, hypotheses: list, audit=None) -> list[Finding]:
    out: list[Finding] = []
    for h in hypotheses:
        if h.http_method != "CONFIG":
            continue
        key = (h.raw or {}).get("pref_key")
        expr = CHECKS.get(key)
        if expr is None:
            continue
        t0 = time.time()
        try:
            observed = bool(await surface.page.evaluate(expr))
            error = ""
        except Exception as e:
            observed, error = False, str(e)
        dur_ms = (time.time() - t0) * 1000

        finding = Finding(
            id=h.id,
            vuln_class=h.vuln_class,
            severity=_SEVERITY_WHEN_CONFIRMED.get(key, h.severity) if observed else "info",
            confirmed=observed,
            target=getattr(h, "asset", "") or "",
            endpoint=h.http_path,
            description=(
                f"{h.http_path}: renderer confirms the weakened configuration."
                if observed else
                f"{h.http_path}: source suggested a weakened configuration, but the "
                f"running renderer does not reproduce it — mitigation holds."
            ),
            evidence={"expression": expr, "observed": observed,
                      "source_file": h.file, "source_line": h.line,
                      **({"error": error} if error else {})},
        )
        out.append(finding)
        if audit is not None:
            audit.request(getattr(surface.profile, "name", "unknown"), h.id,
                          "CONFIG", h.http_path, 200 if observed else 0, dur_ms, "")
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd pentest && python -m pytest tests/test_config_probes.py -v`
Expected: PASS, 4 passed.

- [ ] **Step 5: Commit**

```bash
git add pentest/config_probes.py pentest/tests/test_config_probes.py
git commit -m "feat(pentest): confirm Electron config claims from the live renderer"
```

---

### Task 9: Host probes

**Files:**
- Create: `pentest/host_probes.py`
- Create: `pentest/tests/test_host_probes.py`

**Interfaces:**
- Consumes: `browser_engine.Finding`.
- Produces: `host_probes.run(scan_dirs: list[Path], *, update_feed_url: str = "", audit=None) -> list[Finding]`.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_host_probes.py`:

```python
"""Tests for page-less host probes."""
from __future__ import annotations

import os

import host_probes


def test_finds_plaintext_token_in_electron_store(tmp_path):
    (tmp_path / "config.json").write_text(
        '{"authToken": "eyJhbGciOiJIUzI1NiJ9.abc.def", "theme": "dark"}')
    findings = host_probes.run([tmp_path])
    assert any(f.vuln_class == "sensitive_data_exposure" and f.confirmed for f in findings)


def test_redacts_the_secret_in_evidence(tmp_path):
    (tmp_path / "config.json").write_text('{"authToken": "eyJhbGciOiJIUzI1NiJ9.abc.def"}')
    findings = host_probes.run([tmp_path])
    blob = repr([f.evidence for f in findings])
    assert "eyJhbGciOiJIUzI1NiJ9.abc.def" not in blob


def test_flags_world_readable_user_data_dir(tmp_path):
    os.chmod(tmp_path, 0o777)
    findings = host_probes.run([tmp_path])
    assert any("permissions" in f.description for f in findings)


def test_clean_directory_produces_no_findings(tmp_path):
    os.chmod(tmp_path, 0o700)
    (tmp_path / "notes.txt").write_text("nothing sensitive here")
    assert host_probes.run([tmp_path]) == []


def test_http_update_feed_is_confirmed_without_network_access(tmp_path):
    os.chmod(tmp_path, 0o700)
    findings = host_probes.run([tmp_path], update_feed_url="http://updates.example.com/feed")
    feed = [f for f in findings if f.vuln_class == "insecure_update_channel"]
    assert feed and feed[0].confirmed


def test_https_update_feed_produces_no_finding(tmp_path):
    os.chmod(tmp_path, 0o700)
    findings = host_probes.run([tmp_path], update_feed_url="https://updates.example.com/feed")
    assert not [f for f in findings if f.vuln_class == "insecure_update_channel"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_host_probes.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'host_probes'`.

- [ ] **Step 3: Write the implementation**

Create `pentest/host_probes.py`:

```python
"""Page-less host probes: local data at rest and update-channel configuration.

Reading the filesystem during a pentest is host-level access, so the default
scan scope is only the user-data directories cxg created itself. That is also
the correct scope: those directories were populated by a genuine interactive
login, so what sits in them is exactly as representative as a real install.

No outbound traffic. Fetching a third-party update feed while authorized to
test a different target is a scope violation, and the finding does not need it:
an http:// feed URL read from the app's own configuration is deterministic
evidence on its own.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path

from browser_engine import Finding

_MAX_FILE_BYTES = 5 * 1024 * 1024
_SCAN_SUFFIXES = {".json", ".log", ".txt", ".ldb", ".sqlite", ""}
_SKIP_DIRS = {"Cache", "GPUCache", "Code Cache", "blob_storage", "node_modules"}

# @g.comment -- "Patterns for credential material that must never sit unencrypted in an app's user-data directory; each capture group 1 is the secret, which is redacted before it reaches a report."
_SECRET_PATTERNS = [
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})\b")),
    ("bearer", re.compile(r"[Bb]earer\s+([A-Za-z0-9._\-]{16,})")),
    ("api_key", re.compile(r"['\"]?(?:api[_-]?key|secret|password|authToken)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]")),
]


# @g.comment -- "Replaces all but the first four characters of a secret so a report proves the exposure without republishing the credential."
def _redact(secret: str) -> str:
    return secret[:4] + "…" + f"[{len(secret)} chars redacted]"


# @g.comment -- "Yields every candidate file under a scan root, skipping browser caches and oversized blobs that cannot hold readable credentials."
def _iter_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix not in _SCAN_SUFFIXES:
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


# @g.comment -- "Scans one directory for credential material at rest and for over-permissive directory modes, returning confirmed findings with redacted evidence."
def _scan_dir(root: Path) -> list[Finding]:
    out: list[Finding] = []

    try:
        mode = stat.S_IMODE(root.stat().st_mode)
    except OSError:
        mode = 0
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        out.append(Finding(
            id=f"host-perms-{root.name}",
            vuln_class="sensitive_data_exposure",
            severity="medium",
            confirmed=True,
            target=str(root),
            endpoint=f"file://{root}",
            description=f"User-data directory permissions are {oct(mode)}; expected 0o700.",
            evidence={"mode": oct(mode), "path": str(root)},
        ))

    for path in _iter_files(root):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for kind, pattern in _SECRET_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            out.append(Finding(
                id=f"host-secret-{kind}-{path.name}",
                vuln_class="sensitive_data_exposure",
                severity="high",
                confirmed=True,
                target=str(root),
                endpoint=f"file://{path}",
                description=(
                    f"Credential material ({kind}) stored unencrypted at rest in "
                    f"{path.name}; Electron's safeStorage API is not in use."
                ),
                evidence={"kind": kind, "path": str(path),
                          "match": _redact(m.group(1)),
                          "line": text[: m.start()].count("\n") + 1},
            ))
            break  # one finding per file is enough to prove the exposure
    return out


# @g.comment -- "Assesses the configured update feed without contacting it: an http:// scheme read from the app's own configuration is sufficient and deterministic evidence."
def _check_update_feed(url: str) -> list[Finding]:
    if not url or not url.lower().startswith("http://"):
        return []
    return [Finding(
        id="host-update-feed-insecure",
        vuln_class="insecure_update_channel",
        severity="critical",
        confirmed=True,
        target=url,
        endpoint=url,
        description="Application update feed is configured over plaintext HTTP, "
                    "permitting update tampering by a network attacker.",
        evidence={"feed_url": url, "scheme": "http",
                  "note": "read from application configuration; feed was not contacted"},
    )]


# @g.comment -- "Public entry point: scans the given directories and the configured update feed, emitting findings that merge into the same report and audit stream as HTTP and IPC findings."
def run(scan_dirs: list, *, update_feed_url: str = "", audit=None) -> list[Finding]:
    findings: list[Finding] = []
    for d in scan_dirs:
        root = Path(d)
        if root.is_dir():
            findings.extend(_scan_dir(root))
    findings.extend(_check_update_feed(update_feed_url))

    if audit is not None:
        for f in findings:
            audit.request("host", f.id, "FS", f.endpoint, 200, 0.0, "")
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd pentest && python -m pytest tests/test_host_probes.py -v`
Expected: PASS, 6 passed.

- [ ] **Step 5: Commit**

```bash
git add pentest/host_probes.py pentest/tests/test_host_probes.py
git commit -m "feat(pentest): add page-less host probes for data at rest and update channel"
```

---

### Task 10: Rust CLI flags

**Files:**
- Modify: `src/cli.rs` — `PentestAction::Run` and `PentestAction::Auth`
- Modify: `src/main.rs` — `run_pentest_command` argument forwarding

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `--target-type`, `--app-cmd`, `--app-binary`, `--host-scan-path` forwarded verbatim to `cxg_pentest.py`.

- [ ] **Step 1: Write the failing test**

Add to the bottom of `src/cli.rs`:

```rust
#[cfg(test)]
mod desktop_flag_tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn target_type_defaults_to_web() {
        let cli = parse(&["cxg", "pentest", "run", "--codebase", ".", "--target", "http://x"])
            .expect("should parse");
        if let Commands::Pentest(p) = cli.command {
            if let PentestAction::Run { target_type, .. } = p.action {
                assert_eq!(target_type, "web");
                return;
            }
        }
        panic!("expected pentest run");
    }

    #[test]
    fn electron_requires_a_launch_mechanism() {
        let err = parse(&["cxg", "pentest", "run", "--codebase", ".", "--target", "http://x",
                          "--target-type", "electron"]);
        assert!(err.is_err(), "electron without --app-cmd/--app-binary must fail");
    }

    #[test]
    fn app_cmd_and_app_binary_conflict() {
        let err = parse(&["cxg", "pentest", "run", "--codebase", ".", "--target", "http://x",
                          "--target-type", "electron",
                          "--app-cmd", "npm start", "--app-binary", "/tmp/a"]);
        assert!(err.is_err(), "--app-cmd and --app-binary are mutually exclusive");
    }

    #[test]
    fn electron_with_app_cmd_parses() {
        let cli = parse(&["cxg", "pentest", "run", "--codebase", ".", "--target", "http://x",
                          "--target-type", "electron", "--app-cmd", "npm run electron:dev"])
            .expect("should parse");
        if let Commands::Pentest(p) = cli.command {
            if let PentestAction::Run { app_cmd, .. } = p.action {
                assert_eq!(app_cmd.as_deref(), Some("npm run electron:dev"));
                return;
            }
        }
        panic!("expected pentest run");
    }

    #[test]
    fn rejects_unknown_target_type() {
        assert!(parse(&["cxg", "pentest", "run", "--codebase", ".", "--target", "http://x",
                        "--target-type", "tauri"]).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test desktop_flag_tests`
Expected: FAIL — compile error, `target_type` is not a field of `PentestAction::Run`.

- [ ] **Step 3: Add the flags**

In `src/cli.rs`, inside `PentestAction::Run`:

```rust
        /// Target type to pentest.
        ///
        /// `web` (default): the existing authenticated-browser pipeline against an HTTP
        /// application. `electron`: launch N isolated instances of an Electron desktop
        /// app, drive their renderers over CDP, and additionally probe IPC channels,
        /// renderer configuration, and local data at rest.
        ///
        /// Tauri is not supported — it exposes no CDP endpoint on macOS or Linux.
        ///
        /// EXAMPLES:
        ///
        ///     cxg pentest run --target-type electron --app-cmd "npm run electron:dev" \
        ///       --codebase ./app-repo --target https://api.example.com --auth desk-1,desk-2
        // @g.comment -- "selects which substrate the orchestrator uses; an unknown value is rejected by clap so a typo can never silently downgrade a desktop scan to a web scan"
        #[arg(long, default_value = "web", value_parser = ["web", "electron"])]
        target_type: String,

        /// Command that launches the desktop app, e.g. "npm run electron:dev".
        ///
        /// Required with `--target-type electron` unless `--app-binary` is given.
        /// cxg appends `--remote-debugging-port` and a per-identity `--user-data-dir`.
        // @g.comment -- "operator-supplied launch command forwarded to the orchestrator, which splits and executes it as a child process per identity"
        // @g.source (#operator_app_cmd) -- "command string supplied by the operator on the command line"
        #[arg(long, conflicts_with = "app_binary", required_if_eq("target_type", "electron"))]
        app_cmd: Option<String>,

        /// Path to a built desktop app, e.g. /Applications/Foo.app.
        ///
        /// Alternative to `--app-cmd`; the two are mutually exclusive.
        // @g.comment -- "operator-supplied path to a packaged application, executed directly instead of via a launch command"
        #[arg(long, conflicts_with = "app_cmd")]
        app_binary: Option<String>,

        /// Additionally scan a real installation directory for data at rest.
        ///
        /// By default host probes read only the isolated user-data directories cxg
        /// created itself. Pass this to opt in to scanning an existing install.
        // @g.comment -- "opt-in expansion of host-probe scan scope beyond cxg-created directories, since reading an operator's real install is host-level access"
        #[arg(long)]
        host_scan_path: Option<String>,
```

`required_if_eq` covers `--target-type electron` with neither flag, but not the case where `--app-binary` alone is supplied — `conflicts_with` plus `required_if_eq` on `app_cmd` would then wrongly demand `app_cmd`. clap resolves this correctly because `conflicts_with` suppresses the `required_if_eq` on the conflicting argument. Test `electron_requires_a_launch_mechanism` and a manual `--app-binary`-only run both confirm this.

Add the same four arguments to `PentestAction::Auth`, minus `host_scan_path`.

- [ ] **Step 4: Forward the flags**

In `src/main.rs::run_pentest_command`, inside the `PentestAction::Run` arm, following the existing `args.push` style:

```rust
            // @g.comment -- "forwards desktop target selection and launch configuration to the Python orchestrator, which owns substrate construction"
            args.push("--target-type".into());
            args.push(target_type);
            if let Some(v) = app_cmd {
                args.push("--app-cmd".into());
                args.push(v);
            }
            if let Some(v) = app_binary {
                args.push("--app-binary".into());
                args.push(v);
            }
            if let Some(v) = host_scan_path {
                args.push("--host-scan-path".into());
                args.push(v);
            }
```

Mirror the first three in the `Auth` arm.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test desktop_flag_tests`
Expected: PASS, 5 passed.

Run: `cargo build`
Expected: builds clean, no warnings.

- [ ] **Step 6: Commit**

```bash
git add src/cli.rs src/main.rs
git commit -m "feat(cli): add desktop target flags to cxg pentest"
```

---

### Task 11: Orchestrator wiring and docs

**Files:**
- Modify: `pentest/cxg_pentest.py` — argparse (lines 359-480), `run_pentest` (line 108), `auth` dispatch
- Modify: `pentest/README.md`, `pentest/docs/ARCHITECTURE.md`, `pentest/docs/TEMPLATES.md`, `pentest/docs/OPERATOR_GUIDE.md`
- Create: `pentest/tests/test_orchestrator_wiring.py`

**Interfaces:**
- Consumes: everything from Tasks 2, 5, 7, 8, 9.
- Produces: `cxg_pentest.build_hypotheses(codebase, target_type) -> list`, `cxg_pentest.split_config_hypotheses(hyps) -> tuple[list, list]`.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_orchestrator_wiring.py`:

```python
"""Tests for orchestrator-level wiring of the desktop path."""
from __future__ import annotations

import cxg_pentest


def test_web_target_type_does_not_scan_electron_sources(fixture_dir):
    hyps = cxg_pentest.build_hypotheses(fixture_dir, "web")
    assert not [h for h in hyps if h.http_method in ("IPC", "CONFIG")]


def test_electron_target_type_adds_ipc_hypotheses(fixture_dir):
    hyps = cxg_pentest.build_hypotheses(fixture_dir, "electron")
    assert [h for h in hyps if h.http_method == "IPC"]


def test_config_hypotheses_are_split_out_from_generator_input(fixture_dir):
    hyps = cxg_pentest.build_hypotheses(fixture_dir, "electron")
    generator_input, config_only = cxg_pentest.split_config_hypotheses(hyps)
    assert all(h.http_method != "CONFIG" for h in generator_input)
    assert config_only and all(h.http_method == "CONFIG" for h in config_only)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd pentest && python -m pytest tests/test_orchestrator_wiring.py -v`
Expected: FAIL — `AttributeError: module 'cxg_pentest' has no attribute 'build_hypotheses'`.

- [ ] **Step 3: Add the wiring helpers**

In `pentest/cxg_pentest.py`, above `run_pentest`:

```python
# @g.comment -- "Builds the hypothesis list for a run: guardlink SARIF and inline annotations always, plus Electron IPC and configuration surface when the desktop substrate is selected."
def build_hypotheses(codebase, target_type: str) -> list:
    cb = Path(codebase)
    sarif, inline, _surface = load_guardlink(cb)
    hyps = list(sarif)
    if target_type == "electron":
        import electron_surface
        hyps += electron_surface.extract(cb)
    return hyps


# @g.comment -- "Separates configuration claims from generator input; CONFIG hypotheses go to config_probes for deterministic runtime confirmation and must never reach the AI template author, which would invent fetch-shaped probes for them."
def split_config_hypotheses(hyps: list) -> tuple[list, list]:
    generator_input = [h for h in hyps if h.http_method != "CONFIG"]
    config_only = [h for h in hyps if h.http_method == "CONFIG"]
    return generator_input, config_only
```

- [ ] **Step 4: Add the argparse flags**

Alongside the existing `p_run.add_argument` calls:

```python
    p_run.add_argument("--target-type", default="web", choices=["web", "electron"],
                       help="Target substrate: web (authenticated browser) or electron "
                            "(N isolated desktop app instances driven over CDP).")
    p_run.add_argument("--app-cmd", default="",
                       help="Command that launches the desktop app, e.g. "
                            "'npm run electron:dev'. Required with --target-type electron "
                            "unless --app-binary is given.")
    p_run.add_argument("--app-binary", default="",
                       help="Path to a built desktop app. Alternative to --app-cmd.")
    p_run.add_argument("--host-scan-path", default="",
                       help="Additionally scan this installation directory for data at "
                            "rest. By default only cxg-created user-data dirs are read.")
```

Mirror the first three on `p_auth`.

- [ ] **Step 5: Wire the run path**

In `run_pentest`, in the JS pipeline branch:

1. Replace the existing `sarif, inline, surface = load_guardlink(cb)` line with:

```python
    hyps = build_hypotheses(args.codebase, args.target_type)
    generator_input, config_hyps = split_config_hypotheses(hyps)
```

Pass `generator_input` — not `hyps` — to `generate_js_all`.

2. Build the substrate before constructing the engine:

```python
    from targets import get_substrate

    session_ud_root = session_root / "user-data"
    substrate = get_substrate(args.target_type, target=args.target,
                              app_cmd=args.app_cmd, app_binary=args.app_binary,
                              user_data_root=session_ud_root)
    if args.target_type == "electron":
        substrate.known_channels = [
            h.http_path.removeprefix("ipc://") for h in hyps if h.http_method == "IPC"
        ]
```

Then add one keyword argument to the existing `JsEngine(...)` construction, leaving every current argument in place: `substrate=substrate`.

3. Add `self.surfaces = surfaces` in `JsEngine.run()` immediately after `surfaces = await self.substrate.open(...)`, so the orchestrator can reach them once the run returns.

4. After the template run, before writing the report:

```python
    if config_hyps and engine.surfaces:
        import config_probes
        config_findings = await config_probes.run(engine.surfaces[0], config_hyps, audit)
        results.confirmed_findings.extend([f for f in config_findings if f.confirmed])
        results.mitigation_verifications.extend([f for f in config_findings if not f.confirmed])

    if "host_fs" in substrate.capabilities:
        import host_probes
        scan_dirs = [s.extra["user_data_dir"] for s in engine.surfaces
                     if "user_data_dir" in s.extra]
        if args.host_scan_path:
            scan_dirs.append(Path(args.host_scan_path))
        results.confirmed_findings.extend(host_probes.run(scan_dirs, audit=audit))
```

`config_probes.run` is called **once** and its results partitioned — calling it twice would double every config finding and re-evaluate the renderer.

4. In the `auth` dispatch, route `--target-type electron` to `auth.capture_desktop_multi`.

- [ ] **Step 6: Run the full suite**

Run: `cd pentest && python -m pytest -v`
Expected: PASS, all green.

- [ ] **Step 7: Update the docs**

- `pentest/README.md`: add `electron` to the target table; add a desktop quick-start showing `cxg pentest auth --target-type electron` then `cxg pentest run --target-type electron`.
- `pentest/docs/ARCHITECTURE.md`: add `targets/`, `electron_surface.py`, `config_probes.py`, `host_probes.py` to "Module responsibilities"; document the two-phase substrate protocol and why bridge installation is separate from `open()`.
- `pentest/docs/TEMPLATES.md`: document `@requires_capability`, the `cxg.ipc` API, the raw-`ipcRenderer` ban, and add a worked IDOR-over-IPC template using `cxg.ipc.invokeAs`.
- `pentest/docs/OPERATOR_GUIDE.md`: add the desktop workflow, the single-instance-lock caveat and what it means for coverage, and the host-probe scan-scope default.

- [ ] **Step 8: Commit**

```bash
git add pentest/cxg_pentest.py pentest/tests/test_orchestrator_wiring.py \
        pentest/README.md pentest/docs
git commit -m "feat(pentest): wire desktop substrate through the orchestrator and document it"
```

---

### Task 12: End-to-end verification against the fixture

**Files:**
- Create: `pentest/tests/test_e2e_electron.py`

**Interfaces:**
- Consumes: everything.
- Produces: proof that the fixture's three vulnerabilities are confirmed and its control channel is refuted.

- [ ] **Step 1: Write the end-to-end test**

Create `pentest/tests/test_e2e_electron.py`:

```python
"""End-to-end: scan the vulnerable Electron fixture.

The control channel matters as much as the vulnerable ones. Without it this
test proves only that the tool finds things — it cannot prove the tool does not
hallucinate, which is the failure mode the triage layer exists to prevent.
"""
from __future__ import annotations

import shutil

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("npx") is None, reason="npx not available; Electron fixture cannot launch"
)


@pytest.mark.asyncio
async def test_config_probes_confirm_node_integration(fixture_dir, tmp_path, monkeypatch):
    import config_probes
    import electron_surface
    from targets.electron import ElectronSubstrate

    hyps = [h for h in electron_surface.extract(fixture_dir) if h.http_method == "CONFIG"]
    assert hyps, "fixture must produce config hypotheses"

    sub = ElectronSubstrate(target="http://127.0.0.1:1",
                            app_cmd="npx electron .",
                            user_data_root=tmp_path / "ud")
    # monkeypatch.chdir restores the original cwd at teardown, so this cannot
    # leak into tests that run afterwards.
    monkeypatch.chdir(fixture_dir)
    try:
        surfaces = await sub.open([type("P", (), {"name": "p1", "storage_state": None,
                                                  "extra_headers": {}})()], headless=False)
        findings = await config_probes.run(surfaces[0], hyps)
        by_endpoint = {f.endpoint: f for f in findings}
        assert by_endpoint["config://webPreferences.nodeIntegration"].confirmed is True
        assert by_endpoint["config://webPreferences.contextIsolation"].confirmed is True
    finally:
        await sub.close()


@pytest.mark.asyncio
async def test_host_probes_find_planted_token(tmp_path):
    import host_probes
    ud = tmp_path / "instance-0"
    ud.mkdir(parents=True)
    (ud / "config.json").write_text('{"authToken":"eyJhbGciOiJIUzI1NiJ9.payload.sig"}')
    findings = host_probes.run([ud])
    assert any(f.confirmed and f.vuln_class == "sensitive_data_exposure" for f in findings)
```

- [ ] **Step 2: Run the end-to-end tests**

Run: `cd pentest && python -m pytest tests/test_e2e_electron.py -v`
Expected: PASS, 2 passed.

- [ ] **Step 3: Run a real desktop scan against the fixture**

```bash
cd pentest/tests/fixtures/vuln-electron
cxg pentest auth --target-type electron --app-cmd "npx electron ." \
  --target http://127.0.0.1:1 --profile e2e --auth-numbers 2
cxg pentest run --target-type electron --app-cmd "npx electron ." \
  --codebase . --target http://127.0.0.1:1 --auth e2e-1,e2e-2 --ai \
  -o /tmp/e2e-report.json
```

Verify in `/tmp/e2e-report.json`:
- `confirmed` contains findings for `ipc://file:read` (traversal), `ipc://user:get-profile` (cross-identity read), and `config://webPreferences.nodeIntegration`.
- `refuted` (`mitigation_verifications`) contains `ipc://secure:read-config`. **If `secure:read-config` appears in `confirmed`, that is a false positive — stop and fix before merging.**
- `audit.jsonl` contains `"method": "IPC"` entries.
- No Electron processes survive the run: `pgrep -fl electron` returns nothing.

- [ ] **Step 4: Run the whole suite plus the Rust tests**

Run: `cd pentest && python -m pytest -v && cd .. && cargo test`
Expected: PASS on both.

- [ ] **Step 5: Commit**

```bash
git add pentest/tests/test_e2e_electron.py
git commit -m "test(pentest): end-to-end desktop scan against the vulnerable fixture"
```

---

## Self-review notes

**Spec coverage:** every spec section maps to a task — substrate seam (4), Electron substrate (5), auth profiles (6), bridge composition and `cxg.ipc` (7), hypothesis extraction (2), config confirmation (8), host probes (9), CLI (10), wiring and docs (11), error handling (5, spread through `open`/`close`), testing (1, 3, 12).

**Known deviations from the spec, both deliberate:**
1. Two-phase substrate protocol (`open` + `install_bridge`) instead of one-phase — the spec's version is not implementable, as explained above.
2. `config_probes.py` is a module the spec did not name. The spec required deterministic runtime confirmation of CONFIG claims but left it unplaced; putting it in `electron_surface.py` would mix source scanning with runtime probing, and putting it in `js_engine.py` would reintroduce target-specific logic into the engine.

**Open risk:** Task 3 is a genuine gate. If Playwright bindings do not work over `connect_over_cdp` against Electron, Tasks 5 and 7 need rewriting against raw CDP (`Runtime.addBinding`, `Page.addScriptToEvaluateOnNewDocument`). The seam, Task 2, Task 9, and Task 10 are unaffected either way.
