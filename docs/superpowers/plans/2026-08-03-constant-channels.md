# Constant-Named IPC Channels and Routeless Desktop Threats — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `cxg pentest --target-type electron` extract IPC channels registered with imported constants, and stop discarding guardlink threats that carry no HTTP route.

**Architecture:** A regex pre-pass builds a `name → literal` map from `export const` declarations, consulted at every `ipcMain` and `ipcRenderer` call site that passes a bare identifier. A new `threat_correlation` module joins routeless guardlink threats to the IPC channels registered in the same source file, producing candidates for the generator or a `review_only` mark for the report.

**Tech Stack:** Python 3.11+, stdlib `re` and `pathlib` only. No new dependencies. Tests are `pytest`, run from `pentest/`.

**Spec:** `docs/superpowers/specs/2026-08-03-constant-channels-and-routeless-threats-design.md`

## Global Constraints

- No new third-party dependencies. `re` and `pathlib` only.
- The constant map matches `export const` **only**. Bare `const` must NOT be matched — measured on Mattermost it yields 12 colliding names (`url`, `filename`, `expected`, `html`, `testURL`) that are ordinary locals.
- A constant name exported with more than one distinct value is **omitted from the map** and counted. Never resolve it to either value.
- Every new or changed function gets a `@g.comment -- "…"` annotation directly above it, per the repo's Giggs GAL convention. Match the density and voice of the surrounding annotations in the file you are editing.
- `review_only` hypotheses must never reach the AI generator, exactly as `CONFIG` hypotheses never do.
- No test may invoke a live model, launch Electron, or read the Mattermost checkout at `/Users/zippon/src/mattermost-desktop`. Fixtures only.
- `pentest/tests/fixtures/vuln-electron/` is otherwise FROZEN — Task 1 adds one constant-registered channel and changes nothing else.
- Existing web-target behaviour must be bit-for-bit unchanged. Every function you touch is on the web scan path too.
- Run the full suite from `pentest/` with `python -m pytest tests/ -q` before every commit.

---

### Task 1: Constant map and handler resolution

**Files:**
- Modify: `pentest/electron_surface.py` (add `_RE_EXPORT_CONST`, `_constant_map`; change `_RE_IPC_HANDLER`, `_ipc_hypotheses`, `extract`)
- Modify: `pentest/tests/fixtures/vuln-electron/main.js` (add one constant-registered channel)
- Test: `pentest/tests/test_electron_surface.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `_constant_map(sources) -> tuple[dict[str, str], list[str]]` returning `(name→value, colliding_names)`. Task 2 consumes this map.

- [ ] **Step 1: Write the failing tests**

Add to `pentest/tests/test_electron_surface.py`:

```python
def _write(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def test_export_const_channel_is_resolved(tmp_path):
    _write(tmp_path, "consts.ts", "export const GET_CONFIG = 'get-configuration';\n")
    _write(tmp_path, "main.ts", "ipcMain.handle(GET_CONFIG, h);\n")
    import electron_surface
    paths = {h.http_path for h in electron_surface.extract(tmp_path)}
    assert "ipc://get-configuration" in paths


def test_bare_const_is_not_resolved(tmp_path):
    _write(tmp_path, "consts.ts", "const LOCAL_ONLY = 'local-only';\n")
    _write(tmp_path, "main.ts", "ipcMain.handle(LOCAL_ONLY, h);\n")
    import electron_surface
    paths = {h.http_path for h in electron_surface.extract(tmp_path)}
    assert "ipc://local-only" not in paths


def test_literal_channel_still_extracted(tmp_path):
    _write(tmp_path, "main.ts", "ipcMain.handle('file:read', h);\n")
    import electron_surface
    paths = {h.http_path for h in electron_surface.extract(tmp_path)}
    assert "ipc://file:read" in paths


def test_colliding_export_const_is_omitted(tmp_path):
    _write(tmp_path, "a.ts", "export const DUP = 'value-a';\n")
    _write(tmp_path, "b.ts", "export const DUP = 'value-b';\n")
    _write(tmp_path, "main.ts", "ipcMain.handle(DUP, h);\n")
    import electron_surface
    consts, colliding = electron_surface._constant_map(
        [(p, p.read_text()) for p in electron_surface._iter_sources(tmp_path)])
    assert "DUP" not in consts
    assert "DUP" in colliding
    paths = {h.http_path for h in electron_surface.extract(tmp_path)}
    assert "ipc://value-a" not in paths and "ipc://value-b" not in paths


def test_unresolved_identifier_records_no_channel(tmp_path):
    _write(tmp_path, "main.ts", "ipcMain.handle(NEVER_DECLARED, h);\n")
    import electron_surface
    assert electron_surface.extract(tmp_path) == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd pentest && python -m pytest tests/test_electron_surface.py -q -k "const or literal_channel or unresolved"`
Expected: FAIL — `_constant_map` does not exist; the `export const` case extracts nothing.

- [ ] **Step 3: Add the constant-map pre-pass**

Add beside the other module-level patterns in `pentest/electron_surface.py`:

```python
# @g.comment -- "Matches a top-level `export const NAME = 'literal';` declaration, the form every Electron app that names its IPC channels centrally actually uses. Deliberately anchored to `export`: measured against a real 154-handler tree, matching bare `const` too raised the map from 214 entries to 280 and introduced 12 colliding names — `url`, `filename`, `expected`, `html`, `testURL` — all ordinary locals in tests and helpers, none of them channels. Channel constants must be exported to be importable at the call site, so `export` costs no coverage (152/152 handlers still resolve) and buys the absence of collisions outright."
_RE_EXPORT_CONST = re.compile(
    r"""^\s*export\s+const\s+(\w+)\s*=\s*(['"`])([^'"`\n]+)\2\s*;""", re.M)


# @g.comment -- "Builds the identifier -> channel-name map consulted wherever an ipcMain/ipcRenderer call passes a bare identifier instead of a literal. Returns colliding names separately rather than picking a winner: two files exporting the same name with different values is genuine ambiguity, and resolving it by guess would attribute a probe's result to the wrong channel — a wrong answer, which this codebase consistently refuses in favour of no answer."
def _constant_map(sources) -> tuple[dict[str, str], list[str]]:
    values: dict[str, set[str]] = {}
    for _path, text in sources:
        for m in _RE_EXPORT_CONST.finditer(text):
            values.setdefault(m.group(1), set()).add(m.group(3))
    colliding = sorted(name for name, vals in values.items() if len(vals) > 1)
    resolved = {name: next(iter(vals)) for name, vals in values.items() if len(vals) == 1}
    return resolved, colliding
```

- [ ] **Step 4: Teach `_RE_IPC_HANDLER` the identifier form**

Replace the existing `_RE_IPC_HANDLER` definition. Keep its existing `@g.comment` line and append a second one:

```python
# @g.comment -- "Matches ipcMain.handle('channel', ...) / ipcMain.on('channel', ...), the main-process side of every IPC entry point this module surfaces."
# @g.comment -- "Now also captures a bare IDENTIFIER first argument, resolved against _constant_map by the caller. Without this alternative the pattern recognised literal names only, and a real 154-handler Electron app that names its channels centrally — `ipcMain.handle(VALIDATE_SERVER_URL, ...)` — extracted 0 of 152 handlers, so the whole desktop pipeline reported an empty IPC surface and exited before generating a single template. An identifier that resolves to nothing is still skipped; the miss is counted and logged rather than guessed at."
_RE_IPC_HANDLER = re.compile(
    r"""ipcMain\.(?:handle|on)\s*\(\s*"""
    r"""(?:(?P<q>['"`])(?P<literal>[^'"`]+)(?P=q)|(?P<ident>\w+))""")
```

**This changes group numbering — `m.group(1)` is now the quote character.** Every call site must use the named groups.

- [ ] **Step 5: Resolve at the call site in `_ipc_hypotheses`**

Change the signature and the channel extraction. The rest of the function body — `seen`, `line`, `reachable`, `reachable_via_generic`, the `Hypothesis(...)` construction — is unchanged:

```python
def _ipc_hypotheses(sources, named, passthrough, consts) -> tuple[list[Hypothesis], int]:
    out: list[Hypothesis] = []
    seen: set[str] = set()
    unresolved = 0
    for path, text in sources:
        for m in _RE_IPC_HANDLER.finditer(text):
            channel = m.group("literal")
            if channel is None:
                channel = consts.get(m.group("ident"))
            # @g.comment -- "An identifier with no entry in the constant map is skipped and COUNTED, never guessed. The count is what makes a future app using an idiom this module does not understand (an enum member, a computed name, a re-export) visible as a number in the extraction log instead of silently shrinking the attack surface — the same failure mode, undetected, is what this task exists to fix."
            if channel is None:
                unresolved += 1
                continue
            if channel in seen:
                continue
            seen.add(channel)
            # … rest of the existing loop body unchanged …
    return out, unresolved
```

- [ ] **Step 6: Build the map in `extract` and report what it found**

```python
def extract(codebase: Path) -> list[Hypothesis]:
    sources = [(p, p.read_text(errors="ignore")) for p in _iter_sources(Path(codebase))]
    consts, colliding = _constant_map(sources)
    named, passthrough, namespaces = _bridge_exposure_map(sources)
    ipc_hyps, unresolved = _ipc_hypotheses(sources, named, passthrough, consts)
    if colliding:
        print(f"     · {len(colliding)} constant name(s) exported with conflicting values, "
              f"left unresolved: {', '.join(colliding[:5])}"
              + (" …" if len(colliding) > 5 else ""))
    if unresolved:
        print(f"     · {unresolved} ipcMain registration(s) named by an identifier this "
              f"module could not resolve to a channel")
    return ipc_hyps + _config_hypotheses(sources, namespaces)
```

Note `_bridge_exposure_map` keeps its current two-argument shape here — Task 2 adds `consts` to it.

- [ ] **Step 7: Add one constant-registered channel to the fixture**

In `pentest/tests/fixtures/vuln-electron/main.js`, add near the top:

```js
// Registered by imported-constant name, the form real Electron apps use.
const CONFIG_GET = 'config:get';
export const APP_GET_VERSION = 'app:get-version';
```

and register it beside the existing handlers:

```js
ipcMain.handle(APP_GET_VERSION, async () => app.getVersion());
```

Change nothing else in the fixture. The `CONFIG_GET` bare const is there so the fixture also covers the not-resolved case.

- [ ] **Step 8: Run the tests**

Run: `cd pentest && python -m pytest tests/ -q`
Expected: PASS, including every pre-existing Electron test. If a pre-existing test asserted an exact channel count for the fixture, update it to the new count and note the change in your report.

- [ ] **Step 9: Commit**

```bash
git add pentest/electron_surface.py pentest/tests/test_electron_surface.py pentest/tests/fixtures/vuln-electron/main.js
git commit -m "feat(electron): resolve constant-named ipcMain channels"
```

---

### Task 2: Preload constant resolution and passthrough precedence

**Files:**
- Modify: `pentest/electron_surface.py` (`_bridge_exposure_map`, `extract`)
- Test: `pentest/tests/test_electron_surface.py`

**Interfaces:**
- Consumes: `_constant_map` from Task 1.
- Produces: `_bridge_exposure_map(sources, consts)` — signature gains a third positional parameter.

- [ ] **Step 1: Write the failing tests**

The precedence rule is the subtle part: a known constant makes a binding **channel-specific**, and that check must run BEFORE the passthrough comparison.

```python
_PRELOAD = """
const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('desktop', {
    getSecret: (serverUrl, keySuffix) => ipcRenderer.invoke(SECURE_STORAGE_GET, serverUrl, keySuffix),
});
"""


def test_preload_constant_binding_is_channel_specific(tmp_path):
    _write(tmp_path, "consts.ts", "export const SECURE_STORAGE_GET = 'secure-storage-get';\n")
    _write(tmp_path, "preload.js", _PRELOAD)
    _write(tmp_path, "main.ts", "ipcMain.handle(SECURE_STORAGE_GET, h);\n")
    import electron_surface
    h = [x for x in electron_surface.extract(tmp_path)
         if x.http_path == "ipc://secure-storage-get"][0]
    assert h.raw["reachable_via"] == "desktop.getSecret"
    assert h.raw["reachable_via_generic"] is False


def test_constant_shadowing_a_param_name_resolves_as_channel(tmp_path):
    # `channel` is BOTH the binding's first parameter name and an exported constant.
    # The constant must win: this binding forwards a fixed channel, not its own argument.
    _write(tmp_path, "consts.ts", "export const channel = 'fixed-channel';\n")
    _write(tmp_path, "preload.js",
           "contextBridge.exposeInMainWorld('api', {\n"
           "    send: (channel) => ipcRenderer.invoke(channel),\n"
           "});\n")
    _write(tmp_path, "main.ts", "ipcMain.handle(channel, h);\n")
    import electron_surface
    h = [x for x in electron_surface.extract(tmp_path)
         if x.http_path == "ipc://fixed-channel"][0]
    assert h.raw["reachable_via_generic"] is False


def test_genuine_passthrough_still_detected(tmp_path):
    _write(tmp_path, "preload.js",
           "contextBridge.exposeInMainWorld('api', {\n"
           "    invoke: (ch, ...args) => ipcRenderer.invoke(ch, ...args),\n"
           "});\n")
    _write(tmp_path, "main.ts", "ipcMain.handle('some:channel', h);\n")
    import electron_surface
    h = [x for x in electron_surface.extract(tmp_path)
         if x.http_path == "ipc://some:channel"][0]
    assert h.raw["reachable_via"] == "api.invoke"
    assert h.raw["reachable_via_generic"] is True
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd pentest && python -m pytest tests/test_electron_surface.py -q -k "preload_constant or shadowing or genuine_passthrough"`
Expected: the first two FAIL (constant not consulted, so `reachable_via` is None); the third PASSES already — it is the regression guard.

- [ ] **Step 3: Consult the map before the passthrough test**

In `_bridge_exposure_map`, change the signature to `(sources, consts)` and replace the classification branch:

```python
                call = _RE_IPC_CALL.search(region[head.end(): body_end])
                if call is None:
                    continue
                # @g.comment -- "Resolves a bare-identifier channel argument through the constant map BEFORE the passthrough comparison below, because the two cases are disjoint and only the map can tell them apart: an identifier that names an exported channel constant means this binding forwards one FIXED channel (channel-specific), while an identifier equal to the binding's own first parameter means it forwards whatever the caller passes (generic passthrough). Getting the order wrong misclassifies a channel-specific binding whose parameter happens to share a constant's name as the single generic passthrough, which at dispatch time sends the channel name as an extra leading argument to a binding that does not expect one — a probe that reaches the wrong handler, or none."
                channel = call.group("channel")
                if channel is None and call.group("ident"):
                    channel = consts.get(call.group("ident"))
                if channel is not None:
                    named.setdefault(channel, f"{namespace}.{head.group('key')}")
                elif (call.group("ident")
                      and call.group("ident") == _first_param_name(head)
                      and passthrough is None):
                    passthrough = f"{namespace}.{head.group('key')}"
```

- [ ] **Step 4: Pass the map in from `extract`**

```python
    named, passthrough, namespaces = _bridge_exposure_map(sources, consts)
```

`_constant_map` is already called above this line from Task 1. Move the `_bridge_exposure_map` call below it if it is not already.

- [ ] **Step 5: Run the tests**

Run: `cd pentest && python -m pytest tests/ -q`
Expected: PASS, all three new tests plus the full suite.

- [ ] **Step 6: Commit**

```bash
git add pentest/electron_surface.py pentest/tests/test_electron_surface.py
git commit -m "feat(electron): resolve constant-named channels in preload bindings"
```

---

### Task 3: Correlate routeless threats to candidate channels

**Files:**
- Create: `pentest/threat_correlation.py`
- Test: `pentest/tests/test_threat_correlation.py`

**Interfaces:**
- Consumes: `Hypothesis` from `guardlink`; IPC hypotheses produced by `electron_surface.extract` (Tasks 1–2).
- Produces: `correlate(threats, ipc_hyps, codebase) -> tuple[list, list]` returning `(generator_input, review_only)`. Task 4 consumes `raw["candidate_channels"]`; Task 5 consumes the `review_only` list.

**The path-normalisation trap.** `electron_surface` sets `file=str(path)` from an absolute walk (`/Users/…/src/app/popoutManager.ts`). Guardlink SARIF sets `file` to the relative URI (`src/app/popoutManager.ts`). A direct string comparison matches **nothing** and does so silently — the correlated count would be 0 and every threat would be filed review-only, which looks like a plausible result. Normalise both to a codebase-relative POSIX string before joining, and pin it with a test that uses an absolute IPC file and a relative threat file.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_threat_correlation.py`:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardlink import Hypothesis
import threat_correlation


def _threat(hid, file, path=None):
    return Hypothesis(
        id=hid, vuln_class="idor", threat="#t", asset="#a",
        http_method=None, http_path=path, function_name=None,
        file=file, line=10, severity="high", cwe=None,
        description="d", confidence=0.8, has_mitigation_declared=False)


def _ipc(channel, file):
    return Hypothesis(
        id=f"electron-ipc-{channel}", vuln_class="idor", threat="#ipc-channel",
        asset=f"#{channel}", http_method="IPC", http_path=f"ipc://{channel}",
        function_name=None, file=file, line=1, severity="high", cwe=None,
        description="d", confidence=0.9, has_mitigation_declared=False)


CB = "/repo"


def test_absolute_ipc_file_matches_relative_threat_file():
    gen, review = threat_correlation.correlate(
        [_threat("t1", "src/app/popout.ts")],
        [_ipc("popout:open", "/repo/src/app/popout.ts")],
        CB)
    assert review == []
    assert gen[0].raw["candidate_channels"] == ["popout:open"]


def test_threat_with_no_channels_in_its_file_is_review_only():
    gen, review = threat_correlation.correlate(
        [_threat("t1", "src/common/JsonFileManager.ts")],
        [_ipc("popout:open", "/repo/src/app/popout.ts")],
        CB)
    assert gen == []
    assert review[0].raw["review_only"] is True
    assert review[0].raw["review_only_reason"]


def test_candidates_are_sorted_and_deduped():
    gen, _ = threat_correlation.correlate(
        [_threat("t1", "src/a.ts")],
        [_ipc("z:one", "/repo/src/a.ts"), _ipc("a:two", "/repo/src/a.ts")],
        CB)
    assert gen[0].raw["candidate_channels"] == ["a:two", "z:one"]


def test_threat_with_http_path_passes_through_untouched():
    t = _threat("t1", "src/api/users.ts", path="/api/users/{id}")
    gen, review = threat_correlation.correlate([t], [], CB)
    assert gen == [t] and review == []
    assert "candidate_channels" not in gen[0].raw


def test_threat_with_no_file_is_review_only():
    gen, review = threat_correlation.correlate([_threat("t1", None)], [], CB)
    assert gen == [] and review[0].raw["review_only"] is True


def test_ipc_hypotheses_are_not_themselves_correlated():
    ipc = _ipc("popout:open", "/repo/src/app/popout.ts")
    gen, review = threat_correlation.correlate([ipc], [ipc], CB)
    assert gen == [ipc] and review == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd pentest && python -m pytest tests/test_threat_correlation.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'threat_correlation'`.

- [ ] **Step 3: Write the module**

Create `pentest/threat_correlation.py`:

```python
"""Join routeless guardlink threats to the IPC channels registered beside them.

guardlink reports a threat at a source location; electron_surface reports a
channel at a source location. Neither module imports the other and neither owns
the join, so it lives here.

A threat that names an HTTP route is already runnable and passes through
untouched — this is a desktop-only concern.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional


# @g.comment -- "Normalises a Hypothesis.file to a codebase-relative POSIX string so the two producers can be joined at all. They disagree by construction: electron_surface stores str(path) from an absolute walk, guardlink stores the SARIF artifactLocation URI, which is relative. Comparing them raw matches nothing and does so QUIETLY — every threat would be filed review-only and the run would look like a legitimate 'nothing correlates' result rather than a broken join. Returns None for a threat with no recorded file, which the caller treats as review-only rather than as a match against everything."
# @g.comment -- "The fallback must never manufacture a key that can collide with a legitimate codebase-relative one. An earlier draft ended `.lstrip('./')`, which strips CHARACTERS rather than a prefix: it turned '../foo/a.ts' into 'foo/a.ts' and the out-of-tree '/other/src/a.ts' into 'other/src/a.ts', either of which can equal a real relative threat path and produce a FALSE correlation. That is worse than a miss — a miss surfaces as review-only, while a false match aims a probe at an unrelated file's channels and misattributes whatever it finds to the wrong threat. Leaving an out-of-tree path ABSOLUTE makes the collision structurally impossible, since a relative key never begins with '/'."
def _rel(file: Optional[str], codebase: str) -> Optional[str]:
    if not file:
        return None
    # resolve() is non-strict: it collapses '..' and '.' segments without
    # requiring the path to exist, which is what the tests rely on.
    p = Path(file)
    p = p.resolve() if p.is_absolute() else Path(p.as_posix().removeprefix("./"))
    root = Path(codebase).resolve()
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return p.as_posix()


# @g.comment -- "Splits routeless threats into those the generator can aim at and those it cannot. A threat correlates when its source file registers at least one IPC channel; the channels become CANDIDATES, not an answer — one file can register fifteen, and choosing among them from the threat text is the model's job. What this function guarantees is only that the model is never asked to invent an entry point from nothing, which is the condition that produced inconclusive probes on every prior desktop run."
# @g.comment -- "A threat that correlates to nothing is marked review_only rather than dropped. Ten of Mattermost's seventeen are main-process-internal — a readFileSync, a Windows registry read — and no renderer-side probe reaches them. Dropping them silently, which is what the generator's http_path filter did, makes an empty findings list read as full coverage; carrying them through with a reason makes the gap legible in the report."
def correlate(threats: list, ipc_hyps: list, codebase: str) -> tuple[list, list]:
    channels_by_file: dict[str, set[str]] = {}
    for h in ipc_hyps:
        if h.http_method != "IPC" or not h.http_path:
            continue
        key = _rel(h.file, codebase)
        if key is None:
            continue
        channels_by_file.setdefault(key, set()).add(h.http_path.removeprefix("ipc://"))

    generator_input, review_only = [], []
    for t in threats:
        if t.http_path:
            generator_input.append(t)
            continue
        key = _rel(t.file, codebase)
        candidates = sorted(channels_by_file.get(key, ())) if key else []
        if candidates:
            t.raw = dict(t.raw or {})
            t.raw["candidate_channels"] = candidates
            generator_input.append(t)
        else:
            t.raw = dict(t.raw or {})
            t.raw["review_only"] = True
            t.raw["review_only_reason"] = (
                f"no IPC channel is registered in {key or 'an unrecorded file'}, "
                "so no renderer-side probe can reach this threat"
            )
            review_only.append(t)
    return generator_input, review_only
```

- [ ] **Step 4: Run the tests**

Run: `cd pentest && python -m pytest tests/test_threat_correlation.py -q`
Expected: PASS, all six.

- [ ] **Step 5: Commit**

```bash
git add pentest/threat_correlation.py pentest/tests/test_threat_correlation.py
git commit -m "feat(pentest): correlate routeless threats to candidate IPC channels"
```

---

### Task 4: Make correlated threats runnable, keep review-only out

**Files:**
- Modify: `pentest/js_generator.py` (`rank_hypotheses_by_goal`, `_dedupe_by_probe_shape`, IPC prompt context)
- Test: `pentest/tests/test_js_generator.py`

**Interfaces:**
- Consumes: `raw["candidate_channels"]` and `raw["review_only"]` from Task 3.
- Produces: nothing new. Task 5 is independent of this task.

**The dedupe trap.** `_dedupe_by_probe_shape` keys on `(http_method, http_path, function_name)`. A correlated threat has `http_path=None` and usually `function_name=None`, so two distinct threats in the same file collapse into one and a real finding is lost. `navigationManager.ts` is exactly this case in the measured data — `deeplink-injection` and `ui-spoof`, same file, same three candidates. The key must include the candidate set and the threat id for these.

- [ ] **Step 1: Write the failing tests**

```python
def _routeless(hid, vuln, candidates):
    h = Hypothesis(
        id=hid, vuln_class=vuln, threat=f"#{vuln}", asset="#a",
        http_method=None, http_path=None, function_name=None,
        file="src/app/navigationManager.ts", line=1, severity="high", cwe=None,
        description="d", confidence=0.8, has_mitigation_declared=False)
    h.raw = {"candidate_channels": candidates}
    return h


def test_correlated_threat_is_runnable():
    import js_generator
    out = js_generator.rank_hypotheses_by_goal(
        [_routeless("t1", "deeplink_injection", ["a", "b"])], goal="", use_llm=False)
    assert [h.id for h in out] == ["t1"]


def test_review_only_threat_is_never_runnable():
    import js_generator
    h = _routeless("t1", "insecure_deser", [])
    h.raw = {"review_only": True}
    assert js_generator.rank_hypotheses_by_goal([h], goal="", use_llm=False) == []


def test_two_threats_same_file_survive_dedupe():
    import js_generator
    out = js_generator.rank_hypotheses_by_goal(
        [_routeless("t1", "deeplink_injection", ["a", "b", "c"]),
         _routeless("t2", "ui_spoof", ["a", "b", "c"])],
        goal="", use_llm=False)
    assert sorted(h.id for h in out) == ["t1", "t2"]


def test_web_hypothesis_selection_is_unchanged():
    import js_generator
    web = [Hypothesis(
        id=f"w{i}", vuln_class="idor", threat="#idor", asset="#a",
        http_method="GET", http_path=f"/api/{i}", function_name=f"f{i}",
        file="a.py", line=1, severity="high", cwe=None, description="d",
        confidence=0.8, has_mitigation_declared=False) for i in range(3)]
    out = js_generator.rank_hypotheses_by_goal(web, goal="", use_llm=False)
    assert sorted(h.id for h in out) == ["w0", "w1", "w2"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd pentest && python -m pytest tests/test_js_generator.py -q -k "correlated or review_only or same_file or unchanged"`
Expected: the first three FAIL (filtered out by `if h.http_path`); the last PASSES — it is the regression guard.

- [ ] **Step 3: Change the runnable filter**

In `rank_hypotheses_by_goal`, replace the pre-filter line:

```python
    # @g.comment -- "A hypothesis is runnable when the engine has somewhere to aim a probe: an HTTP route, or — on a desktop target — the candidate IPC channels threat_correlation joined to it from its own source file. The former `if h.http_path` filter admitted only the first, so every guardlink threat on an Electron app (none of which carries an HTTP route) was discarded before ranking and the generator was handed nothing at all."
    # @g.comment -- "review_only is excluded for the same reason CONFIG hypotheses are: threat_correlation could find no channel in the threat's file, so there is no entry point for a probe to reach. Asking a model to write one anyway produces the plausible-but-wrong finding the triage layer exists to kill. These are reported separately, never silently dropped."
    runnable = [h for h in hypotheses
                if not (h.raw or {}).get("review_only")
                and (h.http_path or (h.raw or {}).get("candidate_channels"))]
```

- [ ] **Step 3b: Fix the SECOND runnable gate**

`_keyword_rank` has its own independent `if h.http_path` filter, downstream of the
pre-filter above. It re-excludes exactly the hypotheses Step 3 just admitted, and
because `goal=""` routes straight into it, Step 3 alone leaves the tests still failing.

Extract the rule from Step 3 into a single shared predicate — do **not** write a second
copy. Two copies can drift, and the symptom is a scan whose selected hypotheses depend on
whether a goal was set (`_llm_rank`'s success path never consults the keyword gate) rather
than on the hypotheses themselves. One predicate, called from both sites, covering both the
`review_only` exclusion and the runnable test.

- [ ] **Step 4: Fix the dedupe key**

In `_dedupe_by_probe_shape`, replace the key construction:

```python
    for h in hyps:
        # @g.comment -- "A correlated desktop threat has neither http_path nor function_name, so the original three-part key collapsed every threat sharing a source file into one — silently discarding real findings (navigationManager.ts contributes two distinct threats, deeplink-injection and ui-spoof, with identical candidate sets). Keying those on the threat's own id instead keeps them distinct, while HTTP hypotheses keep the exact key they had, so web dedupe behaviour is unchanged."
        candidates = (h.raw or {}).get("candidate_channels")
        if candidates and not h.http_path:
            key = ("IPC-CANDIDATES", h.id, tuple(candidates))
        else:
            key = (h.http_method or "", h.http_path or "", h.function_name or "")
        bucket.setdefault(key, []).append(h)
```

- [ ] **Step 5: Give the model the candidates**

Find where the IPC hypothesis context is assembled for the prompt (the `reachable_via` block described in the ai-ipc spec) and add the candidate list. Frame them as candidates to choose among, not a channel to call:

```python
    candidates = (hypothesis.raw or {}).get("candidate_channels") or []
    if candidates:
        context += (
            "\nCANDIDATE CHANNELS — this threat was reported at a source file that "
            "registers the following IPC channels. One or more of them is the entry "
            "point for this threat; they are candidates, not an answer. Read the "
            "handler for each in the codebase and probe the one(s) the threat "
            "description actually describes. Do NOT probe all of them blindly, and "
            "do NOT invent a channel name that is not on this list.\n"
            + "\n".join(f"  - {c}" for c in candidates) + "\n")
```

Match the surrounding code's existing string-assembly style. If the context is built by a helper rather than by `+=`, follow that shape instead.

- [ ] **Step 6: Run the tests**

Run: `cd pentest && python -m pytest tests/ -q`
Expected: PASS. Pay attention to any pre-existing `js_generator` test — this function is on the web path.

- [ ] **Step 7: Commit**

```bash
git add pentest/js_generator.py pentest/tests/test_js_generator.py
git commit -m "feat(pentest): make correlated desktop threats runnable"
```

---

### Task 5: Wire correlation in and report review-only threats

**Files:**
- Modify: `pentest/cxg_pentest.py` (`build_hypotheses` call path, report dict, console output, `build_report_caveats`)
- Test: `pentest/tests/test_cxg_pentest.py`

**Interfaces:**
- Consumes: `threat_correlation.correlate` (Task 3); the runnable filter (Task 4).
- Produces: `report["review_only_threats"]`; a caveat entry when the list is non-empty.

- [ ] **Step 1: Write the failing tests**

```python
def test_caveat_names_review_only_count():
    import cxg_pentest
    caveats = cxg_pentest.build_report_caveats(
        "electron", {"desktop_instances_seeded": [True]}, review_only_count=10)
    assert any("10" in c["message"] and "review" in c["message"].lower()
               for c in caveats)


def test_no_review_only_caveat_when_none():
    import cxg_pentest
    caveats = cxg_pentest.build_report_caveats(
        "electron", {"desktop_instances_seeded": [True]}, review_only_count=0)
    assert not any("review-only" in c["message"] for c in caveats)


def test_web_target_still_has_no_caveats():
    import cxg_pentest
    assert cxg_pentest.build_report_caveats("web", None, review_only_count=0) == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd pentest && python -m pytest tests/test_cxg_pentest.py -q -k "review_only or web_target_still"`
Expected: FAIL — `build_report_caveats` takes no `review_only_count`.

- [ ] **Step 3: Add the caveat**

Give `build_report_caveats` a third parameter defaulting to `0`, so every existing call site keeps working. Append after the existing seeded caveat:

```python
    # @g.comment -- "Puts the coverage gap in the artifact, not only on stdout. A desktop report whose findings list is short is otherwise indistinguishable from a clean result, when in fact a portion of what guardlink found was never runtime-tested at all because no IPC channel reaches it. Stating the count and pointing at the list is what keeps 'we did not test this' from reading as 'this is fine'."
    if review_only_count:
        out.append({
            "severity": "medium",
            "affects": ["confirmed_findings", "mitigation_verifications", "ambiguous"],
            "message": (
                f"{review_only_count} guardlink threat(s) were NOT runtime-tested: no IPC "
                "channel is registered in the source file each was reported at, so no "
                "renderer-side probe can reach them. They are listed under "
                "review_only_threats with a per-threat reason. These are neither "
                "confirmed nor refuted — cxg never probed them, and they require "
                "human review. Absence from the findings lists below does not mean "
                "they are safe."
            ),
        })
```

Adapt to however the existing function accumulates its entries — read it before editing; it may return a literal list rather than appending to `out`.

- [ ] **Step 4: Wire correlation into the run**

In the JS pipeline path, after `build_hypotheses` and `split_config_hypotheses`, before the generator is invoked. The IPC hypotheses to correlate against are the ones already in `hyps`:

```python
        # @g.comment -- "Splits routeless guardlink threats into probeable and review-only before generation, so the generator receives only hypotheses it has an entry point for. Runs on the desktop path only: a web scan's threats all carry HTTP routes and pass through correlate() untouched, but calling it there would be pointless work on the hot path."
        review_only = []
        if args.target_type == "electron":
            import threat_correlation
            ipc_hyps = [h for h in hyps if h.http_method == "IPC"]
            generator_input, review_only = threat_correlation.correlate(
                generator_input, ipc_hyps, str(cb))
            print(f"[1c] routeless threats: {len(generator_input) - len(ipc_hyps)} "
                  f"correlated to candidate channels, {len(review_only)} review-only")
```

Use the actual local variable names at that point in the file — `generator_input` is what `split_config_hypotheses` returns first. Read the surrounding lines before editing.

- [ ] **Step 5: Add to the report and console**

In the report dict, beside `"ambiguous"`:

```python
            "review_only_threats": [h.to_dict() for h in review_only],
```

And update the caveats call:

```python
            "caveats": build_report_caveats(args.target_type, substrate.describe(),
                                            review_only_count=len(review_only)),
```

Add a console section after the AMBIGUOUS block, following the existing heading style:

```python
        if review_only:
            print("=" * 72)
            print("NOT RUNTIME-TESTED (review only)")
            print("=" * 72)
            for h in review_only:
                print(f"  · {h.vuln_class:25s} {h.file}:{h.line}")
                print(f"      {h.raw.get('review_only_reason', '')}")
            print()
```

- [ ] **Step 6: Run the full suite**

Run: `cd pentest && python -m pytest tests/ -q`
Expected: PASS with zero failures.

- [ ] **Step 7: Verify against the fixture end to end**

Run: `cd pentest && python -m pytest tests/ -q -k electron`
Expected: PASS. Report in your report file how many channels the fixture now yields versus before.

- [ ] **Step 8: Commit**

```bash
git add pentest/cxg_pentest.py pentest/tests/test_cxg_pentest.py
git commit -m "feat(pentest): report threats no IPC channel can reach"
```

---

## Self-Review Notes

**Spec coverage.** Gap 1 → Tasks 1–2. Gap 2 → Tasks 3–4. Reporting → Task 5. The spec's `review_only`-never-reaches-generator rule is enforced in Task 4 Step 3 and tested there.

**Known cross-task risks, called out in the tasks that own them:**
- Task 1 Step 4 changes regex group numbering — every `_RE_IPC_HANDLER` call site must move to named groups.
- Task 2 Step 3 precedence: constant lookup must precede the passthrough comparison.
- Task 3 path normalisation: absolute vs relative `file` is a silent-zero-match failure. The
  fallback branch must not strip leading characters — doing so lets an out-of-tree or
  `..`-escaping path collide with a real relative key and produce a false correlation.
- Task 4 Step 4 dedupe key: routeless threats sharing a file would otherwise collapse.

**Not verified by any test in this plan**, and deliberately so: that the model, given candidate channels, picks the right one. That requires a live call. Run it by hand against the Mattermost tree after Task 5 and record the result; do not gate CI on it.
