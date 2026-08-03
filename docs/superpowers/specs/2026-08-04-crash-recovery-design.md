# Crash recovery: restart the app, keep scanning, report the crash

**Status:** design approved, not implemented
**Date:** 2026-08-04

## Context

On a live Mattermost Desktop scan a generated template invoked an IPC channel
whose handler is:

```ts
// src/main/security/permissionsManager.ts:269
private openWindowsCameraPreferences = () => shell.openExternal('ms-settings:privacy-webcam');
```

registered at `:75` with a bare `ipcMain.on` — no `event` parameter at all, no
schema, no platform guard. `ms-settings:` is a Windows scheme; on macOS the OS
had no handler, Electron threw, nothing caught it, and the main process died
with `Internal error: No application found to open URL`.

cxg's response was to lose four templates and report nothing about it. An
earlier run of the same shape lost sixteen and ran for 4,600 seconds against a
dead process.

The dead-target work (`3f57279`, `ff591f4`) fixed the *reporting*: such a run
now stops, carries a truncation caveat, and exits 3 instead of 0. This design
addresses the two things that fix deliberately left alone:

1. The scan still ends. Coverage bought at 3–6 minutes per generated template
   is discarded because one probe killed the target.
2. **The crash itself is a finding and is thrown away.** A renderer-reachable
   channel that terminates the main process is availability impact from an
   unprivileged caller — CWE-248 / CWE-754. cxg found it and recorded nothing.

## Decisions

| Decision | Rationale |
|---|---|
| Detection and recovery stay structural; no model in the loop | The rule is deterministic — dispatch raised target-closed, `verify()` says dead, restart. A model adds latency and a way to be wrong about a fact already in hand. |
| `restart(index)` is **optional** on the `Substrate` protocol | `WebSubstrate` and the test `FakeSubstrate` must keep satisfying `@runtime_checkable Substrate` (`tests/test_js_engine_seam.py:86`). Absent means unsupported, not broken. |
| Restart returns a **fresh `Surface`**, same `index` and `profile` | Both are baked into evaluated JS (`bridge.py:275` reads `identities[surface.index]`, `electron.py:415` serialises `surface.index`). A fresh object also gives a clean `extra` dict, which is what avoids the accumulation bug below. |
| The crash is reported as `denial_of_service`, engine-authored | Two precedents already exist: `host_probes.py:117` and `config_probes.py:201` construct `Finding` directly. `Finding` has no provenance field and nothing filters on one. |
| Attribution is by temporal proximity and says so | The audit log proves *what was in flight*, not *what caused it*. An async handler firing late would name the wrong template. |
| A single-channel re-probe after restart converts correlation to causation | Deterministic experiment, not a judgement. Dies again → reproducible. Survives → the attribution was wrong and the report says so. |
| Re-probe once, then quarantine | Reproduction is worth more than the one template it may cost. |
| A fully recovered run exits **2/0**; a partially recovered one exits **3** | `scan_exit_code` checks truncation first, deliberately, so a finding cannot mask a truncation. Recovery must therefore drive `never_executed` to 0 to earn exit 2 — it is not enough to have restarted. |
| `--no-restart` escape hatch | Recovery lets cxg's probes restart the operator's application repeatedly. On a real engagement that is a side effect the operator must be able to decline. |

## Architecture

### 1. `Substrate.restart(index)`

```python
async def restart(self, index: int) -> Surface: ...
```

`WebSubstrate` does not implement it. The engine checks
`hasattr(substrate, "restart")` and falls through to today's hard-kill when
absent.

**`ElectronSubstrate.restart(index)` must:**

- **Allocate a fresh port.** Never reuse `surface.extra["cdp_port"]`.
  `_connect` (`electron.py:242`) polls `connect_over_cdp` and only bails when
  the proc it was handed has exited; if the crashed tree is not fully reaped, a
  reused port attaches to the **zombie's** CDP endpoint and reports success.
  Silent wrong-process attachment is worse than a bind failure.
- **Resolve the old process by `surface.extra["pid"]`, not by list index.**
  `_procs.append` (`:312`) happens *before* the connect and `_browsers.append`
  (`:335`) *after* it, so on the `break` path (`:329`) the two lists are
  different lengths. Index lookup is unsound. Add an explicit per-instance
  record rather than patching around it.
- **Tear down one instance only.** `close()` (`:463-477`) is all-or-nothing and
  ends with `await self._playwright.stop()`. A new `_close_one(index)` must
  close that browser, terminate that process tree, drop both from their lists,
  and **never touch `self._playwright`**, which is shared.
- **Wipe `instance-{i}` before reseeding.** A crashed Electron leaves its own
  `SingletonLock` symlink in that directory. `_SEED_EXCLUDE_LOCK_NAMES`
  (`:48`) excludes those names from the *source* copy only, and the copy is
  `dirs_exist_ok=True` (`:272`), so a stale lock survives into the relaunch.
  Chromium usually reclaims a stale lock whose pid is dead — not reliably when
  the pid has been recycled. `rmtree(user_data_dir, ignore_errors=True)` first.
- **Assign, never append, to `instances_seeded`.** `describe()['desktop_instances_seeded']`
  is read positionally by `build_report_caveats` (`cxg_pentest.py:232`, "in
  open() order"); `tests/test_electron_substrate.py:413` pins it exactly.
- **Not set `single_instance_lock_detected`.** That flag means "instance ≥1
  died fast at launch" and feeds an operator-facing caveat. A restart failing
  minutes into a run, while other instances are healthy, is not evidence about
  the app's singleton lock.
- **Use a restart timeout distinct from `BOOT_TIMEOUT_SECONDS = 90`.** Worst
  case today a restart stalls the event loop ~110 s across `copytree`, `Popen`,
  two `proc.wait(timeout=10)` calls and the connect poll.

### 2. Reviving the identity — the contentious part

`results.dead_profiles` is **append-only by documented contract**
(`js_engine.py:234`): *"it never REMOVES a name. Clearing a dead verdict is the
SessionHealthMonitor's job alone."* A desktop run has no monitor, so on that
path a successful restart would leave the identity permanently dead and every
subsequent template skipped at `js_engine.py:562`. Recovery would restart the
app and then decline to use it.

This design introduces a second sanctioned remover, and states the reasoning
plainly rather than quietly widening the invariant: **a substrate that has
replaced the surface is strictly stronger evidence than the `verify()` that
condemned the old one** — it is not overturning a verdict about the same
object, it is reporting a different object. The clear is gated on
`await substrate.verify(new_surface)` returning alive; a restart whose result
does not itself verify leaves the name in place.

The append-only comment must be amended in the same commit, not left
contradicting the code.

### 3. The engine loop

`_handle_template_exception` (`js_engine.py:250-274`) observes the dead target
but does not have `bridge_ctx` in scope — it is a local built in `run()` after
`open()` (`:492-502`) and never stored. The restart decision therefore hoists
into the template loop (`:532-600`), which has both.

`_dead_target_streak` must reset on a successful restart. Otherwise three
raises reach `DEAD_TARGET_KILL_STREAK` (`:174`) and hard-kill before recovery
is useful.

Budgets: **2 restarts per surface, 3 per run.** Exhausting either falls through
to the existing hard-kill, which already produces the truncation caveat and
exit 3.

### 4. The crash finding

Authored by the engine at the point of detection, where `tpl.id` and the streak
are in hand:

```python
Finding(id=f"engine-crash-{channel}", vuln_class="denial_of_service",
        severity="high", confirmed=True, target=..., endpoint=f"ipc://{channel}",
        description=..., evidence={"outcome": "confirmed", ...})
```

`confirmed=True` **and** `evidence.outcome="confirmed"` are both required —
`mutator.py:159` degrades a finding whose flag and outcome disagree. Verified:
`denial_of_service` is not in `_CROSS_IDENTITY_CLASSES` (`mutator.py:70`), so
the overlap guard returns `False` before consulting anything. Do not nest the
raw dispatch result under `evidence.raw`; it carries `dispatch_failed: True`,
which `_evidence_flag` would read.

Evidence must carry: the channel, the template in flight, the audit tail, the
restart count, the OS-reported error where available, the re-probe result, and
an explicit `attribution: "temporal proximity, not proven causal"`.

Use a distinct id prefix — `seen_finding_ids` (`js_engine.py:328`) is local to
`run()`, so a collision with a template finding would produce two entries.

`denial_of_service` is added to `ALLOWED_VULN_CLASSES` (`validator.py:19`) and
the `docs/TEMPLATES.md:99` table. Not strictly required — that list gates
template source validation only, and `host_probes.py:191` already ships a class
outside it — but leaving it out is an inconsistency.

### 5. The audit ring

`AuditLog` (`scope.py:165-209`) is write-only; its entire state is a file
handle and a counter. The data already exists on disk — `electron.py:391`
audits every IPC dispatch *including the failed one*, carrying channel and
template id — but the process has no API to read it back.

Add a bounded `collections.deque(maxlen=N)` appended inside `_write` under the
existing lock, plus a `recent()` reader. Single choke point, no new concurrency
surface.

Separately, widen `AuditLog.request` to carry the dispatch-failure reason. A
crash-killed dispatch currently records `status: 0` with an empty
`blocked_reason`, indistinguishable from any other failure.

### 6. Re-probe and quarantine

After a successful restart, re-invoke the suspected channel alone, with no
other probe in flight.

- **Dies again** → causal. Upgrade the finding to reproducible, record both
  crashes, quarantine the channel for the rest of the run.
- **Survives** → the attribution was wrong. Say so in the evidence, keep the
  finding as an unattributed crash, quarantine anyway.

Quarantined channels are listed in the report so a reader knows which probes
were withheld and why.

## Testing

No test may launch Electron, invoke a live model, or read the Mattermost
checkout. `tests/test_js_engine_seam.py` already has `FakePage`, `FakeContext`
and `FakeSubstrate` doubles; extend them with a restart-capable fake.

- Restart returns a fresh `Surface` with the same index and profile; the engine
  assigns it into the shared list slot and `fetch_as_router` picks it up.
- `dead_profiles` is cleared **only** when the restarted surface verifies alive;
  a restart whose `verify()` fails leaves the name in place.
- The streak resets on successful restart; it does not reset on a failed one.
- Budgets: 2 per surface and 3 per run each fall through to the existing
  hard-kill, producing the truncation caveat and exit 3.
- A fully recovered run has `never_executed == 0`, no truncation caveat, and
  exits 2 when it found something.
- The crash finding survives triage as confirmed, is not caught by the overlap
  guard, and reaches `report.json`.
- Re-probe: dies-again upgrades to reproducible; survives records the wrong
  attribution rather than deleting the finding.
- `--no-restart` reproduces today's behaviour exactly.
- A web run is unchanged: no `restart` attribute, same hard-kill path.
- `instances_seeded` stays the same length as `surfaces` across restarts —
  `tests/test_electron_substrate.py:413` and `test_e2e_electron.py:150` pin it.

## Out of scope

- Per-template timeouts. A crash that *hangs* rather than raises is a separate
  gap: `page.evaluate` is awaited unbounded, so a blocked main process still
  freezes the scan with zero output. That is the next piece of work and this
  design does not cover it.
- Restarting a web browser context.
- Teaching the generator to avoid crash-prone channels. Quarantine is a runtime
  measure; a `@destructive_priority` prompt rule is separate work.
- Re-running `config_probes` after a restart. `on_surfaces_ready` fires once
  before the loop (`js_engine.py:514`); claims collected from the pre-crash
  instance stay valid, since the new instance is derived from the same argv.

## Validation

1. A fixture scan where the substrate dies mid-run recovers, executes every
   remaining template, and exits 2 with the crash finding present.
2. The same scan with `--no-restart` behaves exactly as it does today.
3. A restart-budget exhaustion produces the truncation caveat and exit 3.
4. The full Python suite passes; web-target behaviour is unchanged.
5. Run by hand against Mattermost Desktop: the `ms-settings:` crash is
   recovered from, re-probed, confirmed reproducible, and reported as
   `denial_of_service` with the channel named.
