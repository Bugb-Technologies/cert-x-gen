# Crash Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** When a probe kills or freezes the target app, restart it, keep scanning, and report the crash as a finding — without ever letting a post-restart refusal become a false refutation.

**Spec:** `docs/superpowers/specs/2026-08-04-crash-recovery-design.md` — read it before starting; it records why two obvious designs were rejected.

**Tech Stack:** Python 3.11+, stdlib + existing playwright. No new dependencies.

## Global Constraints

- No new third-party dependencies. Use `python3`; `python` is not on PATH.
- Suite: `cd pentest && python3 -m pytest tests/ -q`. **500 passing** at branch head.
- Every new/changed function gets a `@g.comment -- "…"` in the file's established voice: long, specific, naming the concrete failure prevented. Read neighbours first.
- No test may launch Electron, invoke a live model, or read `/Users/zippon/src/mattermost-desktop`. Reuse `FakePage`/`FakeContext`/`FakeSubstrate` in `tests/test_js_engine_seam.py`.
- **Web-target behaviour must be unchanged throughout.** `WebSubstrate` gets no `restart`; a web run must take exactly today's path.
- `restart` is OPTIONAL on the `Substrate` protocol — `WebSubstrate` and `FakeSubstrate` must keep satisfying `@runtime_checkable Substrate`.
- `results.dead_profiles` stays append-only. Do NOT add a remover. The third state sits beside it.
- Never reuse a crashed instance's CDP port. Never touch `self._playwright` in per-instance teardown.

---

### Task 1: Audit ring + dispatch-failure reason

**Files:** Modify `pentest/scope.py`; Test `pentest/tests/test_scope.py`

`AuditLog` (`scope.py:165-209`) is write-only — state is a file handle and a counter. The data needed to attribute a crash already goes to disk (`electron.py:391` audits every IPC dispatch including failed ones, carrying channel + template id); the process just cannot read it back.

- [ ] **Step 1:** Add a bounded `collections.deque(maxlen=200)` appended inside `_write`, under the existing lock — one choke point, no new concurrency surface. Add `recent(n=None, event=None) -> list[dict]`.
- [ ] **Step 2:** Widen `AuditLog.request` with an optional `failure_reason: str = ""` field, written into the entry. A crash-killed dispatch currently records `status: 0` with empty `blocked_reason`, indistinguishable from any other failure.
- [ ] **Step 3:** Pass the dispatch failure text from `targets/electron.py`'s IPC audit call (`electron.py:391`) — `unreachable` / `dispatch_failed` / the error string.
- [ ] **Step 4:** Tests — ring bounded at maxlen; `recent()` returns newest-last; filtering by event works; existing on-disk format unchanged for entries that pass no `failure_reason`; concurrent writes do not corrupt the ring.
- [ ] **Step 5:** Commit.

---

### Task 2: Stall detection

**Files:** Modify `pentest/js_engine.py`, `pentest/cxg_pentest.py` (flags); Test `pentest/tests/test_js_engine_seam.py`

A frozen app never raises, so the dead-target machinery never fires. A fixed per-template deadline is wrong — generated templates legitimately run minutes.

**Signal: time since the last COMPLETED dispatch**, read from Task 1's ring. A slow probe keeps writing audit entries; a stalled one stops.

- [ ] **Step 1:** Wrap the template dispatch in `asyncio.wait_for` against an *absolute ceiling* (default 900 s, operator-settable via `--template-timeout`). This is the backstop only.
- [ ] **Step 2:** Add a stall watchdog: a task that wakes every ~10 s and compares `audit.recent(event="request")[-1]["ts"]` against now. Default stall threshold 90 s, settable via `--stall-timeout`.
- [ ] **Step 3:** **Cross-instance corroboration.** On suspecting a stall, issue a trivial `page.evaluate("1")` to a *different* surface with a short timeout.
  - other answers, this one silent → this instance stalled; raise the same dead-target error shape so it enters the existing path.
  - all silent → environmental; hard-kill with that reason, do NOT attribute to a template, do NOT restart.
- [ ] **Step 4:** Tests — a template completing dispatches for 3× the stall threshold is NOT killed; a template producing no dispatches for the threshold IS; cross-instance disambiguation both ways; the absolute ceiling fires independently.
- [ ] **Step 5:** Commit.

---

### Task 3: `ElectronSubstrate.restart(index)`

**Files:** Modify `pentest/targets/base.py`, `pentest/targets/electron.py`; Test `pentest/tests/test_electron_substrate.py`

- [ ] **Step 1:** Add `restart(self, index: int) -> Surface` to the `Substrate` protocol as OPTIONAL (documented; engine uses `hasattr`). `WebSubstrate` does not implement it.
- [ ] **Step 2:** Add an explicit per-instance record (`self._instances: dict[int, ...]` holding proc, browser, port, user_data_dir, pid). `_procs`/`_browsers` desync — `_procs.append` (`:312`) precedes the connect, `_browsers.append` (`:335`) follows it — so index lookup is unsound.
- [ ] **Step 3:** `_close_one(index)`: close that browser, `_terminate_process_tree` that proc, drop from the records. **Never** touch `self._playwright`.
- [ ] **Step 4:** `restart(index)`: `_close_one` → `rmtree(user_data_dir, ignore_errors=True)` (a crashed Electron leaves its own `SingletonLock`; `_SEED_EXCLUDE_LOCK_NAMES` excludes it from the SOURCE only and the copy is `dirs_exist_ok=True`) → reseed → **fresh** `_free_port()` → spawn → connect → return a **new `Surface`** with the same `index` and `profile`, fresh `extra` carrying `user_data_dir`/`cdp_port`/`pid`/`seeded` (`cxg_pentest.py:383,393` read those keys).
- [ ] **Step 5:** `self.instances_seeded[index] = seeded` — **assign, never append**. `describe()['desktop_instances_seeded']` is read positionally (`cxg_pentest.py:232`); `tests/test_electron_substrate.py:413` pins it.
- [ ] **Step 6:** Do NOT set `single_instance_lock_detected` on a restart failure — that flag means "instance ≥1 died fast at launch" and feeds an operator caveat. Use a distinct restart timeout, not `BOOT_TIMEOUT_SECONDS = 90`.
- [ ] **Step 7:** Tests — fresh port never equals the old; `_playwright` untouched; `instances_seeded` stays the same length as surfaces; the returned Surface keeps index and profile; a failed restart raises cleanly rather than aborting the run.
- [ ] **Step 8:** Commit.

---

### Task 4: The third state — confirmations survive, refutations degrade

**Files:** Modify `pentest/js_engine.py`, `pentest/mutator.py`; Test `pentest/tests/test_cross_identity_overlap.py` or a new file

**This is the correctness core. Read spec §2 before writing a line.**

`ElectronSubstrate.verify()` proves only that the renderer evaluates JS, NOT that the session is authenticated. So clearing `dead_profiles` after a restart would let an app that came back logged out record every refusal as a refutation — the false-refutation failure this codebase fights hardest.

- [ ] **Step 1:** Track restarted surfaces on `EngineResults` (e.g. `restarted_profiles: list[str]`) and make the per-template skip at `js_engine.py:562` treat "restarted" as schedulable, while `dead_profiles` stays append-only and untouched.
- [ ] **Step 2:** Thread "this finding came from a restarted surface" into triage. `classify()` degrades a `refuted` verdict from such a surface to `ambiguous`, `reason_kind="environment"`, reason naming the restart. **Confirmations pass through untouched** — a possibly-logged-out renderer that still gets a permission granted is a *stronger* finding, not a weaker one.
- [ ] **Step 3:** Record which templates ran degraded, for the report.
- [ ] **Step 4:** Tests — a refutation from a restarted surface degrades; a confirmation does not; an unevaluated stays unevaluated; a finding from a never-restarted surface is untouched in a run where another surface *was* restarted; `dead_profiles` is never shortened.
- [ ] **Step 5:** Commit.

---

### Task 5: Wire it up — recovery loop, crash finding, re-probe, report

**Files:** Modify `pentest/js_engine.py`, `pentest/cxg_pentest.py`, `pentest/validator.py`, `pentest/docs/TEMPLATES.md`; Tests across both suites

- [ ] **Step 1:** Hoist the restart decision into the template loop (`js_engine.py:532-600`) — `_handle_template_exception` does not have `bridge_ctx` in scope; it is a local built after `open()` (`:492-502`). After `substrate.restart(index)`, call `substrate.install_bridge(new_surface, bridge_ctx, self.profiles)` and assign into the shared `surfaces` slot.
- [ ] **Step 2:** Reset `_dead_target_streak` on a successful restart — otherwise 3 raises hit `DEAD_TARGET_KILL_STREAK` (`:174`) before recovery is useful. Budgets: **2 restarts per surface, 3 per run**; exhausting either falls through to the existing hard-kill.
- [ ] **Step 3:** Author the crash finding at the point of detection: `vuln_class="denial_of_service"`, `confirmed=True` **and** `evidence.outcome="confirmed"` (`mutator.py:159` degrades a finding whose flag and outcome disagree). Distinct id prefix (`engine-crash-<channel>`). Evidence carries channel, template in flight, audit tail from Task 1, restart count, re-probe result, and `attribution: "temporal proximity, not proven causal"`. Do NOT nest the raw dispatch result under `evidence.raw` — it carries `dispatch_failed: True`, which `_evidence_flag` reads.
- [ ] **Step 4:** Re-probe: after restart, invoke the suspected channel alone. Dies again → mark reproducible. Survives → record that the attribution was wrong, keep the finding as unattributed. Quarantine the channel either way; list quarantined channels in the report.
- [ ] **Step 5:** Add `denial_of_service` to `ALLOWED_VULN_CLASSES` (`validator.py:19`) and the `docs/TEMPLATES.md:99` table.
- [ ] **Step 6:** Add `--no-restart`, `--stall-timeout`, `--template-timeout` flags. `--no-restart` must reproduce today's behaviour exactly.
- [ ] **Step 7:** Caveat naming which templates ran degraded, plus restart count. A fully recovered run has `never_executed == 0` and exits 2; a partial one still exits 3.
- [ ] **Step 8:** Tests — full recovery executes every template and exits 2; budget exhaustion produces the truncation caveat and exit 3; the crash finding survives triage and reaches `report.json`; `--no-restart` is byte-identical to today; a web run is unchanged.
- [ ] **Step 9:** Commit.
