# AI-Generated IPC Templates and Structural Triage Outcome — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `cxg pentest --ai` generate working Electron IPC probe templates, and make triage classify their results from structural evidence rather than English prose.

**Architecture:** `js_generator.py` gains a second system prompt selected when a hypothesis's `http_method` is `IPC`, leaving the HTTP prompt untouched. `mutator.classify()` gains a precedence chain — explicit `evidence.outcome` first, then structural evidence, then today's prose rules as a legacy fallback — reusing the `{confirmed, refuted, unevaluated}` vocabulary `config_probes` already ships. `validator.py` gains a hard error for a template that uses `cxg.ipc.*` without declaring the capability.

**Tech Stack:** Python 3.12+, pytest, the existing `claude` CLI provider integration.

## Global Constraints

Copied from `docs/superpowers/specs/2026-08-02-ai-ipc-templates-design.md`:

- The HTTP system prompt (`js_generator.py:26-146`) is **not modified**. Branching exists so web generation quality is untouched.
- `evidence.outcome` uses exactly `{"confirmed", "refuted", "unevaluated"}` — the vocabulary `config_probes.py` already ships.
- `classify()` maps `unevaluated → TriageVerdict("ambiguous", reason_kind="environment")`. `reason_kind="environment"` is load-bearing: it tells the mutator no retry can fix this.
- Prose matching is **retained** as the last resort. Every existing hand-written template must keep working.
- `evidence.unreachable` becomes ambiguous/environment, never refuted. "I could not reach it" is not "it is defended".
- An unrecognised `outcome` value falls through to structural evidence — never guessed into a bucket.
- `CONFIG` hypotheses still never reach the generator.
- Python style per existing `pentest/` modules: `from __future__ import annotations`, `list[str]` generics, module docstrings.
- Every new or changed Python item carries a `@g.comment` annotation directly above it, in the form `-- "description"`, including test functions. `docs/GAL_AGENT_REFERENCE.md` does not exist (issue #35) — follow the convention used by surrounding `pentest/` modules.
- No CI test may depend on a live model call.

## File structure

| File | Responsibility | Change |
|---|---|---|
| `pentest/mutator.py` | Deterministic triage classification | Restructure `classify()` head; add precedence chain; reorder env signals |
| `pentest/validator.py` | Pre-execution template validation | Add capability-declaration hard error |
| `pentest/js_generator.py` | AI template generation | Add `IPC_SYSTEM_PROMPT`; branch prompt selection; surface `reachable_via` |
| `pentest/docs/TEMPLATES.md` | Template authoring contract | Correct the `unreachable` → refutation instruction |
| `pentest/tests/fixtures/vuln-electron-manual-templates/manual-secure-read-config-control.js` | Committed control template | Emit `outcome`; stop conflating unreachable with refuted |
| `pentest/tests/test_mutator_outcome.py` | New | Precedence, mapping, both rule changes, prose corpus |
| `pentest/tests/test_validator_desktop.py` | Existing | Add capability-gate cases |
| `pentest/tests/test_js_generator_ipc.py` | New | Prompt selection, no model invoked |
| `pentest/tests/fixtures/generated-ipc-template/` | New | One real generated template, committed |

## Task order

Task 1 first because Tasks 3 and 4 both depend on the `outcome` contract existing. Task 1 is also the highest-risk change in the plan — it rewrites a function every web scan depends on.

---

### Task 1: Structural outcome precedence in `classify()`

**Files:**
- Modify: `pentest/mutator.py:56-211` (`classify`)
- Create: `pentest/tests/test_mutator_outcome.py`

**Interfaces:**
- Consumes: `TriageVerdict(kind, reason, reason_kind)` from `pentest/mutator.py:30`.
- Produces: `classify(finding: dict) -> TriageVerdict` with the precedence chain below. Later tasks rely on `evidence["outcome"]` ∈ `{"confirmed","refuted","unevaluated"}` being authoritative.

- [ ] **Step 1: Write the characterization test that freezes today's prose behaviour**

This runs **before** any change, capturing what `classify()` does now so the refactor cannot silently alter it.

Create `pentest/tests/test_mutator_outcome.py`:

```python
"""Tests for structural outcome precedence in mutator.classify().

The corpus test is a characterization test: it freezes the prose-path verdicts
that existed before the precedence chain was added, so the refactor cannot
silently change how any existing hand-written template is classified.
"""
from __future__ import annotations

import pytest

from mutator import classify


# @g.comment -- "Descriptions drawn from the real signal tuples classify() matches on, so the corpus exercises the prose path rather than a synthetic approximation of it."
_PROSE_CORPUS = [
    ("mitigation holds: owner-scoping enforced on the target object", "refuted"),
    ("the validation is effective; payload was stripped", "refuted"),
    ("no finding raised against the application", "refuted"),
    ("all probed identities have the same role; re-run with a low-privilege user", "ambiguous"),
    ("blind ssrf — no oob callback url was configured for this run", "ambiguous"),
    ("server rejected the request outright", "refuted"),
]


# @g.comment -- "Pins that every prose description classifies exactly as it did before the precedence chain existed; a change here means an existing template's verdict moved."
@pytest.mark.parametrize("desc,expected_kind", _PROSE_CORPUS)
def test_prose_path_verdicts_are_unchanged(desc, expected_kind):
    verdict = classify({"confirmed": False, "description": desc, "evidence": {}})
    assert verdict.kind == expected_kind


# @g.comment -- "Pins that an environment-bound signal wins over a mitigation-hold phrase in the same description — the ordering bug this task fixes."
def test_environment_signal_beats_a_mitigation_hold_phrase():
    verdict = classify({
        "confirmed": False,
        "description": "mitigation holds: no exploitation observed; only one identity available",
        "evidence": {},
    })
    assert verdict.kind == "ambiguous"
    assert verdict.reason_kind == "environment"
```

- [ ] **Step 2: Run it and record which tests fail**

Run: `cd pentest && python -m pytest tests/test_mutator_outcome.py -v`

Expected: the six `test_prose_path_verdicts_are_unchanged` cases PASS (they describe current behaviour). `test_environment_signal_beats_a_mitigation_hold_phrase` FAILS with `assert 'refuted' == 'ambiguous'` — because `_MITIGATION_HOLD_SIGNALS` is tested at `mutator.py:174`, before `_ENV_BOUND_SIGNALS` at `:180`.

If any corpus case fails, **stop and report it** — the corpus is meant to describe reality, and a failure means the description does not match what `classify()` actually does. Adjust the corpus to reality, not reality to the corpus.

- [ ] **Step 3: Add the precedence tests**

Append to `pentest/tests/test_mutator_outcome.py`:

```python
# @g.comment -- "Pins that an explicit outcome field overrides the prose path entirely, which is the whole point of the structural contract."
@pytest.mark.parametrize("outcome,expected_kind", [
    ("confirmed", "confirmed"),
    ("refuted", "refuted"),
    ("unevaluated", "ambiguous"),
])
def test_explicit_outcome_is_authoritative(outcome, expected_kind):
    verdict = classify({
        "confirmed": False,
        "description": "mitigation holds",   # prose says refuted; outcome must win
        "evidence": {"outcome": outcome},
    })
    assert verdict.kind == expected_kind


# @g.comment -- "Pins the vocabulary bridge: config_probes' 'unevaluated' becomes ambiguous with reason_kind=environment, which is what stops the mutator burning AI retries on an unfixable result."
def test_unevaluated_maps_to_environment_bound_ambiguity():
    verdict = classify({
        "confirmed": False,
        "description": "",
        "evidence": {"outcome": "unevaluated"},
    })
    assert verdict.kind == "ambiguous"
    assert verdict.reason_kind == "environment"


# @g.comment -- "Pins that an unrecognised outcome value is never guessed into a bucket — it falls through to the remaining evidence."
def test_unrecognised_outcome_falls_through_rather_than_guessing():
    verdict = classify({
        "confirmed": False,
        "description": "mitigation holds",
        "evidence": {"outcome": "banana"},
    })
    assert verdict.kind == "refuted"   # reached the prose path, not guessed


# @g.comment -- "Pins that a channel the probe never reached is ambiguous, not a refutation — closes the rule behind four false refutations on the desktop branch."
def test_unreachable_is_ambiguous_not_refuted():
    verdict = classify({
        "confirmed": False,
        "description": "mitigation holds: nothing was returned",
        "evidence": {"unreachable": True},
    })
    assert verdict.kind == "ambiguous"
    assert verdict.reason_kind == "environment"


# @g.comment -- "Pins that a scope-blocked call is environment-bound; retrying the payload cannot change a scope decision."
def test_blocked_is_environment_bound_ambiguity():
    verdict = classify({
        "confirmed": False,
        "description": "",
        "evidence": {"blocked": True, "blocked_reason": "per-endpoint budget exhausted"},
    })
    assert verdict.kind == "ambiguous"
    assert verdict.reason_kind == "environment"


# @g.comment -- "Pins that a confirmed=true finding with an explicit confirmed outcome still requires evidence, preserving the pre-existing sanity check."
def test_confirmed_outcome_without_evidence_is_still_ambiguous():
    verdict = classify({"confirmed": True, "description": "", "evidence": {}})
    assert verdict.kind == "ambiguous"
```

- [ ] **Step 4: Run them to verify they fail for the expected reasons**

Run: `cd pentest && python -m pytest tests/test_mutator_outcome.py -v`

Expected failures: every `outcome`-based test fails because `classify()` never reads that key; `test_unreachable_is_ambiguous_not_refuted` fails with `'refuted' == 'ambiguous'`; `test_blocked_is_environment_bound_ambiguity` fails. `test_confirmed_outcome_without_evidence_is_still_ambiguous` should already PASS (`mutator.py:59-63`).

- [ ] **Step 5: Restructure the head of `classify()`**

`classify()` currently returns on `finding.get("confirmed") is True` at `mutator.py:58` — **before** evidence is extracted at `:70`. Since `outcome` lives inside evidence, extraction must move above the confirmed check.

Replace `mutator.py:56-77` with:

```python
# @g.comment -- "Recognised structural outcomes, matching the vocabulary config_probes.py already emits so both evidence producers speak one language."
_OUTCOME_TO_VERDICT = {
    "confirmed": ("confirmed", "template reported an explicit confirmed outcome", "payload"),
    "refuted": ("refuted", "template reported an explicit refuted outcome", "payload"),
    "unevaluated": ("ambiguous",
                    "template could not evaluate this probe; no retry will fix it",
                    "environment"),
}


# @g.comment -- "Deterministic triage. Precedence is explicit outcome, then structural evidence, then legacy prose matching — so a correct verdict never depends on the wording a model happened to choose."
def classify(finding: dict) -> TriageVerdict:
    """Pure-function classifier — no AI."""
    # Defensive: AI sometimes emits evidence as a string instead of a dict.
    ev_raw = finding.get("evidence") or {}
    if isinstance(ev_raw, dict):
        ev = ev_raw
    else:
        # Wrap stringy evidence so the rest of classify() still works
        ev = {"_raw_evidence": str(ev_raw)}

    # 1. Explicit structural outcome wins over everything else.
    #    No empty-evidence guard is needed here: reading `outcome` at all proves
    #    evidence is a non-empty dict.
    mapped = _OUTCOME_TO_VERDICT.get(ev.get("outcome"))
    if mapped is not None:
        kind, reason, reason_kind = mapped
        return TriageVerdict(kind, reason, reason_kind=reason_kind)

    if finding.get("confirmed") is True:
        # Sanity: a "confirmed" finding without evidence is suspicious
        if not finding.get("evidence"):
            return TriageVerdict("ambiguous",
                                 "marked confirmed but no evidence provided",
                                 reason_kind="payload")
        return TriageVerdict("confirmed",
                             "AI marked confirmed and supplied evidence",
                             reason_kind="payload")

    # 2. Structural evidence, before any prose matching.
    if ev.get("unreachable"):
        return TriageVerdict("ambiguous",
                             "probe never reached the target; this is not a mitigation "
                             "verification",
                             reason_kind="environment")
    if ev.get("blocked"):
        return TriageVerdict("ambiguous",
                             f"call was blocked before dispatch: {ev.get('blocked_reason') or 'scope'}",
                             reason_kind="environment")

    status = ev.get("status") or ev.get("benign_status") or ev.get("escalate_status")
    desc = (finding.get("description") or "").lower()
```

Everything from the original `:79` onward is unchanged for now.

- [ ] **Step 6: Move the environment check above the prose block**

The `_ENV_BOUND_SIGNALS` check currently sits at `mutator.py:180`, after six prose rules that can return `refuted` (at `:123`, `:130`, `:144`, `:154`, `:165`, `:171`) plus the `_MITIGATION_HOLD_SIGNALS` check at `:174`.

Cut this block:

```python
    # Environment-bound ambiguity — re-prompting AI won't help; surface to operator.
    if any(sig in desc for sig in _ENV_BOUND_SIGNALS):
        return TriageVerdict("ambiguous",
                             "environment-bound: AI cannot fix this by retrying "
                             "(missing role tier, missing runtime primitive, OOB needed)",
                             reason_kind="environment")
```

and paste it immediately after the `desc = ...` line you wrote in Step 5, **before** the first prose rule. Add above it:

```python
    # @g.comment -- "Environment-bound signals are tested before every mitigation-hold rule: a probe that lacked the identities or primitives to test something has not verified a mitigation, and the previous ordering reported exactly that as refuted."
```

Note the spec describes this as moving it before `_MITIGATION_HOLD_SIGNALS`; it must move before **all** the refuted-returning prose rules, not just that one, or a description carrying both signals still misclassifies.

- [ ] **Step 7: Run the full suite**

Run: `cd pentest && python -m pytest -v`
Expected: PASS, zero skips, zero warnings. The six corpus cases must still pass — if any moved, the refactor changed an existing template's verdict and must be investigated before proceeding.

- [ ] **Step 8: Commit**

```bash
git add pentest/mutator.py pentest/tests/test_mutator_outcome.py
git commit -m "feat(pentest): classify findings from structural outcome, not prose"
```

---

### Task 2: Validator capability gate

**Files:**
- Modify: `pentest/validator.py`
- Modify: `pentest/tests/test_validator_desktop.py`

**Interfaces:**
- Consumes: `validate(source, destructive_ok=False) -> ValidationResult` from `pentest/validator.py:84`.
- Produces: a hard error when a template calls `cxg.ipc.*` without `@requires_capability: ipc`.

- [ ] **Step 1: Write the failing tests**

Append to `pentest/tests/test_validator_desktop.py`:

```python
# @g.comment -- "Pins that using the IPC API without declaring the capability is rejected before execution, turning a confusing runtime 'Cannot read properties of undefined' into a clear pre-flight error."
def test_cxg_ipc_without_capability_declaration_is_rejected():
    src = """
// @id: t-ipc-nocap
// @vuln_class: idor
async function cxgProbe(cxg) {
    const out = await cxg.ipc.invoke('file:read', '../etc/passwd');
    return [];
}
"""
    r = validate(src)
    assert not r.ok
    assert any("requires_capability" in e for e in r.errors)


# @g.comment -- "Pins that a correctly-declared IPC template still passes, so the new rule cannot reject valid work."
def test_cxg_ipc_with_capability_declaration_is_accepted():
    src = """
// @id: t-ipc-cap
// @vuln_class: idor
// @requires_capability: ipc
async function cxgProbe(cxg) {
    const out = await cxg.ipc.invoke('file:read', '../etc/passwd');
    return [];
}
"""
    assert validate(src).ok


# @g.comment -- "Pins that a template touching no IPC API is unaffected by the new rule."
def test_http_only_template_needs_no_capability_declaration():
    src = """
// @id: t-http
// @vuln_class: idor
async function cxgProbe(cxg) {
    await cxg.fetch('/api/users/1');
    return [];
}
"""
    assert validate(src).ok
```

- [ ] **Step 2: Run to verify the first test fails**

Run: `cd pentest && python -m pytest tests/test_validator_desktop.py -v`
Expected: `test_cxg_ipc_without_capability_declaration_is_rejected` FAILS with `assert not True` — no such rule exists yet. The other two PASS.

- [ ] **Step 3: Add the rule**

Add near the other patterns in `pentest/validator.py`:

```python
# @g.comment -- "Detects any use of the IPC API so the validator can require its capability declaration; the engine's capability gate is opt-in, so without this a generated template missing the annotation runs on a web substrate and throws."
_USES_CXG_IPC = re.compile(r"\bcxg\.ipc\.\w+\s*\(")
```

Add inside `validate()`, next to the raw-`ipcRenderer` check:

```python
    # @g.comment -- "Hard-rejects a template that calls cxg.ipc.* without declaring the capability, matching the raw fetch() and raw ipcRenderer bans in severity and message style."
    if _USES_CXG_IPC.search(source) and meta.get("requires_capability") != "ipc":
        errors.append(
            "template calls cxg.ipc.* but does not declare '@requires_capability: ipc'. "
            "Without the declaration the engine's capability gate cannot skip it on a "
            "substrate that has no IPC, and it will throw at runtime instead.")
```

- [ ] **Step 4: Run to verify all three pass**

Run: `cd pentest && python -m pytest tests/test_validator_desktop.py -v`
Expected: PASS.

- [ ] **Step 5: Confirm the committed fixture templates still validate**

Run: `cd pentest && python -m pytest tests/test_e2e_electron.py -v -k manual`
Expected: PASS or SKIP (skips without fixture `node_modules` — a skip is acceptable, a failure is not).

- [ ] **Step 6: Commit**

```bash
git add pentest/validator.py pentest/tests/test_validator_desktop.py
git commit -m "feat(pentest): require @requires_capability on templates using cxg.ipc"
```

---

### Task 3: The IPC system prompt

**Files:**
- Modify: `pentest/js_generator.py` (add `IPC_SYSTEM_PROMPT`; branch at `:277`; extend the user message at `:259-272`)
- Create: `pentest/tests/test_js_generator_ipc.py`

**Interfaces:**
- Consumes: `generate_js_template(codebase, session_dir, hypothesis, goal, provider, timeout_s)` at `js_generator.py:229`; `SYSTEM_PROMPT` at `:26`.
- Produces: `IPC_SYSTEM_PROMPT` (module-level str) and `select_system_prompt(hypothesis) -> str`, so prompt selection is testable without invoking a model.

- [ ] **Step 1: Write the failing test**

Create `pentest/tests/test_js_generator_ipc.py`:

```python
"""Tests for IPC-aware template generation.

No test here invokes a model — generation is nondeterministic and takes ~105s
per template. These pin prompt *selection* and the context passed into it.
"""
from __future__ import annotations

import js_generator
from guardlink import Hypothesis


# @g.comment -- "Builds a hypothesis in the shape electron_surface.extract() emits for a reachable IPC channel, so prompt-selection tests exercise real field values."
def _ipc_hypothesis(**overrides):
    base = dict(
        id="electron-ipc-file:read", vuln_class="idor", threat="#ipc-channel",
        asset="#file:read", http_method="IPC", http_path="ipc://file:read",
        function_name=None, file="main.js", line=12, severity="high",
        cwe="CWE-862", description="d", confidence=0.9,
        has_mitigation_declared=False,
        raw={"reachable_via": "appApi.readFile", "reachable_via_generic": False,
             "source": "electron_surface"},
    )
    base.update(overrides)
    return Hypothesis(**base)


# @g.comment -- "Pins that an IPC hypothesis selects the IPC prompt, which is what makes the generator capable of writing cxg.ipc probes at all."
def test_ipc_hypothesis_selects_the_ipc_prompt():
    assert js_generator.select_system_prompt(_ipc_hypothesis()) is js_generator.IPC_SYSTEM_PROMPT


# @g.comment -- "Pins that an HTTP hypothesis still selects the original prompt, so web generation quality is untouched by this change."
def test_http_hypothesis_still_selects_the_http_prompt():
    h = _ipc_hypothesis(http_method="GET", http_path="/api/users/1")
    assert js_generator.select_system_prompt(h) is js_generator.SYSTEM_PROMPT


# @g.comment -- "Pins that the IPC prompt teaches the API and the mandatory annotation; a prompt missing these is why generated templates reached for cxg.fetch."
def test_ipc_prompt_teaches_the_ipc_api_and_capability():
    p = js_generator.IPC_SYSTEM_PROMPT
    for token in ("cxg.ipc.invoke", "cxg.ipc.invokeAs", "@requires_capability: ipc",
                  "unreachable", "outcome"):
        assert token in p, f"IPC prompt never mentions {token}"


# @g.comment -- "Pins that the HTTP prompt was not modified — it must not learn about cxg.ipc, or web templates start mixing transports."
def test_http_prompt_does_not_mention_ipc():
    assert "cxg.ipc" not in js_generator.SYSTEM_PROMPT
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd pentest && python -m pytest tests/test_js_generator_ipc.py -v`
Expected: FAIL with `AttributeError: module 'js_generator' has no attribute 'select_system_prompt'`.

- [ ] **Step 3: Add the IPC prompt and the selector**

Add after `SYSTEM_PROMPT`'s closing `"""` at `js_generator.py:146`:

```python
# @g.comment -- "A separate system prompt for IPC hypotheses: the HTTP prompt's 'use cxg.fetch ONLY' rule is correct for HTTP and wrong for IPC, so the two are kept apart rather than one prompt being taught both transports."
IPC_SYSTEM_PROMPT = """\
You are a pentest payload author working inside cert-x-gen. You are writing a
JavaScript probe that runs inside a live Electron renderer with an authenticated
session, testing an INTER-PROCESS COMMUNICATION channel — not an HTTP endpoint.

An IPC channel is NOT a URL. It has no path, no query string, and no status code.
You invoke it by name and inspect what the main process returns.

## The API available to you

    await cxg.ipc.invoke(channel, ...args)          // call as THIS identity
    await cxg.ipc.invokeAs(idx, channel, ...args)   // call as ANOTHER identity
    cxg.ipc.channels()                              // channel names found in source

`invokeAs` is how you test cross-identity access: identity A asks the application
for an object belonging to identity B. Use it for IDOR, cross-tenant and
privilege-escalation probes. `cxg.profiles` lists the identities and their index.

You may also use cxg.fetch / cxg.fetchAs if the finding needs an HTTP baseline
alongside the IPC call — for example, showing the HTTP path denies what IPC allows.

NEVER use `ipcRenderer` directly. The validator rejects it: it bypasses the scope
budget and the audit log.

## The return shape

Each invoke resolves to:

    {ok: bool, value: any, via: string, unreachable?: true, error?: string}

  ok:true          the call reached the main process and returned `value`
  unreachable:true the renderer could NOT reach the channel at all
  error            the call reached a handler and the handler threw

CRITICAL: `unreachable` is NOT a mitigation. It means you never made contact, so
you learned nothing about whether the channel is defended. A handler that
actively REJECTS your call (ok:false with an error) IS evidence the guard works.
Do not conflate them.

## Mandatory meta header

// @id: <kebab-case-id>
// @vuln_class: <idor | privilege_escalation | command_injection | sensitive_data_exposure>
// @severity: <low|medium|high|critical>
// @requires_auth_count: <1 or 2>   -- use 2 for cross-identity probes
// @requires_capability: ipc        -- REQUIRED; the validator rejects its absence
// @description: <one-liner>

## Finding shape — set `outcome` explicitly

Return an array of findings. Each MUST carry an explicit outcome in evidence:

    {
      id, severity, confirmed, endpoint: 'ipc://<channel>', description,
      evidence: {
        outcome: 'confirmed' | 'refuted' | 'unevaluated',
        ...anything else that proves your claim
      }
    }

  'confirmed'   you exploited it; `confirmed` must also be true
  'refuted'     you REACHED the handler and it correctly rejected you
  'unevaluated' you could not reach it, or could not tell — including
                unreachable:true. Never call this refuted.

Do not rely on wording in `description` to convey the verdict. `outcome` is what
triage reads.

OUTPUT FORMAT:
Return ONLY the JavaScript code block (```javascript ... ```). No prose, no commentary,
no second code block.
"""


# @g.comment -- "Chooses the prompt by transport so IPC hypotheses stop being handed a prompt whose hard rules forbid the only API that can probe them."
def select_system_prompt(hypothesis) -> str:
    if (getattr(hypothesis, "http_method", "") or "").upper() == "IPC":
        return IPC_SYSTEM_PROMPT
    return SYSTEM_PROMPT
```

- [ ] **Step 4: Use the selector and surface reachability context**

At `js_generator.py:277`, replace `SYSTEM_PROMPT` with `select_system_prompt(hypothesis)`.

In the `user_msg` built at `:259-272`, add after the `has_mitigation_declared` line:

```python
        f"{_reachability_block(hypothesis)}"
```

and add this helper above `generate_js_template`:

```python
# @g.comment -- "Surfaces the preload binding electron_surface already extracted, so the model calls the real exposed method instead of guessing at a window global."
def _reachability_block(hypothesis) -> str:
    raw = getattr(hypothesis, "raw", None) or {}
    via = raw.get("reachable_via")
    if not via:
        return ""
    generic = raw.get("reachable_via_generic")
    shape = ("a GENERIC passthrough taking the channel as its first argument"
             if generic else "a channel-specific method taking only the channel's own arguments")
    return (f"- reachable_via: {via}\n"
            f"- reachable_via shape: {shape}\n")
```

- [ ] **Step 5: Run to verify all pass**

Run: `cd pentest && python -m pytest tests/test_js_generator_ipc.py -v`
Expected: PASS, 4 passed.

- [ ] **Step 6: Run the full suite**

Run: `cd pentest && python -m pytest -v`
Expected: PASS, zero skips.

- [ ] **Step 7: Commit**

```bash
git add pentest/js_generator.py pentest/tests/test_js_generator_ipc.py
git commit -m "feat(pentest): teach the generator to write cxg.ipc probes"
```

---

### Task 4: Correct the artefacts that teach the old unreachable rule

**Files:**
- Modify: `pentest/docs/TEMPLATES.md` (the `unreachable` instruction, around `:259`)
- Modify: `pentest/tests/fixtures/vuln-electron-manual-templates/manual-secure-read-config-control.js`
- Modify: `pentest/tests/fixtures/vuln-electron-manual-templates/manual-file-read-traversal.js`

**Interfaces:**
- Consumes: the `outcome` contract from Task 1.
- Produces: committed templates that emit `evidence.outcome`, and documentation that no longer instructs authors to refute on `unreachable`.

- [ ] **Step 1: Find every place the old rule is taught**

Run: `cd pentest && grep -rn "unreachable" docs/ tests/fixtures/vuln-electron-manual-templates/`

Record the hits. `docs/TEMPLATES.md` around `:259` and the control template's description line are the known ones; **report anything else you find** — the spec requires enumerating every artefact, not just the two already identified.

- [ ] **Step 2: Correct `docs/TEMPLATES.md`**

Replace the instruction that `unreachable: true` should be converted into a refutation with:

```markdown
`unreachable: true` means the probe never reached the channel — you learned
nothing about whether it is defended. Emit `evidence.outcome: 'unevaluated'`.

A refutation requires POSITIVELY reaching the handler and being rejected by it.
That is `{ok: false, error: ...}` with no `unreachable` flag, and it earns
`evidence.outcome: 'refuted'`.
```

- [ ] **Step 3: Update the control template**

In `manual-secure-read-config-control.js`, the description currently says `"mitigation holds: …"` whenever `leaked` is false, including when the call was unreachable. Replace the finding construction with:

```javascript
    const reached = out && out.unreachable !== true;
    const outcome = leaked ? 'confirmed' : (reached ? 'refuted' : 'unevaluated');
    findings.push({
        id: 'manual-secure-read-config-control',
        severity: 'high',
        confirmed: !!leaked,
        endpoint: 'ipc://secure:read-config',
        description: leaked
            ? 'Traversal succeeded on the guarded channel.'
            : (reached
                ? 'mitigation holds: the handler validated the sender frame and rejected traversal.'
                : 'Channel was not reachable from this renderer; nothing was established.'),
        evidence: { outcome, reached, raw: out },
    });
```

- [ ] **Step 4: Update the exploit template the same way**

In `manual-file-read-traversal.js`, add `outcome` to its evidence using the same rule: `'confirmed'` when content leaked, `'refuted'` when the handler was reached and rejected, `'unevaluated'` when unreachable.

- [ ] **Step 5: Verify the headline test still passes**

Run: `cd pentest && python -m pytest tests/test_e2e_electron.py -v -k manual`

Expected: PASS (or SKIP without fixture `node_modules`). The guarded control returns `{ok:false, error:"rejected: path traversal"}` with **no** `unreachable` flag, so it reaches the handler and is genuinely rejected — a real refutation under the new rule exactly as under the old one. **If this now lands in `ambiguous`, stop and report it**: it means the control is not reaching the handler, which would invalidate the branch's headline result.

- [ ] **Step 6: Run the full suite and commit**

Run: `cd pentest && python -m pytest -v`
Expected: PASS, zero skips.

```bash
git add pentest/docs/TEMPLATES.md pentest/tests/fixtures/vuln-electron-manual-templates/
git commit -m "docs(pentest): stop teaching that an unreachable channel is a refutation"
```

---

### Task 5: Commit a real generated template as a fixture, and run the live bar

**Files:**
- Create: `pentest/tests/fixtures/generated-ipc-template/` (one generated `.js`, committed)
- Modify: `pentest/tests/test_js_generator_ipc.py`

**Interfaces:**
- Consumes: everything from Tasks 1–4.
- Produces: a committed artefact proving the prompt's real output is handled correctly by the pipeline, verified on every CI run without a model call.

- [ ] **Step 1: Generate one template by hand**

```bash
cd pentest/tests/fixtures/vuln-electron
cxg pentest run --target-type electron --app-cmd "npx electron ." \
  --codebase . --target http://127.0.0.1:1 --auth <your-desktop-profile> \
  --ai --ai-provider claude --max-templates 2 \
  -o /tmp/ipc-ai-report.json
```

This is slow (~105s per template) and needs the `claude` CLI. Copy the generated `.js` for the `file:read` hypothesis out of the session's template directory into `pentest/tests/fixtures/generated-ipc-template/`.

**Report honestly if this cannot be completed** — if generation times out or the `claude` CLI is unavailable, say so and mark Step 4 not-run rather than fabricating a result.

- [ ] **Step 2: Write the test against the committed artefact**

Add these two imports to the **top** of `pentest/tests/test_js_generator_ipc.py`, beside the existing ones — not at the point of use:

```python
from pathlib import Path

from validator import validate
```

Then append to the same file:

```python
# @g.comment -- "Locates the committed real generator output, so CI verifies the pipeline handles genuine model output without paying for a model call."
_GENERATED = Path(__file__).parent / "fixtures" / "generated-ipc-template"


# @g.comment -- "Pins that real generated output passes validation, declares its capability, and uses the IPC API rather than reaching for cxg.fetch or a window global — the exact failure that made --ai unusable for desktop."
def test_committed_generated_template_is_well_formed():
    files = sorted(_GENERATED.glob("*.js"))
    assert files, "no committed generated template — see Task 5 Step 1"
    src = files[0].read_text()
    result = validate(src)
    assert result.ok, result.errors
    assert result.meta.get("requires_capability") == "ipc"
    assert "cxg.ipc." in src
    assert "window.appApi" not in src
    assert "ipcRenderer" not in src
```

- [ ] **Step 3: Run it**

Run: `cd pentest && python -m pytest tests/test_js_generator_ipc.py -v`
Expected: PASS.

If the generated template fails validation, that is a **real finding about the prompt**, not a test to weaken. Report the validation errors and fix the prompt in `IPC_SYSTEM_PROMPT`, then regenerate.

- [ ] **Step 4: Run the live bar and record the result**

```bash
cxg pentest run --target-type electron --app-cmd "npx electron ." \
  --codebase . --target http://127.0.0.1:1 --auth <profile-a>,<profile-b> \
  --ai --ai-provider claude --max-templates 5 \
  -o /tmp/ipc-ai-report.json
```

Check `/tmp/ipc-ai-report.json`:
- `confirmed_findings` contains `ipc://file:read`
- `mitigation_verifications` contains `ipc://secure:read-config`
- `secure:read-config` is **not** in `confirmed_findings`

Record the actual outcome. A negative result here is a legitimate finding to report, not a reason to adjust assertions.

- [ ] **Step 5: Run the full suite and commit**

Run: `cd pentest && python -m pytest -v && cd .. && cargo test --release`
Expected: both PASS.

```bash
git add pentest/tests/fixtures/generated-ipc-template pentest/tests/test_js_generator_ipc.py
git commit -m "test(pentest): pin real generated IPC template output"
```

---

## Self-review notes

**Spec coverage:** IPC prompt path → Task 3. Outcome contract and precedence → Task 1. Vocabulary reconciliation → Task 1 Step 5. Signal ordering fix → Task 1 Step 6. Unreachable rule change → Task 1 Steps 3/5. Validator gate → Task 2. Ripple (docs, control template) → Task 4. Prose regression corpus → Task 1 Steps 1–2. Committed generated fixture → Task 5. Live bar → Task 5 Step 4.

**Deviation from the spec, deliberate:** the spec describes moving `_ENV_BOUND_SIGNALS` before `_MITIGATION_HOLD_SIGNALS`. Task 1 Step 6 moves it before **all six** refuted-returning prose rules, because a description carrying both an environment signal and any earlier mitigation phrase would otherwise still misclassify. The spec's wording was too narrow.

**Known risk:** Task 1 rewrites a function every web scan depends on. The corpus test in Step 1 is written and run *before* any change specifically so a behaviour shift is caught rather than discovered. If a corpus case moves, that is a stop-and-report condition, not something to update the expectation for.
