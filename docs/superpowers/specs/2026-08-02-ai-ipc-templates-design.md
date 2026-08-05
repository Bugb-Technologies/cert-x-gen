# AI-generated IPC templates, and a structural triage outcome

**Status:** design approved, not implemented
**Date:** 2026-08-02
**Closes:** #24 (generator cannot produce IPC templates), #22 (classifier reads prose), #36 (unreachable treated as refuted), part of #25 (no forward capability gate)

## Context

The desktop-target work (merged in `e013308`) gave `cxg pentest` an Electron
substrate, an IPC bridge, and hypotheses shaped like HTTP routes. What it did
not give is a way to *generate* IPC probes. `pentest/js_generator.py` was never
touched: its system prompt advertises only `cxg.fetch`/`cxg.fetchAs`, its meta
list omits `@requires_capability`, and its HARD RULE 4 says to use those two
functions *only* — while the generator is handed hypotheses whose
`http_method` is `IPC`.

The observed consequence is not a clean failure. Generated templates reach for
`cxg.fetch` or raw `window.appApi`, run, and return nothing useful; three
consecutive `--ai` desktop runs produced inconclusive IPC results even after
the dispatch bridge had been proven working by hand. So an operator must
hand-write every IPC probe today.

A second defect blocks the same workflow from the other end. `mutator.classify()`
decides a finding's bucket by matching English prose. A probe reasoning
`"REFUTED — the handler enforces a sender-frame origin check"` falls through
every rule to the `unknown` fallback and is filed `ambiguous`, while one saying
`"mitigation holds"` is filed correctly. Generated templates cannot be relied on
to hit a magic phrase, so their refutations — the guarded-channel case that
proves cxg does not hallucinate — would be lost as noise.

This design fixes both, and closes the rule that has repeatedly produced false
refutations along the way.

## Decisions

Settled during design; recorded so implementation does not relitigate them.

| Decision | Rationale |
|---|---|
| A separate IPC system prompt, not one prompt taught both APIs | The HTTP prompt's `cxg.fetch ONLY` rule is correct for HTTP and wrong for IPC. Branching leaves every web scan's generation quality untouched and keeps each prompt short enough for a model to follow. |
| Fix `classify()` structurally rather than teaching the model a magic phrase | Teaching the prompt to write "mitigation holds" would entrench #22 and leave hand-written templates failing the same way. |
| `evidence.outcome` adopts the vocabulary `config_probes` already uses | Task 8 shipped `{confirmed, refuted, unevaluated}` plus `partition()`. Template findings had no equivalent. One vocabulary across both evidence producers rather than two half-systems. |
| Prose matching is retained as the last resort | Every existing hand-written template must keep working unchanged. Prose stops being the only path; it does not stop being a path. |
| `evidence.unreachable` becomes ambiguous, not refuted | Closes #36. "I could not reach it" is not "it is defended". That rule produced four separate false refutations across the desktop branch. |
| The capability gate is a hard error | Matches the existing raw-`fetch()` and raw-`ipcRenderer` bans. Converts a confusing runtime `Cannot read properties of undefined` into a clear pre-flight rejection. |
| `CONFIG` hypotheses still never reach the generator | Unchanged from Task 8. Asking a model to write probe code for "nodeIntegration is true" produces exactly the plausible-but-wrong findings the triage layer exists to kill. |

## Architecture: the IPC generation path

`pentest/js_generator.py` gains a second module-level system prompt beside the
existing one. The HTTP prompt is **not modified**.

```python
_SYSTEM_PROMPT     = """…existing, unchanged…"""
_IPC_SYSTEM_PROMPT = """…cxg.ipc surface, channel model, outcome field…"""
```

`generate_js_template` (`js_generator.py:229`) branches on
`hypothesis.http_method == "IPC"` to select the prompt. Nothing else in the call
path changes — same provider invocation, same JS-block extraction, same file
naming, same post-generation validation.

### What the IPC prompt must teach

- `cxg.ipc.invoke(channel, ...args)` and `cxg.ipc.invokeAs(idx, channel, ...args)`.
- That a channel is **not** a URL: no path, no query string, no status code.
- `@requires_capability: ipc` is mandatory in the meta header.
- The dispatch return shape `{ok, value, via, unreachable?, error?}`, and
  specifically that `unreachable` means the renderer could not reach the channel
  — which is **not** the same as the handler rejecting the call.
- The `evidence.outcome` field defined below.
- `invokeAs` framed as the cross-identity primitive: identity A asks the app for
  an object belonging to identity B.

### Reachability context the prompt must include

Each IPC hypothesis already carries `raw["reachable_via"]` (e.g.
`"appApi.readFile"`) and `raw["reachable_via_generic"]`, extracted from the
preload by `electron_surface.extract()`. The generator does not currently
surface either. The IPC prompt will include them, so the model calls the real
binding rather than guessing at `window.appApi` — which is what it was observed
doing.

## The outcome contract and `classify()` precedence

### Vocabulary reconciliation

`config_probes` uses `{confirmed, refuted, unevaluated}`.
`mutator.classify()` returns `TriageVerdict(kind=…)` with
`{confirmed, refuted, ambiguous}` plus `reason_kind` of
`{payload, environment, unknown}`.

`evidence.outcome` adopts the **config_probes** vocabulary. `classify()` maps
`unevaluated → TriageVerdict("ambiguous", reason_kind="environment")` in one
explicit place.

`reason_kind="environment"` is load-bearing: it means no retry can fix this, so
the mutator does not spend AI calls rewriting a probe whose channel is simply
unreachable.

### Precedence

1. `evidence.outcome` present and recognised → authoritative.
2. Otherwise structural evidence, in this order:
   - `evidence.unreachable` truthy → ambiguous / environment
   - `evidence.blocked` truthy (scope-blocked) → ambiguous / environment
3. Otherwise today's prose rules, with the ordering fix below.
4. An unrecognised `outcome` value falls through to step 2 rather than being
   guessed into a bucket.

Note `classify()` reads neither `evidence.unreachable` nor `evidence.blocked`
today — it sees only `description` and `evidence.status`. Templates currently
signal unreachability through prose. Step 2 is therefore new behaviour, and it
is what makes the unreachable rule change effective rather than cosmetic.

Step 3 is what keeps every existing hand-written template working.

### Two rule changes inside `classify()`

**Signal ordering.** `_MITIGATION_HOLD_SIGNALS` is currently tested at
`mutator.py:174`, before `_ENV_BOUND_SIGNALS` at `:180`. So "no exploitation
observed; only one identity available" is **refuted** today — the tool claiming
a mitigation holds when it actually lacked the identities to test, contradicting
the documented "skipped, never refuted" rule. Environment signals move first.

**Unreachable.** `evidence.unreachable` becomes ambiguous / environment rather
than refuted.

## Validator gate

`pentest/validator.py` gains a rule matching the existing raw-`fetch()` and
raw-`ipcRenderer` bans in structure and message style: a template whose source
calls `cxg.ipc.*` without declaring `@requires_capability: ipc` is a **hard
error**.

Both committed fixture templates already declare it, so nothing breaks.

## Ripple from the unreachable decision

Three artefacts currently teach the old rule and must change with it:

- `pentest/docs/TEMPLATES.md:259` instructs every author to convert
  `unreachable` into a refutation. Rewrite: `unreachable` means the probe never
  reached the channel; a refutation requires positively reaching it and being
  rejected.
- `pentest/tests/fixtures/vuln-electron-manual-templates/manual-secure-read-config-control.js:30`
  emits `"mitigation holds: …"` whenever `leaked` is false, **including** when
  `result.unreachable === true`. It must emit `outcome: "refuted"` only when it
  reached the handler and was rejected, and `outcome: "unevaluated"` when
  unreachable.
- The IPC prompt teaches the corrected rule from the start.

`test_manual_templates_confirm_file_read_and_refute_secure_config` still passes
unchanged: the guarded control returns `{ok: false, error: "rejected: path
traversal"}` with **no** `unreachable` flag, so the probe genuinely reaches the
handler and is genuinely rejected. That is a real refutation under both the old
and new rule. The change affects only probes that never made contact.

## Testing

The hard constraint: AI generation is nondeterministic and slow (~105s per
template, requires the `claude` CLI). **No CI test may depend on a live model
call.**

### Pure unit tests, all CI-safe

- **Prompt selection.** An `IPC` hypothesis selects `_IPC_SYSTEM_PROMPT`; an
  HTTP hypothesis selects the existing prompt; a `CONFIG` hypothesis never
  reaches the generator. Assert on the chosen prompt, invoke no model.
- **`classify()` precedence, exhaustively.** All three tiers, plus an
  unrecognised `outcome` falling through rather than being guessed.
- **Vocabulary mapping.** `unevaluated → ("ambiguous", "environment")`,
  asserted on both fields.
- **Both rule changes**, each pinned by a test that fails against today's code:
  the identity-shortage case must be environment-bound rather than refuted, and
  `evidence.unreachable` must be ambiguous rather than refuted.
- **Validator gate.** `cxg.ipc.*` without the annotation is a hard error; with
  it, passes; both committed fixture templates still validate.

### The regression that matters most

Every existing hand-written template must classify **identically** to today via
the prose path, asserted over a corpus of real descriptions rather than a single
example. This design rewrites a function every web scan depends on.

**With one deliberate exception, which must be enumerated rather than
discovered.** A template that today writes a mitigation-hold phrase for a result
that was actually `unreachable` currently classifies as `refuted`, and under the
new rule classifies as `ambiguous`. That is the intended correction, not a
regression — but it means "identical" is the wrong bar on its own. The
implementation must identify every such template in the repository, list them in
the test, and assert the new outcome explicitly for each. The committed control
template is one known instance and is handled under Ripple above; the corpus
test must establish whether there are others.

### Bridging to real output without a live call

Run `--ai` against the fixture once by hand, commit the resulting template as a
test fixture, and assert it validates, declares its capability, and confirms
`file:read` when executed. This separates *"the prompt produces good output"* —
verified once, deliberately, by a human — from *"the pipeline handles that
output correctly"*, which is then verified on every CI run.

Write this test to avoid launching Electron where possible; validation and
classification are pure. Electron-launching tests still skip in CI (#33).

### The live bar, run manually and recorded

`--ai` alone, with no `--template-dir`, produces a template confirming
`file:read` traversal on the fixture while `secure:read-config` remains refuted.
Reported honestly if it cannot be completed.

## Out of scope

- Non-Electron desktop targets (native apps behind an intercepting proxy).
  Agreed as a separate project with its own spec.
- The remaining parts of #25 (`_RAW_FETCH_PATTERN` missing `window.fetch(`).
- #23 (no record of skipped templates in `report.json`).
- Every other open issue from #26–#37.

## Validation

1. `cxg pentest run --target-type electron --ai` against the vulnerable fixture
   produces an IPC template that confirms `file:read` traversal, with no
   `--template-dir`.
2. The same run leaves `secure:read-config` in `mitigation_verifications`, not
   `ambiguous` and not `confirmed`.
3. The full Python suite passes with zero skips; every existing template
   classifies as it did before.
4. A template using `cxg.ipc.*` without `@requires_capability: ipc` is rejected
   before execution with a message naming the missing annotation.
