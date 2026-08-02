# Constant-named IPC channels, and routeless desktop threats

**Status:** design approved, not implemented
**Date:** 2026-08-03
**Closes:** the two gaps that produced `0 IPC channels` and `selected 0/17` on Mattermost Desktop

## Context

`cxg pentest run --target-type electron` against Mattermost Desktop
(154 `ipcMain` registrations, 17 guardlink threats) generated **zero**
templates and exited at step 3. Neither cause is in the target or the
operator's setup; both are in cxg.

```
[1]  guardlink: 17 SARIF hypotheses, 462 inline, 0 endpoints
[1a] electron surface: 0 IPC channels, 0 configuration claims
[gen] selected 0/17 hypotheses for AI synthesis
[3]  no templates available — exiting
```

### Gap 1 — the extractor only recognises literal channel names

`electron_surface._RE_IPC_HANDLER` requires a quoted string as the first
argument:

```python
_RE_IPC_HANDLER = re.compile(r"""ipcMain\.(?:handle|on)\s*\(\s*['"`]([^'"`]+)['"`]""")
```

Mattermost registers every handler with an imported constant instead:

```ts
ipcMain.handle(VALIDATE_SERVER_URL, this.handleServerURLValidation);  // serverHub.ts:51
```

Measured on the real tree: **0 of 152** registrations use a literal. The
preload is the same shape — `_RE_IPC_CALL`'s identifier alternative exists
only to detect a passthrough (identifier equals the binding's own first
parameter), so `getSecret: (u, k) => ipcRenderer.invoke(SECURE_STORAGE_GET, u, k)`
records no channel either.

The names are not hidden. They are 214 flat `export const NAME = 'literal'`
declarations, most of them in `src/common/communication.ts`. cxg simply
never reads them.

### Gap 2 — the generator discards every hypothesis without an HTTP route

`js_generator.rank_hypotheses_by_goal:637`:

```python
runnable = [h for h in hypotheses if h.http_path]
```

All 17 guardlink threats are desktop-side — permission caching, deeplink
handling, sender-frame checks, policy config from `HKEY_CURRENT_USER`. None
carries an HTTP path, so all 17 are dropped before ranking and the model is
handed nothing.

This is the same seam `_names_an_http_route` was added for on
`feat/ai-ipc-templates`: that function selects `IPC_SYSTEM_PROMPT` for a
routeless hypothesis on a desktop run, but a routeless hypothesis never
reaches it, because this filter kills it one layer earlier. The prompt-branch
fix is real and, on this path, has never executed.

### Why they must be fixed together

Fixing Gap 2 alone hands the model a threat with no entry point to aim at:
*"popoutManager does not check the sender is the target server"* and nothing
else. That is precisely the condition that produced three inconclusive
`--ai` runs on the fixture — the model invents a channel name, the dispatch
returns `unreachable`, and the finding is `unevaluated`. Gap 1's channel
table is what makes Gap 2's output aimable.

## Decisions

| Decision | Rationale |
|---|---|
| Resolve constants with a regex pre-pass, not a TypeScript parser | Verified against the real tree: `export const` matching resolves 152/152 handlers with zero name collisions. A tree-sitter dependency and a rewritten extractor buy no additional channels here. |
| Match `export const` only, never bare `const` | Measured. Bare `const` yields 280 entries with 12 colliding names (`url`, `filename`, `expected`, `html`, `testURL`) — ordinary locals in tests and helpers. `export const` yields 214 with **zero** collisions and loses no handler. Channel constants are exported by construction; they must be, to be imported at the call site. |
| A colliding name resolves to nothing, and says so | Two files exporting the same name with different values is genuine ambiguity. Guessing attributes a probe result to the wrong channel — worse than not probing. |
| Correlate routeless threats to channels by source file | The unit guardlink reports is a file location; the unit the extractor produces is a channel with a file. File-level join needs no new data from either side. |
| Correlation yields **candidates**, not an answer | `callsWidgetWindow.ts` registers 15 channels against one threat. Narrowing to one is the model's job, with the threat text and the codebase in front of it. cxg's job is to stop it guessing from nothing. |
| An uncorrelated threat becomes `review_only` and is reported | Ten of the seventeen reach no channel. Dropping them silently, as today, makes the report imply coverage cxg never had. |
| `review_only` never reaches the generator | Same rule as `CONFIG` hypotheses (spec 2026-08-02): asking a model to probe something with no entry point produces plausible-but-wrong findings, which is what the triage layer exists to kill. |

## Architecture

Three changes, in dependency order.

### 1. Constant resolution — `pentest/electron_surface.py`

A module-level pre-pass, run once per `extract()` before handler and preload
scanning:

```python
_RE_EXPORT_CONST = re.compile(
    r"""^\s*export\s+const\s+(\w+)\s*=\s*(['"`])([^'"`\n]+)\2\s*;""", re.M)
```

It returns `dict[str, str]` plus the set of names seen with more than one
distinct value. A colliding name is **omitted from the map** and reported
once through the existing extraction log, never silently resolved.

`_RE_IPC_HANDLER` gains an identifier alternative. When the captured group is
an identifier rather than a literal, it is looked up in the map; a miss
leaves the registration unrecorded exactly as today, and the count of misses
is logged so a future target with a different idiom is visible rather than
silent.

`_RE_IPC_CALL` already captures a bare identifier for its passthrough test.
The change is ordering: try the constant map **first**, and fall through to
the existing passthrough comparison only when the identifier is not a known
constant. A binding whose first argument resolves to a channel name is a
channel-specific binding, not a passthrough — the two cases are disjoint and
the map is what tells them apart.

Both are one-line-per-callsite changes inside existing functions. No new
module, no change to the `Hypothesis` shape, no change to
`build_known_channels()`.

### 2. Correlation — new `pentest/threat_correlation.py`

One function, no state:

```python
def correlate(threats: list[Hypothesis],
              ipc_hyps: list[Hypothesis]) -> tuple[list, list]:
    """Split routeless threats into (correlated, review_only).

    A threat correlates when its source file registers at least one IPC
    channel. Correlated threats gain raw["candidate_channels"]; review-only
    threats gain raw["review_only"] = True and a reason.
    """
```

It lives in its own module because it joins two producers that neither
imports the other — `guardlink.py` and `electron_surface.py` — and belongs to
neither.

Threats that already carry an `http_path` pass through untouched. This is a
desktop-only concern; a web scan never calls it.

### 3. The filter — `pentest/js_generator.py`

```python
runnable = [h for h in hypotheses if h.http_path]
```

becomes: a hypothesis is runnable when it has an `http_path` **or** carries
`raw["candidate_channels"]`. `review_only` hypotheses are never runnable.

`_dedupe_by_probe_shape` keys on `(http_method, http_path, function_name)`.
A correlated threat has an empty `http_path`, so two distinct threats in the
same file with no `function_name` would collapse into one — losing a real
finding. The key must incorporate the candidate-channel set for these.
`navigationManager.ts` contributes exactly this case: two threats
(`deeplink-injection`, `ui-spoof`), same file, same three candidate channels.

The IPC prompt gains the candidate list, framed as candidates to choose
among rather than a channel to call — `_names_an_http_route` already routes
these hypotheses to `IPC_SYSTEM_PROMPT`.

### Reporting

`review_only` threats appear in `report.json` and in the console under a
heading that states what they are: found by guardlink, not runtime-verifiable
by cxg, and why. They are not findings, not refutations, and not `ambiguous`
— `ambiguous` means cxg tried and could not resolve it. These were never
tried, and the report must not blur that.

`build_report_caveats()` gains a line when any exist, so a reader of a
desktop report always learns the coverage gap without opening the JSON.

## Measured expectations

Everything below is from a spike against the real tree, not estimated. These
are the acceptance numbers.

| | today | expected |
|---|---|---|
| `ipcMain` registrations recognised | 0 / 152 | 152 / 152 |
| distinct channels extracted | 0 | 130 |
| preload bindings mapped to a channel | 0 | 125 of 126 |
| constants in map / colliding | — | 214 / 0 |
| guardlink threats reaching the generator | 0 / 17 | 7 |
| guardlink threats reported as review-only | 0 (dropped) | 10 |

The seven that correlate:

| threat | file | candidates |
|---|---|---|
| `calls-widget` permission-overgrant | `callsWidgetWindow.ts` | 15 |
| `navigation-manager` deeplink-injection | `navigationManager.ts` | 3 |
| `navigation-manager` ui-spoof | `navigationManager.ts` | 3 |
| `downloads` state-tampering | `downloadsManager.ts` | 6 |
| `popout-manager` cross-server-confusion | `popoutManager.ts` | 9 |
| `permissions-manager` permission-overgrant | `permissionsManager.ts` | 4 |
| `permissions-manager` silent-capture | `permissionsManager.ts` | 4 |

The ten that do not are main-process-internal — `JsonFileManager`'s
`readFileSync`, `policyConfigLoader`'s registry read, `serverManager`'s URL
typing. No renderer-side probe reaches them, and reporting them as testable
would be a lie in the direction that matters.

## Testing

No test may depend on a live model call or on the Mattermost checkout.

**Constant resolution.** Fixtures for: literal channel (unchanged behaviour),
`export const` resolved, bare `const` **not** resolved, colliding name
omitted and reported, unresolved identifier counted. Assert on the emitted
`Hypothesis` list.

**Preload precedence.** A binding whose first argument is a known constant is
channel-specific; a binding whose first argument is its own parameter name is
a passthrough; a constant that shadows a parameter name resolves as a
channel. This ordering is the subtle one — pin it.

**Correlation.** A threat in a file with channels gains candidates; a threat
in a file without gains `review_only`; a threat with an `http_path` passes
through untouched; a web-target hypothesis list is unchanged.

**Dedupe.** Two threats, same file, no `function_name`, same candidates
survive as two — the `navigationManager.ts` case, pinned by a test that fails
against the current key.

**Filter.** A `review_only` hypothesis is never runnable. A correlated one is.
Every existing web hypothesis selects exactly as it does today, asserted over
a corpus rather than one example — this changes a function every web scan
depends on.

**Fixture end-to-end.** Extend `pentest/tests/fixtures/vuln-electron/` with a
constant-registered channel alongside its existing literal ones, so the
existing Electron test proves both forms extract. The fixture stays otherwise
frozen.

## Out of scope

- Non-Electron desktop targets (native apps behind an intercepting proxy).
- Resolving constants through re-exports, enums, computed values, or template
  literals. Not needed for any measured target; revisit when one appears.
- Line-proximity narrowing of candidate channels. File-level is what the
  data supports; narrowing 15 candidates to 3 is the model's job first.
- Making the ten review-only threats testable. Several genuinely are not.

## Validation

1. `electron_surface.extract()` on the Mattermost tree yields 130 channels.
2. A desktop run with `--ai` selects 7 hypotheses and writes templates for
   them, with no `--template-dir`.
3. The report lists 10 review-only threats, named, with reasons, and a caveat
   line pointing at them.
4. The full Python suite passes; every web hypothesis ranks as before.
