# Runtime identity metadata for templates

**Status:** implemented
**Date:** 2026-08-03

## Context

A live Mattermost Desktop run with two identities — `mm-alice` (`--tier high`,
label `admin`) and `mm-bob` (`--tier low`, label `bob-user`) — produced eight
generated templates. **Five of the eight had the identities backwards.**

| template | claimed | correct |
|---|---|---|
| `get-unique-servers` | member=1, admin=0 | ✅ |
| `remove-server` | member=1, admin=0 | ✅ |
| `edit-server` | member=0, admin=1 | ❌ |
| `add-server` | member=0, admin=1 | ❌ |
| `update-configuration` | member=0, admin=1 | ❌ |
| `get-local-configuration` | `member_label: "mm-alice"` | ❌ |
| `get-configuration` | `member_label: "mm-alice"` | ❌ |

The consequence is not a cosmetic mislabel. `edit-server` was reported
CONFIRMED on the reasoning *"the member mutated persisted state; the identical
call from the admin did not take effect"* — with the roles inverted, that
sentence describes an admin doing an admin's job, which is the secure outcome
reported as a high-severity finding.

### Why the model gets it wrong

The information exists at generation time and vanishes at runtime.

`js_generator._profile_context_block` (`js_generator.py:500`) tells the ranking
and generation prompt each identity's `label`, `persona`, `role`, `tier`
(marked operator-set or role-derived), `cohort` and `tags`. The model reasons
about tiers correctly while writing the template.

`targets/bridge.py` then exposes only:

```js
window.__cxg.profile   // {name, label, index}
window.__cxg.profiles  // [{name, label, index}, ...]
```

No tier. So a template that wants "the low-privilege identity" has nothing to
read at runtime and must hardcode an index chosen at authoring time. The
observed failure mode is worse than a coin flip in one specific way: several
templates recorded `member_label: "mm-alice"` — the profile **name**, not the
label — showing they read `.name` and assumed index 0 was the attacker, rather
than consulting `label` at all.

## Decisions

| Decision | Rationale |
|---|---|
| Expose `tier` at runtime, not just at generation time | The generation-time block already proves the data is available and useful. The runtime gap is the whole defect. |
| Expose `persona` and `cohort` too | Same source, same cost. `cohort` is what distinguishes a horizontal (peer) test from a vertical one, and a template currently cannot tell those apart at runtime either. |
| Prefer the operator-set tier, fall back to the engine's role-derived one, `null` only when neither exists | `AuthProfile.tier` is `None` unless `--tier` was passed, so operator tiers alone would leave both helpers `null` on an ordinary run and the prompt would tell every privesc probe to give up — trading a minority of mis-oriented probes for the loss of all of them. `JsEngine.profile_tier` already holds a role-derived rank good enough to pick a runner, and it is populated in `__init__` long before `substrate.open`, so passing it is one field on `BridgeContext`. `tierSource` records which was used so neither the model nor a reader has to guess. |
| Add precomputed `lowestPrivilege` / `highestPrivilege` | The ranking arithmetic is exactly what the templates got wrong. Handing them the answer removes the step that failed. |
| Those helpers are `null` when the answer is not well-defined | If any tier is `null`, or the extreme is tied, there is no correct ranking. Returning `null` forces the template to report `unevaluated`; returning a guess reproduces the bug this change exists to fix. |
| Helpers are values, not functions | `profiles` is already a value. A function invites a template to call it once, cache the result, and drift from it. |
| The prompt forbids inferring role from index order | The measured failure was index-order inference. Stating the rule is what makes the new data get used. |

## Architecture

### `pentest/targets/bridge.py`

The payload built at the bottom of `install_base` gains three fields per
identity, and two new top-level entries are computed **in Python** — not in
page JS — so the ranking rule lives in one testable place:

```python
def _identity(p, index):
    return {"name": p.name, "label": p.label, "index": index,
            "tier": p.tier, "persona": p.persona, "cohort": p.cohort}
```

```js
window.__cxg = {
    profile: PROFILE,
    profiles: PROFILES,
    lowestPrivilege: LOWEST,    // identity object, or null
    highestPrivilege: HIGHEST,  // identity object, or null
    …
}
```

`lowestPrivilege` is `null` when the roster is empty, when **any** identity has
`tier is None`, or when two or more identities tie for the minimum. Same rule
for `highestPrivilege` at the maximum. A one-identity roster with a set tier
yields that identity for both — it is unambiguously the lowest and the highest
of the set, and a template comparing the two will find them equal, which is the
correct signal that no differential is available.

Both `web.py` and `electron.py` call `install_base` unchanged; the signature
does not move.

### Prompt and docs

`js_generator.py:49-50`'s shared comment block, the IPC prompt, and
`docs/TEMPLATES.md:140-141` all document the three-field shape and must gain
the new fields. The IPC prompt additionally gains the rule:

> Never infer which identity is privileged from its position in `cxg.profiles`.
> Read `cxg.lowestPrivilege` / `cxg.highestPrivilege`, or compare `tier`
> directly. If either is `null`, the identities cannot be ranked — say so and
> return no confirmation, rather than assuming an order.

The HTTP prompt gets the same rule, phrased for its own contract: it uses a
`confirmed` boolean and has no `outcome` field, so the null case is
`confirmed: false` with the reason in the description — the shape it already
uses for an unavailable `cxg.oast`. This matters because `select_system_prompt`
hands the HTTP prompt to any hypothesis naming a route *even on an Electron
run*, and `cxg.fetchAs(idx, ...)` is index-addressed exactly like `invokeAs`.

## Testing

- `_identity` carries all six fields; `tier` survives as `None`.
- Ranking: distinct tiers pick the right extremes; a `None` anywhere yields
  `null` for both; a tie at the minimum yields `null` for `lowestPrivilege`
  while a distinct maximum still yields `highestPrivilege`; an empty roster
  yields `null` for both; a single identity with a tier is both.
- The bridge JS still parses and `window.__cxg` still carries every
  pre-existing key — this edits a string every web scan depends on.
- A web-target install is unchanged apart from the added fields.

## Out of scope

- Any change to `invokeAs` / `fetchAs` dispatch.
- Re-running the Mattermost scan; that is validation, done by hand.

## Validation

1. A two-identity run exposes `tier` on both entries of `cxg.profiles`.
2. With `--tier high` and `--tier low` captured, `cxg.lowestPrivilege.name`
   is the low-tier profile.
3. The full Python suite passes; web-target bridge behaviour is unchanged.
