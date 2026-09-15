# Changelog

All notable changes to CERT-X-GEN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**A finding carries the identity of the exposure it tested, so
`guardlink hypothesis confirm --from-scan` can settle a hypothesis**

`report.json` gains three keys and every finding gains five. The report carries `scan_id` — the
session directory's name, so a ledger entry months later traces back to the `audit.jsonl` that
produced it — and `findings`, the confirmed set under a second name, the one guardlink's scan
ingest reads. Both names are carried because neither can be renamed from here:
siete reads `confirmed_findings`, guardlink reads `findings`. Refutations
(`mitigation_verifications`) and unresolved triage (`ambiguous`) are deliberately excluded, since
the ingest can only ever write `confirmed`.

Each finding carries `annotation: {file, line}`, `asset`, `threat`, `template_id` and a one-line
`title` derived from its description, so the ingest joins it to the exposure the probe was
actually testing rather than falling through to CWE — the loosest tier, and the only one that can
attach a finding to an exposure it never tested. The identity rides in the template's own
`@exposure_file` / `@exposure_line` / `@exposure_asset` / `@exposure_threat` headers, because a
`--template-dir` replay loads no SARIF and a header is the only carrier it has. The line is part
of the key because `(asset, threat, file)` is not unique in practice: temporal carries six groups
where one file holds two exposures with the same asset and threat, and guardlink's own `threatId`
cannot separate them either.

Only a hypothesis guardlink's SARIF produced is entitled to an identity — a positive `from_sarif`
test, not a list of the producers to exclude — so a probe cxg synthesised itself (Electron IPC,
`--discover-routes`, a CONFIG claim), an AI-written or hand-written template and the engine's own
crash observation carry none and are left unmatched rather than stapled to a neighbour. A mutated
retry inherits its parent's identity and `@id` deterministically instead of depending on the model
to reproduce the headers.

Entitlement is not enough on its own: the provenance must also be unambiguous. `_dedupe_by_probe_shape`
collapses every hypothesis sharing `(method, path, function_name)` onto one template, and where the
collapsed group does not agree on one `(file, line, asset, threat)` the four location keys are
WITHHELD — and `@threat_id` only where the group's members do not all carry one id, compared as
the values `parse_sarif` read off the SARIF rather than as a re-derivation of guardlink's key, so
a group sharing one id keeps the id that names whichever member a finding demonstrates — the prompt is told about the merged-away members, so a finding may demonstrate any of
them while carrying only the survivor's location, and the ingest joins on location first. Findings
there are left unmatched, which is what that path was before an identity was carried at all. The
withholding itself is recorded in `identity_withdrawn` under `cause: ambiguous_collapse`, so a
survivor's unlabelled findings are not mistaken for ones that never held an identity. The
members a disagreeing group's collapse dropped now appear in `not_selected_threats` with a reason
stating that a bigger `--max-templates` does not reach them; previously they appeared nowhere. An
agreeing group records nothing there — its dropped member is the survivor's own exposure, which
the survivor was tested for. That bucket now
has three writers — the ranker, the collapse and a replay's withheld template — so each record
carries the `kind` its writer set, and the `[2b]` banner and the `no_templates_executed` caveat
state a cause only for the members whose kind they name. On the legacy
browser path the same rule removes one pre-existing line: an AI-synthesised probe no longer
attaches the `threat_id` of the vuln-class representative it was invoked with, for exactly the
reason that path carries no annotation, asset or threat either. Every site that attaches an
identity is now tabulated with its proof in `pentest/docs/ARCHITECTURE.md`.

A stamped location can drift between runs. A reused template is re-stamped from the hypothesis it
is being reused for; a replayed one whose stamp no guardlink hypothesis in the run corroborates has
every identity key it holds withdrawn in memory — the four headers and `@threat_id`, which guardlink
derives from asset, threat and file with no line, so it names a file's surviving sibling just as
wrongly. The probe still runs and is still reported; only its claim about WHICH exposure it tests
is dropped, and every refusal is recorded in the new `identity_withdrawn`, whose records name
their own `cause`: `uncorroborated_stamp` for a template the run LOADED whose stamp it refused
(which is not the same as one per template that ran), and `ambiguous_collapse` for the collapse
above. A template that stamps no location and carries only a `@threat_id` is checked on that id,
against the ids the loaded hypotheses carry. A run that loaded no guardlink SARIF hypothesis
checked nothing and therefore withdraws nothing.

Three bounds are stated rather than approximated. An exposure that merely MOVED loses a true
identity, which is accepted: a missed join is silence and recoverable, a wrong join is a
confirmation a human has to catch later. And a stamped exposure deleted while a same-asset,
same-threat sibling comes to sit on exactly the stamped line cannot be detected from this side at
all — separating them needs the anchor hash `guardlink sarif` does not export, so it needs a
guardlink change (board card GAP-58). The third is cxg's own and is closable here: a run that loaded no model
withdraws nothing, which is correct, but its stamps then reach report.json unchecked and an empty
`identity_withdrawn` cannot be told apart from "checked, nothing refused" — the marker that would
distinguish them is deliberately not built here, and tracked as board card GAP-61. Separately, and not one of the
three, `guardlink sarif` omits an exposure carrying a declared `@mitigates`, so cxg is never
offered it at all (measured on temporal: 1 of 142).
`pentest/docs/ARCHITECTURE.md` § "The exposure identity a finding carries" is the authority.
**cxg's acceptance set is DERIVED from guardlink's grammar table, in both directions (GAP-54)**

cert-x-gen accepted a superset of guardlink's grammar along a different dimension for every
verb, so it could act on "threats" guardlink says were never validly declared. Six rounds of
hand-trimming did not converge. This derives the rule instead of trimming toward it, from the
`PATTERNS` table in `src/parser/parse-line.ts` (2.0.0) and the constants it is built from.

- **An END BOUND.** 28 of the 28 entries in that table are anchored `^…$` over the
  marker-stripped line — checked entry by entry over `dist`, since `dist` is what runs — so an
  annotation that leaves text unconsumed is a hard `validate` error there, **not a shorter
  annotation**, which is what cxg silently produced. One rule, replacing the per-verb trimming.
  It closes a fabrication as well as truncations: `@boundary #api| and #db -- "d"` used to
  report a trust boundary between `#api` and the keyword `and`, with the description dropped.
- **Operand classes spelled from guardlink's own constants**, not from the shapes anyone met:
  ASCII (`\w` is Unicode-aware in Python, so `#café` read here and is `Malformed` there), every
  dotted segment opening on a letter or underscore (`App.2fa` likewise), threats and controls
  routed through `TAG_REF` so a dotted cross-repo id such as `#shared-lib.injection` reads, and
  an external-ref tail of ANY count, ANY order and ANY key, as `EXT_REFS_OPT` has it.
- **A trailing lint pragma is read for `@comment` alone.** Measured one fixture per verb:
  `@comment` is the only verb the installed 2.0.0 leaves silent with ` # noqa` appended; the
  other twelve are hard `Malformed` errors. Extending where guardlink is silent is allowed;
  reading a form it refuses is not. Kept for `@comment` as a decision, not a gap — a lint pragma
  must not cost an author their intent note.

**Scope of the claim.** Measured across a 9,152-cell cross-product put to the installed binary,
in three slices: {15 endpoint forms} × {32 trailing characters} × {14 verb × asset positions},
the same forms and characters × {4 threat/control positions}, and {8 ext-ref tails} × {32
trailing characters} × {2 verbs that take one}. Cells cxg reads and guardlink refuses fell from
**2,324 to 32** — all 32 the `@flows` source endpoint, a documented backward-compatibility
tolerance. Cells guardlink reads and cxg refuses fell to **91**, below the base commit's own 97:
15 `@flows` endpoints and 76 bare-word or quoted forms cxg states it does not read, **0** outside
a stated bound.

**What it cost on a live corpus, with every build named.** Corpus siete `main` 733c0fb
(PR #121, 2026-09-12); cxg base **4b342e6**; cxg measured at **d18e2578**; guardlink 2.0.0. cxg
base reads **5,745** annotations in that tree and d18e2578 reads **5,648** — **97 no longer
read**, by kind `@exposes` 69, `@confirmed` 11, `@comment` 9, `@audit` 4, `@mitigates` 4.
guardlink models 558
annotations there and reads **0 of the 97**, so none of them is a form the shared grammar
accepts. Exactly **1** is a description opener written as a bare trailing `--` with the quote on
the next line; the end bound refuses that spelling on purpose, because `-- "` is two tokens and
the quote is what proves a description was opened on that line alone, while a bare trailing `--`
proves nothing and would make any trailing double dash an opener — the arbitrary-trailing-prose
class `_RE_DESC_TAIL_TRAILING` already refuses. (guardlink's own `LINE_MARKERS` does treat `--`
as a comment marker, but none of the 11 extensions cxg walks uses it that way, so that half of
the argument does not carry and is not relied on.)

**The figure at each head that changed the parser.** 0c7a9fb read 5,648 and 39962c5 reads 5,648,
a delta of **0**. No round after d18e2578 changes parser code. **The siete slice itself was NOT
re-measured after 39962c5**, because 733c0fb is not fetched into any local siete clone — that is
stated rather than papered over, and it is the one step of this figure a reader cannot repeat here.

**A comment TERMINATOR is admitted only where its OPENER is on the same line.** guardlink strips
one through anchored patterns that require the matching opener, so the free-floating form cxg
first shipped read `*)`, `-}`, `-->` and `*/` after an annotation in a `.py` file — each a hard
`Malformed` error on the binary — plus a block-comment body line ending `*/`. `-}` and `*)` are
dropped outright: no extension cxg walks uses `{-` or `(*`. The grid does not cross this
dimension; it was derived from `comment-strip.ts` and is now named beside the grid's tables.

**A CROSS-PRODUCT DOES NOT ELIMINATE THE BLIND SPOT; IT RELOCATES IT TO THE CHOICE OF WHICH
DIMENSIONS TO CROSS.** This is the law the card earns, and it is not rhetorical. The end bound
first landed measured on a grid that held two dimensions constant — the threat/control operand
and the ext-ref tail — and along exactly those two it turned 72 shapes guardlink models into
silent zeroes, because the bound is only ever as right as the clause in front of it. Both are
crossed now, both directions are gated
(`test_no_form_the_installed_guardlink_refuses_is_read_as_a_declaration` and
`…_accepts_is_refused_outside_a_stated_bound`), and what is still NOT crossed is written down
beside the tables. Known surviving superset, filed not fixed: `_SEV`'s `[A-Z]?\d+` half reads
`[P9]`, `[Z12]` and `[7]`, each a hard `Malformed @exposes` error on the binary; the grid does
not vary the severity bracket at all. Known stated divergence: `@flows` is exempt from the end
bound wholesale, which is wider than its justification — guardlink accepts a trailed flow only
when there is no description to bound its `via` clause. Known structural follow-up, filed on
GAP-32: the walk and the JOIN now disagree about what an annotation is — `_annotations_on_line`
requires the end bound and `_join_wrapped_description`'s nested-annotation stop still uses the
raw `_VERB_RULES` patterns, where the two rules were identical before this change.

**Any corpus figure in this entry names the commit it was measured on.** A count measured
against an unnamed or stale checkout is not a measurement; the 66 an earlier round nearly
shipped here counted annotations that no longer exist.

**cxg reads the annotation forms guardlink TEACHES, and some of what it accepts**

Three separate claims, because they are separately true. guardlink's `CLAUDE.md` Quick Syntax
block is a TEACHING SUBSET; `guardlink gal` is the authoritative grammar. This change does not
make cxg read guardlink's grammar, and nothing here should be read as saying it does.

- **(a) Teaching examples: 1 of 14 → 12 of 14.** guardlink's `CLAUDE.md` teaches fourteen
  Quick Syntax forms; the installed cxg parser read exactly one of them, the one-line
  `@comment`. A customer who followed guardlink's documentation wrote annotations cxg could
  not see, and nothing said so. `parse_inline` now reads twelve. The two it does not are
  `@actor`, which that block marks `(definitions file)` and which names no code, and
  `@flows`, whose widening was WITHDRAWN — see "What this change withdrew" below. Customer
  source is unchanged; the work is entirely inside cxg.
- **(b) Additional `gal` forms this change adds**, beyond the teaching subset: `@boundary`'s
  PRIMARY spellings `A and B (#id)` and `A | B` (cxg previously read only `between A and B`,
  which `gal` calls the alternate). The parenthesised id is `#`-prefixed and dot-free, derived
  one fixture per form from the installed binary — it accepts `(#data-boundary)` and calls
  `(data-boundary)`, `(zone.one)` and `(#zone.one)` hard `Malformed` errors — and a
  PARENTHETICAL the pattern cannot read refuses the whole annotation instead of silently
  dropping its description. That guard covers a parenthesis and nothing else — any other unread
  tail still half-reads, so `@boundary #api and #db extra -- "d"` is `Malformed` on the binary
  and cxg reads it as its two operands with the description gone. Refusing any unread tail was
  the general trimming problem GAP-54 carries and is **now closed by the END BOUND** described
  above, which supersedes this sentence: the parenthesis guard is no longer the only thing
  refusing an unread tail. Measured: of
  the 91 boundary ids across guardlink, siete and cert-x-gen, 0 are written without the `#` and
  0 carry a dot, so the narrowing costs nothing.
- **`@handles` reads only the classifications guardlink accepts.** The vocabulary is a CLOSED
  enumeration — `guardlink gal` spells the verb `@handles <classification> on <asset>` and lists
  `pii phi financial secrets internal public`, and guardlink's own generated
  `.guardlink/README.md` writes the same set — but cxg matched any word, so
  `@handles credentials on App.API -- "d"` was read as a live annotation while the installed
  binary calls it a hard `Malformed @handles` error. `handles` is in `_INTENT_LABELS`, so that
  description reached the generation prompt as the author's own statement of intent for a line
  guardlink says does not exist. The set is now closed and case-insensitive (the binary accepts
  `PII` and `FINANCIAL` too), verified one fixture per token against guardlink 2.0.0 rather than
  taken from the reference, and a test re-derives it from the installed binary and fails on
  drift — skipping cleanly where guardlink is not on PATH. Measured: all 148 classifications
  across guardlink, siete and cert-x-gen are members, so the narrowing costs nothing.
- **(c) `gal` forms this change DELIBERATELY LEAVES UNREAD.** `@mitigates`' control clause is
  optional in `gal` and `with` is accepted as a synonym for `using`, so
  `@mitigates db.users against Token Theft -- "Rotation implemented in v2"` — `gal`'s own
  second example — validates and parses on the installed binary and cxg still reads nothing
  for it. This is a decision, not a to-do: nothing consumes `@mitigates` (see the consumer
  table below), so widening it would add annotations no reader reads. Filed as **GAP-44**,
  blocked on **GAP-43**, which is where "should an inline declaration with no SARIF result
  behind it become a hypothesis?" gets settled.
- **The grammar was widened to what the INSTALLED guardlink accepts**, not to what an
  instruction file describes: `guardlink validate` over a fixture carrying all thirteen
  source-legal examples reports 0 errors. Assets may be a dotted path (`App.API`) or a bare
  capitalised identifier; severities accept guardlink's word spellings (all 88 severities in
  guardlink's own model are word form and NOT ONE is a `[P0]` code, so the only spelling cxg
  admitted was the one the corpus never writes). `@flows` IS UNCHANGED FROM origin/main — see
  "What this change withdrew".
- **Eight verbs cxg had no reader for at all** — `@confirmed`, `@boundary`, `@handles`,
  `@validates`, `@assumes`, `@transfers`, `@feature`, `@owns` — are read. They are not eight
  new parsers: `@assumes`, `@transfers`, `@boundary`, `@handles` and `@validates` reach the
  generation prompt as intent context, labelled with the verb their author wrote, and
  `@confirmed`, `@feature` and `@owns` are **recognised and consumed by nothing**, which is a
  stated contract rather than an omission. `@exposes`, `@mitigates` and `@audit` are in that
  same unconsumed group — six of the thirteen verbs in all, splitting three deliberate
  (`@confirmed`, `@feature`, `@owns`) and three actionable (`@exposes`, `@mitigates`,
  `@audit`, unconsumed because of GAP-43 rather than by decision). Hypotheses come from the SARIF,
  not from inline annotations, so an exposure declared inline with no matching SARIF result
  is invisible to cxg today; that is GAP-43 and is not decided here. Promoting `@confirmed` — a human asserting an
  exploit is real — into the context that decides whether a finding is a real vulnerability
  is an evidence-standard product call, not a parser change.
- **`.gal` sidecars are read.** `guardlink init` writes EXTERNAL annotation mode by default,
  putting annotations in `.guardlink/annotations/<path>.gal` and leaving source files bare.
  `.gal` is not a source extension, so on a repository set up the way guardlink's own
  instructions describe, cxg read zero annotations and lost every intent note in guardlink's
  DEFAULT mode. Annotations are attributed to the source file and line their `@source` header
  names, never to the sidecar — matching what the installed binary emits.


**What this change withdrew, and why**

`@flows` is byte-for-byte origin/main's behaviour on this head: the same pattern, the same
`attach_flows_to_hypotheses`, the same `derive_chain_edges`. Verified on twelve shapes —
plain, trailing period, trailing hyphen, a bare source, a fan-out, multi-hop, via-less, bare
endpoints, a leading-digit endpoint, a multi-word mechanism and an arrow inside one — every
one identical to main.

The `@flows` widening was attempted and withdrawn after six rounds. It is not that the
widening was wrong: via-less flows, bare and dotted endpoints and multi-word mechanisms all
worked. What did not converge was TRIMMING cxg back to what guardlink accepts. cert-x-gen
accepts a SUPERSET of guardlink's endpoint grammar and always has — `3rdparty`, `123`,
`a..b` and `.lead` are hard `Malformed` on the installed binary and origin/main reads all
four — and each round trimmed one dimension of that superset while holding another constant,
so every fix was right about the case in front of it and wrong about the dimension nobody
varied. Twice the result read a form guardlink rejects; twice it refused one guardlink
accepts.

The minimal withdrawal was measured rather than assumed: reverting only the endpoint
trimming leaves `# @flows #api -> #cache.` reading a destination `#cache.` that does not
exist, and that record reaches `derive_chain_edges` as a real chain edge. A consumer-side
check cannot cover it, because the junk is absorbed INTO the field rather than left over.
So the withdrawal is total.

Everything downstream of the widening went with it, so nothing in the tree is left describing
a flow this head cannot read. The consumer-side refusal of half-read declarations is INERT on
main's `@flows` — it requires a `via` clause and a `#`-prefixed destination, so no input can
produce the half-read record that refusal existed to act on (measured: 0 of 8 shapes) — and
the `partial` flag that fed it went with it, producer included. VIA-LESS flows went the same
way: `derive_chain_edges` skips a flow with no mechanism, so every derived edge carries one,
and the endpoint-derived artifact name (`edge_<digest>`), the branches that existed to
describe an edge with no mechanism, and the tests pinning them are all gone. Keeping any of it
would have shipped machinery no input can reach — the same defect this branch spent two days
filing against other code.

The generation prompt is therefore byte-identical to origin/main on the chaining path as well.
A label naming the declared `via` beside each artifact name was written here and REMOVED
before shipping: an edge is keyed by its SANITISED artifact name, so `via coupon.code` and
`via coupon-code` merge onto one edge and only the first channel string survives — and the
label reported that survivor to the other declaration's author as their own mechanism, under
a header vouching for everything below it as the codebase's own declaration and not a guess.
The merge is pre-existing, identical on origin/main, and stays open as **GAP-47**; what was
removed is the claim built on top of it. The operator console still prints
`(via <channel>)` — unchanged from origin/main, and beside `chain_edges_declared`, which lists
every declaration folded into the edge.

Filed as **GAP-54** with the six rounds of evidence, the `edge_6705daf7` trace showing an
invented id reaching a real chain edge, and the cross-product derivation
`{#-prefixed, bare, dotted} × trailing characters × verbs` that the next attempt should
START from rather than arrive at. The measurement that motivated the work stands: 37 of the
123 flows in guardlink's own repository can never become a chain edge.

### Fixed

- **cert-x-gen still reads annotations that enter no guardlink model by AT LEAST these routes, and
  this branch closed none of them — the list is NOT claimed to be exhaustive:** GAP-69 (`@shield`
  regions), GAP-72 (the double-star body run), GAP-73 (the unterminated HTML comment), GAP-74 (the
  `@comment` pragma tail), GAP-75 (the terminator whose opener sits inside the description), and
  the tail admissions on GAP-65 (any at-token after a complete annotation, and a second closed
  description). Nothing in this entry should be read as cert-x-gen having stopped reading what
  enters no guardlink model; by these routes it still does.

  **No total is published, and the absence is the correction.** Drafts of this entry said TWO and
  then FOUR; both were falsified by the next reading, the second by the round sent to fix the
  first. A count is a completeness claim about a set nobody has enumerated, so the failing step
  was writing one at all. "At least these, and not claimed to be all" survives a later discovery
  where a number does not.

  **The routes those totals omitted were the WORSE half.** The test is whether the annotation
  ENTERS GUARDLINK'S MODEL, not whether guardlink complains, and by it the enumerated cases are
  the mild ones: GAP-69 is an exclusion the binary makes deliberately and records, while GAP-72,
  GAP-73, GAP-74 and GAP-75 are mere SILENCE — 0 `guardlink validate` errors, the file reported
  unannotated by `guardlink parse`. Silence does not license reading: if "does not error" were the
  test, cxg could read arbitrary text, because the binary does not error on that either. The tail
  admissions are HARD REFUSALS, and measured at 83ad8a6 against the installed guardlink 2.0.0,
  one directory per shape with records counted from guardlink's own model, it reports 1 error and
  0 records for each of `// @audit #api -- "y" @later`, `// @audit #api -- "a" -- "b"`,
  `// @flows #api -> #db via redis -- "d" # noqa` and
  `# @comment -- "closed note" @audit #real-api -- "second"` while cert-x-gen reads one live
  annotation from every one. `pentest/docs/ARCHITECTURE.md` is the authority and carries the
  measurements; the routes below are summarised rather than re-derived.

  **`@shield` regions (board card GAP-69).** cxg honours no `@shield:begin`/`@shield:end` region,
  so it reads annotations the installed guardlink DELIBERATELY EXCLUDES from its model — **36**
  across guardlink f3b36ce, siete 7df5848 and cert-x-gen 4b342e6, every one in guardlink's own
  repository (`src/agents/prompts.ts` 30, `templates.ts` 4, `migrate-mode.test.ts` 2), counting
  annotations inside a MATCHED begin/end pair. A figure of 37 was published here and is
  withdrawn: it treated an UNCLOSED `@shield:begin` as running to end of file, and the only such
  begin in the tree is one NAMED inside a template string in `src/cli/index.ts`, which is the
  string-literal reading class this branch exists to remove. guardlink opens no region there
  either — `shields 0` on a fixture carrying that line — so cxg reading below it is correct
  rather than a suppression miss, and `cli/index.ts` contributes 0 rather than 1.
  Suppression was ruled out for this branch
  rather than overlooked — region state carried across lines is new machinery with its own
  failure modes (an unclosed begin, nested pairs, a region opened in one comment and closed in
  another), where every other change here REMOVED an admission. The estate's instruction files
  already tell authors not to annotate inside `@shield`, so the construct is known and only the
  implementation is absent.

  **The DOUBLE-STAR body run (board card GAP-72).** `_body_start_after` consumes a run of the
  marker's final character for every non-HTML marker, so a line whose trimmed start is `**` opens
  a comment body in cxg while guardlink reads nothing from it — the `**` block-comment
  continuation style is a real C-derived convention, so this is reachable in ordinary source.
  Measured exhaustively rather than sampled, and RE-DERIVED 2026-09-13 on this branch head
  against guardlink 2.0.0 once the decoration boundary was scoped back to the join — the figure
  below is what that run reports, not what an earlier commit in this entry claimed. Over all
  4,680 line-start prefixes of length 1-4 drawn from `/ # * ! < ^ | space`, one file per prefix
  carrying `@audit #api -- "d"` and the verdict read from guardlink's own model, cxg and
  guardlink 2.0.0 diverge on 46, every one cxg 1 / guardlink 0, and every one begins — after any
  leading spaces — with a DOUBLED `*`. Zero in the other direction. Identical over `.js` and
  `.py`, since both readers key on the marker and not the extension. It is carried as a BOUND
  rather than fixed
  here because narrowing it means special-casing the double star out of general marker-run
  handling — new discrimination rather than an admission removed, which is the opposite of every
  other change in this entry. Guarding the run with `marker != _BLOCK_BODY_MARKER` takes that
  differential to zero in both directions and costs 0 annotations across the three corpora, so
  the count is not what decided it; the shape of the fix is.

  **The UNTERMINATED HTML comment (board card GAP-73).** `<!--` opens a comment body in cxg and
  the binary additionally requires the comment to CLOSE. `<!-- @audit #api -- "d" -->` in a
  `.html` file is read by BOTH; the same line without its `-->` is read here and reported
  unannotated there, with `guardlink validate` clean. The closed control is what makes the
  missing terminator the discriminator rather than HTML comments generally — and rather than the
  mid-line form, which the line-start opener rule of this branch already refuses on both sides.
  Carried as a BOUND for the reason the others are: closing it adds a terminator requirement
  carried by one opener alone, which is new discrimination, and the `<!--` opener itself is
  load-bearing and stays.

  **The `@comment` PRAGMA TAIL (board card GAP-74).** `// @comment -- "x" # noqa` in a `.js` file
  is read here while guardlink reports the file unannotated with 0 errors and 1 "looks like prose"
  warning. It is admitted by `_PRAGMA_TAIL_ALTERNATIVE` — a comment marker plus whitespace or end
  of line, appended to the tail rule only for `_PRAGMA_TOLERANT_VERBS`, which is `{comment}` alone
  — and is **not** the admission GAP-65 describes, which is the `\s+@\w` at-token rule reaching
  every bounded verb. Proven orthogonal by disabling each alternative in turn over a two-line
  fixture carrying both shapes: removing the pragma alternative leaves only the at-token case,
  removing the at-token alternative leaves only the pragma case. The two also sit on opposite
  sides of the silence/refusal line — guardlink calls `// @audit #api -- "y" @later` a hard
  `Malformed` error where it merely stays silent on the pragma. Cite GAP-74 for this one and
  GAP-65 for the at-token one; neither covers the other. The admission is kept deliberately, so
  that a lint pragma does not cost an author their intent note, and being deliberate is not the
  same as entering guardlink's model — which is why it is counted here.

  **The decoration boundary is the JOIN's rule and is scoped to it.** `_decorations_after` is the
  one spelling of WHICH characters decorate a marker and how many; `_marker_tail_decorations` adds
  the rule that the run counts only where whitespace or end of text follows, and only the join
  calls it. That rule was briefly shared with the body-start step and narrowed it past the binary:
  a decoration flush against a verb made the body start land on the decoration, so `//!@audit`,
  `///<@audit`, `//!<@audit`, `/**<@audit`, `/*!@audit`, `#<@audit`, `##<@audit`, `//<@audit`,
  `//^@audit`, `//|@audit` and a block-comment ` *<@audit` body line each read 1 on guardlink
  2.0.0 and 0 here, while the spaced control `//! @audit` read on both. The two callers ask
  different questions — at the join a decoration against TEXT may be a character the author typed,
  at a body start nothing but the annotation follows it and consuming the run is how the verb is
  found — so the boundary lives with the question it answered. `_FLUSH_BODY_STARTS` pins all
  eleven spellings against the parser AND against the installed binary.

- **A verb must now OPEN a comment body to be read as an annotation (board card GAP-48).**
  cxg's patterns are search-based, so a verb sitting anywhere in ordinary prose parsed as a
  live annotation: `# We removed the @exposes #api to #idor -- "x"` read as a real exposure,
  while the installed guardlink 2.0.0 returns nothing for the same line. That is the
  FABRICATION direction — a threat-model claim guardlink cannot see, attributed to code that
  does not carry it — and it was the root cause of nearly every prose-fabrication finding filed
  on the grammar-widening branch, five of them from cxg's own comments. Rewording the offending
  comment closed one instance; the comments most likely to trip it are the ones EXPLAINING the
  parser, so that was a treadmill rather than a fix.

  A comment body begins ONLY at the start of a trimmed line, after an opener (`//`, `#`, `/*`,
  `<!--`) or after the block-comment body marker `*`. There is no mid-line opener and no
  all-occurrences scan, so a LINE yields at most one annotation. In a `.gal`
  sidecar it begins at the first non-space character — sidecar lines carry no comment marker,
  and that is the trap the card names: a naive anchor drops every sidecar annotation, and
  `.gal` reading is a shipped feature. Verified at 80 sidecar annotations before and after.

  Between the opener and the body a run of the marker's final character is consumed, then up to
  three DECORATION characters from `!`, `<`, `^` and `|`. That set is guardlink 2.0.0's, probed
  one ASCII punctuation character at a time after `//` and after `#`; the binary refuses `-`,
  `=`, `:`, `.`, `>` and `*`, and refuses a fourth decoration, and so does cxg. This was a
  REGRESSION the branch introduced and then fixed rather than a widening anybody wanted: `///<`,
  `/**<`, `//!<`, `//<`, `#<`, `//|` and `//^` are read by the binary and were read by cxg at
  4b342e6, and this branch read NONE of them until the set was spelled out — the Doxygen
  after-member markers, in four languages that are all in the walk's extension list. It converges
  both ways, since cxg still refuses `//-`, which 4b342e6 wrongly read. The corpora are silent on
  it — none of the three contains such a spelling — so the justification is binary agreement, and
  on this branch that is the third time the corpus count would have decided it wrongly. The
  `<!--` opener takes neither a run nor a decoration, measured the same way: `<!---`, `<!--<`,
  `<!--^`, `<!--!` and `<!--|` all parse to zero, with `guardlink validate` naming the character
  and saying the line is not parsed, and cxg read `<!---` until this rule spelled the exception.

  A THIRD body start — wherever a previous description had CLOSED, so that one comment could
  carry several annotations — was written and then REMOVED, and it is worth recording why
  rather than only that. It defeated the rule it was bounding: any quoted word followed by a
  verb satisfied it, so `# prose "quoted" @audit #a -- "x"` read as a live audit in cxg and as
  nothing at all in the installed guardlink, while the control `# @audit #a -- "x"` parses in
  both. And it read what the authority REFUSES rather than extending where the authority is
  silent — `guardlink validate` calls `# @comment -- "first" @audit #real-api -- "second"` a
  hard `Malformed @comment annotation` with `annotations_parsed 0`, and the same for a chained
  `@exposes`. **Removing it DOES cost records, and the cost is stated in the same words a gain
  would have earned:** putting the rule back adds exactly 22 annotations in siete 7df5848 and
  none in guardlink f3b36ce or cert-x-gen 4b342e6, so the 22 the adding commit recorded
  reproduce exactly — an earlier claim that they do not was measured against siete bc64e78 and
  is withdrawn. What settles it is not the size of that number but whose reader can see it: the
  installed guardlink parses the exact shape those 22 are written in — a wrapped note whose
  closing line carries a second verb after its quote — to `annotations_parsed 0`, and the
  one-line form to a hard `Malformed` error — and not only on that fixture: `guardlink parse` over
  siete reads 44 annotations in the whole repository, none on any of the 22 lines.

  **What that removes is a MECHANISM, not a count**, and
  `pentest/docs/ARCHITECTURE.md` § "What the removal changes is a MECHANISM, not a count" is the
  authority; this entry does not restate it. In short: chaining is gone in BOTH forms — off a
  closed description quote, and behind a second comment OPENER written later in the line, which
  the line-start rule removed with it. `x = 1 # @comment -- "n" // @audit #a -- "s"` reads
  NOTHING, its comment being trailing; the same text as a whole-line comment reads ONE, the note
  alone. The installed guardlink reads ZERO from both. An earlier draft of this entry claimed
  cert-x-gen reads at most one annotation per COMMENT: that sentence was false and is withdrawn,
  not qualified — the bound the parser implements is **one annotation per LINE**. **Board card
  GAP-56 is closed as obsolete** (see the same section). **Board card GAP-52 stays OPEN**: the
  display-markup residue it named measures zero on the corpus below, which is a fact about that
  corpus at those commits rather than a property of the code, and the card is its owner's to
  reframe. Extending the refusal to the whole line is separate, is new logic on the wrapped-note
  path, and is deliberately not done.

  What was actually run against the installed guardlink 2.0.0, rather than a blanket claim: the
  marker table (`//`, `  //`, `//@`, `///`, `//!`, `#`, `##`, `/*`, `/**`, `<!--`, a
  block-comment `*` body line), the decoration table (`///<`, `/**<`, `//!<`, `//<`, `#<`, `//|`,
  `//^`), every ASCII punctuation character after `//` and after `#` one at a time, the `.html`
  fixture, the two `.gal` shapes, and the refusals — a verb behind prose, a `TODO:`, a `-` bullet,
  a `(`, a quoted word, both chained forms, `//-`, a fourth decoration character, and the `<!--`
  decoration and run — each through `guardlink parse` and `guardlink validate` one fixture at a
  time. Everything
  else this entry describes is cxg's own reach, which the binary does not read at all.

  `<!--` is in that list because the binary is the authority in BOTH directions. `.html` is a
  deliberate member of the shared walk filter, guardlink reads
  `<!-- @exposes #x to #t -- "d" -->` in a `.html` file, and a server-rendered template is
  exactly where a customer annotates a form for #csrf or #xss — so omitting it would have
  narrowed cxg PAST the tool it is aligning to and dropped a real note in silence, which is
  forbidden as firmly as accepting more — within the domain the two share, which is the
  qualifier `pentest/docs/ARCHITECTURE.md` carries: where guardlink reads a language
  `_TEXT_EXTS` does not, being narrower is meaningless rather than wrong. Board card GAP-57, the
  six further comment styles cxg declines, is a stated bound but is NOT an instance of that
  qualifier — the binary reads those inside the walked extensions too, and ARCHITECTURE.md
  carries the corrected reason and its measurement. **Its cost on
  corpus (A) is now ZERO annotations re-admitted**, re-derived 2026-09-13 with the parser at
  a0bd9ba. It was 3 when the opener was added — all of them TypeScript test-fixture string
  literals in guardlink's own suite (`tests/review.test.ts:180` and `:193`,
  `tests/dashboard-determinism.test.ts:144`) — and every one of the 3 carries its `<!--`
  mid-line, so the later narrowing to a line-start opener refuses them. A wrapped HTML note is
  still not joined: the continuation line of an HTML comment carries no marker, the same stated
  bound as a wrapped trailing comment (GAP-34).

  **Measured 2026-09-13 over guardlink f3b36ce, siete 7df5848 and cert-x-gen 4b342e6, with
  both parsers run over the SAME trees.** Every corpus figure in this entry was taken there, because
  two defensible checkout sets of these repositories exist on the build machine and they give
  different answers; all three commits are BEHIND their respective mains — guardlink f3b36ce
  dates from 2026-09-04 and guardlink main has since merged PR 36 — so this is a fixed
  measurement corpus, not a claim about any repository's current state. An earlier round
  published a set measured on a second, mixed pair of checkouts (`~/Documents/GITHUB` guardlink
  7f331ea with siete bc64e78, whose siete is not an ancestor of siete main); those figures are
  withdrawn wherever they appeared.

  The walk read 10,311 annotations with the parser at 4b342e6 and 9,123 with the parser at
  a0bd9ba: **1,188 fewer, 11.5%.** Nothing is added and nothing returns with CHANGED FIELDS. The 5
  field-change records an earlier set of these figures disclosed are gone, because the single
  dashboard line that produced them no longer parses at all; that line is kept on record because
  the two numbers describing it are easy to confuse — `docs/examples/threat-dashboard.html` line
  NUMBER 7,566, character COUNT 341,627, in a file of 8,418 lines and 1,268,772 bytes.

  One file dominates: that generated dashboard falls from **713 phantom reads to 0**, so
  excluding it the walk reads 9,598 before and 9,123 after — 475, **4.9%**, with nothing added.
  Both decompositions close: 713 + 475 = 1,188, and per repository guardlink 1,578 → 603, siete
  5,221 → 5,128, cert-x-gen 3,512 → 3,392, whose nets are 975 + 93 + 120 = 1,188. Sidecars are
  unchanged at 80 → 80. Every one of the 475 was classified: 444 sit on lines that are not
  comments at all — test-fixture string literals, template text, generated display markup — 9
  are prose on a comment line that names a verb while explaining it, and 22 are the chained
  second annotations described above, all 22 in siete.
  **So 453 of the 475 are fabrications and 22 are notes a human did write.** Whether the binary
  can see any of them was measured rather than inferred: `guardlink parse` over the three corpora
  reads 510 + 44 + 1,544 annotations, and intersecting their `location.file`/`location.line` with
  the 1,188 records cxg stops reading gives the empty set — on not one of those lines does
  guardlink read anything at all.

  **The 1,188 is the cost ESTIMATE, never the reason.** The reason is authority-matching:
  guardlink reads nothing from a trailing comment on a code line, measured over six shapes in
  six languages, so a customer who writes `const DEBUG = 1; // @exposes …` stops having that
  note read by cxg AND guardlink already read nothing from it, which makes cxg match the
  authority rather than lose to it. These three repositories are not a sample of customer code,
  so the count bounds what WE lose and says nothing about what a customer writes.

  Two scope notes. Narrowing to an opener at the start of a trimmed line cost 223 annotations
  (guardlink 78, of which 24 are the dashboard's own phantom reads; siete 62; cert-x-gen 83),
  and that is a cost PAID in a0bd9ba rather than one a later round would pay: the walk read
  9,346 at 6c958a6 and reads 9,123 at a0bd9ba, so those 223 are the narrowing's slice of the
  1,188 above. All 223 classify into the fabrication class — 199 inside a string literal, 24
  generated markup — by a quote-parity test whose residue and a random sample were re-read by
  hand, which found none written beside code. Board card GAP-34 carries the open/wrapped half.
  A `.gal` sidecar line
  carrying TWO annotations now yields the first and not both — and here, unlike in a source
  comment, no second marker can reopen the chain, since a sidecar line has exactly one body start
  and honours no marker at all — and against the binary that is CONVERGENCE rather
  than loss: guardlink refuses such a line outright as malformed and reads ZERO from it, while
  the one-per-line form it actually emits parses as two. cxg stopped reading something guardlink
  never read. And closing this did NOT
  subsume the continuation-line case as GAP-48 predicted — a verb on a continuation line does
  open that line's comment body — so **GAP-32 stands as filed**. What it did close besides
  prose generally is the opener whose join FAILS, whose quoted verb sits mid-line.

- **A verb written inside a note's own description is no longer read as an annotation.** A
  human explaining which mitigation they deliberately did NOT write had that mitigation
  recorded as real. The example is from guardlink's own `tests/fixtures/expense-api`:
  `@comment -- "Written first as @mitigates #api against #malformed-input using
  #auth-required, which nothing rejected even though the control and the threat have nothing
  to do with each other"`. This is one defect in three places — on a continuation line, on a
  line that opens a description running off its end, and on a line where the note opens and
  closes — and this closes the last of those outright and the opening line WHERE THE
  DESCRIPTION JOINS. The opener whose description never closes is covered too, by the opening
  rule rather than by this narrowing: the quoted verb sits mid-line, so an unterminated note
  whose prose names a `@validates`, a `@handles` or a `@boundary` emits NOTHING now, where each
  used to emit the nested verb. Widening the verb set from five to thirteen is what
  made it necessary rather than tidy. It was the only annotation the bound removed across all
  three annotated repositories. The quoted-description span that backed it up — `_RE_DESC_SPAN`,
  `_quoted_spans` and its `@feature` arm — was DELETED in 41607a5 as unreachable, so nothing
  "must begin outside a closed description span" any more; the opening rule refuses these shapes
  first, and `pentest/docs/ARCHITECTURE.md` carries that measurement.
- **The CONTINUATION-line case is NOT closed and is carried as an open bound** (board card
  GAP-32). The join refuses to run past such a line, but `parse_inline` visits it again on its
  own turn, and a verb there genuinely does open that line's comment body, so it is emitted. The
  smallest
  closure was prototyped and measured: it removes 9 fabrications in cert-x-gen but loses 191
  descriptions in siete and overturns a standing PR-74 decision, so it is filed rather than
  attempted. `pentest/docs/ARCHITECTURE.md` carries the measurement.
- **A hyphen is refused in a bare or dotted reference.** `@exposes User-Store to #sqli`,
  `@exposes App-Name.API to #sqli`, `@assumes App.API-v2`, `@transfers #ddos from App-X to
  Ext.CF` and `@boundary internal-network and #db` are every one a hard `Malformed` error on
  the installed guardlink 2.0.0, and cxg read all five as live annotations — `@assumes` and
  `@boundary` carrying their descriptions into the generation prompt as the author's stated
  intent, so a note guardlink calls malformed arrived labelled as one a human wrote. Where the
  asset comes last and the description is optional (`@audit`, `@assumes`, `@handles`) the
  refusal covers the WHOLE annotation rather than degrading into a match that reports an asset
  the author never wrote with the description silently gone. A hyphen after `#` stays legal
  (`#prepared-stmts` is guardlink's own spelling), as does `@owns`' owner token
  (`security-team`, likewise). The flow endpoint keeps its hyphen as a stated
  backward-compatibility tolerance, because cxg read `user-agent` and `3rdparty` before this
  widening. Measured at 0 of 2,133 reference values across guardlink, siete and cert-x-gen —
  the narrowing costs no annotation anywhere.
- **A `.gal` `@source` header is recognised only at the start of a line.** Matched anywhere, a
  note whose own description quoted the header text was consumed as a header — losing its own
  annotation and silently re-attributing every note below it to the quoted path, so a "this is
  by design" note could reach a hypothesis in a different file. Leading whitespace still opens
  a block, because the installed guardlink parses an indented header.
- **Scanned files are decoded as `utf-8-sig`, named rather than left to the machine's locale.**
  `read_text` with no encoding decodes with the SCANNING MACHINE'S locale, so two people reading
  the same repository could get different annotation sets and therefore different threat models,
  out of an environment variable. That is the subject of the change (0e23be9); the BOM is only
  where it became visible. `str.lstrip()` does not remove U+FEFF and Python's `\s` does not match
  it, so a BOM-prefixed first line opened no comment body, and a BOM-prefixed `.gal` `@source`
  header did not match at all — leaving `target` on the sidecar, so EVERY annotation in that
  file was attributed to the `.gal` instead of the source the header names. Those records are
  read and then reach nothing, because `_AnnotationIndex` keys on the path and
  `_annotations_near` on the line, which makes it a silent MIS-ATTRIBUTION rather than a drop.
  The `-sig` half consumes the BOM as part of the decode, so no explicit strip and no per-line
  BOM clause exists anywhere — the one added in a72799b was deleted again in 0e23be9 rather than
  kept beside an encoding that already strips. Justified on binary agreement: guardlink 2.0.0
  reads a BOM-prefixed line-one annotation and anchors a BOM-prefixed header to the file it names.

  **What the corpus measurement does and does NOT cover, stated together.** Measured with the
  parser at 0e23be9 against the locale path over guardlink f3b36ce, siete 7df5848 and cert-x-gen
  4b342e6: 603 / 5,128 / 3,392 both ways, 0 added, 0 removed, 0 field-changed. That zero is real
  and it is narrow. This machine's locale is UTF-8, so the two decode paths agree by construction
  except on a BOM-prefixed file, and of the 848 files the walk opens across the three corpora —
  841 source files plus the 7 `.gal` sidecars, all 7 in guardlink — ZERO carry a BOM. So the
  figure bounds how many records OUR repositories gain or lose from BOM
  handling — none, because they have none — and bounds NOTHING about cp1252, about Windows, or
  about a non-ASCII description on a machine whose locale is not UTF-8. The evidence that the
  change does anything at all is the byte-level test rows, which write `EF BB BF` and UTF-8 smart
  quotes to disk and assert what the parser reads back; the cp1252 case is reasoned from the
  encoding and is executed nowhere.

**What went wrong repeatedly here, and why it was predictable**

Review of this change turned up **six** defects where a written claim exceeded what the code
does — the consumer table, the closed-severity set, the "one defect closed in three places"
claim, the endpoint grammar, the chain-block note on where artifact names come from, and the
headline itself — plus **two false guards**: tests whose assertions passed identically whether
or not the thing they guarded had regressed. These are not unrelated tidy-ups, and the
structural reason is worth stating because it predicts the defect rather than regretting it:
**a change to what a parser ACCEPTS falsifies documentation at a higher rate than most
changes, because the documentation's whole subject is what it accepts** — every widening
invalidates some sentence describing the old bound, including sentences in files the diff does
not touch. Both false guards were found by asking of each test the same question: would it
still fail if the thing it guards were deleted? A guard that cannot fail is worse than no
guard, because it reports coverage it does not have.

One more, and it is the cheaper lesson of the two: **a finding that keeps returning in new
shapes is a cause that has not been named.** The multi-hop `@flows` declaration produced FIVE
findings across five rounds — a hypothesis both providing and requiring one artifact; a
declared hop ordering never applied; two providers silently overwriting one artifact key; an
artifact name that depended on which hypothesis the run iterated first; and finally a
legitimate SINGLE-hop declaration losing its chain edge because a chain was annotated nearer
the same hypothesis. Each fix produced the next, and the fifth was a regression against main on
a path this change was supposed to leave alone. The cause under all five is that a flow
record's IDENTITY and its skip-or-name decision were keyed on different tuples: the dedup keys
on `(src, dst, channel)` while the added `hops` field decided the outcome, so the record that
survived the dedup decided the answer. Multi-hop reading is therefore withdrawn entirely rather
than patched a fifth time, and filed as GAP-49 so whoever picks it up starts from that cause
instead of rediscovering four symptoms. When the same declaration produces a third finding,
stop fixing it and go looking for what makes it produce findings.

**The instrumentation component — building a target that can earn its verdict**
- **`cxg build --instrument`** — a new verb that produces an *instrumented* build of a
  compiled target, so the CLI Security Baseline's low-level classes reach real
  `confirmed`/`refuted` verdicts instead of an honest skip. It detects the build system,
  asks **rustc** what the target can do rather than guessing, builds into a private target
  directory, **re-reads the binary it just produced**, and prints one JSON manifest.
  Cargo/Rust is the only back end; every other recognised build system skips with
  `build-system-not-implemented`.
  `cxg scan` is untouched: it still inspects and refuses, and never builds anything.
  Building runs the project's own build system as the invoking user and costs minutes and
  gigabytes, which is why it is a verb rather than a scan flag.
- **There is no path from "I could not instrument this" to "here is a binary."** Every
  precondition failure is a `skipped` with a machine-readable reason —
  `unknown-build-system`, `build-system-not-implemented(...)`,
  `nightly-toolchain-unavailable(...)`, `sanitizer-unsupported-on-target`,
  `sanitizer-not-verifiable(...)`, `binary-target-ambiguous(pass --bin NAME)`,
  `rust-src-missing(...)`, `instrumented-build-failed(exit=N)` with the last 20 log lines,
  and **`build-produced-no-instrumentation(wanted=… detected=…)`** for a build that reported
  success and produced an artefact carrying none of what it was asked for.
- **`rust-overflow-checks` instrumentation label and the `overflow` oracle.** Rust has no
  UBSan — `-Zsanitizer=undefined` does not exist on any target — so the integer class
  (CWE-190) is carried by `-C overflow-checks=on`, which cxg passes on every instrumented
  build. The detector reads it from the symbol table
  (`core::panicking::panic_const::panic_const_*_overflow`), and `overflow` is a
  *build-dependent* oracle, so a template's overflow branch cannot claim a verdict on a
  build where the check was compiled out.
- **`cxg scan --instrumented-manifest <path>`** — provenance beats inspection. Where cxg
  built the binary itself it already read the artefact back, and that record is used in
  preference to re-sniffing the file, for the binary the manifest names and no other. A
  manifest recording a *skipped* build is an error rather than a silent no-op. Omit the flag
  and a scan behaves exactly as it did before.
- Toolchain cost, stated plainly: **nightly Rust is required** for `-Zsanitizer`
  (`rustup toolchain install nightly`). There is no stable equivalent. Where it is missing,
  `cxg build` skips with an actionable reason and the proof tests explain themselves and
  pass rather than failing a build over it.

**The probe contract — driving a local binary and recording an honest verdict**
- `--scope cli:///path/to/binary` — a scan target can be a locally-built executable rather
  than a network host. `CERT_X_GEN_TARGET_HOST` carries the binary path and the new
  `CERT_X_GEN_TARGET_KIND` says which kind it is. `CERT_X_GEN_TARGET_PORT` is meaningless
  when `KIND=cli` and should be ignored there. A `cli:` scope entry is taken verbatim, so a
  path containing a comma is not split.
- **Execution ledger.** Every (template, target) pair now produces a row in
  `ScanResults.executions` carrying `confirmed` / `refuted` / `errored` / `skipped` /
  `timed-out`, the finding count, the exit code and a reason — so a refutation is
  first-class and observable in the result JSON instead of being indistinguishable from a
  template that did nothing. A new **Execution Status** block reports it in the terminal.
  cxg infers the status from what it observed; a template may override it with
  `{"metadata": {"status": ..., "detail": ...}}`, and `declared_by_template` records which
  happened.
- `# @allow_nonzero_exit: true` — a probe template that provokes a crash in its target
  naturally exits non-zero. cxg now keeps its stdout instead of discarding the finding, the
  sanitizer report and the exit code along with it.
- `--arg` (repeatable, hyphen-leading values allowed), `--stdin-file`, `--input` and
  `--target-env` — cxg supplies the probe's argv, stdin, seed corpus and target environment,
  delivered as `CERT_X_GEN_ARGV`, `CERT_X_GEN_STDIN_FILE`, `CERT_X_GEN_INPUT_DIR` and
  `CERT_X_GEN_TARGET_ENV`. Each is absent unless its flag was passed.
- `--require-instrumentation` — inspect a `cli://` build for sanitizer, coverage and
  debug-info markers before running anything against it, and record `skipped` with a reason
  (`no-instrumentation-detected`, `target-not-found`, `oracle-unavailable(...)`) rather than
  running a probe and reporting a refutation the build could not have earned. The detected
  set is exported to templates as `CERT_X_GEN_TARGET_INSTRUMENTATION`.
- `# @oracles:` and `# @target_kinds:` template annotations. A declared target-kind mismatch
  is recorded as `skipped` rather than run. An absent `@target_kinds` accepts every kind, so
  no existing template changes behaviour.
- `# @oracles: exception` — the one oracle cxg implements itself. A Python traceback or a Node
  unhandled rejection exits 1 with no crash signal, so `signal` never fires and `exit` fires on
  every correct non-zero exit too. A template that declares `exception` hands the target's
  output back in `{"metadata": {"target_output": ..., "target_exit_code": ...}}` and cxg
  matches the per-language shape of an escaped exception (CPython, Node, JVM, Go, Rust),
  recording `confirmed` with `oracle=exception(<kind>)` and a finding carrying the evidence.
  Both new metadata fields are optional, and a template that declares no `exception` oracle is
  unaffected.

### Changed
- **This repository's own inline annotations now use GuardLink's bare verbs.** Every
  annotation here was written to the grammar of Giggs, a discontinued predecessor, which
  prefixes each verb `@g.` — a form the `guardlink` binary reads as nothing at all, so the
  whole corpus was absent from its threat model (`annotations_parsed: 0`). 3,202 `@g.comment`
  verbs across 115 files became `@comment`; no description text, asset, severity or layout
  changed. `guardlink parse` now reads 1,511 of them (0 before). cxg's own `parse_inline` is
  unaffected — it accepts both forms and reads the same 3,256 annotations before and after.
  Two verbs are deliberately left in the old form because they do not map onto GuardLink's
  grammar: `@g.sink` (7), which has no `@sink` counterpart, and `@g.source` (9), whose bare
  `@source` is an unrelated `file:line` anchor directive that fails `guardlink validate`.

### Fixed
- **`--scope-file` failed open.** It is how an operator tells `cxg pentest` what a scan is
  allowed to touch, and every way of failing to read it left the run going on the built-in
  defaults: a path that did not exist returned them **silently**, and an unparseable file —
  or a machine without PyYAML — printed one warning line that scrolled past while the scan
  proceeded. The operator believed the blast radius was bounded and it was not.
  `ScopeConfig.load` now **refuses**: a missing path, an unopenable file, invalid YAML, a
  document that is not a mapping of settings, an empty file, an empty flag value, or PyYAML
  being absent all raise `ScopeFileError`, and `run_pentest` stops with **exit 4** (a
  mis-specified run, not 2, which means "vulnerabilities found") before it resolves the
  codebase or runs guardlink. The empty-value refusal covers direct invocation of the
  orchestrator; `cxg pentest run --scope-file "$SCOPE"` with `SCOPE` unset never reaches it,
  because clap rejects an empty value as a usage error (exit 2) before forwarding argv.
  The message names the path, the reason, and the next action. Passing **no** `--scope-file`
  is unchanged and is not an error — absent is not unreadable, and an operator who set no
  bound still gets the documented defaults.
- Reading a scope file requires **PyYAML**, which no install path checked for: `cxg pentest
  install` verified only playwright and anthropic. It now verifies PyYAML too and names it
  in the `pip3 install` line it prints, it is pinned in `pentest/requirements.txt`, and it
  is named in the refusal — so a machine without it is told what to install instead of
  scanning unbounded. Measured on a host where no interpreter on PATH could import `yaml`:
  before this change every `--scope-file`, valid or not, was ignored.
- `--scope-file` is refused with exit 4 on `--template-lang py`, and the refusal now runs in
  pre-flight, before `--interactive-auth` capture and `--creds-file` re-auth. The legacy
  Python probe path enforces no scope at all, so a file accepted there was read and
  discarded; and an operator who mistyped the path used to complete every interactive login
  first and be refused afterwards.
- A template that outran its execution timeout kept running unsupervised: the timeout stopped
  awaiting the child but never killed it. `execute_command` now sets `kill_on_drop`.
- `--require-instrumentation` skipped **every** template against a target carrying no
  instrumentation, including templates whose oracles need nothing from the build. An
  interpreted CLI can never detect instrumentation, so the flag made cxg refuse to test one at
  all. A template declaring only build-independent oracles (`exit`, `signal`, `timeout`,
  `exception`) now runs and reaches a real verdict; one declaring a sanitizer oracle, or
  declaring none, is still skipped with `no-instrumentation-detected`.
- The instrumentation marker scan read any file, so a shebang script or JS bundle that merely
  *mentioned* `__asan_init` — in a comment or its own documentation — was classified as an
  instrumented build and the preflight passed. The scan now runs only on compiled objects
  (ELF, Mach-O, PE, static archives); everything else reports `none`.
- `cxg pentest` read almost none of the inline `@comment` intent notes an annotated codebase
  carries, so the design decisions those notes exist to explain reached the ranking and
  probe-writing model as unexplained code. Two independent causes, both fixed: the `@g.` verb
  prefix (`@g.comment`) that agent instruction files then taught was not accepted at all, and a
  description wrapped onto a second comment line was read as no annotation rather than as one
  joined note. Measured across three annotated repositories before the fix, 8,098 notes on disk
  read as 140. The bounds that remain — the `\"` escaping rule, the continuation-line cap, and
  the trailing-comment opener that is deliberately not joined — are documented under "Inline
  annotations" in `pentest/docs/ARCHITECTURE.md`.

## [1.3.0] - 2026-08-13

### Added

**Desktop application pentesting**
- `cxg pentest run --target-type electron` — launch, isolate, and probe Electron desktop
  applications. cxg starts N isolated app instances (via `--app-cmd` or `--app-binary`),
  drives their renderers over CDP, and additionally probes IPC channels, renderer security
  configuration, and local data at rest. Add `--host-scan-path` to also scan an existing
  installation directory. Tauri is explicitly **unsupported** — it exposes no CDP endpoint on
  macOS or Linux.

**Out-of-band (OAST) callback confirmation**
- `--oast-interactsh [<server>]` — cxg registers an interactsh session it **owns** and polls it,
  so a callback becomes a genuine `confirmed=true` finding with the interaction recorded as
  evidence. This is different from `--oast <host>`, which only **injects** a callback URL that
  cxg **cannot read back** (e.g. Burp Collaborator or a canary you host): under `--oast`, blind
  probes (SSRF, blind SQLi/XXE/cmd-injection) fall back to status-code and timing heuristics and
  findings stay **unconfirmed** — reading the callback is the operator's job, in their own
  tooling. The two flags **conflict at the CLI level deliberately**: two canaries would leave
  "was this confirmed?" with no single answer per finding.

**Crash recovery for desktop targets**
- `--no-restart` — do not relaunch a desktop target that dies mid-scan (the run ends with a
  truncation caveat and exit code 3).
- `--stall-timeout <secs>` — idle-time bound that catches a frozen app (electron only).
- `--template-timeout <secs>` — absolute per-template dispatch ceiling (a backstop).

**Non-interactive CI authentication**
- `cxg pentest auth import` — write an auth profile from a session captured once and exported as
  a Playwright `storage_state`, with no browser. The state can come from a file, from stdin
  (`--storage-state -`), or from the base64 environment variable `CXG_AUTH_STATE_<NAME>`.
- `cxg pentest auth verify` — liveness-check a saved session (exit 0 alive / non-zero dead)
  before a run spends any AI budget.
- `cxg pentest run --ci` (also enabled by `CXG_CI=1`) — a dead or expired auth session becomes a
  hard failure with **exit code 5** at pre-flight, so a pipeline never silently probes
  unauthenticated.
- `--auth-dir <dir>` — read/write auth profiles from a directory other than `~/.cert-x-gen/auth`,
  so CI can restore a bundle of imported profiles and point the run at it.

**AI generation**
- `bridge` AI provider — posts each prompt to `$BUGB_BRIDGE_URL` (with
  `Authorization: Bearer $BUGB_BRIDGE_TOKEN` when set) and reads the completion back; an
  editor/CI integration point rather than a local CLI. It is preferred first by
  `--ai-provider auto` whenever `$BUGB_BRIDGE_URL` is set.

**Reporting**
- `threat_id` on findings in `report.json`, linking each finding back to the originating
  guardlink hypothesis (`null` for AI- or mutation-synthesised probes).
- `review_only_threats` in `report.json` (electron): routeless guardlink threats that have no IPC
  channel to test, surfaced for manual review rather than silently dropped.
- Engine-stamped actor provenance — every request now records which captured identity issued it,
  which feeds cross-identity (IDOR / privilege-escalation) triage in the report and audit log.

**Templates**
- `@requires_capability` template header — a probe declares a substrate capability it needs; the
  engine skips any template whose capability the running substrate does not provide, instead of
  recording an undefined-namespace error as a refutation.

**Environment**
- `CXG_NO_NAG` — opt out of the occasional one-line post-scan GitHub-star request (which prints
  only on an interactive terminal and at most once a week).

### Changed
- `--help` restructured into functional groups, with a two-tier split: `-h` shows one terse line
  per flag, `--help` shows the full explanation. `cxg scan -h` went from **375 lines to 95**.
- The ASCII banner is now suppressed whenever stdout is **not** a terminal. `cxg --version` is a
  single, parseable line, and piped output is clean — previously the banner corrupted
  `cxg search --format json | jq`. Explicit overrides remain: `CXG_NO_BANNER`, `--quiet`/`-q`.
- Configuration sections are now optional. A partial config file loads, with omitted sections and
  omitted keys taking their compiled-in defaults.
- A configuration file that still contains a `sandbox` section **still loads**. cxg now prints
  a warning on load, and `cxg config validate` reports the file as loadable-with-obsolete-sections
  rather than valid, stating that the settings never took effect and that template execution is
  not confined. Silently ignoring the keys would leave operators believing they are hardened.
- `cxg sandbox` — the command that manages per-language dependency environments — is unaffected
  and unchanged in behaviour. Its help text and docs no longer describe it as providing
  "isolation" or "security": it separates packages, not privileges.
- A started Docker environment with `auto_start` no longer implies the running command is
  contained by it. cxg now says explicitly that the command executes on the host; use
  `cxg sandbox enter` to work inside the container.
- `docs/SANDBOX_GUIDE.md` renamed to `docs/DEPENDENCY_ENVIRONMENTS.md`, matching what it
  documents.

### Fixed
- `cert-x-gen.example.yaml` now loads through the config parser. It previously failed to load on a
  required field that had no default; a regression test now loads it on every build.
- Fewer false "confirmed" pentest findings: the empty-evidence guard no longer mistakes a finding
  carrying only bookkeeping keys for one that the AI confirmed with real evidence.
- Documentation was aligned with actual behaviour across `README.md` and the `--help` tree — false
  and stale claims were removed or corrected (see Notes below).

### Removed

**The `sandbox` configuration section, which never took effect.**

- Removed the `sandbox` section from the configuration schema: `sandbox.enabled`,
  `sandbox.memory_limit_mb`, `sandbox.cpu_limit_percent`, `sandbox.network_access` and
  `sandbox.filesystem_access`, along with the `NetworkAccess` and `FilesystemAccess` enums.

  **These settings never did anything.** No code path has ever read them to confine, throttle,
  or restrict template execution. Their only consumer was `ResourceManager`, which was never
  constructed outside its own unit test. A configuration setting `sandbox.enabled: true` with
  `filesystem_access: readonly` and `network_access: none` produced a run identical to one with
  no sandbox configuration at all: the template read the process uid and username, listed the
  user's home directory, confirmed `.ssh` was readable, spawned a child process, and made an
  outbound DNS query. **Any configuration relying on these keys was not protected by them**, and
  `cxg config validate` reported such a file as simply valid.

  Templates execute as ordinary child processes with the invoking user's privileges and full
  network and filesystem access. Review templates before running them. For isolation, run cxg
  itself inside a container or VM, as a non-privileged user.

- Removed `ResourceManager` from `src/scheduler.rs`, and the now-unreachable `Error`
  variants `ResourceLimitExceeded` and `SandboxViolation` (with the `Error::resource_limit`
  constructor) — no cxg error path can report a limit or a violation, because no limit or
  confinement is enforced anywhere.

**Dead configuration keys.**

- **36 dead configuration keys** and the unused metrics module. Every one of these keys was parsed
  but had **no effect**. Existing config files that still set them **continue to load** — the keys
  are simply ignored.
  - (a) Removed, no plan to reinstate: `global.{verbosity,color,log_level,log_file,debug}`,
    `templates.{use_system_templates,use_user_templates,use_local_templates,auto_update,cache_dir}`,
    `network.{http2,dns_servers,follow_redirects}`,
    `execution.{threads,passive_mode,safe_mode,cache_enabled}`, `output.stream`,
    `metrics.{enabled,export_port,export_format}`, `plugins.{enabled,directories,plugins}`,
    `ai.fallback_providers`, `ai.cost_tracking.*`, `ai.cache.*`.
    (`network.follow_redirects` was removed as a config key only; the `--follow-redirects` flag is
    unaffected.)
  - (b) Removed, but plausible candidates to reinstate wired up later — these describe things a
    config file could reasonably control, and were removed because they lied, not because the
    capability is unwanted: `output.min_severity`, `output.formats`, `output.output_dir`,
    `output.output_file`, `templates.enabled_languages`.

### Notes — accepted-and-ignored surface

Stated plainly so it produces no more false leads:

- **Template execution is NOT sandboxed.** Despite earlier "sandboxed by default" claims in this
  changelog and the README, no execution path isolates or resource-limits templates: they run as
  ordinary child processes with the invoking user's privileges and full network and filesystem
  access. Run cxg inside a container or VM if you need isolation. (`cxg sandbox` manages
  per-language *dependency* environments — it does not confine template execution.) The
  `sandbox` config section that appeared to configure confinement is removed in this release,
  and a config still carrying it now warns rather than loading silently — see **Removed**.
- Nine `cxg scan` flags are accepted and silently ignored: `--protocol`, `--protocols`,
  `--threads`, `--stream`, `--resume`, `--distributed`, `--coordinator`, `--worker-id`,
  `--profile`. They are now grouped under a "Not Implemented" heading in `--help`.
- `cxg server` is not implemented — it exits with an error; its `--tls*`, `--port`, `--bind`, and
  `--auth-token` flags are accepted but do nothing.
- Runtime templates are distributed separately, in the
  [cert-x-gen-templates](https://github.com/Bugb-Technologies/cert-x-gen-templates) repository, and
  installed to `~/.cert-x-gen/templates/`. No template count is stated here.

## [1.2.0] - 2026-08-01

### Added

**AI-driven whitebox pentest pipeline (`cxg pentest`)**
- New subsystem that reads guardlink's `whitebox/findings.sarif`, LLM-ranks threats against an
  operator goal, and has a local AI CLI (claude / codex / gemini, or the Anthropic / OpenAI HTTP
  APIs) write JavaScript probe templates that read the target's source to craft code-aware
  payloads. Those templates run in N parallel **authenticated** Chromium contexts, emitting
  confirmed / refuted / ambiguous findings to `report.json` plus a JSONL audit log of every HTTP
  request.
- Interactive auth capture for SSO/MFA flows (`cxg pentest auth`), chained-auth probes for
  cross-user IDOR (`--auth-numbers 2+`), scope enforcement (URL/method allowlist, per-endpoint
  budget, 5xx hard-kill), validator-guarded code generation, and retry-with-mutation on ambiguous
  triage.
- Operator-supplied identity metadata — `--tier`, `--persona`, `--cohort`, and free-form `--tag`
  — fed to the AI ranker so it selects the right identity per probe.
- The Python orchestrator is embedded in the binary (via `include_dir!`) and installed on demand,
  for a self-contained distribution.
- `cxg update` — self-update the `cxg` binary to the latest released build.

### Fixed
- SPA dashboards are no longer false-flagged as dead sessions during pentest pre-flight and
  session-health checks.
- Template config-directory resolution is now cross-platform (fixes Windows).
- `AIManager` provider tests are isolated from any on-disk AI config.

### Security
- Cleared dependency advisories: openssl 0.10.73 → 0.10.81 (8 advisories),
  bytes 1.10.1 → 1.12.1 (integer overflow), git2 0.18 → 0.20.4 (GHSA-j39j-6gw9-jw6h),
  prometheus 0.13 → 0.14 (protobuf advisory). TLS/HTTP stacks were consolidated onto reqwest.

## [1.1.1] - 2026-03-25

### Added

**MCP Server (Model Context Protocol)**
- 12-tool MCP server for AI agent integration via `cxg mcp` (there is no `serve` subcommand — the
  server is the bare `cxg mcp` invocation)
  - `cxg_search`, `cxg_template_list`, `cxg_template_info`, `cxg_scan`
  - `cxg_template_validate`, `cxg_template_create`, `cxg_template_write`
  - `cxg_template_get_notes`, `cxg_ai_generate`, `cxg_template_test`
  - `cxg_template_stats`, `cxg_template_update`
- `cxg mcp install` — auto-configure 6 AI coding agents (Claude Desktop, Claude Code, Cursor,
  Windsurf, VS Code, Zed), matching `src/mcp/installer.rs`

**AI Template Generation**
- `cxg ai generate` — natural-language to template generation (dual-mode: scaffold or full)
- Multi-provider support: Ollama (local-first default), OpenAI, Anthropic, DeepSeek
- `--api-key` flag for session-only cloud provider authentication

**Parameterised Template Metadata**
- 5 new metadata fields on the template struct: `context_vars`, `vuln_class`, `hypothesis_tags`,
  `batch_group`, `auto_probe` (an earlier revision of this entry listed `confidence`,
  `execution_mode`, and `pipeline_stage`, which do not exist)
- `@field:` annotation parsing across all 12 supported languages
- `context` and `batch_group` parameters added to the `cxg_scan` MCP tool

**Template CLI Extensions**
- `cxg template search` — search templates by query, language, severity, or tags
- `cxg template pwd` — display template directory paths with existence status
- `cxg template skeleton` — view scaffold template for any supported language
- `cxg template add` — copy a local template file into the user template directory

### Fixed

- Auto-migrate official template repository URL on org rename (`BugB-Tech` → `Bugb-Technologies`)
- Detect remote URL drift during `cxg template update` and re-clone when necessary
- `cargo fmt` formatting in skeleton template error path

### Changed

- Template library and MCP server template metadata refreshed. (An earlier revision of this entry
  cited specific template counts — 58 and 147 — that did not correspond to any shipped template
  population; templates are maintained in the separate cert-x-gen-templates repository, so no count
  is stated here.)

## [1.0.0] - 2025-01-13

### Added

**Core Engine**
- Polyglot template execution supporting 12 programming languages
  - Interpreted: Python, JavaScript, Ruby, Perl, PHP, Shell
  - Compiled: Rust, C, C++, Go, Java
  - Declarative: YAML (Nuclei-compatible)
- Sandboxed execution with configurable resource limits
- Compilation caching for compiled language templates
- Parallel template execution with rate limiting

**CLI (`cxg`)**
- Unified `--scope` option for target specification (single host, file, CIDR, URL)
- Smart `--templates` selection with glob patterns, tags, and severity filtering
- Template management commands: `list`, `update`, `validate`, `info`, `search`
- Multiple output formats: JSON, HTML, CSV, Markdown, SARIF
- Configuration via CLI flags, config file, or environment variables

**Template System**
- Git-based template repository management with auto-update
- Official templates repository with 58 templates across 6 languages
- Template validation and metadata extraction
- Skeleton templates for all supported languages

**Output & Reporting**
- HTML reports with dark theme (Antigravity style)
- SARIF output for CI/CD integration
- JSON Lines (JSONL) streaming output
- Structured finding format with evidence capture

**Integration**
- Cookie passthrough for authenticated scanning
- Proxy support
- Rate limiting (global, per-host, per-protocol)

### Security
- Sandboxed template execution
- Template signature verification (planned)
- Safe defaults for all operations

> Note: the "sandboxed execution" claims in this 1.0.0 entry never reflected the shipped binary —
> template execution has never been isolated or resource-limited. See the 1.3.0 Notes.

---

[Unreleased]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/Bugb-Technologies/cert-x-gen/compare/v1.0.0...v1.1.1
[1.0.0]: https://github.com/Bugb-Technologies/cert-x-gen/releases/tag/v1.0.0
