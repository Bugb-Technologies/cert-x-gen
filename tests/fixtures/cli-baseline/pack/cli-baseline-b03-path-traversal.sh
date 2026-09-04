#!/usr/bin/env bash
# @id: cli-baseline-b03-path-traversal
# @name: CLI Baseline B03 - path traversal in a file-naming argument
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: high
# @description: Sends relative and absolute paths in an argument the target uses to name a file inside a root it owns. If the bytes of a file outside that root come back on stdout, the root is not enforced.
# @tags: cli, baseline, path-traversal, cwe-22
# @cwe: CWE-22
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B03 - path traversal in a file argument (CWE-22).
# Detectability: CLEAN.
#
#   input      a name containing `../` (and an absolute path) that resolves
#              outside the tool's own data root, pointing at a canary this
#              template planted.
#   observable the canary's CONTENT appears in the target's output. Content,
#              not an error string: the nonce is a value no correct run of any
#              tool could ever produce.
#   oracle     property -- an output post-condition.
#
# The template does not care WHICH error a safe build returns, only that the
# nonce never appears. That is what makes the refutation robust across tools
# with completely different diagnostics.
set -uo pipefail

CXG_LIB="$(dirname "$0")/cli-baseline.lib"
if [ ! -r "$CXG_LIB" ]; then
    printf '{"findings":[],"metadata":{"status":"errored","detail":"probe-library-not-found"}}\n'
    exit 0
fi
# shellcheck source=cli-baseline.lib
. "$CXG_LIB"

cxg_require_cli_target
cxg_control_alive
cxg_lab b03
cxg_seed_corpus

CANDIDATES="$(cxg_pick_subcommands 'show|cat|read|print|get|open|view|render|export|parse|convert|dump|inspect')"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B03 needs one that names a file)"

# The canary is OUTSIDE any root the target would own -- one level up from the
# seeded `notes/` directory, still inside this template's lab.
NONCE="$(cxg_nonce CXG-B03-CANARY)"
printf '%s\n' "$NONCE" >"$PWD/outside.txt"

EXERCISED=0
SEEN=""

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    cxg_working_arg "$SUB" >/dev/null || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    for PROBE in "../outside.txt" "notes/../../outside.txt" "..%2Foutside.txt" "$PWD/outside.txt"; do
        cxg_run "$SUB" "$PROBE"
        if printf '%s' "$CXG_OUT" | grep -qF "$NONCE"; then
            FINDINGS="$(cxg_finding \
                high 95 \
                "Path traversal: a relative name read a file outside the tool's own root" \
                "The target's \`$SUB\` subcommand was asked for \"$PROBE\". It joined that name onto its own data root without a containment check and returned the contents of a file outside it. The canary nonce $NONCE -- which no correct run can produce -- came back in the output with exit $CXG_RC." \
                "CWE-22" \
                "$CXG_BIN $SUB $PROBE" \
                "$CXG_OUT" \
                "$NONCE" \
                "{\"oracle\":\"property\",\"post_condition\":\"canary nonce in output\",\"subcommand\":\"$SUB\",\"probe\":\"$PROBE\",\"target_exit_code\":$CXG_RC}")"
            cxg_confirm "oracle=property(canary-nonce-echoed) exit=$CXG_RC probe=$PROBE sub=$SUB class=B03" "$FINDINGS"
        fi
    done
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "control-failed(no candidate subcommand accepted a seeded input)"

cxg_refute "target kept every traversal probe inside its own root across$SEEN class=B03"
