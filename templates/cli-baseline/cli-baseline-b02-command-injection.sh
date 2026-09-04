#!/usr/bin/env bash
# @id: cli-baseline-b02-command-injection
# @name: CLI Baseline B02 - OS command injection through an argument
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: critical
# @description: Sends shell metacharacters bound to a benign, observable side effect through every argument that plausibly reaches a shell. If the side effect happens, the argument was interpreted by a shell rather than passed as data.
# @tags: cli, baseline, command-injection, cwe-78
# @cwe: CWE-78
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B02 - OS command injection (CWE-78).  Detectability: CLEAN.
#
#   input      a working argument with shell metacharacters appended, each
#              bound to the most boring side effect available: creating one
#              empty file inside this template's own lab.
#   observable the canary file exists. Only a shell could have created it.
#   oracle     property -- a filesystem post-condition.
#
# The payload is deliberately `touch <path-in-our-own-lab>` and nothing else.
# The class is proved by ANY command executing; proving it with a destructive
# one would add no information and a great deal of risk.
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
cxg_lab b02
cxg_seed_corpus

CANDIDATES="$(cxg_pick_subcommands 'render|show|export|print|convert|parse|open|view|cat|run|exec|build|sync|search|find|grep|diff|log')"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B02 needs one that takes an argument)"

CANARY_DIR="$PWD/b02-canaries"
mkdir -p "$CANARY_DIR"

EXERCISED=0
SEEN=""

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    ARG="$(cxg_working_arg "$SUB")" || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    N=0
    for META in '; touch %s' '$(touch %s)' '`touch %s`' '| touch %s' '&& touch %s' $'\ntouch %s'; do
        N=$((N + 1))
        CANARY="$CANARY_DIR/$SUB-$N"
        # shellcheck disable=SC2059  # META is this template's own format string
        PROBE="$ARG$(printf "$META" "$CANARY")"
        cxg_run "$SUB" "$PROBE"
        if [ -e "$CANARY" ]; then
            FINDINGS="$(cxg_finding \
                critical 95 \
                "OS command injection: an argument was interpreted by a shell" \
                "The target's \`$SUB\` subcommand was given an argument carrying shell metacharacters. The embedded command ran and created $CANARY, which no correct handling of that argument as data could produce. The target exited $CXG_RC. Only the metacharacters changed between this run and the control." \
                "CWE-78" \
                "$CXG_BIN $SUB <arg + shell metacharacters>" \
                "$CXG_OUT" \
                "canary-file-created,shell-metacharacter-executed" \
                "{\"oracle\":\"property\",\"post_condition\":\"canary file exists\",\"subcommand\":\"$SUB\",\"target_exit_code\":$CXG_RC}")"
            cxg_confirm "oracle=property(shell-canary-created) exit=$CXG_RC sub=$SUB class=B02" "$FINDINGS"
        fi
    done
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "control-failed(no candidate subcommand accepted a seeded input)"

cxg_refute "no shell metacharacter reached a shell across$SEEN class=B02"
