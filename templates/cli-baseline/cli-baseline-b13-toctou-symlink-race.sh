#!/usr/bin/env bash
# @id: cli-baseline-b13-toctou-symlink-race
# @name: CLI Baseline B13 - TOCTOU / symlink race
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: high
# @description: Races a symlink swap against the target's check-then-use window. If the canary behind the symlink is written or read, the check was against a path and the use resolved it again.
# @tags: cli, baseline, toctou, race, symlink, cwe-367
# @cwe: CWE-367
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B13 - TOCTOU / symlink race (CWE-367).
# Detectability: PARTIAL -- PROBABILISTIC.
#
#   input      a bait file the target is asked to operate on, replaced with a
#              symlink to a canary while the target is between its check and
#              its use.
#   observable the canary was written (or read) -- the target followed a link
#              that did not exist when it made its decision.
#   oracle     property -- a filesystem post-condition.
#
# READ THE NEGATIVE CAREFULLY. A refutation here means "N attempts did not win
# the race", NOT "there is no race". The window in a real tool is microseconds
# and this probe is a shell loop; losing is the expected outcome even against a
# genuinely vulnerable target. That asymmetry is why the baseline rates this
# class Partial and why the refutation text says how many attempts were made --
# a reader who needs certainty needs source, not more attempts.
#
# The canary lives inside this template's lab, so a target that DOES follow the
# link writes somewhere harmless.
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
cxg_lab b13
cxg_seed_corpus

CANDIDATES="$(cxg_pick_subcommands 'touchfile|touch|update|mark|write|save|lock|stat|check|verify|chmod|edit|append|sync' 8)"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B13 needs one that writes to a named path)"

ATTEMPTS="${CXG_B13_ATTEMPTS:-6}"
CANARY_SENTINEL="CXG-B13-CANARY-UNTOUCHED"

EXERCISED=0
SEEN=""
TOTAL=0

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue

    BAIT="$PWD/b13-bait-$SUB"
    CANARY="$PWD/b13-canary-$SUB.txt"
    printf 'bait file, safe to overwrite\n' >"$BAIT"

    # Control: the target must actually operate on a plain file here, or a
    # quiet result says nothing about racing.
    cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$SUB" "$BAIT" >/dev/null 2>&1 || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    N=0
    while [ "$N" -lt "$ATTEMPTS" ]; do
        N=$((N + 1))
        TOTAL=$((TOTAL + 1))
        rm -f "$BAIT" "$CANARY"
        printf 'bait file, safe to overwrite\n' >"$BAIT"
        printf '%s\n' "$CANARY_SENTINEL" >"$CANARY"

        "$CXG_BIN" "$SUB" "$BAIT" >"$PWD/b13-out.txt" 2>&1 &
        BG=$!
        CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))

        # Swap the bait for a symlink at a spread of delays, so the loop is not
        # betting everything on one guess about where the window is.
        sleep "$(python3 -c "print(0.05 * $N)")"
        rm -f "$BAIT" 2>/dev/null && ln -s "$CANARY" "$BAIT" 2>/dev/null

        wait "$BG" 2>/dev/null
        CXG_RC=$?
        CXG_OUT="$(cat "$PWD/b13-out.txt" 2>/dev/null)"

        if ! grep -qF "$CANARY_SENTINEL" "$CANARY" 2>/dev/null; then
            FINDINGS="$(cxg_finding \
                high 90 \
                "TOCTOU: the target followed a symlink swapped in after its check" \
                "The target's \`$SUB\` subcommand was pointed at a plain file. While it ran, that path was replaced with a symlink to $CANARY, and the canary's contents were overwritten -- so the check the target made was against the PATH, and the later use resolved that path again to whatever it named by then. Won on attempt $N of $ATTEMPTS (exit $CXG_RC). The fix is to operate on a file descriptor, or to open with O_NOFOLLOW, rather than to check faster." \
                "CWE-367" \
                "$CXG_BIN $SUB <path swapped for a symlink mid-run>" \
                "$CXG_OUT" \
                "canary-behind-symlink-modified" \
                "{\"oracle\":\"property\",\"post_condition\":\"canary behind symlink was written\",\"attempt\":$N,\"attempts_budget\":$ATTEMPTS,\"subcommand\":\"$SUB\",\"target_exit_code\":$CXG_RC}")"
            cxg_confirm "oracle=property(symlink-followed attempt=$N/$ATTEMPTS) exit=$CXG_RC sub=$SUB class=B13" "$FINDINGS"
        fi
    done
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "control-failed(no candidate subcommand operated on a named path)"

cxg_refute "$TOTAL race attempts across$SEEN did not win -- NOT evidence the window is absent, only that this probe did not hit it class=B13"
