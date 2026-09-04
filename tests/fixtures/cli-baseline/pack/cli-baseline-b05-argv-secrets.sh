#!/usr/bin/env bash
# @id: cli-baseline-b05-argv-secrets
# @name: CLI Baseline B05 - credentials exposed in the process table
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: high
# @description: Invokes the target with a credential-shaped option and reads the process table from a second process during the run. If the value reaches a child process's argv, every other user on the host can read it.
# @tags: cli, baseline, secrets, argv, cwe-214
# @cwe: CWE-214
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B05 - secrets exposed in argv (CWE-214).  Detectability: CLEAN.
#
#   input      a random nonce passed as `--password`, and the target run in
#              the background so the probe can watch it.
#   observable the nonce appears in the command line of a process OTHER than
#              the one this template launched -- i.e. the target propagated
#              the credential into a child's argv, where `ps` exposes it to
#              every account on the host.
#   oracle     property -- a process-table post-condition.
#
# The one invocation this template makes itself does not count: the operator
# chose to pass the credential that way, and blaming the tool for the caller's
# choice would be a false positive on every tool that has such an option at
# all. What the tool controls, and what this measures, is whether it PASSES IT
# ON. The second half of the class -- whether a file/stdin/env alternative
# exists at all -- is reported as context, not as the verdict.
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
command -v ps >/dev/null 2>&1 || cxg_skip "no-ps-available(this class needs a second view of the process table)"
cxg_lab b05
cxg_seed_corpus

CANDIDATES="$(cxg_pick_subcommands 'login|auth|authenticate|sync|push|pull|connect|register|publish|upload|deploy')"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B05 needs one that takes a credential)"

# Does the tool offer a non-argv way to supply the credential? Context for the
# finding, never the oracle.
ALTERNATIVES="$(cxg_help_text | grep -oE '\-\-(password|token|secret|key|credential)[a-z-]*(file|stdin|env|path)|[A-Z][A-Z0-9_]*_(PASSWORD|TOKEN|SECRET|KEY)' | sort -u | tr '\n' ' ')"
[ -n "$ALTERNATIVES" ] || ALTERNATIVES="none-found"

EXERCISED=0
SEEN=""

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    NONCE="$(cxg_nonce CXGB05SECRET)"

    # Run in the background so the process table can be read WHILE it runs.
    #
    # Deliberately NOT through cxg_timeout. A wrapper such as `timeout` is
    # itself a process carrying the credential in its argv -- it was handed the
    # whole command line -- so wrapping would make the uninteresting baseline
    # two processes instead of one and turn every tool into a false positive.
    # Launching the target directly makes "exactly one carrier" mean "the
    # target and nothing else", which is the comparison this class needs. The
    # watchdog below supplies the time bound the wrapper would have.
    "$CXG_BIN" "$SUB" --password "$NONCE" >"$PWD/b05-out.txt" 2>&1 &
    BG=$!
    (
        sleep "$CXG_TIMEOUT"
        kill -TERM "$BG" 2>/dev/null
    ) >/dev/null 2>&1 &
    WATCHDOG=$!
    CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))

    # Sample repeatedly: the window is however long the child lives.
    #
    # The matching is done inside python rather than with `grep`, so the
    # observer never appears in its own observation -- a `grep <nonce>` carries
    # the nonce in its OWN argv and is counted as a carrier, which reads as a
    # leak on a tool that never leaked anything. python3 gets the nonce through
    # the environment, which `ps` does not show.
    HITS=0
    SAMPLE=""
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        SNAP="$(ps -Ao pid=,args= 2>/dev/null | CXG_NONCE="$NONCE" python3 -c '
import os, sys
nonce = os.environ["CXG_NONCE"]
print("\n".join(l.rstrip("\n") for l in sys.stdin if nonce in l))')"
        COUNT="$(printf '%s' "$SNAP" | python3 -c '
import sys
print(sum(1 for l in sys.stdin if l.strip()))')"
        if [ "$COUNT" -gt "$HITS" ]; then
            HITS="$COUNT"
            SAMPLE="$SNAP"
        fi
        [ "$HITS" -gt 1 ] && break
        sleep 0.25
        kill -0 "$BG" 2>/dev/null || break
    done
    wait "$BG" 2>/dev/null
    CXG_RC=$?
    kill "$WATCHDOG" 2>/dev/null
    wait "$WATCHDOG" 2>/dev/null || true
    CXG_OUT="$(cat "$PWD/b05-out.txt" 2>/dev/null)"

    # If we never saw even our OWN invocation carrying the credential, the
    # target exited before the process table could be read and there was no
    # window in which a leak could have been observed. That is not a
    # refutation, so this subcommand does not count as exercised.
    if [ "$HITS" -eq 0 ]; then
        continue
    fi
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    # Exactly one process carrying it is the invocation this template made, and
    # the operator chose that. More than one means the TARGET handed the
    # credential on to something else, which is the tool's own decision and the
    # defect this class names.
    if [ "$HITS" -gt 1 ]; then
        REDACTED="$(printf '%s' "$SAMPLE" | sed "s/$NONCE/<REDACTED-NONCE>/g" | head -5)"
        FINDINGS="$(cxg_finding \
            high 90 \
            "Credential propagated into a child process's command line" \
            "The target's \`$SUB\` subcommand was given a credential as \`--password\`. During the run $HITS processes carried that value in their command line, so the target passed it on to at least one child process rather than keeping it to itself. Any account on the host can read it out of the process table for as long as that child lives. Non-argv alternatives advertised by the tool: $ALTERNATIVES. Target exit $CXG_RC." \
            "CWE-214" \
            "$CXG_BIN $SUB --password <nonce>" \
            "$REDACTED" \
            "credential-in-child-process-argv" \
            "{\"oracle\":\"property\",\"post_condition\":\"nonce visible in more than one process\",\"processes_carrying_credential\":$HITS,\"subcommand\":\"$SUB\",\"alternatives_advertised\":\"$ALTERNATIVES\",\"target_exit_code\":$CXG_RC}")"
        cxg_confirm "oracle=property(credential-in-child-argv procs=$HITS) sub=$SUB class=B05" "$FINDINGS"
    fi
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "no-candidate-subcommand-ran(B05)"

cxg_refute "credential stayed in the invoked process only across$SEEN (alternatives: $ALTERNATIVES) class=B05"
