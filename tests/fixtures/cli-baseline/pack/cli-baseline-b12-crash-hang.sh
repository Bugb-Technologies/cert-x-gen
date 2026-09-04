#!/usr/bin/env bash
# @id: cli-baseline-b12-crash-hang
# @name: CLI Baseline B12 - crash or hang on malformed input
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: medium
# @description: Feeds malformed, truncated, oversized and deeply-nested input through arguments, files and stdin. A fatal signal, an unhandled exception trace or a timeout is a robustness defect - and is reported as exactly that, not as an exploit.
# @tags: cli, baseline, robustness, fuzzing-adjacent, cwe-20, cwe-400
# @cwe: CWE-20
# @target_kinds: cli
# @oracles: signal, timeout, exception
# @allow_nonzero_exit: true
#
# BASELINE CLASS B12 - crash / hang on malformed input (CWE-20, CWE-400).
# Detectability: PARTIAL.
#
#   input      malformed, truncated, oversized and deeply-nested payloads
#              through argv, a file argument and stdin.
#   observable a fatal signal (rc >= 128), a timeout (rc 124), or an unhandled
#              language-level exception in the output.
#   oracles    signal, timeout, exception -- all BUILD-INDEPENDENT, so this
#              class still runs under `--require-instrumentation` (s15 fix 4)
#              while B11 correctly does not.
#
# THE CLAIM THIS TEMPLATE MAKES, AND THE ONE IT DOES NOT.
# A crash is proof of a robustness defect. It is NOT proof of exploitability,
# and the finding says so in its own text. Deciding whether a given crash is
# reachable with attacker-controlled data and corrupts anything is white-box
# work this baseline deliberately does not pretend to do.
#
# The target's output is handed back in `metadata.target_output` so cxg can
# apply its own `exception` oracle (s15 commit 12) -- it recognises an escaped
# Python traceback, Node rejection, Java exception or Go panic per language,
# which is the oracle neither `exit` nor `signal` can express.
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
cxg_lab b12
cxg_seed_corpus

# Malformed inputs, as files the target can be pointed at.
python3 - "$PWD" <<'PY'
import os, sys
lab = sys.argv[1]
notes = os.path.join(lab, "notes")
os.makedirs(notes, exist_ok=True)
cases = {
    "malformed":  "this line has no key value separator\n",
    "truncated":  "{\"unterminated\": ",
    "oversized":  "key=" + ("A" * 200000) + "\n",
    "nested":     "[" * 5000 + "]" * 5000,
    "nul":        "key=value\x00trailing\n",
    "highbits":   "key=\udcff\udcfe\n".encode("utf-8", "surrogateescape").decode("latin-1"),
    "repeat":     "repeat=100000000\n",
    "empty":      "",
}
for name, body in cases.items():
    with open(os.path.join(notes, name), "w", errors="surrogateescape") as fh:
        fh.write(body)
    with open(os.path.join(lab, name), "w", errors="surrogateescape") as fh:
        fh.write(body)
PY

CASES="malformed truncated oversized nested nul highbits repeat empty"

CANDIDATES="$(cxg_pick_subcommands 'parse|read|load|import|show|render|convert|export|validate|check|extract|format|lint|run' 10)"
[ -n "$CANDIDATES" ] || CANDIDATES="$(cxg_subcommands | head -8)"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B12)"

EXERCISED=0
SEEN=""

adjudicate() { # adjudicate <description> <probe-label>
    CXG_TARGET_OUTPUT="$CXG_OUT"
    local kind="" sev="medium" conf=85 patterns=""

    if [ "$CXG_RC" -ge 128 ] && [ "$CXG_RC" -ne 143 ]; then
        kind="fatal signal $((CXG_RC - 128))"
        sev="high"; conf=95; patterns="fatal-signal"
    elif [ "$CXG_RC" -eq 124 ]; then
        kind="timeout after ${CXG_TIMEOUT}s"
        patterns="timeout"
    else
        case "$CXG_OUT" in
            *"Traceback (most recent call last)"*|*"UnhandledPromiseRejection"*|\
            *"Uncaught Error"*|*"Exception in thread"*|*"panic: "*|\
            *"thread 'main' panicked"*|*"terminate called after throwing"*)
                kind="unhandled exception escaped to the top level"
                patterns="unhandled-exception"
                ;;
            *) return 0 ;;
        esac
    fi

    FINDINGS="$(cxg_finding \
        "$sev" "$conf" \
        "Crash or hang on malformed input: $kind" \
        "Malformed input ($1) delivered through $2 produced: $kind. Exit status $CXG_RC. This is a ROBUSTNESS defect -- the tool did not diagnose input it should have rejected. It is NOT, on this evidence, a proof of exploitability: establishing whether the failure corrupts memory or is reachable with attacker-controlled data needs source or an instrumented build, which this black-box baseline deliberately does not claim to provide." \
        "CWE-20,CWE-400" \
        "$CXG_BIN $2 <$1 input>" \
        "$CXG_OUT" \
        "$patterns" \
        "{\"oracle\":\"$patterns\",\"case\":\"$1\",\"probe\":\"$2\",\"target_exit_code\":$CXG_RC,\"exploitability\":\"not-established-by-this-check\"}")"
    cxg_confirm "oracle=$patterns($kind) exit=$CXG_RC case=$1 probe=$2 class=B12" "$FINDINGS"
}

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    # NO well-formed control gate here, deliberately, unlike the other
    # classes. B12's subcommands come from the target's own `--help`, so they
    # exist; and requiring a well-formed input this template can synthesise
    # would drop every subcommand whose valid input is not a text file -- an
    # archive, say -- which is exactly where the interesting crashes live. The
    # refutation names the subcommands it probed instead, and `cxg_refute`
    # still refuses to fire unless probes were delivered.
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"
    for CASE in $CASES; do
        cxg_run "$SUB" "$CASE"
        adjudicate "$CASE" "$SUB"
        cxg_run "$SUB" "$PWD/$CASE"
        adjudicate "$CASE (absolute path)" "$SUB"
    done
done <<EOF
$CANDIDATES
EOF

# stdin, which many tools read with no argument at all.
for CASE in $CASES; do
    cxg_run_stdin "$PWD/$CASE"
    adjudicate "$CASE" "stdin"
done

[ "$EXERCISED" -gt 0 ] || cxg_skip "no-candidate-subcommand-ran(B12)"

cxg_refute "target diagnosed every malformed, truncated, oversized and deeply-nested input across$SEEN class=B12"
