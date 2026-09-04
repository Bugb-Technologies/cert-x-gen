#!/usr/bin/env bash
# @id: cli-baseline-b01-argument-injection
# @name: CLI Baseline B01 - argument injection via un-separated argv
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: high
# @description: Sends a value that is both a legal argument and a legal option of a downstream helper. If the target forwards it without a `--` end-of-options separator, the helper parses it as its own option and performs the option's side effect.
# @tags: cli, baseline, argument-injection, cwe-88
# @cwe: CWE-88
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B01 - argument injection (CWE-88).  Detectability: CLEAN.
#
#   input      a value that is legal data AND a legal option of a downstream
#              helper -- `--write-to=<canary>` and its common spellings, each
#              pointed at a path inside this template's own lab.
#   observable the option's side effect happens: the canary file exists. The
#              caller only ever named a note; a file appearing on disk proves
#              the value crossed an argv boundary it should not have crossed.
#   oracle     property -- a filesystem post-condition.
#
# Why not an exit oracle: the target exits 0 in BOTH the vulnerable and the
# safe case here, and the fixed build exits NON-zero when it correctly refuses.
# An exit oracle would get this class exactly backwards, which is the concrete
# argument for `property` being in the oracle vocabulary at all.
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
cxg_lab b01
cxg_seed_corpus

# --- every subcommand that plausibly hands an argument to a helper ---------
CANDIDATES="$(cxg_pick_subcommands 'export|render|print|convert|publish|send|open|view|format|show|cat|copy|upload')"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B01 needs one that forwards an argument to a helper)"

CANARY="$PWD/b01-argv-canary.txt"
[ -e "$CANARY" ] && cxg_error "canary-present-before-probe"

EXERCISED=0
SEEN=""

# HEREDOC, not a pipe: `cxg_confirm` exits, and a piped loop would exit only
# its own subshell.
while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    # A control per subcommand: the target must accept some benign input here
    # before a quiet probe against it can mean anything.
    cxg_working_arg "$SUB" >/dev/null || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    # Payloads that are simultaneously legal data and a legal file-writing
    # option. Each points inside this template's own lab, so the observable is
    # produced without touching anything the target owns.
    for PROBE in "--write-to=$CANARY" "--output=$CANARY" "--log-file=$CANARY"; do
        cxg_run "$SUB" "$PROBE"
        if [ -e "$CANARY" ]; then
            FINDINGS="$(cxg_finding \
                high 95 \
                "Argument injection: a caller-supplied value reached a helper as an option" \
                "The target was asked for an item named \"$PROBE\" through its \`$SUB\` subcommand. It forwarded that string to a downstream helper without a \`--\` end-of-options separator, so the helper parsed it as one of its own options and performed the option's side effect, creating $CANARY. The target exited $CXG_RC -- indistinguishable from the safe case, which is why this class needs a property oracle rather than an exit oracle." \
                "CWE-88" \
                "$CXG_BIN $SUB $PROBE" \
                "$CXG_OUT" \
                "canary-file-created" \
                "{\"oracle\":\"property\",\"post_condition\":\"canary file exists\",\"subcommand\":\"$SUB\",\"target_exit_code\":$CXG_RC}")"
            cxg_confirm "oracle=property(argv-canary-created) exit=$CXG_RC sub=$SUB class=B01" "$FINDINGS"
        fi
    done
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "control-failed(no candidate subcommand accepted a seeded input; tried:$(printf '%s' "$CANDIDATES" | tr '\n' ' '))"

cxg_refute "target treated every hyphen-leading value as data across$SEEN (no canary) class=B01"
