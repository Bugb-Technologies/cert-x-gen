#!/usr/bin/env bash
# @id: cli-baseline-b07-path-hijack
# @name: CLI Baseline B07 - untrusted search path / PATH hijack
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: high
# @description: Prepends a controlled directory of benign shims named for common helper programs to PATH. If the target runs one of them, it is resolving helper names through the caller's search path.
# @tags: cli, baseline, path-hijack, cwe-426, cwe-427
# @cwe: CWE-426
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B07 - untrusted search path (CWE-426, CWE-427).
# Detectability: CLEAN.
#
#   input      a directory prepended to PATH holding shims named for helpers a
#              CLI commonly shells out to. Each shim writes one canary file and
#              exits 0 -- it does nothing else at all.
#   observable a canary exists, so a shim ran, so the target resolved a bare
#              command name through a search path the caller controls.
#   oracle     property -- a filesystem post-condition.
#
# The shims are the safest thing that can still be observed: an empty file and
# a zero exit. Nothing is shadowed that this template did not create, and the
# hijack directory disappears with the lab.
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
cxg_lab b07
cxg_seed_corpus

SHIMS="$PWD/b07-shims"
CANARIES="$PWD/b07-canaries"
mkdir -p "$SHIMS" "$CANARIES"

# Helper names a command-line tool commonly invokes by bare name. Deliberately
# excludes the interpreters this template and the target itself depend on
# (sh, env, python3, perl), because shadowing those would break the run rather
# than observe it.
for HELPER in git tar gzip bzip2 xz zip unzip openssl gpg gpg2 ssh scp rsync \
              curl wget diff patch less more editor pager sendmail kenv \
              docker kubectl npm node pip make cc gcc; do
    printf '#!/bin/sh\n: > "%s/%s"\nexit 0\n' "$CANARIES" "$HELPER" >"$SHIMS/$HELPER"
    chmod +x "$SHIMS/$HELPER"
done

PATH="$SHIMS:$PATH"
export PATH

CANDIDATES="$(cxg_pick_subcommands 'sync|push|pull|clone|fetch|update|export|extract|render|convert|build|install|publish|deploy|sign|verify|send|open|edit|diff|log|status' 12)"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B07 needs one that may shell out)"

EXERCISED=0
SEEN=""

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    # Control: the tool has to get far enough to reach whatever helper it
    # shells out to. A subcommand that fails before that point has not been
    # exercised, and no shim firing proves nothing about it.
    ARG="$(cxg_working_arg "$SUB")" || ARG=""
    if [ -n "$ARG" ]; then
        cxg_run "$SUB" "$ARG"
    else
        cxg_run "$SUB"
    fi
    [ "$CXG_RC" -eq 0 ] || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    FIRED="$(ls -1 "$CANARIES" 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
    if [ -n "$FIRED" ]; then
        FINDINGS="$(cxg_finding \
            high 90 \
            "Untrusted search path: the target ran a helper found on the caller's PATH" \
            "With a controlled directory prepended to PATH, the target's \`$SUB\` subcommand executed shim(s) named: $FIRED. The target therefore resolves these helper names through whatever search path its caller exports, so anyone who can influence PATH -- a shared host, a CI job, a hostile parent process -- chooses what code runs with the target's privileges. Target exit $CXG_RC." \
            "CWE-426,CWE-427" \
            "PATH=<controlled-shims>:\$PATH $CXG_BIN $SUB" \
            "$CXG_OUT" \
            "$FIRED" \
            "{\"oracle\":\"property\",\"post_condition\":\"shim canary created\",\"shims_executed\":\"$FIRED\",\"subcommand\":\"$SUB\",\"target_exit_code\":$CXG_RC}")"
        cxg_confirm "oracle=property(path-shim-executed=$FIRED) exit=$CXG_RC sub=$SUB class=B07" "$FINDINGS"
    fi
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "no-candidate-subcommand-ran(B07)"

cxg_refute "no PATH-resolved helper shim ran across$SEEN class=B07"
