#!/usr/bin/env bash
# @id: cli-baseline-b09-environment-trust
# @name: CLI Baseline B09 - unvalidated trust in environment variables
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: medium
# @description: Sets the tool's documented and conventional environment variables to hostile values pointing at a canary file. If the canary's contents appear in the output, the tool loads caller-pointed state without validating where it points.
# @tags: cli, baseline, environment, cwe-454, cwe-526
# @cwe: CWE-454
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B09 - environment-variable trust (CWE-454, CWE-526).
# Detectability: CLEAN.
#
#   input      every environment variable the tool's own help advertises, plus
#              the conventional <NAME>_CONFIG / _RC / _HOME / _PROFILE forms
#              derived from the binary's name, each pointed at a canary file
#              this template planted.
#   observable the canary nonce appears in the target's output -- the tool read
#              a file chosen by its caller and treated it as its own state.
#   oracle     property -- an output post-condition.
#
# Discovery matters here: a tool that documents no environment variables and
# has no conventional ones gets a SKIP, not a clean bill of health.
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
cxg_lab b09
cxg_seed_corpus

NONCE="$(cxg_nonce CXG-B09-ENVTRUST)"
POINTED="$PWD/b09-pointed.conf"
printf '%s\n' "$NONCE" >"$POINTED"

# Candidate variable names: whatever the help text advertises, plus the
# conventional forms built from the leading token of the binary's name
# (`notekeeper_defective.py` -> NOTEKEEPER, `git` -> GIT).
VARS="$(cxg_help_text | CXG_TARGET_BIN="$CXG_BIN" python3 -c '
import os, re, sys

help_text = sys.stdin.read()
base = os.path.basename(os.environ["CXG_TARGET_BIN"])
# The leading token of the program name: notekeeper_defective.py -> NOTEKEEPER,
# git -> GIT. Twin suffixes and extensions are not part of a tools identity.
stem = re.sub(r"[^A-Z0-9]", "", re.split(r"[_.\-]", base)[0].upper()) or "TOOL"

names = set(re.findall(r"\b([A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+)+)\b", help_text))
for suffix in ("CONFIG", "CONF", "RC", "HOME", "PROFILE", "SETTINGS",
               "CONFIG_FILE", "CONFIG_PATH"):
    names.add("%s_%s" % (stem, suffix))
print("\n".join(sorted(n for n in names if len(n) <= 64)))')"

[ -n "$VARS" ] || cxg_skip "no-candidate-env-vars(B09 found none advertised and none conventional)"

CANDIDATES="$(cxg_pick_subcommands 'config|configure|settings|show|status|info|env|version|list|dump|render|export|show' 8)"
[ -n "$CANDIDATES" ] || CANDIDATES="$(cxg_subcommands | head -6)"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B09)"

EXERCISED=0
TRIED_VARS=""

while IFS= read -r VAR; do
    [ -n "$VAR" ] || continue
    TRIED_VARS="$TRIED_VARS $VAR"
    while IFS= read -r SUB; do
        [ -n "$SUB" ] || continue
        # `env` sets the variable for the target only; cxg_timeout keeps the
        # bound. Both are real programs, so they compose.
        CXG_OUT="$(cxg_timeout "$CXG_TIMEOUT" env "$VAR=$POINTED" "$CXG_BIN" "$SUB" 2>&1)"
        CXG_RC=$?
        CXG_PROBES_DELIVERED=$((CXG_PROBES_DELIVERED + 1))
        # Only a subcommand the target actually ran tells us anything about
        # whether it honours the variable.
        [ "$CXG_RC" -eq 0 ] || continue
        EXERCISED=$((EXERCISED + 1))
        if printf '%s' "$CXG_OUT" | grep -qF "$NONCE"; then
            FINDINGS="$(cxg_finding \
                medium 90 \
                "Environment-variable trust: a caller-pointed file was loaded as the tool's own state" \
                "With \`$VAR\` set to a file this probe created, the target's \`$SUB\` subcommand read that file and echoed its contents -- the canary nonce $NONCE appeared in the output with exit $CXG_RC. The tool follows an environment variable to arbitrary state without checking where it points, so any process that can set the environment (a CI job, a parent process, a shared shell profile) chooses the tool's configuration." \
                "CWE-454,CWE-526" \
                "$VAR=<canary> $CXG_BIN $SUB" \
                "$CXG_OUT" \
                "$NONCE" \
                "{\"oracle\":\"property\",\"post_condition\":\"canary nonce in output\",\"env_var\":\"$VAR\",\"subcommand\":\"$SUB\",\"target_exit_code\":$CXG_RC}")"
            cxg_confirm "oracle=property(env-pointed-file-loaded var=$VAR) exit=$CXG_RC sub=$SUB class=B09" "$FINDINGS"
        fi
    done <<INNER
$CANDIDATES
INNER
done <<EOF
$VARS
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "no-probe-ran(B09)"

cxg_refute "target ignored every caller-pointed environment variable ($(printf '%s' "$TRIED_VARS" | wc -w | tr -d ' ') tried) class=B09"
