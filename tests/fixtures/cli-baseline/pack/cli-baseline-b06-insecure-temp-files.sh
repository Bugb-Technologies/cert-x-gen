#!/usr/bin/env bash
# @id: cli-baseline-b06-insecure-temp-files
# @name: CLI Baseline B06 - insecure temporary file creation
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: medium
# @description: Runs the target under a controlled TMPDIR and inspects what it leaves there. A predictably named work file, or one readable or writable by other users, or one that outlives the run, is the defect.
# @tags: cli, baseline, tempfile, cwe-377
# @cwe: CWE-377
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B06 - insecure temp file creation (CWE-377).
# Detectability: CLEAN.
#
#   input      an ordinary, working invocation -- with TMPDIR pointed at a
#              directory this template owns and watches.
#   observable a file left in that directory whose mode grants group or world
#              access, or whose name carries no unpredictable component.
#   oracle     property -- a filesystem post-condition.
#
# There is no hostile payload here at all. The probe is the tool doing its
# ordinary job while somebody looks at where it puts its scratch files, which
# is precisely the position an attacker on a shared host occupies.
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
cxg_lab b06
cxg_seed_corpus

CANDIDATES="$(cxg_pick_subcommands 'convert|render|export|build|compile|process|parse|format|show|extract|sync|init|import')"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B06 needs one that does work)"

WATCH="$PWD/b06-tmp"
mkdir -p "$WATCH"
export TMPDIR="$WATCH"
export TMP="$WATCH"
export TEMP="$WATCH"

EXERCISED=0
SEEN=""

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    # Control: the tool has to actually do some work under this subcommand,
    # or an empty TMPDIR afterwards says nothing about how it handles work
    # files. A subcommand that errors out immediately is not exercised.
    ARG="$(cxg_working_arg "$SUB")" || ARG=""
    if [ -n "$ARG" ]; then
        cxg_run "$SUB" "$ARG"
    else
        cxg_run "$SUB"
    fi
    [ "$CXG_RC" -eq 0 ] || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    # What did it leave behind, and who can read it?
    VERDICT="$(WATCH="$WATCH" SUB="$SUB" python3 - <<'PY'
import json, os, stat

watch, sub = os.environ["WATCH"], os.environ["SUB"]
bad = []
for root, _dirs, files in os.walk(watch):
    for name in files:
        path = os.path.join(root, name)
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            continue
        perms = stat.S_IMODE(mode)
        problems = []
        if perms & 0o077:
            problems.append("mode-%s-grants-group-or-world-access" % oct(perms))
        # A name with no unpredictable component is guessable, which is what
        # makes a pre-created symlink at that path a viable attack.
        stem = os.path.splitext(name)[0]
        if not any(ch.isdigit() for ch in stem) and len(stem) < 40:
            problems.append("predictable-name")
        if problems:
            bad.append({"file": os.path.relpath(path, watch),
                        "mode": oct(perms),
                        "problems": problems})
print(json.dumps({"survivors": bad}))
PY
    )"

    COUNT="$(printf '%s' "$VERDICT" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["survivors"]))')"
    if [ "$COUNT" -gt 0 ]; then
        DETAILS="$(printf '%s' "$VERDICT" | python3 -c '
import json, sys
rows = json.load(sys.stdin)["survivors"]
print("; ".join("%s (%s): %s" % (r["file"], r["mode"], ",".join(r["problems"])) for r in rows[:6]))')"
        FINDINGS="$(cxg_finding \
            medium 85 \
            "Insecure temporary file: a work file was left behind with weak protection" \
            "Running the target's \`$SUB\` subcommand under a controlled TMPDIR left $COUNT file(s) behind: $DETAILS. A work file that survives the run, is named predictably, or is readable or writable by other accounts lets another user on the host read the data or pre-place a symlink at the path the tool is about to use. Target exit $CXG_RC." \
            "CWE-377" \
            "TMPDIR=<controlled> $CXG_BIN $SUB" \
            "$CXG_OUT" \
            "temp-file-left-behind,weak-mode-or-predictable-name" \
            "$(printf '%s' "$VERDICT" | python3 -c '
import json, sys
d = json.load(sys.stdin)
d["oracle"] = "property"
d["subcommand"] = "'"$SUB"'"
print(json.dumps(d))')")"
        cxg_confirm "oracle=property(temp-files=$COUNT) exit=$CXG_RC sub=$SUB class=B06" "$FINDINGS"
    fi
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "no-candidate-subcommand-ran(B06)"

cxg_refute "target left no group/world-accessible or predictably-named work file across$SEEN class=B06"
