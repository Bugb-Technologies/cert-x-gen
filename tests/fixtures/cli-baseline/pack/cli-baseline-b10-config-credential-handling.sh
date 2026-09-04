#!/usr/bin/env bash
# @id: cli-baseline-b10-config-credential-handling
# @name: CLI Baseline B10 - insecure config and credential file handling
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: high
# @description: Lets the target create its own state files and stats their modes, and separately plants a working-directory config to see whether it is honoured without a trust prompt.
# @tags: cli, baseline, config, credentials, cwe-732, cwe-276
# @cwe: CWE-732
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B10 - config/credential file handling (CWE-732, CWE-276).
# Detectability: CLEAN.
#
# Two probes, either of which confirms:
#
#   (a) MODES.  Let the tool write its own configuration, token or cache, then
#       stat what appeared.  Observable: a file the TOOL created whose name
#       reads as configuration or credential and whose mode grants group or
#       world access.
#   (b) WORKING-DIRECTORY CONFIG.  Plant a repo-local config carrying a nonce
#       and run the tool from that directory.  Observable: the nonce appears in
#       the output -- the tool obeyed a config file that arrived with the
#       checkout, with no trust prompt.
#
# (b) is the 2026 agent-CLI research pattern: config files loaded as
# authoritative operator-level instructions before any trust decision.
# A snapshot is taken before the tool runs, so only files the TOOL created are
# ever considered -- the probe never reports on its own seed corpus.
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
cxg_lab b10
cxg_seed_corpus

CANDIDATES="$(cxg_pick_subcommands 'init|setup|configure|config|login|auth|register|install|new|create' 8)"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B10 needs one that writes or reads tool state)"

BEFORE="$PWD/b10-before.txt"
AFTER="$PWD/b10-after.txt"
find . -type f 2>/dev/null | sort >"$BEFORE"

EXERCISED=0
SEEN=""

# ---- probe (a): what does the tool create, and who can read it? ------------
while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    cxg_run "$SUB"
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    find . -type f 2>/dev/null | sort >"$AFTER"
    NEW="$(comm -13 "$BEFORE" "$AFTER")"
    [ -n "$NEW" ] || continue

    VERDICT="$(printf '%s' "$NEW" | python3 -c '
import json, os, re, stat, sys

SENSITIVE = re.compile(
    r"(token|credential|secret|auth|passwd|password|cookie|session|key|"
    r"config|conf|rc$|\.netrc|settings|profile)", re.I)

bad = []
for line in sys.stdin:
    path = line.strip()
    if not path:
        continue
    name = os.path.basename(path)
    if not SENSITIVE.search(name):
        continue
    try:
        perms = stat.S_IMODE(os.lstat(path).st_mode)
    except OSError:
        continue
    if perms & 0o077:
        bad.append({"file": path, "mode": oct(perms),
                    "access": "group/world readable or writable"})
print(json.dumps({"weak_files": bad}))')"

    COUNT="$(printf '%s' "$VERDICT" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["weak_files"]))')"
    if [ "$COUNT" -gt 0 ]; then
        DETAILS="$(printf '%s' "$VERDICT" | python3 -c '
import json, sys
rows = json.load(sys.stdin)["weak_files"]
print("; ".join("%s (%s)" % (r["file"], r["mode"]) for r in rows[:6]))')"
        FINDINGS="$(cxg_finding \
            high 90 \
            "Insecure state file: the tool created configuration or credential files readable by other users" \
            "Running the target's \`$SUB\` subcommand created $COUNT state file(s) with group or world access: $DETAILS. A credential or configuration file that other accounts on the host can read is a disclosure; one they can WRITE is a way to steer the tool. Target exit $CXG_RC." \
            "CWE-732,CWE-276" \
            "$CXG_BIN $SUB (then stat the files it created)" \
            "$CXG_OUT" \
            "world-or-group-accessible-state-file" \
            "$(printf '%s' "$VERDICT" | python3 -c '
import json, sys
d = json.load(sys.stdin); d["oracle"] = "property"; d["subcommand"] = "'"$SUB"'"
print(json.dumps(d))')")"
        cxg_confirm "oracle=property(weak-state-file-modes=$COUNT) exit=$CXG_RC sub=$SUB class=B10" "$FINDINGS"
    fi
done <<EOF
$CANDIDATES
EOF

# ---- probe (b): is a working-directory config obeyed without a prompt? -----
NONCE="$(cxg_nonce CXG-B10-LOCALRC)"
STEM="$(basename "$CXG_BIN" | sed 's/[_.-].*$//' | tr '[:upper:]' '[:lower:]')"
for LOCAL in ".${STEM}rc" ".${STEM}.json" "${STEM}.json" ".${STEM}" "config.json" ".config.json"; do
    printf '%s\n' "$NONCE" >"$PWD/$LOCAL"
done

READERS="$(cxg_pick_subcommands 'config|configure|settings|show|status|info|list|dump|version|env' 8)"
[ -n "$READERS" ] || READERS="$(cxg_subcommands | head -6)"

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    cxg_run "$SUB"
    EXERCISED=$((EXERCISED + 1))
    if printf '%s' "$CXG_OUT" | grep -qF "$NONCE"; then
        FINDINGS="$(cxg_finding \
            high 85 \
            "Working-directory configuration honoured without a trust decision" \
            "A configuration file planted in the working directory was read and acted on by the target's \`$SUB\` subcommand -- the nonce $NONCE appeared in its output, with no trust prompt and no indication that the settings came from an untrusted location. Anyone who can put a file in a directory the tool is run from -- a cloned repository, a shared work area, an extracted archive -- can therefore choose the tool's configuration. Target exit $CXG_RC." \
            "CWE-732,CWE-426" \
            "(plant ./$LOCAL) $CXG_BIN $SUB" \
            "$CXG_OUT" \
            "$NONCE" \
            "{\"oracle\":\"property\",\"post_condition\":\"working-directory config nonce in output\",\"subcommand\":\"$SUB\",\"target_exit_code\":$CXG_RC}")"
        cxg_confirm "oracle=property(cwd-config-honoured) exit=$CXG_RC sub=$SUB class=B10" "$FINDINGS"
    fi
done <<EOF
$READERS
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "no-probe-ran(B10)"

cxg_refute "state files were owner-only and no working-directory config was honoured across$SEEN class=B10"
