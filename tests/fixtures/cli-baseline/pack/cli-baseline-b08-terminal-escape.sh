#!/usr/bin/env bash
# @id: cli-baseline-b08-terminal-escape
# @name: CLI Baseline B08 - terminal escape sequence injection
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: medium
# @description: Sends text carrying ESC-introduced control sequences through every argument the target echoes. If raw ESC bytes survive to the output, the terminal emulator, not the tool, decides what the operator sees.
# @tags: cli, baseline, terminal-escape, ansi, cwe-150, cwe-117
# @cwe: CWE-150
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B08 - terminal escape injection (CWE-150, CWE-117).
# Detectability: CLEAN.  CLI-NATIVE: this class has no web analogue, because
# the rendering surface is the terminal emulator and an unfiltered ESC byte is
# an instruction to it.
#
#   input      text containing ESC (0x1b) followed by CSI (SGR colour), OSC 0
#              (window-title set) and OSC 8 (hyperlink) -- the exact shapes
#              used in the 2026 vercel-labs `skills` and OpenAI Codex CLI
#              disclosures.
#   observable a raw 0x1b byte in the target's output, checked at the BYTE
#              level so a tool that renders the sequence visibly (\x1b, ^[, a
#              replacement glyph) correctly REFUTES.
#   oracle     property -- an output post-condition.
#
# This template asserts nothing about what a terminal would DO with the
# sequence. It reports only that the tool passed the control bytes through,
# which is the black-box fact and the whole of the finding.
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
cxg_lab b08
cxg_seed_corpus

CANDIDATES="$(cxg_pick_subcommands 'banner|echo|print|say|show|render|message|log|note|comment|label|title|describe|export' 10)"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B08 needs one that echoes text)"

# CSI SGR colour; OSC 0 window-title set; OSC 8 hyperlink. The hyperlink points
# at .invalid, which is reserved by RFC 2606 and can never resolve.
PROBE="$(printf 'safe\033[31mRED\033]0;CXG-TITLE-PROBE\007\033]8;;https://example.invalid/cxg\033\\link\033]8;;\033\\')"

EXERCISED=0
SEEN=""

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue

    # Control: the target must echo ORDINARY text through this subcommand,
    # otherwise a run with no ESC in the output proves nothing about escaping.
    CTRL="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$SUB" "cxg-plain-control-text" 2>&1)"
    printf '%s' "$CTRL" | grep -qF 'cxg-plain-control-text' || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    # Byte-exact capture: command substitution cannot carry these bytes intact.
    cxg_run_files "$PWD/b08-out.bin" "$PWD/b08-err.bin" "$SUB" "$PROBE"
    cat "$PWD/b08-out.bin" "$PWD/b08-err.bin" >"$PWD/b08-all.bin" 2>/dev/null

    ESC_COUNT="$(od -An -tx1 -v "$PWD/b08-all.bin" | tr ' ' '\n' | grep -c '^1b$' || true)"
    if [ "${ESC_COUNT:-0}" -gt 0 ]; then
        SEQ="$(python3 - "$PWD/b08-all.bin" <<'PY'
import re, sys
data = open(sys.argv[1], "rb").read()
kinds = []
if re.search(rb"\x1b\[[0-9;]*[A-Za-z]", data): kinds.append("CSI")
if re.search(rb"\x1b\]0;", data):              kinds.append("OSC-0-title")
if re.search(rb"\x1b\]8;;", data):             kinds.append("OSC-8-hyperlink")
print(",".join(kinds) or "ESC-present")
PY
        )"
        RAW="$(python3 -c '
import sys
sys.stdout.write(open(sys.argv[1], "rb").read()[:600].decode("utf-8", "replace"))' "$PWD/b08-all.bin")"
        FINDINGS="$(cxg_finding \
            medium 90 \
            "Terminal escape injection: raw ESC control bytes reach the output" \
            "Caller-supplied text carrying ESC-introduced sequences ($SEQ) was echoed by the target's \`$SUB\` subcommand byte-for-byte: $ESC_COUNT raw 0x1b bytes survived to the output, exit $CXG_RC. The terminal emulator, not the tool, therefore decides what the operator sees -- the tool cannot claim its output is what it printed. This is the mechanism behind the 2026 vercel-labs skills and OpenAI Codex CLI disclosures, where crafted path components carrying ESC escalated to hyperlink and title spoofing." \
            "CWE-150,CWE-117" \
            "$CXG_BIN $SUB <ESC-bearing text>" \
            "$RAW" \
            "$SEQ" \
            "{\"oracle\":\"property\",\"post_condition\":\"0x1b present in output\",\"esc_bytes\":$ESC_COUNT,\"sequences\":\"$SEQ\",\"subcommand\":\"$SUB\",\"target_exit_code\":$CXG_RC}")"
        cxg_confirm "oracle=property(raw-esc-bytes=$ESC_COUNT seq=$SEQ) exit=$CXG_RC sub=$SUB class=B08" "$FINDINGS"
    fi
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "control-failed(no candidate subcommand echoed its argument back)"

cxg_refute "target neutralised every control byte before display across$SEEN (esc_bytes=0) class=B08"
