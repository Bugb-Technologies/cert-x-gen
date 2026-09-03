#!/usr/bin/env bash
# @id: cli-probe-exception
# @name: CLI probe that hands the target's output to cxg's exception oracle
# @author: CERT-X-GEN
# @severity: high
# @description: Runs the target and reports its output back, leaving the verdict to cxg's exception oracle
# @tags: cli, probe, exception
# @target_kinds: cli
# @oracles: exception
#
# The template runs the target; cxg owns the matching. It declares no status
# and reports no findings of its own -- it hands back what the target printed
# in metadata.target_output, and cxg decides whether an unhandled exception
# escaped. That is the point of the oracle: every template would otherwise
# re-implement "is this a traceback" slightly differently (s14 report §5).
set -uo pipefail

BIN="${CERT_X_GEN_TARGET_HOST:-}"

if [ ! -x "$BIN" ]; then
  printf '{"findings":[],"metadata":{"status":"errored","detail":"target-not-executable"}}\n'
  exit 0
fi

OUT="$("$BIN" 2>&1)"; RC=$?

# Minimal JSON string escaping: backslash, quote, newline. The fixture output
# is ASCII by construction; cxg does its own character-safe truncation.
ESCAPED="$(
  printf '%s' "$OUT" \
    | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
    | awk 'BEGIN{ORS=""} {print sep $0; sep="\\n"}'
)"

printf '{"findings":[],"metadata":{"target_output":"%s","target_exit_code":%d}}\n' "$ESCAPED" "$RC"
