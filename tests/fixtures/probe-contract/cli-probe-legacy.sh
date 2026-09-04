#!/usr/bin/env bash
# @id: cli-probe-legacy
# @name: CLI probe contract demonstrator (no exit tolerance)
# @author: CERT-X-GEN
# @severity: high
# @description: Drives a local CLI target with cxg-supplied input and reports a first-class execution status
# @tags: cli, probe, memory-safety
# @target_kinds: cli
# @oracles: asan, signal, exit
#
# Exercises the whole probe contract:
#   in : CERT_X_GEN_TARGET_HOST, CERT_X_GEN_TARGET_KIND,
#        CERT_X_GEN_TARGET_INSTRUMENTATION, CERT_X_GEN_ARGV,
#        CERT_X_GEN_STDIN_FILE, CERT_X_GEN_TARGET_ENV
#   out: {"findings":[...], "metadata":{"status":..., "detail":...}} on stdout,
#        plus a deliberate NON-ZERO exit on confirmation -- which is why the
#        template declares @allow_nonzero_exit: without it cxg discards stdout
#        and the confirmation is lost.
set -uo pipefail

BIN="${CERT_X_GEN_TARGET_HOST:-}"
KIND="${CERT_X_GEN_TARGET_KIND:-}"
INSTR="${CERT_X_GEN_TARGET_INSTRUMENTATION:-unknown}"

emit() { # emit <status> <detail> [findings-json]
  printf '{"findings":%s,"metadata":{"status":"%s","detail":"%s","instrumentation":"%s"}}\n' \
    "${3:-[]}" "$1" "$2" "$INSTR"
}

# --- precondition: this template only understands cli:// targets -------------
if [ "$KIND" != "cli" ]; then
  emit skipped "not-a-cli-target(kind=$KIND)"
  exit 0
fi
if [ ! -x "$BIN" ]; then
  emit errored "target-not-executable"
  exit 0
fi

# --- environment cxg wants set on the TARGET (not on this template) ---------
if [ -n "${CERT_X_GEN_TARGET_ENV:-}" ]; then
  while IFS='=' read -r k v; do
    [ -n "$k" ] && export "$k=$v"
  done < <(
    python3 -c 'import json,os;[print(f"{k}={v}") for k,v in json.loads(os.environ["CERT_X_GEN_TARGET_ENV"]).items()]' \
      2>/dev/null || true
  )
fi

# --- input delivery: argv/stdin from cxg, else a built-in default -----------
DEFAULT_PROBE='AAAAAAAAAAAAAAAAAAAA'   # 20 bytes into a 16-byte buffer
if [ -n "${CERT_X_GEN_ARGV:-}" ]; then
  # CERT_X_GEN_ARGV is a JSON array of strings. python3 is the accurate reader;
  # the fallback handles the simple, unescaped case.
  IFS=$'\n' read -r -d '' -a PROBE_ARGV < <(
    python3 -c 'import json,os;[print(a) for a in json.loads(os.environ["CERT_X_GEN_ARGV"])]' 2>/dev/null \
      || printf '%s' "$CERT_X_GEN_ARGV" | sed -e 's/^\[//' -e 's/\]$//' -e 's/","/\n/g' -e 's/^"//' -e 's/"$//'
    printf '\0'
  )
  SOURCE="cxg-argv"
elif [ -n "${CERT_X_GEN_STDIN_FILE:-}" ]; then
  PROBE_ARGV=(--stdin)
  SOURCE="cxg-stdin-file"
else
  PROBE_ARGV=(--label "$DEFAULT_PROBE")
  SOURCE="template-default"
fi

# --- control run: the target must work on benign input ----------------------
if ! "$BIN" --label ok >/dev/null 2>&1; then
  emit errored "control-run-failed(exit=$?)"
  exit 0
fi

# --- probe run --------------------------------------------------------------
if [ "$SOURCE" = "cxg-stdin-file" ]; then
  OUT="$("$BIN" "${PROBE_ARGV[@]}" < "$CERT_X_GEN_STDIN_FILE" 2>&1)"; RC=$?
else
  OUT="$("$BIN" "${PROBE_ARGV[@]}" 2>&1)"; RC=$?
fi

# --- oracles ----------------------------------------------------------------
ASAN=no; SIGNAL=no
case "$OUT" in *AddressSanitizer*|*"runtime error:"*) ASAN=yes ;; esac
[ "$RC" -ge 128 ] && SIGNAL=yes

if [ "$ASAN" = yes ] || [ "$SIGNAL" = yes ]; then
  ORACLE=$([ "$ASAN" = yes ] && echo asan || echo "signal($((RC-128)))")
  SUMMARY="$(printf '%s' "$OUT" | grep -m1 'SUMMARY: AddressSanitizer' | tr -d '"' | head -c 200)"
  [ -z "$SUMMARY" ] && SUMMARY="target terminated by signal $((RC-128)); no sanitizer report available"
  FINDINGS=$(printf '[{"severity":"high","confidence":95,"title":"Synthetic fixture: out-of-bounds write reached",
    "description":"probe input from %s fired oracle %s (exit=%d) against %s","cwe":"CWE-787",
    "evidence":{"matched_patterns":["%s"],"response":"%s"}}]' \
    "$SOURCE" "$ORACLE" "$RC" "$BIN" "$ORACLE" "$SUMMARY")
  emit confirmed "oracle=$ORACLE exit=$RC input=$SOURCE" "$FINDINGS"
  # Deliberately non-zero: without @allow_nonzero_exit cxg discards everything
  # printed above this line and reports the run as errored.
  exit 3
fi

emit refuted "target handled probe input cleanly (exit=$RC, input=$SOURCE)"
exit 0
