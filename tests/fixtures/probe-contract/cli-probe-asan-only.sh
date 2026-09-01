#!/usr/bin/env bash
# @id: cli-probe-asan-only
# @name: CLI probe that can only decide via AddressSanitizer
# @author: CERT-X-GEN
# @severity: high
# @description: Declares asan as its only oracle, so it cannot reach a verdict on a build without one
# @tags: cli, probe, memory-safety
# @target_kinds: cli
# @oracles: asan
# @allow_nonzero_exit: true
#
# The single-oracle counterpart of cli-probe-contract.sh. It has no fallback:
# without an ASan report there is nothing for it to observe, so running it
# against a build with no ASan can only ever produce an unearned refutation.
set -uo pipefail

BIN="${CERT_X_GEN_TARGET_HOST:-}"
OUT="$("$BIN" --label AAAAAAAAAAAAAAAAAAAA 2>&1)"; RC=$?

case "$OUT" in
  *AddressSanitizer*)
    printf '{"findings":[{"severity":"high","confidence":95,"title":"Synthetic fixture: out-of-bounds write reached","description":"asan oracle fired (exit=%d)","cwe":"CWE-787"}],"metadata":{"status":"confirmed","detail":"oracle=asan exit=%d"}}\n' "$RC" "$RC"
    exit 3
    ;;
esac
printf '{"findings":[],"metadata":{"status":"refuted","detail":"no asan report (exit=%d)"}}\n' "$RC"
exit 0
