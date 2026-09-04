#!/usr/bin/env bash
# @id: cli-probe-exit-only
# @name: CLI probe that decides from the target's exit status alone
# @author: CERT-X-GEN
# @severity: medium
# @description: Declares only build-independent oracles, so it can reach a verdict on any build
# @tags: cli, probe, diagnostic
# @target_kinds: cli
# @oracles: exit, timeout
# @allow_nonzero_exit: true
#
# The counterpart of cli-probe-asan-only.sh. Its oracles need nothing from the
# build -- an exit status exists whatever the target was compiled with, or
# whether it was compiled at all -- so --require-instrumentation has no reason
# to refuse it, even against a target whose instrumentation is `none`
# (every interpreted CLI: s14 report §4.1(a)).
set -uo pipefail

BIN="${CERT_X_GEN_TARGET_HOST:-}"
INSTR="${CERT_X_GEN_TARGET_INSTRUMENTATION:-unknown}"

if [ ! -x "$BIN" ]; then
  printf '{"findings":[],"metadata":{"status":"errored","detail":"target-not-executable"}}\n'
  exit 0
fi

OUT="$("$BIN" --label AAAAAAAAAAAAAAAAAAAA 2>&1)"; RC=$?

if [ "$RC" -ne 0 ]; then
  printf '{"findings":[{"severity":"medium","confidence":80,"title":"Synthetic fixture: target exited non-zero on probe input","description":"exit oracle fired (exit=%d, instrumentation=%s)","cwe":"CWE-703"}],"metadata":{"status":"confirmed","detail":"oracle=exit exit=%d instrumentation=%s"}}\n' \
    "$RC" "$INSTR" "$RC" "$INSTR"
  exit 3
fi

printf '{"findings":[],"metadata":{"status":"refuted","detail":"oracle=exit exit=0 instrumentation=%s"}}\n' "$INSTR"
exit 0
