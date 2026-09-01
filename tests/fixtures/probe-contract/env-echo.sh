#!/usr/bin/env bash
# @id: env-echo
# @name: Probe environment contract echo
# @author: CERT-X-GEN
# @severity: info
# @description: Reports the probe-contract environment cxg handed it, as the execution detail
# @tags: cli, probe, diagnostic
#
# Emits one finding-free result whose metadata.detail lists each probe-contract
# variable and its value, or <unset>. Used to assert the wire-level contract:
# a target scanned without the probe flags must see none of these.
set -uo pipefail

v() { # v <name>
  local name="$1"
  printf '%s=%s' "$name" "${!name:-<unset>}"
}

DETAIL="$(v CERT_X_GEN_TARGET_HOST) | $(v CERT_X_GEN_TARGET_KIND) | $(v CERT_X_GEN_TARGET_PORT)"
for name in CERT_X_GEN_ARGV CERT_X_GEN_STDIN_FILE CERT_X_GEN_INPUT_DIR \
            CERT_X_GEN_TARGET_ENV CERT_X_GEN_TARGET_INSTRUMENTATION; do
  DETAIL="$DETAIL | $(v "$name")"
done

printf '{"findings":[],"metadata":{"status":"skipped","detail":"%s"}}\n' \
  "$(printf '%s' "$DETAIL" | tr -d '"\\')"
