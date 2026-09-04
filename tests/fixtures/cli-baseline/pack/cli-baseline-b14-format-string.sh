#!/usr/bin/env bash
# @id: cli-baseline-b14-format-string
# @name: CLI Baseline B14 - format-string defect
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: high
# @description: Sends conversion specifiers through arguments the target echoes. If they are consumed rather than printed, the argument is being used as a format string. A clean echo does not prove the opposite.
# @tags: cli, baseline, format-string, cwe-134
# @cwe: CWE-134
# @target_kinds: cli
# @oracles: property, signal
# @allow_nonzero_exit: true
#
# BASELINE CLASS B14 - format-string defect (CWE-134).
# Detectability: HINT -- the weakest class in the baseline, and labelled so.
#
#   input      `%x %x %x` and `%s %s %s` inside a marked payload, sent through
#              arguments the target echoes.
#   observable the specifiers are MISSING from the echoed output while the
#              marker survives -- they were consumed by a formatting call --
#              or the target dies on a fatal signal.
#   oracles    property, signal -- the two this template actually READS, and
#              both build-independent, so the class still runs under
#              `--require-instrumentation`.
#
# ON THE ORACLE DECLARATION, against the s16 taxonomy table.
# s16 lists B14's oracles as `signal, asan`. This template declares
# `property, signal` instead, deliberately. cxg's preflight treats a template
# as a sanitizer template when ANY declared oracle is build-dependent
# (`oracles_are_build_independent` in src/engine/common.rs is an `all`, not an
# `any`), so declaring `asan` here would make cxg SKIP this check on every
# uninstrumented build -- including the builds where its `%x` probe confirms
# perfectly well. The s16 column's `asan` describes the stronger WHITE-BOX
# signal that the deferred module D would use; it is not an oracle this
# black-box template reads, and a template must declare what it depends on
# rather than what a richer check might one day want.
#
# The Hint tier is unchanged by this, because the tier is about the strength of
# a REFUTATION, which is a separate question from which oracles are available.
#
# WHY THIS IS A HINT AND NOT A CLEAN CLASS.
# A confirmation is solid: specifiers do not vanish from text that was merely
# printed. A REFUTATION is weak, and the finding text says so -- a tool may
# simply not echo the argument that reaches its format call, and the argument
# would still be a format string. The strong signal needs source or a sanitizer.
#
# `%n` IS DELIBERATELY NOT SENT. It is the write primitive of this class; `%x`
# and `%s` are reads and settle the question just as well. A baseline does not
# need to attempt a memory write to report that a format string is caller-
# controlled.
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
cxg_lab b14
cxg_seed_corpus

SUBS="$(cxg_subcommands | head -8)"
OPTS="$(cxg_help_text | grep -oE '^[[:space:]]+--[a-z][a-z0-9-]*' | tr -d ' ' | sort -u | head -8)"
TARGETS="$(printf '%s\n%s\n' "$SUBS" "$OPTS" | grep -v '^$')"
[ -n "$TARGETS" ] || cxg_skip "no-candidate-argument(B14 needs an argument the target echoes)"

MARKER="CXGB14MARK"
EXERCISED=0
SEEN=""

while IFS= read -r WHAT; do
    [ -n "$WHAT" ] || continue

    # Control: does this argument get echoed at all? If a plain marker does not
    # come back, a missing specifier proves nothing -- the tool never printed
    # the argument in the first place.
    CTRL="$(cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$WHAT" "$MARKER-plain" 2>&1)"
    printf '%s' "$CTRL" | grep -qF "$MARKER-plain" || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $WHAT"

    for PROBE in "$MARKER-%x-%x-%x" "$MARKER-%s-%s-%s"; do
        cxg_run "$WHAT" "$PROBE"

        if [ "$CXG_RC" -ge 128 ] && [ "$CXG_RC" -ne 143 ]; then
            FINDINGS="$(cxg_finding \
                high 85 \
                "Format-string defect: the target died on a conversion specifier" \
                "The argument to \`$WHAT\` carried conversion specifiers and the target terminated with exit $CXG_RC (signal $((CXG_RC - 128))). Plain text through the same argument returned normally, so the specifiers -- not the length or the shape of the input -- caused the failure, which means they reached a formatting call as its format string." \
                "CWE-134" \
                "$CXG_BIN $WHAT $PROBE" \
                "$CXG_OUT" \
                "fatal-signal-on-conversion-specifier" \
                "{\"oracle\":\"signal\",\"probe\":\"$WHAT\",\"payload\":\"$PROBE\",\"target_exit_code\":$CXG_RC}")"
            cxg_confirm "oracle=signal(rc=$CXG_RC) probe=$WHAT class=B14" "$FINDINGS"
        fi

        # The marker came back but the specifiers did not: something consumed
        # them. Text that is merely printed keeps its percent signs.
        if printf '%s' "$CXG_OUT" | grep -qF "$MARKER" &&
           ! printf '%s' "$CXG_OUT" | grep -qF "%x" &&
           ! printf '%s' "$CXG_OUT" | grep -qF "%s"; then
            FINDINGS="$(cxg_finding \
                high 85 \
                "Format-string defect: conversion specifiers were interpreted, not printed" \
                "Text sent through \`$WHAT\` came back with its marker intact but its conversion specifiers gone -- they were consumed by a formatting call rather than printed as characters, so the caller's argument is being used as a format string. The output shows the values the specifiers pulled from the call frame, which is an information disclosure in itself; the same defect with a write specifier is a memory-corruption primitive. Target exit $CXG_RC." \
                "CWE-134" \
                "$CXG_BIN $WHAT $PROBE" \
                "$CXG_OUT" \
                "conversion-specifiers-consumed" \
                "{\"oracle\":\"property\",\"post_condition\":\"marker echoed but specifiers absent\",\"probe\":\"$WHAT\",\"payload\":\"$PROBE\",\"target_exit_code\":$CXG_RC}")"
            cxg_confirm "oracle=property(specifiers-consumed) exit=$CXG_RC probe=$WHAT class=B14" "$FINDINGS"
        fi
    done
done <<EOF
$TARGETS
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "control-failed(no argument echoed a plain marker back, so no format-string probe could be read)"

cxg_refute "specifiers came back verbatim through$SEEN -- weak evidence only: a tool may not echo the argument that reaches its format call class=B14"
