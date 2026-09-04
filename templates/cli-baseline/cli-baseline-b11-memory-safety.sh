#!/usr/bin/env bash
# @id: cli-baseline-b11-memory-safety
# @name: CLI Baseline B11 - memory-safety defect (instrumentation-dependent)
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: critical
# @description: Drives over-length and boundary-shaped input at every argument and stdin, and reads the sanitizer runtime's verdict. Declares sanitizer oracles so cxg skips it honestly on a build that cannot show the defect.
# @tags: cli, baseline, memory-safety, cwe-787, cwe-125, cwe-416, instrumentation-dependent
# @cwe: CWE-787
# @target_kinds: cli
# @oracles: asan, ubsan, msan
# @allow_nonzero_exit: true
#
# BASELINE CLASS B11 - memory-safety defect (CWE-787, CWE-125, CWE-416).
# Detectability: PARTIAL -- needs instrumentation.
#
# This template exists to mark the black-box LIMIT, and it is the reason the
# baseline has a Detectability column at all.
#
# B01-B10 reach a verdict from observable behaviour alone. B11 cannot: an
# UNINSTRUMENTED build that silently corrupts memory exits 0 and looks
# identical to a correct one. Reporting `refuted` there would be a false
# negative indistinguishable from a real refutation.
#
# So this template declares `@oracles: asan, ubsan, msan`, none of which is
# build-independent. Two things follow:
#
#   * under `--require-instrumentation`, cxg's preflight skips it with
#     `no-instrumentation-detected` before it ever runs;
#   * WITHOUT that flag, the template checks for itself and skips anyway --
#     because the operator forgetting a flag is not evidence about the target.
#
# The honest outcome against an interpreted CLI is therefore SKIPPED, never
# REFUTED, and that is the whole point of shipping this class.
set -uo pipefail

CXG_LIB="$(dirname "$0")/cli-baseline.lib"
if [ ! -r "$CXG_LIB" ]; then
    printf '{"findings":[],"metadata":{"status":"errored","detail":"probe-library-not-found"}}\n'
    exit 0
fi
# shellcheck source=cli-baseline.lib
. "$CXG_LIB"

cxg_require_cli_target
# The self-check: no sanitizer, no verdict. This runs whether or not the
# operator passed --require-instrumentation.
cxg_require_instrumentation asan ubsan msan tsan
cxg_control_alive
cxg_lab b11
cxg_seed_corpus

# Boundary-shaped inputs: just over common buffer sizes, and far over.
LONG_64="$(python3 -c 'print("A"*65)')"
LONG_256="$(python3 -c 'print("A"*257)')"
LONG_4K="$(python3 -c 'print("A"*4096)')"
LONG_64K="$(python3 -c 'print("A"*65536)')"

SUBS="$(cxg_subcommands | head -8)"
OPTS="$(cxg_help_text | grep -oE '^[[:space:]]+--[a-z][a-z0-9-]*' | tr -d ' ' | sort -u | head -8)"
TARGETS="$(printf '%s\n%s\n' "$SUBS" "$OPTS" | grep -v '^$')"
[ -n "$TARGETS" ] || TARGETS="--label"

CXG_TARGET_OUTPUT=""

check_report() { # check_report <what>
    case "$CXG_OUT" in
        *AddressSanitizer*|*MemorySanitizer*|*ThreadSanitizer*|*LeakSanitizer*|*"runtime error:"*)
            SAN="$(printf '%s' "$CXG_OUT" | grep -oE '(AddressSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer|runtime error)[^\n]{0,80}' | head -1)"
            FINDINGS="$(cxg_finding \
                critical 95 \
                "Memory-safety defect reported by the sanitizer runtime" \
                "Over-length input delivered through \`$1\` produced a sanitizer report: $SAN. The target exited $CXG_RC. A sanitizer report is a direct observation of memory corruption, not an inference from behaviour -- which is exactly the evidence an uninstrumented build cannot provide, and why this class is only ever adjudicated on a build that carries one." \
                "CWE-787,CWE-125,CWE-416" \
                "$CXG_BIN $1 <over-length input>" \
                "$CXG_OUT" \
                "sanitizer-report" \
                "{\"oracle\":\"asan\",\"instrumentation\":\"$CXG_INSTR\",\"probe\":\"$1\",\"target_exit_code\":$CXG_RC}")"
            cxg_confirm "oracle=asan($SAN) exit=$CXG_RC probe=$1 instrumentation=$CXG_INSTR class=B11" "$FINDINGS"
            ;;
    esac
    # A fatal signal on an instrumented build is also a memory-safety
    # observation, even when the runtime printed nothing readable.
    if [ "$CXG_RC" -ge 128 ] && [ "$CXG_RC" -ne 143 ]; then
        FINDINGS="$(cxg_finding \
            critical 80 \
            "Target terminated by a fatal signal on over-length input" \
            "Over-length input delivered through \`$1\` terminated the target with exit $CXG_RC (signal $((CXG_RC - 128))) on a build carrying $CXG_INSTR. On an instrumented build a fatal signal under boundary-shaped input is a memory-safety observation." \
            "CWE-787" \
            "$CXG_BIN $1 <over-length input>" \
            "$CXG_OUT" \
            "fatal-signal" \
            "{\"oracle\":\"signal\",\"instrumentation\":\"$CXG_INSTR\",\"probe\":\"$1\",\"target_exit_code\":$CXG_RC}")"
        cxg_confirm "oracle=signal(rc=$CXG_RC) probe=$1 instrumentation=$CXG_INSTR class=B11" "$FINDINGS"
    fi
}

while IFS= read -r WHAT; do
    [ -n "$WHAT" ] || continue
    for PAYLOAD in "$LONG_64" "$LONG_256" "$LONG_4K" "$LONG_64K"; do
        cxg_run "$WHAT" "$PAYLOAD"
        CXG_TARGET_OUTPUT="$CXG_OUT"
        check_report "$WHAT"
    done
done <<EOF
$TARGETS
EOF

# And through stdin, which many tools read without any argument at all.
printf '%s\n' "$LONG_64K" >"$PWD/b11-stdin.txt"
cxg_run_stdin "$PWD/b11-stdin.txt"
CXG_TARGET_OUTPUT="$CXG_OUT"
check_report "stdin"

cxg_refute "instrumented build ($CXG_INSTR) handled every over-length input cleanly class=B11"
