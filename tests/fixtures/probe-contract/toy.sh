#!/bin/bash
#
# Benign synthetic fixture for the probe-contract tests. NOT a real
# vulnerability and not derived from any CVE: it is a stand-in target whose
# only job is to give cxg's probe contract something deterministic to
# adjudicate.
#
# It "stores" a caller-supplied label in a notional 16-byte buffer. Which twin
# it is comes from its own filename, so one file serves as both builds:
#   copied to a name containing "defective"  the copy is unbounded, so an
#       over-length label makes it print a sanitizer-shaped report and die with
#       exit 134 -- the shape a real ASan-instrumented crash has.
#   any other name                           the copy is bounds-checked and
#       truncates; exit 0.
# TOY_DEFECTIVE=1/0 overrides the filename.
#
# Two input channels, so both of cxg's delivery models are exercised:
#   toy.sh --label <text>
#   toy.sh --stdin           (reads one line from stdin)
set -u

case "$(basename "$0")" in
    *defective*) DEFAULT_DEFECTIVE=1 ;;
    *)           DEFAULT_DEFECTIVE=0 ;;
esac
DEFECTIVE="${TOY_DEFECTIVE:-$DEFAULT_DEFECTIVE}"

BUFSZ=16

store_label() {
    local src="$1"
    if [ "$DEFECTIVE" = "1" ] && [ "${#src}" -ge "$BUFSZ" ]; then
        echo "=================================================================" >&2
        echo "ERROR: AddressSanitizer: stack-buffer-overflow on address 0x0000dead" >&2
        echo "WRITE of size ${#src} at 0x0000dead thread T0" >&2
        echo "    #0 0x0 in store_label toy.sh:${BUFSZ}" >&2
        echo "SUMMARY: AddressSanitizer: stack-buffer-overflow toy.sh in store_label" >&2
        exit 134
    fi
    echo "label=${src:0:$((BUFSZ - 1))}"
}

case "${1:-}" in
    --label)
        [ $# -ge 2 ] || { echo "usage: toy.sh --label <text>" >&2; exit 64; }
        store_label "$2"
        ;;
    --stdin)
        IFS= read -r line || exit 2
        store_label "$line"
        ;;
    *)
        echo "usage: toy.sh --label <text> | toy.sh --stdin" >&2
        exit 64
        ;;
esac
