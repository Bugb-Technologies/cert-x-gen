#!/usr/bin/env bash
# Materialise the CLI Security Baseline fixture twins.
#
# The corpus is kept in the repository as ONE source per program, because a
# flawed and a fixed twin that can drift apart are worth nothing as a
# refutation test. Which twin a program is comes from its own filename, so the
# twins are copies (interpreted) or separate builds (compiled) made here.
#
# Usage:  ./build.sh [output-directory]     (default: this directory)
#
# `cc` is not an extra dependency: cargo already needs a C toolchain to link
# the crate under test. ASan is required for the B11 twins -- without it the
# defective build overflows its buffer, exits 0 and looks perfect, which is the
# exact false negative B11 exists to refuse to report.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE}"
mkdir -p "$OUT"

# --- interpreted twins -----------------------------------------------------
for TWIN in defective fixed; do
    cp "$HERE/notekeeper.py" "$OUT/notekeeper_$TWIN.py"
    chmod +x "$OUT/notekeeper_$TWIN.py"
done
for HELPER in noteprint.py notesync.py; do
    [ "$HERE" = "$OUT" ] || cp "$HERE/$HELPER" "$OUT/$HELPER"
    chmod +x "$OUT/$HELPER"
done

# --- compiled twins (B11 memory safety, B14 format string) -----------------
CC="${CC:-cc}"
for TWIN in defective fixed; do
    "$CC" -fsanitize=address -g -O0 -Wall -Wextra \
        -o "$OUT/memtoy_$TWIN" "$HERE/memtoy.c"
done

echo "fixtures built in $OUT:"
ls -1 "$OUT" | grep -E '^(notekeeper_|noteprint|notesync|memtoy_)' | sed 's/^/  /'
