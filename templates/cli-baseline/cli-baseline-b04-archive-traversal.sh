#!/usr/bin/env bash
# @id: cli-baseline-b04-archive-traversal
# @name: CLI Baseline B04 - zip-slip / archive extraction traversal
# @author: CERT-X-GEN / CLI Security Baseline
# @severity: high
# @description: Feeds an archive whose entries carry `../` components, an absolute path, and a symlink pointing outside. If a file materialises outside the extraction directory, member names are being trusted.
# @tags: cli, baseline, zip-slip, archive, cwe-22, cwe-409
# @cwe: CWE-22
# @target_kinds: cli
# @oracles: property
# @allow_nonzero_exit: true
#
# BASELINE CLASS B04 - archive extraction traversal (CWE-22, CWE-409).
# Detectability: CLEAN.
#
#   input      a tar archive containing (1) a member named `../<nonce>`,
#              (2) a member with an absolute path, and (3) a symlink member
#              aimed out of the extraction directory.
#   observable a file materialises outside the extraction directory.
#   oracle     property -- a filesystem post-condition.
#
# Every escaping path is aimed INSIDE this template's own lab. A probe that
# escaped further would demonstrate nothing extra and would write somewhere it
# has no business writing.
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
cxg_lab b04
cxg_seed_corpus

CANDIDATES="$(cxg_pick_subcommands 'extract|unpack|unzip|untar|decompress|install|import|restore|load|add')"
[ -n "$CANDIDATES" ] || cxg_skip "no-candidate-subcommand(B04 needs one that unpacks an archive)"

NONCE="$(cxg_nonce b04)"
ESCAPED="$PWD/$NONCE-escaped.txt"
ABS_TARGET="$PWD/$NONCE-absolute.txt"

# Build the probe archives with python3's tarfile: hand-rolling a tar header is
# how a probe ends up testing its own arithmetic instead of the target.
NONCE="$NONCE" LAB="$PWD" python3 - <<'PY'
import io, os, tarfile

nonce, lab = os.environ["NONCE"], os.environ["LAB"]
body = ("zip-slip canary %s\n" % nonce).encode()

def add(tar, name, linkname=None):
    info = tarfile.TarInfo(name)
    if linkname is not None:
        info.type = tarfile.SYMTYPE
        info.linkname = linkname
        tar.addfile(info)
    else:
        info.size = len(body)
        tar.addfile(info, io.BytesIO(body))

# The CONTROL: a well-formed archive with nothing untoward in it. The probe
# archives below cannot serve as the control, because a correctly-behaving
# target REFUSES those -- which would make "control failed" indistinguishable
# from "target is safe".
with tarfile.open(os.path.join(lab, "b04-control.tar"), "w") as tar:
    add(tar, "harmless.txt")

with tarfile.open(os.path.join(lab, "b04-relative.tar"), "w") as tar:
    add(tar, "harmless.txt")
    add(tar, "../%s-escaped.txt" % nonce)

with tarfile.open(os.path.join(lab, "b04-absolute.tar"), "w") as tar:
    add(tar, "harmless.txt")
    add(tar, os.path.join(lab, "%s-absolute.txt" % nonce).lstrip("/"))

with tarfile.open(os.path.join(lab, "b04-symlink.tar"), "w") as tar:
    add(tar, "link", linkname="../%s-symlinked.txt" % nonce)
PY

[ -f "$PWD/b04-control.tar" ] || cxg_error "probe-archive-build-failed"

EXERCISED=0
SEEN=""

while IFS= read -r SUB; do
    [ -n "$SUB" ] || continue
    # The control is the archive the tool SHOULD accept. If it cannot unpack a
    # well-formed archive through this subcommand, a quiet result on a
    # malformed one refutes NOTHING, and this subcommand does not count as
    # exercised -- which is what turns "I could not test this" into a skip
    # rather than a clean bill of health.
    cxg_timeout "$CXG_TIMEOUT" "$CXG_BIN" "$SUB" "$PWD/b04-control.tar" >/dev/null 2>&1 || continue
    EXERCISED=$((EXERCISED + 1))
    SEEN="$SEEN $SUB"

    for ARCHIVE in b04-relative.tar b04-absolute.tar b04-symlink.tar; do
        cxg_run "$SUB" "$PWD/$ARCHIVE"
        for OUTSIDE in "$ESCAPED" "$ABS_TARGET"; do
            if [ -e "$OUTSIDE" ]; then
                FINDINGS="$(cxg_finding \
                    high 95 \
                    "Archive extraction traversal: a member escaped the extraction directory" \
                    "The target's \`$SUB\` subcommand unpacked $ARCHIVE, whose member names carry traversal components. A file materialised at $OUTSIDE, outside the directory being extracted into, so member names are being trusted as paths. The target exited $CXG_RC." \
                    "CWE-22,CWE-409" \
                    "$CXG_BIN $SUB $ARCHIVE" \
                    "$CXG_OUT" \
                    "file-materialised-outside-extraction-directory" \
                    "{\"oracle\":\"property\",\"post_condition\":\"file exists outside extraction dir\",\"subcommand\":\"$SUB\",\"archive\":\"$ARCHIVE\",\"escaped_path\":\"$OUTSIDE\",\"target_exit_code\":$CXG_RC}")"
                cxg_confirm "oracle=property(archive-member-escaped) exit=$CXG_RC archive=$ARCHIVE sub=$SUB class=B04" "$FINDINGS"
            fi
        done
    done
done <<EOF
$CANDIDATES
EOF

[ "$EXERCISED" -gt 0 ] || cxg_skip "control-failed(no candidate subcommand accepted an archive)"

cxg_refute "every archive member stayed inside the extraction directory across$SEEN class=B04"
