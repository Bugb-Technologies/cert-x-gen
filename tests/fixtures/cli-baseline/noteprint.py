#!/usr/bin/env python3
"""
noteprint -- the benign synthetic helper `notekeeper export` shells out to.

It is deliberately ORDINARY, and it contains no defect. Like almost every real
CLI helper -- `curl`, `tar`, `ssh`, `find`, `git` -- it has options, and one of
them has a side effect on the filesystem.

The defect being demonstrated lives in the CALLER: notekeeper's defective twin
hands this program a caller-controlled string as the first element of its argv
with no `--` end-of-options separator, so the string is parsed here as an
option of this program.

`--write-to <path>` is the benign stand-in for that class of option. All it
does is copy the rendered note to a path, and that is the observable: if it
runs when the caller only ever meant to name a note, argument injection
happened.
"""

import argparse
import os
import sys

C0_SAFE = {0x09, 0x0A}  # tab and newline are legitimate in a message


def sanitise(text):
    """Render C0 control bytes visibly.

    This helper carries no defect, and echoing a caller-supplied name back to a
    terminal with its ESC bytes intact would be one -- B08 (CWE-150) is about
    every argument a tool echoes, diagnostics included. Unconditional, because
    unlike notekeeper this program is not a two-twin fixture: it is the
    always-correct helper both twins call.
    """
    out = []
    for ch in text:
        o = ord(ch)
        if (o < 0x20 and o not in C0_SAFE) or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(prog="noteprint", add_help=True)
    ap.add_argument("name", nargs="?", default=None, help="note to render")
    ap.add_argument("--write-to", default=None, help="also copy the rendered note here")
    ap.add_argument("--banner", default=None, help="text to print above the note")
    args = ap.parse_args()

    root = os.path.realpath(os.environ.get("NOTEKEEPER_NOTES", "."))
    body = ""
    if args.name:
        # This helper contains its POSITIONAL argument to the notes root. It
        # has no defect of its own, and a traversal here would make it one --
        # B03 would then confirm against the fixed twin of notekeeper through
        # this program rather than through the defect it is testing for.
        #
        # `--write-to` is deliberately NOT contained: writing where the
        # operator points is that option's whole purpose, exactly as with
        # `curl -o` or `tar -f`. That asymmetry is the point of the B01
        # fixture -- the danger is a CALLER letting untrusted data become this
        # option, not the option existing.
        path = os.path.realpath(os.path.join(root, args.name))
        if not (path == root or path.startswith(root + os.sep)):
            sys.stderr.write(
                "noteprint: note name escapes the notes root: %s\n" % sanitise(args.name)
            )
            return 3
        if os.path.isfile(path):
            with open(path, "r", errors="replace") as fh:
                body = fh.read()
        else:
            sys.stderr.write("noteprint: no such note: %s\n" % sanitise(args.name))
            return 4

    if args.banner:
        sys.stdout.write("== %s ==\n" % sanitise(args.banner))
    sys.stdout.write(body)

    if args.write_to:
        with open(args.write_to, "w") as fh:
            fh.write("noteprint reached --write-to\n")
            fh.write(body)
        sys.stderr.write("noteprint: wrote %s\n" % args.write_to)
    return 0


if __name__ == "__main__":
    sys.exit(main())
