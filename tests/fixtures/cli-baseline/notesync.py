#!/usr/bin/env python3
"""
notesync -- the benign synthetic helper `notekeeper login` runs with a
credential.

It contains no defect either. It accepts the credential the two ordinary ways a
real helper does:

    --token <value>     on the command line  -- world-readable in `ps`
    --token-from-env    from NOTEKEEPER_TOKEN -- not world-readable

The class being demonstrated (B05, CWE-214) is the CALLER's choice of which one
to use. notekeeper's defective twin picks the first; the fixed twin picks the
second.

It sleeps briefly so that a probe running concurrently has a window in which to
observe the process table at all. That sleep is the fixture making a real race
observable on purpose; it is not itself the defect.
"""

import os
import sys
import time

HOLD_SECONDS = float(os.environ.get("NOTESYNC_HOLD", "1.5"))


def main(argv):
    token = None
    rest = list(argv[1:])
    while rest:
        arg = rest.pop(0)
        if arg == "--token" and rest:
            token = rest.pop(0)
        elif arg == "--token-from-env":
            token = os.environ.get("NOTEKEEPER_TOKEN")
        elif arg.startswith("--token="):
            token = arg.split("=", 1)[1]

    if not token:
        sys.stderr.write("notesync: no credential supplied\n")
        return 4

    # The window. Whatever is in this process's argv is readable from the
    # process table for as long as this runs.
    time.sleep(HOLD_SECONDS)

    sys.stdout.write("notesync: synchronised (credential length %d)\n" % len(token))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
