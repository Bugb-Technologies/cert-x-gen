#!/bin/bash
#
# Benign synthetic fixture for the `exception` oracle tests. NOT a real
# vulnerability, not derived from any advisory, and not a copy of any real
# tool's output: it is a stand-in whose only job is to exit non-zero in the
# three shapes cxg has to tell apart.
#
# Which shape it prints comes from its own filename, so one file serves as all
# three targets:
#   a name containing "python"  a CPython traceback, exit 1
#   a name containing "node"    a Node unhandled-rejection stack, exit 1
#   any other name              a plain error message, exit 1 -- a program
#                               reporting a problem correctly, which the exit
#                               oracle cannot tell from the two above
set -u

case "$(basename "$0")" in
    *python*)
        {
            echo 'Traceback (most recent call last):'
            echo '  File "/tmp/synthetic/app.py", line 14, in <module>'
            echo '    main()'
            echo '  File "/tmp/synthetic/app.py", line 9, in main'
            echo '    raise ValueError("synthetic fixture")'
            echo 'ValueError: synthetic fixture'
        } >&2
        exit 1
        ;;
    *node*)
        {
            echo 'node:internal/process/promises:288'
            echo '            triggerUncaughtException(err, true /* fromPromise */);'
            echo '            ^'
            echo 'Error: synthetic fixture'
            echo '    at file:///tmp/synthetic/app.js:3:9'
            echo '[UnhandledPromiseRejection: This error originated in a rejected promise]'
        } >&2
        exit 1
        ;;
    *)
        echo 'error: no such file or directory: /tmp/synthetic/missing' >&2
        exit 1
        ;;
esac
