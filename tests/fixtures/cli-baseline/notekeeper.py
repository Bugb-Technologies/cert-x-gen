#!/usr/bin/env python3
"""
notekeeper -- the BENIGN SYNTHETIC target of the CLI Security Baseline pack.

It is not derived from any real tool and it reproduces no CVE. It exists so
that every class in the baseline has a flawed twin that CONFIRMS and a fixed
twin that REFUTES, which is the pack's honesty guarantee: a class nobody can
refute is a class nobody should ship.

Which twin this file is comes from its own filename -- the convention
`tests/fixtures/probe-contract/toy.sh` already uses, so one source file is both
builds:

    a name containing "defective"  ->  the flawed build
    any other name                 ->  the fixed build

NOTEKEEPER_DEFECTIVE=1/0 overrides the filename.

Everything it does is confined to its notes root and to paths the caller names.
It opens no network socket, downloads nothing, and every "dangerous" helper
option only copies or prints a text file. The planted defects are the smallest
thing that produces the class's observable, and each has a one-line fix
directly beside it.

    command             defect (defective twin only)                    class
    ------------------  ----------------------------------------------  -----
    show <name>         join, no containment check                      B03
    render <name>       builds a shell string, shell=True               B02
    export <name>       helper argv with no `--` separator              B01
    extract <archive>   tar extractall, no member containment check     B04
    login --password P  forwards the credential in a child's argv       B05
    convert <name>      predictable temp name, mode 0666, left behind   B06
    sync                bare "git" resolved through the caller's PATH   B07
    banner <text>       caller text written byte-for-byte               B08
    config              honours a caller-pointed config path            B09/B10
    init                writes config + token world-readable            B10
    parse <name>        unhandled exception / unbounded loop            B12
    extract <archive>   archive-library exception escapes to top level  B12
    touchfile <path>    path check, then open() that follows a symlink  B13

B11 (memory safety) and B14 (format string) need a compiled target and live in
`memtoy.c` beside this file.
"""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "noteprint.py")
SYNC_HELPER = os.path.join(HERE, "notesync.py")

_name = os.path.basename(sys.argv[0])
DEFECTIVE = (
    os.environ.get("NOTEKEEPER_DEFECTIVE", "1" if "defective" in _name else "0") == "1"
)

# Default to a cwd-relative root. The baseline pack runs every probe from inside
# its own `mktemp -d` lab, so a cwd-relative default keeps the target's whole
# world inside that sandbox without the pack needing to know this tool's names.
NOTES_ROOT = os.path.abspath(os.environ.get("NOTEKEEPER_NOTES", "notes"))

USAGE = """usage: notekeeper <command> [args]

commands:
  show <name>        print the note called <name>
  render <name>      render a note through the system pager
  export <name>      render a note through the noteprint helper
  extract <archive>  unpack a note archive into the notes root
  login              store a credential and sync with it
  convert <name>     convert a note to upper case via a work file
  sync               synchronise the notes root with its checkout
  banner <text>      print <text> in a banner
  config             print the effective configuration
  init               create the configuration and token files
  parse <name>       parse a structured note
  touchfile <path>   mark a note file as seen
  version            print the build identity

options:
  --password <pw>    credential for `login` (see also NOTEKEEPER_TOKEN)

environment:
  NOTEKEEPER_NOTES   the notes root (default: ./notes)
  NOTEKEEPER_CONFIG  path to an alternate configuration file
  NOTEKEEPER_TOKEN   credential, read instead of --password
"""


def die(msg, code=2):
    # A diagnostic echoes caller-supplied data back to a terminal just as
    # surely as a banner does, so the fixed twin neutralises control bytes
    # HERE too. B08 is about every argument the tool echoes -- names, labels,
    # error messages, progress lines -- and a tool that sanitises only its
    # happy path has not fixed the class. `sanitise` is defined below.
    if not DEFECTIVE:
        msg = sanitise(msg)
    sys.stderr.write("notekeeper: %s\n" % msg)
    sys.exit(code)


def ensure_root():
    if not os.path.isdir(NOTES_ROOT):
        os.makedirs(NOTES_ROOT)


def contained(path):
    """Is `path` inside the notes root once every symlink is resolved?"""
    real = os.path.realpath(path)
    root = os.path.realpath(NOTES_ROOT)
    return real == root or real.startswith(root + os.sep)


# ---------------------------------------------------------------- B03: show
def cmd_show(name):
    if DEFECTIVE:
        # PLANTED DEFECT (CWE-22): join, and no containment check.
        path = os.path.join(NOTES_ROOT, name)
    else:
        # FIX: resolve first, then require the result to stay under the root.
        path = os.path.realpath(os.path.join(NOTES_ROOT, name))
        if not contained(path):
            die("note name escapes the notes directory: %s" % name, 3)

    if not os.path.isfile(path):
        die("no such note: %s" % name, 4)
    with open(path, "r", errors="replace") as fh:
        sys.stdout.write(fh.read())
    return 0


# -------------------------------------------------------------- B02: render
def cmd_render(name):
    """Render a note through the pager."""
    if DEFECTIVE:
        # PLANTED DEFECT (CWE-78): the note name is pasted into a string that
        # is handed to a shell, so its metacharacters are the shell's.
        cmd = "cat %s/%s" % (NOTES_ROOT, name)
        proc = subprocess.run(cmd, shell=True)
        return proc.returncode
    # FIX: one argument vector, no shell, and the name is still contained.
    path = os.path.realpath(os.path.join(NOTES_ROOT, name))
    if not contained(path):
        die("note name escapes the notes directory: %s" % name, 3)
    if not os.path.isfile(path):
        die("no such note: %s" % name, 4)
    proc = subprocess.run(["cat", path])
    return proc.returncode


# -------------------------------------------------------------- B01: export
def cmd_export(name):
    if DEFECTIVE:
        # PLANTED DEFECT (CWE-88): no `--` separator, so a leading-hyphen name
        # is consumed by the helper's own option parser.
        argv = [sys.executable, HELPER, name]
    else:
        # FIX: end the option list before the caller's value.
        argv = [sys.executable, HELPER, "--", name]

    trace = "notekeeper: exec %s" % " ".join(shlex.quote(a) for a in argv)
    # shlex.quote makes a string safe for a SHELL, not for a terminal: it does
    # nothing about ESC. The fixed twin neutralises the control bytes as well.
    sys.stderr.write((trace if DEFECTIVE else sanitise(trace)) + "\n")
    proc = subprocess.run(argv, env=dict(os.environ, NOTEKEEPER_NOTES=NOTES_ROOT))
    return proc.returncode


# ------------------------------------------------------------- B04: extract
def cmd_extract(archive):
    ensure_root()
    if not os.path.isfile(archive):
        die("no such archive: %s" % archive, 4)

    try:
        tar = tarfile.open(archive, "r:*")
    except tarfile.TarError as exc:
        # PLANTED DEFECT (CWE-20), the B12 half of this command: the flawed
        # twin lets the archive library's exception escape to the top level, so
        # anything that is not a readable archive produces a traceback instead
        # of a diagnosis.
        if DEFECTIVE:
            raise
        # FIX: diagnose it.
        die("not a readable archive: %s" % exc, 5)

    with tar:
        if not DEFECTIVE:
            # FIX: refuse any member that would land outside the root, and any
            # link that points out of it. This check -- and ONLY this check --
            # is what separates the two twins.
            for member in tar.getmembers():
                dest = os.path.realpath(os.path.join(NOTES_ROOT, member.name))
                if not contained(dest):
                    die("archive member escapes the notes root: %s" % member.name, 3)
                if member.issym() or member.islnk():
                    target = os.path.realpath(
                        os.path.join(NOTES_ROOT, os.path.dirname(member.name), member.linkname)
                    )
                    if not contained(target):
                        die("archive link escapes the notes root: %s" % member.name, 3)

        # PLANTED DEFECT (CWE-22), defective twin only by virtue of the check
        # above being absent: member names are trusted as paths, so a member
        # called `../x` is written outside the extraction directory.
        #
        # The filter is pinned DELIBERATELY, in both twins. Python's default
        # changed in 3.14 to `data`, which refuses traversing members inside
        # the library -- so an unpinned `extractall` makes this fixture's
        # planted defect appear or vanish with the interpreter, and the twin
        # pair stops isolating the one variable it exists to isolate. Pinning
        # it in BOTH twins keeps the containment check above the only
        # difference between them, so a refutation is the TOOL's doing and not
        # the standard library's.
        try:
            tar.extractall(NOTES_ROOT, filter="fully_trusted")
        except TypeError:
            # Python < 3.12 has no `filter` parameter, and its default is this.
            tar.extractall(NOTES_ROOT)
    sys.stdout.write("extracted %s\n" % archive)
    return 0


# --------------------------------------------------------------- B05: login
def cmd_login(argv):
    password = None
    rest = list(argv)
    while rest:
        arg = rest.pop(0)
        if arg == "--password" and rest:
            password = rest.pop(0)
        elif arg.startswith("--password="):
            password = arg.split("=", 1)[1]
    if password is None:
        password = os.environ.get("NOTEKEEPER_TOKEN")
    if not password:
        die("login needs --password or NOTEKEEPER_TOKEN", 64)

    if DEFECTIVE:
        # PLANTED DEFECT (CWE-214): the credential is handed to a child process
        # as a command-line argument, where every other user on the host can
        # read it out of the process table for as long as the child runs.
        child = [sys.executable, SYNC_HELPER, "--token", password]
    else:
        # FIX: the credential travels in the child's environment instead, which
        # is not world-readable on any platform this runs on.
        child = [sys.executable, SYNC_HELPER, "--token-from-env"]

    proc = subprocess.run(child, env=dict(os.environ, NOTEKEEPER_TOKEN=password))
    sys.stdout.write("login ok\n")
    return proc.returncode


# ------------------------------------------------------------- B06: convert
def cmd_convert(name):
    ensure_root()
    path = os.path.realpath(os.path.join(NOTES_ROOT, name))
    if not contained(path) or not os.path.isfile(path):
        die("no such note: %s" % name, 4)
    with open(path, "r", errors="replace") as fh:
        body = fh.read()

    if DEFECTIVE:
        # PLANTED DEFECT (CWE-377): a predictable name in the shared temp
        # directory, created world-writable, and left behind afterwards.
        work = os.path.join(tempfile.gettempdir(), "notekeeper-convert.tmp")
        fd = os.open(work, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666)
        with os.fdopen(fd, "w") as fh:
            fh.write(body.upper())
        with open(work, "r", errors="replace") as fh:
            sys.stdout.write(fh.read())
        # and no cleanup
    else:
        # FIX: mkstemp gives an unpredictable name created 0600 with O_EXCL,
        # and the work file does not outlive the run.
        fd, work = tempfile.mkstemp(prefix="notekeeper-convert-")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(body.upper())
            with open(work, "r", errors="replace") as fh:
                sys.stdout.write(fh.read())
        finally:
            os.unlink(work)
    return 0


# ---------------------------------------------------------------- B07: sync
def cmd_sync():
    ensure_root()
    if DEFECTIVE:
        # PLANTED DEFECT (CWE-426): a bare command name, resolved through
        # whatever PATH the caller happened to export.
        argv = ["git", "rev-parse", "--show-toplevel"]
        proc = subprocess.run(argv, cwd=NOTES_ROOT)
    else:
        # FIX: resolve the helper against a fixed system search path, ignoring
        # the inherited one, and fail closed if it is not there.
        resolved = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin")
        if resolved is None:
            sys.stdout.write("sync: no git available, nothing to do\n")
            return 0
        proc = subprocess.run(
            [resolved, "rev-parse", "--show-toplevel"], cwd=NOTES_ROOT
        )
    sys.stdout.write("sync done\n")
    return 0


# -------------------------------------------------------------- B08: banner
C0_SAFE = {0x09, 0x0A}  # tab and newline are legitimate in a banner


def sanitise(text):
    out = []
    for ch in text:
        o = ord(ch)
        if (o < 0x20 and o not in C0_SAFE) or o == 0x7F:
            out.append("\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


def cmd_banner(text):
    if not DEFECTIVE:
        # FIX: neutralise C0 controls (ESC among them) before display.
        text = sanitise(text)
    bar = "+" + "-" * 40 + "+"
    sys.stdout.write(bar + "\n| " + text + "\n" + bar + "\n")
    return 0


# ------------------------------------------------------- B09/B10: config
def cmd_config():
    settings = {"notes_root": NOTES_ROOT, "build": "defective" if DEFECTIVE else "fixed"}

    if DEFECTIVE:
        # PLANTED DEFECT (CWE-454/CWE-526): an environment variable names a
        # configuration file, and its content is read and echoed with no check
        # on where it points.
        pointed = os.environ.get("NOTEKEEPER_CONFIG")
        if pointed and os.path.isfile(pointed):
            with open(pointed, "r", errors="replace") as fh:
                settings["extra"] = fh.read().strip()
        # PLANTED DEFECT (CWE-732 companion): a config file in the working
        # directory is honoured with no trust prompt at all.
        local = os.path.join(os.getcwd(), ".notekeeperrc")
        if os.path.isfile(local):
            with open(local, "r", errors="replace") as fh:
                settings["local"] = fh.read().strip()
    else:
        # FIX: configuration comes from one place the tool owns, and a caller
        # pointing elsewhere is ignored rather than obeyed.
        owned = os.path.join(NOTES_ROOT, "config.json")
        if os.path.isfile(owned) and contained(owned):
            with open(owned, "r", errors="replace") as fh:
                try:
                    settings["extra"] = json.load(fh).get("extra", "")
                except ValueError:
                    settings["extra"] = ""

    sys.stdout.write(json.dumps(settings, indent=2) + "\n")
    return 0


# ---------------------------------------------------------------- B10: init
def cmd_init():
    ensure_root()
    config_path = os.path.join(NOTES_ROOT, "config.json")
    token_path = os.path.join(NOTES_ROOT, "token")
    body = json.dumps({"extra": "", "created": "static-for-reproducibility"}, indent=2)

    if DEFECTIVE:
        # PLANTED DEFECT (CWE-732/CWE-276): state files, one of them a
        # credential, created readable by every user on the host.
        mode = 0o644
    else:
        # FIX: owner-only, which is what a credential file has to be.
        mode = 0o600

    for path, content in ((config_path, body), (token_path, "static-demo-token\n")):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        os.chmod(path, mode)

    sys.stdout.write("initialised %s (mode %s)\n" % (NOTES_ROOT, oct(mode)))
    return 0


# --------------------------------------------------------------- B12: parse
def cmd_parse(name):
    """Parse a structured (key=value per line) note."""
    path = os.path.realpath(os.path.join(NOTES_ROOT, name))
    if not contained(path) or not os.path.isfile(path):
        die("no such note: %s" % name, 4)
    with open(path, "r", errors="replace") as fh:
        body = fh.read()

    if DEFECTIVE:
        # PLANTED DEFECT (CWE-20): a malformed line escapes as an unhandled
        # exception rather than a diagnosed error...
        pairs = {}
        for line in body.splitlines():
            if not line.strip():
                continue
            key, value = line.split("=", 1)  # raises on a line with no '='
            pairs[key] = value
        # ...and a repeat-count header is honoured without a bound (CWE-400).
        if "repeat=" in body:
            count = int(pairs.get("repeat", "0"))
            total = 0
            for _ in range(count):
                total += 1
                time.sleep(0.001)
            pairs["counted"] = str(total)
        sys.stdout.write(json.dumps(pairs) + "\n")
        return 0

    # FIX: a malformed line is a diagnosed error, and the repeat count is
    # bounded by something the input cannot choose.
    pairs = {}
    for line in body.splitlines():
        if not line.strip():
            continue
        if "=" not in line:
            die("malformed note line: %r" % line[:60], 5)
        key, value = line.split("=", 1)
        pairs[key] = value
    if "repeat" in pairs:
        try:
            count = min(int(pairs["repeat"]), 1000)
        except ValueError:
            die("malformed repeat count", 5)
        pairs["counted"] = str(count)
    sys.stdout.write(json.dumps(pairs) + "\n")
    return 0


# ----------------------------------------------------------- B13: touchfile
def cmd_touchfile(path):
    """Mark a note file as seen by writing a marker into it."""
    if not os.path.exists(path):
        die("no such file: %s" % path, 4)
    if os.path.islink(path):
        die("refusing to follow a symlink: %s" % path, 3)

    # Both twins wait here. The window is deliberately wide so the class is
    # demonstrable at all -- a real tool's window is microseconds, which is
    # exactly why B13's negative result is probabilistic and the baseline says
    # so. The FIX below is not "be faster"; it is "make following impossible".
    time.sleep(float(os.environ.get("NOTEKEEPER_TOCTOU_WINDOW", "0.6")))

    if DEFECTIVE:
        # PLANTED DEFECT (CWE-367): the check above was against the *path*, and
        # this open resolves that path again -- following whatever it names now.
        with open(path, "w") as fh:
            fh.write("seen\n")
    else:
        # FIX: refuse to traverse a final symlink at open time, so whatever was
        # swapped in during the window cannot be followed.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            die("refusing to follow a symlink at open: %s" % exc.strerror, 3)
        with os.fdopen(fd, "w") as fh:
            fh.write("seen\n")

    sys.stdout.write("touched %s\n" % path)
    return 0


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(USAGE)
        return 64
    cmd = argv[1]
    rest = argv[2:]

    if cmd in ("--help", "-h", "help"):
        sys.stdout.write(USAGE)
        return 0
    if cmd == "version":
        sys.stdout.write(
            "notekeeper 0.2 (%s)\n" % ("defective" if DEFECTIVE else "fixed")
        )
        return 0
    if cmd == "login":
        return cmd_login(rest)
    if cmd in ("sync", "config", "init"):
        return {"sync": cmd_sync, "config": cmd_config, "init": cmd_init}[cmd]()

    one_arg = {
        "show": cmd_show,
        "render": cmd_render,
        "export": cmd_export,
        "extract": cmd_extract,
        "convert": cmd_convert,
        "banner": cmd_banner,
        "parse": cmd_parse,
        "touchfile": cmd_touchfile,
    }
    if cmd in one_arg:
        if not rest:
            die("%s needs one argument" % cmd, 64)
        return one_arg[cmd](rest[0])

    sys.stderr.write(USAGE)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
