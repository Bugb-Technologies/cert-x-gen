/*
 * memtoy -- the compiled BENIGN SYNTHETIC twin of the CLI Security Baseline
 * fixture corpus, for the two classes that need a compiled target:
 *
 *   B11  memory-safety defect (CWE-787)   `memtoy --label <text>`
 *   B14  format-string defect  (CWE-134)  `memtoy --echo  <text>`
 *
 * Not derived from any advisory and not a reproduction of any CVE. Each defect
 * is the smallest thing that produces the class's observable, with its one-line
 * fix directly beside it.
 *
 * Which twin this is comes from argv[0] -- a basename containing "defective" is
 * the flawed build -- so one source file builds both, the same convention as
 * `tests/fixtures/probe-contract/toy_instrumented.c` and `notekeeper.py`.
 *
 * Build (the harness does this; see tests/cli_baseline_pack.rs):
 *
 *   cc -fsanitize=address -g -O0 -o memtoy_defective memtoy.c
 *   cc -fsanitize=address -g -O0 -o memtoy_fixed     memtoy.c
 *
 * ASan matters for B11 specifically: an uninstrumented build of the defective
 * twin can overflow its buffer, exit 0 and look perfect, which is the exact
 * false negative the baseline's Detectability column is about. The pack's B11
 * template declares `@oracles: asan, ubsan` so that cxg SKIPS it on a build
 * that cannot show the defect, rather than reporting a refutation it did not
 * earn.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 16

static int defective(const char *argv0) {
    const char *base = strrchr(argv0, '/');
    base = base ? base + 1 : argv0;
    return strstr(base, "defective") != NULL;
}

static void usage(void) {
    printf("usage: memtoy <command> [text]\n"
           "\n"
           "commands:\n"
           "  --label <text>   store <text> in a fixed-size label buffer\n"
           "  --echo <text>    print <text> back to stdout\n"
           "  version          print the build identity\n");
}

/* ------------------------------------------------------------- B11: label */
static int cmd_label(const char *text, int is_defective) {
    char buf[BUFSZ];

    if (is_defective) {
        /* PLANTED DEFECT (CWE-787): an unbounded copy into a fixed buffer.
         * Without a sanitizer this frequently "works" and exits 0. */
        strcpy(buf, text);
    } else {
        /* FIX: bound the copy by the destination, and always terminate. */
        strncpy(buf, text, BUFSZ - 1);
        buf[BUFSZ - 1] = '\0';
    }

    printf("label: %s\n", buf);
    return 0;
}

/* -------------------------------------------------------------- B14: echo */
static int cmd_echo(const char *text, int is_defective) {
    if (is_defective) {
        /* PLANTED DEFECT (CWE-134): caller text used as the format string, so
         * its conversion specifiers are honoured rather than printed.
         *
         * The diagnostic is suppressed only here, and only so this fixture
         * builds warning-free: -Wformat-security is the compiler correctly
         * identifying the very defect this twin is meant to carry. */
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
        printf(text);
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    } else {
        /* FIX: the caller's text is an argument, never the format. */
        printf("%s", text);
    }
    printf("\n");
    return 0;
}

int main(int argc, char **argv) {
    int is_defective = defective(argv[0]);

    if (argc < 2) {
        usage();
        return 64;
    }
    if (strcmp(argv[1], "version") == 0) {
        printf("memtoy 0.1 (%s)\n", is_defective ? "defective" : "fixed");
        return 0;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0 ||
        strcmp(argv[1], "help") == 0) {
        usage();
        return 0;
    }
    if (argc < 3) {
        usage();
        return 64;
    }
    if (strcmp(argv[1], "--label") == 0) {
        return cmd_label(argv[2], is_defective);
    }
    if (strcmp(argv[1], "--echo") == 0) {
        return cmd_echo(argv[2], is_defective);
    }

    usage();
    return 64;
}
