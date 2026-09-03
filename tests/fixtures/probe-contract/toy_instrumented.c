/*
 * Benign synthetic fixture for the probe-contract tests -- the compiled twin
 * of toy.sh. NOT a real vulnerability and not derived from any advisory.
 *
 * It exists because an instrumentation marker only means something inside a
 * *compiled object*: since s14 item 2, cxg reports `none` for a shebang
 * script however many marker strings it contains, so a test that needs an
 * instrumented target needs a real object file. The markers are carried as an
 * ordinary string constant, which is where a sanitizer-linked build carries
 * them too (its symbol table).
 *
 * Contract, identical to toy.sh:
 *   toy --label <text>   store a label in a notional 16-byte buffer
 *   toy --stdin          read one line from stdin and store that
 * Which twin it is comes from argv[0]: a name containing "defective" is the
 * unbounded one, and an over-length label makes it print a sanitizer-shaped
 * report and exit 134 -- the shape a real ASan crash has. Any other name is
 * bounds-checked and truncates.
 *
 * Build markers are injected by the test harness:
 *   cc -DCXG_BUILD_MARKERS='"__asan_init __asan_report_load1"' toy_instrumented.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CXG_BUILD_MARKERS
#define CXG_BUILD_MARKERS "none"
#endif

/* Referenced from main() so no optimisation level can drop it. */
const char cxg_build_markers[] = "cxg-build-markers: " CXG_BUILD_MARKERS;

#define BUFSZ 16

static int defective(const char *argv0) {
    const char *base = strrchr(argv0, '/');
    base = base ? base + 1 : argv0;
    return strstr(base, "defective") != NULL;
}

static int store_label(const char *src, int is_defective) {
    char buf[BUFSZ];
    size_t len = strlen(src);

    if (is_defective && len >= BUFSZ) {
        fprintf(stderr, "=================================================================\n");
        fprintf(stderr, "ERROR: AddressSanitizer: stack-buffer-overflow on address 0x0000dead\n");
        fprintf(stderr, "WRITE of size %zu at 0x0000dead thread T0\n", len);
        fprintf(stderr, "    #0 0x0 in store_label toy_instrumented.c:%d\n", BUFSZ);
        fprintf(stderr, "SUMMARY: AddressSanitizer: stack-buffer-overflow toy_instrumented.c in store_label\n");
        return 134;
    }

    memset(buf, 0, sizeof buf);
    if (len > BUFSZ - 1) {
        len = BUFSZ - 1;
    }
    memcpy(buf, src, len);
    printf("label=%s\n", buf);
    return 0;
}

int main(int argc, char **argv) {
    int is_defective = defective(argv[0]);

    if (getenv("TOY_DEFECTIVE") != NULL) {
        is_defective = strcmp(getenv("TOY_DEFECTIVE"), "1") == 0;
    }
    if (getenv("CXG_SHOW_BUILD_MARKERS") != NULL) {
        printf("%s\n", cxg_build_markers);
        return 0;
    }

    if (argc >= 3 && strcmp(argv[1], "--label") == 0) {
        return store_label(argv[2], is_defective);
    }
    if (argc >= 2 && strcmp(argv[1], "--stdin") == 0) {
        char line[4096];
        if (fgets(line, sizeof line, stdin) == NULL) {
            return 2;
        }
        line[strcspn(line, "\n")] = '\0';
        return store_label(line, is_defective);
    }

    fprintf(stderr, "usage: toy --label <text> | toy --stdin\n");
    return 64;
}
