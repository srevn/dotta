/**
 * version.c - Version banner renderer.
 *
 * All data comes from the compile-time constants in `<version.h>`;
 * this file owns only the formatting.
 */

#include "utils/version.h"

#include <git2.h>
#include <sqlite3.h>
#include <string.h>
#include <version.h>

void version_print(FILE *out) {
    int major, minor, rev;
    git_libgit2_version(&major, &minor, &rev);

    fprintf(out, "dotta version %s\n", DOTTA_VERSION_STRING);

    if (strcmp(DOTTA_BUILD_COMMIT, "unknown") != 0) {
        fprintf(out, "Git: %s", DOTTA_BUILD_COMMIT);
        if (strcmp(DOTTA_BUILD_BRANCH, "unknown") != 0) {
            fprintf(out, " (%s)", DOTTA_BUILD_BRANCH);
        }
        fputc('\n', out);
    }

    if (strcmp(DOTTA_BUILD_OS, "unknown") != 0 &&
        strcmp(DOTTA_BUILD_ARCH, "unknown") != 0) {
        fprintf(out, "Platform: %s/%s\n", DOTTA_BUILD_OS, DOTTA_BUILD_ARCH);
    }

    fprintf(out, "Build: %s", DOTTA_BUILD_TYPE);
    fprintf(out, " - %s %s\n", DOTTA_BUILD_DATE, DOTTA_BUILD_TIME);

    if (strcmp(DOTTA_BUILD_CC, "unknown") != 0) {
        fprintf(out, "Compiler: %s\n", DOTTA_BUILD_CC);
    }

    fprintf(out, "libgit2: %d.%d.%d\n", major, minor, rev);
    fprintf(out, "sqlite: %s\n", sqlite3_libversion());
}
