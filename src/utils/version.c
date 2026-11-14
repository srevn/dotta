/**
 * version.c - Version banner renderer.
 *
 * All data comes from the compile-time constants in `<version.h>`; this file
 * owns only the formatting.
 */

#include "utils/version.h"

#include <git2.h>
#include <sqlite3.h>
#include <version.h>

void version_print(FILE *out) {
    int major, minor, rev;
    git_libgit2_version(&major, &minor, &rev);

    /* Print dotta version */
    fprintf(out, "dotta version %s\n", DOTTA_VERSION_STRING);

    /* Print git information */
    if (DOTTA_BUILD_COMMIT[0] != '\0') {
        fprintf(out, "Git: %s", DOTTA_BUILD_COMMIT);
        if (DOTTA_BUILD_BRANCH[0] != '\0') {
            fprintf(out, " (%s)", DOTTA_BUILD_BRANCH);
        }
        fputc('\n', out);
    }

    /* Print platform information */
    if (DOTTA_BUILD_PLATFORM[0] != '\0') {
        fprintf(out, "Platform: %s\n", DOTTA_BUILD_PLATFORM);
    }

    /* Print build information */
    fprintf(out, "Build: %s", DOTTA_BUILD_TYPE);
    fprintf(out, " - %s %s\n", DOTTA_BUILD_DATE, DOTTA_BUILD_TIME);

    /* Print compiler information */
    if (DOTTA_BUILD_CC[0] != '\0') {
        fprintf(out, "Compiler: %s\n", DOTTA_BUILD_CC);
    }

    /* Print libgit2 and sqlite version */
    fprintf(
        out, "Libraries: libgit2 %d.%d.%d, sqlite %s\n",
        major, minor, rev, sqlite3_libversion()
    );
}
