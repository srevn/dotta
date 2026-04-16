/**
 * version.h - Version banner renderer for the dotta CLI.
 *
 * Thin layer on top of the compile-time constants exposed by
 * `<version.h>` (the project-wide header in `include/`). That header
 * owns the data; this module owns the *presentation* — composing
 * version string, commit, platform, build metadata, and the linked
 * libgit2 version into the banner printed by `dotta --version`.
 *
 * Kept in `utils/` rather than `base/` because the banner's wording
 * and layout are dotta-specific application plumbing (per CLAUDE.md's
 * layer charter), not a generic primitive.
 */

#ifndef DOTTA_UTILS_VERSION_H
#define DOTTA_UTILS_VERSION_H

#include <stdio.h>

/**
 * Print the version banner to the given stream.
 *
 * Emits (in order):
 *   - `dotta version <X.Y.Z-suffix>`
 *   - `Git: <commit> (<branch>)`      (skipped if unknown)
 *   - `Platform: <os>/<arch>`         (skipped if either is unknown)
 *   - `Build: <type> - <date> <time>` (sanitizer tag for debug builds)
 *   - `Compiler: <cc>`                (skipped if unknown)
 *   - `libgit2: <major>.<minor>.<rev>`
 *
 * No allocations, no error paths — every input is a compile-time
 * constant or a libgit2 call that cannot fail.
 */
void version_print(FILE *out);

#endif /* DOTTA_UTILS_VERSION_H */
