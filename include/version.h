/**
 * version.h - Version information for dotta.
 *
 * Defines the project's semantic version (https://semver.org/) and the
 * compile-time constants describing the build environment. All values
 * are string/integer literals — there is no runtime accessor layer; the
 * banner renderer in `src/utils/version.c` uses these macros directly.
 *
 * Version format: MAJOR.MINOR.PATCH[-PRERELEASE]
 *
 *   MAJOR      Incompatible API changes
 *   MINOR      Backwards-compatible functionality additions
 *   PATCH      Backwards-compatible bug fixes
 *   PRERELEASE Pre-release identifier (e.g., "dev", "rc.1"); empty on a
 *              stable release. Stored with its leading dash so it can
 *              be concatenated unconditionally into the version string.
 *
 * Release workflow: bump the numeric components below and toggle
 * DOTTA_VERSION_PRERELEASE between "-dev" (or similar) and "".
 * DOTTA_VERSION_STRING is derived — never edit it by hand.
 */

#ifndef DOTTA_VERSION_H
#define DOTTA_VERSION_H

/**
 * Semantic version components.
 *
 * Integer literals so they can participate in arithmetic or
 * preprocessor comparisons if a call site ever needs to.
 */
#define DOTTA_VERSION_MAJOR 0
#define DOTTA_VERSION_MINOR 86
#define DOTTA_VERSION_PATCH 0

/**
 * Pre-release suffix, including a leading dash when present.
 *
 * Examples:
 *   ""       stable release         → "0.65.1"
 *   "-dev"   in-development build   → "0.65.1-dev"
 *   "-rc.1"  release candidate      → "0.65.1-rc.1"
 *   "-alpha" alpha                  → "0.65.1-alpha"
 *
 * The leading dash lives in the suffix itself rather than being
 * emitted conditionally; `#if` cannot inspect string-literal contents,
 * so unconditional concatenation is the only clean option.
 */
#define DOTTA_VERSION_PRERELEASE "-dev"

/**
 * Full version string, derived from the components above.
 *
 * Produced with the two-level stringize idiom: `#` in a function-like
 * macro stringizes the argument's *name*, not its expansion, so a
 * single level would yield "DOTTA_VERSION_MAJOR" rather than "0". The
 * outer macro forces expansion first, then the inner one applies `#`.
 * Adjacent string literals are concatenated by the translator
 * (C11 §5.1.1.2 phase 6), so the result is a single literal with no
 * runtime cost.
 */
#define DOTTA_STRINGIFY_(x) #x
#define DOTTA_STRINGIFY(x)  DOTTA_STRINGIFY_(x)

#define DOTTA_VERSION_STRING \
    DOTTA_STRINGIFY(DOTTA_VERSION_MAJOR) "." \
    DOTTA_STRINGIFY(DOTTA_VERSION_MINOR) "." \
    DOTTA_STRINGIFY(DOTTA_VERSION_PATCH) \
    DOTTA_VERSION_PRERELEASE

/**
 * Build metadata injected by the Makefile via `-D` flags.
 *
 * Each value is a string literal defined by the build system:
 *
 *   -DDOTTA_BUILD_COMMIT="abc1234-dirty"   short git SHA + dirty flag
 *   -DDOTTA_BUILD_BRANCH="main"            current git branch
 *   -DDOTTA_BUILD_PLATFORM="darwin/arm64"  kernel name + machine arch
 *   -DDOTTA_BUILD_TYPE="release"           "release" | "debug"
 *   -DDOTTA_BUILD_CC="clang version ..."   compiler identity
 *
 * The `#ifndef` fallbacks below keep the header self-contained when
 * the translation unit is built outside the project Makefile (e.g.,
 * by an IDE's language server). `BUILD_DATE` and `BUILD_TIME` fall
 * back to the standard `__DATE__` / `__TIME__` predefined macros.
 */
#ifndef DOTTA_BUILD_COMMIT
#define DOTTA_BUILD_COMMIT "unknown"
#endif
#ifndef DOTTA_BUILD_BRANCH
#define DOTTA_BUILD_BRANCH "unknown"
#endif
#ifndef DOTTA_BUILD_PLATFORM
#define DOTTA_BUILD_PLATFORM "unknown"
#endif
#ifndef DOTTA_BUILD_TYPE
#define DOTTA_BUILD_TYPE "release"
#endif
#ifndef DOTTA_BUILD_CC
#define DOTTA_BUILD_CC "unknown"
#endif
#ifndef DOTTA_BUILD_DATE
#define DOTTA_BUILD_DATE __DATE__
#endif
#ifndef DOTTA_BUILD_TIME
#define DOTTA_BUILD_TIME __TIME__
#endif

#endif /* DOTTA_VERSION_H */
