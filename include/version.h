/**
 * version.h - Version information for dotta
 *
 * This file defines version constants and helper functions.
 * Version numbers follow Semantic Versioning (https://semver.org/)
 *
 * Version format: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
 *
 * MAJOR: Incompatible API changes
 * MINOR: Backwards-compatible functionality additions
 * PATCH: Backwards-compatible bug fixes
 * PRERELEASE: Pre-release identifier (e.g., "alpha", "beta", "rc.1")
 * BUILD: Build metadata (e.g., git commit hash, build date)
 */

#ifndef DOTTA_VERSION_H
#define DOTTA_VERSION_H

/**
 * Version number components
 *
 * These can be compared numerically for version checks.
 */
#define DOTTA_VERSION_MAJOR 0
#define DOTTA_VERSION_MINOR 4
#define DOTTA_VERSION_PATCH 0

/**
 * Pre-release identifier (empty string for release versions)
 *
 * Examples: "dev", "alpha", "beta.1", "rc.2"
 */
#define DOTTA_VERSION_PRERELEASE "dev"

/**
 * Full version string
 *
 * Format: "MAJOR.MINOR.PATCH[-PRERELEASE]"
 */
#define DOTTA_VERSION_STRING "0.4.0-dev"

/**
 * Numeric version for comparisons
 *
 * Format: (MAJOR * 10000) + (MINOR * 100) + PATCH
 * Example: 0.1.0 = 100, 1.2.3 = 10203
 */
#define DOTTA_VERSION_NUM \
    ((DOTTA_VERSION_MAJOR * 10000) + \
     (DOTTA_VERSION_MINOR * 100) + \
     DOTTA_VERSION_PATCH)

/**
 * Build metadata (set by build system)
 *
 * Can be defined via compiler flags:
 *   -DDOTTA_BUILD_COMMIT="abc123"
 *   -DDOTTA_BUILD_DATE="2025-01-15"
 *   -DDOTTA_BUILD_TIME="10:30:00"
 *   -DDOTTA_BUILD_OS="darwin"
 *   -DDOTTA_BUILD_ARCH="arm64"
 *   -DDOTTA_BUILD_TYPE="release"
 *   -DDOTTA_BUILD_BRANCH="main"
 *   -DDOTTA_BUILD_CC="clang version 15.0.0"
 */
#ifndef DOTTA_BUILD_COMMIT
#define DOTTA_BUILD_COMMIT "unknown"
#endif

#ifndef DOTTA_BUILD_COMMIT_FULL
#define DOTTA_BUILD_COMMIT_FULL "unknown"
#endif

#ifndef DOTTA_BUILD_BRANCH
#define DOTTA_BUILD_BRANCH "unknown"
#endif

#ifndef DOTTA_BUILD_DATE
#define DOTTA_BUILD_DATE __DATE__
#endif

#ifndef DOTTA_BUILD_TIME
#define DOTTA_BUILD_TIME __TIME__
#endif

#ifndef DOTTA_BUILD_OS
#define DOTTA_BUILD_OS "unknown"
#endif

#ifndef DOTTA_BUILD_ARCH
#define DOTTA_BUILD_ARCH "unknown"
#endif

#ifndef DOTTA_BUILD_TYPE
#define DOTTA_BUILD_TYPE "alpha"
#endif

#ifndef DOTTA_BUILD_CC
#define DOTTA_BUILD_CC "unknown"
#endif

/**
 * Get version string
 *
 * Returns the full version string (e.g., "0.1.0-dev")
 *
 * @return Version string (static, do not free)
 */
static inline const char *dotta_version_string(void) {
    return DOTTA_VERSION_STRING;
}

/**
 * Get version number
 *
 * Returns numeric version for comparisons.
 * Higher numbers indicate newer versions.
 *
 * @return Numeric version
 */
static inline int dotta_version_num(void) {
    return DOTTA_VERSION_NUM;
}

/**
 * Get major version
 *
 * @return Major version number
 */
static inline int dotta_version_major(void) {
    return DOTTA_VERSION_MAJOR;
}

/**
 * Get minor version
 *
 * @return Minor version number
 */
static inline int dotta_version_minor(void) {
    return DOTTA_VERSION_MINOR;
}

/**
 * Get patch version
 *
 * @return Patch version number
 */
static inline int dotta_version_patch(void) {
    return DOTTA_VERSION_PATCH;
}

/**
 * Get pre-release identifier
 *
 * @return Pre-release string (empty for release versions)
 */
static inline const char *dotta_version_prerelease(void) {
    return DOTTA_VERSION_PRERELEASE;
}

/**
 * Get build commit hash
 *
 * @return Git commit hash or "unknown"
 */
static inline const char *dotta_version_commit(void) {
    return DOTTA_BUILD_COMMIT;
}

/**
 * Get build date
 *
 * @return Build date string
 */
static inline const char *dotta_version_build_date(void) {
    return DOTTA_BUILD_DATE;
}

/**
 * Get build time
 *
 * @return Build time string
 */
static inline const char *dotta_version_build_time(void) {
    return DOTTA_BUILD_TIME;
}

/**
 * Get full commit hash
 *
 * @return Full Git commit hash or "unknown"
 */
static inline const char *dotta_version_commit_full(void) {
    return DOTTA_BUILD_COMMIT_FULL;
}

/**
 * Get build branch
 *
 * @return Git branch name or "unknown"
 */
static inline const char *dotta_version_branch(void) {
    return DOTTA_BUILD_BRANCH;
}

/**
 * Get build OS
 *
 * @return Build operating system (darwin, linux, freebsd, etc.)
 */
static inline const char *dotta_version_build_os(void) {
    return DOTTA_BUILD_OS;
}

/**
 * Get build architecture
 *
 * @return Build architecture (x86_64, arm64, etc.)
 */
static inline const char *dotta_version_build_arch(void) {
    return DOTTA_BUILD_ARCH;
}

/**
 * Get build type
 *
 * @return Build type (release, debug, etc.)
 */
static inline const char *dotta_version_build_type(void) {
    return DOTTA_BUILD_TYPE;
}

/**
 * Get compiler version
 *
 * @return Compiler version string
 */
static inline const char *dotta_version_build_cc(void) {
    return DOTTA_BUILD_CC;
}

/**
 * Check if version is at least the specified version
 *
 * @param major Major version to check
 * @param minor Minor version to check
 * @param patch Patch version to check
 * @return true if current version >= specified version
 */
static inline int dotta_version_at_least(int major, int minor, int patch) {
    int required = (major * 10000) + (minor * 100) + patch;
    return DOTTA_VERSION_NUM >= required;
}

#endif /* DOTTA_VERSION_H */
