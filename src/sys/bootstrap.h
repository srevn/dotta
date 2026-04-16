/**
 * bootstrap.h - Profile bootstrap script primitives
 *
 * Pure content operations on per-profile .bootstrap scripts stored in
 * Git trees. Every function here is a single-responsibility primitive
 * — Git blob read, temp-file extraction, or shebang validation — with
 * no knowledge of iteration, progress output, subprocess spawning, or
 * configuration.
 *
 * Orchestration (filtering, per-script progress, dry-run, aggregated
 * failure reporting) lives in utils/bootstrap.h on top of these
 * primitives and the unified subprocess primitive in sys/process.h.
 */

#ifndef DOTTA_BOOTSTRAP_H
#define DOTTA_BOOTSTRAP_H

#include <git2.h>
#include <stdbool.h>
#include <stddef.h>
#include <types.h>

/**
 * Bootstrap script filename (fixed).
 *
 * Always lives at the root of a profile's Git tree. Dotta does not
 * support alternate names; the constant exists to avoid scattering
 * the literal ".bootstrap" through progress messages and UI code.
 */
#define BOOTSTRAP_SCRIPT_NAME ".bootstrap"

/**
 * Check whether a profile's tree contains a .bootstrap script.
 *
 * Swallows errors — a missing profile, an unreadable tree, or a
 * non-existent entry all collapse to `false`. Callers use this to
 * drive UI decisions (show ✓/✗, filter which profiles to execute)
 * where "no script" is not a fatal condition.
 *
 * @param repo    Open Git repository (must not be NULL)
 * @param profile Profile branch name (must not be NULL or empty)
 * @return true iff profile's tree has .bootstrap at the root
 */
bool bootstrap_exists(git_repository *repo, const char *profile);

/**
 * Read a profile's .bootstrap script into a buffer.
 *
 * On success, ownership of *out_content transfers to the caller, who
 * must buffer_free() it. On failure, *out_content is left in the
 * zero-initialized state (safe to buffer_free).
 *
 * @param repo        Open Git repository (must not be NULL)
 * @param profile     Profile branch name (must not be NULL)
 * @param out_content Destination buffer (must not be NULL)
 * @return NULL on success; ERR_NOT_FOUND if the profile has no
 *         script; wrapped Git or allocation error otherwise
 */
error_t *bootstrap_read(
    git_repository *repo,
    const char *profile,
    buffer_t *out_content
);

/**
 * Extract a profile's .bootstrap script to a secure temporary file
 * with mode 0700.
 *
 * On success, *out_temp_path is a heap-allocated path the caller
 * must unlink() and free() when finished. On failure, no temp file
 * is left behind — the implementation cleans up any partial state.
 *
 * Script content is validated via bootstrap_validate() before being
 * written to disk, so a bad shebang never produces a stale temp file.
 *
 * Used by the edit workflow: an external editor operates on the
 * extracted file, and the edited content is read back for commit.
 * The orchestrator in utils/bootstrap.c does NOT use this — it
 * manages its own temp file lifecycle so the exec-then-unlink
 * window is tight around the actual subprocess call.
 *
 * @param repo          Open Git repository (must not be NULL)
 * @param profile       Profile branch name (must not be NULL)
 * @param out_temp_path Receives a heap-allocated path (must not be NULL)
 * @return NULL on success; ERR_NOT_FOUND if the profile has no
 *         script; wrapped error on validation, Git, allocation, or
 *         filesystem failure
 */
error_t *bootstrap_extract_to_temp(
    git_repository *repo,
    const char *profile,
    char **out_temp_path
);

/**
 * Validate bootstrap script content — check for a shebang line.
 *
 * Rejects any of:
 *   - content shorter than 3 bytes,
 *   - content not beginning with "#!",
 *   - a shebang with no interpreter path after the bang,
 *   - an interpreter path that is not absolute (does not start `/`).
 *
 * Content is inspected bytewise; size is authoritative (the buffer
 * is not required to be NUL-terminated).
 *
 * @param content Script bytes (must not be NULL when size > 0)
 * @param size    Number of bytes in content
 * @return NULL if valid; ERR_INVALID_ARG with a descriptive message
 *         otherwise
 */
error_t *bootstrap_validate(const unsigned char *content, size_t size);

#endif /* DOTTA_BOOTSTRAP_H */
