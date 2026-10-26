/**
 * policy.c - Centralized encryption policy decision logic
 *
 * Implements the single source of truth for encryption decisions. The compiled
 * auto-encrypt ruleset lives on the config handle (see include/config.h); policy
 * calls read it directly and never own or free it.
 */

#include "core/policy.h"

#include <config.h>

#include "base/error.h"
#include "base/gitignore.h"
#include "infra/label.h"

/**
 * Check if file path matches auto-encrypt patterns
 *
 * Tests storage path against the config's compiled auto-encrypt ruleset. The
 * list is a *selector*, not an exclusion: the last rule that reaches the path —
 * matching it or any directory above it — decides, so a `!` beneath a directory
 * rule stands and a later directory rule outranks an earlier exception
 * (base/gitignore.h). `.dottaignore` reads the other program, where an excluded
 * directory is final; nothing here walks a tree for a barrier to prune.
 *
 * Full gitignore semantics (`!` negation, directory-only, anchoring, `**` recursive
 * globs) via base/gitignore. The storage-path prefix (`home/`, `root/`, `custom/`)
 * is stripped before matching, so users write `.ssh/id_*` rather than
 * `home/.ssh/id_*`; `.ssh/id_*` is anchored (no match under `backup/`), `*.key`
 * matches by basename, `secrets/` matches by directory walk-up.
 *
 * The list is compiled at load whether or not encryption is enabled, so the switch
 * is read here: priority 4 is the one priority it gates (the header says why 1
 * and 3 answer without it), and this is the one reader both of 4's callers share.
 *
 * Never fails. Returns false when config is NULL, encryption is disabled,
 * storage_path is NULL, no rule matches — an absent list has none — or the winning
 * rule is a negation.
 *
 * @param config Configuration (can be NULL)
 * @param storage_path File path in profile (e.g., "home/.bashrc")
 * @return true if path matches an auto-encrypt rule, false otherwise
 */
static bool encryption_policy_matches_auto_patterns(
    const config_t *config,
    const char *storage_path
) {
    if (!config || !config->encryption_enabled || !storage_path) {
        return false;
    }

    /* Strip storage prefix so patterns like ".ssh/id_*" match "home/.ssh/id_rsa"
     * without forcing users to write "home/" in config. */
    const char *path_for_matching = label_tail(storage_path);

    /* Encryption applies to files, not directories — is_dir is always false.
     * Gitignore's last-match-wins with negation support is what the user actually
     * wants: `*.key` + `!public.key` correctly excludes `public.key` from
     * auto-encryption. */
    return gitignore_is_selected(
        config->auto_encrypt_ruleset, path_for_matching, false
    );
}

error_t encryption_policy_should_encrypt(
    const config_t *config,
    const char *storage_path,
    encryption_request_t request,
    bool previously_encrypted,
    bool *out_should_encrypt
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out_should_encrypt);

    /* Default: no encryption (safe default) */
    *out_should_encrypt = false;

    /* Priority 1: Explicit --encrypt flag wins (highest priority) */
    if (request == ENCRYPTION_REQUEST_ENCRYPT) {
        *out_should_encrypt = true;
        return NULL;
    }

    /* Priority 2: Explicit --no-encrypt keeps a path out of the auto-encrypt
     * patterns' reach — that is the whole of its job, and what its help says.
     *
     * It is not a declassification verb. A file the profile holds sealed is not
     * a pattern's doing, and storing it as plaintext would put the secret into
     * the branch, into its history, and into every clone that pulls it — with
     * no way to take it back and nothing on screen to say it happened. The two
     * facts together are a conflict, not a race for precedence, so the flag is
     * refused: the user is told which fact stood and what to do instead.
     *
     * Declassifying is remove-then-add: with no prior blob there is no seal,
     * priority 3 has nothing to say, and the file is stored plaintext. */
    if (request == ENCRYPTION_REQUEST_PLAINTEXT) {
        if (previously_encrypted) {
            return error_create(
                ERR_VALIDATION, "Cannot store '%s' as plaintext: the profile holds it "
                "encrypted, and --no-encrypt does not decrypt content; a path "
                "removed from the profile and added again with --no-encrypt is "
                "stored plaintext", storage_path
            );
        }

        *out_should_encrypt = false;
        return NULL;
    }

    /* Priority 3: Maintain previous encryption state.
     *
     * Source: the seal the profile holds at the name, asked by the caller — its
     * stamp or its bytes, false where no blob stands (core/profiles.h
     * profile_sealed) — and read here as a pure bool, with no I/O and no
     * allocation. Important for workflows like:
     *   1. dotta add --encrypt file
     *   2. ... modify file on disk ...
     *   3. dotta update file  (should stay encrypted)
     */
    if (previously_encrypted) {
        *out_should_encrypt = true;
        return NULL;
    }

    /* Priority 4: Check auto-encrypt patterns.
     *
     * Pattern matching is pure computation on the pre-compiled ruleset; it cannot
     * fail. An inactive policy (no config, disabled, or no patterns) is treated
     * as a non-match. */
    *out_should_encrypt =
        encryption_policy_matches_auto_patterns(config, storage_path);
    return NULL;
}

bool encryption_policy_violation(
    const config_t *config,
    const char *storage_path,
    path_type_t type,
    bool encrypted
) {
    /* Only content-bearing kinds can violate: a symlink's blob is its target
     * path and a directory row carries no blob — neither has an encryption state
     * to be missing (see the header for the design rationale). */
    if (type != PATH_TYPE_FILE && type != PATH_TYPE_EXECUTABLE) {
        return false;
    }

    /* Only plaintext blobs can violate the auto-encrypt policy: an encrypted
     * blob satisfies the intent whatever its cipher version — the caller's bool
     * collapses ENCRYPTED and UNSUPPORTED_VERSION onto true, and both carry intent
     * (see the header). */
    if (encrypted) {
        return false;
    }

    /* encryption_policy_matches_auto_patterns is NULL-safe and pure. */
    return encryption_policy_matches_auto_patterns(config, storage_path);
}
