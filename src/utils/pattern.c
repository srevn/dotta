/**
 * pattern.c - Auto-encrypt pattern matching implementation
 */

#include "utils/pattern.h"

#include <git2.h>
#include <string.h>

#include "base/error.h"
#include "utils/config.h"
#include "utils/string.h"

error_t *encrypt_should_auto_encrypt(
    const dotta_config_t *config,
    const char *storage_path,
    bool *out_matches
) {
    CHECK_NULL(config);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_matches);

    /* Default: no match */
    *out_matches = false;

    /* If encryption disabled, never auto-encrypt */
    if (!config->encryption_enabled) {
        return NULL;
    }

    /* If no patterns configured, never auto-encrypt */
    if (!config->auto_encrypt_patterns || config->auto_encrypt_pattern_count == 0) {
        return NULL;
    }

    /* Strip "home/" or "root/" prefix for pattern matching
     * This allows patterns like ".ssh/id_*" to match "home/.ssh/id_rsa"
     * without requiring users to write "home/.ssh/id_*" */
    const char *path_for_matching = storage_path;

    if (str_starts_with(storage_path, "home/")) {
        path_for_matching = storage_path + 5;  /* Skip "home/" */
    } else if (str_starts_with(storage_path, "root/")) {
        path_for_matching = storage_path + 5;  /* Skip "root/" */
    }

    /* Create pathspec from patterns */
    git_strarray pathspec_array = {
        .strings = (char **)config->auto_encrypt_patterns,
        .count = config->auto_encrypt_pattern_count
    };

    git_pathspec *pathspec = NULL;
    int git_err = git_pathspec_new(&pathspec, &pathspec_array);
    if (git_err < 0) {
        const git_error *err = git_error_last();
        return ERROR(ERR_GIT, "Failed to create pathspec from patterns: %s",
                     err ? err->message : "unknown error");
    }

    /* Test if path matches any pattern using gitignore semantics */
    int match_result = git_pathspec_matches_path(
        pathspec,
        GIT_PATHSPEC_DEFAULT,
        path_for_matching
    );

    git_pathspec_free(pathspec);

    *out_matches = (match_result == 1);
    return NULL;
}
