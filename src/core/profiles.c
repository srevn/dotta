/**
 * profiles.c - Profile management implementation
 */

#include "core/profiles.h"

#include <ctype.h>
#include <git2.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/state.h"
#include "sys/gitops.h"

/**
 * Check if profile exists
 */
bool profile_exists(git_repository *repo, const char *profile) {
    if (!repo || !profile) {
        return false;
    }

    bool exists = false;
    error_t *err = gitops_branch_exists(repo, profile, &exists);
    if (err) {
        error_free(err);
        return false;
    }

    return exists;
}

/**
 * Match hierarchical profiles from available branches
 *
 * Finds base match (exact prefix) and sub-matches (prefix/variant, one level
 * deep only). Sub-matches are sorted alphabetically for deterministic ordering.
 *
 * @param available Available branch names to match against
 * @param prefix Prefix to match (e.g., "darwin", "hosts/myhost")
 * @param out Output array to append matches to (base first, then sorted subs)
 * @return Error or NULL on success
 */
static error_t *match_hierarchical_profiles(
    const string_array_t *available,
    const char *prefix,
    string_array_t *out
) {
    error_t *err = NULL;
    size_t prefix_len = strlen(prefix);

    string_array_t *sub_profiles = string_array_new(0);
    if (!sub_profiles) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate sub-profiles array"
        );
    }

    for (size_t i = 0; i < available->count; i++) {
        const char *profile = available->items[i];

        /* Check if branch starts with prefix */
        if (!str_starts_with(profile, prefix)) {
            continue;
        }

        const char *suffix = profile + prefix_len;

        if (suffix[0] == '\0') {
            /* Exact match: base profile — add directly to output */
            err = string_array_push(out, profile);
            if (err) {
                goto cleanup;
            }
        } else if (suffix[0] == '/') {
            const char *variant = suffix + 1;
            /* One level deep only: non-empty variant with no further '/' */
            if (variant[0] != '\0' && strchr(variant, '/') == NULL) {
                err = string_array_push(sub_profiles, profile);
                if (err) {
                    goto cleanup;
                }
            }
        }
    }

    /* Sort sub-profiles alphabetically for deterministic ordering */
    if (sub_profiles->count > 1) {
        string_array_sort(sub_profiles);
    }

    /* Append sorted sub-profiles after base */
    for (size_t i = 0; i < sub_profiles->count; i++) {
        err = string_array_push(out, sub_profiles->items[i]);
        if (err) goto cleanup;
    }

cleanup:
    string_array_free(sub_profiles);

    return err;
}

/**
 * Detect matching profile names from a list of available branches
 */
error_t *profile_detect(
    const string_array_t *available_branches,
    string_array_t **out_profiles
) {
    CHECK_NULL(available_branches);
    CHECK_NULL(out_profiles);

    error_t *err = NULL;
    char *os_name = NULL;

    string_array_t *profiles = string_array_new(0);
    if (!profiles) {
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }

    /* 1. "global" — always first if present */
    if (string_array_contains(available_branches, "global")) {
        err = string_array_push(profiles, "global");
        if (err) goto cleanup;
    }

    /* 2. OS-specific profiles (darwin, linux, freebsd, ...) */
    struct utsname uts;
    if (uname(&uts) == 0) {
        os_name = strdup(uts.sysname);
        if (!os_name) {
            err = ERROR(ERR_MEMORY, "Failed to allocate OS name");
            goto cleanup;
        }

        /* Safe tolower: cast to unsigned char to avoid UB with negative values */
        for (char *p = os_name; *p; p++) {
            *p = (char) tolower((unsigned char) *p);
        }

        err = match_hierarchical_profiles(available_branches, os_name, profiles);
        if (err) {
            /* Non-fatal: skip OS profiles if detection fails */
            error_free(err);
            err = NULL;
        }
    }
    /* Non-fatal: skip OS profiles if uname() fails */

    /* 3. Host-specific profiles (hosts/<hostname>, hosts/<hostname>/variant) */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1] = '\0';

        char host_prefix[DOTTA_REFNAME_MAX];
        int ret = snprintf(host_prefix, sizeof(host_prefix), "hosts/%s", hostname);
        if (ret >= 0 && (size_t) ret < sizeof(host_prefix)) {
            err = match_hierarchical_profiles(available_branches, host_prefix, profiles);
            if (err) {
                /* Non-fatal: skip host profiles if detection fails */
                error_free(err);
                err = NULL;
            }
        }
    }
    /* Non-fatal: continue if gethostname() fails */

    /* Success */
    free(os_name);
    *out_profiles = profiles;

    return NULL;

cleanup:
    free(os_name);
    string_array_free(profiles);

    return err;
}

/**
 * Get custom deployment prefixes for named profiles
 *
 * Queries the state database for custom prefixes. Only profiles with
 * non-NULL custom prefixes are included in the output.
 */
error_t *profile_get_custom_prefixes(
    git_repository *repo,
    const state_t *state,
    const string_array_t *profiles,
    string_array_t **out_prefixes
) {
    CHECK_NULL(out_prefixes);

    error_t *err = NULL;
    string_array_t *prefixes = string_array_new(0);
    if (!prefixes) {
        return ERROR(ERR_MEMORY, "Failed to allocate prefixes array");
    }

    /* Use provided state or load internally */
    state_t *local_state = NULL;
    const state_t *effective_state = state;

    if (!effective_state) {
        err = state_load(repo, &local_state);
        if (err) {
            /* State load failure is non-fatal — no custom prefixes available */
            error_free(err);
            *out_prefixes = prefixes;
            return NULL;
        }
        if (!local_state) {
            *out_prefixes = prefixes;
            return NULL;
        }
        effective_state = local_state;
    }

    hashmap_t *prefix_map = NULL;
    err = state_get_prefix_map(effective_state, &prefix_map);
    if (err) {
        state_free(local_state);
        string_array_free(prefixes);
        return error_wrap(err, "Failed to get custom prefix map");
    }

    if (profiles) {
        for (size_t i = 0; i < profiles->count; i++) {
            const char *prefix = (const char *) hashmap_get(prefix_map, profiles->items[i]);
            if (prefix) {
                err = string_array_push(prefixes, prefix);
                if (err) break;
            }
        }
    } else {
        hashmap_iter_t iter;
        hashmap_iter_init(&iter, prefix_map);
        void *value = NULL;
        while (hashmap_iter_next(&iter, NULL, &value)) {
            err = string_array_push(prefixes, (const char *) value);
            if (err) break;
        }
    }

    if (err) {
        hashmap_free(prefix_map, free);
        state_free(local_state);
        string_array_free(prefixes);
        return error_wrap(err, "Failed to collect custom prefix");
    }

    hashmap_free(prefix_map, free);
    state_free(local_state);

    *out_prefixes = prefixes;
    return NULL;
}

/**
 * Validate state profiles and filter out non-existent ones
 *
 * Checks that all profiles listed in state exist as local branches.
 * Warns about missing profiles and filters them out.
 *
 * @param repo Repository (must not be NULL)
 * @param state_profiles Profiles from state (must not be NULL)
 * @param out_valid_profiles Valid profiles (caller must free)
 * @param out_missing_profiles Missing profiles (caller must free, can be NULL)
 * @return Error or NULL on success
 */
static error_t *validate_state_profiles(
    git_repository *repo,
    const string_array_t *state_profiles,
    string_array_t **out_valid_profiles,
    string_array_t **out_missing_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(state_profiles);
    CHECK_NULL(out_valid_profiles);

    error_t *err = NULL;
    string_array_t *valid = NULL;
    string_array_t *missing = NULL;

    valid = string_array_new(0);
    if (!valid) {
        err = ERROR(
            ERR_MEMORY, "Failed to allocate valid profiles array"
        );
        goto cleanup;
    }

    if (out_missing_profiles) {
        missing = string_array_new(0);
        if (!missing) {
            err = ERROR(
                ERR_MEMORY, "Failed to allocate missing profiles array"
            );
            goto cleanup;
        }
    }

    /* Check each profile */
    for (size_t i = 0; i < state_profiles->count; i++) {
        const char *profile = state_profiles->items[i];

        if (profile_exists(repo, profile)) {
            err = string_array_push(valid, profile);
            if (err) goto cleanup;
        } else {
            /* Profile doesn't exist */
            if (missing) {
                err = string_array_push(missing, profile);
                if (err) goto cleanup;
            }
        }
    }

    /* Success */
    *out_valid_profiles = valid;
    if (out_missing_profiles) *out_missing_profiles = missing;

    return NULL;

cleanup:
    string_array_free(valid);
    string_array_free(missing);

    return err;
}

/**
 * Resolve enabled profile names from state database
 *
 * Lightweight name-only resolution — no Git ref resolution or tree loading.
 * Loads state, validates that referenced profiles exist as
 * branches, and returns the validated names. Warns on stderr about
 * missing profiles.
 *
 * When state is non-NULL, reads from the provided handle without taking
 * ownership. When NULL, opens and closes a private read-only state handle.
 *
 * @param repo Repository (must not be NULL)
 * @param state State handle for connection reuse (NULL = load internally)
 * @param out Validated profile names (must not be NULL, caller frees)
 * @return Error (ERR_NOT_FOUND if no enabled profiles) or NULL on success
 */
error_t *profile_resolve_enabled(
    git_repository *repo,
    const state_t *state,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    error_t *err = NULL;
    state_t *local_state = NULL;
    const state_t *effective_state = state;
    string_array_t *state_profiles = NULL;
    string_array_t *valid_profiles = NULL;
    string_array_t *missing_profiles = NULL;

    /* Use provided state or load internally */
    if (!effective_state) {
        err = state_load(repo, &local_state);
        if (err) {
            return error_wrap(
                err, "Failed to load state for profile resolution"
            );
        }
        effective_state = local_state;
    }

    /* Get profile names from state */
    err = state_get_profiles(effective_state, &state_profiles);
    if (err) {
        error_free(err);
        state_free(local_state);
        return ERROR(ERR_NOT_FOUND, "No enabled profiles found");
    }

    if (!state_profiles || state_profiles->count == 0) {
        string_array_free(state_profiles);
        state_free(local_state);
        return ERROR(ERR_NOT_FOUND, "No enabled profiles found");
    }

    /* Validate: check which profiles still exist as branches */
    err = validate_state_profiles(
        repo, state_profiles, &valid_profiles, &missing_profiles
    );
    if (err) {
        err = error_wrap(err, "Failed to validate state profiles");
        goto cleanup;
    }

    /* Warn about missing profiles (diagnostic message)
     *
     * Note: We use fprintf(stderr) here because this is a low-level core module
     * without access to an output_ctx_t. This is consistent with other core
     * modules (deploy.c, workspace.c) that also write diagnostic warnings to stderr.
     */
    if (missing_profiles && missing_profiles->count > 0) {
        fprintf(
            stderr, "Warning: State references non-existent profiles:\n"
        );
        for (size_t i = 0; i < missing_profiles->count; i++) {
            fprintf(stderr, "  • %s\n", missing_profiles->items[i]);
        }
        fprintf(
            stderr, "\nHint: Run 'dotta profile validate' to fix state,\n"
            "      or 'dotta profile enable <name>' to enable profiles\n\n"
        );
    }
    string_array_free(missing_profiles);
    missing_profiles = NULL;

    /* No valid profiles after filtering */
    if (valid_profiles->count == 0) {
        string_array_free(valid_profiles);
        string_array_free(state_profiles);
        state_free(local_state);
        return ERROR(ERR_NOT_FOUND, "No enabled profiles found");
    }

    /* Success */
    *out = valid_profiles;
    state_free(local_state);
    string_array_free(state_profiles);

    return NULL;

cleanup:
    string_array_free(valid_profiles);
    string_array_free(missing_profiles);
    string_array_free(state_profiles);
    state_free(local_state);

    return err;
}

/**
 * Resolve CLI profile names for operation filtering
 *
 * Lightweight validation: checks branch existence without resolving
 * Git refs or loading profile objects.
 */
error_t *profile_resolve_filter(
    git_repository *repo,
    char **cli_profiles,
    size_t cli_count,
    bool strict_mode,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(cli_profiles);
    CHECK_NULL(out);

    if (cli_count == 0) {
        return ERROR(
            ERR_INVALID_ARG, "CLI profile count cannot be zero"
        );
    }

    error_t *err = NULL;
    string_array_t *validated = string_array_new(cli_count);
    if (!validated) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate validated profiles"
        );
    }

    for (size_t i = 0; i < cli_count; i++) {
        if (profile_exists(repo, cli_profiles[i])) {
            err = string_array_push(validated, cli_profiles[i]);
            if (err) {
                string_array_free(validated);
                return error_wrap(
                    err, "Failed to add profile '%s'", cli_profiles[i]
                );
            }
        } else if (strict_mode) {
            string_array_free(validated);
            return ERROR(
                ERR_NOT_FOUND, "Profile not found: %s\n"
                "Hint: Run 'dotta profile list' to see available profiles",
                cli_profiles[i]
            );
        }
        /* Non-strict: skip non-existent profiles silently */
    }

    *out = validated;
    return NULL;
}

/**
 * Validate that filter profiles are enabled
 *
 * Ensures CLI filter only references profiles that are actually enabled
 * in the workspace.
 */
error_t *profile_validate_filter(
    const string_array_t *enabled_profiles,
    const string_array_t *filter
) {
    CHECK_NULL(enabled_profiles);

    /* NULL filter is valid (no filter) */
    if (!filter) {
        return NULL;
    }

    /* Check each filter profile is in workspace */
    for (size_t i = 0; i < filter->count; i++) {
        const char *filter_name = filter->items[i];
        bool found = false;

        for (size_t j = 0; j < enabled_profiles->count; j++) {
            if (strcmp(enabled_profiles->items[j], filter_name) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            return ERROR(
                ERR_INVALID_ARG, "Profile '%s' is not enabled\n"
                "Hint: Run 'dotta profile enable %s' first",
                filter_name, filter_name
            );
        }
    }

    return NULL;
}

/**
 * Check if profile name matches operation filter
 *
 * Helper for filtering operations by profile. NULL filter matches all,
 * NULL name never matches.
 */
bool profile_filter_matches(
    const char *profile,
    const string_array_t *filter
) {
    /* NULL profile never matches (defensive) */
    if (!profile) {
        return false;
    }

    /* NULL filter matches all (no filter = match all) */
    if (!filter) {
        return true;
    }

    /* Check if profile is in filter list */
    for (size_t i = 0; i < filter->count; i++) {
        if (strcmp(profile, filter->items[i]) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * List all local profile branch names (lightweight, no ref resolution)
 */
error_t *profile_list_all_local(
    git_repository *repo,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (err) return err;

    string_array_remove_value(branches, "dotta-worktree");

    *out = branches;
    return NULL;
}

/**
 * Tree walk callback data
 */
struct walk_data {
    string_array_t *paths;
    error_t *error;
};

/**
 * Tree walk callback
 */
static int tree_walk_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct walk_data *data = (struct walk_data *) payload;

    /* Only process blobs (files) */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* Build full path */
    const char *name = git_tree_entry_name(entry);
    char full_path[1024];
    int ret;

    if (root && root[0] != '\0') {
        ret = snprintf(
            full_path, sizeof(full_path), "%s%s",
            root, name
        );
    } else {
        ret = snprintf(
            full_path, sizeof(full_path), "%s",
            name
        );
    }

    /* Check for truncation */
    if (ret < 0 || (size_t) ret >= sizeof(full_path)) {
        data->error = ERROR(
            ERR_INTERNAL, "Path exceeds maximum length: %s%s",
            root ? root : "", name
        );
        return -1;
    }

    /* Skip repository metadata files */
    if (strcmp(full_path, ".dottaignore") == 0 ||
        strcmp(full_path, ".bootstrap") == 0 ||
        strcmp(full_path, ".gitignore") == 0 ||
        strcmp(full_path, "README.md") == 0 ||
        strcmp(full_path, "README") == 0 ||
        str_starts_with(full_path, ".git/") ||
        str_starts_with(full_path, ".dotta/")) {
        return 0;
    }

    /* Add to array */
    error_t *err = string_array_push(data->paths, full_path);
    if (err) {
        data->error = err;
        return -1;  /* Stop walk */
    }

    return 0;
}

/**
 * List deployable files in a Git tree
 *
 * Walks the tree, filters metadata paths, and returns storage paths.
 * This is the lightweight primitive for "files in a branch" — takes
 * a pre-loaded tree and returns storage paths.
 *
 * @param tree Git tree to walk (must not be NULL)
 * @param out String array of storage paths (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
static error_t *profile_list_tree_files(
    git_tree *tree,
    string_array_t **out
) {
    struct walk_data data = {
        .paths = string_array_new(0),
        .error = NULL
    };

    if (!data.paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate paths array");
    }

    error_t *err = gitops_tree_walk(tree, tree_walk_callback, &data);
    if (err || data.error) {
        string_array_free(data.paths);
        return err ? err : data.error;
    }

    *out = data.paths;
    return NULL;
}

/**
 * List files in profile
 */
error_t *profile_list_files(
    git_repository *repo,
    const char *profile,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for profile '%s'", profile
        );
    }

    err = profile_list_tree_files(tree, out);
    git_tree_free(tree);
    return err;
}

/**
 * Check if profile contains any custom/ files
 *
 * Uses direct tree lookup instead of full tree walk for O(log k) performance
 * where k is the number of top-level entries (typically <20).
 */
error_t *profile_has_custom_files(
    git_repository *repo,
    const char *profile,
    bool *out_has_custom
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out_has_custom);

    *out_has_custom = false;

    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for profile '%s'", profile
        );
    }

    /* Check for custom/ directory using O(log k) lookup.
     * git_tree_entry_byname returns a pointer owned by the tree —
     * must read before git_tree_free. */
    const git_tree_entry *entry = git_tree_entry_byname(tree, "custom");
    if (entry) {
        *out_has_custom = (git_tree_entry_type(entry) == GIT_OBJECT_TREE);
    }

    git_tree_free(tree);
    return NULL;
}

/**
 * Context for file_index_callback
 */
struct file_index_ctx {
    hashmap_t *index;          /* Target hashmap: storage_path -> string_array_t* */
    const char *branch_name;   /* Current branch (borrowed from all_branches) */
    error_t *error;            /* Error propagation */
    bool fatal;                /* If true, error is unrecoverable (propagate to caller) */
};

/**
 * Tree walk callback that populates the file index directly
 *
 * Inserts each file's storage path into the index hashmap during the walk,
 * eliminating the intermediate string_array_t that the old approach needed
 * per branch (each path was strdup'd into the array, strdup'd again into
 * the hashmap, then the array copy was freed).
 */
static int file_index_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct file_index_ctx *ctx = (struct file_index_ctx *) payload;

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    const char *name = git_tree_entry_name(entry);
    char full_path[1024];
    int ret;

    if (root && root[0] != '\0') {
        ret = snprintf(
            full_path, sizeof(full_path), "%s%s", root, name
        );
    } else {
        ret = snprintf(
            full_path, sizeof(full_path), "%s", name
        );
    }

    if (ret < 0 || (size_t) ret >= sizeof(full_path)) {
        ctx->error = ERROR(
            ERR_INTERNAL, "Path exceeds maximum length: %s%s",
            root ? root : "", name
        );
        return -1;
    }

    if (strcmp(full_path, ".dottaignore") == 0 ||
        strcmp(full_path, ".bootstrap") == 0 ||
        strcmp(full_path, ".gitignore") == 0 ||
        strcmp(full_path, "README.md") == 0 ||
        strcmp(full_path, "README") == 0 ||
        str_starts_with(full_path, ".git/") ||
        str_starts_with(full_path, ".dotta/")) {
        return 0;
    }

    /* Get or create profile list for this path */
    string_array_t *profiles = hashmap_get(ctx->index, full_path);
    if (!profiles) {
        profiles = string_array_new(0);
        if (!profiles) {
            ctx->error = ERROR(
                ERR_MEMORY, "Failed to create profile list for file"
            );
            ctx->fatal = true;
            return -1;
        }

        error_t *err = hashmap_set(ctx->index, full_path, profiles);
        if (err) {
            string_array_free(profiles);
            ctx->error = error_wrap(err, "Failed to index file");
            ctx->fatal = true;
            return -1;
        }
    }

    /* Add this branch to the list (non-fatal on failure) */
    error_t *err = string_array_push(profiles, ctx->branch_name);
    if (err) {
        error_free(err);
    }

    return 0;
}

/**
 * Build inverted index of all files across profiles
 *
 * Walks each branch tree directly into a hashmap that maps storage paths
 * to lists of profile names. Uses gitops_load_branch_tree for direct tree
 * loading, and populates the hashmap
 * during the tree walk to eliminate intermediate string arrays.
 *
 * Complexity: O(M×P) where M = profile count, P = avg files per profile.
 * Lookups are then O(1) instead of O(M×GitOps).
 */
error_t *profile_build_file_index(
    git_repository *repo,
    const char *exclude_profile,
    hashmap_t **out_index
) {
    CHECK_NULL(repo);
    CHECK_NULL(out_index);

    error_t *err = NULL;
    hashmap_t *index = NULL;
    string_array_t *all_branches = NULL;

    /* Create index hashmap */
    index = hashmap_create(256);  /* Reasonable initial size */
    if (!index) {
        err = ERROR(ERR_MEMORY, "Failed to create profile file index");
        goto cleanup;
    }

    /* Get all branches */
    err = gitops_list_branches(repo, &all_branches);
    if (err) {
        err = error_wrap(err, "Failed to list branches");
        goto cleanup;
    }

    /* Load each profile once and index its files */
    for (size_t i = 0; i < all_branches->count; i++) {
        const char *branch_name = all_branches->items[i];

        /* Skip excluded profile and dotta-worktree */
        if (strcmp(branch_name, "dotta-worktree") == 0) {
            continue;
        }

        if (exclude_profile && strcmp(branch_name, exclude_profile) == 0) {
            continue;
        }

        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, branch_name, &tree, NULL);
        if (err) {
            error_free(err);
            err = NULL;
            continue;  /* Non-fatal: skip this profile */
        }

        struct file_index_ctx ctx = {
            .index       = index,
            .branch_name = branch_name,
            .error       = NULL,
            .fatal       = false
        };

        err = gitops_tree_walk(tree, file_index_callback, &ctx);
        git_tree_free(tree);

        if (ctx.fatal) {
            error_free(err);
            err = ctx.error;
            goto cleanup;
        }

        if (err || ctx.error) {
            error_free(err);
            error_free(ctx.error);
            err = NULL;
            continue;
        }
    }

    /* Success */
    string_array_free(all_branches);
    *out_index = index;

    return NULL;

cleanup:
    string_array_free(all_branches);
    if (index) {
        /* Free index and all its arrays */
        hashmap_free(index, string_array_free_cb);
    }

    return err;
}

error_t *profile_discover_file(
    git_repository *repo,
    const state_t *state,
    const char *storage_path,
    bool enabled_only,
    string_array_t **out_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_profiles);

    error_t *err = NULL;
    *out_profiles = NULL;

    if (enabled_only) {
        /* Manifest fast path: O(1) via state DB index.
         * Returns the single owning profile (precedence already resolved).
         *
         * Reuse the caller's handle when provided; otherwise open a
         * short-lived read-only handle for this lookup. */
        state_t *local_state = NULL;
        const state_t *effective_state = state;

        if (!effective_state) {
            err = state_load(repo, &local_state);
            if (err) {
                return error_wrap(err, "Failed to load state for file discovery");
            }
            effective_state = local_state;
        }

        state_file_entry_t *entry = NULL;
        err = state_get_file_by_storage(effective_state, storage_path, &entry);

        if (err) {
            state_free(local_state);
            if (error_code(err) == ERR_NOT_FOUND) {
                error_free(err);
                return ERROR(
                    ERR_NOT_FOUND, "File '%s' not found in enabled profiles",
                    storage_path
                );
            }
            return err;
        }

        string_array_t *profiles = string_array_new(0);
        if (!profiles) {
            state_free_entry(entry);
            state_free(local_state);
            return ERROR(ERR_MEMORY, "Failed to allocate profile array");
        }

        err = string_array_push(profiles, entry->profile);
        state_free_entry(entry);
        state_free(local_state);

        if (err) {
            string_array_free(profiles);
            return err;
        }

        *out_profiles = profiles;

        return NULL;
    }

    /* Targeted branch scan: O(M×D) where D = path depth in tree.
     * Checks each branch for the specific file instead of building the */
    string_array_t *all_branches = NULL;
    err = gitops_list_branches(repo, &all_branches);
    if (err) {
        return error_wrap(err, "Failed to list branches for file discovery");
    }

    string_array_t *result = string_array_new(0);
    if (!result) {
        string_array_free(all_branches);
        return ERROR(ERR_MEMORY, "Failed to allocate result array");
    }

    for (size_t i = 0; i < all_branches->count; i++) {
        const char *branch = all_branches->items[i];

        if (strcmp(branch, "dotta-worktree") == 0) {
            continue;
        }

        char refname[DOTTA_REFNAME_MAX];
        err = gitops_build_refname(
            refname, sizeof(refname), "refs/heads/%s", branch
        );
        if (err) {
            error_free(err);
            err = NULL;
            continue;
        }

        git_tree *tree = NULL;
        err = gitops_load_tree(repo, refname, &tree);
        if (err) {
            error_free(err);
            err = NULL;
            continue;
        }

        /* O(D) targeted lookup instead of full tree walk */
        git_tree_entry *found = NULL;
        int rc = git_tree_entry_bypath(&found, tree, storage_path);
        git_tree_free(tree);

        if (rc == 0) {
            git_tree_entry_free(found);
            err = string_array_push(result, branch);
            if (err) {
                error_free(err);
                err = NULL;
            }
        }
    }

    string_array_free(all_branches);

    if (result->count == 0) {
        string_array_free(result);
        return ERROR(
            ERR_NOT_FOUND, "File '%s' not found in any profile",
            storage_path
        );
    }

    *out_profiles = result;

    return NULL;
}
