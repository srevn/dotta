/**
 * profiles.c - Profile management implementation
 */

#include "core/profiles.h"

#include <ctype.h>
#include <git2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/state.h"
#include "infra/path.h"
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
        const char *profile_name = available->items[i];

        /* Check if branch starts with prefix */
        if (!str_starts_with(profile_name, prefix)) {
            continue;
        }

        const char *suffix = profile_name + prefix_len;

        if (suffix[0] == '\0') {
            /* Exact match: base profile — add directly to output */
            err = string_array_push(out, profile_name);
            if (err) {
                goto cleanup;
            }
        } else if (suffix[0] == '/') {
            const char *variant = suffix + 1;
            /* One level deep only: non-empty variant with no further '/' */
            if (variant[0] != '\0' && strchr(variant, '/') == NULL) {
                err = string_array_push(sub_profiles, profile_name);
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
        err = ERROR(ERR_MEMORY, "Failed to allocate valid profiles array");
        goto cleanup;
    }

    if (out_missing_profiles) {
        missing = string_array_new(0);
        if (!missing) {
            err = ERROR(ERR_MEMORY, "Failed to allocate missing profiles array");
            goto cleanup;
        }
    }

    /* Check each profile */
    for (size_t i = 0; i < state_profiles->count; i++) {
        const char *profile_name = state_profiles->items[i];

        if (profile_exists(repo, profile_name)) {
            err = string_array_push(valid, profile_name);
            if (err) goto cleanup;
        } else {
            /* Profile doesn't exist */
            if (missing) {
                err = string_array_push(missing, profile_name);
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
            return error_wrap(err, "Failed to load state for profile resolution");
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
        fprintf(stderr, "Warning: State references non-existent profiles:\n");
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
        return ERROR(ERR_INVALID_ARG, "CLI profile count cannot be zero");
    }

    error_t *err = NULL;
    string_array_t *validated = string_array_new(cli_count);
    if (!validated) {
        return ERROR(ERR_MEMORY, "Failed to allocate validated profiles");
    }

    for (size_t i = 0; i < cli_count; i++) {
        if (profile_exists(repo, cli_profiles[i])) {
            err = string_array_push(validated, cli_profiles[i]);
            if (err) {
                string_array_free(validated);
                return error_wrap(err, "Failed to add profile '%s'", cli_profiles[i]);
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
    const char *profile_name,
    const string_array_t *filter
) {
    /* NULL name never matches (defensive) */
    if (!profile_name) {
        return false;
    }

    /* NULL filter matches all (no filter = match all) */
    if (!filter) {
        return true;
    }

    /* Check if name is in filter list */
    for (size_t i = 0; i < filter->count; i++) {
        if (strcmp(profile_name, filter->items[i]) == 0) {
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
 * Check if a storage path is profile metadata (not a user file)
 *
 * These are internal files maintained by dotta within each profile branch.
 * They should be excluded when listing user-deployable files.
 */
static bool profile_is_metadata_path(const char *path) {
    return strcmp(path, ".dottaignore") == 0 ||
           strcmp(path, ".bootstrap") == 0 ||
           strcmp(path, ".gitignore") == 0 ||
           strcmp(path, "README.md") == 0 ||
           strcmp(path, "README") == 0 ||
           str_starts_with(path, ".git/") ||
           str_starts_with(path, ".dotta/");
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
    if (profile_is_metadata_path(full_path)) {
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
static error_t *profile_list_tree_files(git_tree *tree, string_array_t **out) {
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
 * Context for manifest building callback
 *
 * Passed to gitops_tree_walk() to build manifest entries directly during
 * tree traversal, eliminating O(N×D) two-pass overhead. The callback
 * extracts identity fields from borrowed tree entries at O(1) per file.
 *
 * Memory ownership:
 * - manifest: borrowed, caller retains ownership
 * - path_map: borrowed, caller retains ownership
 * - custom_prefix: borrowed, can be NULL (used for path_from_storage only)
 * - error: owned by callback, caller must free on error
 */
struct manifest_build_ctx {
    manifest_t *manifest;       /* Target manifest (modified by callback) */
    size_t capacity;            /* Current entries capacity (updated on growth) */
    hashmap_t *path_map;        /* For O(1) dedup/override detection */
    const char *profile_name;   /* Profile name for entries and error messages */
    const char *custom_prefix;  /* For path_from_storage (can be NULL) */
    arena_t *arena;             /* Arena for string allocations (NULL = heap) */
    error_t *error;             /* Error propagation (set on failure) */
};

/**
 * Tree walk callback that builds manifest entries directly
 *
 * Performance optimization: Instead of collecting paths in pass 1 then
 * re-traversing via git_tree_entry_bypath() in pass 2 (O(N×D)), this
 * callback builds file_entry_t directly in O(N) time.
 *
 * Extracts identity fields (blob_oid, type, mode) from the borrowed tree
 * entry at the callback boundary — no git_tree_entry_dup needed, no opaque
 * handle stored on file_entry_t.
 *
 * Handles:
 * - Metadata file filtering (.dotta/, .bootstrap, etc.)
 * - Storage path to filesystem path conversion
 * - Profile precedence override (higher precedence wins)
 * - Array growth on demand
 * - File identity extraction from Git tree entry
 *
 * @param root Directory path within tree (empty string for root level)
 * @param entry Git tree entry (borrowed — valid for callback duration only)
 * @param payload Pointer to manifest_build_ctx
 * @return 0 to continue walk, -1 to stop on error
 */
static int manifest_build_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct manifest_build_ctx *ctx = (struct manifest_build_ctx *) payload;

    /* Only process blobs (files), skip directories */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* Build full storage path from root + entry name */
    const char *name = git_tree_entry_name(entry);
    char storage_path[1024];
    int ret;

    if (root && root[0] != '\0') {
        ret = snprintf(
            storage_path, sizeof(storage_path), "%s%s",
            root, name
        );
    } else {
        ret = snprintf(
            storage_path, sizeof(storage_path), "%s",
            name
        );
    }

    /* Check for path truncation */
    if (ret < 0 || (size_t) ret >= sizeof(storage_path)) {
        ctx->error = ERROR(
            ERR_INTERNAL, "Path exceeds maximum length: %s%s",
            root ? root : "", name
        );
        return -1;
    }

    /* Skip repository metadata files */
    if (profile_is_metadata_path(storage_path)) {
        return 0;
    }

    /* Convert storage path to filesystem path */
    char *filesystem_path = NULL;
    error_t *err = NULL;

    if (str_starts_with(storage_path, "custom/") && !ctx->custom_prefix) {
        /* Skip custom/ files when deployment prefix is unknown.
         *
         * Custom prefix is machine-specific configuration (e.g., /jails/proxy/root)
         * stored in the per-machine state database. During clone or when a profile is
         * enabled without --prefix, we can't resolve where these files belong on disk.
         */
        return 0;  /* Skip, continue walk */
    } else {
        char *heap_path = NULL;
        err = path_from_storage(storage_path, ctx->custom_prefix, &heap_path);
        if (err) {
            ctx->error = error_wrap(
                err, "Failed to convert path '%s' from profile '%s'",
                storage_path, ctx->profile_name
            );
            return -1;
        }
        if (ctx->arena) {
            filesystem_path = arena_strdup(ctx->arena, heap_path);
            free(heap_path);
            if (!filesystem_path) {
                ctx->error = ERROR(ERR_MEMORY, "Failed to arena-copy filesystem path");
                return -1;
            }
        } else {
            filesystem_path = heap_path;
        }
    }

    /* Check for existing entry (profile precedence override) */
    void *idx_ptr = hashmap_get(ctx->path_map, filesystem_path);

    if (idx_ptr) {
        /* Override existing entry (profile with higher precedence) */
        /*
         * Convert pointer back to index. We offset by 1 when storing to
         * distinguish NULL (not found) from index 0.
         * Safe because: indices are always << SIZE_MAX, uintptr_t can hold
         * any valid pointer value, and we never store actual pointers here.
         */
        size_t existing_idx = (size_t) (uintptr_t) idx_ptr - 1;

        /* Duplicate storage path */
        char *dup_storage_path = ctx->arena ? arena_strdup(ctx->arena, storage_path)
                                            : strdup(storage_path);
        if (!dup_storage_path) {
            if (!ctx->arena) free(filesystem_path);
            ctx->error = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
            return -1;
        }

        /* Free old resources — strings abandoned when arena-backed */
        if (!ctx->arena) {
            free(ctx->manifest->entries[existing_idx].storage_path);
            free(ctx->manifest->entries[existing_idx].filesystem_path);
        }

        /* Update with new values from higher-precedence profile */
        file_entry_t *override = &ctx->manifest->entries[existing_idx];
        override->storage_path = dup_storage_path;
        override->filesystem_path = filesystem_path;
        override->profile_name = ctx->profile_name;

        /* Extract identity from borrowed tree entry (blob_oid, type, mode).
         * The overriding profile may differ in filemode (e.g., executable bit). */
        git_oid_cpy(&override->blob_oid, git_tree_entry_id(entry));
        switch (git_tree_entry_filemode(entry)) {
            case GIT_FILEMODE_BLOB_EXECUTABLE:
                override->type = STATE_FILE_EXECUTABLE;
                override->mode = 0755;
                break;
            case GIT_FILEMODE_LINK:
                override->type = STATE_FILE_SYMLINK;
                override->mode = 0;
                break;
            default:
                override->type = STATE_FILE_REGULAR;
                override->mode = 0644;
                break;
        }

        /* Other VWD fields remain NULL/0 (not populated for Git-based manifests).
         * The existing entry already has these initialized from initial creation. */
    } else {
        /* Add new entry - grow array if needed */
        if (ctx->manifest->count >= ctx->capacity) {
            if (ctx->capacity > SIZE_MAX / 2) {
                if (!ctx->arena) free(filesystem_path);
                ctx->error = ERROR(ERR_INTERNAL, "Manifest capacity overflow");
                return -1;
            }
            size_t new_capacity = ctx->capacity * 2;

            file_entry_t *new_entries = realloc(
                ctx->manifest->entries,
                new_capacity * sizeof(file_entry_t)
            );
            if (!new_entries) {
                if (!ctx->arena) free(filesystem_path);
                ctx->error = ERROR(ERR_MEMORY, "Failed to grow manifest");
                return -1;
            }
            ctx->manifest->entries = new_entries;
            ctx->capacity = new_capacity;
        }

        /* Duplicate storage path */
        char *dup_storage_path = ctx->arena
            ? arena_strdup(ctx->arena, storage_path)
            : strdup(storage_path);
        if (!dup_storage_path) {
            if (!ctx->arena) free(filesystem_path);
            ctx->error = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
            return -1;
        }

        /* Initialize entry.
         *
         * realloc() does NOT zero new memory. Zero the whole slot first so
         * every VWD cache field starts clean; then overwrite the fields this
         * Git-built path actually sets. Deployment context fields (deployed_at,
         * stat_cache, encrypted, owner, group) remain zero — they are only
         * populated for state-built entries. */
        file_entry_t *new_entry = &ctx->manifest->entries[ctx->manifest->count];
        memset(new_entry, 0, sizeof(*new_entry));
        new_entry->storage_path = dup_storage_path;
        new_entry->filesystem_path = filesystem_path;
        new_entry->profile_name = ctx->profile_name;

        /* Extract identity from borrowed tree entry (blob_oid, type, mode) */
        git_oid_cpy(&new_entry->blob_oid, git_tree_entry_id(entry));
        switch (git_tree_entry_filemode(entry)) {
            case GIT_FILEMODE_BLOB_EXECUTABLE:
                new_entry->type = STATE_FILE_EXECUTABLE;
                new_entry->mode = 0755;
                break;
            case GIT_FILEMODE_LINK:
                new_entry->type = STATE_FILE_SYMLINK;
                new_entry->mode = 0;
                break;
            default:
                /* Should never happen (we filtered to blobs above) */
                new_entry->type = STATE_FILE_REGULAR;
                new_entry->mode = 0644;
                break;
        }

        /* Store index in hashmap (offset by 1 to distinguish from NULL) */
        err = hashmap_set(
            ctx->path_map, filesystem_path, (void *) (uintptr_t) (ctx->manifest->count + 1)
        );
        if (err) {
            /* Entry already added to manifest, but hashmap failed.
             * Clean up the entry (strings abandoned when arena-backed). */
            if (!ctx->arena) {
                free(new_entry->storage_path);
                free(new_entry->filesystem_path);
            }
            new_entry->storage_path = NULL;
            new_entry->filesystem_path = NULL;
            ctx->error = error_wrap(err, "Failed to update hashmap");
            return -1;
        }

        ctx->manifest->count++;
    }

    return 0;  /* Continue walk */
}

/**
 * List files in profile
 */
error_t *profile_list_files(
    git_repository *repo,
    const char *profile_name,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(out);

    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, profile_name, &tree, NULL);
    if (err) {
        return error_wrap(err, "Failed to load tree for profile '%s'", profile_name);
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
    const char *profile_name,
    bool *out_has_custom
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_has_custom);

    *out_has_custom = false;

    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, profile_name, &tree, NULL);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for profile '%s'",
            profile_name
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
 * Build manifest from profile names
 *
 * Performance: O(N) where N is total files across all profiles.
 * Uses manifest_build_callback for single-pass tree traversal.
 * One Git tree alive per iteration (loaded, walked, freed).
 */
error_t *profile_build_manifest(
    git_repository *repo,
    const string_array_t *profiles,
    const state_t *state,
    arena_t *arena,
    manifest_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    error_t *err = NULL;
    manifest_t *manifest = NULL;
    hashmap_t *path_map = NULL;
    hashmap_t *prefix_map = NULL;

    /* Load custom prefix map from state (internalized — callers no longer manage this) */
    if (state) {
        err = state_get_prefix_map(state, &prefix_map);
        if (err) {
            return error_wrap(err, "Failed to get custom prefix map");
        }
    }

    /* Allocate manifest */
    manifest = calloc(1, sizeof(manifest_t));
    if (!manifest) {
        err = ERROR(ERR_MEMORY, "Failed to allocate manifest");
        goto cleanup;
    }

    /* Allocate entries array */
    size_t capacity = 64;
    manifest->entries = calloc(capacity, sizeof(file_entry_t));
    if (!manifest->entries) {
        err = ERROR(ERR_MEMORY, "Failed to allocate manifest entries");
        goto cleanup;
    }
    manifest->count = 0;

    /*
     * Create hash map for O(1) duplicate detection
     * Maps: filesystem_path -> index in entries array
     *
     * Borrow keys when arena-backed (arena outlives hashmap).
     * In non-arena mode, manifest_free() frees entry strings before
     * the hashmap, so keys must be owned copies.
     */
    path_map = arena ? hashmap_borrow(128) : hashmap_create(128);
    if (!path_map) {
        err = ERROR(ERR_MEMORY, "Failed to create hashmap");
        goto cleanup;
    }

    /* Process each profile in order (later profiles override earlier) */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];

        /* Load tree for this profile (scoped to iteration) */
        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, profile, &tree, NULL);
        if (err) {
            err = error_wrap(
                err, "Failed to load tree for profile '%s'",
                profile
            );
            goto cleanup;
        }

        /* Build manifest entries via single-pass tree traversal
         *
         * The callback extracts identity fields (blob_oid, type, mode) from
         * borrowed tree entries, converts paths, handles precedence override,
         * and populates file_entry_t directly—all in O(N) time.
         *
         * profile_name borrows from caller's profiles array — must outlive manifest */
        struct manifest_build_ctx ctx = {
            .manifest      = manifest,
            .capacity      = capacity,
            .path_map      = path_map,
            .profile_name  = profile,
            .custom_prefix = prefix_map
                ? (const char *) hashmap_get(prefix_map, profile)
                : NULL,
            .arena         = arena,
            .error         = NULL
        };

        err = gitops_tree_walk(tree, manifest_build_callback, &ctx);
        git_tree_free(tree);

        if (err || ctx.error) {
            err = ctx.error ? ctx.error : err;
            err = error_wrap(
                err, "Failed to build manifest for profile '%s'",
                profile
            );
            goto cleanup;
        }

        /* Update capacity (may have grown during callback) */
        capacity = ctx.capacity;
    }

    /* prefix_map no longer needed — all per-profile lookups are done */
    hashmap_free(prefix_map, free);
    prefix_map = NULL;

    /* Success - transfer index ownership to manifest */
    manifest->index = path_map;
    manifest->arena_backed = (arena != NULL);
    *out = manifest;

    return NULL;

cleanup:
    hashmap_free(prefix_map, free);
    hashmap_free(path_map, NULL);
    if (err) manifest_free(manifest);

    return err;
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

    if (profile_is_metadata_path(full_path)) {
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

/**
 * Build manifest from a single Git tree
 *
 * Creates a manifest from a specific Git tree. This is used for historical diffs
 * where we need to build a manifest from a past commit's tree.
 *
 * @param tree Git tree to build manifest from (must not be NULL)
 * @param profile_name Profile name for entries (must not be NULL)
 * @param custom_prefix Custom prefix for custom/ paths (NULL for graceful degradation)
 * @param out Manifest (must not be NULL, caller must free with manifest_free)
 * @return Error or NULL on success
 */
error_t *profile_build_manifest_from_tree(
    git_tree *tree,
    const char *profile_name,
    const char *custom_prefix,
    manifest_t **out
) {
    CHECK_NULL(tree);
    CHECK_NULL(profile_name);
    CHECK_NULL(out);

    error_t *err = NULL;
    manifest_t *manifest = NULL;
    hashmap_t *path_map = NULL;

    /* Allocate manifest */
    manifest = calloc(1, sizeof(manifest_t));
    if (!manifest) {
        err = ERROR(ERR_MEMORY, "Failed to allocate manifest");
        goto cleanup;
    }

    /* Allocate entries array */
    size_t capacity = 64;
    manifest->entries = calloc(capacity, sizeof(file_entry_t));
    if (!manifest->entries) {
        err = ERROR(ERR_MEMORY, "Failed to allocate manifest entries");
        goto cleanup;
    }
    manifest->count = 0;

    /* Create hash map for O(1) duplicate detection */
    path_map = hashmap_create(128);
    if (!path_map) {
        err = ERROR(ERR_MEMORY, "Failed to create hashmap");
        goto cleanup;
    }

    /* Own copy of profile name for entry borrowing.
     * Entries set profile_name to this pointer —
     * manifest lifetime guarantees it remains valid until manifest_free(). */
    manifest->owned_profile_name = strdup(profile_name);
    if (!manifest->owned_profile_name) {
        err = ERROR(ERR_MEMORY, "Failed to duplicate profile name");
        goto cleanup;
    }

    /* Build manifest entries via single-pass tree traversal
     *
     * The callback extracts identity fields (blob_oid, type, mode) from
     * borrowed tree entries, converts paths, and populates file_entry_t
     * directly—all in O(N) time.
     *
     * custom_prefix borrows from function parameter — outlives tree walk. */
    struct manifest_build_ctx ctx = {
        .manifest      = manifest,
        .capacity      = capacity,
        .path_map      = path_map,
        .profile_name  = manifest->owned_profile_name,
        .custom_prefix = custom_prefix,
        .arena         = NULL,
        .error         = NULL
    };

    err = gitops_tree_walk(tree, manifest_build_callback, &ctx);

    if (err || ctx.error) {
        err = ctx.error ? ctx.error : err;
        err = error_wrap(err, "Failed to build manifest from tree");
        goto cleanup;
    }

    /* Success - transfer index ownership to manifest */
    manifest->index = path_map;
    *out = manifest;
    return NULL;

cleanup:
    hashmap_free(path_map, NULL);
    if (err) {
        manifest_free(manifest);
    }

    return err;
}


/**
 * Free manifest
 */
void manifest_free(manifest_t *manifest) {
    if (!manifest) {
        return;
    }

    for (size_t i = 0; i < manifest->count; i++) {
        /* Skip string field frees when arena-backed.
         * blob_oid is an inline binary field — no free. */
        if (!manifest->arena_backed) {
            free(manifest->entries[i].storage_path);
            free(manifest->entries[i].filesystem_path);
            free(manifest->entries[i].old_profile);
            free(manifest->entries[i].owner);
            free(manifest->entries[i].group);
        }
    }

    /* entries array, index, owned strings, and manifest struct are always heap */
    free(manifest->entries);

    /* Free index if present */
    if (manifest->index) {
        hashmap_free(manifest->index, NULL);
    }

    /* Free owned profile name (used by tree-based manifests, NULL otherwise) */
    free(manifest->owned_profile_name);

    free(manifest);
}
