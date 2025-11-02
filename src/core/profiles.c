/**
 * profiles.c - Profile management implementation
 */

#include "profiles.h"

#include <ctype.h>
#include <errno.h>
#include <git2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/state.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/hashmap.h"
#include "utils/string.h"

/**
 * Check if profile exists
 */
bool profile_exists(git_repository *repo, const char *name) {
    if (!repo || !name) {
        return false;
    }

    bool exists = false;
    error_t *err = gitops_branch_exists(repo, name, &exists);
    if (err) {
        error_free(err);
        return false;
    }

    return exists;
}

/**
 * Load profile
 */
error_t *profile_load(
    git_repository *repo,
    const char *name,
    profile_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(out);

    error_t *err = NULL;
    profile_t *profile = NULL;

    /* Check if profile exists */
    bool exists;
    err = gitops_branch_exists(repo, name, &exists);
    if (err) {
        return err;
    }

    if (!exists) {
        return ERROR(ERR_NOT_FOUND, "Profile not found: %s", name);
    }

    /* Allocate profile */
    profile = calloc(1, sizeof(profile_t));
    if (!profile) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profile");
        goto cleanup;
    }

    profile->name = strdup(name);
    if (!profile->name) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profile name");
        goto cleanup;
    }

    /* Load reference */
    char refname[256];
    int ret = snprintf(refname, sizeof(refname), "refs/heads/%s", name);
    if (ret < 0 || (size_t)ret >= sizeof(refname)) {
        err = ERROR(ERR_INTERNAL, "Profile name too long: %s", name);
        goto cleanup;
    }

    err = gitops_lookup_reference(repo, refname, &profile->ref);
    if (err) {
        err = error_wrap(err, "Failed to load profile '%s'", name);
        goto cleanup;
    }

    /* Tree will be loaded lazily */
    profile->tree = NULL;
    profile->auto_detected = false;

    *out = profile;
    return NULL;

cleanup:
    if (profile) {
        free(profile->name);
        free(profile);
    }
    return err;
}

/**
 * Load profile tree (lazy)
 */
error_t *profile_load_tree(git_repository *repo, profile_t *profile) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);

    if (profile->tree) {
        return NULL;  /* Already loaded */
    }

    char refname[256];
    int ret = snprintf(refname, sizeof(refname), "refs/heads/%s", profile->name);
    if (ret < 0 || (size_t)ret >= sizeof(refname)) {
        return ERROR(ERR_INTERNAL, "Profile name too long: %s", profile->name);
    }

    return gitops_load_tree(repo, refname, &profile->tree);
}

/**
 * Helper: Add profiles from array to list as auto-detected
 */
static error_t *add_profiles_to_list(
    git_repository *repo,
    const string_array_t *profile_names,
    profile_list_t *list
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_names);
    CHECK_NULL(list);

    for (size_t i = 0; i < string_array_size(profile_names); i++) {
        const char *profile_name = string_array_get(profile_names, i);
        profile_t *profile = NULL;
        error_t *err = profile_load(repo, profile_name, &profile);
        if (err) {
            return err;
        }

        profile->auto_detected = true;
        list->profiles[list->count++] = *profile;
        free(profile);  /* Shallow copy of internals to list, only free struct */
    }

    return NULL;
}

/**
 * Detect hierarchical profiles (base + sub-profiles)
 *
 * Generic helper for detecting profiles with hierarchical structure.
 * Finds both base profile (exact match) and sub-profiles (prefix/variant).
 * Sub-profiles are limited to one level deep and sorted alphabetically.
 *
 * This is a pure filtering function - it takes a pre-fetched branch list
 * and filters it by prefix. This allows the caller to fetch branches once
 * and reuse the list for multiple hierarchical detections (OS, host, etc.),
 * avoiding redundant Git operations.
 *
 * Examples:
 * - Prefix "darwin":
 *   Finds: darwin, darwin/personal, darwin/work
 *   Rejects: darwin/ (empty variant), darwin/work/nested (too deep)
 *
 * - Prefix "hosts/visavis":
 *   Finds: hosts/visavis, hosts/visavis/github, hosts/visavis/work
 *
 * @param repo Repository (must not be NULL)
 * @param branches Pre-fetched branch list to filter (must not be NULL)
 * @param prefix Profile prefix to match (must not be NULL)
 * @param list Profile list to append to (must not be NULL)
 * @param capacity Current capacity of list->profiles array (must not be NULL, updated on realloc)
 * @return Error or NULL on success (no matches is not an error)
 */
static error_t *detect_hierarchical_profiles(
    git_repository *repo,
    const string_array_t *branches,
    const char *prefix,
    profile_list_t *list,
    size_t *capacity
) {
    CHECK_NULL(repo);
    CHECK_NULL(branches);
    CHECK_NULL(prefix);
    CHECK_NULL(list);
    CHECK_NULL(capacity);

    error_t *err = NULL;
    string_array_t *base_profile = NULL;
    string_array_t *sub_profiles = NULL;

    size_t prefix_len = strlen(prefix);

    /* Collect matching profiles: base + sub-profiles */
    base_profile = string_array_create();
    sub_profiles = string_array_create();

    if (!base_profile || !sub_profiles) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profile arrays");
        goto cleanup;
    }

    for (size_t i = 0; i < string_array_size(branches); i++) {
        const char *branch = string_array_get(branches, i);

        /* Check if branch starts with prefix */
        if (!str_starts_with(branch, prefix)) {
            continue;
        }

        const char *suffix = branch + prefix_len;

        /* Exact match: prefix exactly matches branch name */
        if (suffix[0] == '\0') {
            err = string_array_push(base_profile, branch);
            if (err) {
                goto cleanup;
            }
        }
        /* Sub-profile: prefix/variant (one level deep only) */
        else if (suffix[0] == '/') {
            const char *variant = suffix + 1;
            /* Validate: variant must be non-empty and contain no '/' (one level deep) */
            if (variant[0] != '\0' && strchr(variant, '/') == NULL) {
                err = string_array_push(sub_profiles, branch);
                if (err) {
                    goto cleanup;
                }
            }
        }
    }

    /* Calculate total profiles to add */
    size_t base_count = string_array_size(base_profile);
    size_t sub_count = string_array_size(sub_profiles);
    size_t total_to_add = base_count + sub_count;

    if (total_to_add == 0) {
        /* No matching profiles found - success with no changes */
        goto cleanup;
    }

    /* Ensure capacity with overflow check */
    size_t needed_capacity = list->count + total_to_add;
    if (needed_capacity > *capacity) {
        /* Check for overflow in doubling loop */
        if (*capacity > SIZE_MAX / 2) {
            err = ERROR(ERR_INTERNAL, "Profile capacity overflow");
            goto cleanup;
        }

        size_t new_capacity = *capacity * 2;
        while (new_capacity < needed_capacity) {
            if (new_capacity > SIZE_MAX / 2) {
                err = ERROR(ERR_INTERNAL, "Profile capacity overflow");
                goto cleanup;
            }
            new_capacity *= 2;
        }

        profile_t *new_profiles = realloc(list->profiles, new_capacity * sizeof(profile_t));
        if (!new_profiles) {
            err = ERROR(ERR_MEMORY, "Failed to grow profiles array");
            goto cleanup;
        }

        list->profiles = new_profiles;
        *capacity = new_capacity;
    }

    /* Sort sub-profiles alphabetically for deterministic ordering */
    if (sub_count > 1) {
        string_array_sort(sub_profiles);
    }

    /* Add base profile first (if exists) */
    err = add_profiles_to_list(repo, base_profile, list);
    if (err) {
        goto cleanup;
    }

    /* Add sub-profiles (sorted alphabetically) */
    err = add_profiles_to_list(repo, sub_profiles, list);
    if (err) {
        goto cleanup;
    }

cleanup:
    string_array_free(base_profile);
    string_array_free(sub_profiles);
    return err;
}

/**
 * Auto-detect profiles based on system information
 *
 * Detection order (precedence: later overrides earlier):
 * 1. global             - Universal settings
 * 2. <os>               - OS base profile (darwin, linux, freebsd)
 * 3. <os>/<variant>     - OS sub-profiles (alphabetically sorted)
 * 4. hosts/<hostname>   - Host base profile
 * 5. hosts/<hostname>/<variant> - Host sub-profiles (alphabetically sorted)
 *
 * All detection steps are non-fatal. Missing profiles or system information
 * failures are silently skipped to maximize compatibility.
 *
 * @param repo Repository (must not be NULL)
 * @param out Profile list (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *profile_detect_auto(
    git_repository *repo,
    profile_list_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    error_t *err = NULL;
    profile_list_t *list = NULL;
    string_array_t *branches = NULL;
    char *os_name = NULL;
    char host_prefix[256];

    /* Allocate profile list */
    list = calloc(1, sizeof(profile_list_t));
    if (!list) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profile list");
        goto cleanup;
    }

    /* Initial capacity for typical case (will grow if needed) */
    size_t capacity = 8;
    list->profiles = calloc(capacity, sizeof(profile_t));
    if (!list->profiles) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profiles array");
        goto cleanup;
    }
    list->count = 0;

    /* 1. Try "global" profile */
    if (profile_exists(repo, "global")) {
        profile_t *profile = NULL;
        err = profile_load(repo, "global", &profile);
        if (err) {
            goto cleanup;
        }
        profile->auto_detected = true;
        list->profiles[list->count++] = *profile;
        free(profile);  /* Shallow copy of internals to list, only free struct */
    }

    /* Fetch all branches once for efficient hierarchical profile detection.
     * This list is reused for both OS-specific and host-specific detection,
     * avoiding redundant Git operations. Non-fatal if fetching fails. */
    err = gitops_list_branches(repo, &branches);
    if (err) {
        /* Non-fatal: skip hierarchical profile detection if branch listing fails.
         * The function can still succeed with just the global profile (if present)
         * or return an empty profile list. */
        error_free(err);
        err = NULL;
        /* branches remains NULL, hierarchical detection will be skipped */
    }

    /* 2. Detect OS-specific profiles (e.g., darwin, darwin/work) */
    struct utsname uts;
    if (branches && uname(&uts) == 0) {
        /* Convert OS name to lowercase (Darwin -> darwin, Linux -> linux) */
        os_name = strdup(uts.sysname);
        if (!os_name) {
            err = ERROR(ERR_MEMORY, "Failed to allocate OS name");
            goto cleanup;
        }

        /* Safe tolower: cast to unsigned char to avoid UB with negative values */
        for (char *p = os_name; *p; p++) {
            *p = (char)tolower((unsigned char)*p);
        }

        err = detect_hierarchical_profiles(repo, branches, os_name, list, &capacity);
        if (err) {
            /* Non-fatal: skip OS profiles if detection fails */
            error_free(err);
            err = NULL;
        }

        free(os_name);
        os_name = NULL;
    }
    /* Non-fatal: skip OS profiles if uname() fails */

    /* 3. Detect host-specific profiles (e.g., hosts/myhost, hosts/myhost/work) */
    char hostname[256];
    if (branches && gethostname(hostname, sizeof(hostname)) == 0) {
        /* Null-terminate to be safe */
        hostname[sizeof(hostname) - 1] = '\0';

        /* Build host prefix */
        int ret = snprintf(host_prefix, sizeof(host_prefix), "hosts/%s", hostname);
        if (ret < 0 || (size_t)ret >= sizeof(host_prefix)) {
            err = ERROR(ERR_INTERNAL, "Host prefix too long");
            goto cleanup;
        }

        err = detect_hierarchical_profiles(repo, branches, host_prefix, list, &capacity);
        if (err) {
            /* Non-fatal: skip host profiles if detection fails */
            error_free(err);
            err = NULL;
        }
    }
    /* Non-fatal: continue if gethostname() fails */

    /* Success */
    *out = list;
    string_array_free(branches);
    return NULL;

cleanup:
    string_array_free(branches);
    free(os_name);
    if (err) {
        profile_list_free(list);
    }
    return err;
}

/**
 * Load multiple profiles
 */
error_t *profile_list_load(
    git_repository *repo,
    char **names,
    size_t count,
    bool strict,
    profile_list_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(names);
    CHECK_NULL(out);

    error_t *err = NULL;
    profile_list_t *list = NULL;

    list = calloc(1, sizeof(profile_list_t));
    if (!list) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profile list");
        goto cleanup;
    }

    list->profiles = calloc(count, sizeof(profile_t));
    if (!list->profiles) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profiles array");
        goto cleanup;
    }
    list->count = 0;

    for (size_t i = 0; i < count; i++) {
        profile_t *profile = NULL;
        err = profile_load(repo, names[i], &profile);
        if (err) {
            if (strict) {
                /* In strict mode, fail on missing profiles */
                err = error_wrap(err, "Failed to load profile '%s'", names[i]);
                goto cleanup;
            } else {
                /* In non-strict mode, skip missing profiles silently */
                error_free(err);
                err = NULL;
                continue;
            }
        }

        list->profiles[list->count++] = *profile;
        free(profile);
    }

    *out = list;
    return NULL;

cleanup:
    if (err) {
        profile_list_free(list);
    }
    return err;
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

    valid = string_array_create();
    if (!valid) {
        err = ERROR(ERR_MEMORY, "Failed to allocate valid profiles array");
        goto cleanup;
    }

    if (out_missing_profiles) {
        missing = string_array_create();
        if (!missing) {
            err = ERROR(ERR_MEMORY, "Failed to allocate missing profiles array");
            goto cleanup;
        }
    }

    /* Check each profile */
    for (size_t i = 0; i < string_array_size(state_profiles); i++) {
        const char *name = string_array_get(state_profiles, i);

        if (profile_exists(repo, name)) {
            err = string_array_push(valid, name);
            if (err) {
                goto cleanup;
            }
        } else {
            /* Profile doesn't exist */
            if (missing) {
                err = string_array_push(missing, name);
                if (err) {
                    goto cleanup;
                }
            }
        }
    }

    /* Success */
    *out_valid_profiles = valid;
    if (out_missing_profiles) {
        *out_missing_profiles = missing;
    }
    return NULL;

cleanup:
    string_array_free(valid);
    string_array_free(missing);
    return err;
}

/**
 * Resolve profiles based on priority hierarchy
 *
 * Priority order (highest to lowest):
 * 1. Explicit CLI profiles (-p flag) - Temporary override
 * 2. State profiles - Persistent management (set via 'dotta profile enable')
 * 3. Error - No profiles found
 */
error_t *profile_resolve(
    git_repository *repo,
    char **explicit_profiles,
    size_t explicit_count,
    bool strict_mode,
    profile_list_t **out,
    profile_source_t *source_out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    error_t *err = NULL;
    state_t *state = NULL;
    string_array_t *state_profiles = NULL;
    string_array_t *valid_profiles = NULL;
    string_array_t *missing_profiles = NULL;
    char **names = NULL;

    /* Priority 1: Explicit CLI profiles (temporary override) */
    if (explicit_profiles && explicit_count > 0) {
        if (source_out) {
            *source_out = PROFILE_SOURCE_EXPLICIT;
        }
        return profile_list_load(repo, explicit_profiles, explicit_count, true, out);
    }

    /* Priority 2: State profiles (persistent management) */
    err = state_load(repo, &state);
    if (err) {
        /* Non-fatal: if state loading fails, fall through to "no profiles" error */
        error_free(err);
        err = NULL;
        goto no_profiles;
    }

    if (!state) {
        goto no_profiles;
    }

    err = state_get_profiles(state, &state_profiles);
    if (err) {
        error_free(err);
        err = NULL;
        goto no_profiles;
    }

    if (!state_profiles || string_array_size(state_profiles) == 0) {
        goto no_profiles;
    }

    /* State has enabled profiles - validate and use them */
    err = validate_state_profiles(repo, state_profiles, &valid_profiles, &missing_profiles);
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
    if (missing_profiles && string_array_size(missing_profiles) > 0) {
        fprintf(stderr, "Warning: State references non-existent profiles:\n");
        for (size_t i = 0; i < string_array_size(missing_profiles); i++) {
            fprintf(stderr, "  • %s\n", string_array_get(missing_profiles, i));
        }
        fprintf(stderr, "\nHint: Run 'dotta profile validate' to fix state,\n");
        fprintf(stderr, "      or 'dotta profile enable <name>' to enable profiles\n\n");
    }
    string_array_free(missing_profiles);
    missing_profiles = NULL;

    /* Use valid profiles if any exist */
    if (string_array_size(valid_profiles) == 0) {
        goto no_profiles;
    }

    /* Convert string_array to const char** for profile_list_load */
    size_t count = string_array_size(valid_profiles);
    names = malloc(count * sizeof(char *));
    if (!names) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profile names");
        goto cleanup;
    }

    for (size_t i = 0; i < count; i++) {
        names[i] = (char *)string_array_get(valid_profiles, i);
    }

    err = profile_list_load(repo, names, count, strict_mode, out);
    if (err) {
        goto cleanup;
    }

    /* Success */
    if (source_out) {
        *source_out = PROFILE_SOURCE_STATE;
    }

    /* Cleanup and return success */
    free(names);
    string_array_free(valid_profiles);
    string_array_free(state_profiles);
    state_free(state);
    return NULL;

no_profiles:
    /* No profiles found from any source - return helpful error */
    err = ERROR(ERR_NOT_FOUND,
                "No enabled profiles found\n\n"
                "To enable profiles:\n"
                "  dotta profile enable <name>         # Enable specific profile\n"
                "  dotta profile enable --all          # Enable all local profiles\n\n"
                "To create and enable a new profile:\n"
                "  dotta add -p <name> <file>          # Automatically enables new profiles\n\n"
                "To use profiles without enabling:\n"
                "  dotta status -p <name>              # Use -p flag for any command\n\n"
                "To see available profiles:\n"
                "  dotta profile list                  # List local profiles\n"
                "  dotta profile list --remote         # List remote profiles");

cleanup:
    free(names);
    string_array_free(valid_profiles);
    string_array_free(missing_profiles);
    string_array_free(state_profiles);
    state_free(state);
    return err;
}

/**
 * List all local profile branches
 *
 * Similar to what clone does, but returns profiles instead of just creating branches.
 */
error_t *profile_list_all_local(
    git_repository *repo,
    profile_list_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    error_t *err = NULL;
    profile_list_t *list = NULL;
    git_reference_iterator *iter = NULL;
    git_reference *ref = NULL;

    /* Allocate profile list */
    list = calloc(1, sizeof(profile_list_t));
    if (!list) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profile list");
        goto cleanup;
    }

    /* Start with capacity for 32 profiles to reduce reallocations */
    size_t capacity = 32;
    list->profiles = calloc(capacity, sizeof(profile_t));
    if (!list->profiles) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profiles array");
        goto cleanup;
    }
    list->count = 0;

    /* Create git reference iterator */
    int git_err = git_reference_iterator_new(&iter, repo);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Iterate over all local branches */
    while (git_reference_next(&ref, iter) == 0) {
        const char *refname = git_reference_name(ref);

        /* Only process local branches (refs/heads/...) */
        if (!str_starts_with(refname, "refs/heads/")) {
            git_reference_free(ref);
            ref = NULL;
            continue;
        }

        /* Extract branch name */
        const char *branch_name = refname + 11;

        /* Skip dotta-worktree */
        if (strcmp(branch_name, "dotta-worktree") == 0) {
            git_reference_free(ref);
            ref = NULL;
            continue;
        }

        /* Grow array if needed */
        if (list->count >= capacity) {
            /* Check for overflow */
            if (capacity > SIZE_MAX / 2) {
                err = ERROR(ERR_INTERNAL, "Profile capacity overflow");
                goto cleanup;
            }
            capacity *= 2;

            profile_t *new_profiles = realloc(list->profiles, capacity * sizeof(profile_t));
            if (!new_profiles) {
                err = ERROR(ERR_MEMORY, "Failed to grow profiles array");
                goto cleanup;
            }
            list->profiles = new_profiles;
        }

        /* Load this profile */
        profile_t *profile = NULL;
        err = profile_load(repo, branch_name, &profile);
        if (err) {
            /* Skip profiles we can't load (non-fatal) */
            error_free(err);
            err = NULL;
            git_reference_free(ref);
            ref = NULL;
            continue;
        }

        /* Add to list (shallow copy) */
        list->profiles[list->count++] = *profile;
        free(profile);  /* Don't free internals, they're copied */

        git_reference_free(ref);
        ref = NULL;
    }

    /* Success */
    git_reference_iterator_free(iter);
    *out = list;
    return NULL;

cleanup:
    if (ref) {
        git_reference_free(ref);
    }
    if (iter) {
        git_reference_iterator_free(iter);
    }
    if (err) {
        profile_list_free(list);
    }
    return err;
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
static int tree_walk_callback(const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct walk_data *data = (struct walk_data *)payload;

    /* Only process blobs (files) */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* Build full path */
    const char *name = git_tree_entry_name(entry);
    char full_path[1024];
    int ret;

    if (root && root[0] != '\0') {
        ret = snprintf(full_path, sizeof(full_path), "%s%s", root, name);
    } else {
        ret = snprintf(full_path, sizeof(full_path), "%s", name);
    }

    /* Check for truncation */
    if (ret < 0 || (size_t)ret >= sizeof(full_path)) {
        data->error = ERROR(ERR_INTERNAL,
                           "Path exceeds maximum length: %s%s",
                           root ? root : "", name);
        return -1;
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
 * List files in profile
 */
error_t *profile_list_files(
    git_repository *repo,
    profile_t *profile,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    /* Load tree if not loaded (lazy loading) */
    error_t *err = profile_load_tree(repo, profile);
    if (err) {
        return err;
    }

    /* Walk tree */
    struct walk_data data = {0};
    data.paths = string_array_create();
    if (!data.paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate paths array");
    }
    data.error = NULL;

    err = gitops_tree_walk(profile->tree, tree_walk_callback, &data);
    if (err || data.error) {
        string_array_free(data.paths);
        return err ? err : data.error;
    }

    *out = data.paths;
    return NULL;
}

/**
 * Build manifest from profiles
 *
 * Uses a hashmap for O(1) lookups when checking for duplicates.
 * This changes overall complexity from O(n*m) to O(n) where n is total files.
 */
error_t *profile_build_manifest(
    git_repository *repo,
    profile_list_t *profiles,
    manifest_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    error_t *err = NULL;
    manifest_t *manifest = NULL;
    hashmap_t *path_map = NULL;
    string_array_t *files = NULL;
    char *filesystem_path = NULL;
    git_tree_entry *entry = NULL;
    char *dup_storage_path = NULL;

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
     */
    path_map = hashmap_create(128);
    if (!path_map) {
        err = ERROR(ERR_MEMORY, "Failed to create hashmap");
        goto cleanup;
    }

    /* Process each profile in order */
    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];

        /* Load tree */
        err = profile_load_tree(repo, profile);
        if (err) {
            err = error_wrap(err, "Failed to load tree for profile '%s'", profile->name);
            goto cleanup;
        }

        /* List files in profile */
        err = profile_list_files(repo, profile, &files);
        if (err) {
            err = error_wrap(err, "Failed to list files for profile '%s'", profile->name);
            goto cleanup;
        }

        /* Process each file */
        for (size_t j = 0; j < string_array_size(files); j++) {
            const char *storage_path = string_array_get(files, j);

            /* Skip repository metadata files */
            if (strcmp(storage_path, ".dottaignore") == 0 ||
                strcmp(storage_path, ".bootstrap") == 0 ||
                strcmp(storage_path, ".gitignore") == 0 ||
                strcmp(storage_path, "README.md") == 0 ||
                strcmp(storage_path, "README") == 0 ||
                str_starts_with(storage_path, ".git/") ||
                str_starts_with(storage_path, ".dotta/")) {
                continue;
            }

            /* Convert to filesystem path */
            filesystem_path = NULL;
            err = path_from_storage(storage_path, &filesystem_path);
            if (err) {
                err = error_wrap(err, "Failed to convert path '%s'", storage_path);
                goto cleanup;
            }

            /* Get tree entry */
            entry = NULL;
            int git_err = git_tree_entry_bypath(&entry, profile->tree, storage_path);
            if (git_err != 0) {
                err = error_from_git(git_err);
                goto cleanup;
            }

            /* Check if file already in manifest using hashmap (O(1)) */
            void *idx_ptr = hashmap_get(path_map, filesystem_path);

            if (idx_ptr) {
                /* Override existing entry (profile with higher precedence) */
                /*
                 * Convert pointer back to index. We offset by 1 when storing to
                 * distinguish NULL (not found) from index 0.
                 * Safe because: indices are always << SIZE_MAX, uintptr_t can hold
                 * any valid pointer value, and we never store actual pointers here.
                 */
                size_t existing_idx = (size_t)(uintptr_t)idx_ptr - 1;

                /* Add current profile to all_profiles list (for overlap tracking) */
                if (!manifest->entries[existing_idx].all_profiles) {
                    manifest->entries[existing_idx].all_profiles = string_array_create();
                    if (!manifest->entries[existing_idx].all_profiles) {
                        err = ERROR(ERR_MEMORY, "Failed to create all_profiles array");
                        goto cleanup;
                    }
                    /* Add the original profile that was there first */
                    err = string_array_push(manifest->entries[existing_idx].all_profiles,
                                           manifest->entries[existing_idx].source_profile->name);
                    if (err) {
                        goto cleanup;
                    }
                }

                /* Add current profile (the one with higher precedence) */
                err = string_array_push(manifest->entries[existing_idx].all_profiles, profile->name);
                if (err) {
                    goto cleanup;
                }

                /* Duplicate storage path before freeing old one */
                dup_storage_path = strdup(storage_path);
                if (!dup_storage_path) {
                    err = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
                    goto cleanup;
                }

                /* Now safe to free old resources and update */
                free(manifest->entries[existing_idx].storage_path);
                free(manifest->entries[existing_idx].filesystem_path);
                git_tree_entry_free(manifest->entries[existing_idx].entry);

                manifest->entries[existing_idx].storage_path = dup_storage_path;
                manifest->entries[existing_idx].filesystem_path = filesystem_path;
                manifest->entries[existing_idx].entry = entry;
                manifest->entries[existing_idx].source_profile = profile;

                /* Clear temporary variables (ownership transferred) */
                dup_storage_path = NULL;
                filesystem_path = NULL;
                entry = NULL;
            } else {
                /* Add new entry */
                if (manifest->count >= capacity) {
                    /* Check for overflow before doubling */
                    if (capacity > SIZE_MAX / 2) {
                        err = ERROR(ERR_INTERNAL, "Manifest capacity overflow");
                        goto cleanup;
                    }
                    capacity *= 2;

                    file_entry_t *new_entries = realloc(manifest->entries,
                                                        capacity * sizeof(file_entry_t));
                    if (!new_entries) {
                        err = ERROR(ERR_MEMORY, "Failed to grow manifest");
                        goto cleanup;
                    }
                    manifest->entries = new_entries;
                }

                /* Duplicate storage path */
                dup_storage_path = strdup(storage_path);
                if (!dup_storage_path) {
                    err = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
                    goto cleanup;
                }

                /* Store in array */
                manifest->entries[manifest->count].storage_path = dup_storage_path;
                manifest->entries[manifest->count].filesystem_path = filesystem_path;
                manifest->entries[manifest->count].entry = entry;
                manifest->entries[manifest->count].source_profile = profile;
                manifest->entries[manifest->count].all_profiles = NULL;  /* Initialize to NULL (single profile) */

                /* Store index in hashmap (offset by 1 to distinguish from NULL).
                 * We cast the index through uintptr_t to store it as a void pointer.
                 * This is safe because:
                 * 1. Array indices are always much smaller than SIZE_MAX
                 * 2. uintptr_t can hold any pointer value (by definition)
                 * 3. We never dereference these "pointers" - they're just tagged integers
                 */
                err = hashmap_set(path_map, filesystem_path,
                                (void *)(uintptr_t)(manifest->count + 1));
                if (err) {
                    err = error_wrap(err, "Failed to update hashmap");
                    goto cleanup;
                }

                manifest->count++;

                /* Clear temporary variables (ownership transferred) */
                dup_storage_path = NULL;
                filesystem_path = NULL;
                entry = NULL;
            }
        }

        string_array_free(files);
        files = NULL;
    }

    /* Success */
    hashmap_free(path_map, NULL);
    *out = manifest;
    return NULL;

cleanup:
    /* Clean up temporary per-iteration resources */
    free(filesystem_path);
    free(dup_storage_path);
    if (entry) {
        git_tree_entry_free(entry);
    }
    string_array_free(files);

    /* Clean up main resources */
    hashmap_free(path_map, NULL);
    if (err) {
        manifest_free(manifest);
    }

    return err;
}

/**
 * Build inverted index of all files across profiles
 *
 * Loads all profile branches once and builds an in-memory hashmap that maps
 * each storage path to a list of profile names containing that file.
 *
 * This is the centralized, optimized solution for multi-profile operations.
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
    string_array_t *files = NULL;

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
    for (size_t i = 0; i < string_array_size(all_branches); i++) {
        const char *branch_name = string_array_get(all_branches, i);

        /* Skip excluded profile and dotta-worktree */
        if (strcmp(branch_name, "dotta-worktree") == 0) {
            continue;
        }

        if (exclude_profile && strcmp(branch_name, exclude_profile) == 0) {
            continue;
        }

        /* Try to load profile */
        profile_t *profile = NULL;
        err = profile_load(repo, branch_name, &profile);
        if (err) {
            error_free(err);
            err = NULL;
            continue;  /* Non-fatal: skip this profile */
        }

        /* Get list of all files in this profile */
        files = NULL;
        err = profile_list_files(repo, profile, &files);
        profile_free(profile);

        if (err) {
            error_free(err);
            err = NULL;
            continue;  /* Non-fatal: skip this profile */
        }

        /* Add this profile to the index for each of its files */
        for (size_t j = 0; j < string_array_size(files); j++) {
            const char *storage_path = string_array_get(files, j);

            /* Get or create profile list for this storage path */
            string_array_t *profile_list = hashmap_get(index, storage_path);
            if (!profile_list) {
                profile_list = string_array_create();
                if (!profile_list) {
                    err = ERROR(ERR_MEMORY, "Failed to create profile list for file");
                    goto cleanup;
                }

                err = hashmap_set(index, storage_path, profile_list);
                if (err) {
                    string_array_free(profile_list);
                    err = error_wrap(err, "Failed to index file");
                    goto cleanup;
                }
            }

            /* Add this profile to the list */
            err = string_array_push(profile_list, branch_name);
            if (err) {
                /* Non-fatal: continue without this entry */
                error_free(err);
                err = NULL;
            }
        }

        string_array_free(files);
        files = NULL;
    }

    /* Success */
    string_array_free(all_branches);
    *out_index = index;
    return NULL;

cleanup:
    string_array_free(files);
    string_array_free(all_branches);
    if (index) {
        /* Free index and all its arrays */
        hashmap_free(index, string_array_free);
    }
    return err;
}

/**
 * Free profile
 */
void profile_free(profile_t *profile) {
    if (!profile) {
        return;
    }

    free(profile->name);
    if (profile->ref) {
        git_reference_free(profile->ref);
    }
    if (profile->tree) {
        git_tree_free(profile->tree);
    }
    free(profile);
}

/**
 * Free profile list
 */
void profile_list_free(profile_list_t *list) {
    if (!list) {
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        profile_t *profile = &list->profiles[i];
        free(profile->name);
        if (profile->ref) {
            git_reference_free(profile->ref);
        }
        if (profile->tree) {
            git_tree_free(profile->tree);
        }
    }

    free(list->profiles);
    free(list);
}

/**
 * Free manifest
 */
void manifest_free(manifest_t *manifest) {
    if (!manifest) {
        return;
    }

    for (size_t i = 0; i < manifest->count; i++) {
        free(manifest->entries[i].storage_path);
        free(manifest->entries[i].filesystem_path);
        if (manifest->entries[i].entry) {
            git_tree_entry_free(manifest->entries[i].entry);
        }
        if (manifest->entries[i].all_profiles) {
            string_array_free(manifest->entries[i].all_profiles);
        }
    }

    free(manifest->entries);
    free(manifest);
}
