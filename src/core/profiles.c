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
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/string.h"

/**
 * Get OS name
 */
error_t *profile_get_os_name(char **out) {
    CHECK_NULL(out);

    struct utsname uts;
    if (uname(&uts) < 0) {
        return ERROR(ERR_FS, "Failed to get OS name: %s", strerror(errno));
    }

    /* Convert to lowercase */
    char *os_name = strdup(uts.sysname);
    if (!os_name) {
        return ERROR(ERR_MEMORY, "Failed to allocate OS name");
    }

    for (char *p = os_name; *p; p++) {
        *p = tolower(*p);
    }

    *out = os_name;
    return NULL;
}

/**
 * Get hostname
 */
error_t *profile_get_hostname(char **out) {
    CHECK_NULL(out);

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) < 0) {
        return ERROR(ERR_FS, "Failed to get hostname: %s", strerror(errno));
    }

    /* Null-terminate to be safe */
    hostname[sizeof(hostname) - 1] = '\0';

    *out = strdup(hostname);
    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate hostname");
    }

    return NULL;
}

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

    /* Check if profile exists */
    bool exists;
    error_t *err = gitops_branch_exists(repo, name, &exists);
    if (err) {
        return err;
    }

    if (!exists) {
        return ERROR(ERR_NOT_FOUND, "Profile not found: %s", name);
    }

    /* Allocate profile */
    profile_t *profile = calloc(1, sizeof(profile_t));
    if (!profile) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile");
    }

    profile->name = strdup(name);
    if (!profile->name) {
        free(profile);
        return ERROR(ERR_MEMORY, "Failed to allocate profile name");
    }

    /* Load reference */
    char refname[256];
    snprintf(refname, sizeof(refname), "refs/heads/%s", name);

    err = gitops_lookup_reference(repo, refname, &profile->ref);
    if (err) {
        free(profile->name);
        free(profile);
        return error_wrap(err, "Failed to load profile '%s'", name);
    }

    /* Tree will be loaded lazily */
    profile->tree = NULL;
    profile->auto_detected = false;

    *out = profile;
    return NULL;
}

/**
 * Load profile tree (lazy)
 */
static error_t *profile_load_tree(git_repository *repo, profile_t *profile) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);

    if (profile->tree) {
        return NULL;  /* Already loaded */
    }

    char refname[256];
    snprintf(refname, sizeof(refname), "refs/heads/%s", profile->name);

    return gitops_load_tree(repo, refname, &profile->tree);
}

/**
 * Helper: Compare strings for qsort (case-sensitive alphabetical)
 */
static int string_compare(const void *a, const void *b) {
    const char *str_a = *(const char **)a;
    const char *str_b = *(const char **)b;
    return strcmp(str_a, str_b);
}

/**
 * Detect host-specific profiles (base + sub-profiles)
 *
 * Finds both base host profile (hosts/<hostname>) and sub-profiles
 * (hosts/<hostname>/<variant>) for hierarchical configuration.
 *
 * Sub-profiles are sorted alphabetically for deterministic ordering.
 *
 * @param repo Repository (must not be NULL)
 * @param hostname Hostname (must not be NULL)
 * @param list Profile list to append to (must not be NULL)
 * @param capacity Current capacity of list->profiles array (must not be NULL, updated on realloc)
 * @return Error or NULL on success
 */
static error_t *detect_host_profiles(
    git_repository *repo,
    const char *hostname,
    profile_list_t *list,
    size_t *capacity
) {
    CHECK_NULL(repo);
    CHECK_NULL(hostname);
    CHECK_NULL(list);
    CHECK_NULL(capacity);

    error_t *err = NULL;

    /* Build host profile prefix */
    char host_prefix[256];
    int ret = snprintf(host_prefix, sizeof(host_prefix), "hosts/%s", hostname);
    if (ret < 0 || (size_t)ret >= sizeof(host_prefix)) {
        return ERROR(ERR_INTERNAL, "Host prefix too long");
    }
    size_t prefix_len = strlen(host_prefix);

    /* Get all branches */
    string_array_t *branches = NULL;
    err = gitops_list_branches(repo, &branches);
    if (err) {
        return err;
    }

    /* Collect matching profiles: base + sub-profiles */
    string_array_t *base_profile = string_array_create();
    string_array_t *sub_profiles = string_array_create();

    if (!base_profile || !sub_profiles) {
        string_array_free(base_profile);
        string_array_free(sub_profiles);
        string_array_free(branches);
        return ERROR(ERR_MEMORY, "Failed to allocate profile arrays");
    }

    for (size_t i = 0; i < string_array_size(branches); i++) {
        const char *branch = string_array_get(branches, i);

        /* Check if branch starts with "hosts/<hostname>" */
        if (strncmp(branch, host_prefix, prefix_len) != 0) {
            continue;
        }

        const char *suffix = branch + prefix_len;

        /* Exact match: hosts/<hostname> */
        if (suffix[0] == '\0') {
            err = string_array_push(base_profile, branch);
            if (err) {
                string_array_free(base_profile);
                string_array_free(sub_profiles);
                string_array_free(branches);
                return err;
            }
        }
        /* Sub-profile: hosts/<hostname>/something */
        else if (suffix[0] == '/') {
            /* Ensure only one level deep: no additional '/' after the first */
            const char *after_slash = suffix + 1;
            if (strchr(after_slash, '/') == NULL && after_slash[0] != '\0') {
                err = string_array_push(sub_profiles, branch);
                if (err) {
                    string_array_free(base_profile);
                    string_array_free(sub_profiles);
                    string_array_free(branches);
                    return err;
                }
            }
        }
    }

    string_array_free(branches);

    /* Calculate total profiles to add */
    size_t base_count = string_array_size(base_profile);
    size_t sub_count = string_array_size(sub_profiles);
    size_t total_to_add = base_count + sub_count;

    if (total_to_add == 0) {
        /* No host profiles found */
        string_array_free(base_profile);
        string_array_free(sub_profiles);
        return NULL;
    }

    /* Ensure capacity */
    size_t needed_capacity = list->count + total_to_add;
    if (needed_capacity > *capacity) {
        size_t new_capacity = *capacity * 2;
        while (new_capacity < needed_capacity) {
            new_capacity *= 2;
        }

        profile_t *new_profiles = realloc(list->profiles, new_capacity * sizeof(profile_t));
        if (!new_profiles) {
            string_array_free(base_profile);
            string_array_free(sub_profiles);
            return ERROR(ERR_MEMORY, "Failed to grow profiles array");
        }

        list->profiles = new_profiles;
        *capacity = new_capacity;
    }

    /* Sort sub-profiles alphabetically for deterministic ordering */
    if (sub_count > 1) {
        /* Get direct access to internal array for sorting */
        const char **sub_array = malloc(sub_count * sizeof(char *));
        if (!sub_array) {
            string_array_free(base_profile);
            string_array_free(sub_profiles);
            return ERROR(ERR_MEMORY, "Failed to allocate sort array");
        }

        for (size_t i = 0; i < sub_count; i++) {
            sub_array[i] = string_array_get(sub_profiles, i);
        }

        qsort(sub_array, sub_count, sizeof(char *), string_compare);

        /* Rebuild sorted array */
        string_array_t *sorted_subs = string_array_create();
        if (!sorted_subs) {
            free(sub_array);
            string_array_free(base_profile);
            string_array_free(sub_profiles);
            return ERROR(ERR_MEMORY, "Failed to allocate sorted array");
        }

        for (size_t i = 0; i < sub_count; i++) {
            err = string_array_push(sorted_subs, sub_array[i]);
            if (err) {
                free(sub_array);
                string_array_free(sorted_subs);
                string_array_free(base_profile);
                string_array_free(sub_profiles);
                return err;
            }
        }

        free(sub_array);
        string_array_free(sub_profiles);
        sub_profiles = sorted_subs;
    }

    /* Add base profile first (if exists) */
    for (size_t i = 0; i < base_count; i++) {
        const char *profile_name = string_array_get(base_profile, i);
        profile_t *profile = NULL;
        err = profile_load(repo, profile_name, &profile);
        if (err) {
            string_array_free(base_profile);
            string_array_free(sub_profiles);
            return err;
        }

        profile->auto_detected = true;
        list->profiles[list->count++] = *profile;
        free(profile);  /* Shallow copy of internals to list, only free struct */
    }

    /* Add sub-profiles (sorted alphabetically) */
    for (size_t i = 0; i < sub_count; i++) {
        const char *profile_name = string_array_get(sub_profiles, i);
        profile_t *profile = NULL;
        err = profile_load(repo, profile_name, &profile);
        if (err) {
            string_array_free(base_profile);
            string_array_free(sub_profiles);
            return err;
        }

        profile->auto_detected = true;
        list->profiles[list->count++] = *profile;
        free(profile);  /* Shallow copy of internals to list, only free struct */
    }

    string_array_free(base_profile);
    string_array_free(sub_profiles);

    return NULL;
}

/**
 * Auto-detect profiles
 *
 * Detection order (lower numbers = lower precedence):
 * 1. global - Universal settings
 * 2. <os> - OS-specific (darwin, linux, freebsd)
 * 3. hosts/<hostname> - Host base profile
 * 4. hosts/<hostname>/<variant> - Host sub-profiles (sorted alphabetically)
 *
 * Later profiles override earlier ones for conflicting files.
 */
error_t *profile_detect_auto(
    git_repository *repo,
    profile_list_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    profile_list_t *list = calloc(1, sizeof(profile_list_t));
    if (!list) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile list");
    }

    /* Start with capacity for typical case: global + os + host + 2 sub-profiles */
    size_t capacity = 5;
    list->profiles = calloc(capacity, sizeof(profile_t));
    if (!list->profiles) {
        free(list);
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }
    list->count = 0;

    error_t *err = NULL;

    /* 1. Try "global" profile */
    if (profile_exists(repo, "global")) {
        profile_t *profile = NULL;
        err = profile_load(repo, "global", &profile);
        if (err) {
            /* Defensive: ensure profile is freed if partially allocated */
            if (profile) {
                profile_free(profile);
            }
            free(list->profiles);
            free(list);
            return err;
        }
        profile->auto_detected = true;
        list->profiles[list->count++] = *profile;
        free(profile);  /* Shallow copy of internals to list, only free struct */
        profile = NULL;  /* Prevent accidental reuse */
    }

    /* 2. Try OS profile */
    char *os_name = NULL;
    err = profile_get_os_name(&os_name);
    if (!err && os_name) {
        if (profile_exists(repo, os_name)) {
            profile_t *profile = NULL;
            err = profile_load(repo, os_name, &profile);
            if (!err) {
                profile->auto_detected = true;
                list->profiles[list->count++] = *profile;
                free(profile);
            } else {
                error_free(err);
                err = NULL;
            }
        }
        free(os_name);
    } else {
        error_free(err);
        err = NULL;
    }

    /* 3. Detect host profiles (base + sub-profiles, hierarchical) */
    char *hostname = NULL;
    err = profile_get_hostname(&hostname);
    if (!err && hostname) {
        err = detect_host_profiles(repo, hostname, list, &capacity);
        if (err) {
            free(hostname);
            profile_list_free(list);
            return err;
        }
        free(hostname);
    } else {
        /* Non-fatal: unable to get hostname */
        error_free(err);
        err = NULL;
    }

    *out = list;
    return NULL;
}

/**
 * Load multiple profiles
 */
error_t *profile_list_load(
    git_repository *repo,
    const char **names,
    size_t count,
    bool strict,
    profile_list_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(names);
    CHECK_NULL(out);

    profile_list_t *list = calloc(1, sizeof(profile_list_t));
    if (!list) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile list");
    }

    list->profiles = calloc(count, sizeof(profile_t));
    if (!list->profiles) {
        free(list);
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }
    list->count = 0;

    for (size_t i = 0; i < count; i++) {
        profile_t *profile = NULL;
        error_t *err = profile_load(repo, names[i], &profile);
        if (err) {
            if (strict) {
                /* In strict mode, fail on missing profiles */
                profile_list_free(list);
                return error_wrap(err, "Failed to load profile '%s'", names[i]);
            } else {
                /* In non-strict mode, skip missing profiles silently */
                error_free(err);
                continue;
            }
        }

        list->profiles[list->count++] = *profile;
        free(profile);
    }

    *out = list;
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

    string_array_t *valid = string_array_create();
    if (!valid) {
        return ERROR(ERR_MEMORY, "Failed to allocate valid profiles array");
    }

    string_array_t *missing = NULL;
    if (out_missing_profiles) {
        missing = string_array_create();
        if (!missing) {
            string_array_free(valid);
            return ERROR(ERR_MEMORY, "Failed to allocate missing profiles array");
        }
    }

    /* Check each profile */
    for (size_t i = 0; i < string_array_size(state_profiles); i++) {
        const char *name = string_array_get(state_profiles, i);

        if (profile_exists(repo, name)) {
            error_t *err = string_array_push(valid, name);
            if (err) {
                if (missing) string_array_free(missing);
                string_array_free(valid);
                return err;
            }
        } else {
            /* Profile doesn't exist */
            if (missing) {
                error_t *err = string_array_push(missing, name);
                if (err) {
                    string_array_free(missing);
                    string_array_free(valid);
                    return err;
                }
            }
        }
    }

    *out_valid_profiles = valid;
    if (out_missing_profiles) {
        *out_missing_profiles = missing;
    }

    return NULL;
}

/**
 * Resolve profiles based on priority hierarchy
 */
error_t *profile_resolve(
    git_repository *repo,
    const char **explicit_profiles,
    size_t explicit_count,
    const struct dotta_config *config,
    bool strict_mode,
    profile_list_t **out,
    profile_source_t *source_out
) {
    CHECK_NULL(repo);
    CHECK_NULL(config);
    CHECK_NULL(out);

    profile_source_t source;

    /* Priority 1: Explicit CLI profiles */
    if (explicit_profiles && explicit_count > 0) {
        source = PROFILE_SOURCE_EXPLICIT;
        if (source_out) *source_out = source;
        return profile_list_load(repo, explicit_profiles, explicit_count, true, out);
    }

    /* Priority 2: Config profile_order (manual override) */
    if (config->profile_order && config->profile_order_count > 0) {
        source = PROFILE_SOURCE_CONFIG;
        if (source_out) *source_out = source;
        return profile_list_load(repo,
                                (const char **)config->profile_order,
                                config->profile_order_count,
                                strict_mode,
                                out);
    }

    /* Priority 3: State module */
    state_t *state = NULL;
    error_t *err = state_load(repo, &state);

    if (!err && state) {
        string_array_t *state_profiles = NULL;
        err = state_get_profiles(state, &state_profiles);

        if (!err && state_profiles && string_array_size(state_profiles) > 0) {
            /* State has active profiles - validate and use them */
            string_array_t *valid_profiles = NULL;
            string_array_t *missing_profiles = NULL;

            err = validate_state_profiles(repo, state_profiles, &valid_profiles, &missing_profiles);

            if (err) {
                string_array_free(state_profiles);
                state_free(state);
                return error_wrap(err, "Failed to validate state profiles");
            }

            /* Warn about missing profiles (diagnostic message) */
            if (missing_profiles && string_array_size(missing_profiles) > 0) {
                fprintf(stderr, "Warning: State references non-existent profiles:\n");
                for (size_t i = 0; i < string_array_size(missing_profiles); i++) {
                    fprintf(stderr, "  • %s\n", string_array_get(missing_profiles, i));
                }
                fprintf(stderr, "\nHint: Run 'dotta profile validate' to fix state\n");
                fprintf(stderr, "      or 'dotta profile activate <name>' to update active profiles\n\n");
            }
            string_array_free(missing_profiles);

            /* Use valid profiles if any exist */
            if (string_array_size(valid_profiles) > 0) {
                /* Convert string_array to const char** for profile_list_load */
                size_t count = string_array_size(valid_profiles);
                const char **names = malloc(count * sizeof(char *));
                if (!names) {
                    string_array_free(valid_profiles);
                    string_array_free(state_profiles);
                    state_free(state);
                    return ERROR(ERR_MEMORY, "Failed to allocate profile names");
                }

                for (size_t i = 0; i < count; i++) {
                    names[i] = string_array_get(valid_profiles, i);
                }

                err = profile_list_load(repo, names, count, strict_mode, out);
                free(names);
                string_array_free(valid_profiles);
                string_array_free(state_profiles);
                state_free(state);

                if (!err) {
                    source = PROFILE_SOURCE_STATE;
                    if (source_out) *source_out = source;
                }
                return err;
            }

            /* No valid profiles in state - treat as no active profiles */
            string_array_free(valid_profiles);
        }

        string_array_free(state_profiles);
    } else if (err) {
        /* Non-fatal: if state loading fails, fall through to error */
        error_free(err);
        err = NULL;
    }

    state_free(state);

    /* No profiles found from any source - return helpful error */
    return ERROR(ERR_NOT_FOUND,
                "No active profiles found\n\n"
                "To activate profiles:\n"
                "  dotta profile activate <name>       # Activate specific profile\n"
                "  dotta profile activate --all        # Activate all local profiles\n\n"
                "To create and activate a new profile:\n"
                "  dotta add -p <name> <file>          # Automatically activates new profiles\n\n"
                "To use profiles without activating:\n"
                "  dotta status -p <name>              # Use -p flag for any command\n\n"
                "To see available profiles:\n"
                "  dotta profile list                  # List local profiles\n"
                "  dotta profile list --remote         # List remote profiles");
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

    profile_list_t *list = calloc(1, sizeof(profile_list_t));
    if (!list) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile list");
    }

    /* Start with capacity for 16 profiles */
    size_t capacity = 16;
    list->profiles = calloc(capacity, sizeof(profile_t));
    if (!list->profiles) {
        free(list);
        return ERROR(ERR_MEMORY, "Failed to allocate profiles array");
    }
    list->count = 0;

    /* Iterate over all local branches */
    git_reference_iterator *iter = NULL;
    int git_err = git_reference_iterator_new(&iter, repo);
    if (git_err < 0) {
        free(list->profiles);
        free(list);
        return error_from_git(git_err);
    }

    git_reference *ref = NULL;
    while (git_reference_next(&ref, iter) == 0) {
        const char *refname = git_reference_name(ref);

        /* Only process local branches (refs/heads/...) */
        if (strncmp(refname, "refs/heads/", 11) != 0) {
            git_reference_free(ref);
            continue;
        }

        /* Extract branch name */
        const char *branch_name = refname + 11;

        /* Skip dotta-worktree */
        if (strcmp(branch_name, "dotta-worktree") == 0) {
            git_reference_free(ref);
            continue;
        }

        /* Grow array if needed */
        if (list->count >= capacity) {
            capacity *= 2;
            profile_t *new_profiles = realloc(list->profiles, capacity * sizeof(profile_t));
            if (!new_profiles) {
                git_reference_free(ref);
                git_reference_iterator_free(iter);
                profile_list_free(list);
                return ERROR(ERR_MEMORY, "Failed to grow profiles array");
            }
            list->profiles = new_profiles;
        }

        /* Load this profile */
        profile_t *profile = NULL;
        error_t *err = profile_load(repo, branch_name, &profile);
        if (err) {
            /* Skip profiles we can't load */
            error_free(err);
            git_reference_free(ref);
            continue;
        }

        /* Add to list (shallow copy) */
        list->profiles[list->count++] = *profile;
        free(profile);  /* Don't free internals, they're copied */
        git_reference_free(ref);
    }

    git_reference_iterator_free(iter);

    *out = list;
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
static int tree_walk_callback(const char *root, const git_tree_entry *entry, void *payload) {
    struct walk_data *data = (struct walk_data *)payload;

    /* Only process blobs (files) */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return 0;
    }

    /* Build full path */
    const char *name = git_tree_entry_name(entry);
    char full_path[1024];

    if (root && root[0] != '\0') {
        snprintf(full_path, sizeof(full_path), "%s%s", root, name);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", name);
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
    const profile_t *profile,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    /* Load tree if not loaded */
    profile_t *mutable_profile = (profile_t *)profile;
    error_t *err = profile_load_tree(repo, mutable_profile);
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

    /* Allocate manifest */
    manifest_t *manifest = calloc(1, sizeof(manifest_t));
    if (!manifest) {
        return ERROR(ERR_MEMORY, "Failed to allocate manifest");
    }

    /* Allocate entries array */
    size_t capacity = 64;
    manifest->entries = calloc(capacity, sizeof(file_entry_t));
    if (!manifest->entries) {
        free(manifest);
        return ERROR(ERR_MEMORY, "Failed to allocate manifest entries");
    }
    manifest->count = 0;

    /*
     * Create hash map for O(1) duplicate detection
     * Maps: filesystem_path -> index in entries array
     */
    hashmap_t *path_map = hashmap_create(128);
    if (!path_map) {
        free(manifest->entries);
        free(manifest);
        return ERROR(ERR_MEMORY, "Failed to create hashmap");
    }

    /* Process each profile in order */
    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];

        /* Load tree */
        error_t *err = profile_load_tree(repo, profile);
        if (err) {
            hashmap_free(path_map, NULL);
            manifest_free(manifest);
            return error_wrap(err, "Failed to load tree for profile '%s'", profile->name);
        }

        /* List files in profile */
        string_array_t *files = NULL;
        err = profile_list_files(repo, profile, &files);
        if (err) {
            hashmap_free(path_map, NULL);
            manifest_free(manifest);
            return error_wrap(err, "Failed to list files for profile '%s'", profile->name);
        }

        /* Process each file */
        for (size_t j = 0; j < string_array_size(files); j++) {
            const char *storage_path = string_array_get(files, j);

            /* Skip repository metadata files */
            if (strcmp(storage_path, ".dottaignore") == 0 ||
                strcmp(storage_path, ".gitignore") == 0 ||
                strcmp(storage_path, "README.md") == 0 ||
                strcmp(storage_path, "README") == 0 ||
                str_starts_with(storage_path, ".git/") ||
                str_starts_with(storage_path, ".dotta/")) {
                continue;
            }

            /* Convert to filesystem path */
            char *filesystem_path = NULL;
            err = path_from_storage(storage_path, &filesystem_path);
            if (err) {
                string_array_free(files);
                hashmap_free(path_map, NULL);
                manifest_free(manifest);
                return error_wrap(err, "Failed to convert path '%s'", storage_path);
            }

            /* Get tree entry */
            git_tree_entry *entry = NULL;
            int git_err = git_tree_entry_bypath(&entry, profile->tree, storage_path);
            if (git_err != 0) {
                free(filesystem_path);
                string_array_free(files);
                hashmap_free(path_map, NULL);
                manifest_free(manifest);
                return error_from_git(git_err);
            }

            /* Check if file already in manifest using hashmap (O(1)) */
            void *idx_ptr = hashmap_get(path_map, filesystem_path);

            if (idx_ptr) {
                /* Override existing entry */
                size_t existing_idx = (size_t)(uintptr_t)idx_ptr - 1;

                free(manifest->entries[existing_idx].storage_path);
                free(manifest->entries[existing_idx].filesystem_path);
                git_tree_entry_free(manifest->entries[existing_idx].entry);

                manifest->entries[existing_idx].storage_path = strdup(storage_path);
                manifest->entries[existing_idx].filesystem_path = filesystem_path;
                manifest->entries[existing_idx].entry = entry;
                manifest->entries[existing_idx].source_profile = profile;
            } else {
                /* Add new entry */
                if (manifest->count >= capacity) {
                    capacity *= 2;
                    file_entry_t *new_entries = realloc(manifest->entries,
                                                        capacity * sizeof(file_entry_t));
                    if (!new_entries) {
                        free(filesystem_path);
                        git_tree_entry_free(entry);
                        string_array_free(files);
                        hashmap_free(path_map, NULL);
                        manifest_free(manifest);
                        return ERROR(ERR_MEMORY, "Failed to grow manifest");
                    }
                    manifest->entries = new_entries;
                }

                /* Store in array */
                manifest->entries[manifest->count].storage_path = strdup(storage_path);
                manifest->entries[manifest->count].filesystem_path = filesystem_path;
                manifest->entries[manifest->count].entry = entry;
                manifest->entries[manifest->count].source_profile = profile;

                /* Store index in hashmap (offset by 1 to distinguish from NULL) */
                err = hashmap_set(path_map, filesystem_path,
                                (void *)(uintptr_t)(manifest->count + 1));
                if (err) {
                    string_array_free(files);
                    hashmap_free(path_map, NULL);
                    manifest_free(manifest);
                    return error_wrap(err, "Failed to update hashmap");
                }

                manifest->count++;
            }
        }

        string_array_free(files);
    }

    /* Cleanup hashmap (don't free values, they're just indices) */
    hashmap_free(path_map, NULL);

    *out = manifest;
    return NULL;
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
    }

    free(manifest->entries);
    free(manifest);
}
