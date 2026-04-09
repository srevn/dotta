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
    char refname[DOTTA_REFNAME_MAX];
    err = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", name
    );
    if (err) {
        err = error_wrap(
            err, "Invalid profile name '%s'",
            name
        );
        goto cleanup;
    }

    err = gitops_lookup_reference(repo, refname, &profile->ref);
    if (err) {
        err = error_wrap(
            err, "Profile not found: %s",
            name
        );
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

    /* Use cached reference if available (avoids redundant ref lookup) */
    if (profile->ref) {
        git_object *obj = NULL;
        int git_err = git_reference_peel(&obj, profile->ref, GIT_OBJECT_ANY);
        if (git_err < 0) {
            error_t *err = error_from_git(git_err);
            return error_wrap(
                err, "Failed to peel reference for profile '%s'",
                profile->name
            );
        }

        git_object_t obj_type = git_object_type(obj);
        if (obj_type == GIT_OBJECT_COMMIT) {
            git_commit *commit = (git_commit *) obj;
            git_err = git_commit_tree(&profile->tree, commit);
            git_object_free(obj);
            if (git_err < 0) {
                return error_from_git(git_err);
            }
        } else if (obj_type == GIT_OBJECT_TREE) {
            profile->tree = (git_tree *) obj;
        } else {
            git_object_free(obj);
            return ERROR(
                ERR_GIT, "Profile '%s': unexpected object type %d",
                profile->name, (int) obj_type
            );
        }

        return NULL;
    }

    /* Fallback: resolve by name (for profiles without cached reference) */
    char refname[DOTTA_REFNAME_MAX];
    error_t *err = gitops_build_refname(
        refname, sizeof(refname), "refs/heads/%s", profile->name
    );
    if (err) {
        return error_wrap(
            err, "Invalid profile name '%s'",
            profile->name
        );
    }

    return gitops_load_tree(repo, refname, &profile->tree);
}

error_t *file_entry_ensure_tree_entry(
    file_entry_t *entry,
    git_repository *repo
) {
    CHECK_NULL(entry);
    CHECK_NULL(repo);
    CHECK_NULL(entry->source_profile);
    CHECK_NULL(entry->storage_path);

    /* Idempotent: already loaded */
    if (entry->entry) {
        return NULL;
    }

    /* Load profile tree (cached in profile structure) */
    error_t *err = profile_load_tree(repo, entry->source_profile);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for profile '%s'",
            entry->profile_name
        );
    }

    /* Lookup tree entry from Git (creates owned reference) */
    int git_err = git_tree_entry_bypath(
        &entry->entry, entry->source_profile->tree, entry->storage_path
    );
    if (git_err != 0) {
        if (git_err == GIT_ENOTFOUND) {
            return ERROR(
                ERR_NOT_FOUND, "File '%s' not found in profile '%s' Git tree",
                entry->storage_path, entry->profile_name
            );
        }
        err = error_from_git(git_err);
        return error_wrap(
            err, "Failed to lookup tree entry for '%s' in profile '%s'",
            entry->storage_path, entry->profile_name
        );
    }

    return NULL;
}

/**
 * Match hierarchical profile names from available names
 *
 * Finds base match (exact prefix) and sub-matches (prefix/variant, one level
 * deep only). Sub-matches are sorted alphabetically for deterministic ordering.
 *
 * @param available Available names to match against
 * @param prefix Prefix to match (e.g., "darwin", "hosts/myhost")
 * @param out Output array to append matches to (base first, then sorted subs)
 * @return Error or NULL on success
 */
static error_t *match_hierarchical_names(
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
        const char *name = available->items[i];

        /* Check if branch starts with prefix */
        if (!str_starts_with(name, prefix)) {
            continue;
        }

        const char *suffix = name + prefix_len;

        if (suffix[0] == '\0') {
            /* Exact match: base profile — add directly to output */
            err = string_array_push(out, name);
            if (err) {
                goto cleanup;
            }
        } else if (suffix[0] == '/') {
            const char *variant = suffix + 1;
            /* One level deep only: non-empty variant with no further '/' */
            if (variant[0] != '\0' && strchr(variant, '/') == NULL) {
                err = string_array_push(sub_profiles, name);
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
error_t *profile_detect_names(
    const string_array_t *available_branches,
    string_array_t **out_names
) {
    CHECK_NULL(available_branches);
    CHECK_NULL(out_names);

    error_t *err = NULL;
    char *os_name = NULL;

    string_array_t *names = string_array_new(0);
    if (!names) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile names array");
    }

    /* 1. "global" — always first if present */
    if (string_array_contains(available_branches, "global")) {
        err = string_array_push(names, "global");
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

        err = match_hierarchical_names(available_branches, os_name, names);
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
            err = match_hierarchical_names(available_branches, host_prefix, names);
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
    *out_names = names;

    return NULL;

cleanup:
    free(os_name);
    string_array_free(names);

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
                err = error_wrap(
                    err, "Failed to load profile '%s'",
                    names[i]
                );
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
    if (err) profile_list_free(list);

    return err;
}

/**
 * Enrich profiles with custom prefixes from state
 *
 * Populates profile->custom_prefix for each profile by querying the state
 * database prefix map. Bridges profile loading (Git-based) with deployment
 * configuration (state-based).
 *
 * Safe for re-enrichment: frees existing custom_prefix before setting.
 * Empty state (from state_create_empty) produces no enrichment — correct
 * behavior for pre-init or missing DB scenarios.
 */
error_t *profiles_enrich_with_prefixes(
    profile_list_t *profiles,
    const state_t *state
) {
    CHECK_NULL(profiles);
    CHECK_NULL(state);

    if (profiles->count == 0) {
        return NULL;
    }

    /* Get prefix map from state */
    hashmap_t *prefix_map = NULL;
    error_t *err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        return error_wrap(err, "Failed to get custom prefix map");
    }

    /* Enrich each profile with its custom prefix (if any) */
    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];
        const char *custom_prefix = (const char *) hashmap_get(prefix_map, profile->name);

        /* Free existing custom_prefix before setting (safe for re-enrichment) */
        free(profile->custom_prefix);

        /* Attach to profile (owned by profile, freed in profile_list_free) */
        if (custom_prefix) {
            profile->custom_prefix = strdup(custom_prefix);
            if (!profile->custom_prefix) {
                hashmap_free(prefix_map, free);
                return ERROR(
                    ERR_MEMORY,
                    "Failed to allocate custom_prefix for profile '%s'",
                    profile->name
                );
            }
        } else {
            /* No custom prefix - ensure field is NULL */
            profile->custom_prefix = NULL;
        }
    }

    /* Cleanup temporary resources */
    hashmap_free(prefix_map, free);

    return NULL;
}

/**
 * Get custom deployment prefixes for named profiles
 *
 * Queries the state database for custom prefixes. Only profiles with
 * non-NULL custom prefixes are included in the output.
 */
error_t *profile_get_custom_prefixes(
    git_repository *repo,
    const char *const *names,
    size_t count,
    string_array_t **out_prefixes
) {
    CHECK_NULL(repo);
    CHECK_NULL(names);
    CHECK_NULL(out_prefixes);

    error_t *err = NULL;
    string_array_t *prefixes = string_array_new(0);
    if (!prefixes) {
        return ERROR(ERR_MEMORY, "Failed to allocate prefixes array");
    }

    /* Load state (read-only) to get prefix map */
    state_t *state = NULL;
    err = state_load(repo, &state);
    if (err) {
        /* State load failure is non-fatal — no custom prefixes available */
        error_free(err);
        *out_prefixes = prefixes;
        return NULL;
    }

    if (!state) {
        *out_prefixes = prefixes;
        return NULL;
    }

    hashmap_t *prefix_map = NULL;
    err = state_get_prefix_map(state, &prefix_map);
    if (err) {
        state_free(state);
        string_array_free(prefixes);
        return error_wrap(err, "Failed to get custom prefix map");
    }

    for (size_t i = 0; i < count; i++) {
        const char *prefix = (const char *) hashmap_get(prefix_map, names[i]);
        if (prefix) {
            err = string_array_push(prefixes, prefix);
            if (err) {
                hashmap_free(prefix_map, free);
                state_free(state);
                string_array_free(prefixes);
                return error_wrap(err, "Failed to collect custom prefix");
            }
        }
    }

    hashmap_free(prefix_map, free);
    state_free(state);

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
        const char *name = state_profiles->items[i];

        if (profile_exists(repo, name)) {
            err = string_array_push(valid, name);
            if (err) goto cleanup;
        } else {
            /* Profile doesn't exist */
            if (missing) {
                err = string_array_push(missing, name);
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
 * Resolve enabled profile names from state database (internal helper)
 *
 * Loads state, validates that referenced profiles exist as branches,
 * and returns the validated names. Warns on stderr about missing profiles.
 *
 * When out_state is non-NULL, transfers ownership of the state handle
 * to the caller (for enrichment or further queries). When NULL, state
 * is freed internally.
 *
 * @param repo Repository (must not be NULL)
 * @param out_names Validated profile names (must not be NULL, caller frees)
 * @param out_state Optional: receives state handle (caller frees). NULL to discard.
 * @return Error (ERR_NOT_FOUND if no enabled profiles) or NULL on success
 */
static error_t *resolve_state_profile_names(
    git_repository *repo,
    string_array_t **out_names,
    state_t **out_state
) {
    error_t *err = NULL;
    state_t *state = NULL;
    string_array_t *state_profiles = NULL;
    string_array_t *valid_profiles = NULL;
    string_array_t *missing_profiles = NULL;

    /* Load state */
    err = state_load(repo, &state);
    if (err) {
        return error_wrap(err, "Failed to load state for profile resolution");
    }

    /* Get profile names from state */
    err = state_get_profiles(state, &state_profiles);
    if (err) {
        error_free(err);
        state_free(state);
        return ERROR(ERR_NOT_FOUND, "No enabled profiles found");
    }

    if (!state_profiles || state_profiles->count == 0) {
        string_array_free(state_profiles);
        state_free(state);
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
        state_free(state);
        return ERROR(ERR_NOT_FOUND, "No enabled profiles found");
    }

    /* Success */
    *out_names = valid_profiles;
    if (out_state) {
        *out_state = state;
    } else {
        state_free(state);
    }
    string_array_free(state_profiles);

    return NULL;

cleanup:
    string_array_free(valid_profiles);
    string_array_free(missing_profiles);
    string_array_free(state_profiles);
    state_free(state);

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
    string_array_t *valid_profiles = NULL;
    char **names = NULL;

    /* Priority 1: Explicit CLI profiles (temporary override) */
    if (explicit_profiles && explicit_count > 0) {
        if (source_out) {
            *source_out = PROFILE_SOURCE_EXPLICIT;
        }
        err = profile_list_load(
            repo, explicit_profiles, explicit_count, strict_mode, out
        );
        if (err) {
            return err;
        }
        /* Enrich with custom prefixes from state.
         * Explicit-profiles path has no pre-loaded state — load temporarily. */
        state_t *enrich_state = NULL;
        err = state_load(repo, &enrich_state);
        if (err) {
            profile_list_free(*out);
            *out = NULL;
            return error_wrap(err, "Failed to load state for prefix enrichment");
        }
        err = profiles_enrich_with_prefixes(*out, enrich_state);
        state_free(enrich_state);
        if (err) {
            profile_list_free(*out);
            *out = NULL;
            return err;
        }
        return NULL;
    }

    /* Priority 2: State profiles (persistent management)
     *
     * Resolve validated names from state, keeping the state handle
     * for custom prefix enrichment after profile loading.
     */
    err = resolve_state_profile_names(repo, &valid_profiles, &state);
    if (err) {
        if (error_code(err) == ERR_NOT_FOUND) {
            error_free(err);
            goto no_profiles;
        }
        goto cleanup;
    }

    /* Load full profile_t structs from validated names */
    size_t count = valid_profiles->count;
    names = malloc(count * sizeof(char *));
    if (!names) {
        err = ERROR(ERR_MEMORY, "Failed to allocate profile names");
        goto cleanup;
    }

    for (size_t i = 0; i < count; i++) {
        names[i] = valid_profiles->items[i];
    }

    err = profile_list_load(repo, names, count, strict_mode, out);
    if (err) {
        goto cleanup;
    }

    /* Enrich with custom prefixes (state already loaded by resolve_state_profile_names) */
    err = profiles_enrich_with_prefixes(*out, state);
    if (err) {
        profile_list_free(*out);
        *out = NULL;
        goto cleanup;
    }

    /* Success */
    if (source_out) *source_out = PROFILE_SOURCE_STATE;

    free(names);
    string_array_free(valid_profiles);
    state_free(state);

    return NULL;

no_profiles:
    /* No profiles found from any source - return helpful error */
    err = ERROR(
        ERR_NOT_FOUND,
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
        "  dotta profile list --remote         # List remote profiles"
    );

cleanup:
    free(names);
    string_array_free(valid_profiles);
    state_free(state);

    return err;
}

/**
 * Resolve CLI profile names for operation filtering
 *
 * Lightweight validation: checks branch existence without resolving
 * Git refs or loading profile objects.
 */
error_t *profile_resolve_cli_names(
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
    string_array_t *names = string_array_new(cli_count);
    if (!names) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile names");
    }

    for (size_t i = 0; i < cli_count; i++) {
        if (profile_exists(repo, cli_profiles[i])) {
            err = string_array_push(names, cli_profiles[i]);
            if (err) {
                string_array_free(names);
                return error_wrap(err, "Failed to add profile name '%s'", cli_profiles[i]);
            }
        } else if (strict_mode) {
            string_array_free(names);
            return ERROR(
                ERR_NOT_FOUND, "Profile not found: %s\n"
                "Hint: Run 'dotta profile list' to see available profiles",
                cli_profiles[i]
            );
        }
        /* Non-strict: skip non-existent profiles silently */
    }

    *out = names;
    return NULL;
}

/**
 * Resolve enabled profile names from state database
 *
 * Lightweight name-only resolution — no Git ref resolution or profile_t
 * allocation. Thin wrapper around the internal resolve_state_profile_names.
 */
error_t *profile_resolve_state_names(
    git_repository *repo,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);

    return resolve_state_profile_names(repo, out, NULL);
}

/**
 * Validate that filter profiles are enabled
 *
 * Ensures CLI filter only references profiles that are actually enabled
 * in the workspace.
 */
error_t *profile_validate_filter(
    const string_array_t *workspace_names,
    const char *const *filter_names,
    size_t filter_count
) {
    CHECK_NULL(workspace_names);

    /* NULL filter is valid (no filter) */
    if (!filter_names) {
        return NULL;
    }

    /* Check each filter profile is in workspace */
    for (size_t i = 0; i < filter_count; i++) {
        const char *filter_name = filter_names[i];
        bool found = false;

        for (size_t j = 0; j < workspace_names->count; j++) {
            if (strcmp(workspace_names->items[j], filter_name) == 0) {
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
    const char *const *filter_names,
    size_t filter_count
) {
    /* NULL name never matches (defensive) */
    if (!profile_name) {
        return false;
    }

    /* NULL filter matches all (no filter = match all) */
    if (!filter_names) {
        return true;
    }

    /* Check if name is in filter list */
    for (size_t i = 0; i < filter_count; i++) {
        if (strcmp(profile_name, filter_names[i]) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * List all local profile branch names (lightweight, no ref resolution)
 */
error_t *profile_list_all_local_names(
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
        return 0;  /* Skip, continue walk */
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
 * Context for manifest building callback
 *
 * Passed to gitops_tree_walk() to build manifest entries directly during
 * tree traversal, eliminating O(N×D) two-pass overhead. The callback
 * uses git_tree_entry_dup() for O(1) owned copies instead of re-traversing
 * from root via git_tree_entry_bypath().
 *
 * Memory ownership:
 * - manifest: borrowed, caller retains ownership
 * - path_map: borrowed, caller retains ownership
 * - profile: borrowed, caller retains ownership
 * - custom_prefix: borrowed, can be NULL
 * - error: owned by callback, caller must free on error
 */
struct manifest_build_ctx {
    manifest_t *manifest;       /* Target manifest (modified by callback) */
    size_t capacity;            /* Current entries capacity (updated on growth) */
    hashmap_t *path_map;        /* For O(1) dedup/override detection */
    profile_t *profile;         /* Current profile (borrowed, NULL for tree-based manifests) */
    const char *profile_name;   /* Profile name for entries and error messages */
    const char *custom_prefix;  /* For path_from_storage and entry custom_prefix (can be NULL) */
    arena_t *arena;             /* Arena for string allocations (NULL = heap) */
    error_t *error;             /* Error propagation (set on failure) */
};

/**
 * Tree walk callback that builds manifest entries directly
 *
 * Performance optimization: Instead of collecting paths in pass 1 then
 * re-traversing via git_tree_entry_bypath() in pass 2 (O(N×D)), this
 * callback builds file_entry_t directly using git_tree_entry_dup() (O(N)).
 *
 * Handles:
 * - Metadata file filtering (.dotta/, .bootstrap, etc.)
 * - Storage path to filesystem path conversion
 * - Profile precedence override (higher precedence wins)
 * - Array growth on demand
 * - File type derivation from Git filemode
 *
 * @param root Directory path within tree (empty string for root level)
 * @param entry Git tree entry (NOT owned - must dup for ownership)
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
    if (strcmp(storage_path, ".dottaignore") == 0 ||
        strcmp(storage_path, ".bootstrap") == 0 ||
        strcmp(storage_path, ".gitignore") == 0 ||
        strcmp(storage_path, "README.md") == 0 ||
        strcmp(storage_path, "README") == 0 ||
        str_starts_with(storage_path, ".git/") ||
        str_starts_with(storage_path, ".dotta/")) {
        return 0;  /* Skip, continue walk */
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

    /* Get owned copy of tree entry */
    git_tree_entry *dup_entry = NULL;
    int git_err = git_tree_entry_dup(&dup_entry, entry);
    if (git_err != 0) {
        if (!ctx->arena) free(filesystem_path);
        ctx->error = ERROR(
            ERR_GIT, "Failed to duplicate tree entry: %s",
            git_error_last() ? git_error_last()->message : "unknown"
        );
        return -1;
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
        char *dup_storage_path = ctx->arena
            ? arena_strdup(ctx->arena, storage_path)
            : strdup(storage_path);
        if (!dup_storage_path) {
            if (!ctx->arena) free(filesystem_path);
            git_tree_entry_free(dup_entry);
            ctx->error = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
            return -1;
        }

        /* Free old resources — strings abandoned when arena-backed */
        if (!ctx->arena) {
            free(ctx->manifest->entries[existing_idx].storage_path);
            free(ctx->manifest->entries[existing_idx].filesystem_path);
        }
        git_tree_entry_free(ctx->manifest->entries[existing_idx].entry);

        /* Update with new values */
        ctx->manifest->entries[existing_idx].storage_path = dup_storage_path;
        ctx->manifest->entries[existing_idx].filesystem_path = filesystem_path;
        ctx->manifest->entries[existing_idx].entry = dup_entry;
        ctx->manifest->entries[existing_idx].source_profile = ctx->profile;
        ctx->manifest->entries[existing_idx].profile_name = ctx->profile_name;
        ctx->manifest->entries[existing_idx].custom_prefix = ctx->custom_prefix;

        /* Update type from overriding entry's filemode (may differ between profiles) */
        switch (git_tree_entry_filemode(dup_entry)) {
            case GIT_FILEMODE_BLOB_EXECUTABLE:
                ctx->manifest->entries[existing_idx].type = STATE_FILE_EXECUTABLE;
                break;
            case GIT_FILEMODE_LINK:
                ctx->manifest->entries[existing_idx].type = STATE_FILE_SYMLINK;
                break;
            default:
                ctx->manifest->entries[existing_idx].type = STATE_FILE_REGULAR;
                break;
        }

        /* Other VWD fields remain NULL/0 (not populated for Git-based manifests).
         * The existing entry already has these initialized from initial creation. */
    } else {
        /* Add new entry - grow array if needed */
        if (ctx->manifest->count >= ctx->capacity) {
            if (ctx->capacity > SIZE_MAX / 2) {
                if (!ctx->arena) free(filesystem_path);
                git_tree_entry_free(dup_entry);
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
                git_tree_entry_free(dup_entry);
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
            git_tree_entry_free(dup_entry);
            ctx->error = ERROR(ERR_MEMORY, "Failed to duplicate storage path");
            return -1;
        }

        /* Initialize entry */
        file_entry_t *new_entry = &ctx->manifest->entries[ctx->manifest->count];
        new_entry->storage_path = dup_storage_path;
        new_entry->filesystem_path = filesystem_path;
        new_entry->entry = dup_entry;
        new_entry->source_profile = ctx->profile;
        new_entry->profile_name = ctx->profile_name;
        new_entry->custom_prefix = ctx->custom_prefix;

        /* Initialize VWD expected state cache to NULL/0
         *
         * These fields are only populated when manifest is built from state database.
         * For manifests built from Git (this callback), they remain NULL/0 except
         * for the type field which we derive from the Git tree entry's filemode.
         *
         * IMPORTANT: After realloc(), new memory is NOT zero-initialized. */
        new_entry->old_profile = NULL;
        new_entry->git_oid = NULL;
        new_entry->blob_oid = NULL;

        /* Derive type from Git filemode (executable bit detection) */
        switch (git_tree_entry_filemode(dup_entry)) {
            case GIT_FILEMODE_BLOB_EXECUTABLE:
                new_entry->type = STATE_FILE_EXECUTABLE;
                break;
            case GIT_FILEMODE_LINK:
                new_entry->type = STATE_FILE_SYMLINK;
                break;
            default:
                /* Should never happen (we filtered to blobs above) */
                new_entry->type = STATE_FILE_REGULAR;
                break;
        }

        new_entry->mode = 0;
        new_entry->owner = NULL;
        new_entry->group = NULL;
        new_entry->encrypted = false;
        new_entry->deployed_at = 0;
        new_entry->stat_cache = STAT_CACHE_UNSET;

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
            git_tree_entry_free(new_entry->entry);
            new_entry->entry = NULL;
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
    struct walk_data data = { 0 };
    data.paths = string_array_new(0);
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

    /* Load profile */
    profile_t *profile = NULL;
    error_t *err = profile_load(repo, profile_name, &profile);
    if (err) {
        return error_wrap(err, "Failed to load profile");
    }

    /* Load tree if not loaded (lazy loading) */
    err = profile_load_tree(repo, profile);
    if (err) {
        profile_free(profile);
        return error_wrap(err, "Failed to load tree");
    }

    /* Check for custom/ directory using O(log k) lookup */
    const git_tree_entry *entry = git_tree_entry_byname(profile->tree, "custom");
    if (entry) {
        /* Verify it's a tree (directory), not a blob (file) */
        git_object_t type = git_tree_entry_type(entry);
        *out_has_custom = (type == GIT_OBJECT_TREE);
    }

    profile_free(profile);

    return NULL;
}

/**
 * Build manifest from profiles
 *
 * Performance: O(N) where N is total files across all profiles.
 * Uses manifest_build_callback for single-pass tree traversal with
 * git_tree_entry_dup() instead of two-pass with git_tree_entry_bypath().
 */
error_t *profile_build_manifest(
    git_repository *repo,
    profile_list_t *profiles,
    arena_t *arena,
    manifest_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
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
        profile_t *profile = &profiles->profiles[i];

        /* Load tree (lazy loading - cached in profile struct) */
        err = profile_load_tree(repo, profile);
        if (err) {
            err = error_wrap(
                err, "Failed to load tree for profile '%s'",
                profile->name
            );
            goto cleanup;
        }

        /* Build manifest entries via single-pass tree traversal
         *
         * The callback captures owned tree entries with git_tree_entry_dup(),
         * converts paths, handles precedence override, and populates
         * file_entry_t directly—all in O(N) time. */
        struct manifest_build_ctx ctx = {
            .manifest      = manifest,
            .capacity      = capacity,
            .path_map      = path_map,
            .profile       = profile,
            .profile_name  = profile->name,
            .custom_prefix = profile->custom_prefix,
            .arena         = arena,
            .error         = NULL
        };

        err = gitops_tree_walk(profile->tree, manifest_build_callback, &ctx);
        if (err || ctx.error) {
            err = ctx.error ? ctx.error : err;
            err = error_wrap(
                err, "Failed to build manifest for profile '%s'",
                profile->name
            );
            goto cleanup;
        }

        /* Update capacity (may have grown during callback) */
        capacity = ctx.capacity;
    }

    /* Success - transfer index ownership to manifest */
    manifest->index = path_map;
    manifest->arena_backed = (arena != NULL);
    *out = manifest;

    return NULL;

cleanup:
    hashmap_free(path_map, NULL);
    if (err) manifest_free(manifest);

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
    for (size_t i = 0; i < all_branches->count; i++) {
        const char *branch_name = all_branches->items[i];

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
        for (size_t j = 0; j < files->count; j++) {
            const char *storage_path = files->items[j];

            /* Get or create profile list for this storage path */
            string_array_t *profile_list = hashmap_get(index, storage_path);
            if (!profile_list) {
                profile_list = string_array_new(0);
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
        hashmap_free(index, string_array_free_cb);
    }

    return err;
}

error_t *profile_discover_file(
    git_repository *repo,
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
         * Returns the single owning profile (precedence already resolved). */
        state_t *state = NULL;
        err = state_load(repo, &state);
        if (err) {
            return error_wrap(err, "Failed to load state for file discovery");
        }

        state_file_entry_t *entry = NULL;
        err = state_get_file_by_storage(state, storage_path, &entry);

        if (err) {
            state_free(state);
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
            state_free(state);
            return ERROR(ERR_MEMORY, "Failed to allocate profile array");
        }

        err = string_array_push(profiles, entry->profile);
        state_free_entry(entry);
        state_free(state);

        if (err) {
            string_array_free(profiles);
            return err;
        }

        *out_profiles = profiles;

        return NULL;
    }

    /* Branch scan: O(M×P) via profile_build_file_index().
     * Returns ALL profiles containing the file across all local branches. */
    hashmap_t *index = NULL;
    err = profile_build_file_index(repo, NULL, &index);
    if (err) {
        return error_wrap(
            err, "Failed to build profile index for file discovery"
        );
    }

    string_array_t *matches = hashmap_get(index, storage_path);

    if (!matches || matches->count == 0) {
        hashmap_free(index, string_array_free_cb);
        return ERROR(
            ERR_NOT_FOUND, "File '%s' not found in any profile",
            storage_path
        );
    }

    /* Clone the result — hashmap owns the original */
    string_array_t *result = string_array_new(matches->count);
    if (!result) {
        hashmap_free(index, string_array_free_cb);
        return ERROR(ERR_MEMORY, "Failed to allocate profile matches");
    }

    error_t *clone_err = string_array_clone(matches, result);
    hashmap_free(index, string_array_free_cb);

    if (clone_err) {
        string_array_free(result);
        return clone_err;
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

    /* Own copies of profile name and custom prefix for entry borrowing.
     * Entries set profile_name and custom_prefix to these pointers —
     * manifest lifetime guarantees they remain valid until manifest_free(). */
    manifest->owned_profile_name = strdup(profile_name);
    if (!manifest->owned_profile_name) {
        err = ERROR(ERR_MEMORY, "Failed to duplicate profile name");
        goto cleanup;
    }
    if (custom_prefix) {
        manifest->owned_custom_prefix = strdup(custom_prefix);
        if (!manifest->owned_custom_prefix) {
            err = ERROR(ERR_MEMORY, "Failed to duplicate custom prefix");
            goto cleanup;
        }
    }

    /* Build manifest entries via single-pass tree traversal
     *
     * The callback captures owned tree entries with git_tree_entry_dup(),
     * converts paths, and populates file_entry_t directly—all in O(N) time.
     *
     * No source_profile for tree-based manifests — entries have pre-populated
     * tree entries from git_tree_entry_dup() and never need lazy loading. */
    struct manifest_build_ctx ctx = {
        .manifest      = manifest,
        .capacity      = capacity,
        .path_map      = path_map,
        .profile       = NULL,
        .profile_name  = manifest->owned_profile_name,
        .custom_prefix = manifest->owned_custom_prefix,
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
 * Free profile
 */
void profile_free(profile_t *profile) {
    if (!profile) {
        return;
    }

    free(profile->name);
    free(profile->custom_prefix);
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

    if (list->profiles) {
        for (size_t i = 0; i < list->count; i++) {
            profile_t *profile = &list->profiles[i];
            free(profile->name);
            free(profile->custom_prefix);
            if (profile->ref) {
                git_reference_free(profile->ref);
            }
            if (profile->tree) {
                git_tree_free(profile->tree);
            }
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
        /* Free Git tree entry (always libgit2-allocated, never arena) */
        if (manifest->entries[i].entry) {
            git_tree_entry_free(manifest->entries[i].entry);
        }

        /* Skip string field frees when arena-backed */
        if (!manifest->arena_backed) {
            free(manifest->entries[i].storage_path);
            free(manifest->entries[i].filesystem_path);
            free(manifest->entries[i].old_profile);
            free(manifest->entries[i].git_oid);
            free(manifest->entries[i].blob_oid);
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

    /* Free owned strings (used by tree-based manifests, NULL otherwise) */
    free(manifest->owned_profile_name);
    free(manifest->owned_custom_prefix);

    free(manifest);
}
