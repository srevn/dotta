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

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/metadata.h"
#include "core/state.h"
#include "infra/mount.h"
#include "sys/gitops.h"
#include "sys/stats.h"

/* Storage paths composed during a tree walk. A profile path is a storage label
 * plus what a mount-relative path can be, and every writer validated it long
 * before it reached Git; the walks below treat an overrun as corruption. */
#define PROFILE_TREE_PATH_MAX 1024

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
 * Appends the base match (exact prefix) and its sub-matches (prefix/variant,
 * one level deep only) to `out`, in the order `available` holds them. Selection
 * only: the ordering is profile_detect's, which sorts everything it selected
 * with profile_order once the three steps have run.
 *
 * @param available Available branch names to match against
 * @param prefix Prefix to match (e.g., "darwin", "hosts/myhost")
 * @param out Output array to append matches to
 * @return Error or NULL on success
 */
static error_t *match_hierarchical_profiles(
    const string_array_t *available,
    const char *prefix,
    string_array_t *out
) {
    size_t prefix_len = strlen(prefix);

    for (size_t i = 0; i < available->count; i++) {
        const char *profile = available->items[i];

        /* Check if branch starts with prefix */
        if (!str_starts_with(profile, prefix)) {
            continue;
        }

        const char *suffix = profile + prefix_len;
        error_t *err = NULL;

        if (suffix[0] == '\0') {
            /* Exact match: base profile */
            err = string_array_push(out, profile);
        } else if (suffix[0] == '/') {
            const char *variant = suffix + 1;
            /* One level deep only: non-empty variant with no further '/' */
            if (variant[0] != '\0' && strchr(variant, '/') == NULL) {
                err = string_array_push(out, profile);
            }
        }

        if (err) {
            return err;
        }
    }

    return NULL;
}

/**
 * The layer a profile name stands in — see profile_order.
 */
static int profile_rank(const char *name) {
    if (strcmp(name, "global") == 0) return 0;
    if (str_starts_with(name, "hosts/")) return 2;
    return 1;
}

static int profile_order_cmp(const void *a, const void *b) {
    const char *x = *(const char *const *) a;
    const char *y = *(const char *const *) b;

    int rx = profile_rank(x), ry = profile_rank(y);
    if (rx != ry) {
        return rx < ry ? -1 : 1;
    }

    return strcmp(x, y);
}

void profile_order(string_array_t *names) {
    if (!names || names->count < 2) {
        return;
    }

    qsort(names->items, names->count, sizeof(char *), profile_order_cmp);
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

        err = match_hierarchical_profiles(
            available_branches,
            os_name,
            profiles
        );
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
        int ret = snprintf(
            host_prefix, sizeof(host_prefix), "hosts/%s", hostname
        );
        if (ret >= 0 && (size_t) ret < sizeof(host_prefix)) {
            err = match_hierarchical_profiles(
                available_branches,
                host_prefix,
                profiles
            );
            if (err) {
                /* Non-fatal: skip host profiles if detection fails */
                error_free(err);
                err = NULL;
            }
        }
    }
    /* Non-fatal: continue if gethostname() fails */

    /* The three steps above answer *which* names this machine layers; this is
     * the order they layer in. Each step appends in branch-listing order, so
     * the one sort is what makes the result precedence — the module's one answer,
     * shared with every caller that already holds its set. */
    profile_order(profiles);

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
 * Build a per-machine mount table from state
 *
 * State-aware adapter that materializes enabled_profiles' (name, target) rows
 * into mount_t entries and delegates the augmentation (HOME, canonical HOME,
 * root sentinel) to mount_table_build. Single chokepoint for "what does the mount
 * table look like for this command?".
 *
 * Name and target are read from the state row cache for the call only — the table
 * copies every string it keeps — so the handle is a value: the topology the rows
 * described at the instant it was built, readable for the arena's lifetime whatever
 * enabled_profiles mutation follows.
 *
 * A state with no database has no rows and yields the bare table (HOME and the
 * root sentinel). A row read that fails on an opened database is an error and
 * propagates: a bare table in its place would classify every input as home/ or
 * root/ and resolve no custom/ path, silently.
 */
error_t *profile_build_mount_table(
    const state_t *state,
    arena_t *arena,
    mount_table_t **out
) {
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    const state_profile_entry_t *entries = NULL;
    size_t count = 0;
    error_t *err = state_peek_profiles(state, &entries, &count);
    if (err) {
        return error_wrap(err, "Failed to read enabled profiles");
    }

    mount_t *mounts = NULL;
    if (count > 0) {
        mounts = arena_calloc(arena, count, sizeof(*mounts));
        if (!mounts) {
            return ERROR(ERR_MEMORY, "Failed to allocate mounts");
        }
        for (size_t i = 0; i < count; i++) {
            mounts[i] = (mount_t){
                .profile = entries[i].name,
                .target = entries[i].target
            };
        }
    }

    return mount_table_build(arena, mounts, count, out);
}

/**
 * Validate state profiles and filter out non-existent ones
 *
 * Checks that all profiles listed in state exist as local branches. Warns about
 * missing profiles and filters them out.
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
 * Lightweight name-only resolution — no Git ref resolution or tree loading. Reads
 * enabled profiles from the borrowed state handle, validates that each still
 * exists as a branch, and returns the validated names. Warns on stderr about
 * missing profiles.
 *
 * @param repo Repository (must not be NULL)
 * @param state Borrowed state handle (must not be NULL)
 * @param out Validated profile names (must not be NULL, caller frees)
 * @return Error (ERR_NOT_FOUND if no enabled profiles) or NULL on success
 */
error_t *profile_resolve_enabled(
    git_repository *repo,
    const state_t *state,
    string_array_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(out);

    error_t *err = NULL;
    string_array_t *state_profiles = NULL;
    string_array_t *valid_profiles = NULL;
    string_array_t *missing_profiles = NULL;

    /* Get profile names from state */
    err = state_get_profiles(state, &state_profiles);
    if (err) {
        error_free(err);
        return ERROR(ERR_NOT_FOUND, "No enabled profiles found");
    }

    if (!state_profiles || state_profiles->count == 0) {
        string_array_free(state_profiles);
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
     * without access to an output_t. This is consistent with other core modules
     * (deploy.c, workspace.c) that also write diagnostic warnings to stderr.
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
        return ERROR(ERR_NOT_FOUND, "No enabled profiles found");
    }

    /* Success */
    *out = valid_profiles;
    string_array_free(state_profiles);

    return NULL;

cleanup:
    string_array_free(valid_profiles);
    string_array_free(missing_profiles);
    string_array_free(state_profiles);

    return err;
}

/**
 * Resolve CLI profile names for operation filtering
 *
 * Lightweight validation: checks branch existence without resolving Git refs or
 * loading profile objects.
 */
error_t *profile_resolve_filter(
    git_repository *repo,
    char *const *cli_profiles,
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
                "Hint: Run 'dotta profile list' for available profiles",
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
 * Ensures CLI filter only references profiles that are actually enabled in the
 * workspace.
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
 * Is this path inside a profile branch dotta's own bookkeeping?
 */
bool profile_is_repo_metadata(const char *storage_path) {
    if (!storage_path) {
        return false;
    }

    return strcmp(storage_path, ".dottaignore") == 0 ||
           strcmp(storage_path, ".bootstrap") == 0 ||
           strcmp(storage_path, ".gitignore") == 0 ||
           strcmp(storage_path, "README.md") == 0 ||
           strcmp(storage_path, "README") == 0 ||
           str_starts_with(storage_path, ".git/") ||
           str_starts_with(storage_path, ".dotta/");
}

/**
 * Compose a tree entry's storage path, and say whether the walk should see it
 *
 * Every walk over a profile tree below asks an entry the same three things: is
 * it a blob, what is its path within the branch, and is that path tracked content
 * rather than bookkeeping. Answered once here, so each walk differs only in what
 * it does with a path it accepts.
 *
 * `out_err` receives the truncation error and nothing else — an entry that is
 * simply not content leaves it untouched, which is what lets a caller read "false
 * with no error" as "skip this entry, keep walking".
 *
 * @param root Walk root as libgit2 supplies it ("" or "dir/")
 * @param entry Tree entry (must not be NULL)
 * @param buf Receives the storage path when the entry is accepted
 * @param size Size of buf
 * @param out_err Receives a truncation error (must not be NULL)
 * @return true when buf holds a content path the walk should process
 */
static bool tree_entry_content_path(
    const char *root,
    const git_tree_entry *entry,
    char *buf,
    size_t size,
    error_t **out_err
) {
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return false;
    }

    const char *name = git_tree_entry_name(entry);
    int ret;

    if (root && root[0] != '\0') {
        ret = snprintf(buf, size, "%s%s", root, name);
    } else {
        ret = snprintf(buf, size, "%s", name);
    }

    if (ret < 0 || (size_t) ret >= size) {
        *out_err = ERROR(
            ERR_INTERNAL, "Path exceeds maximum length: %s%s",
            root ? root : "", name
        );
        return false;
    }

    return !profile_is_repo_metadata(buf);
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

    char storage_path[PROFILE_TREE_PATH_MAX];
    if (!tree_entry_content_path(
        root, entry, storage_path, sizeof(storage_path), &data->error
        )) {
        return data->error ? -1 : 0;
    }

    /* Add to array */
    error_t *err = string_array_push(data->paths, storage_path);
    if (err) {
        data->error = err;
        return -1;  /* Stop walk */
    }

    return 0;
}

/**
 * List deployable files in a Git tree
 */
error_t *profile_list_tree_files(
    git_tree *tree,
    string_array_t **out
) {
    CHECK_NULL(tree);
    CHECK_NULL(out);

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
 * Tree walk data for the branch statistics
 */
struct stats_walk_data {
    git_odb *odb;        /* Held for the walk: one handle, N header reads */
    size_t file_count;
    size_t total_size;
    error_t *error;
};

/**
 * Tree walk callback: count content blobs and accumulate their bytes
 */
static int stats_walk_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct stats_walk_data *data = (struct stats_walk_data *) payload;

    char storage_path[PROFILE_TREE_PATH_MAX];
    if (!tree_entry_content_path(
        root, entry, storage_path, sizeof(storage_path), &data->error
        )) {
        return data->error ? -1 : 0;
    }

    size_t size = 0;
    error_t *err = stats_get_blob_size_with_odb(
        data->odb, git_tree_entry_id(entry), &size
    );
    if (err) {
        data->error = err;
        return -1;
    }

    if (data->total_size > SIZE_MAX - size) {
        data->error = ERROR(
            ERR_INTERNAL, "Profile size exceeds maximum representable value"
        );
        return -1;
    }

    data->file_count++;
    data->total_size += size;

    return 0;
}

/**
 * Count what a profile branch holds
 */
error_t *profile_get_stats(
    git_repository *repo,
    const char *profile,
    profile_stats_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    *out = (profile_stats_t){ 0 };

    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for profile '%s'", profile
        );
    }

    /* The files: one walk, one ODB handle, sizes read from the object headers. */
    git_odb *odb = NULL;
    int git_err = git_repository_odb(&odb, repo);
    if (git_err < 0) {
        git_tree_free(tree);
        return error_from_git(git_err);
    }

    struct stats_walk_data data = {
        .odb        = odb,
        .file_count = 0,
        .total_size = 0,
        .error      = NULL
    };

    err = gitops_tree_walk(tree, stats_walk_callback, &data);
    git_odb_free(odb);

    if (err || data.error) {
        /* Prefer the callback's error — it names the entry that failed */
        if (data.error) {
            error_free(err);
            err = data.error;
        }
        git_tree_free(tree);
        return error_wrap(
            err, "Failed to read statistics for profile '%s'", profile
        );
    }

    out->file_count = data.file_count;
    out->total_size = data.total_size;

    /* The directories: the branch's own metadata, the same source the view's
     * claim routine reads. No metadata.json is no claim, not a failure — every
     * other load error is real and propagates. */
    metadata_t *metadata = NULL;
    err = metadata_load_from_tree(repo, tree, profile, &metadata);
    if (err) {
        git_tree_free(tree);
        if (error_code(err) == ERR_NOT_FOUND) {
            error_free(err);
            return NULL;
        }
        return error_wrap(
            err, "Failed to load metadata for profile '%s'", profile
        );
    }

    size_t item_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);
    for (size_t i = 0; i < item_count; i++) {
        /* The managed set alone: an ancestor claim is the way to content, not
         * content the profile tracks, and counting the spine would inflate the
         * number the screens call "directories" past anything the user named. */
        if (items[i]->kind != PATH_KIND_DIRECTORY || !items[i]->tracked) continue;

        /* A path is a tree or a blob: a DIRECTORY item where the tree holds a
         * blob is stale metadata, and the tree is the content authority — the
         * same rule manifest_claim_tree applies when the profile is enabled. */
        git_tree_entry *held = NULL;
        if (git_tree_entry_bypath(&held, tree, items[i]->key) == 0) {
            bool is_blob = git_tree_entry_type(held) == GIT_OBJECT_BLOB;
            git_tree_entry_free(held);
            if (is_blob) continue;
        }

        out->directory_count++;
    }

    metadata_free(metadata);
    git_tree_free(tree);

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

    /* Check for custom/ directory using O(log k) lookup. git_tree_entry_byname
     * returns a pointer owned by the tree — must read before git_tree_free. */
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
 * eliminating the intermediate string_array_t that the old approach needed per
 * branch (each path was strdup'd into the array, strdup'd again into the hashmap,
 * then the array copy was freed).
 */
static int file_index_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct file_index_ctx *ctx = (struct file_index_ctx *) payload;

    char storage_path[PROFILE_TREE_PATH_MAX];
    if (!tree_entry_content_path(
        root, entry, storage_path, sizeof(storage_path), &ctx->error
        )) {
        return ctx->error ? -1 : 0;
    }

    /* Get or create profile list for this path */
    string_array_t *profiles = hashmap_get(ctx->index, storage_path);
    if (!profiles) {
        profiles = string_array_new(0);
        if (!profiles) {
            ctx->error = ERROR(
                ERR_MEMORY, "Failed to create profile list for file"
            );
            ctx->fatal = true;
            return -1;
        }

        error_t *err = hashmap_set(ctx->index, storage_path, profiles);
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
 * Walks each branch tree directly into a hashmap that maps storage paths to lists
 * of profile names. Uses gitops_load_branch_tree for direct tree loading, and
 * populates the hashmap during the tree walk to eliminate intermediate string
 * arrays.
 *
 * Complexity: O(M×P) where M = profile count, P = avg files per profile. Lookups
 * are then O(1) instead of O(M×GitOps).
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
    const char *storage_path,
    string_array_t **out_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_profiles);

    error_t *err = NULL;
    *out_profiles = NULL;

    /* Targeted branch scan: O(M×D) where D = path depth in tree. Checks each
     * branch for the specific file instead of building the full file index
     * (profile_build_file_index walks every tree, O(M×P)). */
    string_array_t *all_branches = NULL;
    err = gitops_list_branches(repo, &all_branches);
    if (err) {
        return error_wrap(
            err, "Failed to list branches for file discovery"
        );
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

        git_tree *tree = NULL;
        err = gitops_load_branch_tree(repo, branch, &tree, NULL);
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
