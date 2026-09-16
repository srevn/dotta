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
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/state.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/stats.h"

/* Storage paths composed during a tree walk. A profile path is a storage label
 * plus what a mount-relative path can be, and every writer validated it long
 * before it reached Git; the walks below treat an overrun as corruption. */
#define PROFILE_TREE_PATH_MAX 1024

/**
 * Is there a profile of this name here, or refuse
 */
error_t *profile_require(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    bool exists = false;
    RETURN_IF_ERROR(gitops_branch_exists(repo, name, &exists));
    if (!exists) {
        return ERROR(
            ERR_NOT_FOUND, "Profile '%s' doesn't exist locally\n"
            "Hint: Run 'dotta profile list' for the local profiles, or "
            "'dotta profile fetch %s' to bring it from the remote",
            name, name
        );
    }

    return NULL;
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
     * the order they are seeded in. Each step appends in branch-listing order,
     * so the one sort is what makes the answer the convention's — the same sort
     * every --all runs over its own set. */
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

        bool exists = false;
        err = gitops_branch_exists(repo, profile, &exists);
        if (err) goto cleanup;

        if (exists) {
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
 * Compose a tree entry's storage path, and say whether the walk should see it
 *
 * Every walk over a profile tree below asks an entry the same three things: is
 * it a blob, does it stand under a storage label, and what is its path within
 * the branch. Answered once here, so each walk differs only in what it does with
 * a path it accepts.
 *
 * `out_err` receives corruption and nothing else — a truncated join, or a path
 * whose shape no mount can place. An entry that is simply not content leaves it
 * untouched, which is what lets a caller read "false with no error" as "skip
 * this entry, keep walking".
 *
 * @param root Walk root as libgit2 supplies it ("" or "dir/")
 * @param entry Tree entry (must not be NULL)
 * @param buf Receives the storage path when the entry is accepted
 * @param size Size of buf
 * @param out_err Receives a corruption error (must not be NULL)
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

    /* The content gate: a managed path lives under a storage label, so the walk's
     * own root is the whole test (core/manifest.c reads it the same way). A blob
     * at the branch root, or beneath a tree no label names, is not content —
     * dotta's own files sit there, and so does whatever else a hand or a tool
     * left beside them. */
    if (!label_prefixes(root)) {
        return false;
    }

    const char *name = git_tree_entry_name(entry);

    /* The path within the branch is the walk root and the entry's name: libgit2
     * supplies the root as "" or "dir/", and an empty one is the name alone. */
    int ret = snprintf(buf, size, "%s%s", root ? root : "", name);

    if (ret < 0 || (size_t) ret >= size) {
        *out_err = ERROR(
            ERR_INTERNAL, "Path exceeds maximum length: %s%s",
            root ? root : "", name
        );
        return false;
    }

    /* The entry name is Git's, not this machine's. A tree can name a subtree
     * "..", and every consumer of a path from here joins it onto a root's spelling
     * (infra/mount.h mount_resolve) on the strength of its having been validated
     * where it was written — which holds for a branch this machine authored and
     * not for one that arrived by clone, sync or foreign push. So the shape is
     * checked where the tree is read, exactly as the view checks its own
     * (core/manifest.c manifest_claim_blob). Malformed here is corruption, not
     * an entry to skip: a walk that dropped it silently would leave the caller
     * a listing it cannot place and call it complete. */
    error_t *shape = label_validate_storage(buf);
    if (shape) {
        *out_err = shape;
        return false;
    }

    return true;
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
    const git_tree *tree,
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
    if (data.error) {
        /* The callback's error names the entry that failed; the walk's own is
         * the abort libgit2 stamped in answer to it — an echo of this call's
         * own decision, which names nothing and is freed rather than reported
         * in its place. */
        error_free(err);
        err = data.error;
    }
    if (err) {
        string_array_free(data.paths);
        return err;
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
     * claim routine reads. A tree without a sheet loads as an empty one — no
     * claim, so nothing counted below — and every load error is real and
     * propagates. */
    metadata_t *metadata = NULL;
    err = metadata_load_from_tree(repo, tree, profile, &metadata);
    if (err) {
        git_tree_free(tree);
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
         * same rule the view's directory pass applies when the profile is enabled
         * (core/manifest.c manifest_contribute), asked there of the sheet at
         * the blob its own walk met rather than of the ODB.
         *
         * Three answers, not two: the entry is there, it is absent, or the tree
         * will not read — and an object that will not load is corruption, never
         * an absence, so the count refuses rather than counts a directory the
         * branch may not hold. */
        git_tree_entry *entry = NULL;
        int rc = git_tree_entry_bypath(&entry, tree, items[i]->key);
        if (rc == 0) {
            bool is_blob = git_tree_entry_type(entry) == GIT_OBJECT_BLOB;
            git_tree_entry_free(entry);
            if (is_blob) continue;
        } else if (rc != GIT_ENOTFOUND) {
            metadata_free(metadata);
            git_tree_free(tree);
            return error_wrap(
                error_from_git(rc), "Failed to read '%s' in profile '%s'",
                items[i]->key, profile
            );
        }

        out->directory_count++;
    }

    metadata_free(metadata);
    git_tree_free(tree);

    return NULL;
}

/**
 * Does this profile's branch need a deployment target?
 *
 * The table binds nothing on purpose — HOME and the sentinel alone — so a custom/
 * claim has nowhere to go and is recorded, which is the answer. The view is built
 * to read one count off it and freed before the arena that holds it.
 */
error_t *profile_needs_target(
    git_repository *repo,
    const char *profile,
    bool *needs_target
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(needs_target);

    *needs_target = false;

    arena_t *scratch = arena_create(0);
    if (!scratch) {
        return ERROR(ERR_MEMORY, "Failed to allocate the branch's view");
    }

    mount_table_t *mounts = NULL;
    manifest_t *view = NULL;
    error_t *err = mount_table_build(scratch, NULL, 0, &mounts);
    if (!err) err = manifest_build_branch(repo, profile, mounts, scratch, &view);
    if (!err) *needs_target = manifest_unbound(view).count > 0;

    manifest_free(view);                 /* reads the arena: before the destroy */
    arena_destroy(scratch);
    return err;
}

/**
 * By location, then by profile
 *
 * Equal locations sort together, so the rows standing at one location form a
 * contiguous run; the profile breaks the tie, and the order is total because
 * one branch places one row per location. The name would not be: two branches
 * can hold one name at one location.
 */
static int index_order(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;

    int by_location = strcmp((*ra)->filesystem_path, (*rb)->filesystem_path);

    return by_location ? by_location : strcmp((*ra)->profile, (*rb)->profile);
}

/**
 * location → the claims every local branch but `exclude` places there
 */
error_t *profile_build_location_index(
    git_repository *repo,
    const mount_table_t *mounts,
    const char *exclude,
    arena_t *arena,
    hashmap_t **out_index
) {
    CHECK_NULL(repo);
    CHECK_NULL(mounts);
    CHECK_NULL(arena);
    CHECK_NULL(out_index);

    *out_index = NULL;

    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (err) return err;

    /* Every placed row of every branch, gathered before any of it is keyed: the
     * rows are the arena's and outlive the views they came from. */
    ptr_array_t rows PTR_ARRAY_AUTO = { 0 };
    for (size_t i = 0; i < branches->count && !err; i++) {
        if (exclude && strcmp(branches->items[i], exclude) == 0) continue;

        manifest_t *view = NULL;
        err = manifest_build_branch(
            repo, branches->items[i], mounts, arena, &view
        );
        if (err) break;

        manifest_rows_t placed = manifest_rows(view);
        for (size_t j = 0; j < placed.count && !err; j++) {
            err = ptr_array_push(&rows, placed.entries[j]);
        }
        manifest_free(view);
    }
    string_array_free(branches);
    if (err) return err;

    /* The runs, typed once: a ptr_array holds void *, and every read below is a
     * row's location, its profile or its name. */
    const manifest_row_t **sorted = (const manifest_row_t **) rows.items;
    qsort(sorted, rows.count, sizeof(*sorted), index_order);

    hashmap_t *index = hashmap_borrow(rows.count);
    if (!index) {
        return ERROR(ERR_MEMORY, "Failed to create the location index");
    }

    for (size_t i = 0; i < rows.count && !err;) {
        const char *location = sorted[i]->filesystem_path;

        size_t n = 0;
        while (i + n < rows.count &&
            strcmp(sorted[i + n]->filesystem_path, location) == 0) n++;

        profile_claim_t *entries = arena_calloc(arena, n, sizeof(*entries));
        profile_claims_t *claims = arena_calloc(arena, 1, sizeof(*claims));
        if (!entries || !claims) {
            err = ERROR(ERR_MEMORY, "Failed to allocate the claims at a location");
            break;
        }
        for (size_t g = 0; g < n; g++) {
            entries[g] = (profile_claim_t){
                sorted[i + g]->profile, sorted[i + g]->storage_path
            };
        }
        *claims = (profile_claims_t){ entries, n };

        /* The key is the row's own string — hashmap_borrow keeps the pointer
         * and compares by content, and the row outlives the map. */
        err = hashmap_set(index, location, claims);
        i += n;
    }
    if (err) {
        hashmap_free(index, NULL);
        return err;
    }

    *out_index = index;

    return NULL;
}

/**
 * The name `profile` has for `location` in `tree`
 */
error_t *profile_claim_name(
    git_repository *repo,
    const git_tree *tree,
    const mount_table_t *mounts,
    const char *profile,
    const char *location,
    arena_t *arena,
    const char **out_storage
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(mounts);
    CHECK_NULL(profile);
    CHECK_NULL(location);
    CHECK_NULL(arena);
    CHECK_NULL(out_storage);

    *out_storage = NULL;

    manifest_t *view = NULL;
    error_t *err = manifest_build_tree(repo, tree, profile, mounts, arena, &view);
    if (err) return err;

    /* The claim standing there, before the name one would take: a derived claim
     * is held and names nothing, so the ascent climbs past it and would answer
     * a name the branch never held. */
    const manifest_row_t *row = manifest_lookup_claim(view, profile, location);
    if (row) {
        *out_storage = row->storage_path;   /* the arena's: outlives the view */
        manifest_free(view);
        return NULL;
    }

    /* Nothing stands there, so the name the profile would give the place — NULL
     * at a root of its own namespace, and the refusal below is that. */
    err = manifest_name(view, profile, location, NULL, arena, out_storage);
    manifest_free(view);
    if (err) return err;

    if (!*out_storage) {
        /* A root of the profile with no claim on it, and the table says which:
         * the namer's last rung is the deepest root of this very table, asker
         * and location (core/manifest.c manifest_ascend), and it answers NULL
         * there and nowhere else — which is mount_root_at's own definition. */
        const mount_root_t *root = mount_root_at(mounts, profile, location);
        char buf[MOUNT_NOUN_MAX];
        return ERROR(
            ERR_INVALID_ARG, "'%s' is %s: name what is inside it", location,
            mount_root_describe(root, buf, sizeof(buf))
        );
    }

    return NULL;
}

/**
 * The claim `branch` stands at `location`, or NULL
 *
 * The branch's own view of its tip under this machine's table, so the name is
 * the branch's — a binding's, or one kept from before the binding — and never
 * one this machine composed. The view is strict (core/manifest.h): a sheet that
 * will not load is this branch's error, which is the whole cost a location argument
 * carries over a name.
 *
 * The answer is the row's own string, the arena's, and outlives the view freed
 * here.
 */
static error_t *claim_in_view(
    git_repository *repo,
    const char *branch,
    const mount_table_t *mounts,
    const char *location,
    arena_t *arena,
    const char **out_storage
) {
    *out_storage = NULL;

    manifest_t *view = NULL;
    error_t *err = manifest_build_branch(repo, branch, mounts, arena, &view);
    if (err) return err;

    const manifest_row_t *row = manifest_lookup_claim(view, branch, location);
    if (row) {
        *out_storage = row->storage_path;
    }

    manifest_free(view);
    return NULL;
}

/**
 * The claim `branch` holds under `storage_path`, or NULL
 *
 * A name is Git's key, so one lookup in the branch's tip answers it — a subtree
 * counts, as a name has always counted. Three answers read as three: an
 * intermediate object that will not load is a failure to read, never an absence.
 * No sheet, no table, no view — the tolerant half of the split above.
 */
static error_t *claim_in_tree(
    git_repository *repo,
    const char *branch,
    const char *storage_path,
    const char **out_storage
) {
    *out_storage = NULL;

    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, branch, &tree, NULL);
    if (err) {
        return error_wrap(err, "Failed to load tree for profile '%s'", branch);
    }

    git_tree_entry *entry = NULL;
    int rc = git_tree_entry_bypath(&entry, tree, storage_path);
    git_tree_free(tree);

    if (rc == 0) {
        git_tree_entry_free(entry);
        *out_storage = storage_path;
        return NULL;
    }
    if (rc != GIT_ENOTFOUND) {
        return error_wrap(
            error_from_git(rc), "Failed to read profile '%s'", branch
        );
    }

    return NULL;
}

/**
 * Every claim standing at what the user named, across the local branches
 */
error_t *profile_discover_claims(
    git_repository *repo,
    const mount_table_t *mounts,
    const path_input_t *arg,
    arena_t *arena,
    profile_claims_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(mounts);
    CHECK_NULL(arg);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = (profile_claims_t){ 0 };

    /* Two keys search, and the third is a caller's bug — said here, above the
     * enumeration, as mount_resolve states its own (infra/mount.c). This looks
     * for a claim standing at a key, and a label is the namespace itself: no
     * branch stands at one, and every branch holds a tree under it, so a search
     * would answer "held by all" to a question nobody asked. revert, the sole
     * caller, refuses a label at its own door (cmds/revert.c).
     *
     * Above the enumeration and not inside it, because a store with no branches
     * runs no loop: a door per branch would let a label reach the not-found
     * sentence below, which reads a key's member on the word of the tag. */
    switch (arg->key) {
        case PATH_KEY_LOCATION:
        case PATH_KEY_STORAGE:
            break;

        case PATH_KEY_LABEL:
            return ERROR(
                ERR_INTERNAL, "profile_discover_claims received the label '%s'",
                label_words[arg->label]
            );
    }

    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (err) return err;

    /* At most one claim per branch: a branch names a location once and holds a
     * name once. */
    profile_claim_t *claims = arena_calloc(
        arena, branches->count, sizeof(*claims)
    );
    if (!claims) {
        string_array_free(branches);
        return ERROR(ERR_MEMORY, "Failed to allocate the claims");
    }

    size_t count = 0;
    for (size_t i = 0; i < branches->count; i++) {
        const char *branch = branches->items[i];
        const char *storage_path = NULL;

        /* The door left two keys, and each names its own search: the branch's
         * view of its tip, or one lookup in its tree. */
        if (arg->key == PATH_KEY_LOCATION) {
            err = claim_in_view(
                repo, branch, mounts, arg->location, arena, &storage_path
            );
        } else {
            err = claim_in_tree(repo, branch, arg->storage_path, &storage_path);
        }
        if (err) break;
        if (!storage_path) continue;

        /* The branch name outlives the list freed below; the claim's name is
         * the arena's already — the row's own, or the argument's. */
        const char *owner = arena_strdup(arena, branch);
        if (!owner) {
            err = ERROR(ERR_MEMORY, "Failed to record a claim");
            break;
        }
        claims[count++] = (profile_claim_t){ owner, storage_path };
    }

    string_array_free(branches);
    if (err) return err;

    /* The argument in its own key, which the door said is one of two — whatever
     * the enumeration held, this loop having run or not. */
    if (count == 0) {
        return ERROR(
            ERR_NOT_FOUND, "'%s' is not held by any profile",
            arg->key == PATH_KEY_LOCATION ? arg->location : arg->storage_path
        );
    }

    *out = (profile_claims_t){ claims, count };

    return NULL;
}
