/**
 * profiles.c - Profile management implementation
 */

#include "core/profiles.h"

#include <ctype.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "core/branch.h"
#include "core/manifest.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"

/**
 * Is there a profile of this name here, or refuse
 */
error_t profile_require(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    bool exists = false;
    error_t err = gitops_branch_exists(repo, name, &exists);
    if (err) return err;
    if (!exists) {
        return error_create(
            ERR_NOT_FOUND, "Profile '%s' doesn't exist locally; 'dotta profile fetch %s' "
            "brings it from a remote that holds it", name, name
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
 */
static void match_hierarchical_profiles(
    const string_array_t *available,
    const char *prefix,
    string_array_t *out
) {
    size_t prefix_len = strlen(prefix);

    for (size_t i = 0; i < available->count; i++) {
        const char *profile = available->entries[i];

        /* Check if branch starts with prefix */
        if (!str_starts_with(profile, prefix)) {
            continue;
        }

        const char *suffix = profile + prefix_len;

        if (suffix[0] == '\0') {
            /* Exact match: base profile */
            string_array_push(out, profile);
        } else if (suffix[0] == '/') {
            const char *variant = suffix + 1;
            /* One level deep only: non-empty variant with no further '/' */
            if (variant[0] != '\0' && strchr(variant, '/') == NULL) {
                string_array_push(out, profile);
            }
        }
    }
}

/**
 * The layer a profile name stands in — see profile_order.
 */
static int profile_rank(const char *name) {
    if (strcmp(name, "global") == 0) return 0;
    if (str_starts_with(name, "hosts/")) return 2;
    return 1;
}

static int profile_rank_order(const void *a, const void *b) {
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

    qsort(names->entries, names->count, sizeof(*names->entries), profile_rank_order);
}

/**
 * Detect matching profile names from a list of available branches
 */
string_array_t profile_detect(arena_t *arena, const string_array_t *available_branches) {
    CHECK_NULL(available_branches);

    string_array_t profiles;
    string_array_init(&profiles, arena);

    /* 1. "global" — always first if present */
    if (string_array_contains(available_branches, "global")) {
        string_array_push(&profiles, "global");
    }

    /* 2. OS-specific profiles (darwin, linux, freebsd, ...), the system's name
     *    lowered where uname wrote it */
    struct utsname uts;
    if (uname(&uts) == 0) {
        /* Safe tolower: cast to unsigned char to avoid UB with negative values */
        for (char *p = uts.sysname; *p; p++) {
            *p = (char) tolower((unsigned char) *p);
        }

        match_hierarchical_profiles(available_branches, uts.sysname, &profiles);
    }
    /* Non-fatal: skip OS profiles if uname() fails */

    /* 3. Host-specific profiles (hosts/<hostname>, hosts/<hostname>/variant) */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1] = '\0';

        char host_prefix[DOTTA_REFNAME_MAX];
        int n = snprintf(
            host_prefix, sizeof(host_prefix), "hosts/%s", hostname
        );
        if (n >= 0 && (size_t) n < sizeof(host_prefix)) {
            match_hierarchical_profiles(available_branches, host_prefix, &profiles);
        }
    }
    /* Non-fatal: continue if gethostname() fails */

    /* The three steps above answer *which* names this machine layers; this is
     * the order they are seeded in. Each step appends in branch-listing order,
     * so the one sort is what makes the answer the convention's — the same sort
     * every --all runs over its own set. */
    profile_order(&profiles);

    return profiles;
}

/**
 * Walk visitor: one entry of a profile tree, onto the listing where it is content
 *
 * A content blob's storage path is pushed onto the listing, the payload; the
 * branch's machinery is pruned with its subtree, a tree beneath a label is entered
 * and a gitlink passed; a name the storage grammar refuses is the walk's failure.
 */
static error_t profile_list_entry(
    const char *path,
    const git_tree_entry *entry,
    void *payload,
    gitops_next_t *next
) {
    string_array_t *paths = payload;

    /* The content gate: a managed path is a name in the grammar — beneath a label,
     * or the label's word alone, the namespace's own directory — and everything
     * else the branch carries is machinery, which no walk of content sees
     * (infra/label.h label_prefixes). Asked of every entry's whole name, a tree's
     * included, so a tree of machinery goes with everything beneath it. */
    if (!label_prefixes(path)) {
        *next = GITOPS_NEXT_SKIP;
        return NULL;
    }

    /* Content is a blob: a tree beneath a label is walked into, and a gitlink
     * claims nothing. */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return NULL;
    }

    /* The entry name is Git's, not this machine's. A tree can name a subtree
     * "..", and every consumer of a path from here joins it onto a root's spelling
     * (infra/mount.h mount_resolve) on the strength of its having been validated
     * where it was written — which holds for a branch this machine authored and
     * not for one that arrived by clone, sync or foreign push. So the shape is
     * checked where the tree is read, exactly as the branch's walk checks its
     * own (core/branch.c branch_step). Malformed here is corruption, not an entry
     * to skip: a walk that dropped it silently would leave the caller a listing
     * it cannot place and call it complete. */
    error_t err = label_validate_storage(path);
    if (err) return err;

    string_array_push(paths, path);
    return NULL;
}

/**
 * List deployable files in a Git tree
 */
error_t profile_list_tree_files(
    const git_tree *tree,
    const char *profile,
    arena_t *arena,
    string_array_t *out
) {
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The walk pushes straight onto the listing, handed out once it is whole.
     * Its failures name a path in the tree — a name the grammar refused, a subtree
     * that would not load — and the profile is the where they do not say. */
    string_array_t paths;
    string_array_init(&paths, arena);
    error_t err = gitops_tree_walk(tree, profile_list_entry, &paths);
    if (err) return error_wrap(err, "Failed to list files in profile '%s'", profile);

    *out = paths;
    return NULL;
}

/**
 * Walk visitor: the label a claim stands under, noted
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The labels noted so far (bool[LABEL_COUNT])
 * @return NULL: noting a label fails nowhere
 */
static error_t profile_note_label(const branch_claim_t *claim, void *payload) {
    bool *claimed = payload;

    /* Every name the walk shows is under a label: a blob's passed the walk's
     * own gate and shape check, a directory claim's key the sheet's parse
     * (core/branch.h) */
    claimed[label_of(claim->storage_path)] = true;

    return NULL;
}

/**
 * Does this profile's branch need a deployment target?
 *
 * The labels its walk shows, each asked of a table that binds nothing — HOME
 * and the sentinel alone — in a frame of the call's own: a label with no root
 * there is one only a binding places, and the product is a bool.
 */
error_t profile_needs_target(branch_t *branch, bool *needs_target) {
    CHECK_NULL(branch);
    CHECK_NULL(needs_target);

    *needs_target = false;

    /* The labels the branch claims anything under, read as the view is shown
     * them: one strict walk, so a sheet that will not load and a tree the walk
     * refuses are the answer's failure here, as they are the view build's */
    bool claimed[LABEL_COUNT] = { false };
    error_t err = branch_walk(branch, BRANCH_READ_STRICT, profile_note_label, claimed);
    if (err) return err;

    /* Each asked of the table no state row can produce, for the profile's own
     * root of it: one with none there is placed by a binding alone, and which
     * labels a binding places is the table's to say (infra/mount.h
     * mount_table_build), so no label is named here */
    arena_t *frame = arena_create(0);
    mount_table_t *mounts = NULL;
    err = mount_table_build(frame, NULL, 0, &mounts);
    for (label_t label = LABEL_HOME; !err && label < LABEL_COUNT; label++) {
        if (claimed[label] && !mount_root_of(mounts, branch_profile(branch), label)) {
            *needs_target = true;
        }
    }
    arena_free(frame);

    return err;
}

/**
 * By filesystem path, then by profile
 *
 * Equal paths sort together, so the rows standing at one path form a contiguous
 * run; the profile breaks the tie, and the order is total because one branch
 * places one row per path. The name would not be: two branches can hold one name
 * at one path.
 */
static int index_order(const void *a, const void *b) {
    const manifest_row_t *const *ra = a;
    const manifest_row_t *const *rb = b;

    int by_path = strcmp((*ra)->filesystem_path, (*rb)->filesystem_path);

    return by_path ? by_path : strcmp((*ra)->profile, (*rb)->profile);
}

/**
 * filesystem path → the claims every local branch but `exclude` places there
 */
error_t profile_build_filesystem_index(
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

    /* The branches, in the arena the index lives in */
    string_array_t branches;
    error_t err = gitops_list_branches(repo, arena, &branches);
    if (err) return err;

    /* Every placed row of every branch, gathered before any of it is keyed: the
     * rows are the arena's, as the views they came from are, and so is the list
     * of them. */
    ptr_array_t rows;
    ptr_array_init(&rows, arena);
    for (size_t i = 0; i < branches.count; i++) {
        if (exclude && strcmp(branches.entries[i], exclude) == 0) continue;

        branch_t *branch = NULL;
        manifest_t *view = NULL;
        err = branch_load(repo, branches.entries[i], &branch);
        if (!err) err = manifest_build_branch(branch, mounts, arena, &view);
        branch_free(branch);
        if (err) return err;

        manifest_rows_t placed = manifest_rows(view);
        for (size_t j = 0; j < placed.count; j++) {
            ptr_array_push(&rows, placed.entries[j]);
        }
    }

    /* The runs, typed once: a ptr_array holds void *, and every read below is a
     * row's path, its profile or its name. */
    const manifest_row_t **sorted = (const manifest_row_t **) rows.entries;
    qsort(sorted, rows.count, sizeof(*sorted), index_order);

    hashmap_t *index = hashmap_borrow(arena, rows.count);

    for (size_t i = 0; i < rows.count;) {
        const char *filesystem_path = sorted[i]->filesystem_path;

        size_t n = 0;
        while (i + n < rows.count &&
            strcmp(sorted[i + n]->filesystem_path, filesystem_path) == 0) n++;

        profile_claim_t *entries = arena_calloc(arena, n, sizeof(*entries));
        profile_claims_t *claims = arena_calloc(arena, 1, sizeof(*claims));
        for (size_t g = 0; g < n; g++) {
            entries[g] = (profile_claim_t){
                sorted[i + g]->profile, sorted[i + g]->storage_path
            };
        }
        *claims = (profile_claims_t){ entries, n };

        /* The key is the row's own string — hashmap_borrow keeps the pointer
         * and compares by content, and the row lives as long as the map. */
        hashmap_set(index, filesystem_path, claims);
        i += n;
    }

    *out_index = index;

    return NULL;
}

/**
 * The claim `profile`'s branch stands at `filesystem_path`, or NULL
 *
 * The branch's own view of its tip under this machine's table, so the name is
 * the branch's — a binding's, or one kept from before the binding — and never
 * one this machine composed. The view is strict (core/manifest.h): a sheet that
 * will not load is this branch's error, which is the whole cost a path argument
 * carries over a name the tree answers.
 *
 * The answer is the row's own string, the arena's, as the view is.
 */
static error_t claim_by_filesystem_path(
    git_repository *repo,
    const char *profile,
    const mount_table_t *mounts,
    const char *filesystem_path,
    arena_t *arena,
    const char **out_storage
) {
    *out_storage = NULL;

    branch_t *branch = NULL;
    manifest_t *view = NULL;
    error_t err = branch_load(repo, profile, &branch);
    if (!err) err = manifest_build_branch(branch, mounts, arena, &view);
    branch_free(branch);
    if (err) return err;

    const manifest_row_t *row = manifest_lookup_claim(view, profile, filesystem_path);
    if (row) *out_storage = row->storage_path;

    return NULL;
}

/**
 * The claim `profile`'s branch holds under `storage_path`, or NULL
 *
 * A name is Git's key, and one question of the branch answers it (core/branch.h
 * branch_holds): the tree first — a subtree counts, as a name has always counted
 * — and the sheet where the tree is silent, because a directory claim with nothing
 * beneath it stands there alone, held by the branch as surely as a blob is.
 * Complete or an error on both documents: an object that will not load and a
 * sheet that will not parse are each this branch's failure, never an absence —
 * and the sheet is opened only where the tree did not answer, which is the whole
 * of what a name still costs less than a path.
 */
static error_t claim_by_name(
    git_repository *repo,
    const char *profile,
    const char *storage_path,
    const char **out_storage
) {
    *out_storage = NULL;

    branch_t *branch = NULL;
    branch_held_t held = { 0 };
    error_t err = branch_load(repo, profile, &branch);
    if (!err) err = branch_holds(branch, storage_path, &held);
    branch_free(branch);
    if (err) return err;

    if (held.kind != BRANCH_HELD_NOTHING) *out_storage = storage_path;

    return NULL;
}

/**
 * Every claim standing at what the user named, across the local branches
 */
error_t profile_discover_claims(
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

    /* The branches, in the arena the claims live in, so a claim borrows its
     * profile's name from the listing */
    string_array_t branches;
    error_t err = gitops_list_branches(repo, arena, &branches);
    if (err) return err;

    /* At most one claim per branch: a branch names a path once and holds a name
     * once. */
    profile_claim_t *claims = arena_calloc(
        arena, branches.count, sizeof(*claims)
    );

    size_t count = 0;
    for (size_t i = 0; i < branches.count; i++) {
        const char *profile = branches.entries[i];
        const char *storage_path = NULL;

        /* Two keys, and each names its own search: the branch's view of its tip,
         * or its two documents asked for the name. */
        if (arg->key == PATH_KEY_FILESYSTEM) {
            err = claim_by_filesystem_path(
                repo, profile, mounts, arg->filesystem_path, arena, &storage_path
            );
        } else {
            err = claim_by_name(repo, profile, arg->storage_path, &storage_path);
        }
        if (err) break;
        if (!storage_path) continue;

        /* Both names are the arena's already: the profile's the listing's, the
         * claim's the row's own or the argument's. */
        claims[count++] = (profile_claim_t){ profile, storage_path };
    }

    if (err) return err;

    /* Every branch answered: none holding the argument is the empty set, the
     * caller's to word, and never an error a failed read could also wear */
    *out = (profile_claims_t){ claims, count };

    return NULL;
}
