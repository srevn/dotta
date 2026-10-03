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
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/gitops.h"
#include "sys/stats.h"

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
        return error_create(ERR_NOT_FOUND, "Profile '%s' doesn't exist locally", name);
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
 * Resolve enabled profile names from state database
 */
error_t profile_resolve_enabled(
    git_repository *repo,
    const state_t *state,
    arena_t *arena,
    string_array_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The enabled rows, where the handle holds them: nothing below moves them
     * (core/state.h state_profiles) */
    state_profiles_t enabled_profiles = state_profiles(state);

    /* The answer, the arena's: each profile whose branch is here. One that is
     * gone is dropped unsaid — the health commands say it, off the view
     * (core/manifest.h manifest_missing). */
    string_array_t valid_profiles;
    string_array_init(&valid_profiles, arena);

    for (size_t i = 0; i < enabled_profiles.count; i++) {
        const char *profile = enabled_profiles.entries[i].name;

        bool exists = false;
        error_t err = gitops_branch_exists(repo, profile, &exists);
        if (err) return error_wrap(err, "Failed to validate state profiles");
        if (exists) string_array_push(&valid_profiles, profile);
    }

    *out = valid_profiles;
    return NULL;
}

/*
 * The search's absence, said of what it searched: every enabled profile, or the
 * ones the filter names — a filter that left the holder out has not made the
 * commit "any enabled profile"'s absence. No cause under it: one profile's sentence
 * is not this one's.
 */
static error_t profile_unheld(const char *commit_ref, const string_array_t *filter) {
    if (!filter) {
        return error_create(
            ERR_NOT_FOUND, "Commit '%s' not found in any enabled profile",
            commit_ref
        );
    }

    /* The names -p gave, joined in the arena the filter keeps them in: an array
     * remembers its arena (base/array.h) */
    return error_create(
        ERR_NOT_FOUND, "Commit '%s' not found in profile%s '%s'", commit_ref,
        filter->count == 1 ? "" : "s", string_array_join(filter->arena, filter, "', '")
    );
}

/* The ends one search is asked for: a commit's one, a range's two */
#define PROFILE_ENDS_MAX 2

/*
 * The search both entries make: the first profile holding every end, and the
 * commit each end names in it. The ends are read once, before any profile is
 * asked, so a spelling that names nothing is its own failure and no profile is
 * passed over for it; then each profile the filter admits, from the highest
 * precedence down — the last enabled wins every path it shares, so its tip is
 * the HEAD the view reads — has its tip read once and every end asked of that
 * one tip. Nothing is published until a profile holds them all.
 *
 * Each end's first holder is kept as the search goes, for the refusal: an end
 * no profile holds is that end's absence, said of what was searched, and ends
 * held only apart are a range no one profile's history holds.
 */
static error_t profile_holder(
    git_repository *repo,
    const string_array_t *enabled,
    const string_array_t *filter,
    const char *const spellings[],
    size_t count,
    git_commit *out_commits[],
    const char **out_profile
) {
    CHECK_ARG(count >= 1 && count <= PROFILE_ENDS_MAX, "a search asks one or two ends");

    gitops_revision_t revs[PROFILE_ENDS_MAX];
    for (size_t end = 0; end < count; end++) {
        error_t err = gitops_revision_resolve(repo, spellings[end], &revs[end]);
        if (err) return err;
    }

    const char *holders[PROFILE_ENDS_MAX] = { NULL };
    for (size_t i = enabled->count; i-- > 0;) {
        const char *profile = enabled->entries[i];
        if (filter && !string_array_contains(filter, profile)) continue;

        /* The profile's tip, read once, and every end asked of it. A tip or a
         * history that will not read ends the search where it stands, whatever
         * a later profile would have said: what comes back is the first holder
         * in precedence order, a claim about every profile ahead of it, and a
         * branch that would not read is one the claim cannot be made over. */
        git_commit *tip = NULL;
        error_t err = gitops_load_branch_commit(repo, profile, &tip);
        if (err) return err;

        git_commit *found[PROFILE_ENDS_MAX] = { NULL };
        size_t held = 0;
        for (size_t end = 0; !err && end < count; end++) {
            err = gitops_revision_find(repo, &revs[end], profile, tip, &found[end]);
            if (!found[end]) continue;
            held++;
            if (!holders[end]) holders[end] = profile;
        }
        git_commit_free(tip);

        if (!err && held == count) {
            for (size_t end = 0; end < count; end++) out_commits[end] = found[end];
            *out_profile = profile;
            return NULL;
        }
        for (size_t end = 0; end < count; end++) git_commit_free(found[end]);
        if (err) return err;
    }

    /* Every profile searched was asked: an end none holds is its absence */
    for (size_t end = 0; end < count; end++) {
        if (!holders[end]) return profile_unheld(spellings[end], filter);
    }

    /* Each end held, and no profile holding both. Dotta profiles are orphan
     * branches — a range across two would diff two unrelated trees, producing
     * meaningless output. */
    return error_create(
        ERR_VALIDATION,
        "Commits belong to different profiles ('%s' and '%s'); "
        "cross-profile commit comparison is not supported",
        holders[0], holders[1]
    );
}

/**
 * Which enabled profile holds a commit
 */
error_t profile_resolve_commit(
    git_repository *repo,
    const string_array_t *enabled,
    const string_array_t *filter,
    const char *commit_ref,
    git_commit **out_commit,
    const char **out_profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(enabled);
    CHECK_NULL(commit_ref);
    CHECK_NULL(out_commit);
    CHECK_NULL(out_profile);

    const char *const spellings[] = { commit_ref };
    return profile_holder(repo, enabled, filter, spellings, 1, out_commit, out_profile);
}

/**
 * Which enabled profile holds both ends of a range
 */
error_t profile_resolve_range(
    git_repository *repo,
    const string_array_t *enabled,
    const string_array_t *filter,
    const char *from_ref,
    const char *to_ref,
    git_commit **out_from,
    git_commit **out_to,
    const char **out_profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(enabled);
    CHECK_NULL(from_ref);
    CHECK_NULL(to_ref);
    CHECK_NULL(out_from);
    CHECK_NULL(out_to);
    CHECK_NULL(out_profile);

    const char *const spellings[] = { from_ref, to_ref };
    git_commit *commits[PROFILE_ENDS_MAX] = { NULL };
    error_t err = profile_holder(repo, enabled, filter, spellings, 2, commits, out_profile);
    if (err) return err;

    *out_from = commits[0];
    *out_to = commits[1];
    return NULL;
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
     * checked where the tree is read, exactly as the view checks its own
     * (core/manifest.c manifest_claim_blob). Malformed here is corruption, not
     * an entry to skip: a walk that dropped it silently would leave the caller
     * a listing it cannot place and call it complete. */
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
    arena_t *arena,
    string_array_t *out
) {
    CHECK_NULL(tree);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The walk pushes straight onto the listing, handed out once it is whole */
    string_array_t paths;
    string_array_init(&paths, arena);
    error_t err = gitops_tree_walk(tree, profile_list_entry, &paths);
    if (err) return err;

    *out = paths;
    return NULL;
}

/**
 * List files in profile
 */
error_t profile_list_files(
    git_repository *repo,
    const char *profile,
    arena_t *arena,
    string_array_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    git_tree *tree = NULL;
    error_t err = gitops_load_branch_tree(repo, profile, &tree);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for profile '%s'", profile
        );
    }

    err = profile_list_tree_files(tree, arena, out);
    git_tree_free(tree);
    return err;
}

/**
 * The branch statistics' walk: what the count reads through, and the count so far
 */
typedef struct {
    git_odb *odb;              /* Held for the walk: one handle, N header reads */
    const metadata_t *sheet;   /* The branch's claims: what the sizes are read through */
    size_t file_count;
    size_t total_size;
} count_walk_t;

/**
 * Walk visitor: one entry of a profile tree, counted where it is content
 *
 * A content blob is counted, with the bytes it stands for; the branch's machinery
 * is pruned with its subtree, a tree beneath a label is entered and a gitlink
 * passed; a name the storage grammar refuses, a size that will not read and a
 * total past what a size_t holds are the walk's failure.
 */
static error_t profile_count_entry(
    const char *path,
    const git_tree_entry *entry,
    void *payload,
    gitops_next_t *next
) {
    count_walk_t *walk = payload;

    /* The content gate and the shape, asked as the file listing asks them
     * (profile_list_entry): this is the fold of the rows that listing prints,
     * so the two admit one set of names or the two screens disagree by a file. */
    if (!label_prefixes(path)) {
        *next = GITOPS_NEXT_SKIP;
        return NULL;
    }
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return NULL;
    }
    error_t err = label_validate_storage(path);
    if (err) return err;

    /* The size from the object's header: nothing inflated */
    size_t size = 0;
    err = stats_blob_size_with_odb(walk->odb, git_tree_entry_id(entry), &size);
    if (err) return err;

    /* The bytes the entry stands for, not the bytes the object database holds:
     * a sealed blob carries the cipher's framing and its file does not, and the
     * file is what a screen names (197 R5). The stamp is the branch's own claim,
     * read as the view projects it — never onto a link, whose bytes are its target
     * and never a seal (core/manifest.c manifest_apply_claim) — and this is the
     * fold of exactly the rows the file listing prints one by one, so the two
     * read the claim the same way or the two screens disagree by the framing
     * (cmds/list.c list_files). */
    const metadata_item_t *claim = metadata_lookup(walk->sheet, path);
    bool encrypted = git_tree_entry_filemode(entry) != GIT_FILEMODE_LINK
        && claim && claim->encrypted;

    size = content_estimated_plaintext_size(size, encrypted);

    if (walk->total_size > SIZE_MAX - size) {
        return error_create(
            ERR_INTERNAL, "Profile size exceeds maximum representable value"
        );
    }

    walk->file_count++;
    walk->total_size += size;

    return NULL;
}

/**
 * Count what a profile branch holds, in a tree already open
 */
error_t profile_get_tree_stats(
    git_repository *repo,
    const git_tree *tree,
    const char *profile,
    profile_stats_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    /* The branch's own metadata, the same source the view's claim routine reads,
     * and read first because both halves below want it: the directories it claims,
     * and the stamp each blob's size is taken through. A tree without a sheet
     * loads as an empty one — no claim, so nothing counted and nothing stamped
     * — and every load error is real and propagates. */
    metadata_t *metadata = NULL;
    error_t err = metadata_load_from_tree(repo, tree, profile, &metadata);
    if (err) {
        return error_wrap(
            err, "Failed to load metadata for profile '%s'", profile
        );
    }

    /* The files: one walk, one ODB handle, sizes read from the object headers. */
    git_odb *odb = NULL;
    int rc = git_repository_odb(&odb, repo);
    if (rc < 0) {
        err = error_from_git(rc);
        goto cleanup;
    }

    count_walk_t walk = {
        .odb        = odb,
        .sheet      = metadata,
        .file_count = 0,
        .total_size = 0
    };

    err = gitops_tree_walk(tree, profile_count_entry, &walk);
    git_odb_free(odb);

    if (err) {
        err = error_wrap(
            err, "Failed to read statistics for profile '%s'", profile
        );
        goto cleanup;
    }

    size_t directory_count = 0;
    size_t item_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);
    for (size_t i = 0; i < item_count; i++) {
        /* The tracked set alone: an ancestor claim is the way to content, not
         * content the profile tracks, and counting the spine would inflate the
         * number the screens call "directories" past anything the user named. */
        if (items[i]->kind != PATH_KIND_DIRECTORY || !items[i]->tracked) continue;

        /* A path is a tree or a blob: a DIRECTORY item where the tree holds a
         * blob is stale metadata, and the tree is the content authority — the
         * same rule the view's directory pass applies when the profile is enabled
         * (core/manifest.c manifest_contribute), asked there of the sheet at
         * the blob its own walk met rather than of the ODB.
         *
         * One question, two witnesses, and they answer alike for every key the
         * grammar admits: the gate is asked of the whole name at every rung,
         * the branch root's included (profile_count_entry), so a blob standing
         * at a label's own word is a blob to both witnesses as one standing beneath
         * the word is.
         *
         * Three answers, not two: the entry is there, it is absent, or the tree
         * will not read — and an object that will not load is corruption, never
         * an absence, so the count refuses rather than counts a directory the
         * branch may not hold. */
        git_tree_entry *entry = NULL;
        rc = git_tree_entry_bypath(&entry, tree, items[i]->key);
        if (rc == 0) {
            bool is_blob = git_tree_entry_type(entry) == GIT_OBJECT_BLOB;
            git_tree_entry_free(entry);
            if (is_blob) continue;
        } else if (rc != GIT_ENOTFOUND) {
            err = error_wrap(
                error_from_git(rc), "Failed to read '%s' in profile '%s'",
                items[i]->key, profile
            );
            goto cleanup;
        }

        directory_count++;
    }

    metadata_free(metadata);

    /* Both sides at once, and only here: a walk that stopped short or a probe
     * that refused has jumped to the label below, so what the caller supplied
     * is either replaced whole or never touched. The success path frees the sheet
     * itself rather than falling into that label, which is what keeps that true
     * structurally: nothing reaches this write except the path that earned it. */
    *out = (profile_stats_t){
        .file_count = walk.file_count,
        .directory_count = directory_count,
        .total_size = walk.total_size,
    };

    return NULL;

cleanup:
    metadata_free(metadata);
    return err;
}

/**
 * Count what a profile branch holds
 */
error_t profile_get_stats(
    git_repository *repo,
    const char *profile,
    profile_stats_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out);

    git_tree *tree = NULL;
    error_t err = gitops_load_branch_tree(repo, profile, &tree);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for profile '%s'", profile
        );
    }

    err = profile_get_tree_stats(repo, tree, profile, out);
    git_tree_free(tree);
    return err;
}

/**
 * What `profile` holds at `name` in `tree`
 */
error_t profile_holds(
    git_repository *repo,
    const git_tree *tree,
    const metadata_t *sheet,
    const char *profile,
    const char *name,
    profile_held_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(profile);
    CHECK_NULL(name);
    CHECK_NULL(out);

    /* The tree first: a name is Git's key, and the tree is the content authority
     * (core/metadata.h), so an entry here is the whole answer whatever the sheet
     * says at the name. Three answers read as three: an intermediate object that
     * will not load is a failure to read, never an absence. */
    git_tree_entry *entry = NULL;
    int rc = git_tree_entry_bypath(&entry, tree, name);
    if (rc == 0) {
        /* Three kinds and no fourth: git_tree_entry_type reads the entry's mode
         * word, which is a gitlink, a directory, or a blob — so the last arm is
         * the gitlink and not a shrug. */
        profile_held_kind_t kind;
        switch (git_tree_entry_type(entry)) {
            case GIT_OBJECT_BLOB: kind = PROFILE_HELD_FILE; break;
            case GIT_OBJECT_TREE: kind = PROFILE_HELD_DIRECTORY; break;
            default:              kind = PROFILE_HELD_SUBMODULE; break;
        }

        *out = (profile_held_t){
            .kind = kind,
            .oid = *git_tree_entry_id(entry),
            .filemode = git_tree_entry_filemode(entry),
        };
        git_tree_entry_free(entry);

        return NULL;
    }
    if (rc != GIT_ENOTFOUND) {
        return error_wrap(
            error_from_git(rc), "Failed to read '%s' in profile '%s'", name,
            profile
        );
    }

    /* The sheet, and only on the tree's silence: a directory claim with nothing
     * beneath it stands here and nowhere else. The caller's sheet where it holds
     * one, read as the caller read it; else the tree's own, read strictly and
     * freed below — `own` marks whose it is, and metadata_free takes a NULL. */
    metadata_t *own = NULL;
    if (!sheet) {
        error_t err = metadata_load_from_tree(repo, tree, profile, &own);
        if (err) {
            return error_wrap(
                err, "Failed to load metadata for profile '%s'", profile
            );
        }
        sheet = own;
    }

    const metadata_item_t *item = metadata_lookup(sheet, name);
    *out = (profile_held_t){
        .kind = item && item->kind == PATH_KIND_DIRECTORY ? PROFILE_HELD_DIRECTORY
                                                          : PROFILE_HELD_NOTHING,
    };
    metadata_free(own);

    return NULL;
}

/**
 * Does this profile's branch need a deployment target?
 *
 * The table binds nothing on purpose — HOME and the sentinel alone — so a custom/
 * claim has nowhere to go and is recorded, which is the answer. The view is a
 * frame's, built to read one count off it.
 */
error_t profile_needs_target(
    git_repository *repo,
    const char *profile,
    bool *needs_target
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(needs_target);

    *needs_target = false;

    arena_t *frame = arena_create(0);

    mount_table_t *mounts = NULL;
    manifest_t *view = NULL;
    error_t err = mount_table_build(frame, NULL, 0, &mounts);
    if (!err) err = manifest_build_branch(repo, profile, mounts, frame, &view);
    if (!err) *needs_target = manifest_unbound(view).count > 0;

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

        manifest_t *view = NULL;
        err = manifest_build_branch(
            repo, branches.entries[i], mounts, arena, &view
        );
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
 * The name `profile` has for `filesystem_path` in `tree`
 */
error_t profile_claim_name(
    git_repository *repo,
    const git_tree *tree,
    const mount_table_t *mounts,
    const char *profile,
    const char *filesystem_path,
    arena_t *arena,
    const char **out_storage
) {
    CHECK_NULL(repo);
    CHECK_NULL(tree);
    CHECK_NULL(mounts);
    CHECK_NULL(profile);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(arena);
    CHECK_NULL(out_storage);

    *out_storage = NULL;

    manifest_t *view = NULL;
    error_t err = manifest_build_tree(repo, tree, profile, mounts, arena, &view);
    if (err) return err;

    /* The claim standing there, before the name one would take: a derived claim
     * is held and names nothing, so the ascent climbs past it and would answer
     * a name the branch never held. Else the name the profile would give the
     * place — its label's word at a root of its own. Either answer is the arena's,
     * as the view is. */
    const manifest_row_t *row = manifest_lookup_claim(view, profile, filesystem_path);
    *out_storage = row ? row->storage_path
                       : manifest_name(arena, view, profile, filesystem_path, NULL);
    return NULL;
}

/**
 * The claim `branch` stands at `filesystem_path`, or NULL
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
    const char *branch,
    const mount_table_t *mounts,
    const char *filesystem_path,
    arena_t *arena,
    const char **out_storage
) {
    *out_storage = NULL;

    manifest_t *view = NULL;
    error_t err = manifest_build_branch(repo, branch, mounts, arena, &view);
    if (err) return err;

    const manifest_row_t *row = manifest_lookup_claim(view, branch, filesystem_path);
    if (row) *out_storage = row->storage_path;

    return NULL;
}

/**
 * The claim `branch` holds under `storage_path`, or NULL
 *
 * A name is Git's key, and one question of the branch's two documents answers
 * it (profile_holds): the tree first — a subtree counts, as a name has always
 * counted — and the sheet where the tree is silent, because a directory claim
 * with nothing beneath it stands there alone, held by the branch as surely as a
 * blob is. Complete or an error on both documents: an object that will not load
 * and a sheet that will not parse are each this branch's failure, never an absence
 * — and the sheet is opened only where the tree did not answer, which is the
 * whole of what a name still costs less than a path.
 */
static error_t claim_by_name(
    git_repository *repo,
    const char *branch,
    const char *storage_path,
    const char **out_storage
) {
    *out_storage = NULL;

    git_tree *tree = NULL;
    error_t err = gitops_load_branch_tree(repo, branch, &tree);
    if (err) {
        return error_wrap(err, "Failed to load tree for profile '%s'", branch);
    }

    profile_held_t held;
    err = profile_holds(repo, tree, NULL, branch, storage_path, &held);
    git_tree_free(tree);
    if (err) return err;

    if (held.kind != PROFILE_HELD_NOTHING) *out_storage = storage_path;

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
     * branch's name from the listing */
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
        const char *branch = branches.entries[i];
        const char *storage_path = NULL;

        /* Two keys, and each names its own search: the branch's view of its tip,
         * or its two documents asked for the name. */
        if (arg->key == PATH_KEY_FILESYSTEM) {
            err = claim_by_filesystem_path(
                repo, branch, mounts, arg->filesystem_path, arena, &storage_path
            );
        } else {
            err = claim_by_name(repo, branch, arg->storage_path, &storage_path);
        }
        if (err) break;
        if (!storage_path) continue;

        /* Both names are the arena's already: the branch's the listing's, the
         * claim's the row's own or the argument's. */
        claims[count++] = (profile_claim_t){ branch, storage_path };
    }

    if (err) return err;

    /* The argument in its own key — whatever the enumeration held, this loop
     * having run or not. */
    if (count == 0) {
        return error_create(
            ERR_NOT_FOUND, "'%s' is not held by any profile",
            arg->key == PATH_KEY_FILESYSTEM ? arg->filesystem_path : arg->storage_path
        );
    }

    *out = (profile_claims_t){ claims, count };

    return NULL;
}
