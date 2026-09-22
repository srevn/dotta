/**
 * export.c - Materialize profile content to the filesystem
 *
 * Export is a copy, not a deployment. It never registers in state, never applies
 * ownership, and dotta makes no ongoing claim over the destination. One profile,
 * never the enabled set: no layer composition, plaintext bytes with stored
 * permission modes. A directory claim without a tree entry (an empty tracked
 * directory — its whole Git footprint is its metadata item) is content too:
 * materialized with its stored mode, beside what a walk collects.
 *
 * Three ways to name what is copied, and each lays the copy out in the key it
 * was named in. A profile alone mirrors its branch (dest/home/..., dest/root/...).
 * A storage path copies that branch subtree, laid out beneath it. A filesystem
 * path copies what the profile *places* there on this machine — every row its
 * branch and this machine's roots put at and beneath the path, whatever label
 * each is stored under, laid out beneath the path. Only the third reads the mount
 * table, and it is the only one that can answer a place a branch spells under
 * two labels: a file captured before a binding stands beside one captured after,
 * and a name reaches under one label alone. Single files are the degenerate case
 * of each.
 *
 * Directory modes come off the claim without asking which kind of claim stands
 * there, and that is right rather than incidental: every directory an export
 * produces is one the export itself creates, and creation is precisely what both
 * kinds of claim bind. A rung the profile only passes through, claimed at 0700
 * by the chain above a captured leaf, exports at 0700 — the same fidelity a
 * deployment gives it, reached with no class test anywhere in this file. The
 * distinction core/deploy must draw — converge what the profile manages, only
 * create what it passes through — has no counterpart where nothing pre-exists.
 *
 * Two sheet policies, one per key, and the split is the view's rather than this
 * file's: an arm that reads the sheet itself reads it tolerantly (load_sheet),
 * while the path arm asks the profile's view, which is strict about the sheet
 * by contract (core/manifest.h). So on a branch whose sheet will not load `export
 * p home/x` proceeds with a warning and `export p ~/x` refuses — and that refusal
 * is not "use the name instead": a name is a different selection wherever the
 * path spans two labels, which is the partial copy this arm exists to stop
 * offering.
 *
 * Two-phase execution model:
 *
 *   Phase 1 (read-only): collect entries, complete the copy into a tree, resolve
 *   every final destination path, and validate everything — type collisions,
 *   pre-existing symlinks that would re-route content writes — then read every
 *   blob the sheet stamps sealed into memory, as plaintext. Every crypto refusal
 *   those blobs can raise lands before the first byte is written: the passphrase
 *   prompt, a wrong key, a corrupt ciphertext, a version this build does not
 *   read. A sheet dotta wrote stamps every sealed blob its branch holds
 *   (core/metadata.h), so on such a branch that is all of them. --dry-run is
 *   phase 1 alone.
 *
 *   Phase 2 (write): create directories, write blobs, recreate symlinks. A blob
 *   no stamp speaks for is first read here, and read by its bytes, which route
 *   it correctly whatever the sheet said — so a stamp costs a late prompt and
 *   never wrong content. Fail fast on first error; the failure window is filesystem
 *   errors, repository corruption, and the crypto that a sheet speaking for no
 *   blob of its branch leaves late (load_sheet).
 *
 * Traversal safety is established, not assumed. A tree entry's name is whoever
 * wrote the branch's, and git accepts one called ".." without a murmur, so every
 * path a source dictates is read against the storage grammar where the source
 * is read: label_validate_storage in the walk callback, the same check the view
 * makes for the same reason (core/manifest.c manifest_claim_blob) and therefore
 * already made for every row the path arm reads, and, for the claim sheet, its
 * own loader (core/metadata.c). Every rung is read against the grammar, the branch
 * root's included, and what prunes machinery there is the content gate every
 * walk asks of a name (infra/label.h label_prefixes). So every entry this walk
 * collects carries a validated storage path — the metadata key and the associated
 * data both. The remaining escape vector — a pre-existing symlink at a
 * content-dictated path below the root — is refused in phase 1, which can see
 * every such path because the entry list is completed first: every directory
 * the copy needs is an entry of it.
 */

#include "cmds/export.h"

#include <errno.h>
#include <git2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/refspec.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "infra/content.h"
#include "infra/label.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"

/**
 * One collected export entry.
 *
 * Paths are arena-owned (command scope). `content` is heap-owned and held only
 * for entries phase 1 must materialize early: the plaintext of every blob the
 * sheet stamps sealed (so every crypto failure front-loads) and symlink targets
 * (tiny, and the dry-run listing shows them). Every other file blob stays lazy
 * — phase 2 reads it, so a whole profile is never held in memory, and that read
 * is the blob's first: the failure window there is the ODB's own, which the file
 * header already names.
 *
 * `encrypted` is a copy of the claim's word rather than a borrow of it, because
 * the sheet does not outlive the collector that read it (metadata_free at the
 * tail of collect_profile and collect_storage) while the entry list lives in
 * the arena into phase 2. The mode beside it is copied for the same reason.
 */
typedef enum {
    EXPORT_ENTRY_DIRECTORY,
    EXPORT_ENTRY_FILE,
    EXPORT_ENTRY_SYMLINK
} export_entry_kind_t;

typedef struct {
    export_entry_kind_t kind;
    const char *storage_path;  /* The source's name for it — the metadata key and
                                * the AAD. NULL where the copy needs a directory
                                * no source names: the root of a whole-profile
                                * copy, and the rungs complete_directories
                                * supplies. */
    const char *rel_path;      /* Path relative to the export root (display) */
    const char *dest_path;     /* Final filesystem path */
    git_oid blob_oid;          /* FILE / SYMLINK only */
    mode_t mode;               /* Resolved final mode (FILE / DIRECTORY) */
    bool encrypted;            /* FILE: the sheet's stamp, read where the entry is made */
    bool claimed;              /* DIRECTORY: a metadata DIRECTORY at this storage path */
    bool dest_existed;         /* DIRECTORY: phase-1 lstat fact */
    bool content_held;         /* `content` carries bytes from phase 1 */
    buffer_t content;
} export_entry_t;

/**
 * The entries of one copy, its shape, and its name.
 *
 * A tree-shaped copy's first entry is its root: relative path "", the mode and
 * claim of whatever stands at the source. Every arm appends it before anything
 * beneath it, and the sort keeps it first — "" is a prefix of every other relative
 * path, so it compares least, and the same fact puts every directory before its
 * own contents (creation order) and after them when read backwards (the
 * deepest-first chmod).
 *
 * A single-file copy has no root: its one entry is the leaf, and the destination
 * is the user's own path rather than a directory to nest under (cp semantics,
 * validate_destinations' `single_dest`). So `items[0].rel_path[0] == '\0'` says
 * which shape a list is and nothing else has to; every arm appends its first
 * entry or fails, so there is always an items[0] to ask.
 *
 * Where the copy lands is nobody's until the copy is whole: resolve_destinations
 * fills every dest_path in one pass, from the name below and the destination
 * the user typed, after the collection and the completion. No collector knows a
 * destination at all.
 */
typedef struct {
    export_entry_t *items;     /* Arena-owned spine */
    size_t count;
    size_t capacity;
    const char *basename;      /* The last segment of whatever named the copy — the
                                * profile, the storage path, the path — which a
                                * directory destination nests the copy under. Every
                                * arm sets it, and a single-file copy's leaf borrows
                                * this very pointer as its relative path, so the two
                                * cannot drift. */
} export_entry_list_t;

/**
 * Append an entry, growing the arena-backed spine geometrically.
 *
 * Abandoned blocks stay in the arena until dispatch teardown — bounded waste,
 * same pattern as core/manifest's precedence view.
 */
static error_t *entry_list_append(
    export_entry_list_t *list,
    arena_t *arena,
    const export_entry_t *src
) {
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity ? list->capacity * 2 : 64;
        export_entry_t *grown = arena_calloc(
            arena, new_capacity, sizeof(*grown)
        );
        if (!grown) {
            return ERROR(ERR_MEMORY, "Failed to grow export entry list");
        }
        if (list->count > 0) {
            memcpy(grown, list->items, list->count * sizeof(*grown));
        }
        list->items = grown;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = *src;
    return NULL;
}

/**
 * Open a tree-shaped copy with its root — the entry whose relative path is empty.
 *
 * `storage_path` and `claimed` are the source's word about the directory standing
 * there — a sheet item, a row — or NULL and false where nothing names it: a whole
 * profile, whose root is the destination and not a path of the branch.
 */
static error_t *append_root(
    export_entry_list_t *list,
    arena_t *arena,
    const char *storage_path,
    mode_t mode,
    bool claimed
) {
    export_entry_t e;
    memset(&e, 0, sizeof(e));
    e.kind = EXPORT_ENTRY_DIRECTORY;
    e.storage_path = storage_path;
    e.rel_path = "";
    e.mode = mode;
    e.claimed = claimed;

    return entry_list_append(list, arena, &e);
}

/**
 * Join two path fragments into the arena ("" base yields rel verbatim).
 */
static char *arena_join_path(
    arena_t *arena,
    const char *base,
    const char *rel
) {
    if (base == NULL || base[0] == '\0') {
        return arena_strdup(arena, rel);
    }

    size_t base_len = strlen(base);
    size_t rel_len = strlen(rel);
    bool needs_slash = base[base_len - 1] != '/';

    char *joined = arena_alloc(
        arena, base_len + (needs_slash ? 1 : 0) + rel_len + 1
    );
    if (!joined) return NULL;

    memcpy(joined, base, base_len);
    size_t at = base_len;
    if (needs_slash) joined[at++] = '/';
    memcpy(joined + at, rel, rel_len + 1);
    return joined;
}

/**
 * Last path segment ("hosts/mbp" -> "mbp", "home/.bashrc" -> ".bashrc").
 */
static const char *path_basename(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/**
 * Resolve an entry's final mode, from the claim standing at its name.
 *
 * A claimed mode wins; the fallback is the git filemode for files (the same floor
 * the view resolves absence into) and the canonical default for directories.
 * Kind-checked so a stale item of the wrong kind cannot leak its mode across
 * entry types.
 *
 * The claim is the caller's rather than a key looked up here, because every
 * collector wants more of it than the mode — the directory arms its class, the
 * file arms its stamp — so the sheet is asked once per entry, where the entry
 * is made, and this is the rule alone. A NULL claim is the answer where the sheet
 * holds none, and the floor is what stands.
 *
 * This rule and `manifest_row_t.mode` are one rule with two spellings — the claim
 * of the matching kind, else the floor (core/manifest.h) — which is what lets
 * the path arm take a row's mode and read no sheet. They agree by contract, not
 * by coincidence: a change to either belongs in both.
 */
static mode_t export_entry_mode(
    const metadata_item_t *item,
    path_kind_t kind,
    git_filemode_t filemode
) {
    if (item && item->kind == kind && item->mode != MODE_UNCLAIMED) {
        return item->mode;
    }
    if (kind == PATH_KIND_DIRECTORY) {
        return DIR_MODE_DEFAULT;
    }

    return (filemode == GIT_FILEMODE_BLOB_EXECUTABLE) ? 0755 : 0644;
}

/**
 * The profile's claim sheet, or an empty one and a warning.
 *
 * Export's own sheet policy, in one place. A tree with no sheet loads as empty;
 * a sheet that will not load costs the copy its stored modes and its blob-less
 * directory claims — not the copy — and, an empty sheet stamping nothing, the
 * pre-write window for whatever of its content is sealed: those blobs are read
 * in phase 2 instead, by their bytes, so the copy still comes out right and is
 * no longer all-or-nothing under a key that will not open them. The bytes are
 * the tree's own and an export is often the repair, so this says what it lost
 * and lets the walk materialize git filemodes rather than refuse.
 *
 * The two arms that read a sheet call this. The arm that selects rows reads none:
 * it asks the profile's view, which is strict about the sheet by contract
 * (core/manifest.h), and inherits that answer.
 */
static error_t *load_sheet(
    const dotta_ctx_t *ctx,
    git_tree *tree,
    const char *profile,
    metadata_t **out
) {
    error_t *err = metadata_load_from_tree(ctx->run.repo, tree, profile, out);
    if (!err) return NULL;

    output_warning(
        ctx->out, OUTPUT_NORMAL,
        "Metadata unreadable for profile '%s' (%s); falling back to git filemodes",
        profile, error_message(err)
    );
    error_free(err);

    return metadata_create_empty(out);
}

/**
 * Apply the destination rules shared by every export shape.
 *
 * Expand '~', then on directory intent — an existing directory, or an explicit
 * trailing '/' — append `name` so `-o .` lands under the original name. Order
 * matters: expand, join, and only then let the caller validate the final path.
 * Returned string is arena-owned.
 *
 * A copy with no name of its own is the destination itself: the filesystem root
 * has no last segment, and there is nothing for a directory destination to nest
 * the copy under. Asked before the join, which refuses an empty component.
 */
static error_t *dest_resolve(
    const char *dest,
    const char *name,
    arena_t *arena,
    const char **out
) {
    char *expanded = NULL;
    error_t *err = fs_expand_tilde(dest, &expanded);
    if (err) return err;

    char *final = expanded;
    size_t len = strlen(expanded);
    if (name[0] != '\0' &&
        (fs_is_directory(expanded) || (len > 0 && expanded[len - 1] == '/'))) {
        char *joined = NULL;
        err = fs_path_join(expanded, name, &joined);
        free(expanded);
        if (err) return err;
        final = joined;
    }

    *out = arena_strdup(arena, final);
    free(final);
    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to allocate destination path");
    }
    return NULL;
}

/**
 * Phase-1 tree collection
 */
struct collect_ctx {
    const metadata_t *metadata;
    const char *profile;       /* Named by the refusal a malformed tree earns */
    const char *storage_base;  /* "" for whole profile, else target path */
    export_entry_list_t *list;
    arena_t *arena;
    error_t *error;
};

static int collect_tree_callback(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    struct collect_ctx *ctx = payload;
    const char *name = git_tree_entry_name(entry);

    /* Build path relative to the walked tree (root carries its own trailing '/'
     * at nested levels). */
    char rel[1024];
    int ret = snprintf(rel, sizeof(rel), "%s%s", root, name);
    if (ret < 0 || (size_t) ret >= sizeof(rel)) {
        ctx->error = ERROR(
            ERR_INTERNAL, "Path exceeds maximum length: %s%s", root, name
        );
        return -1;
    }

    export_entry_t e;
    memset(&e, 0, sizeof(e));
    e.rel_path = arena_strdup(ctx->arena, rel);
    e.storage_path = arena_join_path(ctx->arena, ctx->storage_base, rel);
    if (!e.rel_path || !e.storage_path) {
        ctx->error = ERROR(ERR_MEMORY, "Failed to allocate export entry");
        return -1;
    }

    /* The content gate every walk over a branch asks (infra/label.h
     * label_prefixes), of trees as much as blobs: a name in the grammar is content,
     * and whatever else the branch root holds — dotta's own files, a README a
     * hand left — is pruned with its subtree by the positive return. Beneath a
     * label the gate is always passed, and so is every rung of a named export's
     * walk, whose storage base already stands under one; it prunes at a
     * whole-profile walk's top level and nowhere else. */
    if (!label_prefixes(e.storage_path)) {
        return 1;
    }

    /* The name is Git's, not this machine's: a branch that arrived by clone,
     * push or `dotta git` was validated by whoever wrote it, which is to say
     * not at all, and a tree can name a subtree ".." or an entry "home/../x".
     * Asked of trees as much as blobs — an empty malicious subtree has no blob
     * for a blob-only check to meet — of every rung, the branch root's included,
     * and after the join, because the grammar is the whole path's (core/manifest.c
     * manifest_claim_blob makes the same check in the same words). A link's target
     * is the link's own business, copied verbatim, and is not a path of this
     * copy. */
    error_t *shape = label_validate_storage(e.storage_path);
    if (shape) {
        ctx->error = error_wrap(
            shape, "Invalid path in profile '%s'", ctx->profile
        );
        return -1;
    }

    /* The claim standing at this name, read once for whichever arm wants it. */
    const metadata_item_t *item = metadata_lookup(ctx->metadata, e.storage_path);

    switch (git_tree_entry_type(entry)) {
        case GIT_OBJECT_TREE: {
            e.kind = EXPORT_ENTRY_DIRECTORY;
            e.mode = export_entry_mode(
                item, PATH_KIND_DIRECTORY, GIT_FILEMODE_TREE
            );
            e.claimed = item && item->kind == PATH_KIND_DIRECTORY;
            break;
        }

        case GIT_OBJECT_BLOB: {
            git_filemode_t filemode = git_tree_entry_filemode(entry);
            git_oid_cpy(&e.blob_oid, git_tree_entry_id(entry));
            if (filemode == GIT_FILEMODE_LINK) {
                e.kind = EXPORT_ENTRY_SYMLINK;
            } else {
                e.kind = EXPORT_ENTRY_FILE;
                e.mode = export_entry_mode(item, PATH_KIND_FILE, filemode);
                e.encrypted = item && item->encrypted;
            }
            break;
        }

        default:
            ctx->error = ERROR(
                ERR_INVALID_ARG,
                "Unsupported entry '%s' in profile tree (submodule?)",
                e.storage_path
            );
            return -1;
    }

    error_t *err = entry_list_append(ctx->list, ctx->arena, &e);
    if (err) {
        ctx->error = err;
        return -1;
    }
    return 0;
}

/**
 * Order export entries by their path within the copy.
 *
 * Applied once to the whole list, after every collector and the completion: a
 * prefix compares less, so the root ("") leads, every directory precedes its
 * own contents, and reading backwards reaches the deepest first. Relative rather
 * than storage, because the root of a whole-profile copy has no storage path —
 * and within one copy the two orders agree anyway, every entry sharing one base.
 */
static int export_entry_cmp(const void *a, const void *b) {
    const export_entry_t *ea = a;
    const export_entry_t *eb = b;
    return strcmp(ea->rel_path, eb->rel_path);
}

/**
 * The branch's directory claims with no tree entry, appended beneath `base`.
 *
 * An empty tracked directory holds no blobs, so no walk can see it; the metadata
 * item is its whole Git footprint, and it is content — materialized at its stored
 * mode. `base` scopes the batch to one exported subtree (NULL for a whole profile);
 * the base itself is the copy's root and never a claim of the list. The sheet's
 * keys were checked against the storage grammar when the sheet loaded
 * (core/metadata.c), so unlike the walk's names they arrive well-formed.
 */
static error_t *append_claim_dirs(
    export_entry_list_t *list,
    arena_t *arena,
    const metadata_t *metadata,
    git_tree *tree,
    const char *base
) {
    size_t base_len = base ? strlen(base) : 0;

    size_t item_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);

    for (size_t i = 0; i < item_count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;
        const char *key = items[i]->key;

        const char *rel = key;
        if (base_len > 0) {
            if (strncmp(key, base, base_len) != 0 || key[base_len] != '/') {
                continue;
            }
            rel = key + base_len + 1;
        }

        /* Three answers, not two: the entry is there, it is absent, or the tree
         * will not read — a lookup that fails on a missing object is corruption
         * and not a claim without a blob. */
        git_tree_entry *probe = NULL;
        int rc = git_tree_entry_bypath(&probe, tree, key);
        if (rc == 0) {
            git_tree_entry_free(probe);
            continue;   /* Tree-backed: the walk collected it */
        }
        if (rc != GIT_ENOTFOUND) {
            return error_wrap(
                error_from_git(rc), "Failed to read '%s' in the profile tree", key
            );
        }

        export_entry_t e;
        memset(&e, 0, sizeof(e));
        e.kind = EXPORT_ENTRY_DIRECTORY;
        e.claimed = true;
        e.storage_path = arena_strdup(arena, key);
        if (!e.storage_path) {
            return ERROR(ERR_MEMORY, "Failed to allocate export entry");
        }
        e.rel_path = e.storage_path + (rel - key);
        e.mode = export_entry_mode(
            items[i], PATH_KIND_DIRECTORY, GIT_FILEMODE_TREE
        );

        error_t *err = entry_list_append(list, arena, &e);
        if (err) return err;
    }

    return NULL;
}

/**
 * The whole-profile arm: the branch's own layout, mirrored.
 *
 * The root is the destination and no path of the branch names it (dest/home/...,
 * dest/root/...), so the list opens with a root claiming nothing. The walk starts
 * at branch root, where the content gate prunes the machinery beside the labels,
 * and the sheet's blob-less directory claims follow it.
 *
 * Emptiness is asked here, at the arm's own source: a profile holding nothing
 * but its root has no content to copy.
 */
static error_t *collect_profile(
    const dotta_ctx_t *ctx,
    git_tree *tree,
    const char *profile,
    const char *commit_suffix,
    export_entry_list_t *list
) {
    arena_t *arena = ctx->arena;
    metadata_t *metadata = NULL;

    error_t *err = load_sheet(ctx, tree, profile, &metadata);
    if (err) return err;

    /* Under a directory destination the copy takes the profile's last segment
     * (hosts/mbp -> mbp). */
    list->basename = path_basename(profile);

    err = append_root(list, arena, NULL, DIR_MODE_DEFAULT, false);
    if (err) goto cleanup;

    struct collect_ctx cctx = {
        .metadata     = metadata,
        .profile      = profile,
        .storage_base = "",
        .list         = list,
        .arena        = arena,
        .error        = NULL
    };
    err = gitops_tree_walk(tree, collect_tree_callback, &cctx);
    if (cctx.error) {
        /* The callback error is the cause; the walk's generic user-abort wrapper
         * is noise. */
        error_free(err);
        err = cctx.error;
    }
    if (err) goto cleanup;

    err = append_claim_dirs(list, arena, metadata, tree, NULL);
    if (err) goto cleanup;

    if (list->count == 1) {
        err = ERROR(
            ERR_NOT_FOUND, "Profile '%s'%s has no exportable content",
            profile, commit_suffix
        );
    }

cleanup:
    metadata_free(metadata);
    return err;
}

/**
 * The name arm: the branch subtree the name holds, laid out beneath it.
 *
 * `name` is a key in the branch's own tree, validated where the argument was
 * read (infra/path.h) — a name beneath a label, or the label's word alone, which
 * is the namespace's own directory and a key like any other.
 *
 * What stands at the name is one read of the branch's two documents
 * (core/profiles.h profile_holds), answered four ways. A blob is the single-entry
 * copy, its destination the user's own path (cp semantics); a directory is the
 * copy's root, its subtree walked beneath it where the tree holds one and nothing
 * to walk where the sheet alone makes the claim — an empty tracked directory
 * has no tree entry, and the export is then the claim itself. Either way the
 * sheet's blob-less claims beneath the name follow the walk. A gitlink is refused,
 * and a name neither document holds is not found.
 */
static error_t *collect_storage(
    const dotta_ctx_t *ctx,
    git_tree *tree,
    const char *profile,
    const char *name,
    const char *commit_suffix,
    export_entry_list_t *list
) {
    arena_t *arena = ctx->arena;
    metadata_t *metadata = NULL;
    git_tree *subtree = NULL;

    error_t *err = load_sheet(ctx, tree, profile, &metadata);
    if (err) return err;

    list->basename = path_basename(name);

    /* The name, answered from both documents at once (core/profiles.h
     * profile_holds) — the sheet as this verb read it, tolerantly (load_sheet),
     * so a damaged sheet costs the copy a claim and never the tree's answer. */
    profile_held_t held;
    err = profile_holds(ctx->run.repo, tree, metadata, profile, name, &held);
    if (err) goto cleanup;

    switch (held.kind) {
        case PROFILE_HELD_NOTHING:
            err = ERROR(
                ERR_NOT_FOUND, "'%s' not found in profile '%s'%s",
                name, profile, commit_suffix
            );
            goto cleanup;

        case PROFILE_HELD_DIRECTORY: {
            /* Directory export: the target is the copy's root, and beneath it
             * the subtree is walked — or, where the sheet alone holds the claim,
             * there is no subtree to walk and any children are claims themselves,
             * collected by the append below. An empty tracked directory has no
             * tree entry, so the read answers it with no mode word at all
             * (core/profiles.h profile_held_t) and the export is then the claim
             * itself: the directory, at its stored mode. */
            const metadata_item_t *root_item = metadata_lookup(metadata, name);
            mode_t root_mode = export_entry_mode(
                root_item, PATH_KIND_DIRECTORY, GIT_FILEMODE_TREE
            );
            err = append_root(
                list, arena, name, root_mode,
                root_item && root_item->kind == PATH_KIND_DIRECTORY
            );
            if (err) goto cleanup;

            if (held.filemode == GIT_FILEMODE_TREE) {
                int git_ret = git_tree_lookup(&subtree, ctx->run.repo, &held.oid);
                if (git_ret < 0) {
                    err = error_from_git(git_ret);
                    goto cleanup;
                }

                struct collect_ctx cctx = {
                    .metadata     = metadata,
                    .profile      = profile,
                    .storage_base = name,
                    .list         = list,
                    .arena        = arena,
                    .error        = NULL
                };
                err = gitops_tree_walk(subtree, collect_tree_callback, &cctx);
                if (cctx.error) {
                    error_free(err);
                    err = cctx.error;
                }
                if (err) goto cleanup;
            }

            err = append_claim_dirs(list, arena, metadata, tree, name);
            goto cleanup;
        }

        case PROFILE_HELD_FILE: {
            /* Single-entry export: degenerate case of the walk. */
            export_entry_t e;
            memset(&e, 0, sizeof(e));
            e.storage_path = name;
            e.rel_path = list->basename;
            git_oid_cpy(&e.blob_oid, &held.oid);
            if (held.filemode == GIT_FILEMODE_LINK) {
                e.kind = EXPORT_ENTRY_SYMLINK;
            } else {
                const metadata_item_t *item = metadata_lookup(metadata, name);
                e.kind = EXPORT_ENTRY_FILE;
                e.mode = export_entry_mode(item, PATH_KIND_FILE, held.filemode);
                e.encrypted = item && item->encrypted;
            }

            err = entry_list_append(list, arena, &e);
            goto cleanup;
        }

        case PROFILE_HELD_SUBMODULE:
            err = ERROR(
                ERR_INVALID_ARG, "Unsupported entry type for '%s'", name
            );
            goto cleanup;
    }

cleanup:
    if (subtree) git_tree_free(subtree);
    metadata_free(metadata);
    return err;
}

/**
 * A view row as an export entry: the source's name, its bytes, its mode.
 *
 * The projection the path arm reads a row through. Every directory row is a claim
 * of the profile, derived or tracked alike — the file header's own argument:
 * every directory an export produces is one it creates, and creation is what
 * both classes bind. `encrypted` is the row's own — the sheet's stamp as the
 * view projects it — and says which blobs phase 1 reads (validate_content). A
 * link row carries neither a mode nor a stamp and needs neither: its bytes are
 * its target (core/manifest.h).
 */
static export_entry_t entry_from_row(const manifest_row_t *row) {
    export_entry_t e;
    memset(&e, 0, sizeof(e));
    e.storage_path = row->storage_path;

    switch (row->type) {
        case PATH_TYPE_DIRECTORY:
            e.kind = EXPORT_ENTRY_DIRECTORY;
            e.mode = row->mode;
            e.claimed = true;
            break;

        case PATH_TYPE_SYMLINK:
            e.kind = EXPORT_ENTRY_SYMLINK;
            git_oid_cpy(&e.blob_oid, &row->blob_oid);
            break;

        case PATH_TYPE_FILE:
        case PATH_TYPE_EXECUTABLE:
            e.kind = EXPORT_ENTRY_FILE;
            e.mode = row->mode;
            e.encrypted = row->encrypted;
            git_oid_cpy(&e.blob_oid, &row->blob_oid);
            break;
    }

    return e;
}

/**
 * The path arm: every row the profile places at or beneath the path, laid out
 * beneath it.
 *
 * One profile's view of one tree (core/manifest.h manifest_build_tree), built
 * under the run's table — so a path keys against a row by strcmp, both being
 * spellings (infra/mount.h) — and read for two questions: what stands at the
 * path, and what stands strictly beneath it. Everything the entries carry is
 * the rows': the mode is the claim or the floor the builder already resolved,
 * which is export_entry_mode's rule under another name, so no sheet is read here;
 * the source name is the row's own, which is the name its blob was sealed under
 * (the AAD, infra/content.h). A name the contribution did not keep is no row
 * and is not copied — the copy is what the profile would place, and that is what
 * the view answers.
 *
 * The row standing at the path decides the shape. A directory row is a claimed
 * root at its mode; no row at all is an unclaimed root at the default, the same
 * rung complete_directories supplies. A blob is the single-entry copy — and a
 * blob with rows beneath it refuses the copy, one filesystem being unable to
 * hold both where a branch can, two of its names reaching one chain
 * (core/manifest.h manifest_lookup_claim). A root of this machine's topology is
 * a path like any other here: rows beneath it, and nothing standing at it unless
 * a claim does. The rungs between the rows are complete_directories'.
 */
static error_t *collect_filesystem(
    const dotta_ctx_t *ctx,
    git_tree *tree,
    const char *profile,
    const char *filesystem_path,
    const char *commit_suffix,
    export_entry_list_t *list
) {
    arena_t *arena = ctx->arena;

    manifest_t *view = NULL;
    error_t *err = manifest_build_tree(
        ctx->run.repo, tree, profile, ctx->run.mounts, arena, &view
    );
    if (err) {
        return error_wrap(
            err, "Failed to read what profile '%s' places at '%s'",
            profile, filesystem_path
        );
    }

    /* The path as a prefix: the filesystem root is spelled "" — the one prefix
     * every absolute path is beneath, as the table spells it and the pathspec
     * reads it (infra/pathspec.c prefix_filesystem). The row standing at the
     * path is taken by the path itself, before the prefix is asked, so the root's
     * "" — which encloses "/" as well as everything under it — cannot claim it
     * twice. */
    const char *base = strcmp(filesystem_path, "/") == 0 ? "" : filesystem_path;
    size_t base_len = strlen(base);
    list->basename = path_basename(filesystem_path);

    const manifest_row_t *at = NULL;
    ptr_array_t beneath PTR_ARRAY_AUTO = { 0 };
    manifest_rows_t rows = manifest_rows(view);
    for (size_t i = 0; i < rows.count && !err; i++) {
        const manifest_row_t *row = rows.entries[i];
        if (strcmp(row->filesystem_path, filesystem_path) == 0) {
            at = row;
        } else if (str_path_beneath(row->filesystem_path, base, base_len)) {
            err = ptr_array_push(&beneath, row);
        }
    }
    if (err) goto cleanup;

    if (!at && beneath.count == 0) {
        /* A claim this machine cannot place stands nowhere and is no row — the
         * likely cause when a profile answers nothing at all, export's own case
         * being the profile this machine does not deploy. */
        const char *hint = manifest_unbound(view).count > 0
            ? "\nHint: some of this profile's paths have no deployment target on "
            "this machine and stand nowhere; export them by name (custom/...)"
            : "";
        err = ERROR(
            ERR_NOT_FOUND, "Profile '%s'%s places nothing at '%s'%s",
            profile, commit_suffix, filesystem_path, hint
        );
        goto cleanup;
    }

    if (at && at->type != PATH_TYPE_DIRECTORY) {
        if (beneath.count > 0) {
            /* The least path, so the refusal names one thing and names the same
             * one every run: row order is the view's own business. */
            const manifest_row_t *first = beneath.items[0];
            for (size_t i = 1; i < beneath.count; i++) {
                const manifest_row_t *row = beneath.items[i];
                if (strcmp(row->filesystem_path, first->filesystem_path) < 0) {
                    first = row;
                }
            }
            err = ERROR(
                ERR_CONFLICT,
                "Cannot export '%s': '%s' is a %s in profile '%s' and '%s' stands "
                "beneath it — one filesystem cannot hold both",
                filesystem_path, at->storage_path,
                at->type == PATH_TYPE_SYMLINK ? "symlink" : "file",
                profile, first->storage_path
            );
            goto cleanup;
        }

        export_entry_t e = entry_from_row(at);
        e.rel_path = list->basename;
        err = entry_list_append(list, arena, &e);
        goto cleanup;
    }

    err = append_root(
        list, arena, at ? at->storage_path : NULL,
        at ? at->mode : DIR_MODE_DEFAULT, at != NULL
    );

    for (size_t i = 0; i < beneath.count && !err; i++) {
        const manifest_row_t *row = beneath.items[i];
        export_entry_t e = entry_from_row(row);
        /* Past the base and its separator — borrowed from the row, whose string
         * is the arena's and outlives the view. For the filesystem root the base
         * is "" and the '+ 1' steps over the leading slash. */
        e.rel_path = row->filesystem_path + base_len + 1;
        err = entry_list_append(list, arena, &e);
    }

cleanup:
    manifest_free(view);
    return err;
}

/**
 * Complete the copy into a tree: every directory it needs is an entry, and nothing
 * stands beneath a file.
 *
 * The census holds every collected entry by its relative path. The climb reads
 * each proper prefix of each entry — every rung between the root and it — and
 * every rung must be a directory entry: one no entry names is supplied at the
 * default mode claiming nothing (core/deploy's own rule for an ancestor no verdict
 * covers), and one a file or a link stands at refuses the copy, a filesystem
 * being unable to hold both a file and paths beneath it where a branch can, two
 * of its names reaching one chain. Run after any collector, because each leaves
 * its own kind of gap: the walk sees every tree node but never the label above
 * a blob-less claim, and a selection of rows sees claims but never the rungs
 * between them.
 *
 * What it establishes is what phase 1 goes on to trust — an lstat of every entry
 * covers every content-dictated component beneath the root, so a symlink standing
 * at any of them is refused before a byte is written. The root's own ancestors
 * are the user's typed destination and follow normal resolution (cp semantics);
 * this is about the paths content dictates.
 *
 * The census holds each entry by index rather than by pointer — the spine moves
 * when a rung is appended, an index does not — so a refusal can name the entry
 * standing in the way, and index zero (the root) stays distinct from absence by
 * the customary +1. Only the collected entries climb: a supplied rung's own
 * prefixes were the climb that supplied it.
 */
static error_t *complete_directories(export_entry_list_t *list, arena_t *arena) {
    hashmap_t *standing = hashmap_borrow(list->count);
    if (!standing) {
        return ERROR(ERR_MEMORY, "Failed to index the export entries");
    }

    error_t *err = NULL;
    for (size_t i = 0; i < list->count && !err; i++) {
        err = hashmap_set(
            standing, list->items[i].rel_path, (void *) (uintptr_t) (i + 1)
        );
    }

    size_t collected = list->count;

    for (size_t i = 0; i < collected && !err; i++) {
        /* One copy spells every prefix of this entry in turn. */
        char *rung = strdup(list->items[i].rel_path);
        if (!rung) {
            err = ERROR(ERR_MEMORY, "Failed to copy a path for the climb");
            break;
        }

        for (char *slash = strchr(rung, '/'); slash && !err;
            slash = strchr(slash + 1, '/')) {
            *slash = '\0';

            size_t held = (size_t) (uintptr_t) hashmap_get(standing, rung);
            if (held == 0) {
                export_entry_t e;
                memset(&e, 0, sizeof(e));
                e.kind = EXPORT_ENTRY_DIRECTORY;
                e.mode = DIR_MODE_DEFAULT;
                e.rel_path = arena_strdup(arena, rung);
                if (!e.rel_path) {
                    err = ERROR(ERR_MEMORY, "Failed to allocate export entry");
                } else {
                    err = entry_list_append(list, arena, &e);
                }
                if (!err) {
                    err = hashmap_set(
                        standing, e.rel_path, (void *) (uintptr_t) list->count
                    );
                }
            } else if (list->items[held - 1].kind != EXPORT_ENTRY_DIRECTORY) {
                /* Both subjects in the branch's own names, because the
                 * contradiction is the branch's and that is where it gets fixed.
                 * Every entry that climbs carries one: a leaf comes from a source
                 * that named it, and the root — the only collected entry without
                 * a name — holds no slash to climb. */
                const export_entry_t *blocker = &list->items[held - 1];
                err = ERROR(
                    ERR_CONFLICT,
                    "Cannot export '%s': '%s' is a %s in this profile, so "
                    "nothing can stand beneath it",
                    list->items[i].storage_path, blocker->storage_path,
                    blocker->kind == EXPORT_ENTRY_SYMLINK ? "symlink" : "file"
                );
            }

            *slash = '/';
        }

        free(rung);
    }

    hashmap_free(standing, NULL);
    return err;
}

/**
 * Phase-1 destination resolution: every entry's final path, in one pass.
 *
 * The copy's first entry — the root of a tree-shaped copy, the leaf of a
 * single-file one — takes the destination itself, which is where dest_resolve
 * applies the directory-intent rule to the copy's name; everything else hangs
 * off it by the relative path its collector gave it. The layout is the collection's
 * and where it lands is this pass's, so no collector knows a destination at all
 * — which is also why a '-' export resolves none.
 */
static error_t *resolve_destinations(
    export_entry_list_t *list,
    const char *output,
    arena_t *arena
) {
    error_t *err = dest_resolve(
        output, list->basename, arena, &list->items[0].dest_path
    );
    if (err) return err;

    const char *root = list->items[0].dest_path;
    for (size_t i = 1; i < list->count; i++) {
        list->items[i].dest_path = arena_join_path(
            arena, root, list->items[i].rel_path
        );
        if (!list->items[i].dest_path) {
            return ERROR(ERR_MEMORY, "Failed to allocate destination path");
        }
    }

    return NULL;
}

/**
 * Phase-1 destination validation.
 *
 * lstat every entry's final path — the root among them — and refuse anything
 * that would collide by type or write through a pre-existing symlink. Below the
 * export root every intermediate directory is itself an entry
 * (complete_directories), so checking entries covers every content-dictated path
 * component; the root's own ancestors are user-typed and deliberately follow
 * normal filesystem resolution (cp semantics).
 *
 * A single-file copy — the list whose one entry is a leaf rather than a root —
 * keeps the shipped cp semantics for its user-typed destination: writing through
 * a symlink there is the user's stated intent, while content-dictated paths inside
 * a tree copy refuse symlinks outright (the escape vector).
 */
static error_t *validate_destinations(export_entry_list_t *list) {
    const bool single_dest = list->items[0].rel_path[0] != '\0';

    for (size_t i = 0; i < list->count; i++) {
        export_entry_t *e = &list->items[i];

        struct stat st;
        if (fs_lstat(e->dest_path, &st) != 0) {
            if (errno == ENOENT) continue;  /* Fresh path */
            if (errno == ENOTDIR) {
                return ERROR(
                    ERR_CONFLICT,
                    "A path component of '%s' exists and is not a directory",
                    e->dest_path
                );
            }
            return error_from_errno(errno, "Cannot stat '%s'", e->dest_path);
        }

        switch (e->kind) {
            case EXPORT_ENTRY_DIRECTORY:
                if (S_ISDIR(st.st_mode)) {
                    e->dest_existed = true;
                    break;
                }
                if (S_ISLNK(st.st_mode)) {
                    return ERROR(
                        ERR_CONFLICT,
                        "'%s' is a symlink where a directory must go — "
                        "refusing to write through it", e->dest_path
                    );
                }
                return ERROR(
                    ERR_CONFLICT,
                    "'%s' exists and is not a directory", e->dest_path
                );

            case EXPORT_ENTRY_FILE:
                if (S_ISDIR(st.st_mode)) {
                    return ERROR(
                        ERR_CONFLICT,
                        "'%s' is a directory where a file must go",
                        e->dest_path
                    );
                }
                if (S_ISLNK(st.st_mode)) {
                    /* Follow: a link to a directory can't take a write */
                    if (fs_is_directory(e->dest_path)) {
                        return ERROR(
                            ERR_CONFLICT, "Destination '%s' is a directory",
                            e->dest_path
                        );
                    }
                    if (!single_dest) {
                        return ERROR(
                            ERR_CONFLICT,
                            "'%s' is a symlink where a file must go — "
                            "refusing to write through it", e->dest_path
                        );
                    }
                }
                break;

            case EXPORT_ENTRY_SYMLINK:
                if (S_ISDIR(st.st_mode)) {
                    return ERROR(
                        ERR_CONFLICT,
                        "'%s' is a directory where a symlink must go",
                        e->dest_path
                    );
                }
                break;  /* File or symlink: replaced in phase 2 */
        }
    }

    return NULL;
}

/**
 * Phase-1 content validation.
 *
 * The stamp schedules the read; it never routes it. Every file the sheet stamps
 * sealed is read NOW and its plaintext held: the first decryption triggers the
 * passphrase prompt, so the prompt and every crypto failure (no key, wrong key,
 * corruption, path mismatch, a version this build does not read) land in the
 * pre-write window, each in the content reader's own words — its ladder names
 * the path and the cause, and nothing here restates either. Symlink targets are
 * read here too: tiny, needed by phase 2, and shown by --dry-run.
 *
 * What the stamp cannot do is decide a blob's kind, and it is never asked to:
 * the reader classifies the bytes itself (infra/content.h), so an unstamped blob
 * the store sealed is read correctly in phase 2 and one stamped over plaintext
 * is copied. A wrong stamp therefore costs a glyph on two screens, the moment a
 * prompt appears, or the memory of a blob held early — never a byte. Asking the
 * bytes here instead would inflate every blob of the copy to read six of them,
 * and inflate each again to write it, there being no partial read of a packed
 * object.
 *
 * The stamp needs no kind test of its own: a directory claim carries none, by
 * construction at both of the sheet's boundaries (core/metadata.h).
 */
static error_t *validate_content(
    const dotta_ctx_t *ctx, const char *profile, export_entry_list_t *list
) {
    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;

    for (size_t i = 0; i < list->count; i++) {
        export_entry_t *e = &list->items[i];

        switch (e->kind) {
            case EXPORT_ENTRY_DIRECTORY:
                break;

            case EXPORT_ENTRY_SYMLINK: {
                error_t *err = content_get_from_blob_oid(
                    repo, &e->blob_oid, GIT_FILEMODE_LINK, e->storage_path,
                    profile, keymgr, &e->content
                );
                if (err) {
                    return error_wrap(
                        err, "Failed to read symlink '%s'", e->storage_path
                    );
                }
                e->content_held = true;
                if (e->content.size == 0) {
                    return ERROR(
                        ERR_INVALID_ARG, "Symlink '%s' has an empty target",
                        e->storage_path
                    );
                }
                break;
            }

            case EXPORT_ENTRY_FILE: {
                /* Unstamped: phase 2 reads it, by its bytes, and holds nothing
                 * until then. */
                if (!e->encrypted) break;

                /* Sealed — or sealed under a version this build does not read,
                 * which the reader refuses with the version pair. Its error passes
                 * through: "Cannot decrypt '<path>'" over the cause is the whole
                 * story. */
                error_t *err = content_get_from_blob_oid(
                    repo, &e->blob_oid, GIT_FILEMODE_BLOB, e->storage_path,
                    profile, keymgr, &e->content
                );
                if (err) {
                    return err;
                }
                e->content_held = true;
                break;
            }
        }
    }

    return NULL;
}

/**
 * Phase 2: materialize entries.
 *
 * Directories are created with `mode | S_IRWXU` so children can land even under
 * restrictive stored modes (0500), then chmod'd to the exact stored mode
 * deepest-first after the subtree is fully written. Pre-existing directories
 * are never touched — the copy makes no claim over what was already there.
 *
 * Sorted order does the sequencing: the root leads and every directory precedes
 * its own contents, so nothing here creates a path phase 1 did not lstat, and
 * the reverse pass reaches the deepest first and the root last.
 */
static error_t *materialize_entries(
    const dotta_ctx_t *ctx,
    const char *profile,
    export_entry_list_t *list,
    bool verbose
) {
    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;
    output_t *out = ctx->out;

    error_t *err = NULL;

    for (size_t i = 0; i < list->count; i++) {
        export_entry_t *e = &list->items[i];
        bool is_root = e->rel_path[0] == '\0';

        switch (e->kind) {
            case EXPORT_ENTRY_DIRECTORY:
                if (e->dest_existed) break;
                /* Parents only for the root, whose ancestors are the destination
                 * the user typed and follow normal resolution (cp semantics).
                 * Every directory beneath it is an entry created before this
                 * loop reached its contents (complete_directories). */
                err = fs_create_dir_with_mode(e->dest_path, e->mode | S_IRWXU, is_root);
                if (err) {
                    return error_wrap(
                        err, "Failed to create directory '%s'", e->dest_path
                    );
                }
                if (verbose && !is_root) {
                    output_styled(
                        out, OUTPUT_NORMAL, "  created {cyan}%s/{reset} (mode %04o)\n",
                        e->rel_path, (unsigned) e->mode
                    );
                }
                break;

            case EXPORT_ENTRY_FILE: {
                buffer_t local = BUFFER_INIT;
                const buffer_t *bytes = &e->content;
                if (!e->content_held) {
                    err = content_get_from_blob_oid(
                        repo, &e->blob_oid, GIT_FILEMODE_BLOB, e->storage_path,
                        profile, keymgr, &local
                    );
                    if (err) {
                        return error_wrap(err, "Failed to read '%s'", e->storage_path);
                    }
                    bytes = &local;
                }

                err = fs_write_file_raw(
                    e->dest_path, (const unsigned char *) bytes->data,
                    bytes->size, e->mode, (uid_t) -1, (gid_t) -1, NULL
                );
                buffer_free(&local);
                if (err) {
                    return error_wrap(
                        err, "Failed to write '%s'", e->dest_path
                    );
                }
                if (verbose) {
                    output_styled(
                        out, OUTPUT_NORMAL, "  wrote {cyan}%s{reset} (mode %04o%s)\n",
                        e->rel_path, (unsigned) e->mode, e->encrypted ? ", decrypted" : ""
                    );
                }
                break;
            }

            case EXPORT_ENTRY_SYMLINK:
                /* Blob content is the target path; recreate the link. symlink(2)
                 * cannot overwrite — clear any stale entry. */
                err = fs_remove_file(e->dest_path);
                if (err) return err;

                /* The one-entry copy's destination is the user's own path, and
                 * its parent is created here exactly as fs_write_file_raw creates
                 * one for a file (sys/filesystem.h). Inside a tree copy every
                 * parent is already an entry, created before this loop reached
                 * the link. */
                err = fs_ensure_parent_dirs(e->dest_path);
                if (err) return err;

                err = fs_create_symlink(
                    (const char *) e->content.data, e->dest_path,
                    (uid_t) -1, (gid_t) -1      /* no claim: the export's own */
                );
                if (err) {
                    return error_wrap(
                        err, "Failed to create symlink '%s'", e->dest_path
                    );
                }
                if (verbose) {
                    output_styled(
                        out, OUTPUT_NORMAL, "  linked {cyan}%s{reset} -> %s\n",
                        e->rel_path, (const char *) e->content.data
                    );
                }
                break;
        }
    }

    /* Exact directory modes, deepest-first, created-by-us only. A stored mode
     * already carrying owner-rwx was applied at creation. */
    for (size_t i = list->count; i-- > 0;) {
        export_entry_t *e = &list->items[i];
        if (e->kind != EXPORT_ENTRY_DIRECTORY || e->dest_existed) continue;
        if ((e->mode | S_IRWXU) == e->mode) continue;

        err = fs_set_permissions(e->dest_path, e->mode);
        if (err) {
            return error_wrap(
                err, "Failed to set mode on '%s'", e->dest_path
            );
        }
    }

    return NULL;
}

/**
 * Print the --dry-run plan: header plus one line per file entry and per directory
 * claim (slash-marked; scaffolding directories are not listed).
 *
 * The root is not a line of it: the header names the destination, and the root
 * is the destination. Everything listed is relative to it.
 */
static void print_dry_run(
    output_t *out,
    const export_entry_list_t *list,
    const char *counts,
    const char *dest_display,
    const char *profile,
    const char *commit_suffix
) {
    output_styled(
        out, OUTPUT_NORMAL,
        "Would export %s to {cyan}%s{reset} "
        "(from {magenta}%s{reset}%s):\n",
        counts, dest_display, profile, commit_suffix
    );

    int width = 0;
    for (size_t i = 0; i < list->count; i++) {
        const export_entry_t *e = &list->items[i];
        if (e->rel_path[0] == '\0') continue;
        if (e->kind == EXPORT_ENTRY_DIRECTORY && !e->claimed) continue;
        int len = (int) strlen(e->rel_path) +
            (e->kind == EXPORT_ENTRY_DIRECTORY ? 1 : 0);
        if (len > width) width = len;
    }
    if (width > 48) width = 48;

    for (size_t i = 0; i < list->count; i++) {
        const export_entry_t *e = &list->items[i];
        if (e->rel_path[0] == '\0') continue;

        switch (e->kind) {
            case EXPORT_ENTRY_DIRECTORY: {
                if (!e->claimed) break;
                int len = (int) strlen(e->rel_path) + 1;
                int pad = width > len ? width - len : 0;
                output_print(
                    out, OUTPUT_NORMAL, "  %s/%*s (mode %04o)\n",
                    e->rel_path, pad, "", (unsigned) e->mode
                );
                break;
            }
            case EXPORT_ENTRY_FILE:
                output_print(
                    out, OUTPUT_NORMAL, "  %-*s (mode %04o%s)\n",
                    width, e->rel_path, (unsigned) e->mode,
                    e->encrypted ? ", encrypted" : ""
                );
                break;
            case EXPORT_ENTRY_SYMLINK:
                output_print(
                    out, OUTPUT_NORMAL, "  %-*s (symlink -> %s)\n",
                    width, e->rel_path, (const char *) e->content.data
                );
                break;
        }
    }
}

/**
 * Write raw bytes to stdout ('-o -').
 *
 * Byte-faithful: no headers, no trailing-newline normalization — unlike show,
 * which is a terminal display. Flushes so buffered IO failures surface as a
 * non-zero exit.
 */
static error_t *write_bytes_stdout(const buffer_t *content) {
    if (content->size > 0 &&
        fwrite(content->data, 1, content->size, stdout) != content->size) {
        return ERROR(ERR_FS, "Failed to write content to stdout");
    }
    if (fflush(stdout) != 0) {
        return ERROR(ERR_FS, "Failed to write content to stdout");
    }
    return NULL;
}

/**
 * Export command implementation
 */
error_t *cmd_export(const dotta_ctx_t *ctx, const cmd_export_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->profile);
    CHECK_NULL(opts->output);
    /* '-' names one file's bytes, so a path was named — export_post_parse refuses
     * the pairing in its own words, and the refusal below names what was typed. */
    CHECK_ARG(
        strcmp(opts->output, "-") != 0 || opts->file_path != NULL,
        "A stdout export must name a path"
    );

    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;
    output_t *out = ctx->out;
    arena_t *arena = ctx->arena;
    bool to_stdout = strcmp(opts->output, "-") == 0;
    bool verbose = opts->verbose || output_is_verbose(out);

    /* '-' dedicates stdout to the payload. Errors already live there. */
    if (to_stdout) output_set_stream(out, stderr);

    error_t *err = NULL;
    git_commit *commit = NULL;
    git_tree *tree = NULL;
    export_entry_list_t list = { 0 };
    char commit_suffix[16] = "";

    /* Export is local-only: no network IO, ever. The explicit porcelain for making
     * a profile local already exists, and the refusal names it. */
    err = profile_require(repo, opts->profile);
    if (err) goto cleanup;

    /* Load the tree (HEAD or historical commit). Every arm reads the SAME tree
     * — its claim sheet included — so historical exports get historical modes
     * and encryption flags. */
    if (opts->commit) {
        /* The resolution names both the commit and the branch in every fate it
         * has (sys/gitops.h): nothing to restate, and the sentence that used to
         * stand over it said "not found" of an ancestry the walk could not read. */
        err = gitops_resolve_commit_in_branch(
            repo, opts->profile, opts->commit, &commit
        );
        if (err) goto cleanup;

        /* The commit is in hand and its tree is one dereference away; the OID
         * helper beside this one would look the commit up a second time. */
        int git_ret = git_commit_tree(&tree, commit);
        if (git_ret < 0) {
            err = error_wrap(
                error_from_git(git_ret),
                "Failed to load tree from commit '%s'", opts->commit
            );
            goto cleanup;
        }

        char oid_str[8];
        git_oid_tostr(oid_str, sizeof(oid_str), git_commit_id(commit));
        snprintf(commit_suffix, sizeof(commit_suffix), " @ %s", oid_str);
    } else {
        err = gitops_load_branch_tree(repo, opts->profile, &tree, NULL);
        if (err) {
            err = error_wrap(
                err, "Failed to load tree for profile '%s'", opts->profile
            );
            goto cleanup;
        }
    }

    if (opts->file_path) {
        /* Read the argument in the key the user named — a path or a storage path,
         * neither manufactured from the other (infra/path.h) — and hand it to
         * the arm that answers in that key. A storage shape was validated as
         * typed and carries no trailing slash; a filesystem shape was normalized.
         *
         * Every refusal is the resolver's, in the resolver's words: a `..` in a
         * tail, a tilde it cannot expand, an empty path — and a word standing
         * alone, which is neither shape and has no reading here either. The three
         * words are names, and the resolver reads them; anything else standing
         * alone is a word this verb knows nothing more about than the resolver
         * does, so export says nothing of its own about one. The branch's own
         * files beside the labels are not content and `dotta git` reads them
         * (the help). */
        path_input_t arg;
        err = path_input_resolve(opts->file_path, arena, &arg);
        if (err) goto cleanup;

        switch (arg.key) {
            case PATH_KEY_FILESYSTEM:
                err = collect_filesystem(
                    ctx, tree, opts->profile, arg.filesystem_path, commit_suffix, &list
                );
                break;

            case PATH_KEY_STORAGE:
                err = collect_storage(
                    ctx, tree, opts->profile, arg.storage_path, commit_suffix,
                    &list
                );
                break;
        }
        if (err) goto cleanup;
    } else {
        err = collect_profile(ctx, tree, opts->profile, commit_suffix, &list);
        if (err) goto cleanup;
    }

    /* Which shape the copy is, asked of the list rather than remembered by the
     * arms: a tree-shaped one opens with its root, a single-file one is its
     * leaf. */
    bool tree_export = list.items[0].rel_path[0] == '\0';

    /* ── Phase 1 validation: every refusal before the first byte ── */

    if (to_stdout && tree_export) {
        err = ERROR(
            ERR_INVALID_ARG,
            "'-' streams a single file's bytes; '%s' is a directory and "
            "needs a path destination", opts->file_path
        );
        goto cleanup;
    }

    if (tree_export) {
        err = complete_directories(&list, arena);
        if (err) goto cleanup;
    }

    qsort(list.items, list.count, sizeof(*list.items), export_entry_cmp);

    if (!to_stdout) {
        err = resolve_destinations(&list, opts->output, arena);
        if (err) goto cleanup;

        err = validate_destinations(&list);
        if (err) goto cleanup;
    }

    err = validate_content(ctx, opts->profile, &list);
    if (err) goto cleanup;

    /* ── Reporting / phase 2 ── */

    /* The counts phrase: files (symlinks included) and the directory claims this
     * export materializes — the root among them when it is itself a claim, since
     * the root is an entry like any other. Scaffolding directories are plumbing,
     * not content: uncounted. */
    size_t file_count = 0;
    size_t dir_claims = 0;
    for (size_t i = 0; i < list.count; i++) {
        if (list.items[i].kind == EXPORT_ENTRY_DIRECTORY) {
            if (list.items[i].claimed) dir_claims++;
        } else {
            file_count++;
        }
    }
    char counts[64];
    output_format_counts(file_count, dir_claims, counts, sizeof(counts));

    /* The copy's own first entry: the root for a tree, the leaf for a file. */
    const char *dest_display = to_stdout ? "stdout" : list.items[0].dest_path;

    if (opts->dry_run) {
        print_dry_run(
            out, &list, counts, dest_display, opts->profile, commit_suffix
        );
        goto cleanup;
    }

    if (to_stdout) {
        /* Bytes only — any styled output would corrupt the stream. */
        export_entry_t *e = &list.items[0];
        if (e->content_held) {
            err = write_bytes_stdout(&e->content);
        } else {
            /* An unstamped file's: a link's target and a stamped file's plaintext
             * are held since phase 1 (validate_content) */
            buffer_t local = BUFFER_INIT;
            err = content_get_from_blob_oid(
                repo, &e->blob_oid, GIT_FILEMODE_BLOB, e->storage_path,
                opts->profile, keymgr, &local
            );
            if (!err) err = write_bytes_stdout(&local);
            buffer_free(&local);
        }
        goto cleanup;
    }

    err = materialize_entries(ctx, opts->profile, &list, verbose);
    if (err) goto cleanup;

    output_styled(
        out, OUTPUT_NORMAL,
        "Exported %s to {cyan}%s{reset} (from {magenta}%s{reset}%s)\n",
        counts, dest_display, opts->profile, commit_suffix
    );

cleanup:
    for (size_t i = 0; i < list.count; i++) {
        if (list.items[i].content_held) {
            buffer_free(&list.items[i].content);
        }
    }
    if (tree) git_tree_free(tree);
    if (commit) git_commit_free(commit);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Interpret the 1-3 raw positionals into `profile`, `file_path`, and `commit`.
 * The profile is always explicit — shapes:
 *
 *   <profile>                          whole profile at HEAD
 *   <profile>@<commit>                 whole profile, historical
 *   <profile>:<path>[@commit]          refspec
 *   <profile> <path>[@commit]          two positionals
 *   <profile> <commit>                 whole profile, historical
 *   <profile> <path> <commit>          three positionals
 *
 * Allocation model mirrors show: refspec strings live in `arena`, pure positionals
 * borrow argv. The destination is settled last: every shape must have named one,
 * and '-' can only stream a single file.
 */
static error_t *export_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) cmd;
    cmd_export_options_t *o = opts_v;
    char **args = o->positional_args;

    /* A path in the profile slot is the one predictable misuse — catch it with
     * a usage hint instead of a branch-lookup error. Alone, a name in the grammar
     * — beneath a label or the label's word itself — is content and never a branch;
     * with a second positional the first word is the profile, whatever it looks
     * like. */
    const char *first = args[0];
    if (first[0] == '~' || first[0] == '/' ||
        (o->positional_count == 1 && label_prefixes(first))) {
        return ERROR(
            ERR_INVALID_ARG,
            "'%s' looks like a path — export requires an explicit "
            "profile\nUsage: dotta export <profile> %s -o <dest>",
            first, first
        );
    }

    if (o->positional_count == 1) {
        refspec_t rs = { 0 };
        error_t *err = parse_refspec(arena, first, &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse target specification");
        }
        if (rs.profile != NULL) {
            /* <profile>:<path>[@commit] */
            o->profile = rs.profile;
            o->file_path = rs.file;
            o->commit = rs.commit;
        } else if (rs.commit != NULL) {
            /* <profile>@<commit> — whole profile, historical */
            o->profile = rs.file;
            o->commit = rs.commit;
        } else {
            /* <profile> — whole profile at HEAD */
            o->profile = first;
        }
    } else if (strchr(args[0], ':') != NULL) {
        /* Colon-packed refspec first: ':' is never legal in a branch name, so
         * the token is self-contained and the next positional is the destination
         * (cp-style; '-o' stays valid as the explicit form). Only the colon form
         * earns this — every other shape would need a heuristic on the destination
         * token to distinguish it from a path or commit, and heuristics on user
         * paths are how silent misroutes happen. */
        refspec_t rs = { 0 };
        error_t *err = parse_refspec(arena, args[0], &rs);
        if (err != NULL) {
            return error_wrap(err, "Failed to parse target specification");
        }
        if (rs.profile == NULL) {
            return ERROR(
                ERR_INVALID_ARG, "Failed to parse target specification '%s'",
                args[0]
            );
        }
        o->profile = rs.profile;
        o->file_path = rs.file;
        o->commit = rs.commit;

        if (o->positional_count > 2) {
            return ERROR(
                ERR_INVALID_ARG,
                "Too many arguments for the refspec form\n"
                "Usage: dotta export <profile>:<path>[@commit] <dest>"
            );
        }
        if (o->output != NULL) {
            return ERROR(
                ERR_INVALID_ARG,
                "Destination given twice: '-o %s' and positional '%s'",
                o->output, args[1]
            );
        }
        o->output = args[1];
    } else if (o->positional_count == 2) {
        o->profile = args[0];

        /* A bare ref selects a whole-profile historical export; anything
         * path-shaped goes through refspec parsing. */
        if (refspec_looks_like_commit(args[1]) && !strchr(args[1], '/') &&
            !strchr(args[1], '.')) {
            o->commit = args[1];
        } else {
            refspec_t rs = { 0 };
            error_t *err = parse_refspec(arena, args[1], &rs);
            if (err != NULL) {
                return error_wrap(err, "Failed to parse file specification");
            }
            if (rs.profile != NULL) o->profile = rs.profile;
            o->file_path = rs.file;
            o->commit = rs.commit;
        }
    } else {
        /* count == 3 (engine-enforced max): <profile> <path> <commit> */
        o->profile = args[0];
        o->file_path = args[1];
        o->commit = args[2];
    }

    if (o->output == NULL || o->output[0] == '\0') {
        return ERROR(
            ERR_INVALID_ARG,
            "A destination is required: -o <dest>, or a positional after "
            "the <profile>:<path> form ('-' streams to stdout)"
        );
    }
    if (strcmp(o->output, "-") == 0 && o->file_path == NULL) {
        return ERROR(
            ERR_INVALID_ARG,
            "'-' streams a single file's bytes; a whole-profile export "
            "needs a path destination"
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor, by the shapes export_post_parse reads: a local
 * profile or a refspec first. After `profile:path` the destination, a filesystem
 * path; after a bare profile a file or directory claim of its branch, or a commit;
 * then the commit. An `@` in the token being typed completes its commit part
 * from the profile's history; -o takes a path.
 */
static args_want_t export_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_export_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_export_options_t, output)) {
        return ARGS_WANT_FILES;
    }
    if (completion_commits_at(ctx, out, at->current, NULL)) {
        return ARGS_WANT_NONE;
    }

    if (o->positional_count == 0) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        completion_refspecs(ctx, out, NULL);
        return ARGS_WANT_NONE;
    }
    if (strchr(o->positional_args[0], ':') != NULL) {
        /* Colon-packed: the destination follows, nothing after it. */
        return o->positional_count == 1 ? ARGS_WANT_FILES : ARGS_WANT_NONE;
    }

    const char *profile = completion_profile_of(ctx, o->positional_args[0]);
    if (o->positional_count == 1) {
        completion_refspecs(ctx, out, profile);
        completion_directories(ctx, out, profile);
        completion_history(ctx, out, profile);
    } else if (o->positional_count == 2) {
        completion_history(ctx, out, profile);
    }
    return ARGS_WANT_NONE;
}

static error_t *export_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_export(ctx, (const cmd_export_options_t *) opts_v);
}

static const args_opt_t export_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "o output",          "<dest>",
        cmd_export_options_t,output,
        "Destination path ('-' streams a single file to stdout)"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_export_options_t,dry_run,
        "Resolve and validate everything, write nothing; list the plan"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_export_options_t,verbose,
        "Per-entry progress lines"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_export_options_t,positional_args, positional_count,
        1,                   3
    ),
    ARGS_END,
};

const args_command_t spec_export = {
    .name        = "export",
    .summary     = "Materialize profile content to the filesystem",
    .usage       =
        "%s export <profile>:<path>[@commit] <dest>\n"
        "   or: %s export <profile> [<path>] -o <dest>\n"
        "   or: %s export <profile>[@commit] [<path>] [<commit>] -o <dest>",
    .description =
        "Copy content out of a profile branch without deploying it:\n"
        "nothing registers in state, ownership is never applied, and\n"
        "dotta makes no ongoing claim over the destination. Content is\n"
        "decrypted, stored permission modes are applied, and profile\n"
        "machinery (.dotta/, .bootstrap, ...) never lands in an export.\n",
    .notes       =
        "Semantics:\n"
        "  An export copies ONE profile branch verbatim — layers are\n"
        "  not composed, so 'export darwin ~/.config/nvim' yields\n"
        "  darwin's files even where hosts/* would override them at\n"
        "  deploy time. The profile is always explicit; disabled and\n"
        "  foreign profiles work the same as enabled ones but must\n"
        "  exist locally ('dotta profile fetch <name>' first — export\n"
        "  itself never touches the network).\n"
        "\n"
        "Naming what is copied:\n"
        "  Without a path the whole profile is exported, storage layout\n"
        "  mirrored (home/, root/, custom/). A label alone copies one of\n"
        "  those namespaces whole ('home' or 'home/'); a storage path\n"
        "  beneath it copies that branch subtree. A filesystem path\n"
        "  copies what the profile PLACES there on this machine — every\n"
        "  path it puts at or beneath that directory, however each one\n"
        "  is stored, laid out beneath it. The two can differ: a file\n"
        "  captured before a profile had a target and one captured\n"
        "  after are stored two different ways and deploy to the same\n"
        "  directory. A profile with no deployment target here places\n"
        "  none of its custom/ paths; export those by name.\n"
        "  The branch's own files beside the labels (.dotta/,\n"
        "  .bootstrap, a README) are not content and never export;\n"
        "  'dotta git show <profile>:<file>' reads them.\n"
        "\n"
        "Destination:\n"
        "  The refspec form takes its destination as the next argument\n"
        "  ('export darwin:home/.bashrc .' reads like cp); every other\n"
        "  shape names it explicitly with -o. An existing directory (or\n"
        "  trailing '/') receives the target under its original name —\n"
        "  '.' exports here. Otherwise <dest> itself is the target file\n"
        "  or directory root. Existing files are overwritten (cp\n"
        "  semantics); type collisions and pre-existing symlinks in\n"
        "  content paths refuse the whole export before anything is\n"
        "  written.\n",
    .examples    =
        "  %s export darwin:home/.bashrc .                  # cp-style, original name\n"
        "  %s export hosts/mbp:home/.config/nvim ./nvim     # Directory\n"
        "  %s export darwin:home/.bashrc@a4f2c8e old        # Historical file\n"
        "  %s export darwin ~/.bashrc -o .                  # Explicit -o form\n"
        "  %s export web ~/.config -o cfg                   # All web places under ~/.config\n"
        "  %s export hosts/mbp -o mbp-files                 # Whole profile\n"
        "  %s export hosts/mbp@a4f2c8e -o mbp-old           # Whole profile, historical\n"
        "  %s export global:home/.ssh/config -              # Bytes to stdout\n"
        "  %s export hosts/vps -o /tmp/vps --dry-run        # Plan only\n",
    .epilogue    =
        "See also:\n"
        "  %s show <profile>:<file>    # Inspect content in the terminal\n"
        "  %s profile fetch <name>     # Make a remote profile local\n",
    .opts_size   = sizeof(cmd_export_options_t),
    .opts        = export_opts,
    .post_parse  = export_post_parse,
    .complete    = export_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
        .mounts  = true,
        .crypto  = DOTTA_CRYPTO_OBTAIN,
    },
    .dispatch    = export_dispatch,
};
