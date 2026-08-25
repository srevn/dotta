/**
 * export.c - Materialize profile content to the filesystem
 *
 * Export is a copy, not a deployment. It never registers in state, never applies
 * ownership, and dotta makes no ongoing claim over the destination. One profile
 * branch's subtree is copied verbatim: no layer composition, no mount mapping,
 * plaintext bytes with stored permission modes. Single files are the degenerate
 * case of the tree walk. A directory claim without a tree entry (an empty tracked
 * directory — its whole Git footprint is its metadata item) is content too:
 * materialized with its stored mode, beside what the walk collects.
 *
 * Two-phase execution model:
 *
 *   Phase 1 (read-only): walk the tree collecting entries, resolve every final
 *   destination path, and validate everything — type collisions, pre-existing
 *   symlinks that would re-route content writes, unsupported blob formats — then
 *   decrypt encrypted files into memory. Every refusal, including the passphrase
 *   prompt and any decryption failure, lands before the first byte is written.
 *   --dry-run is phase 1 alone.
 *
 *   Phase 2 (write): create directories, write blobs, recreate symlinks. Fail
 *   fast on first error; the remaining failure window is filesystem errors and
 *   repository corruption only.
 *
 * Traversal safety is structural: git forbids '/', '.', and '..' in tree entry
 * names, so joined paths cannot escape the export root. The remaining escape
 * vector — a pre-existing symlink at a content-dictated path below the root —
 * is refused in phase 1.
 */

#include "cmds/export.h"

#include <errno.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "base/refspec.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/metadata.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"

/**
 * One collected export entry.
 *
 * Paths are arena-owned (command scope). `content` is heap-owned and held only
 * for entries phase 1 must materialize early: decrypted plaintext (so every crypto
 * failure front-loads) and symlink targets (tiny, and the dry-run listing shows
 * them). Plaintext file blobs stay lazy — phase 2 re-reads them so a whole profile
 * is never held in memory, and an ODB read that succeeded in phase 1 can only
 * fail there on repository corruption.
 */
typedef enum {
    EXPORT_ENTRY_DIRECTORY,
    EXPORT_ENTRY_FILE,
    EXPORT_ENTRY_SYMLINK
} export_entry_kind_t;

typedef struct {
    export_entry_kind_t kind;
    const char *storage_path;  /* Full storage path (metadata key, AAD) */
    const char *rel_path;      /* Path relative to the export root (display) */
    const char *dest_path;     /* Final filesystem path */
    git_oid blob_oid;          /* FILE / SYMLINK only */
    mode_t mode;               /* Resolved final mode (FILE / DIRECTORY) */
    bool encrypted;            /* FILE: byte-classified in phase 1 */
    bool claimed;              /* DIRECTORY: a metadata DIRECTORY at this storage path */
    bool dest_existed;         /* DIRECTORY: phase-1 lstat fact */
    bool content_held;         /* `content` carries bytes from phase 1 */
    buffer_t content;
} export_entry_t;

typedef struct {
    export_entry_t *items;     /* Arena-owned spine */
    size_t count;
    size_t capacity;
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
 * Does the first path component decode as a storage label?
 *
 * The mount vocabulary is the authority for the content namespace: everything a
 * profile deploys lives under home/, root/, or custom/. Anything else at branch
 * root (.dotta/, .bootstrap, README, ...) is profile machinery and never part
 * of an export. Bare labels ("home") name the whole subtree. Iterates until
 * mount_spec_for_kind returns NULL so a future fourth label is covered without
 * an edit here.
 */
static bool storage_namespace_contains(const char *path) {
    for (mount_kind_t kind = MOUNT_HOME; ; kind = (mount_kind_t) (kind + 1)) {
        const mount_spec_t *spec = mount_spec_for_kind(kind);
        if (!spec) break;

        size_t len = strlen(spec->label);
        if (strncmp(path, spec->label, len) != 0) continue;
        if (path[len] == '\0' || path[len] == '/') return true;
    }
    return false;
}

/**
 * Resolve an entry's final mode.
 *
 * Stored metadata mode wins; the fallback is the git filemode for files (mirroring
 * deploy's corruption fallback) and the canonical default for directories.
 * Kind-checked so a stale item of the wrong kind cannot leak its mode across
 * entry types.
 */
static mode_t export_entry_mode(
    const metadata_t *metadata,
    const char *storage_path,
    metadata_item_kind_t kind,
    git_filemode_t filemode
) {
    const metadata_item_t *item = NULL;
    error_t *err = metadata_get_item(metadata, storage_path, &item);
    if (err) {
        error_free(err);
        item = NULL;
    }

    if (item && item->kind == kind && item->mode != 0) {
        return item->mode;
    }
    if (kind == METADATA_ITEM_DIRECTORY) {
        return DIR_MODE_DEFAULT;
    }
    return (filemode == GIT_FILEMODE_BLOB_EXECUTABLE) ? 0755 : 0644;
}

/**
 * Apply the destination rules shared by every export shape.
 *
 * Expand '~', then on directory intent — an existing directory, or an explicit
 * trailing '/' — append `name` so `-o .` lands under the original name. Order
 * matters: expand, join, and only then let the caller validate the final path.
 * Returned string is arena-owned.
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
    if (fs_is_directory(expanded) ||
        (len > 0 && expanded[len - 1] == '/')) {
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
    const char *storage_base;  /* "" for whole profile, else target path */
    const char *dest_root;
    bool whole_profile;        /* Branch-root machinery gate active */
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

    /* Whole-profile walks start at branch root, where content lives only under
     * storage-label subtrees; everything else is machinery. Positive return prunes
     * the entry (and its subtree, pre-order). */
    if (ctx->whole_profile && root[0] == '\0' &&
        (git_tree_entry_type(entry) != GIT_OBJECT_TREE ||
        !storage_namespace_contains(name))) {
        return 1;
    }

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
    e.dest_path = arena_join_path(ctx->arena, ctx->dest_root, rel);
    if (!e.rel_path || !e.storage_path || !e.dest_path) {
        ctx->error = ERROR(ERR_MEMORY, "Failed to allocate export entry");
        return -1;
    }

    switch (git_tree_entry_type(entry)) {
        case GIT_OBJECT_TREE: {
            e.kind = EXPORT_ENTRY_DIRECTORY;
            e.mode = export_entry_mode(
                ctx->metadata, e.storage_path, METADATA_ITEM_DIRECTORY,
                GIT_FILEMODE_TREE
            );
            const metadata_item_t *item = NULL;
            error_t *item_err = metadata_get_item(
                ctx->metadata, e.storage_path, &item
            );
            if (item_err) error_free(item_err);
            e.claimed = item && item->kind == METADATA_ITEM_DIRECTORY;
            break;
        }

        case GIT_OBJECT_BLOB: {
            git_filemode_t filemode = git_tree_entry_filemode(entry);
            git_oid_cpy(&e.blob_oid, git_tree_entry_id(entry));
            if (filemode == GIT_FILEMODE_LINK) {
                e.kind = EXPORT_ENTRY_SYMLINK;
            } else {
                e.kind = EXPORT_ENTRY_FILE;
                e.mode = export_entry_mode(
                    ctx->metadata, e.storage_path, METADATA_ITEM_FILE,
                    filemode
                );
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
 * Order export entries by storage path.
 *
 * Applied to the appended claims batch alone: parents sort before children (a
 * prefix compares less), keeping creation order and the deepest-first chmod
 * coherent with the walk's pre-order.
 */
static int export_entry_cmp(const void *a, const void *b) {
    const export_entry_t *ea = a;
    const export_entry_t *eb = b;
    return strcmp(ea->storage_path, eb->storage_path);
}

/**
 * Phase-1 destination validation.
 *
 * lstat every entry's final path and refuse anything that would collide by type
 * or write through a pre-existing symlink. Below the export root every intermediate
 * directory is itself a walk entry, so checking entries covers every
 * content-dictated path component; the root's own ancestors are user-typed and
 * deliberately follow normal filesystem resolution (cp semantics).
 *
 * `single_dest`: a lone user-typed file destination keeps the shipped cp semantics
 * — writing through a symlink at the typed path is the user's stated intent —
 * while content-dictated paths inside a tree export refuse symlinks outright
 * (the escape vector).
 */
static error_t *validate_destinations(
    export_entry_list_t *list,
    bool single_dest
) {
    for (size_t i = 0; i < list->count; i++) {
        export_entry_t *e = &list->items[i];

        struct stat st;
        if (lstat(e->dest_path, &st) != 0) {
            if (errno == ENOENT) continue;  /* Fresh path */
            if (errno == ENOTDIR) {
                return ERROR(
                    ERR_CONFLICT,
                    "A path component of '%s' exists and is not a directory",
                    e->dest_path
                );
            }
            return error_wrap(
                error_from_errno(errno), "Cannot stat '%s'", e->dest_path
            );
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
 * Classify every blob by its bytes — the authoritative source of encryption state
 * (metadata's flag is a cache; bytes win) — refuse version-skewed ciphertext,
 * and decrypt encrypted files NOW, holding the plaintext. The first decryption
 * triggers the passphrase prompt, so the prompt and every crypto failure (wrong
 * key, corruption, path mismatch) land in the pre-write window. Symlink targets
 * are read here too: tiny, needed by phase 2, and shown by --dry-run.
 */
static error_t *validate_content(
    const dotta_ctx_t *ctx,
    const char *profile,
    export_entry_list_t *list
) {
    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;

    for (size_t i = 0; i < list->count; i++) {
        export_entry_t *e = &list->items[i];
        error_t *err = NULL;

        if (e->kind == EXPORT_ENTRY_DIRECTORY) continue;

        if (e->kind == EXPORT_ENTRY_SYMLINK) {
            err = content_get_from_blob_oid(
                repo, &e->blob_oid, e->storage_path, profile, keymgr,
                &e->content
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
            continue;
        }

        content_kind_t ckind;
        err = content_classify(repo, &e->blob_oid, &ckind, NULL);
        if (err) {
            return error_wrap(err, "Failed to read '%s'", e->storage_path);
        }

        if (ckind == CONTENT_UNSUPPORTED_VERSION) {
            return ERROR(
                ERR_CRYPTO,
                "Cannot decrypt '%s': encrypted under an unsupported "
                "format version", e->storage_path
            );
        }

        if (ckind == CONTENT_ENCRYPTED) {
            e->encrypted = true;
            err = content_get_from_blob_oid(
                repo, &e->blob_oid, e->storage_path, profile, keymgr,
                &e->content
            );
            if (err) {
                return error_wrap(
                    err, "Failed to decrypt '%s'", e->storage_path
                );
            }
            e->content_held = true;
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
 */
static error_t *materialize_entries(
    const dotta_ctx_t *ctx,
    const char *profile,
    const char *root_path,     /* NULL for single-file exports */
    bool root_existed,
    mode_t root_mode,
    export_entry_list_t *list,
    bool verbose
) {
    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;
    output_t *out = ctx->out;

    error_t *err = NULL;

    if (root_path && !root_existed) {
        err = fs_create_dir_with_mode(root_path, root_mode | S_IRWXU, true);
        if (err) {
            return error_wrap(err, "Failed to create '%s'", root_path);
        }
    }

    for (size_t i = 0; i < list->count; i++) {
        export_entry_t *e = &list->items[i];

        switch (e->kind) {
            case EXPORT_ENTRY_DIRECTORY:
                if (e->dest_existed) break;
                /* Parents allowed: a claims-batch entry may sit under an unclaimed,
                 * blob-less ancestor no walk entry created — intermediates land
                 * at the default mode, deploy's own ancestor rule. Walk entries'
                 * parents always exist. */
                err = fs_create_dir_with_mode(
                    e->dest_path, e->mode | S_IRWXU, true
                );
                if (err) {
                    return error_wrap(
                        err, "Failed to create directory '%s'", e->dest_path
                    );
                }
                if (verbose) {
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  created {cyan}%s/{reset} (mode %04o)\n",
                        e->rel_path, (unsigned) e->mode
                    );
                }
                break;

            case EXPORT_ENTRY_FILE: {
                buffer_t local = BUFFER_INIT;
                const buffer_t *bytes = &e->content;
                if (!e->content_held) {
                    err = content_get_from_blob_oid(
                        repo, &e->blob_oid, e->storage_path, profile, keymgr,
                        &local
                    );
                    if (err) {
                        return error_wrap(
                            err, "Failed to read '%s'", e->storage_path
                        );
                    }
                    bytes = &local;
                }

                err = fs_write_file_raw(
                    e->dest_path, (const unsigned char *) bytes->data,
                    bytes->size, e->mode, (uid_t) -1, (gid_t) -1
                );
                buffer_free(&local);
                if (err) {
                    return error_wrap(
                        err, "Failed to write '%s'", e->dest_path
                    );
                }
                if (verbose) {
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  wrote {cyan}%s{reset} (mode %04o%s)\n",
                        e->rel_path, (unsigned) e->mode,
                        e->encrypted ? ", decrypted" : ""
                    );
                }
                break;
            }

            case EXPORT_ENTRY_SYMLINK:
                /* Blob content is the target path; recreate the link. symlink(2)
                 * cannot overwrite — clear any stale entry. */
                err = fs_remove_file(e->dest_path);
                if (err) return err;

                err = fs_ensure_parent_dirs(e->dest_path);
                if (err) return err;

                err = fs_create_symlink(
                    (const char *) e->content.data, e->dest_path
                );
                if (err) {
                    return error_wrap(
                        err, "Failed to create symlink '%s'", e->dest_path
                    );
                }
                if (verbose) {
                    output_styled(
                        out, OUTPUT_NORMAL,
                        "  linked {cyan}%s{reset} -> %s\n",
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

    if (root_path && !root_existed && (root_mode | S_IRWXU) != root_mode) {
        err = fs_set_permissions(root_path, root_mode);
        if (err) {
            return error_wrap(err, "Failed to set mode on '%s'", root_path);
        }
    }

    return NULL;
}

/**
 * Print the --dry-run plan: header plus one line per file entry and per directory
 * claim (slash-marked; scaffolding directories are not listed).
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
        if (e->kind == EXPORT_ENTRY_DIRECTORY && !e->claimed) continue;
        int len = (int) strlen(e->rel_path) +
            (e->kind == EXPORT_ENTRY_DIRECTORY ? 1 : 0);
        if (len > width) width = len;
    }
    if (width > 48) width = 48;

    for (size_t i = 0; i < list->count; i++) {
        const export_entry_t *e = &list->items[i];
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
 * Byte-faithful: no headers, no trailing-newline normalization — unlike show's
 * --raw, which is a terminal display mode. Flushes so buffered IO failures surface
 * as a non-zero exit.
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

    git_repository *repo = ctx->run.repo;
    const mount_table_t *mounts = ctx->run.mounts;
    keymgr *keymgr = ctx->run.keymgr;
    output_t *out = ctx->out;
    arena_t *arena = ctx->arena;
    bool to_stdout = strcmp(opts->output, "-") == 0;
    bool verbose = opts->verbose || output_is_verbose(out);

    error_t *err = NULL;
    git_commit *commit = NULL;
    git_tree *tree = NULL;
    git_tree *subtree = NULL;
    git_tree_entry *target = NULL;
    metadata_t *metadata = NULL;
    export_entry_list_t list = { 0 };
    const char *root_path = NULL;    /* Non-NULL for tree exports */
    bool root_existed = false;
    mode_t root_mode = DIR_MODE_DEFAULT;
    bool tree_export = false;
    const char *claims_base = NULL;  /* Claims-append scope (NULL = whole profile) */
    bool claim_only = false;         /* Target is a metadata-only directory claim */
    char commit_suffix[16] = "";

    /* Export is local-only: no network IO, ever. The explicit porcelain for making
     * a profile local already exists. */
    bool exists = false;
    err = gitops_branch_exists(repo, opts->profile, &exists);
    if (err) goto cleanup;
    if (!exists) {
        err = ERROR(
            ERR_NOT_FOUND,
            "Profile '%s' is not available locally\n"
            "Hint: Fetch it first: dotta profile fetch %s",
            opts->profile, opts->profile
        );
        goto cleanup;
    }

    /* Load the tree (HEAD or historical commit). Metadata comes from the SAME
     * tree below, so historical exports get historical modes and encryption
     * flags. */
    if (opts->commit) {
        git_oid commit_oid;
        err = gitops_resolve_commit_in_branch(
            repo, opts->profile, opts->commit, &commit_oid, &commit
        );
        if (err) {
            err = error_wrap(
                err, "Commit '%s' not found in profile '%s'",
                opts->commit, opts->profile
            );
            goto cleanup;
        }

        err = gitops_get_tree_from_commit(repo, &commit_oid, &tree);
        if (err) {
            err = error_wrap(
                err, "Failed to load tree from commit '%s'", opts->commit
            );
            goto cleanup;
        }

        char oid_str[8];
        git_oid_tostr(oid_str, sizeof(oid_str), &commit_oid);
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

    err = metadata_load_from_tree(repo, tree, opts->profile, &metadata);
    if (err) {
        if (err->code != ERR_NOT_FOUND) {
            output_warning(
                out, OUTPUT_NORMAL,
                "Metadata unreadable for profile '%s' (%s); "
                "falling back to git filemodes",
                opts->profile, error_message(err)
            );
        }
        error_free(err);
        err = metadata_create_empty(&metadata);
        if (err) goto cleanup;
    }

    if (opts->file_path) {
        /* Resolve the CLI path to storage form. On resolution failure fall back
         * to the raw input — the tree lookup below is the final authority (mirrors
         * show). */
        const char *converted = NULL;
        error_t *conv_err = path_input_resolve(
            mounts, opts->file_path, arena, &converted
        );
        const char *storage = conv_err ? opts->file_path : converted;
        if (conv_err) error_free(conv_err);

        /* Tolerate a typed trailing slash on directory targets. */
        size_t slen = strlen(storage);
        while (slen > 1 && storage[slen - 1] == '/') slen--;
        if (storage[slen] != '\0') {
            storage = arena_strndup(arena, storage, slen);
            if (!storage) {
                err = ERROR(ERR_MEMORY, "Failed to allocate storage path");
                goto cleanup;
            }
        }

        if (!storage_namespace_contains(storage)) {
            err = ERROR(
                ERR_INVALID_ARG,
                "'%s' is not exportable content\n"
                "Profile content lives under home/, root/, or custom/; "
                "anything else is dotta machinery.\n"
                "Hint: Use 'dotta git' for raw repository access",
                storage
            );
            goto cleanup;
        }

        err = gitops_find_file_in_tree(tree, storage, &target);
        if (err) {
            if (err->code != ERR_NOT_FOUND) goto cleanup;

            /* Not in the tree. An empty tracked directory has no tree entry —
             * its claim lives only in the metadata, and the export is then the
             * claim itself: the directory, at its stored mode. */
            const metadata_item_t *claim_item = NULL;
            error_t *item_err = metadata_get_item(metadata, storage, &claim_item);
            if (item_err) {
                error_free(item_err);
                claim_item = NULL;
            }
            if (!claim_item || claim_item->kind != METADATA_ITEM_DIRECTORY) {
                error_free(err);
                err = ERROR(
                    ERR_NOT_FOUND, "'%s' not found in profile '%s'%s",
                    storage, opts->profile, commit_suffix
                );
                goto cleanup;
            }
            error_free(err);
            err = NULL;
        }

        bool claim_target = target == NULL;
        if (claim_target || git_tree_entry_type(target) == GIT_OBJECT_TREE) {
            /* Directory export: walk the subtree — or, for a metadata-only claim,
             * no subtree to walk: any children are claims themselves, collected
             * by the append below. */
            if (to_stdout) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "'-' streams a single file's bytes; '%s' is a "
                    "directory and needs a path destination", storage
                );
                goto cleanup;
            }

            err = dest_resolve(
                opts->output, path_basename(storage), arena, &root_path
            );
            if (err) goto cleanup;

            root_mode = export_entry_mode(
                metadata, storage, METADATA_ITEM_DIRECTORY,
                GIT_FILEMODE_TREE
            );
            tree_export = true;
            claims_base = storage;
            claim_only = claim_target;

            if (!claim_target) {
                int git_ret = git_tree_lookup(
                    &subtree, repo, git_tree_entry_id(target)
                );
                if (git_ret < 0) {
                    err = error_from_git(git_ret);
                    goto cleanup;
                }

                struct collect_ctx cctx = {
                    .metadata      = metadata,
                    .storage_base  = storage,
                    .dest_root     = root_path,
                    .whole_profile = false,
                    .list          = &list,
                    .arena         = arena,
                    .error         = NULL
                };
                err = gitops_tree_walk(subtree, collect_tree_callback, &cctx);
                if (cctx.error) {
                    /* The callback error is the cause; the walk's generic
                     * user-abort wrapper is noise. */
                    error_free(err);
                    err = cctx.error;
                }
                if (err) goto cleanup;
            }
        } else if (git_tree_entry_type(target) == GIT_OBJECT_BLOB) {
            /* Single-entry export: degenerate case of the walk. */
            git_filemode_t filemode = git_tree_entry_filemode(target);

            export_entry_t e;
            memset(&e, 0, sizeof(e));
            e.storage_path = storage;
            e.rel_path = path_basename(storage);
            git_oid_cpy(&e.blob_oid, git_tree_entry_id(target));
            if (filemode == GIT_FILEMODE_LINK) {
                e.kind = EXPORT_ENTRY_SYMLINK;
            } else {
                e.kind = EXPORT_ENTRY_FILE;
                e.mode = export_entry_mode(
                    metadata, storage, METADATA_ITEM_FILE, filemode
                );
            }

            if (!to_stdout) {
                err = dest_resolve(
                    opts->output, path_basename(storage), arena,
                    &e.dest_path
                );
                if (err) goto cleanup;
            }

            err = entry_list_append(&list, arena, &e);
            if (err) goto cleanup;
        } else {
            err = ERROR(
                ERR_INVALID_ARG, "Unsupported entry type for '%s'", storage
            );
            goto cleanup;
        }
    } else {
        /* Whole profile: walk from branch root, storage layout mirrored verbatim
         * (dest/home/..., dest/root/...). The export root takes the profile's
         * last segment under a directory
         * destination (hosts/mbp -> mbp). */
        err = dest_resolve(
            opts->output, path_basename(opts->profile), arena, &root_path
        );
        if (err) goto cleanup;

        tree_export = true;

        struct collect_ctx cctx = {
            .metadata      = metadata,
            .storage_base  = "",
            .dest_root     = root_path,
            .whole_profile = true,
            .list          = &list,
            .arena         = arena,
            .error         = NULL
        };
        err = gitops_tree_walk(tree, collect_tree_callback, &cctx);
        if (cctx.error) {
            error_free(err);
            err = cctx.error;
        }
        if (err) goto cleanup;
    }

    /* The branch's directory claims with no tree entry — an empty tracked directory
     * holds no blobs, so the walk cannot see it; the metadata item is its whole
     * footprint. Appended after the walk (nothing tree-backed can live beneath
     * a blob-less claim, so parents still precede children) and sorted so creation
     * order and the deepest-first chmod stay coherent. */
    if (tree_export) {
        size_t appended_from = list.count;
        size_t base_len = claims_base ? strlen(claims_base) : 0;
        size_t item_count = 0;
        const metadata_item_t *items = metadata_get_all_items(metadata, &item_count);
        for (size_t i = 0; i < item_count; i++) {
            if (items[i].kind != METADATA_ITEM_DIRECTORY) continue;
            const char *key = items[i].key;

            const char *rel = key;
            if (base_len > 0) {
                /* Inside the exported subtree only; the base itself is the export
                 * root, not a list entry. */
                if (strncmp(key, claims_base, base_len) != 0 ||
                    key[base_len] != '/') {
                    continue;
                }
                rel = key + base_len + 1;
            }

            git_tree_entry *probe = NULL;
            if (git_tree_entry_bypath(&probe, tree, key) == 0) {
                git_tree_entry_free(probe);
                continue;   /* Tree-backed: the walk collected it */
            }

            export_entry_t e;
            memset(&e, 0, sizeof(e));
            e.kind = EXPORT_ENTRY_DIRECTORY;
            e.claimed = true;
            e.storage_path = arena_strdup(arena, key);
            if (!e.storage_path) {
                err = ERROR(ERR_MEMORY, "Failed to allocate export entry");
                goto cleanup;
            }
            e.rel_path = e.storage_path + (rel - key);
            e.dest_path = arena_join_path(arena, root_path, e.rel_path);
            if (!e.dest_path) {
                err = ERROR(ERR_MEMORY, "Failed to allocate export entry");
                goto cleanup;
            }
            e.mode = items[i].mode != 0 ? items[i].mode : DIR_MODE_DEFAULT;

            err = entry_list_append(&list, arena, &e);
            if (err) goto cleanup;
        }
        if (list.count > appended_from + 1) {
            qsort(
                list.items + appended_from, list.count - appended_from,
                sizeof(*list.items), export_entry_cmp
            );
        }
    }

    if (list.count == 0 && !claim_only) {
        err = ERROR(
            ERR_NOT_FOUND, "Profile '%s'%s has no exportable content",
            opts->profile, commit_suffix
        );
        goto cleanup;
    }

    /* ── Phase 1 validation: every refusal before the first byte ── */

    if (tree_export) {
        struct stat st;
        if (lstat(root_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                root_existed = true;
            } else if (S_ISLNK(st.st_mode)) {
                err = ERROR(
                    ERR_CONFLICT,
                    "Destination '%s' is a symlink — refusing to write "
                    "through it", root_path
                );
                goto cleanup;
            } else {
                err = ERROR(
                    ERR_CONFLICT,
                    "Destination '%s' exists and is not a directory",
                    root_path
                );
                goto cleanup;
            }
        } else if (errno == ENOTDIR) {
            err = ERROR(
                ERR_CONFLICT,
                "A path component of '%s' exists and is not a directory",
                root_path
            );
            goto cleanup;
        } else if (errno != ENOENT) {
            err = error_wrap(
                error_from_errno(errno), "Cannot stat '%s'", root_path
            );
            goto cleanup;
        }
    }

    if (!to_stdout) {
        err = validate_destinations(&list, !tree_export);
        if (err) goto cleanup;
    }

    err = validate_content(ctx, opts->profile, &list);
    if (err) goto cleanup;

    /* ── Reporting / phase 2 ── */

    /* The counts phrase: files (symlinks included) and the directory claims this
     * export materializes — the walk's claimed entries, the appended batch, and
     * (for a subtree export) the root when it is itself a claim. Scaffolding
     * directories are plumbing, not content: uncounted. */
    size_t file_count = 0;
    size_t dir_claims = 0;
    for (size_t i = 0; i < list.count; i++) {
        if (list.items[i].kind == EXPORT_ENTRY_DIRECTORY) {
            if (list.items[i].claimed) dir_claims++;
        } else {
            file_count++;
        }
    }
    if (claims_base) {
        const metadata_item_t *root_item = NULL;
        error_t *root_err = metadata_get_item(metadata, claims_base, &root_item);
        if (root_err) {
            error_free(root_err);
            root_item = NULL;
        }
        if (root_item && root_item->kind == METADATA_ITEM_DIRECTORY) {
            dir_claims++;
        }
    }
    char counts[64];
    output_format_counts(file_count, dir_claims, counts, sizeof(counts));

    const char *dest_display = to_stdout ? "stdout"
        : (root_path ? root_path : list.items[0].dest_path);

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
            buffer_t local = BUFFER_INIT;
            err = content_get_from_blob_oid(
                repo, &e->blob_oid, e->storage_path, opts->profile,
                keymgr, &local
            );
            if (!err) err = write_bytes_stdout(&local);
            buffer_free(&local);
        }
        goto cleanup;
    }

    err = materialize_entries(
        ctx, opts->profile, root_path, root_existed, root_mode, &list,
        verbose
    );
    if (err) goto cleanup;

    output_styled(
        out, OUTPUT_NORMAL,
        "Exported %s to {cyan}%s{reset} "
        "(from {magenta}%s{reset}%s)\n",
        counts, dest_display, opts->profile,
        commit_suffix
    );

cleanup:
    for (size_t i = 0; i < list.count; i++) {
        if (list.items[i].content_held) {
            buffer_free(&list.items[i].content);
        }
    }
    if (target) git_tree_entry_free(target);
    if (subtree) git_tree_free(subtree);
    if (metadata) metadata_free(metadata);
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
     * a usage hint instead of a branch-lookup error. */
    const char *first = args[0];
    if (first[0] == '~' || first[0] == '/' ||
        (o->positional_count == 1 && storage_namespace_contains(first))) {
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
        if (str_looks_like_git_ref(args[1]) && !strchr(args[1], '/') &&
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
        "  itself never touches the network). Without a path the whole\n"
        "  profile is exported, storage layout mirrored (home/, root/).\n"
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
        .repo    = true,
        .state   = DOTTA_STATE_READ,
        .mounts  = true,
        .crypto  = true,
    },
    .dispatch    = export_dispatch,
};
