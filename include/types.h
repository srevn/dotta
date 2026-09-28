/**
 * types.h - The vocabulary every layer may assume
 *
 * A prelude, not a module: four opaque handles, base's error codes and transparent
 * containers, a managed path's kind and type, and what a look finds standing at
 * a path — not its two keys, which are strings and declare nothing (infra/path.h).
 * include/config.h is the second prelude — the config layout, read by core without
 * including utils/. base/args.h and base/hashmap.h re-declare the handles they
 * need instead of including this, staying standalone engines with no domain
 * dependency; every other base header includes it.
 *
 * Admission is by meaning, not by owner. A value a reader can interpret holding
 * nothing else stands here; a verdict one module computes stands with that module:
 * workspace_state_t and divergence_type_t in core/workspace.h, beside
 * workspace_displaced_t and workspace_fault_t. Reach bounds what meaning admits:
 * every type here is named by three headers or more, and the best candidate below
 * — hashmap_t, output_color_t — by two besides its own.
 *
 * path_kind_t, path_type_t and fs_occupant_t cross layers besides: infra/pathspec
 * matches on the kind core/manifest produces; the type is read by manifest.h
 * and policy.h, neither of which can hold it for the other, and mapped onto the
 * node it stands as by workspace.h; and the occupant sys/filesystem's look produces
 * is the node core/state keeps a record of, which core/workspace and core/deploy
 * hold against the next look.
 *
 * <stdint.h> and <stdbool.h> have no user here: base/gitignore.h reaches uint8_t
 * and a dozen headers reach bool through this file. Not unused.
 */

#ifndef DOTTA_TYPES_H
#define DOTTA_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Forward declarations
 *
 * error_t is the one handle that is a pointer: an immutable error, NULL for
 * success, borrowed by every reader (base/error.h "Lifetime"). It is must-check
 * by its type: an error a call answers and nobody reads does not compile under
 * the build's -Werror, called directly, through a function pointer or from any
 * producer. A deliberate discard is spelled `(void) f()`.
 */
typedef const struct error *error_t __attribute__((warn_unused_result));
typedef struct arena arena_t;
typedef struct config config_t;
typedef struct output output_t;

/**
 * Error codes
 */
typedef enum {
    OK = 0,                    /* Success */
    ERR_INVALID_ARG,           /* Invalid argument */
    ERR_NOT_FOUND,             /* Resource not found */
    ERR_EXISTS,                /* Resource already exists */
    ERR_PERMISSION,            /* Permission denied */
    ERR_GIT,                   /* Git operation failed */
    ERR_FS,                    /* Filesystem operation failed */
    ERR_STATE_INVALID,         /* Invalid state file */
    ERR_CONFLICT,              /* Conflict detected */
    ERR_VALIDATION,            /* Validation failed */
    ERR_MEMORY,                /* A mapping or a linked library could not get memory */
    ERR_CRYPTO,                /* Cryptographic operation failed */
    ERR_LOCKED,                /* No usable passphrase this run */
    ERR_INTERNAL               /* Internal error */
} error_code_t;

/**
 * String array - names, each a copy in the arena the array was made in
 *
 * entries[count] is NULL whenever entries is not, so the entries are an argv or
 * an envp as they stand once anything was pushed or reserved.
 */
typedef struct {
    char **entries;
    size_t count;
    size_t capacity;
    arena_t *arena;       /* where the spine and every copy live; NULL until string_array_init */
} string_array_t;

/**
 * Pointer array - borrowed pointers, the spine in the arena it was made in
 */
typedef struct {
    void **entries;
    size_t count;
    size_t capacity;
    arena_t *arena;       /* where the spine grows; NULL until ptr_array_init */
} ptr_array_t;

/**
 * Buffer - dynamic byte buffer
 */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} buffer_t;

/**
 * Path kind — what a managed storage path refers to
 *
 * The manifest's kind, not the on-disk kind: a tracked directory currently squatted
 * by a regular file is still PATH_KIND_DIRECTORY. Symlinks are files (matching
 * gitignore's treatment — a symlink is never descended). Layer-neutral: carried
 * by workspace items and consumed by the infra matchers, whose directory-only
 * patterns (`dir/`) need it.
 *
 * Two divisions are called a kind, and this is the coarse one. The ladder's keeps
 * a link apart from a file: the node a type stands as (fs_occupant_t below,
 * core/workspace.h workspace_type_occupant), which is the kind a record keeps
 * (core/state.h state_record_t).
 */
typedef enum {
    PATH_KIND_FILE,       /* Regular file, symlink, or executable — content + metadata */
    PATH_KIND_DIRECTORY   /* Directory — metadata only (mode/ownership) */
} path_kind_t;

/**
 * Path type — what stands at a managed path
 *
 * The type axis of a manifest row (core/manifest.h). The first three are the
 * Git filemodes a blob can carry; the fourth is a metadata-only container dotta
 * creates and converges, claimed through a profile's metadata.json rather than
 * its tree. Kind is coarse and derived from it (path_type_kind); it is never
 * stored beside the type. The record dotta keeps of a path holds no type: it
 * keeps the node it describes (fs_occupant_t below), and the executable half,
 * Git's filemode, is the row's alone.
 */
typedef enum {
    PATH_TYPE_FILE,        /* Regular blob, 0644 default */
    PATH_TYPE_SYMLINK,     /* Link blob; carries no settable mode */
    PATH_TYPE_EXECUTABLE,  /* Regular blob, 0755 default */
    PATH_TYPE_DIRECTORY    /* Metadata-only: a container dotta creates and converges */
} path_type_t;

/**
 * Derive a path's kind from its type
 *
 * A directory is the one metadata-only type; every blob type is a file.
 */
static inline path_kind_t path_type_kind(path_type_t type) {
    return type == PATH_TYPE_DIRECTORY ? PATH_KIND_DIRECTORY : PATH_KIND_FILE;
}

/**
 * The suffix a path's kind adds when the path is written out
 *
 * A directory reads as one: `~/.config/nvim/`. The trailing slash is the marker
 * dotta already spells on the pattern side — gitignore's directory-only rules
 * (base/gitignore.h), the globs infra/pathspec compiles from them — now given
 * to the paths those rules match, so a screen whose tags name the divergence
 * rather than the kind still says which lines are directories. A file adds nothing.
 *
 * The kind is the claim's, never the occupant's: a tracked directory currently
 * squatted by a regular file keeps its slash, and the tag beside it is what names
 * the squatter.
 */
static inline const char *path_kind_suffix(path_kind_t kind) {
    return kind == PATH_KIND_DIRECTORY ? "/" : "";
}

/**
 * Occupant — what stands at a path, as one look finds it
 *
 * The link itself, never its target: a symlink is a distinct occupant, not the
 * thing it points to. Every reader that removes or replaces a path acts on the
 * node at the path, so the target's type and permissions are none of its business.
 *
 * NONE is absence. UNKNOWN is a look that failed for any other reason — something
 * may well be there, and a reader must never infer absence from a failure to
 * look — or no look at all. So UNKNOWN is the zero too: an occupant no look wrote
 * reads as a look nobody took, never as absence.
 *
 * One producer, the look (sys/filesystem.h fs_lstat_occupant). The record keeps
 * one as the node it describes — a regular file, a link or a directory, never
 * the rest (core/state.h state_record_t) — so a look is asked whether that node
 * still stands by one compare.
 */
typedef enum {
    FS_OCCUPANT_UNKNOWN = 0, /* unstattable for a reason other than absence, or not looked at */
    FS_OCCUPANT_NONE,        /* absent, or beneath a non-directory */
    FS_OCCUPANT_REGULAR,
    FS_OCCUPANT_SYMLINK,     /* the link itself, never its target */
    FS_OCCUPANT_DIRECTORY,
    FS_OCCUPANT_OTHER        /* fifo, socket, device */
} fs_occupant_t;

#endif /* DOTTA_TYPES_H */
