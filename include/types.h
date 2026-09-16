/**
 * types.h - The vocabulary every layer may assume
 *
 * A prelude, not a module: four opaque handles, base's error codes and transparent
 * containers, and the two words for a managed path. include/config.h is the second
 * prelude — the config layout, read by core without including utils/. base/args.h
 * and base/hashmap.h re-declare the handles they need instead of including this,
 * staying standalone engines with no domain dependency; every other base header
 * includes it.
 *
 * Admission is by meaning, not by owner. A value a reader can interpret holding
 * nothing else stands here; a verdict one module computes stands with that module:
 * workspace_state_t and divergence_type_t in core/workspace.h, beside
 * workspace_displaced_t and workspace_fault_t. Reach bounds what meaning admits:
 * every type here is named by three headers or more, and the best candidate below
 * — hashmap_t, fs_occupant_t, output_color_t — by two.
 *
 * path_kind_t and path_type_t cross layers besides: infra/pathspec matches on
 * the kind core/manifest produces, and manifest.h, state.h, deploy.h and policy.h
 * read the type where none can hold it for the other three.
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
 */
typedef struct error error_t;
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
    ERR_MEMORY,                /* Memory allocation failed */
    ERR_CRYPTO,                /* Cryptographic operation failed */
    ERR_LOCKED,                /* No usable passphrase this run */
    ERR_INTERNAL               /* Internal error */
} error_code_t;

/**
 * String array - dynamic array of strings
 */
typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} string_array_t;

/**
 * Pointer array - dynamic array of borrowed pointers
 */
typedef struct {
    void **items;
    size_t count;
    size_t capacity;
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
 */
typedef enum {
    PATH_KIND_FILE,       /* Regular file, symlink, or executable — content + metadata */
    PATH_KIND_DIRECTORY   /* Tracked directory — metadata only (mode/ownership) */
} path_kind_t;

/**
 * Path type — what stands at a managed path
 *
 * The one type axis for a manifest row and for the record dotta keeps of it
 * (core/manifest.h, core/state.h). The first three are the Git filemodes a blob
 * can carry; the fourth is a metadata-only container dotta creates and converges,
 * claimed through a profile's metadata.json rather than its tree. Kind is coarse
 * and derived from it (path_type_kind); it is never stored beside the type.
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

#endif /* DOTTA_TYPES_H */
