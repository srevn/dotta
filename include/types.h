/**
 * types.h - Common type definitions for dotta
 *
 * This file defines common types used throughout the dotta codebase.
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
 * Workspace state - where an item exists
 *
 * Represents the location/deployment status of a file or directory across
 * the three states: profile (Git), deployment (state.db), and filesystem.
 *
 * This enum captures WHERE an item exists, separate from WHAT is wrong with it
 * (see divergence_flags_t). States are mutually exclusive.
 */
typedef enum {
    WORKSPACE_STATE_DEPLOYED,      /* In profile + deployed + on filesystem */
    WORKSPACE_STATE_UNDEPLOYED,    /* In profile, not deployed yet */
    WORKSPACE_STATE_DELETED,       /* Was deployed, removed from filesystem */
    WORKSPACE_STATE_ORPHANED,      /* In deployment state, not in profile */
    WORKSPACE_STATE_UNTRACKED,     /* On filesystem in tracked directory, not in manifest */
    WORKSPACE_STATE_RELEASED       /* File removed from Git externally, released from management */
} workspace_state_t;

/**
 * Divergence type - what is wrong with an item
 *
 * Bit flags representing types of divergence between expected and actual state.
 * Multiple flags can be set simultaneously (e.g., content changed AND mode changed).
 *
 * This enum captures WHAT is wrong, separate from WHERE the item exists
 * (see workspace_state_t). Flags can be combined with bitwise OR.
 */
typedef enum {
    DIVERGENCE_NONE       = 0,       /* No divergence detected */
    DIVERGENCE_CONTENT    = 1 << 0,  /* Disk content is not the blob it was measured */
    DIVERGENCE_MODE       = 1 << 1,  /* Permissions/mode changed */
    DIVERGENCE_OWNERSHIP  = 1 << 2,  /* Owner/group changed (requires root) */
    DIVERGENCE_ENCRYPTION = 1 << 3,  /* File violates encryption policy */
    DIVERGENCE_TYPE       = 1 << 4,  /* Type changed (file/symlink/dir) */
    DIVERGENCE_UNVERIFIED = 1 << 5,  /* Cannot verify (missing key, error, large file) */
    DIVERGENCE_STALE      = 1 << 6   /* Git advanced past the blob dotta last deployed */
} divergence_type_t;

/**
 * Path kind — what a managed storage path refers to
 *
 * The manifest's kind, not the on-disk kind: a tracked directory currently
 * squatted by a regular file is still PATH_KIND_DIRECTORY. Symlinks are
 * files (matching gitignore's treatment — a symlink is never descended).
 * Layer-neutral: carried by workspace items and consumed by the infra
 * matchers, whose directory-only patterns (`dir/`) need it.
 */
typedef enum {
    PATH_KIND_FILE,       /* Regular file, symlink, or executable — content + metadata */
    PATH_KIND_DIRECTORY   /* Tracked directory — metadata only (mode/ownership) */
} path_kind_t;

/**
 * Path type — what stands at a managed path
 *
 * The one type axis for a manifest row and for the record dotta keeps of
 * it (core/manifest.h, core/state.h). The first three are the Git filemodes a
 * blob can carry; the fourth is a metadata-only container dotta creates
 * and converges, claimed through a profile's metadata.json rather than its
 * tree. Kind is coarse and derived from it (path_type_kind); it is never
 * stored beside the type.
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

#endif /* DOTTA_TYPES_H */
