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
 * Buffer - dynamic byte buffer
 */
typedef struct {
    unsigned char *data;
    size_t size;
    size_t capacity;
} buffer_t;

/**
 * Path prefix types (for storage path conversion)
 */
typedef enum {
    PREFIX_HOME,    /* Path under $HOME (stored as home/.bashrc) */
    PREFIX_ROOT,    /* Absolute path (stored as root/etc/hosts) */
    PREFIX_CUSTOM   /* Custom prefix (stored as custom/etc/nginx.conf) */
} path_prefix_t;

/**
 * Profile resolution source - tracks where profiles came from
 *
 * Used for informational/diagnostic purposes only.
 *
 * Priority order (highest to lowest):
 *   EXPLICIT - CLI flags (-p/--profile), temporary override
 *   STATE    - State file profiles array, persistent management
 */
typedef enum {
    PROFILE_SOURCE_EXPLICIT,   /* CLI -p flag (temporary override) */
    PROFILE_SOURCE_STATE       /* State file (persistent management) */
} profile_source_t;

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
    WORKSPACE_STATE_UNTRACKED      /* On filesystem in tracked directory, not in manifest */
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
    DIVERGENCE_CONTENT    = 1 << 0,  /* Content differs from profile */
    DIVERGENCE_MODE       = 1 << 1,  /* Permissions/mode changed */
    DIVERGENCE_OWNERSHIP  = 1 << 2,  /* Owner/group changed (requires root) */
    DIVERGENCE_ENCRYPTION = 1 << 3,  /* File violates encryption policy */
    DIVERGENCE_TYPE       = 1 << 4,  /* Type changed (file/symlink/dir) */
    DIVERGENCE_UNVERIFIED = 1 << 5   /* Cannot verify (missing key, error, large file) */
} divergence_type_t;

/**
 * Workspace item kind
 *
 * Distinguishes between files (which have content and are deployed to the
 * filesystem) and directories (which are metadata-only containers that exist
 * implicitly when files are deployed).
 *
 * This enum makes the type discrimination explicit and type-safe, replacing
 * the previous implicit pattern of using in_state==false to detect directories.
 */
typedef enum {
    WORKSPACE_ITEM_FILE,       /* Regular file, symlink, or executable */
    WORKSPACE_ITEM_DIRECTORY   /* Directory (never in deployment state) */
} workspace_item_kind_t;

#endif /* DOTTA_TYPES_H */
