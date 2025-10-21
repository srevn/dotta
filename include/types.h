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
    PREFIX_ROOT     /* Absolute path (stored as root/etc/hosts) */
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
 * Workspace divergence category
 *
 * Represents the relationship between profile state (Git), deployment state
 * (.git/dotta.db), and filesystem state (actual files).
 */
typedef enum {
    DIVERGENCE_CLEAN,       /* All states aligned */
    DIVERGENCE_UNDEPLOYED,  /* In profile, not in deployment state */
    DIVERGENCE_MODIFIED,    /* Deployed, content changed on filesystem */
    DIVERGENCE_DELETED,     /* Deployed, removed from filesystem */
    DIVERGENCE_ORPHANED,    /* In deployment state, not in profile */
    DIVERGENCE_MODE_DIFF,   /* Deployed, mode changed on filesystem */
    DIVERGENCE_TYPE_DIFF,   /* Deployed, type changed on filesystem */
    DIVERGENCE_UNTRACKED    /* On filesystem in tracked directory, not in manifest */
} divergence_type_t;

#endif /* DOTTA_TYPES_H */
