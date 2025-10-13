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
 * Profile resolution mode - determines which profiles to operate on
 *
 * This is an application-wide setting that affects ALL commands:
 * apply, update, sync, status, list, diff, clean, show, revert, ignore.
 *
 * Modes:
 *   LOCAL - All local branches (default, variant-friendly workflow)
 *           Best for: Teams with multiple configuration variants
 *           Behavior: Operates on all existing local profile branches
 *
 *   AUTO  - Auto-detect: global + OS + hosts/<hostname> (minimal workflow)
 *           Best for: Single-purpose machines (servers, CI/CD, minimal setups)
 *           Behavior: Only operates on auto-detected system-specific profiles
 *
 *   ALL   - All available profiles (backup/hub workflow)
 *           Best for: Hub machines, backup servers, disaster recovery
 *           Behavior: Mirrors entire repository (all local, sync fetches all remote)
 */
typedef enum {
    PROFILE_MODE_LOCAL,   /* All local branches (default) */
    PROFILE_MODE_AUTO,    /* Auto-detect: global + OS + host */
    PROFILE_MODE_ALL      /* All available profiles */
} profile_mode_t;

/**
 * Workspace divergence category
 *
 * Represents the relationship between profile state (Git), deployment state
 * (.git/dotta-state.json), and filesystem state (actual files).
 */
typedef enum {
    DIVERGENCE_CLEAN,       /* All states aligned */
    DIVERGENCE_UNDEPLOYED,  /* In profile, not in deployment state */
    DIVERGENCE_MODIFIED,    /* Deployed, content changed on filesystem */
    DIVERGENCE_DELETED,     /* Deployed, removed from filesystem */
    DIVERGENCE_ORPHANED,    /* In deployment state, not in profile */
    DIVERGENCE_MODE_DIFF,   /* Deployed, mode changed on filesystem */
    DIVERGENCE_TYPE_DIFF    /* Deployed, type changed on filesystem */
} divergence_type_t;

#endif /* DOTTA_TYPES_H */
