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
typedef struct dotta_error dotta_error_t;

/**
 * Error codes
 */
typedef enum {
    DOTTA_OK = 0,              /* Success */
    DOTTA_ERR_INVALID_ARG,     /* Invalid argument */
    DOTTA_ERR_NOT_FOUND,       /* Resource not found */
    DOTTA_ERR_EXISTS,          /* Resource already exists */
    DOTTA_ERR_PERMISSION,      /* Permission denied */
    DOTTA_ERR_GIT,             /* Git operation failed */
    DOTTA_ERR_FS,              /* Filesystem operation failed */
    DOTTA_ERR_STATE_INVALID,   /* Invalid state file */
    DOTTA_ERR_CONFLICT,        /* Conflict detected */
    DOTTA_ERR_MEMORY,          /* Memory allocation failed */
    DOTTA_ERR_INTERNAL         /* Internal error */
} dotta_error_code_t;

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

#endif /* DOTTA_TYPES_H */
