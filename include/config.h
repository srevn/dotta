/**
 * config.h - Configuration type definition
 *
 * Defines the config struct layout. Include this header when you need
 * to access config fields directly. For config lifecycle functions
 * (load, free, validate), include "utils/config.h" instead.
 */

#ifndef DOTTA_CONFIG_DEF_H
#define DOTTA_CONFIG_DEF_H

#include <types.h>

/**
 * Configuration structure
 */
struct config {
    /* [core] */
    char *repo_dir;              /* Repository directory path */
    bool strict_mode;            /* Strict profile resolution (error if no profiles found) */
    bool auto_detect_new_files;  /* Auto-detect new files in tracked directories */

    /* [hooks] */
    char *hooks_dir;              /* Directory containing hook scripts */
    int32_t hook_timeout;         /* Hook execution timeout in seconds (default: 30, 0 = no timeout) */
    bool pre_apply;               /* Enable pre-apply hook */
    bool post_apply;              /* Enable post-apply hook */
    bool pre_add;                 /* Enable pre-add hook */
    bool post_add;                /* Enable post-add hook */
    bool pre_remove;              /* Enable pre-remove hook */
    bool post_remove;             /* Enable post-remove hook */
    bool pre_update;              /* Enable pre-update hook */
    bool post_update;             /* Enable post-update hook */

    /* [security] */
    bool confirm_destructive;     /* Require confirmation before destructive operations */
    bool confirm_new_files;       /* Require confirmation before adding new files */

    /* [ignore] */
    char **ignore_patterns;       /* Array of patterns from config */
    size_t ignore_pattern_count;
    char *ignore_file;            /* Path to .dottaignore (default: $REPO/.dottaignore) */
    bool respect_gitignore;       /* Check .gitignore in source directories */

    /* [output] */
    char *verbosity;              /* "quiet", "normal", "verbose" */
    char *color;                  /* "auto", "always", "never" */

    /* [commit] */
    char *commit_title;           /* Title template for commits */
    char *commit_body;            /* Body template for commits */

    /* [sync] */
    bool auto_pull;               /* Auto-pull when remote is ahead (default: true) */
    char *diverged_strategy;      /* Strategy for diverged branches: warn, rebase, merge, ours, theirs */

    /* [encryption] */
    bool encryption_enabled;      /* Enable encryption feature (default: false) */
    char **auto_encrypt_patterns; /* Auto-encrypt patterns (gitignore-style) */
    size_t auto_encrypt_pattern_count;
    uint64_t encryption_opslimit; /* CPU cost for password hashing (default: 10000) */
    size_t encryption_memlimit;   /* Memory cost for balloon hashing in MB (default: 64, 0 = disabled) */
    int32_t session_timeout;      /* Key cache timeout in seconds (default: 3600, 0 = always prompt, -1 = never expire) */
};

#endif /* DOTTA_CONFIG_DEF_H */
