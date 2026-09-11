/**
 * config.h - Configuration type definition
 *
 * Defines the config struct layout. Include this header when you need to access
 * config fields directly. For config lifecycle functions (load, free, validate),
 * include "utils/config.h" instead.
 */

#ifndef DOTTA_CONFIG_DEF_H
#define DOTTA_CONFIG_DEF_H

#include <types.h>

/**
 * Default hooks directory
 */
#define DOTTA_DEFAULT_HOOKS_DIR "~/.config/dotta/hooks"

/* Forward declaration — kept opaque so consumers of struct config do not
 * transitively pull in the gitignore engine. The full type lives in
 * base/gitignore.h; utils/config.c compiles the two rulesets at load, and
 * core/ignore.c, core/policy.c and cmds/key.c read them. */
typedef struct gitignore_ruleset gitignore_ruleset_t;

/**
 * Configuration structure
 */
struct config {
    /* [core] */
    char *repo_dir;              /* Repository directory path */
    bool strict_mode;            /* Refuse where the repo's state would otherwise be proceeded past */
    bool strict_ownership;       /* An ownership claim this system cannot resolve aborts */
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
    bool pre_sync;                /* Enable pre-sync hook */
    bool post_sync;               /* Enable post-sync hook */

    /* [security] */
    bool confirm_destructive;     /* Require confirmation before destructive operations */
    bool confirm_new_files;       /* Require confirmation before adding new files */

    /* [ignore] */
    const gitignore_ruleset_t *ignore_ruleset; /* patterns, compiled at load; NULL when absent */
    bool respect_gitignore;                    /* Check .gitignore in source directories */

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
    bool encryption_enabled;                         /* Enable encryption feature (default: false) */
    const gitignore_ruleset_t *auto_encrypt_ruleset; /* compiled at load, enabled or not */

    /* Key cache timeout in seconds */
    int32_t session_timeout;                         /* default: 3600, 0 = always prompt, -1 = never expire */

    /* The configuration's own, for the process (include/runtime.h) */
    arena_t *arena;                                  /* backs both compiled rulesets */
};

#endif /* DOTTA_CONFIG_DEF_H */
