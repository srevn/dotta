/**
 * config.h - Configuration type definition
 *
 * Defines the config struct layout. Include this header when you need to access
 * config fields directly. For the load, include "utils/config.h" instead. The
 * configuration is a value of the process's arena (main's): nothing frees one,
 * and no field says where it lives.
 */

#ifndef DOTTA_CONFIG_DEF_H
#define DOTTA_CONFIG_DEF_H

#include <types.h>

#include "base/output.h"

/* Forward declaration — kept opaque so consumers of struct config do not
 * transitively pull in the gitignore engine. The full type lives in
 * base/gitignore.h; utils/config.c compiles the two rulesets at load, and
 * core/ignore.c, core/policy.c and cmds/key.c read them. */
typedef struct gitignore_ruleset gitignore_ruleset_t;

/**
 * Configuration structure
 */
struct config {
    const char *file;            /* The file it is read from, there or not: DOTTA_CONFIG_FILE, else the default — absolute, folded */

    /* [core] */
    const char *repo_dir;        /* The store's directory: DOTTA_REPO_DIR, else this key, else the default — absolute, folded */
    bool strict_ownership;       /* An ownership claim this system cannot resolve aborts */
    bool auto_detect_new_files;  /* Auto-detect new files in tracked directories */

    /* [hooks] */
    const char *hooks_dir;        /* Directory containing hook scripts — absolute, folded */
    int32_t hook_timeout;         /* Hook execution timeout in seconds (default: 30, 0 = no timeout) */

    /* [security] */
    bool confirm_destructive;     /* Require confirmation before destructive operations */
    bool confirm_new_files;       /* Require confirmation before adding new files */

    /* [ignore] */
    const gitignore_ruleset_t *ignore_ruleset; /* patterns, compiled at load; NULL when absent */
    bool respect_gitignore;                    /* The source layer: Git's ignore rules, read or not */

    /* [output] */
    output_verbosity_t verbosity; /* quiet, normal or verbose (base/output) */
    output_color_mode_t color;    /* auto, always or never (base/output) */

    /* [commit] */
    const char *commit_title;     /* Title template for commits */
    const char *commit_body;      /* Body template for commits */

    /* [encryption] */
    bool encryption_enabled;                         /* Enable encryption feature (default: false) */
    const gitignore_ruleset_t *auto_encrypt_ruleset; /* compiled at load, enabled or not */

    /* Key cache timeout in seconds */
    int32_t session_timeout;                         /* default: 3600, 0 = always prompt, -1 = never expire */
};

#endif /* DOTTA_CONFIG_DEF_H */
