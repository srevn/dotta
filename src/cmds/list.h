/**
 * list.h - List profiles, files, and history
 *
 * Hierarchical listing interface:
 * - Level 1: Profiles (default)
 * - Level 2: Files (with -p flag)
 * - Level 3: File history (with -p flag + file path)
 *
 * The --verbose flag adds detail at each level.
 */

#ifndef DOTTA_CMD_LIST_H
#define DOTTA_CMD_LIST_H

#include <git2.h>

#include "types.h"

/**
 * List mode (determined by arguments)
 */
typedef enum {
    LIST_PROFILES,       /* List all profiles */
    LIST_FILES,          /* List files in profile */
    LIST_FILE_HISTORY    /* Show history of specific file */
} list_mode_t;

/**
 * Command options
 */
typedef struct {
    list_mode_t mode;           /* What to list (auto-determined) */
    const char *profile;        /* Profile name (for LIST_FILES or LIST_FILE_HISTORY) */
    const char *file_path;      /* File path (for LIST_FILE_HISTORY) */
    bool verbose;               /* Print detailed output */
    bool remote;                /* Show remote tracking state */
} cmd_list_options_t;

/**
 * List profiles or files
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_list(git_repository *repo, const cmd_list_options_t *opts);

#endif /* DOTTA_CMD_LIST_H */
