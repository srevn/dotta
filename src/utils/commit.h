/**
 * commit.h - Commit message template builder
 *
 * Builds structured commit messages for dotfile operations with metadata.
 */

#ifndef DOTTA_COMMIT_H
#define DOTTA_COMMIT_H

#include <stddef.h>

#include "dotta/types.h"
#include "utils/config.h"

/**
 * Action types for commit messages
 */
typedef enum {
    COMMIT_ACTION_ADD,      /* Adding new files to profile */
    COMMIT_ACTION_UPDATE,   /* Updating existing files */
    COMMIT_ACTION_REMOVE,   /* Removing files from profile */
    COMMIT_ACTION_SYNC,     /* Syncing from filesystem */
    COMMIT_ACTION_REVERT    /* Reverting files to previous state */
} commit_action_t;

/**
 * Context for building commit messages
 */
typedef struct {
    commit_action_t action;   /* Action being performed */
    const char *profile;      /* Profile name (required) */
    const char **files;       /* Array of file storage paths */
    size_t file_count;        /* Number of files */
    const char *custom_msg;   /* Custom message from -m flag (NULL = use template) */
    const char *target_commit; /* Target commit SHA (for revert operations, NULL otherwise) */
} commit_message_context_t;

/**
 * Build a commit message from context
 *
 * If custom_msg is provided, uses it directly.
 * Otherwise, builds message from config templates with variable substitution.
 *
 * Available template variables:
 *   {host}          - System hostname
 *   {user}          - Current username
 *   {profile}       - Profile name
 *   {action}        - Action (Add, Update, Remove, Sync, Revert)
 *   {action_past}   - Past tense (Added, Updated, Removed, Synced, Reverted)
 *   {count}         - Number of files
 *   {datetime}      - Local timestamp with timezone (ISO 8601)
 *   {files}         - Formatted file list (bullet points)
 *   {target_commit} - Target commit SHA (for revert operations, empty otherwise)
 *
 * @param config Configuration with templates (if NULL, uses defaults)
 * @param ctx Context with action, profile, files (required)
 * @return Allocated commit message string (caller must free), or NULL on error
 */
char *build_commit_message(const dotta_config_t *config, const commit_message_context_t *ctx);

/**
 * Get action name in present tense
 *
 * @param action Action type
 * @return Static string ("Add", "Update", "Sync")
 */
const char *commit_action_name(commit_action_t action);

/**
 * Get action name in past tense
 *
 * @param action Action type
 * @return Static string ("Added", "Updated", "Synced")
 */
const char *commit_action_name_past(commit_action_t action);

#endif /* DOTTA_COMMIT_H */
