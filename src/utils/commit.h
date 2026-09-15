/**
 * commit.h - Commit message template builder
 *
 * Builds structured commit messages for dotfile operations with metadata.
 */

#ifndef DOTTA_COMMIT_H
#define DOTTA_COMMIT_H

#include <stddef.h>
#include <types.h>

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
 * What a message names
 *
 * The unit is the path, not the file. One commit carries two documents — the
 * tree, which holds a blob at every path that has bytes, and the sheet, which
 * holds the directories a tree cannot (core/metadata.h) — so a caller that named
 * its blobs alone left the message saying "(no paths)" over a commit that claimed
 * a directory, and counted a mixed one at its files.
 *
 * `paths` is what this commit is about, in the caller's own order and both kinds:
 * the paths it took, and, for a verb that lets paths go, the ones it let go
 * (cmds/remove.c, cmds/update.c). A claim is named as the branch spells it —
 * the storage path, unadorned, so a name read out of a log is the key the tree
 * and the sheet hold and the key `remove` takes back — and a claim no verb named
 * is none of the commit's, an ancestor the derivation authored included.
 * `path_count` is the length of `paths` and the one number {count} renders: no
 * template can make the list and the count disagree. Both borrowed for the call.
 */
typedef struct {
    commit_action_t action;     /* Action being performed */
    const char *profile;        /* Profile name (required) */
    const char *const *paths;   /* The paths the commit names, both kinds */
    size_t path_count;          /* How many, and what {count} renders */
    const char *custom_msg;     /* Custom message from -m flag (NULL = use template) */
    const char *target_commit;  /* Target commit SHA (revert alone, NULL otherwise) */
} commit_message_context_t;

/**
 * Build a commit message from context
 *
 * If custom_msg is provided, uses it directly. Otherwise, builds message from
 * config templates with variable substitution.
 *
 * Available template variables:
 *   {host}          - System hostname
 *   {user}          - The invoker's username (the human behind sudo)
 *   {profile}       - Profile name
 *   {action}        - Action (Add, Update, Remove, Sync, Revert)
 *   {action_past}   - Past tense (Added, Updated, Removed, Synced, Reverted)
 *   {count}         - Number of paths, both kinds
 *   {date}          - Local date (YYYY-MM-DD)
 *   {datetime}      - Local timestamp with timezone (ISO 8601)
 *   {paths}         - Formatted path list (bullet points, at most five)
 *   {target_commit} - Target commit SHA (for revert operations, empty otherwise)
 *
 * A variable the table has no row for is left as the template spelled it, braces
 * and all, so a template is never silently emptied by a typo.
 *
 * @param config Configuration holding the two templates (must not be NULL)
 * @param ctx Context with action, profile, paths (must not be NULL)
 * @return Allocated commit message string (caller must free), or NULL: every
 *         reachable failure is an allocation's, the callers' ERR_MEMORY being
 *         the whole truth about it
 */
char *build_commit_message(const config_t *config, const commit_message_context_t *ctx);

/**
 * Get action name in present tense
 *
 * @param action Action type
 * @return Static string ("Add", "Update", "Remove", "Sync", "Revert")
 */
const char *commit_action_name(commit_action_t action);

/**
 * Get action name in past tense
 *
 * @param action Action type
 * @return Static string ("Added", "Updated", "Removed", "Synced", "Reverted")
 */
const char *commit_action_name_past(commit_action_t action);

#endif /* DOTTA_COMMIT_H */
