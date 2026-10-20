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
 * The action a commit's title names: its writer's
 *
 * One for each command that commits through the template; every other commit
 * dotta makes — ignore's, bootstrap's, the epoch's — words its own message.
 */
typedef enum {
    COMMIT_ACTION_ADD,      /* cmds/add.c */
    COMMIT_ACTION_UPDATE,   /* cmds/update.c */
    COMMIT_ACTION_REMOVE,   /* cmds/remove.c */
    COMMIT_ACTION_REVERT    /* cmds/revert.c */
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
 * (cmds/remove.c, cmds/update.c). A claim is named as the profile spells it —
 * the storage path, so a name read out of a log is the key the tree and the sheet
 * hold and the key `remove` takes back, but for a byte no terminal may be handed,
 * which the message spells (commit_message) — and a claim no verb named is none
 * of the commit's, an ancestor the derivation authored included. `path_count`
 * is the length of `paths` and the one number {count} renders: no template can
 * make the list and the count disagree. Both borrowed for the call.
 */
typedef struct {
    commit_action_t action;     /* Action being performed */
    const char *profile;        /* Profile name (required) */
    const char *const *paths;   /* The paths the commit names, both kinds */
    size_t path_count;          /* How many, and what {count} renders */
    const char *custom_msg;     /* Custom message from -m flag (NULL or empty = use template) */
    const char *target_commit;  /* Target commit SHA (revert alone, NULL otherwise) */
} commit_message_context_t;

/**
 * Build a commit message from context
 *
 * A custom message the user wrote is the whole message. Otherwise — none given,
 * or an empty one, which Git itself never commits — builds the message from the
 * config templates with variable substitution.
 *
 * Available template variables:
 *   {host}          - System hostname
 *   {user}          - The invoker's username (the human behind sudo)
 *   {profile}       - Profile name
 *   {action}        - Action (Add, Update, Remove, Revert)
 *   {action_past}   - Past tense (Added, Updated, Removed, Reverted)
 *   {count}         - Number of paths, both kinds
 *   {date}          - Local date (YYYY-MM-DD)
 *   {datetime}      - Local timestamp with timezone (ISO 8601)
 *   {paths}         - Formatted path list (bullet points, at most five)
 *   {target_commit} - Target commit SHA (for revert operations, empty otherwise)
 *
 * A variable the table has no row for is left as the template spelled it, braces
 * and all, so a template is never silently emptied by a typo.
 *
 * Every name a value carries — a path, the profile, the host, the user — is display
 * text the moment the template inserts it, read by every reader of the log: spelled
 * as a terminal may show it (base/string.h str_display), so no name opens a line
 * or sends a control in Git itself. The template's own text and a custom message
 * are their writers', inserted as written.
 *
 * @param arena Arena the message lives in (must not be NULL)
 * @param config Configuration holding the two templates (must not be NULL)
 * @param ctx Context with action, profile, paths (must not be NULL)
 * @return The message, the arena's; never NULL
 */
const char *commit_message(
    arena_t *arena, const config_t *config, const commit_message_context_t *ctx
);

#endif /* DOTTA_COMMIT_H */
