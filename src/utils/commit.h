/**
 * commit.h - Commit message template builder
 *
 * Builds structured commit messages for dotfile operations with metadata.
 */

#ifndef DOTTA_COMMIT_H
#define DOTTA_COMMIT_H

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
 * The commit, never its command's arguments: each name whose explicit claim the
 * commit adds, updates or removes — the blob at the name with the item that rides
 * it, the directory the profile tracks there — under its change's heading, as
 * the draft answers it (core/profiles.h profile_changes, whose three lists these
 * are). A derived claim is the way to the claims and never one, so no message
 * names it, and a commit that moved only the way says so in one line where the
 * headings would stand. A name is the profile's spelling of it — the storage
 * path, the key the tree and the sheet hold and `remove` takes back — but for a
 * byte no terminal may be handed, which the message spells (commit_message).
 * {count} is the three lists' summed length, the one number {paths} cannot disagree
 * with. The lists are borrowed for the call, and a zeroed one names nothing.
 */
typedef struct {
    commit_action_t action;     /* Action being performed */
    const char *profile;        /* Profile name (required) */
    string_array_t added;       /* Names whose claim the commit adds */
    string_array_t updated;     /* Names whose claim it updates */
    string_array_t removed;     /* Names whose claim it removes */
    const char *custom_msg;     /* Custom message from -m flag (NULL or empty = use template) */
    const char *target_commit;  /* The commit a revert restores from; NULL otherwise */
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
 *   {count}         - Number of claims the commit adds, updates or removes
 *   {date}          - Local date (YYYY-MM-DD)
 *   {datetime}      - Local timestamp with timezone (ISO 8601)
 *   {paths}         - Each change under its heading (Added, Updated, Removed),
 *                     at most five names a heading; one line where none
 *   {target_commit} - The commit a revert restores from; empty otherwise, so a
 *                     body line whose only variable it is shows on a revert alone
 *
 * A brace closes at the next `}` on its line: one its line leaves open is a
 * character like any other. A variable the table has no row for is left as the
 * template spelled it, braces and all, so a template is never silently emptied
 * by a typo.
 *
 * The title always stands. A body line holding variables, every one of which
 * rendered empty, is left out with the newline that parts it from the rest —
 * its own, or, for the body's last line, the one before it.
 *
 * Every name a value carries — a path, the profile, the host, the user — is display
 * text the moment the template inserts it, read by every reader of the log: spelled
 * as a terminal may show it (base/string.h str_display), so no name opens a line
 * or sends a control in Git itself. The template's own text and a custom message
 * are their writers', inserted as written.
 *
 * @param arena Arena the message lives in (must not be NULL)
 * @param config Configuration holding the two templates (must not be NULL)
 * @param ctx The action, the profile and what the commit changes (must not be NULL)
 * @return The message, the arena's; never NULL
 */
const char *commit_message(
    arena_t *arena, const config_t *config, const commit_message_context_t *ctx
);

#endif /* DOTTA_COMMIT_H */
