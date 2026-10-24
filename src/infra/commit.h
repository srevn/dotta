/**
 * commit.h - A commit's words: the action that made it, and the message its
 * templates render
 *
 * A message is two facts from two owners, which meet here and nowhere else. The
 * writer says what it did and how its message reads (commit_words_t): the command
 * that made the commit, the configuration's two templates, the message the user
 * wrote where -m gave one, a revert's target. The draft says what the commit
 * changes of its profile's explicit claims (commit_changes_t), and renders the
 * message from both under its profile's name (core/profiles.h profile_commit).
 *
 * Layer: infra/. It reads base/ and sys/identity, for the invoker's name, and
 * no configuration — the templates are the writer's to hand by name — so core,
 * where a profile's draft commits, may read it.
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
 * What a writer says of its commit
 *
 * Its action; the two templates its message renders, the configuration's [commit]
 * title and body; the message the user wrote, where -m gave one and it is not
 * empty, which is then the whole message; and a revert's target. Filled once,
 * at the writer's commit, every string borrowed for the call.
 */
typedef struct commit_words {
    commit_action_t action;     /* The command that made the commit */
    const char *title;          /* The title template (must not be NULL) */
    const char *body;           /* The body template (must not be NULL) */
    const char *custom_msg;     /* -m: the whole message; NULL or empty, the templates' */
    const char *target_commit;  /* The commit a revert restores from; NULL otherwise */
} commit_words_t;

/**
 * What a commit changes of its profile's explicit claims: each name in one list
 * at most, each list in byte order
 *
 * The commit, never its writer's arguments: each name whose explicit claim the
 * commit adds, updates or removes — the blob at the name with the item that rides
 * it, the directory the profile tracks there — as the draft answers it
 * (core/profiles.h profile_changes). A derived claim is the way to the claims
 * and never one, so no list names it. A name is the profile's spelling of it:
 * the storage path, the key the tree and the sheet hold and `remove` takes back.
 * The lists are borrowed for the call, and a zeroed one names nothing.
 */
typedef struct commit_changes {
    string_array_t added;     /* Names the profile claimed nothing at, and the commit does */
    string_array_t updated;   /* Names claimed on both sides, saying another thing */
    string_array_t removed;   /* Names the profile claimed, and the commit nothing at */
} commit_changes_t;

/**
 * The message a commit carries: its writer's words, over what it changes
 *
 * A custom message the user wrote is the whole message. Otherwise — none given,
 * or an empty one, which Git itself never commits — the writer's two templates,
 * with variable substitution.
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
 * {paths} names the changes, and a commit that moved only the way to the claims
 * says so in one line where the headings would stand. {count} is the three lists'
 * summed length, the one number {paths} cannot disagree with.
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
 * @param words What the writer says of the commit, its two templates among them
 *              (must not be NULL)
 * @param profile The profile's name (must not be NULL)
 * @param changes What the commit changes of the profile's explicit claims (must
 *                not be NULL)
 * @return The message, the arena's; never NULL
 */
const char *commit_message(
    arena_t *arena,
    const commit_words_t *words,
    const char *profile,
    const commit_changes_t *changes
);

#endif /* DOTTA_COMMIT_H */
