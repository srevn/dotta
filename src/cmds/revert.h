/**
 * revert.h - A path or a whole profile made as a past commit held it
 *
 * A profile's claims at and beneath a path made exactly a commit's of its history,
 * or the profile's next commit that commit's own tree, in one commit on the
 * profile's head. At a path, what the commit's view stands there comes back,
 * each claim under the name the profile holds its place by, else the commit's
 * own; and every claim the profile holds there that the commit did not is removed
 * (revert_restore_path). A whole profile takes the commit's tree whole, its own
 * names and dotta's own files with them, its sheet the save's as at every commit
 * (core/profiles.h profile_restore_tree). Nothing on disk changes: every machine's
 * next apply brings its files in line, deleting the unchanged copies of the files
 * a revert removed (infra/commit.h commit_action_t).
 */

#ifndef DOTTA_CMD_REVERT_H
#define DOTTA_CMD_REVERT_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Revert command options
 *
 * The trailing `positional_args` / `positional_count` pair is a raw bucket
 * populated by the spec engine; `revert_post_parse` reads it by the forms and
 * assigns the user-facing `profile`/`path`/`commit` fields. Consumers of cmd_revert
 * read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_revert). */
    const char *profile;        /* Profile name (NULL = the one holding the path, searched) */
    const char *path;           /* The path, a file or a directory (NULL = the whole profile) */
    const char *commit;         /* Commit reference (required) */
    const char *message;        /* Commit message (NULL = auto-generate) */
    bool force;                 /* Skip confirmation */
    bool dry_run;               /* Preview without making changes */
    int verbosity;              /* dotta_verbosity_t (int for ARGS_FLAG_SET) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_revert_options_t;

/**
 * Execute revert command
 *
 * The forms (revert_post_parse): `p@C` and `p C` the whole profile p; `p:X@C`,
 * `p X C`, `X@C` and `X C` the path X, in p or in the one profile holding it, a
 * commit written after its path's word read by position, a tag or a branch among
 * them. A word that announces a path is one, and any other is a profile
 * (infra/input.h input_announces_path): `src/config@C` is the profile src/config,
 * and `./src/config@C` the path. A typed name is a path like any other, to the
 * search and the restore alike: the place this machine puts it at — or, where
 * it places it nowhere, the name itself (revert_select_profile,
 * revert_restore_path) — so the revert writes the name the profile holds and
 * authors none.
 *
 * The profile is the one named — a refspec's, -p's, a whole profile's own word
 * — or the one local profile holding the path (revert_select_profile). Everything
 * the revert writes is decided on the profile's draft at its head before any of
 * it is shown, so a dry run and a real run reach the same verdict on the same
 * argument — the restore's refusals included, a sealed file restored under another
 * name without its key among them — and a path neither side holds anything at
 * is refused, naming both. Off a terminal, a confirmation it owes is refused
 * before the preview. The pre-revert hook, handed every path a changed claim
 * stands at, and the question are the only gates between the preview and the
 * one commit, made on the head the preview showed: a ref another writer moved
 * since refuses it, --force or not, and a reseal's bytes are written with its
 * tree (sys/stage.h stage_put_unwritten). A commit the prune leaves equal to
 * the head is none, and says nothing to revert. The receipt comes before the
 * record phase, naming a profile this machine has not enabled, and the post-revert
 * hook last.
 *
 * What a revert is said of is what was typed — the argument as the shell spells
 * it, a name as typed — or the profile whole. Its preview shows one file's restore
 * whole, under the name the commit writes it at, where the path is that file
 * and reaches nothing else: restored, its contents unchanged, or its diff; any
 * other revert lists what the commit changes of the profile, in the commit's words.
 *
 * The record phase: a revert changes Git and nothing on disk, and owes the record
 * one write, the reclaim — this profile's record retired at a place the commit
 * changed a claim at, where its node is gone — by one of two rules:
 *   - a place the commit restored a claim at, whatever row stands there: the
 *     record is the restored claim's own history, which would read its absence
 *     as the user's deletion again wherever the claim comes to stand;
 *   - a place only its removals reached, where no row stands there after the
 *     commit, as remove's: a record kept under another profile's row is that
 *     row's reassignment (core/workspace.h workspace_reassigned), which the screens
 *     say.
 * A node standing there is the copy the record describes, apply's to bring: the
 * next load reads a restored file there as [stale].
 *
 * Costs, a verb's, paid when typed: at a path, the restore's two one-profile
 * views and its walk of the profile (revert_restore_path); without a profile
 * named, each local profile's one-profile view where the argument has a place
 * in it, and its documents at the name where it has none (revert_select_profile).
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_revert(const dotta_ctx_t *ctx, const cmd_revert_options_t *opts);

/**
 * Spec-engine command specification for `dotta revert`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in revert.c beside
 * the post_parse and dispatch wrappers.
 */
extern const args_command_t spec_revert;

#endif /* DOTTA_CMD_REVERT_H */
