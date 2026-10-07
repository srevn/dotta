/**
 * revert.h - Revert file to previous commit state
 *
 * Restores a file in a profile to its state at a specific commit, optionally
 * deploying the reverted file to the filesystem.
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
 * populated by the spec engine; `revert_post_parse` reads it and assigns the
 * user-facing `profile`/`file_path`/`commit` fields based on how many positionals
 * the user provided. Consumers of cmd_revert read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_revert). */
    const char *profile;        /* Profile name (NULL = search every local profile) */
    const char *file_path;      /* File path within profile (required) */
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
 * Reverts a file in a profile to its state at the specified commit. This command
 * modifies the Git repository only - deployed files remain unchanged until 'dotta
 * apply' is run.
 *
 * Everything the revert writes is decided before any of it is shown, and shown
 * before it is asked: a dry run and a real run reach the same verdict on the
 * same argument — the same admission, semantic and structural, the draft's own
 * refusals included — and the prompt is the only gate between the preview and
 * the commit. What no preview can foresee is what is left: a ref another writer
 * moved between the preview and the commit, a repository that will not write.
 *
 * The two names. A revert restores what the commit held into the name the profile
 * holds at its head, and the key the user named is the key both trees are asked
 * in. A filesystem path asks each tree what claim stood there; a name asks each
 * tree for that name. Only a name a tree holds in neither of its two documents
 * falls back to that tree's claim at its path — never the reverse, because a
 * path is always answerable and a name may simply not exist:
 *
 *              the write's name (the head)      the read's name (the commit)
 *   LOCATION   the claim standing at L,        the claim standing at L
 *              else the read's own name
 *   STORAGE    the name as typed               that name in either document,
 *                                              else the claim at L
 *
 * Reading across names is safe: a name the commit held is a fact, and following
 * it is how a revert survives a contract change. Writing across them is not — a
 * name is where a claim lands on every machine — so where the head holds nothing
 * the restore takes the name the commit held it by, never one composed from today's
 * roots, and a typed name is refused where authoring it would give the profile
 * a second name for one path — a name the profile already holds there is a
 * re-capture and authors nothing, whether or not the settle kept it
 * (core/manifest.h manifest_holds_name). Encrypted bytes are sealed under their
 * own name (crypto/cipher.h), so a cross-name restore reseals them: the same
 * plaintext, a different object, and a key where a same-name restore needed none.
 *
 * The operation:
 * 1. Discovers which profile holds the argument (requires --profile if ambiguous)
 * 2. Resolves commit reference in profile branch history
 * 3. Opens the profile's draft at its head (core/profiles.h profile_draft_t),
 *    and reads the claim the commit holds — a blob's, decoded — what the head's
 *    tree holds at the name the write uses, which may be nothing, and the restored
 *    blob's own bytes
 * 4. Refuses a typed name that would be the profile's second for one path
 * 5. Restores the claim onto the profile's draft — the write's own admission,
 *    made here so that a commit that cannot hold it refuses before the preview
 *    and not after the prompt: the sheet first, since a directory the profile
 *    claims and nothing fills has no entry for the index to find and a blob above
 *    one leaves it nowhere to stand, then the tree. The entry is put at its id
 *    and no object is written; the claim goes beside it, and the directory claims
 *    the file stood on at the commit wherever the head holds nothing
 * 6. Answers "nothing to do" when the restore moved neither document
 * 7. Shows the preview (restored / diff / mode and ownership only), naming the
 *    commit's own name for the file wherever it differs
 * 8. Prompts for confirmation (unless --force)
 * 9. Creates one commit: the restored blob, its claim and its way
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
