/**
 * add.h - Add files to profiles
 *
 * Captures files onto a profile branch's stage (sys/stage) and commits it: nothing
 * is checked out, nothing is written under $TMPDIR.
 */

#ifndef DOTTA_CMD_ADD_H
#define DOTTA_CMD_ADD_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Command options
 *
 * `profile` and `files` are populated from the raw positional bucket by
 * `add_post_parse`. Consumers read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_add). */
    const char *profile;     /* Profile name (required) */
    char **files;            /* Array of file paths (required) */
    size_t file_count;       /* Number of files */
    const char *target;      /* Deployment target (optional, for custom/ storage) */
    const char *message;     /* Commit message (optional) */
    char **exclude_patterns; /* Exclude patterns (glob) - read-only */
    size_t exclude_count;    /* Number of exclude patterns */
    bool force;              /* Overwrite existing files in profile */
    bool verbose;            /* Print verbose output */
    int encrypt_mode;        /* encryption_request_t (int for ARGS_FLAG_SET) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_add_options_t;

/**
 * Add files to a profile
 *
 * Stages every file onto the profile branch and commits once. Creates the profile
 * branch if it doesn't exist; a re-add of what the profile already holds commits
 * nothing and says so.
 *
 * What the walk lists: every regular file and symlink it finds, and every directory
 * it enters. A special file — a FIFO, a socket, a device — is no entry a branch
 * can hold, so a walked one is skipped and a named one refused by its noun. A
 * directory below FS_WALK_MAX_DEPTH frames from where its walk began refuses
 * the command, since collection precedes capture and a subtree silently omitted
 * is one the untracked scan cannot offer back (sys/filesystem.h).
 *
 * **The name a capture lands under** is never composed here. A storage-shaped
 * argument is the user's own choice of contract and is written as typed; every
 * other path is named by the claim standing at it — this command's own where it
 * has listed one there, else the profile's, else the composition beneath the
 * nearest directory claim above it, else the label of the root it lies under
 * (core/manifest.h manifest_name). So a re-capture lands on the name the profile
 * already has, whatever binding arrived since, and a fresh path beneath a tracked
 * directory takes that directory's name. A typed name is refused where it would
 * give the profile a second name for one location, which is the one place a second
 * name could be born.
 *
 * **The chosen name is the subject of two matchers**, its label stripped: the
 * `.dottaignore` layers and the auto-encryption patterns (core/ignore,
 * core/policy). A path beneath a tracked `home/jail/etc` is matched as `jail/etc/x`
 * and not as `etc/x`, whichever root it physically lies under. The source tree's
 * own `.gitignore` keeps reading where the path stands, that repository's rules
 * being relative to its own root. Prior ciphertext is preserved by the policy's
 * read of the committed bytes and not by a pattern, so a re-capture under a name
 * no pattern matches stays sealed.
 *
 * **What the selection promises**: a command that succeeds captures every path
 * it listed, files and directories alike. That is what lets the listing stand
 * in for the commit while the command is still naming — and it is load-bearing,
 * since a directory this command lists is the name its walk composed beneath.
 * So one refusal is owed by the completed selection and cannot be reached path
 * by path: where the command's own directory claims would move which of a profile's
 * two names stands at a location, the name that will stand must be a name this
 * command captured.
 *
 * What the commit guarantees: its two documents name one namespace. The tree
 * holds every blob and the sheet holds the directories a tree cannot — an empty
 * one has no entry — and a blob at a name is incompatible with anything at that
 * name and with everything beneath it. Every path is tested against both before
 * it is listed, so a walked entry the branch has no room for is skipped with
 * its subtree and a named one is refused; and the finished sheet is read against
 * the finished tree before anything durable is written, which is what covers
 * the pair this command itself creates. A branch that arrived carrying the
 * contradiction refuses too — `dotta remove <profile> <path>` gives the claim
 * up. The kind a profile's own claim gives a location is the location's question
 * and is asked of the view: a path whose kind changed under a claim is refused
 * by name and skipped by a walk, and `--force` lifts neither — overwriting bytes
 * under a name the profile holds is not re-shaping the tree.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_add(const dotta_ctx_t *ctx, const cmd_add_options_t *opts);

/**
 * Spec-engine command specification for `dotta add`.
 *
 * Registered in cmds/registry.c. Defined in add.c beside the post_parse and
 * dispatch wrappers.
 */
extern const args_command_t spec_add;

#endif /* DOTTA_CMD_ADD_H */
