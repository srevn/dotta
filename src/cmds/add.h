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
    bool dry_run;            /* Preview without writing */
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
 * (core/manifest.h manifest_name) — the word alone at the root itself, so `add
 * p ~` and `add p home/` name one claim. So a re-capture lands on the name the
 * profile already has, whatever binding arrived since, and a fresh path beneath
 * a tracked directory takes that directory's name. A typed name is refused where
 * it would give the profile a second name for one path, which is the one place
 * a second name could be born. The receipt counts the paths captured under each
 * label: which label a name keeps is the profile's history, and no argument says
 * it.
 *
 * **The chosen name is the subject of two matchers**, its label stripped: the
 * `.dottaignore` layers and the auto-encryption patterns (core/ignore,
 * core/policy). A path beneath a tracked `home/jail/etc` is matched as `jail/etc/x`
 * and not as `etc/x`, whichever root it physically lies under. The source tree's
 * own `.gitignore` keeps reading where the path stands, that repository's rules
 * being relative to its own root. Prior ciphertext is preserved by the policy's
 * read of the committed bytes and not by a pattern, so a re-capture under a name
 * no pattern matches stays sealed. The encryption verdict is decided with the
 * name, before any capture runs: a verdict that seals on a machine with encryption
 * turned off refuses the command before a byte of it is stored, and a link —
 * whose entry is its target — is never sealed, nor keeps a name sealed
 * (infra/content.h).
 *
 * **What the selection promises**: a command that succeeds captures every path
 * it listed, files and directories alike, each as the kind it was listed as — a
 * path whose kind changed after its listing is refused by its capture, never
 * read as the other. That is what lets the listing stand in for the commit while
 * the command is still naming — and it is load-bearing, since a directory this
 * command lists is the name its walk composed beneath. So one refusal is owed
 * by the completed selection and cannot be reached path by path: where the
 * command's own directory claims would move which of a profile's two names stands
 * at a path, the name that will stand must be a name this command captured.
 *
 * What the commit guarantees: its two documents name one namespace. The tree
 * holds every blob and the sheet holds the directories a tree cannot — an empty
 * one has no entry — and a blob leaves no room for a directory at its name or
 * for anything beneath it. Every path is tested against both as it is listed —
 * the tree as this command has chosen it so far (sys/stage.h, the admission)
 * and the branch's claims — so a walked entry the commit has no room for, or
 * whose name Git will not hold, is skipped with its subtree and a named one is
 * refused; and with the selection complete, before a byte is read, every directory
 * the commit will claim is read against every name its tree will hold. That covers
 * a blob chosen above a directory this command listed first, which refuses the
 * command whichever of the two was walked. A branch that arrived carrying the
 * contradiction refuses too — `dotta remove <profile> <path>` gives the claim
 * up — and a file captured at a directory claim's own name takes the claim's
 * place. The kind a profile's own claim gives a path is that path's question
 * and is asked of the view: a path whose kind changed under a claim is refused
 * by name and skipped by a walk, and `--force` lifts neither — overwriting bytes
 * under a name the profile holds is not re-shaping the tree.
 *
 * **THE KEY INVARIANT**: for every path this command lists, `mount_resolve` of
 * the claim it was listed under is the filesystem path it was read at. A typed
 * name is resolved into its path by construction; a walked one is named from
 * the claim standing at the path the walk reached. That is what lets the record
 * join by the filesystem path without a round trip through the name. It holds
 * by construction and nothing moves it: a run holds the store's write lock from
 * dispatch, so the rows its table was built from are the rows the record's view
 * is built from, and a key is a string of those rows' own (infra/mount.h), which
 * the disk cannot move. The join still tests it, the test being the NULL-row
 * guard the record's counts rest on.
 *
 * **What the record records**: every capture is an ownership event — the path
 * was put there from disk, so the record binds the committed blob to the stat
 * the capture took and the next status takes its fast path. A capture whose path
 * another profile's row wins, or another name of this profile's own, takes no
 * anchor and the receipt says which; a capture whose claim no longer stands where
 * it was read ends the phase, the topology having moved under the command. The
 * record phase is not the command: a failure leaves Git's commit standing, leaves
 * the record exactly as it was, says so, and names the retry — `--force`, over
 * a branch that now holds the name, because an apply re-earns the event for a
 * file it adopts and never for a directory.
 *
 * **-n previews the add and writes nothing of dotta's.** Every decision this
 * command makes runs and no capture does, so an add refused over a name is a
 * preview refused in the same words and with the same status: the listing, the
 * admission of every name together, the name a directory claim would abandon,
 * the entries a chosen name already holds, and each file's encryption verdict.
 * What only a source or a later writer can say is the run's alone — bytes that
 * cannot be read, the key a seal needs, an owner a claim cannot name, a kind
 * that changed since its listing, the chain above each path, whether the commit
 * moves anything, and the record. Its lines are the capture's in the future tense;
 * it captures no file's contents, writes no object, ref, row or database, and
 * takes no write lock (include/runtime.h), so it neither blocks a run nor waits
 * for one. The pre-add hook runs under DOTTA_DRY_RUN=1 and the post-add hook
 * does not (utils/hooks.h).
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
