/**
 * policy.h - Centralized encryption policy decision logic
 *
 * The one answer to whether a file should be encrypted, the hierarchy below:
 * add and update ask it whole, ahead of each capture of a file's bytes
 * (encryption_policy_should_encrypt), and the workspace asks its priority 4 alone,
 * the auto-encrypt patterns, of a row stored plaintext
 * (encryption_policy_violation).
 *
 * Design principle: This module provides POLICY (should we encrypt?), while the
 * content layer provides MECHANISM (how to encrypt). This separation of concerns
 * improves testability and maintainability.
 *
 * Policy hierarchy (priority order):
 * 1. Explicit --encrypt flag → ENCRYPT (highest priority)
 * 2. Explicit --no-encrypt flag → PLAINTEXT, or ERROR where the profile holds
 *    it sealed
 * 3. The profile holds the file sealed → ENCRYPT (maintain state)
 * 4. Auto-encrypt patterns, when encryption is enabled → ENCRYPT (a selector —
 *    the last rule that reaches the path wins; base/gitignore.h)
 * 5. Default → PLAINTEXT (safe default)
 *
 * Ruleset ownership:
 *   The compiled auto-encrypt ruleset lives on the config handle
 *   (config->auto_encrypt_ruleset), compiled once at config_load whether or not
 *   encryption is enabled, in the process's arena with the rest of the
 *   configuration. Policy calls read it directly from config, and only when
 *   encryption is enabled — callers never build, thread, or free the compiled
 *   form themselves.
 */

#ifndef DOTTA_POLICY_H
#define DOTTA_POLICY_H

#include <stdbool.h>
#include <types.h>

/**
 * What the user asked for on the command line
 *
 * Three intentions, one closed enum: no flag, `--encrypt`, `--no-encrypt`. The
 * flags are mutually exclusive at the CLI, and the enum is how that reaches the
 * policy — a bool pair would carry a fourth state ("both") that no caller can
 * produce and the policy would still have to reconcile.
 *
 * `cmd_add_options_t::encrypt_mode` holds this (as int, for ARGS_FLAG_SET); a
 * command with no such flags passes NONE.
 */
typedef enum {
    ENCRYPTION_REQUEST_NONE = 0,   /* No flag: the priorities below decide */
    ENCRYPTION_REQUEST_ENCRYPT,    /* --encrypt */
    ENCRYPTION_REQUEST_PLAINTEXT   /* --no-encrypt */
} encryption_request_t;

/**
 * Determine if file should be encrypted based on policy
 *
 * Policy hierarchy (priority order):
 * 1. If request is ENCRYPT → ENCRYPT (highest priority) Example: User ran `dotta
 *    add --encrypt file`
 *
 * 2. If request is PLAINTEXT → PLAINTEXT, or ERROR when the profile holds the
 *    path sealed Example: User ran `dotta add --no-encrypt file` Rationale: the
 *    flag's job is to keep a path out of the auto-encrypt patterns' reach (priority
 *    4), not to declassify. Storing a sealed file as plaintext would publish
 *    the secret to the branch and its history, so the conflict is refused rather
 *    than silently resolved either way; declassifying is remove-then-add, which
 *    leaves no prior state for priority 3 to read
 *
 * 3. If previously_encrypted=true → ENCRYPT (maintain state) Example: `dotta
 *    update` on already-encrypted file Rationale: Preserve encryption state to
 *    avoid accidental decryption
 *
 * 4. If encryption is enabled and the file matches auto-encrypt patterns → ENCRYPT
 *    (pattern match) Example: File matches config pattern like ".ssh/id_*"
 *
 * 5. Otherwise → PLAINTEXT (default) Rationale: Encryption is opt-in, not opt-out
 *    (safer default)
 *
 * Implementation notes:
 * - NULL config, or encryption disabled, disables priority 4; an absent list
 *   selects nothing
 * - The refusal at priority 2 states the route out (remove, then add again) in
 *   words rather than in commands: the profile and the path as the user typed
 *   them are the command's to know, and a decision function that took them only
 *   to fill a format string would be taking inputs it does not decide on
 * - Priorities 1 and 3 are NOT gated on `config->encryption_enabled`. This is
 *   intentional: if the user explicitly asked to encrypt or a file's prior state
 *   says "encrypted", the policy says so, and the content layer is the single
 *   enforcement point. When encryption is disabled it refuses the seal
 *   (content_require_encryption: ERR_LOCKED, naming the path and the switch) —
 *   at the capture, or ahead of it where a command decides before it reads
 *   (cmds/add). We never silently coerce a request to plaintext, because doing
 *   so on a previously-encrypted file would leak its content.
 *
 * Source of `previously_encrypted`:
 *   The seal the profile holds at the name in the tree its draft opened at, asked
 *   by the caller (core/profiles.h profile_sealed): update at each capture
 *   (cmds/update.c update_capture), add in its decision pass (cmds/add.c cmd_add);
 *   false where no blob stands, a link keeping no name sealed. Its two witnesses,
 *   the blob's bytes and the claim's stamp, a cache of them established at the
 *   write boundary (cmds/add.c, cmds/update.c, and cmds/revert.c's restore),
 *   seal wherever either does: a sheet that disagrees with its tree is a state
 *   the view tolerates (core/profiles.c profile_step), and here a wrong answer
 *   publishes a secret. Stated: a stamp a hand writes over plaintext is a seal
 *   like any other — the next capture seals the file, --no-encrypt is refused
 *   over it, and with encryption off its capture is refused, update's after a
 *   preview that listed it — and remove-then-add is the way out. Policy reads
 *   the answer as the bool and opens no document.
 *
 * @param config Configuration (can be NULL; disables priority-4)
 * @param storage_path File path in profile (e.g., "home/.bashrc", must not be NULL)
 * @param request What the user asked for on the command line
 * @param previously_encrypted Whether the profile holds the name sealed
 *                             (core/profiles.h profile_sealed)
 * @param out_should_encrypt Output decision (must not be NULL)
 * @return Error or NULL on success
 *
 * Errors:
 * - ERR_VALIDATION: --no-encrypt over a seal
 */
error_t encryption_policy_should_encrypt(
    const config_t *config,
    const char *storage_path,
    encryption_request_t request,
    bool previously_encrypted,
    bool *out_should_encrypt
);

/**
 * Check whether a row is in violation of the auto-encrypt policy.
 *
 * Returns true iff the row is content-bearing, its blob is stored plaintext,
 * AND the path matches an active auto-encrypt rule.
 *
 * Used by workspace analysis to flag DIVERGENCE_ENCRYPTION (core/workspace.h)
 * when an active file matches an auto-encrypt pattern but is stored plaintext
 * in Git.
 *
 * Only content-bearing kinds (FILE, EXECUTABLE) can violate. A symlink's blob
 * is its target path, not content: deploy materializes it via symlink(2) and
 * readlink exposes the target on the deployed machine regardless, so encrypting
 * the blob would buy no secrecy — the design stores link targets plaintext always
 * (metadata.h: symlinks carry no encrypted flag; a secret target belongs in an
 * encrypted regular file). A directory row carries no blob at all. For both,
 * "stored plaintext" is not a state the row can be in, so the predicate answers
 * false rather than reading their structural encrypted=false as a violation
 * update's capture could never resolve.
 *
 * Why a bool is exact: the caller holds the view's cached `encrypted` — byte
 * truth by the write-boundary invariant (stamped from the blob's bytes at every
 * committing boundary — cmds/add.c, cmds/update.c, cmds/revert.c — projected
 * onto the view row at build). That bool collapses ENCRYPTED and
 * UNSUPPORTED_VERSION onto true, and the collapse is exactly right here: a blob
 * at a cipher version this build does not understand still carries encryption
 * intent, and flagging it as "missing encryption" would be misleading — the version
 * skew surfaces from the content read path when a caller actually tries to decrypt.
 *
 * Pure — no I/O, no allocation. NULL-safe (returns false if config or storage_path
 * is NULL); an inactive policy (no compiled ruleset) never matches.
 *
 * @param config Configuration (can be NULL)
 * @param storage_path File path in profile (can be NULL)
 * @param type The row's type — only content-bearing kinds can violate
 * @param encrypted Whether the blob's bytes carry encryption intent (the view's
 *                  cache)
 * @return true iff the row violates auto-encrypt policy
 */
bool encryption_policy_violation(
    const config_t *config,
    const char *storage_path,
    path_type_t type,
    bool encrypted
);

#endif /* DOTTA_POLICY_H */
