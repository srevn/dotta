/**
 * restore.h - A commit's claims at a path, restored onto a profile's draft
 *
 * The profile's claims at and beneath a path made the commit's, by one rule for
 * a file, a directory and every place the table puts claims beneath: what the
 * commit's view stands there comes back, and what the head holds there that no
 * restore writes goes. Read through two views of the one profile — at the draft's
 * base, and at the commit — placed by this machine's table, so one path keys
 * both; written through the draft's verbs (core/profiles.h), so every rule of a
 * restored claim is the draft's, and every rule of an entry the stage's.
 *
 * A whole profile at a commit is no path here: its commit is the commit's own
 * tree, no claim selected (core/profiles.h profile_restore_tree).
 */

#ifndef DOTTA_RESTORE_H
#define DOTTA_RESTORE_H

#include <types.h>

#include "infra/path.h"

/* A restore edits a profile's draft from a profile at a commit (core/profiles.h),
 * places both sides through a mount table (infra/mount.h) and reseals a claim
 * under its key manager (crypto/keymgr.h), each by pointer; each is named here
 * and defined there. */
typedef struct keymgr keymgr;
typedef struct mount_table mount_table_t;
typedef struct profile profile_t;
typedef struct profile_draft profile_draft_t;

/**
 * The profile's claims at and beneath `arg`, made the commit's on its draft
 *
 * The argument reaches a place, or a name. A path, and a name this machine places,
 * reach every claim either side places at or beneath that place, whichever label
 * names it; a name this machine places nowhere — a custom/ name with no target
 * here — reaches every claim either side holds at or beneath that name. Of those:
 *   - the commit's, as its view stands them (core/manifest.h
 *     manifest_build_profile), one a place, the view standing one row a path,
 *     each restored whole by the draft's verb of its kind (core/profiles.h
 *     profile_restore_file, profile_restore_directory) — a derived one with its
 *     attributes, as the commit had them — under the name the head gives its
 *     place, its claim there, explicit else derived (manifest_lookup_claim),
 *     else under its own: a name is where a claim lands on every machine, and
 *     the profile's stays. A claim the commit held that stood nowhere in its
 *     view — a second name for one path, a claim its own claims contradict — is
 *     not restored; one placed nowhere keeps its own name;
 *   - the head's, every claim it holds, standing or not (core/profiles.h
 *     profile_walk, profile_contradicted), each taken from the draft
 *     (profile_remove) where no restore writes its name in its kind. A derived
 *     one is the way to the claims beneath it, and no writer's to take: the
 *     commit's prune takes one nothing stands beneath any longer.
 * Every removal before any restore, so a restore of the other kind at a name
 * meets nothing in its way. All or nothing: any refusal — the draft's, the stage's,
 * a seal's that moves with no key — leaves a draft its writer abandons.
 *
 * A claim the head holds as the commit held it is written over and moves nothing
 * (sys/stage.h, an entry put as the index holds it; core/metadata.h
 * metadata_write_item), and still pays its restore's reads: its blob, for the
 * stamp, and a tree lookup a rung of its way. The head's claims are placed again,
 * as its view placed them (infra/mount.h mount_resolve): a second walk of the
 * profile, beside the two views' builds.
 *
 * What moved is the draft's to say (profile_changed, profile_changes); the one
 * thing no draft holds is how many claims the argument reaches.
 *
 * Reader: cmds/revert.c cmd_revert, a revert at a path: it refuses an argument
 * that reaches no claim, and says one file's restore whole where the argument
 * reaches one, the commit's file at its own place.
 *
 * @param draft The profile's next commit, opened at its head (must not be NULL)
 * @param mounts This machine's table, which places both sides (must not be NULL)
 * @param arg The argument, in the key it named (must not be NULL)
 * @param from The profile at the commit's tree (must not be NULL; its sheet read
 *             strictly)
 * @param keymgr Key manager, for a sealed claim restored under another name (can
 *               be NULL: such a restore is then refused, ERR_LOCKED)
 * @param out_found The claims the argument reaches, the commit's and the head's,
 *                  a claim both hold counted once and a derivation, a way, none
 *                  (must not be NULL; 0 after an error)
 * @return Error or NULL on success
 */
error_t restore_path(
    profile_draft_t *draft,
    const mount_table_t *mounts,
    const path_input_t *arg,
    profile_t *from,
    keymgr *keymgr,
    size_t *out_found
);

#endif /* DOTTA_RESTORE_H */
