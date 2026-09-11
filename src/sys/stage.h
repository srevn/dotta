/**
 * stage.h - One ref's next tree, staged in memory
 *
 * The one way dotta turns a tree edit into a commit. Open a ref: its tip is the
 * parent the commit will have, and its tree seeds a private index. Put and remove
 * entries. Commit: the index is written as a tree; a tree equal to the opened
 * one is not committed (no writer wants an empty commit, so none can make one);
 * otherwise one commit with the opened tip as its parent, and the ref moved only
 * if it still is that tip — libgit2 refuses the move when another writer got
 * there first. Four spellings of this answer lived in the tree before (a temp
 * worktree, an index primitive, a recursive treebuilder, the epoch's own mint),
 * and every one looked the parent up at commit time, so a tree built from one
 * tip could be committed on top of another and discard its change; only one of
 * the four declined an empty commit. Both properties are the stage's, once.
 *
 * A writer says what it expects of the ref, and the open refuses the other state:
 * stage_open wants the ref (a profile the view listed, the branch a command
 * resolved) and is refused ERR_NOT_FOUND without it; stage_orphan wants its absence
 * (a profile being created, the epoch's mint, the machine's baseline) and is
 * refused ERR_EXISTS by its presence. An orphan's stage stands on the empty tree
 * — Git's own, which every repository answers for without holding it — so every
 * reader of the opened tree sees a tree, and a ref that does not exist yet reads
 * as one with nothing in it. The expectation is checked once more where it matters,
 * at the commit: a tip that moved, or a ref that appeared where the open found
 * none, reads as ERR_CONFLICT and nothing is committed. A ref deleted between
 * open and commit is recreated at the commit; that one is not guarded — the other
 * actor's delete and this writer's commit are two intents, and the commit's is
 * the one with content.
 *
 * A put never removes another path. libgit2's index REPLACES on a file/directory
 * collision — `git_index_add` of `a/x` over blob `a` drops `a` — so the stage
 * refuses both collisions itself, and stage_remove is the only verb that takes
 * an entry away. Paths are canonical tree paths (no leading or trailing slash,
 * no empty component): libgit2 refuses `..`, `.` and `.git` components at the
 * put and `a//b` at the tree write, but writes `/a` as a tree with an empty-named
 * component, so the stage checks the shape at the door.
 *
 * That rule is askable without writing. stage_admit_blob and stage_admit_subtree
 * are the two sides of it — a blob at N is incompatible with anything at N and
 * with everything beneath N — and both answer about the index as it stands: the
 * branch's tree at the open, plus whatever this stage has already put. A caller
 * that must know before it reads a file's bytes asks; the put asks again and
 * stays the authority, since two names one caller chooses can collide with each
 * other after both were admitted. Neither verb reserves a name, writes an entry
 * or is undone.
 *
 * Every entry names a blob the ODB holds by commit time: stage_put writes it,
 * stage_put_blob trusts the caller (revert's target blob is looked up from a
 * commit), and the tree write refuses an id the ODB lacks. *By commit time* is
 * the whole of the promise: the put itself does not check, so an id whose object
 * is not written yet is admitted and refused only if the commit still lacks it.
 * A writer that must decide before it writes puts the id and materialises the
 * bytes later — revert admits a reseal's hash before its preview and stores the
 * object only past the prompt, so a dry run leaves the database as it found it.
 * Bytes are stored as given — no clean filter, no autocrlf, no filemode config
 * — the way apply writes them back; the mode is the caller's word.
 *
 * Nothing here touches HEAD, a working directory, or the repository's own index,
 * and an open writes nothing at all — the ref is resolved and its tree read, an
 * orphan's empty tree included — so a stage freed before its first put leaves
 * the repository exactly as it found it. A put writes its blob at once: a stage
 * freed after one without a commit, or whose commit was refused, leaves loose
 * objects and no ref, and a refused put may leave its blob the same way. One
 * commit per stage: after it the ref names the commit and the stage still describes
 * the tree it opened on, so a second commit is refused by the tip check — a writer
 * with more to write opens another.
 *
 * Layer: sys/. The module knows libgit2 and sys/gitops' signature, nothing of
 * mounts, content or dotta's vocabulary. Called by the commands that write trees
 * (add, update, remove, revert, bootstrap), by core/metadata's sheet writer,
 * core/ignore's two writers (a profile's .dottaignore, the machine's baseline),
 * infra/content's capture and infra/epoch's mint.
 */

#ifndef DOTTA_STAGE_H
#define DOTTA_STAGE_H

#include <git2.h>
#include <stdbool.h>
#include <stddef.h>
#include <types.h>

/**
 * A stage: one ref, its tip at open, and the tree being made for it (opaque)
 */
typedef struct stage stage_t;

/**
 * Open a ref that exists: the tip's tree in a private index, the tip as the
 * parent-to-be
 *
 * A ref that is absent is refused (ERR_NOT_FOUND): the writer expected it there.
 * A ref that is not a commit (a hand-made ref to a tree), or one that cannot be
 * read, is an error in Git's words. `refname` is a full reference name
 * (refs/heads/<profile>, refs/dotta/epoch) and is copied.
 *
 * @param repo Repository (must not be NULL; borrowed for the stage's lifetime)
 * @param refname Full reference name (must not be NULL)
 * @param out Stage (must not be NULL; freed with stage_free)
 * @return Error or NULL on success
 */
error_t *stage_open(git_repository *repo, const char *refname, stage_t **out);

/**
 * Open a ref that does not exist: the empty tree in a private index, and no parent
 * — the commit will be a root
 *
 * A ref that is present is refused (ERR_EXISTS): the writer expected to create
 * it. One that cannot be read is an error in Git's words. `refname` is copied.
 *
 * @param repo Repository (must not be NULL; borrowed for the stage's lifetime)
 * @param refname Full reference name (must not be NULL)
 * @param out Stage (must not be NULL; freed with stage_free)
 * @return Error or NULL on success
 */
error_t *stage_orphan(git_repository *repo, const char *refname, stage_t **out);

/**
 * The tree the stage opened at — the ref's own bytes at open
 *
 * Readers: the sheet loader (add, update, revert); add's view of its own branch
 * (manifest_build_tree); and the questions revert and remove ask of the branch
 * as it stood — the claim at a location, the entry at a name, a second name,
 * the claims an argument removes. Never NULL: an orphan's stage stands on the
 * empty tree, and add — the one reader that opens one — reads it as a profile
 * with nothing in it yet, no entry and no sheet. Borrowed; valid until stage_free.
 *
 * @param st Stage (must not be NULL)
 * @return The opened tree
 */
const git_tree *stage_tree(const stage_t *st);

/**
 * The index as the stage stands: the tree the commit would record
 *
 * Read it — the prune judge, the entry at a path (git_index_get_bypath). Write
 * it only through the verbs below, which is what keeps the collision rule true.
 * Borrowed; valid until stage_free. Non-const because libgit2's own readers of
 * an index are.
 *
 * @param st Stage (must not be NULL)
 * @return The index
 */
git_index *stage_index(stage_t *st);

/**
 * Can a blob stand at this path — the shape and the two collisions, without writing
 * anything?
 *
 * What stage_put_blob refuses before it adds an entry, asked on its own so a
 * caller can find out before it reads a file's bytes: the tree-path shape libgit2
 * would reject later with a worse message, a proper prefix that names an entry
 * (a file where a directory is needed), and an entry beneath the path (a directory
 * where the file goes). An entry at the path itself is the upsert every writer
 * wants and is admitted.
 *
 * It is not a dry run of the put: libgit2's own path validator is the put's
 * (`home/.git` passes the framing rule and is refused by git_index_add), and so
 * is the mode admission, which a caller listing a path does not yet have.
 *
 * Readers: add's walk and add's argument arm, before either lists a name; and
 * stage_put_blob itself. cmds/revert deliberately does not read it — it holds
 * the id and the mode, so it hoists the whole put before its preview and needs
 * the actual index operation's refusal there, not a question about it.
 *
 * @param st Stage (must not be NULL)
 * @param path Storage path (must not be NULL)
 * @return Error naming the collision, or NULL when a blob may stand there
 */
error_t *stage_admit_blob(const stage_t *st, const char *path);

/**
 * Can a subtree stand at this path — the shape, and the one collision?
 *
 * The other half of the index's file/directory rule, for the caller that has no
 * put to make: dotta's empty directories live in the sheet alone (core/metadata.h),
 * so a profile can claim a directory the tree holds no entry for. A blob at the
 * path, or at any proper prefix of it, leaves no room for entries beneath — nor
 * for a claim about the directory itself. Entries beneath the path are the subtree
 * already standing, and are admitted.
 *
 * Readers: add's walk and add's argument arm, before either lists a directory;
 * and add's read of its finished sheet against its finished index.
 *
 * @param st Stage (must not be NULL)
 * @param path Storage path (must not be NULL)
 * @return Error naming the collision, or NULL when a subtree may stand there
 */
error_t *stage_admit_subtree(const stage_t *st, const char *path);

/**
 * A blob from bytes, then the entry at `path`
 *
 * `mode` is the caller's — a capture's own stat mapped by the caller, never a
 * re-stat here — and one of GIT_FILEMODE_BLOB, GIT_FILEMODE_BLOB_EXECUTABLE or
 * GIT_FILEMODE_LINK; a link's bytes are its target. An entry already at the path
 * is replaced. A file where a directory is needed, or a directory where the file
 * goes, is refused (ERR_CONFLICT) and the index is unchanged; a mode or a path
 * shape outside the contract is refused (ERR_INVALID_ARG).
 *
 * @param st Stage (must not be NULL)
 * @param path Tree path (must not be NULL; canonical, see the header)
 * @param data The bytes (may be NULL when size is 0)
 * @param size Byte count
 * @param mode The entry's filemode
 * @return Error or NULL on success
 */
error_t *stage_put(
    stage_t *st,
    const char *path,
    const void *data,
    size_t size,
    git_filemode_t mode
);

/**
 * The entry at `path` for a blob already in the ODB
 *
 * The same rules as stage_put over a blob the caller wrote or looked up; an id
 * the ODB lacks is refused at the tree write, not here.
 *
 * @param st Stage (must not be NULL)
 * @param path Tree path (must not be NULL; canonical, see the header)
 * @param blob The blob's id (must not be NULL)
 * @param mode The entry's filemode
 * @return Error or NULL on success
 */
error_t *stage_put_blob(
    stage_t *st,
    const char *path,
    const git_oid *blob,
    git_filemode_t mode
);

/**
 * Remove the entry at `path`
 *
 * A path the stage lacks is an error (ERR_NOT_FOUND): the caller's model of the
 * tree is wrong, and the mismatch surfaces instead of silently no-op'ing.
 *
 * @param st Stage (must not be NULL)
 * @param path Tree path (must not be NULL)
 * @return Error or NULL on success
 */
error_t *stage_remove(stage_t *st, const char *path);

/**
 * The tree, and — when it differs from the opened one — one commit
 *
 * The index is written as a tree. A tree equal to the opened one is not committed:
 * nothing moves, `*out_committed` is false. Otherwise one commit with the opened
 * tip as its parent (a root for an orphan's stage) and the ref moved to it, only
 * if the ref still is what the open read: a tip that moved, or a ref that appeared,
 * reads as ERR_CONFLICT naming the ref, and nothing is committed.
 *
 * @param st Stage (must not be NULL)
 * @param message Commit message (must not be NULL)
 * @param out_committed Whether a commit was made — for the callers that must
 *                      say "nothing changed" and cannot know before staging
 *                      (optional, can be NULL)
 * @return Error or NULL on success
 */
error_t *stage_commit(stage_t *st, const char *message, bool *out_committed);

/**
 * Free the stage
 *
 * Safe with NULL. Nothing in the repository is undone: what was committed stands,
 * what was not is loose objects.
 *
 * @param st Stage (can be NULL)
 */
void stage_free(stage_t *st);

#endif /* DOTTA_STAGE_H */
