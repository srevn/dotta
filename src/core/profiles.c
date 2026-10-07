/**
 * profiles.c - A profile: what its name says, what it claims at a tree, and its
 * next commit
 *
 * The name's questions: which names this machine layers (the host's), in what
 * order (the names' alone), and whether a profile's branch stands (Git's). The
 * handle is a tree and the sheet read from it once, at the first question, its
 * failure kept beside it; the handle itself stands in an arena of its own, with
 * its name and every claim it lends. The walk is the decode core/profiles.h states,
 * in two halves: one walk of the tree for the blobs (profile_step), then the
 * sheet's directory items, each asked the one question that classifies it, whether
 * a blob stands at its name or at a rung above it (profile_blob_above) — the
 * items a blob stands over are profile_contradicted's. The point questions ask
 * the decode of one name: what the tree holds there, Git's one-entry rule
 * (profile_entry); a blob's claim through the walk's own decode
 * (profile_decode_blob), over the entry that rule answers; and the directory
 * claim standing at a name through the question the walk asks of each item
 * (profile_directory_item), decoded as the walk decodes it
 * (profile_decode_directory). The counts and the need of a target are the walk,
 * folded (profile_counts, profile_needs_target). The next commit is three things
 * in an arena of its own: a sys/stage, opened at the profile's head or over Git's
 * empty tree for a profile the commit creates; the base, the profile at the tree
 * the stage opened, its sheet read at the open; and that sheet copied. An admission
 * asks a name chosen before its bytes of the copy and of the tree as chosen so
 * far, claiming a directory in the copy as it admits it; a removal edits the
 * stage and the copy; a capture authors its claim off the look, asks the base
 * what stands in its way, puts its bytes and writes the claim into the copy,
 * and the climb claims the way to a leaf off the disk; a restore asks the base
 * the same, puts its entry by id and writes its claim and its way into the copy;
 * dotta's own file is put beside the claims; the change test holds each document
 * against the one the stage opened; and the commit, where an edit moved either,
 * prunes the copy, saves it where its claims are no longer the base's and commits.
 */

#include "core/profiles.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/string.h"
#include "core/metadata.h"
#include "infra/content.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/stage.h"

/**
 * One layer's profiles among those available: its base, and its variants one
 * level deep
 *
 * Appended to `out` in the order `available` holds them. Selection only: the
 * ordering is profile_detect's, which sorts everything it selected with
 * profile_order once its three steps have run.
 *
 * @param available The names to match among
 * @param prefix The layer's base name (e.g., "darwin", "hosts/myhost")
 * @param out Where the matches are appended
 */
static void profile_match_hierarchical(
    const string_array_t *available, const char *prefix, string_array_t *out
) {
    size_t prefix_len = strlen(prefix);

    for (size_t i = 0; i < available->count; i++) {
        const char *profile = available->entries[i];

        /* A name of the layer starts with its base */
        if (!str_starts_with(profile, prefix)) continue;

        const char *suffix = profile + prefix_len;
        if (suffix[0] == '\0') {
            /* The base itself */
            string_array_push(out, profile);
        } else if (suffix[0] == '/') {
            const char *variant = suffix + 1;
            /* One level deep only: a non-empty variant with no further '/' */
            if (variant[0] != '\0' && strchr(variant, '/') == NULL) {
                string_array_push(out, profile);
            }
        }
    }
}

string_array_t profile_detect(arena_t *arena, const string_array_t *available) {
    CHECK_NULL(available);

    string_array_t profiles;
    string_array_init(&profiles, arena);

    /* 1. "global" — always first if present */
    if (string_array_contains(available, "global")) {
        string_array_push(&profiles, "global");
    }

    /* 2. The OS's layer (darwin, linux, freebsd, ...), the system's name lowered
     *    where uname wrote it */
    struct utsname uts;
    if (uname(&uts) == 0) {
        /* Safe tolower: cast to unsigned char to avoid UB with negative values */
        for (char *p = uts.sysname; *p; p++) {
            *p = (char) tolower((unsigned char) *p);
        }

        profile_match_hierarchical(available, uts.sysname, &profiles);
    }
    /* Non-fatal: skip OS profiles if uname() fails */

    /* 3. The host's layer (hosts/<hostname>, hosts/<hostname>/<variant>) */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1] = '\0';

        char host_prefix[DOTTA_REFNAME_MAX];
        int n = snprintf(
            host_prefix, sizeof(host_prefix), "hosts/%s", hostname
        );
        if (n >= 0 && (size_t) n < sizeof(host_prefix)) {
            profile_match_hierarchical(available, host_prefix, &profiles);
        }
    }
    /* Non-fatal: continue if gethostname() fails */

    /* The three steps above answer *which* names this machine layers; this is
     * the order they are seeded in. Each step appends in the order `available`
     * holds them, so the one sort is what makes the answer the convention's —
     * the same sort every --all runs over its own set. */
    profile_order(&profiles);

    return profiles;
}

/**
 * The layer a profile name stands in — see profile_order.
 */
static int profile_rank(const char *name) {
    if (strcmp(name, "global") == 0) return 0;
    if (str_starts_with(name, "hosts/")) return 2;

    return 1;
}

/**
 * Two profile names by the layering convention: their layers, then byte order
 * (profile_order)
 */
static int profile_rank_order(const void *a, const void *b) {
    const char *x = *(const char *const *) a;
    const char *y = *(const char *const *) b;

    int rx = profile_rank(x), ry = profile_rank(y);
    if (rx != ry) {
        return rx < ry ? -1 : 1;
    }

    return strcmp(x, y);
}

void profile_order(string_array_t *names) {
    if (!names || names->count < 2) {
        return;
    }

    qsort(names->entries, names->count, sizeof(*names->entries), profile_rank_order);
}

error_t profile_require(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    /* Git's answer or Git's error: an unreadable or corrupt loose ref is an error,
     * never an absence — a bool that read it as "no" sent the user to fetch a
     * profile that was here, let --force delete nothing and call it done, and
     * had validate --fix offer to disable a healthy profile */
    bool exists = false;
    error_t err = gitops_branch_exists(repo, name, &exists);
    if (err) return err;

    /* The refusal: "locally" leaves both readings open, since no verb can tell
     * a typo from a profile not yet fetched; then the verb that brings one, which
     * the fact does not imply, true of both readings — the natural guess, sync,
     * fetches the enabled profiles alone */
    if (!exists) {
        return error_create(
            ERR_NOT_FOUND, "Profile '%s' doesn't exist locally; 'dotta profile fetch %s' "
            "brings it from a remote that holds it", name, name
        );
    }

    return NULL;
}

mode_t profile_claim_mode(const profile_claim_t *claim) {
    CHECK_NULL(claim);

    /* The claim's own, where it makes one: a 0000 claim is a claim */
    if (claim->mode != MODE_UNCLAIMED) return claim->mode;

    /* Else the floor its type stands at */
    switch (claim->type) {
        case PATH_TYPE_FILE:
            return 0644;
        case PATH_TYPE_EXECUTABLE:
            return 0755;
        case PATH_TYPE_SYMLINK:
            return 0;   /* the row's don't-care: no mode stands on a link */
        case PATH_TYPE_DIRECTORY:
            return DIR_MODE_DEFAULT;
    }

    CHECK_ARG(false, "a path type no enumerator names");
}

struct profile {
    arena_t *arena;         /* The handle's own: the handle, its name, the claims it lends */
    const char *name;       /* Whose claims these are, named over every failure */
    const git_tree *tree;   /* The caller's, or `own` */
    git_tree *own;          /* The head profile_load read; NULL at a caller's tree */
    metadata_t *sheet;      /* NULL until a question loads it, and beside a failure */
    error_t sheet_failure;  /* Why it would not load; NULL where it did or is not asked yet */
};

profile_t *profile_open(const char *name, const git_tree *tree) {
    CHECK_NULL(name);
    CHECK_NULL(tree);

    /* The handle in an arena of its own, made here and freed with it, beside
     * the name it copies and every claim it lends; the tree borrowed, and nothing
     * read: the sheet waits for the first question that needs it
     * (profile_load_sheet) */
    arena_t *arena = arena_create(0);
    profile_t *profile = arena_calloc(arena, 1, sizeof(*profile));
    profile->arena = arena;
    profile->name = arena_strdup(arena, name);
    profile->tree = tree;

    return profile;
}

error_t profile_load(git_repository *repo, const char *name, profile_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(out);

    *out = NULL;

    /* The head, its absence refused in gitops' words, which name the reference:
     * nothing to say over them */
    git_tree *head = NULL;
    error_t err = gitops_load_branch_tree(repo, name, &head);
    if (err) return err;

    /* The profile at it, and the head the handle's own, released with it */
    profile_t *profile = profile_open(name, head);
    profile->own = head;

    *out = profile;
    return NULL;
}

void profile_free(profile_t *profile) {
    if (!profile) return;

    /* What the arena does not hold first, read off the handle while it stands;
     * then the arena, and the handle with it */
    metadata_free(profile->sheet);
    git_tree_free(profile->own);
    arena_free(profile->arena);
}

const char *profile_name(const profile_t *profile) {
    CHECK_NULL(profile);

    return profile->name;
}

error_t profile_load_sheet(profile_t *profile) {
    CHECK_NULL(profile);

    /* Asked once. The loader answers a sheet or a failure — an absent sheet is
     * an empty one, never NULL — so a handle holding neither has not asked yet;
     * and a failure leaves the sheet as it was, NULL beside it (core/metadata.h
     * metadata_load_from_tree, untouched on failure). The blob is read through
     * the repository the tree was read from, which a tree knows
     * (lib/libgit2/src/libgit2/object.c git_object_owner) */
    if (!profile->sheet && !profile->sheet_failure) {
        profile->sheet_failure = metadata_load_from_tree(
            git_tree_owner(profile->tree),
            profile->tree,
            profile->name,
            &profile->sheet
        );
    }

    return profile->sheet_failure;
}

/**
 * The claim a blob makes at its name: its identity, and the item's claim over it
 *
 * Identity — the blob's id and the type its filemode says — is handed in as the
 * two facts the caller read off the entry it holds: the walk's, borrowed for
 * its visit, or a point question's answer by value (profile_entry). So no claim
 * carries an opaque handle, and nothing is duplicated to outlive the walk.
 *
 * Readers: profile_step, at every blob the walk meets, and profile_find, at the
 * one it is asked — so the file claim a point question answers is the walk's;
 * and profile_stage_capture_file, at the blob it put — so the claim a capture
 * answers is the one the next walk shows there.
 *
 * @param path The claim's name, which the claim keeps (must not be NULL)
 * @param id The blob's id (must not be NULL)
 * @param filemode The blob's filemode, as its tree records it
 * @param item The FILE item at the name, or NULL where the sheet holds none there
 * @return The claim, by value: a function of its four inputs, which cannot fail
 */
static profile_claim_t profile_decode_blob(
    const char *path,
    const git_oid *id,
    git_filemode_t filemode,
    const metadata_item_t *item
) {
    /* The blob's identity: its id, and the type its filemode says — libgit2
     * normalizes the mode a tree hands back (lib/libgit2/src/libgit2/tree.c
     * normalize_filemode), so a blob's is one of three. No mode is claimed until
     * the item says one. */
    profile_claim_t claim = {
        .storage_path = path,
        .mode         = MODE_UNCLAIMED,
    };
    git_oid_cpy(&claim.blob_oid, id);
    switch (filemode) {
        case GIT_FILEMODE_BLOB_EXECUTABLE:
            claim.type = PATH_TYPE_EXECUTABLE;
            break;
        case GIT_FILEMODE_LINK:
            claim.type = PATH_TYPE_SYMLINK;
            break;
        default:
            /* A blob (the callers pass blobs alone) */
            claim.type = PATH_TYPE_FILE;
            break;
    }

    /* The item's claim over the blob, where the sheet makes one. Owner and group
     * ride every blob, links included: the ownership claim is true regardless
     * of what the path became, and a name the item does not make stays NULL. */
    if (item) {
        claim.owner = item->owner;
        claim.group = item->group;

        /* Mode and stamp only where a mode can stand — the tree's word (the type),
         * never the item's kind: symlink(2) takes no mode, and a link's bytes
         * are its target rather than content anything could seal. A mode the
         * item does not claim stays unclaimed, for the reader to floor
         * (profile_claim_mode). */
        if (claim.type != PATH_TYPE_SYMLINK) {
            claim.mode = item->mode;
            claim.encrypted = item->encrypted;
        }
    }

    return claim;
}

/**
 * The claim a directory item makes at its name
 *
 * The sheet's alone: a tree holds no empty directory, so the item is the claim's
 * whole footprint, and the claim's strings are the sheet's, which the handle keeps.
 *
 * Readers: profile_walk, at each directory claim that stands; profile_contradicted,
 * at each one a blob contradicts; profile_find, at the one it is asked — so the
 * directory claim a point question answers is the walk's; and
 * profile_stage_capture_directory, at the item it wrote.
 *
 * @param item A DIRECTORY item (must not be NULL)
 * @return The claim, by value: a function of its item, which cannot fail
 */
static profile_claim_t profile_decode_directory(const metadata_item_t *item) {
    /* The item's every field but the stamp: the class rides the claim, and a
     * directory takes no stamp */
    return (profile_claim_t){
        .storage_path = item->key,
        .type = PATH_TYPE_DIRECTORY,
        .mode = item->mode,
        .owner = item->owner,
        .group = item->group,
        .tracked = item->tracked,
    };
}

/**
 * The blob over a directory claim at `storage_path` — at its name, or at a rung
 * above it — as the length of the name it stands at; 0 where none stands
 *
 * The classification's question of the tree, one question wherever a directory
 * claim is classified, so no two readers of it can part. A blob leaves no room
 * at its name or beneath it (core/profiles.h, the decode), so the first entry
 * on the way down that is no tree answers: a blob contradicts the claim; a gitlink
 * does not, placing nothing on disk; nor does a name the tree lacks. A name that
 * is a tree at every rung, itself included, stands. The label's word is a rung
 * like any other: a blob at `home` contradicts every home/ claim.
 *
 * Readers: profile_walk and profile_contradicted, at each DIRECTORY item;
 * profile_directory_item, for the point questions; and a profile's next commit,
 * whose admission and put rule ask the base (profile_stage_refuse_beneath,
 * profile_stage_convert).
 *
 * @param profile Handle
 * @param storage_path A validated storage path
 * @param out The length of the blob's name — a prefix of storage_path, or the
 *            whole of it — or 0 where none stands at or above it
 * @return Error or NULL on success: a subtree on the way that will not load,
 *         under "Cannot read '%s' in profile '%s'", naming the claim's name
 */
static error_t profile_blob_above(
    profile_t *profile,
    const char *storage_path,
    size_t *out
) {
    *out = 0;

    /* The name copied once and cut at each separator in turn, so each component
     * is a string the lookup takes whole: a name has no bound but memory, so no
     * buffer on the stack holds it */
    char *name = heap_strdup(storage_path);
    const git_tree *tree = profile->tree;
    git_tree *loaded = NULL;    /* The subtree the descent holds; NULL at the root */
    error_t err = NULL;

    for (char *component = name;;) {
        char *slash = strchr(component, '/');
        if (slash) *slash = '\0';

        /* Top-down, each component looked up once in the tree the one before it
         * found — a claim costs its own components, the lookups a question at the
         * name alone makes (lib/libgit2/src/libgit2/tree.c git_tree_entry_bypath);
         * a climb from the name would descend from the root at every rung. A
         * blob answers, as the length of the name it stands at */
        const git_tree_entry *entry = git_tree_entry_byname(tree, component);
        git_object_t type = entry ? git_tree_entry_type(entry) : GIT_OBJECT_INVALID;
        if (type == GIT_OBJECT_BLOB) {
            *out = slash ? (size_t) (slash - name) : strlen(storage_path);
            break;
        }

        /* Nothing there, a gitlink, or the name itself a tree: the claim stands */
        if (type != GIT_OBJECT_TREE || !slash) break;

        /* A tree on the way, the next component asked of it — read before the
         * one holding its entry is let go. One that will not load is a failure
         * to read, never an absence, as git_tree_entry_bypath reads it */
        git_tree *next = NULL;
        int rc = git_tree_lookup(&next, git_tree_owner(tree), git_tree_entry_id(entry));
        if (rc < 0) {
            err = error_git(
                rc, "Cannot read '%s' in profile '%s'", storage_path, profile->name
            );
            break;
        }
        git_tree_free(loaded);
        tree = loaded = next;
        component = slash + 1;
    }

    git_tree_free(loaded);    /* NULL-safe */
    free(name);

    return err;
}

/**
 * The sheet's directory claim standing at `storage_path`, or NULL: the DIRECTORY
 * item there, where no blob stands at the name or above it
 *
 * The classification at one name, for the questions asked of one: the tree first
 * (profile_blob_above), so a name a blob stands at or over answers without the
 * sheet; then the sheet, under `read`. The raw item, which is this module's own:
 * each reader makes of it what it asks.
 *
 * Readers: profile_holds, where the tree is silent at the name; and profile_find,
 * for a directory claim.
 *
 * @param profile Handle
 * @param read The sheet's policy for this question
 * @param storage_path A validated storage path
 * @param out The item, or NULL where none stands (NULL after an error)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"; the sheet's (STRICT), in the loader's words
 */
static error_t profile_directory_item(
    profile_t *profile,
    profile_read_t read,
    const char *storage_path,
    const metadata_item_t **out
) {
    *out = NULL;

    /* A blob at the name or above it contradicts the claim there, and is the
     * tree's answer, the sheet unread */
    size_t above = 0;
    error_t err = profile_blob_above(profile, storage_path, &above);
    if (err || above > 0) return err;

    /* An open question: the sheet, under the reader's policy. A tolerant read
     * past a sheet that will not load holds no item, since metadata_find_item
     * takes the NULL sheet the failure leaves (profile_load_sheet) */
    err = profile_load_sheet(profile);
    if (err && read == PROFILE_READ_STRICT) return err;

    /* The directory claim at the name, by its kind: a FILE item with no blob is
     * the other kind's, and claims nothing here, as in the walk */
    *out = metadata_find_item(profile->sheet, PATH_KIND_DIRECTORY, storage_path);

    return NULL;
}

/* The walk's tree half: the sheet each blob's item is read from, the visitor,
 * and the visitor's failure past the tree walk it stopped */
typedef struct {
    const metadata_t *sheet;    /* NULL: a tolerant walk past a sheet that will not load */
    profile_visit_fn visit;     /* The visitor */
    void *payload;              /* The caller's, untouched */
    error_t failure;            /* The visitor's: the one that stopped the tree walk */
} profile_walk_t;

/**
 * Walk visitor: one entry of the profile's tree, shown to profile_walk's visitor
 * where it is a claim
 *
 * The tree's half of the decode, in order: the content gate on the name the walk
 * joined (a name in the grammar, and nothing else), the kind, the shape, the
 * sheet's item at the name — and, in the same answer, the content authority —
 * the claim, and the visitor's turn.
 *
 * @param path The entry's path within the tree, joined by the walk (borrowed —
 *             valid for the call only)
 * @param entry Git tree entry (borrowed — valid for the call only)
 * @param payload The walk (profile_walk_t)
 * @param next Set to SKIP past machinery, and to STOP where the visitor failed
 * @return NULL, or the tree's failure that ends the walk: a name outside the
 *         grammar
 */
static error_t profile_step(
    const char *path, const git_tree_entry *entry, void *payload,
    gitops_next_t *next
) {
    profile_walk_t *walk = payload;

    /* The content gate, asked of the name the entry stands at (infra/label.h
     * label_prefixes): a managed path is a name in the grammar — beneath a label,
     * or the label's word alone, the namespace's own directory, which holds what
     * a directory holds. Everything else the branch carries is machinery: dotta's
     * own files (.dottaignore, .bootstrap, .dotta/) and whatever else a hand or
     * a tool left beside them — a README, a LICENSE, a docs/ tree — and no walk
     * of content sees it. Asked of every entry's whole name, a tree's included,
     * so a tree of machinery is skipped with everything beneath it; beneath a
     * label it is always passed. Skipped in silence, and before the shape rule,
     * so machinery is never read as corruption. */
    if (!label_prefixes(path)) {
        *next = GITOPS_NEXT_SKIP;
        return NULL;
    }

    /* Only blobs are claims: a tree beneath a label is walked into — and, in
     * the same line, a gitlink, which is neither, is passed. dotta never writes
     * one (sys/stage refuses the mode), but `dotta git` and a foreign push can,
     * and the profile's answer is that it claims nothing: no claim, no path,
     * nothing beneath it composed through it. Stated rather than incidental,
     * because what this walk shows is what export copies — its claims, or the
     * view's rows placed from them (cmds/export.c) — so every copy goes around
     * such an entry in silence. */
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
        return NULL;
    }

    /* The entry name is Git's, not this machine's. mount_resolve joins a label's
     * tail verbatim on the strength of the path having been validated at its
     * write boundary, and for a branch this machine authored it was — but a branch
     * that arrived by clone or sync was validated by whoever wrote it, which is
     * to say not at all. A tree can name a subtree "..", so the shape has to be
     * checked where the tree is read, the same reason the sheet's key loop checks
     * its own (core/metadata.c). Malformed here is corruption, not a lifecycle
     * stage: it ends the walk as the profile's failure, never a claim. */
    error_t err = label_validate_storage(path);
    if (err) return err;

    /* This blob's claim, by the name the tree gave it: the sheet's FILE item
     * there, its kind the lookup's — and, in the same answer, the content
     * authority. A path is a tree or a blob and the tree is the content authority,
     * so a DIRECTORY item standing at a blob's name is contradicted: it claims
     * nothing here, not even its owner or group — the other kind's, the lookup
     * never reaches it — and nothing as a directory either, which the directory
     * half finds for itself, asking whether a blob stands at the item's name or
     * above it, as a point question does (profile_blob_above). Asked by name,
     * and a name needs no path, so the one rule covers the blob this machine
     * can place and the blob it cannot alike.
     *
     * A blob no FILE item stands at is claimed at its floors and with no stamp,
     * which reads a ciphertext blob through the plaintext comparison and prints
     * [modified] on every load (core/workspace.c) — a sheet a hand or a merge
     * left without the blob's item. That is the profile's to fix; the decode
     * states it rather than repairs it. */
    const metadata_item_t *item = metadata_find_item(walk->sheet, PATH_KIND_FILE, path);

    /* The claim the blob makes, its identity read off the entry while the visit
     * lends it and the item's claim over it, by the one decode a point question
     * at this name reads too (profile_decode_blob) */
    const profile_claim_t claim = profile_decode_blob(
        path, git_tree_entry_id(entry), git_tree_entry_filemode(entry), item
    );

    /* The visitor's turn. Its failure ends the walk and is kept, so every failure
     * the tree walk answers is the tree's (profile_walk), and the visitor's comes
     * back as it made it. */
    walk->failure = walk->visit(&claim, walk->payload);
    if (walk->failure) *next = GITOPS_NEXT_STOP;

    return NULL;
}

error_t profile_walk(
    profile_t *profile, profile_read_t read, profile_visit_fn visit, void *payload
) {
    CHECK_NULL(profile);
    CHECK_NULL(visit);

    /* The sheet first, so a strict walk the sheet refuses shows no claim, and a
     * tolerant one goes on without it, the sheet's half alone lost. The failure
     * is the loader's, which names the profile, and comes back as it is. */
    error_t err = profile_load_sheet(profile);
    if (err && read == PROFILE_READ_STRICT) return err;

    /* The blobs, in the tree's pre-order (profile_step). What the tree walk answers
     * is the tree's — a name its grammar refused, a subtree that would not load
     * — and each names a path in the tree, so the profile is the where neither
     * says. The visitor's own failure stopped the walk and comes back as it was
     * made. */
    profile_walk_t walk = {
        .sheet   = profile->sheet,
        .visit   = visit,
        .payload = payload,
    };
    err = gitops_tree_walk(profile->tree, profile_step, &walk);
    if (err) return error_wrap(err, "Cannot read profile '%s'", profile->name);
    if (walk.failure) return walk.failure;

    /* The directory claims the tree leaves standing: every DIRECTORY item the
     * sheet carries, in key order — none past a sheet a tolerant walk went on
     * without, which holds no item — each asked the question that classifies
     * it, whether a blob stands at its name or at a rung above it, the one a
     * point question asks there (profile_blob_above). One a blob stands at or
     * over claims nothing, and is profile_contradicted's to show. The descent
     * reads no tree the blobs' half did not, so its failure needs a store that
     * changed beneath the walk. */
    const metadata_items_t directories = metadata_items(profile->sheet, PATH_KIND_DIRECTORY);
    for (size_t i = 0; i < directories.count; i++) {
        size_t above = 0;
        err = profile_blob_above(profile, directories.entries[i]->key, &above);
        if (err) return err;
        if (above > 0) continue;

        /* The claim the point question answers at that name, by its decode */
        const profile_claim_t claim = profile_decode_directory(directories.entries[i]);
        err = visit(&claim, payload);
        if (err) return err;
    }

    return NULL;
}

error_t profile_contradicted(
    profile_t *profile, profile_read_t read, profile_visit_fn visit, void *payload
) {
    CHECK_NULL(profile);
    CHECK_NULL(visit);

    /* The sheet first, as the walk reads it: a strict question the sheet refuses
     * shows no claim, and a tolerant one shows none past it, the failure kept
     * for the reader to say. The failure is the loader's, which names the profile,
     * and comes back as it is. */
    error_t err = profile_load_sheet(profile);
    if (err && read == PROFILE_READ_STRICT) return err;

    /* The walk's directory half, answered the other way: every DIRECTORY item,
     * in key order, asked the same question (profile_blob_above), and shown where
     * a blob stands at its name or at a rung above it. Asked before any walk
     * read the tree, the descent can meet a subtree that will not load on its
     * way, and says so in its own words, naming the claim's name. */
    const metadata_items_t directories = metadata_items(profile->sheet, PATH_KIND_DIRECTORY);
    for (size_t i = 0; i < directories.count; i++) {
        size_t above = 0;
        err = profile_blob_above(profile, directories.entries[i]->key, &above);
        if (err) return err;
        if (above == 0) continue;

        /* The item, decoded as the walk would have shown it had no blob stood
         * at its name or above it, and that blob, by its name — a prefix of the
         * claim's own, or the whole of it where the blob stands at the claim's
         * name — kept in the handle's arena, as an answer is */
        profile_claim_t claim = profile_decode_directory(directories.entries[i]);
        claim.blob_above = arena_strndup(profile->arena, directories.entries[i]->key, above);
        err = visit(&claim, payload);
        if (err) return err;
    }

    return NULL;
}

/**
 * Walk visitor: one claim, tallied by its kind
 *
 * A blob is a file, whatever its type; a directory claim counts where the profile
 * tracks it, and an ancestor claim not at all (profile_counts_t).
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The counts so far (profile_counts_t)
 * @return NULL: a tally fails nowhere
 */
static error_t profile_count_claim(const profile_claim_t *claim, void *payload) {
    profile_counts_t *counts = payload;

    if (claim->type != PATH_TYPE_DIRECTORY) {
        counts->file_count++;
    } else if (claim->tracked) {
        counts->directory_count++;
    }

    return NULL;
}

error_t profile_counts(profile_t *profile, profile_counts_t *out) {
    CHECK_NULL(profile);
    CHECK_NULL(out);

    /* The claims the walk shows, read strictly, tallied in a value of the call's
     * own and handed out whole: a walk that stopped short leaves the caller's
     * as it was. The walk's failures name the profile already — the loader's
     * words for the sheet, "Cannot read profile" over the tree's — so nothing
     * is said over them. */
    profile_counts_t counts = { 0 };
    error_t err = profile_walk(
        profile, PROFILE_READ_STRICT, profile_count_claim, &counts
    );
    if (err) return err;

    *out = counts;
    return NULL;
}

/**
 * Walk visitor: the label a claim stands under, noted
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The labels noted so far (bool[LABEL_COUNT])
 * @return NULL: noting a label fails nowhere
 */
static error_t profile_note_label(const profile_claim_t *claim, void *payload) {
    bool *claimed = payload;

    /* Every name the walk shows is under a label: a blob's passed the walk's
     * own gate and shape check, a directory claim's key the sheet's parse
     * (core/profiles.h, the decode) */
    claimed[label_of(claim->storage_path)] = true;

    return NULL;
}

error_t profile_needs_target(profile_t *profile, bool *needs_target) {
    CHECK_NULL(profile);
    CHECK_NULL(needs_target);

    *needs_target = false;

    /* The labels the profile claims anything under, read as the view is shown
     * them: one strict walk, so a sheet that will not load and a tree the walk
     * refuses are the answer's failure here, as they are the view build's */
    bool claimed[LABEL_COUNT] = { false };
    error_t err = profile_walk(
        profile, PROFILE_READ_STRICT, profile_note_label, claimed
    );
    if (err) return err;

    /* Each asked of the table no state row can produce — HOME and the sentinel
     * alone — for the profile's own root of it, in a frame of the call's own,
     * the product being a bool: one with none there is placed by a binding alone,
     * and which labels a binding places is the table's to say (infra/mount.h
     * mount_table_build), so a label it learns to bind moves the answer with it
     * and no label is named here */
    arena_t *frame = arena_create(0);
    mount_table_t *mounts = NULL;
    err = mount_table_build(frame, NULL, 0, &mounts);
    for (label_t label = LABEL_HOME; !err && label < LABEL_COUNT; label++) {
        if (claimed[label] && !mount_root_of(mounts, profile->name, label)) {
            *needs_target = true;
        }
    }
    arena_free(frame);

    return err;
}

error_t profile_entry(
    profile_t *profile, const char *storage_path, profile_held_t *out
) {
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* The tree at the name, and the tree alone. Three answers read as three: no
     * entry at the name, or none to reach it through, is an answer; an intermediate
     * object that will not load is a failure to read, never an absence. */
    git_tree_entry *entry = NULL;
    int rc = git_tree_entry_bypath(&entry, profile->tree, storage_path);
    if (rc == GIT_ENOTFOUND) {
        *out = (profile_held_t){ .kind = PROFILE_HELD_NOTHING };
        return NULL;
    }
    if (rc < 0) {
        return error_git(
            rc, "Cannot read '%s' in profile '%s'",
            storage_path, profile->name
        );
    }

    /* Three kinds and no fourth: git_tree_entry_type reads the entry's mode word,
     * which is a gitlink, a directory, or a blob — so the last arm is the gitlink
     * and not a shrug. The entry's two facts are copied out by value, and the
     * entry goes. */
    profile_held_kind_t kind;
    switch (git_tree_entry_type(entry)) {
        case GIT_OBJECT_BLOB: kind = PROFILE_HELD_FILE; break;
        case GIT_OBJECT_TREE: kind = PROFILE_HELD_DIRECTORY; break;
        default:              kind = PROFILE_HELD_SUBMODULE; break;
    }

    *out = (profile_held_t){
        .kind = kind,
        .oid = *git_tree_entry_id(entry),
        .filemode = git_tree_entry_filemode(entry),
    };
    git_tree_entry_free(entry);

    return NULL;
}

error_t profile_holds(
    profile_t *profile, const char *storage_path, profile_held_t *out
) {
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* The tree first: a name is Git's key, and the tree is the content authority
     * (core/metadata.h), so an entry here is the whole answer whatever the sheet
     * says at the name. Held in a value of the call's own, since `out` is written
     * on success alone. */
    profile_held_t held;
    error_t err = profile_entry(profile, storage_path, &held);
    if (err) return err;
    if (held.kind != PROFILE_HELD_NOTHING) {
        *out = held;
        return NULL;
    }

    /* The tree's silence — no entry at the name, or none to reach it through:
     * the one claim a tree cannot hold, a directory claim with nothing beneath
     * it, standing here and nowhere else, where no blob stands above the name.
     * Read strictly — whether the sheet alone holds one is the sheet's question,
     * so a sheet that will not load is the answer — and by the question the walk
     * and the directory question ask too, so none of them can part */
    const metadata_item_t *item = NULL;
    err = profile_directory_item(profile, PROFILE_READ_STRICT, storage_path, &item);
    if (err) return err;

    *out = (profile_held_t){
        .kind = item ? PROFILE_HELD_DIRECTORY : PROFILE_HELD_NOTHING,
    };

    return NULL;
}

error_t profile_find(
    profile_t *profile, profile_read_t read, path_kind_t kind,
    const char *storage_path, const profile_claim_t **out
) {
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    *out = NULL;

    switch (kind) {
        case PATH_KIND_FILE: {
            /* The blob at the name, or no file claim: the tree's answer, the
             * sheet unread where it gives one (profile_entry) */
            profile_held_t held;
            error_t err = profile_entry(profile, storage_path, &held);
            if (err || held.kind != PROFILE_HELD_FILE) return err;

            /* Its FILE item, under the reader's policy, by its kind: a DIRECTORY
             * item at a blob's name is the other kind's and claims nothing at
             * the blob — the walk's at-name rule (profile_step) */
            err = profile_load_sheet(profile);
            if (err && read == PROFILE_READ_STRICT) return err;
            const metadata_item_t *item = metadata_find_item(
                profile->sheet, PATH_KIND_FILE, storage_path
            );

            /* Decoded as the walk decodes the blob, over the entry's two facts,
             * and kept for the handle's life, its name copied beside it: an answer
             * outlives the caller's argument */
            profile_claim_t *kept = arena_alloc(profile->arena, sizeof(*kept));
            *kept = profile_decode_blob(
                arena_strdup(profile->arena, storage_path), &held.oid, held.filemode, item
            );

            *out = kept;
            return NULL;
        }

        case PATH_KIND_DIRECTORY: {
            /* The directory claim standing at the name, by the question the walk
             * asks of each item and holds asks where the tree is silent */
            const metadata_item_t *item = NULL;
            error_t err = profile_directory_item(profile, read, storage_path, &item);
            if (err || !item) return err;

            /* Decoded as the walk decodes the claim, and kept for the handle's
             * life: its strings are the sheet's, which the handle keeps too */
            profile_claim_t *kept = arena_alloc(profile->arena, sizeof(*kept));
            *kept = profile_decode_directory(item);

            *out = kept;
            return NULL;
        }
    }

    CHECK_ARG(false, "a path kind no enumerator names");
}

struct profile_stage {
    arena_t *arena;                 /* Its own: the struct, the climb's and the prune's names */
    stage_t *stage;                 /* The next tree, on the profile's branch */
    profile_t *base;                /* The profile at the tree it opened: never edited */
    metadata_t *sheet;              /* The base's sheet, copied: what the commit carries */
    stage_admission_t *admission;   /* The tree as a writer chooses its names; NULL until it asks */
};

/**
 * A profile's next commit over the stage `opener` opens: the base at the tree
 * the stage opened, its sheet read now and strictly, and that sheet copied
 *
 * `opener` is sys/stage's for what the writer expects of the profile's branch —
 * stage_open where it stands, stage_orphan where the commit creates it — handed
 * the branch's reference by Git's branch rule, and refusing the other state in
 * its own words. Everything after it is one body: the two openers differ in what
 * they expect of the branch and in nothing they make.
 *
 * Readers: profile_stage_open and profile_stage_orphan.
 *
 * @param repo Repository
 * @param name The profile's name
 * @param opener sys/stage's opener of the branch's stage
 * @param out The stage; NULL on a failure
 * @return Error or NULL on success
 */
static error_t profile_stage_seed(
    git_repository *repo,
    const char *name,
    error_t (*opener)(git_repository *repo, const char *refname, stage_t **out),
    profile_stage_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(out);

    *out = NULL;

    /* The branch the profile is built on, by Git's branch rule, before anything
     * is opened (sys/gitops.h gitops_branch_refname) */
    char refname[DOTTA_REFNAME_MAX];
    error_t err = gitops_branch_refname(refname, sizeof(refname), name);
    if (err) return err;

    /* The stage in an arena of its own, made here and freed with it, as the profile
     * handle stands in its own. Then the stage the opener opens, refused in
     * sys/stage's words where the branch is not as the writer expects it, and
     * the base at the tree the stage opened — the head's, or Git's empty tree,
     * which holds no sheet and so an empty one — its sheet read now and strictly:
     * a writer refuses a sheet that will not load before its preview. The struct
     * holds each from its first allocation, so every failure releases through
     * profile_stage_free, and the sheet's failure outlives the base that kept
     * it (base/error.h "Lifetime") */
    arena_t *arena = arena_create(0);
    profile_stage_t *stage = arena_calloc(arena, 1, sizeof(*stage));
    stage->arena = arena;
    err = opener(repo, refname, &stage->stage);
    if (!err) {
        stage->base = profile_open(name, stage_tree(stage->stage));
        err = profile_load_sheet(stage->base);
    }
    if (err) {
        profile_stage_free(stage);
        return err;
    }

    /* The sheet the commit carries: the base's, copied, so every claim the base
     * lends stands whatever the edits do, and the commit has the base's to compare
     * it with */
    stage->sheet = metadata_clone(stage->base->sheet);

    *out = stage;
    return NULL;
}

error_t profile_stage_open(git_repository *repo, const char *name, profile_stage_t **out) {
    return profile_stage_seed(repo, name, stage_open, out);
}

error_t profile_stage_orphan(git_repository *repo, const char *name, profile_stage_t **out) {
    return profile_stage_seed(repo, name, stage_orphan, out);
}

profile_t *profile_stage_base(const profile_stage_t *stage) {
    CHECK_NULL(stage);

    return stage->base;
}

error_t profile_stage_remove(
    profile_stage_t *stage, path_kind_t kind, const char *storage_path
) {
    CHECK_NULL(stage);
    CHECK_NULL(storage_path);

    switch (kind) {
        case PATH_KIND_FILE: {
            /* The blob leaves the tree, refused in the stage's words where the
             * tree holds none, so a refusal leaves the sheet as it was */
            error_t err = stage_remove(stage->stage, storage_path);
            if (err) return err;

            /* And its FILE item with it, where one stands: its own kind alone,
             * so a directory claim at the name stays — carried, it stands again
             * once the blob is gone */
            metadata_remove_item(stage->sheet, PATH_KIND_FILE, storage_path);

            return NULL;
        }

        case PATH_KIND_DIRECTORY: {
            /* A directory claim's whole footprint is its item, so none of that
             * kind at the name is the sheet's refusal, naming the profile */
            if (!metadata_remove_item(stage->sheet, PATH_KIND_DIRECTORY, storage_path)) {
                return error_create(
                    ERR_NOT_FOUND, "Profile '%s' claims no directory at '%s'",
                    stage->base->name, storage_path
                );
            }

            return NULL;
        }
    }

    CHECK_ARG(false, "a path kind no enumerator names");
}

/**
 * The sheet's half of the admission at `storage_path`: refused where a tracked
 * directory claim the commit carries stands strictly beneath the name, one the
 * base does not contradict
 *
 * The copy is the state: a claim this commit removed, or one a blob's put took
 * the place of, answers nothing, and nothing beside the sheet says so. A derived
 * claim is not asked — what anchors it refuses on its own, a tracked claim here
 * or an entry the tree's half finds, and the prune takes one nothing anchors —
 * nor is one a blob in the base stands at or above, a claim void before the commit
 * and void after it, whatever this commit writes above it. Named by the byte-least
 * such claim — the copy's key order — so a commit's claims say one sentence
 * whatever order its writer made them in.
 *
 * Readers: profile_stage_admit, of a blob a writer chooses before it reads it;
 * and profile_stage_capture_file and profile_stage_restore_file, each before
 * its put.
 *
 * @param stage The stage
 * @param storage_path The name a blob would stand at
 * @return The refusal, ERR_CONFLICT naming the claim; the classification's failure,
 *         a subtree of the base that will not load; or NULL
 */
static error_t profile_stage_refuse_beneath(
    const profile_stage_t *stage, const char *storage_path
) {
    /* The directory claims strictly beneath the name, one slice of the copy's
     * key order: one at the name is the put rule's, and one above it the way
     * every path has. None, in the common case, found in one search */
    const metadata_items_t beneath = metadata_items_beneath(
        stage->sheet, PATH_KIND_DIRECTORY, storage_path
    );

    for (size_t i = 0; i < beneath.count; i++) {
        /* A tracked claim: a derived one is not asked (above) */
        const metadata_item_t *dir = beneath.entries[i];
        if (!dir->tracked) continue;

        /* As the base classifies it (profile_blob_above): a claim a blob in the
         * base stands at or above claims nothing, and is in nothing's way */
        size_t above = 0;
        error_t err = profile_blob_above(stage->base, dir->key, &above);
        if (err) return err;
        if (above > 0) continue;

        return error_create(
            ERR_CONFLICT, "Cannot stage '%s': '%s' is a directory profile '%s' "
            "claims beneath it", storage_path, dir->key, stage->base->name
        );
    }

    return NULL;
}

error_t profile_stage_admit(
    profile_stage_t *stage, path_kind_t kind, const char *storage_path
) {
    CHECK_NULL(stage);
    CHECK_NULL(storage_path);

    /* The tree as the writer chooses its names, made at its first question: only
     * a writer that chooses its names before it reads them asks, and an index
     * of the whole tree at every other open would buy those nothing */
    if (!stage->admission) {
        error_t err = stage_admission_create(stage->stage, &stage->admission);
        if (err) return err;
    }

    switch (kind) {
        case PATH_KIND_FILE: {
            /* The sheet's half first: a directory the commit claims beneath the
             * name has no tree entry for the tree's half to find. Then the tree's,
             * which records the blob, so the next name is asked of a tree that
             * holds it */
            error_t err = profile_stage_refuse_beneath(stage, storage_path);
            if (err) return err;

            return stage_admit_blob(stage->admission, storage_path);
        }

        case PATH_KIND_DIRECTORY: {
            /* The tree's half: a blob at the name or above it — the opened tree's,
             * or one admitted since — leaves the directory none */
            error_t err = stage_admit_subtree(stage->admission, storage_path);
            if (err) return err;

            /* And the walk's word, in the sheet the commit carries, its attributes
             * left to the look its capture takes (profile_stage_capture_directory):
             * a blob chosen above it later meets it at its own admission, as
             * one above a claim the base holds does. A claim the profile tracks
             * there already says it */
            const metadata_item_t *held = metadata_find_item(
                stage->sheet, PATH_KIND_DIRECTORY, storage_path
            );
            if (held && held->tracked) return NULL;

            metadata_item_t *item = metadata_item_create_directory(
                storage_path, MODE_UNCLAIMED, true
            );
            metadata_add_item(stage->sheet, &item);

            return NULL;
        }
    }

    CHECK_ARG(false, "a path kind no enumerator names");
}

/**
 * The put rule for a blob written at `storage_path`: a directory claim standing
 * there gives way, and one the base contradicts rides the write
 *
 * The one write across kinds (core/metadata.h): a blob leaves a directory claim
 * at its name no room. Asked only where the copy holds such a claim, so an ordinary
 * put pays one probe, and of the base, so a claim void before the commit — a
 * blob at its name or above it — is carried, and stands again once that blob goes.
 *
 * Readers: profile_stage_capture_file and profile_stage_restore_file, each after
 * its put.
 *
 * @param stage The stage
 * @param storage_path The name the blob was written at
 * @return Error or NULL on success: the classification's, a subtree of the base
 *         that will not load
 */
static error_t profile_stage_convert(profile_stage_t *stage, const char *storage_path) {
    if (!metadata_find_item(stage->sheet, PATH_KIND_DIRECTORY, storage_path)) return NULL;

    /* As the base classifies it (profile_blob_above): a blob there contradicts
     * the claim, which rides the write */
    size_t above = 0;
    error_t err = profile_blob_above(stage->base, storage_path, &above);
    if (err || above > 0) return err;

    metadata_remove_item(stage->sheet, PATH_KIND_DIRECTORY, storage_path);
    return NULL;
}

error_t profile_stage_capture_file(
    profile_stage_t *stage, const char *storage_path, const content_capture_t *capture,
    arena_t *arena, profile_claim_t *out
) {
    CHECK_NULL(stage);
    CHECK_NULL(storage_path);
    CHECK_NULL(capture);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* Every refusal before anything moves: the claim off the look first, which
     * an owner this host cannot name refuses; then the admission's two halves,
     * the sheet's and the tree's, the put asking the second of the index it writes
     * and writing the blob only once it is admitted */
    metadata_item_t *item = NULL;
    git_oid blob;
    error_t err = metadata_capture_file(storage_path, &capture->st, capture->encrypted, &item);
    if (!err) err = profile_stage_refuse_beneath(stage, storage_path);
    if (!err) {
        err = stage_put(
            stage->stage, storage_path, capture->bytes.data, capture->bytes.size,
            capture->mode, &blob
        );
    }

    /* Then the put rule at the name, whose one failure — a subtree of the base
     * that will not load — leaves the put made, a stage its writer abandons */
    if (!err) err = profile_stage_convert(stage, storage_path);
    if (err) {
        metadata_item_free(item);
        return err;
    }

    /* The claim the commit now carries at the name, by the walk's own decode
     * over the blob the put wrote and the item the look authored — none where
     * it claims nothing — its names the caller's before the sheet takes the item:
     * the record built from it is read past the stage */
    profile_claim_t claim = profile_decode_blob(storage_path, &blob, capture->mode, item);
    claim.owner = arena_strdup(arena, claim.owner);
    claim.group = arena_strdup(arena, claim.group);

    /* The claim at its own kind, by the sheet's rule that an item exists iff it
     * claims something: the look's item, or the retire of the one standing */
    if (item) {
        metadata_add_item(stage->sheet, &item);
    } else {
        metadata_remove_item(stage->sheet, PATH_KIND_FILE, storage_path);
    }

    *out = claim;
    return NULL;
}

error_t profile_stage_capture_directory(
    profile_stage_t *stage, const char *storage_path, const struct stat *st,
    arena_t *arena, profile_claim_t *out
) {
    CHECK_NULL(stage);
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The claim off the look, tracked: a writer captures only a directory the
     * profile tracks. Its one refusal, an owner this host cannot name, comes
     * before anything moves */
    metadata_item_t *item = NULL;
    error_t err = metadata_capture_directory(storage_path, st, true, &item);
    if (err) return err;

    /* The claim as the walk decodes it, its names the caller's and taken before
     * the sheet takes the item: over a claim standing at the name, the sheet
     * keeps its own key and frees the look's */
    profile_claim_t claim = profile_decode_directory(item);
    claim.storage_path = storage_path;
    claim.owner = arena_strdup(arena, claim.owner);
    claim.group = arena_strdup(arena, claim.group);

    /* Its own kind, over the directory claim at the name whatever it said: a
     * FILE item no blob backs there is the other kind's, and rides */
    metadata_add_item(stage->sheet, &item);

    *out = claim;
    return NULL;
}

/**
 * Author, refresh or retire the derived claim at one rung of a chain
 *
 * One component of a leaf's name, spelled by the climb, standing where its own
 * name resolves under the table the leaf was named under — the profile the base's,
 * whose bindings place a custom/ rung. The rule is the sheet's own, read one
 * level up: an item exists iff it claims something, so a rung the disk answers
 * "directory" for claims its attributes, a rung it answers anything else for
 * retires the claim that said otherwise, and a rung it does not answer at all
 * leaves the copy exactly as it found it.
 *
 * Derived throughout: this rule authors the way, never intent. And it cannot
 * fail: every answer the disk gives is one of the three, and the one the capture
 * refuses is the silence of the third.
 *
 * Reader: profile_stage_capture_ancestors, each rung of each leaf it climbs.
 *
 * @param stage The stage: the copy the rung's claim is read and written in, and
 *              the arena the rung's place is spelled into
 * @param mounts The table the rung's name resolves through
 * @param rung The rung's name
 * @param captured Incremented where the rung's claim moved
 * @param retired Receives the name where the rung's claim goes
 */
static void profile_stage_capture_rung(
    profile_stage_t *stage, const mount_table_t *mounts, const char *rung,
    size_t *captured, string_array_t *retired
) {
    /* The directory claim at the rung, the one a derivation may touch, and only
     * a derived one: a tracked claim is the walk's own word about a directory
     * the profile tracks, and nothing derived refreshes or retires it. A FILE
     * item at the rung's key is the other kind's, and no business of this rule:
     * a blob at the rung would have left the leaf beneath it no room, so the
     * item is residue no blob backs, carried as every write carries it, and the
     * rung is claimed beside it — the way's mode is the claim another machine
     * creates the rung by. The prune is no authority over it either: it takes
     * derivations, and this item is not one. */
    const metadata_item_t *held = metadata_find_item(stage->sheet, PATH_KIND_DIRECTORY, rung);
    if (held && held->tracked) return;

    /* Where the rung stands is where its own name resolves. The climb carries
     * one string, not a pair that must agree: a resolve is a root's spelling
     * and a tail, and truncating the leaf's path would land the same bytes — at
     * the cost of a second string the caller must have got right, which is what
     * the cross-check this shape deleted used to assert. One producer places a
     * name (infra/mount.h mount_resolve); the cost is one table scan per rung
     * per leaf, bounded by the profile count. */
    const char *filesystem_path = mount_resolve(stage->arena, mounts, stage->base->name, rung);

    /* A rung this machine cannot place — an unbound custom/ name — has no answer
     * to give, the same silence as a rung nothing stands at. */
    if (!filesystem_path) return;

    struct stat st;
    fs_occupant_t occupant = fs_lstat_occupant(filesystem_path, &st);

    /* Nothing there, or nothing this host could see: the rung has no answer,
     * and no answer is not an answer of "no". A chain the world moved under between
     * the leaf's capture and this climb keeps the claims it already had. */
    if (occupant == FS_OCCUPANT_NONE || occupant == FS_OCCUPANT_UNKNOWN) {
        return;
    }

    /* Something stands here that is not a directory, so the profile passes through
     * no directory at this rung and a claim that says it does has just been
     * contradicted by the disk. The case that matters is a symlink the user put
     * there after the first capture: writing through it is what they asked for,
     * and dropping the claim is what lets dotta — the row leaves the view with
     * the claim, and the caller retires the record that named the path (the two
     * halves core/workspace reads to call a directory displaced). A symlink that
     * was there at capture time never authored a claim to drop; this is the same
     * consent, one command later. */
    if (occupant != FS_OCCUPANT_DIRECTORY) {
        if (metadata_remove_item(stage->sheet, PATH_KIND_DIRECTORY, rung)) {
            string_array_push(retired, rung);
        }
        return;
    }

    /* A directory stands, the look's own kind, so the capture's one refusal is
     * a name this host cannot spell (core/metadata.h metadata_capture_directory)
     * — the same silence as a path it cannot see: a directory capture that fails
     * loses a claim and nothing else, so the rung keeps what it had and dotta
     * creates it as it would have before. Its error is dropped — one per such
     * rung, per leaf climbed through it. */
    metadata_item_t *item = NULL;
    error_t err = metadata_capture_directory(rung, &st, false, &item);
    if (err) return;

    /* A re-derivation that found nothing new authors nothing: the standing claim
     * keeps its place, so nothing is counted and the commit's gate never fires
     * on a chain that has not moved. Ownership is both names or neither
     * (core/metadata.c metadata_capture_ownership), so an absent one compares
     * as the value it is. */
    if (held && held->mode == item->mode &&
        str_equal(held->owner, item->owner) &&
        str_equal(held->group, item->group)) {
        metadata_item_free(item);
        return;
    }

    metadata_add_item(stage->sheet, &item);

    (*captured)++;
}

void profile_stage_capture_ancestors(
    profile_stage_t *stage, const mount_table_t *mounts, const char *storage_path,
    size_t *captured, string_array_t *retired
) {
    CHECK_NULL(stage);
    CHECK_NULL(mounts);
    CHECK_NULL(storage_path);
    CHECK_NULL(captured);
    CHECK_NULL(retired);

    /* One rung per separator in the label's tail. The word is excluded by where
     * the scan starts and the leaf by where it ends — arithmetic, not a special
     * case — so a path directly beneath a root climbs nowhere. */
    const char *first = strchr(label_tail(storage_path), '/');
    if (!first) return;

    /* Every rung is a prefix of the leaf's own name, so one copy spells them
     * all: each separator truncates it in place and is restored before the next
     * one extends past it. The scan reads the caller's string, which is never
     * written, so the cut is an offset into it. The copy is the stage's arena's,
     * as each rung's place is; what keeps a rung — the copy's item, the retired
     * array — copies it. */
    char *rung = arena_strdup(stage->arena, storage_path);

    for (const char *sep = first; sep; sep = strchr(sep + 1, '/')) {
        size_t cut = (size_t) (sep - storage_path);

        rung[cut] = '\0';
        profile_stage_capture_rung(stage, mounts, rung, captured, retired);
        rung[cut] = '/';
    }
}

/**
 * The way a restored file stood on at the commit it came from
 *
 * Each rung of `storage_path` — a separator of its label's tail, the word and
 * the leaf excluded, as the climb names them (profile_stage_capture_ancestors)
 * — paired from the leaf with a rung of `from_storage_path`: both names place
 * one path, so their tails end alike, and the pairing ends where either runs
 * out. Each rung is decided alone, since the base may hold a rung by a sheet
 * claim with nothing above it. A rung the base holds anything at is the base's
 * word on that directory, kept as it stands; at one it holds nothing at, `from`'s
 * directory claim at the pair is written, derived. No disk read: the commit is
 * the source.
 *
 * Asked after the put, of the base, which the restore edited at the leaf alone:
 * the put admitted, no blob stands at or above any rung, so every claim at a
 * rung stands, and a claim written there replaces none the base contradicts.
 *
 * Reader: profile_stage_restore_file.
 *
 * @param stage The stage
 * @param from The profile at the commit
 * @param from_storage_path The commit's name for the file
 * @param storage_path The name the restore writes
 * @return Error or NULL on success: a subtree that will not load, in either tree
 */
static error_t profile_stage_restore_ancestors(
    profile_stage_t *stage, profile_t *from, const char *from_storage_path,
    const char *storage_path
) {
    /* Each name copied once and cut from the leaf in step, a rung of each at
     * every cut: a name is read past its label's word alone (infra/label.h
     * label_tail), so the word is never a rung */
    char *rung = heap_strdup(storage_path);
    char *pair = heap_strdup(from_storage_path);
    error_t err = NULL;

    for (;;) {
        /* The next rung of each name, at its last separator left; a name with
         * none left ends the pairing */
        char *rung_cut = strrchr(label_tail(rung), '/');
        char *pair_cut = strrchr(label_tail(pair), '/');
        if (!rung_cut || !pair_cut) break;
        *rung_cut = '\0';
        *pair_cut = '\0';

        /* A rung the base holds anything at — a subtree, a gitlink, a standing
         * directory claim — is the base's, by the namespace's own question, the
         * one every reader asks there (profile_holds) */
        profile_held_t held;
        err = profile_holds(stage->base, rung, &held);
        if (err) break;
        if (held.kind != PROFILE_HELD_NOTHING) continue;

        /* The commit's claim at the pair, as its walk shows it — none where the
         * commit claimed none there — restored derived: the restore brings a
         * file's way, never a directory's tracking. A FILE item no blob backs
         * at the rung is the other kind's, and stays beside it */
        const profile_claim_t *claim = NULL;
        err = profile_find(from, PROFILE_READ_STRICT, PATH_KIND_DIRECTORY, pair, &claim);
        if (err) break;
        if (!claim) continue;

        metadata_item_t *item = metadata_item_create_directory(rung, claim->mode, false);
        item->owner = heap_strdup(claim->owner);
        item->group = heap_strdup(claim->group);
        metadata_add_item(stage->sheet, &item);
    }

    free(rung);
    free(pair);

    return err;
}

error_t profile_stage_restore_file(
    profile_stage_t *stage, const profile_claim_t *claim, profile_t *from,
    const char *from_storage_path
) {
    CHECK_NULL(stage);
    CHECK_NULL(claim);
    CHECK_NULL(from);
    CHECK_NULL(from_storage_path);

    /* The admission's two halves, each refusing before anything moves: the sheet's,
     * then the tree's, which the put asks of the index it writes — the entry at
     * its id, an object the ODB holds by the commit, so nothing is written here */
    error_t err = profile_stage_refuse_beneath(stage, claim->storage_path);
    if (!err) {
        err = stage_put_blob(
            stage->stage, claim->storage_path, &claim->blob_oid,
            gitops_type_filemode(claim->type)
        );
    }

    /* Then the put rule at the name, and the way the commit stood the file on */
    if (!err) err = profile_stage_convert(stage, claim->storage_path);
    if (!err) {
        err = profile_stage_restore_ancestors(
            stage, from, from_storage_path, claim->storage_path
        );
    }
    if (err) return err;

    /* The claim at its own kind, by the sheet's rule that an item exists iff it
     * claims something: one of no mode, owner or group — a link the commit records
     * no ownership for — retires the item standing at the name */
    if (claim->mode == MODE_UNCLAIMED && !claim->owner && !claim->group) {
        metadata_remove_item(stage->sheet, PATH_KIND_FILE, claim->storage_path);
        return NULL;
    }

    metadata_item_t *item = metadata_item_create_file(
        claim->storage_path, claim->mode, claim->encrypted
    );
    item->owner = heap_strdup(claim->owner);
    item->group = heap_strdup(claim->group);
    metadata_add_item(stage->sheet, &item);

    return NULL;
}

error_t profile_stage_put_machinery(
    profile_stage_t *stage, const char *name, const void *bytes, size_t size
) {
    CHECK_NULL(stage);
    CHECK_NULL(name);

    /* The door's contract, and no refusal of a user's: a name in the grammar is
     * a claim's, which this door would put past the admission and the put rule,
     * and the sheet's directory is the commit's own to write, at its save */
    CHECK_ARG(
        !label_prefixes(name),
        "a name in the grammar is a claim's, never machinery"
    );
    CHECK_ARG(
        strcmp(name, METADATA_DIR) != 0 && !str_starts_with(name, METADATA_DIR "/"),
        "the sheet's directory is the commit's own"
    );

    /* A regular blob, at once in the object database (sys/stage.h stage_put) */
    return stage_put(stage->stage, name, bytes, size, GIT_FILEMODE_BLOB, NULL);
}

error_t profile_stage_changed(const profile_stage_t *stage, bool *out) {
    CHECK_NULL(stage);
    CHECK_NULL(out);

    /* Each document against the one the stage opened, by its owner: the sheet
     * claim by claim, which reads nothing; then the tree, entry by entry */
    if (!metadata_same(stage->sheet, stage->base->sheet)) {
        *out = true;
        return NULL;
    }

    return stage_changed(stage->stage, out);
}

/**
 * Does a tracked claim stand beneath this key?
 *
 * The sheet's half of the tracked set. An empty directory is named by its own
 * claim and by nothing else, so a tracked claim is the one thing beneath a
 * derivation that no index can name. A derivation anchors nothing — it survives
 * by being anchored itself, and letting one anchor another would hold a doomed
 * chain alive a rung per command. The word that decides the prune's subject decides
 * this too, so the two readings cannot drift: they are one field.
 *
 * Strictly beneath, at a component boundary: a claim AT the key is the key, and
 * one above it is the ancestry every path has — so the claims asked are one slice
 * of the copy's key order (core/metadata.h metadata_items_beneath).
 *
 * Reader: profile_stage_prune_ancestors.
 *
 * @param stage The stage, whose copy is asked
 * @param key The derivation's key
 * @return true iff a tracked directory claim stands strictly beneath it
 */
static bool profile_stage_tracked_beneath(const profile_stage_t *stage, const char *key) {
    const metadata_items_t beneath = metadata_items_beneath(
        stage->sheet, PATH_KIND_DIRECTORY, key
    );

    for (size_t i = 0; i < beneath.count; i++) {
        if (beneath.entries[i]->tracked) return true;
    }

    return false;
}

/**
 * Prune the derivations nothing stands beneath
 *
 * The ancestors' third edit (profile_stage_t): the climb and the way author a
 * derived claim at a rung because something beneath it stands, and this removes
 * one the moment nothing does. A tracked claim is not this pass's subject at
 * all — the walk's own word stands with nothing beneath it and at any attributes,
 * and it is retracted where it was made (core/metadata.h) — so the pass reads
 * one field and asks one question of what is left:
 *
 *   Is anything tracked beneath it? The profile's tracked set is the index's
 *   paths and the copy's own tracked claims together. The index names every path
 *   a tree can hold and is the sole authority for those — deliberately not the
 *   sheet's items, which are sparse by design (a symlink carries an item only
 *   where its owner is one absence would misstate), so a directory whose only
 *   tracked content is an item-less symlink is anchored by the index and survives.
 *   What no index can name is an empty directory, and only a tracked claim names
 *   one — a derivation cannot anchor, since it survives solely by being anchored
 *   itself and would otherwise hold a doomed chain alive one command per rung.
 *
 * Anchoring is judged against the stage's index past every edit — the tree the
 * commit will record — so the prune sees the commit's exact tracked set and lands
 * in the same commit as the removals that left a derivation nothing beneath it.
 * Such a derivation has no role in any downstream pipeline: the view would claim
 * it as an [ancestor] row over an emptied subtree, and divergence detection has
 * nothing to compare against — typically the tail of an ancestry whose leaf has
 * just gone (`dotta add ~/dir/f.conf`, then `dotta remove` of that file). One
 * forward pass decides each derivation where it meets it and removes it there:
 * a decision reads the index and the tracked claims alone, and the prune moves
 * neither, so a removal changes no later decision, and the keys come back in
 * key order.
 *
 * Reader: profile_stage_commit, past its gate.
 *
 * @param stage The stage
 * @param pruned Receives the keys pruned, appended as copies in the array's arena;
 *               NULL where the writer keeps none, one with no record phase
 * @return Error or NULL on success: a failed look at the index, which must not
 *         prune
 */
static error_t profile_stage_prune_ancestors(profile_stage_t *stage, string_array_t *pruned) {
    git_index *index = stage_index(stage->stage);

    metadata_items_t directories = metadata_items(stage->sheet, PATH_KIND_DIRECTORY);
    for (size_t d = 0; d < directories.count;) {
        const metadata_item_t *dir = directories.entries[d];

        /* The subject: a derivation, which exists because something beneath it
         * does. A tracked claim is the walk's own word that the profile tracks
         * the directory — it stands with nothing beneath it and at any attributes,
         * and it leaves the sheet where a verb takes it, never by inference
         * (core/metadata.h). The field the climb's rung reads to leave a standing
         * claim alone (profile_stage_capture_rung), asked here for the same
         * reason. */
        if (dir->tracked) {
            d++;
            continue;
        }

        /* Half of what stands beneath: any path under the directory that a tree
         * can hold. The sheet's items are not the universe there — a symlink
         * tracked without elevation carries no item, yet still anchors its parent
         * — so the index is the authority. It is sorted, so one prefix probe
         * answers, the prefix spelled into the stage's arena; a failed look must
         * not prune. */
        int rc = git_index_find_prefix(
            NULL, index, arena_str_format(stage->arena, "%s/", dir->key)
        );
        if (rc != 0 && rc != GIT_ENOTFOUND) {
            return error_git(rc, "Cannot search the tree beneath '%s'", dir->key);
        }

        /* And the other half: the one path a tree cannot hold. Anchored by either,
         * the derivation stands, and the cursor moves past it. */
        if (rc == 0 || profile_stage_tracked_beneath(stage, dir->key)) {
            d++;
            continue;
        }

        /* Nothing stands beneath it: its key handed back where the caller keeps
         * them, copied before the removal frees it; then the derivation goes,
         * and the slice is read again, the removal having moved the entries behind
         * the cursor up to it */
        if (pruned) string_array_push(pruned, dir->key);
        metadata_remove_item(stage->sheet, PATH_KIND_DIRECTORY, dir->key);
        directories = metadata_items(stage->sheet, PATH_KIND_DIRECTORY);
    }

    return NULL;
}

error_t profile_stage_commit(
    profile_stage_t *stage, const char *message, bool *out_committed,
    string_array_t *pruned
) {
    CHECK_NULL(stage);
    CHECK_NULL(message);

    /* No commit until the tree write answers one: every return before it says
     * nothing was committed */
    if (out_committed) *out_committed = false;

    /* Nothing an edit moved: nothing prunes, nothing is saved, nothing commits
     * — imported redundancy rides a commit and never drives one */
    bool changed = false;
    error_t err = profile_stage_changed(stage, &changed);
    if (err || !changed) return err;

    /* The prune, against the stage's index — the tree the commit will record,
     * the removed file claims gone from it (the judge's own contract,
     * profile_stage_prune_ancestors): removing a file may leave the derived claim
     * above it with nothing tracked beneath. The index answers that for every
     * path a tree can hold — never the sheet's items, which omit unelevated
     * symlinks — and the copy's own tracked claims answer it for the one path
     * it cannot, an empty directory. Its keys are handed back where the writer
     * keeps them, for its record phase. */
    err = profile_stage_prune_ancestors(stage, pruned);
    if (err) return err;

    /* The sheet, saved only where its claims are no longer the base's: a commit
     * whose edits took no item and pruned none keeps the sheet's bytes as they
     * stand, a hand's spelling included, as the stage keeps a tree no edit moved
     * (core/metadata.h metadata_same) */
    err = metadata_same(stage->sheet, stage->base->sheet)
        ? NULL : metadata_save_to_stage(stage->stage, stage->sheet);
    if (err) return err;

    /* One commit, the tree and the sheet in one tree write, whether it landed
     * the write's own answer: none where the tree is the one the stage opened,
     * and a head another writer moved since the open is refused (sys/stage.h
     * stage_commit) */
    return stage_commit(stage->stage, message, out_committed);
}

void profile_stage_free(profile_stage_t *stage) {
    if (!stage) return;

    /* The admission and the copy, each its own; then the base, before the stage
     * whose tree it borrows; then the stage, which undoes nothing in the repository
     * (sys/stage.h stage_free); then the arena, the struct with it */
    stage_admission_free(stage->admission);
    metadata_free(stage->sheet);
    profile_free(stage->base);
    stage_free(stage->stage);
    arena_free(stage->arena);
}
