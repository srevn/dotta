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
 * the decode of one name: a blob's claim through the walk's own decode
 * (profile_decode_blob), and the directory claim standing at a name through the
 * question the walk asks of each item (profile_directory_item), decoded as the
 * walk decodes it (profile_decode_directory). The counts and the need of a target
 * are the walk, folded (profile_counts, profile_needs_target). The next commit
 * is a sys/stage, the base — the profile at the tree the stage opened, its sheet
 * read at the open — and that sheet copied: a removal edits the stage and the
 * copy, and the commit prunes the copy, saves it where its claims are no longer
 * the base's and commits.
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
#include "infra/label.h"
#include "infra/mount.h"
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
 * Identity — the blob's id and the type its filemode says — is read off the entry
 * here, at the one boundary where the entry is valid (borrowed for the walk's
 * visit, or a point question's own copy), so no claim carries an opaque handle
 * and nothing is duplicated to outlive the walk.
 *
 * Readers: profile_step, at every blob the walk meets, and profile_find, at the
 * one it is asked — so the file claim a point question answers is the walk's.
 *
 * @param path The claim's name, which the claim keeps (must not be NULL)
 * @param entry The blob's tree entry (must not be NULL)
 * @param item The FILE item at the name, or NULL: none, or one the caller voided
 * @return The claim, by value: a function of its three inputs, which cannot fail
 */
static profile_claim_t profile_decode_blob(
    const char *path,
    const git_tree_entry *entry,
    const metadata_item_t *item
) {
    /* The blob's identity: its id, and the type its filemode says — libgit2
     * normalizes the mode it hands back (lib/libgit2/src/libgit2/tree.c
     * normalize_filemode), so a blob's is one of three. No mode is claimed until
     * the item says one. */
    profile_claim_t claim = {
        .storage_path = path,
        .mode         = MODE_UNCLAIMED,
    };
    git_oid_cpy(&claim.blob_oid, git_tree_entry_id(entry));
    switch (git_tree_entry_filemode(entry)) {
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
 * at each one a blob contradicts; and profile_find, at the one it is asked — so
 * the directory claim a point question answers is the walk's.
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
 * Readers: profile_walk and profile_contradicted, at each DIRECTORY item; and
 * profile_directory_item, for the point questions.
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
     * past a sheet that will not load holds no item, since metadata_lookup takes
     * the NULL sheet the failure leaves (profile_load_sheet) */
    err = profile_load_sheet(profile);
    if (err && read == PROFILE_READ_STRICT) return err;

    /* The item at the name, where it claims a directory: a FILE item with no
     * blob claims nothing here, as in the walk */
    const metadata_item_t *item = metadata_lookup(profile->sheet, storage_path);
    if (item && item->kind == PATH_KIND_DIRECTORY) *out = item;

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

    /* This blob's claim, by the name the tree gave it — and, in the same answer,
     * the content authority. A path is a tree or a blob and the tree is the content
     * authority, so a DIRECTORY item standing at a blob's name is contradicted:
     * it claims nothing here, not even its owner or group — and nothing as a
     * directory either, which the directory half finds for itself, asking whether
     * a blob stands at the item's name or above it, as a point question does
     * (profile_blob_above). Asked by name, and a name needs no path, so the one
     * rule covers the blob this machine can place and the blob it cannot alike.
     *
     * The blob a contradicted item leaves is claimed at its floors and with no
     * stamp, which reads a ciphertext blob through the plaintext comparison and
     * prints [modified] on every load (core/workspace.c). The contradiction is
     * the profile's and that is where it gets fixed; the decode states it rather
     * than repairs it. */
    const metadata_item_t *item = metadata_lookup(walk->sheet, path);
    if (item && item->kind == PATH_KIND_DIRECTORY) item = NULL;

    /* The claim the blob makes, its identity and the item's claim over it, by
     * the one decode a point question at this name reads too
     * (profile_decode_blob) */
    const profile_claim_t claim = profile_decode_blob(path, entry, item);

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
     * sheet carries, in its own order — none past a sheet a tolerant walk went
     * on without, which holds no item — each asked the question that classifies
     * it, whether a blob stands at its name or at a rung above it, the one a
     * point question asks there (profile_blob_above). One a blob stands at or
     * over claims nothing, and is profile_contradicted's to show. The descent
     * reads no tree the blobs' half did not, so its failure needs a store that
     * changed beneath the walk. */
    size_t count = 0;
    const metadata_item_t *const *items = metadata_items(profile->sheet, &count);
    for (size_t i = 0; i < count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;

        size_t above = 0;
        err = profile_blob_above(profile, items[i]->key, &above);
        if (err) return err;
        if (above > 0) continue;

        /* The claim the point question answers at that name, by its decode */
        const profile_claim_t claim = profile_decode_directory(items[i]);
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
     * in the sheet's own order, asked the same question (profile_blob_above),
     * and shown where a blob stands at its name or at a rung above it. Asked
     * before any walk read the tree, the descent can meet a subtree that will
     * not load on its way, and says so in its own words, naming the claim's
     * name. */
    size_t count = 0;
    const metadata_item_t *const *items = metadata_items(profile->sheet, &count);
    for (size_t i = 0; i < count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;

        size_t above = 0;
        err = profile_blob_above(profile, items[i]->key, &above);
        if (err) return err;
        if (above == 0) continue;

        /* The item, decoded as the walk would have shown it had no blob stood
         * at its name or above it */
        const profile_claim_t claim = profile_decode_directory(items[i]);
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

error_t profile_holds(
    profile_t *profile, const char *storage_path, profile_held_t *out
) {
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    /* The tree first: a name is Git's key, and the tree is the content authority
     * (core/metadata.h), so an entry here is the whole answer whatever the sheet
     * says at the name. Three answers read as three: an intermediate object that
     * will not load is a failure to read, never an absence. */
    git_tree_entry *entry = NULL;
    int rc = git_tree_entry_bypath(&entry, profile->tree, storage_path);
    if (rc == 0) {
        /* Three kinds and no fourth: git_tree_entry_type reads the entry's mode
         * word, which is a gitlink, a directory, or a blob — so the last arm is
         * the gitlink and not a shrug. */
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
    if (rc != GIT_ENOTFOUND) {
        return error_git(
            rc, "Cannot read '%s' in profile '%s'",
            storage_path, profile->name
        );
    }

    /* The tree's silence — no entry at the name, or none to reach it through:
     * the one claim a tree cannot hold, a directory claim with nothing beneath
     * it, standing here and nowhere else, where no blob stands above the name.
     * Read strictly — whether the sheet alone holds one is the sheet's question,
     * so a sheet that will not load is the answer — and by the question the walk
     * and the directory question ask too, so none of them can part */
    const metadata_item_t *item = NULL;
    error_t err = profile_directory_item(
        profile, PROFILE_READ_STRICT, storage_path, &item
    );
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
             * sheet unread where it gives one. The look reads three answers as
             * three, as every look here does (profile_holds) */
            git_tree_entry *entry = NULL;
            int rc = git_tree_entry_bypath(&entry, profile->tree, storage_path);
            if (rc < 0 && rc != GIT_ENOTFOUND) {
                return error_git(
                    rc, "Cannot read '%s' in profile '%s'", storage_path, profile->name
                );
            }
            if (rc != 0 || git_tree_entry_type(entry) != GIT_OBJECT_BLOB) {
                git_tree_entry_free(entry);   /* NULL-safe */
                return NULL;
            }

            /* Its FILE item, under the reader's policy: a DIRECTORY item at a
             * blob's name claims nothing at the blob — the walk's at-name rule
             * (profile_step) */
            error_t err = profile_load_sheet(profile);
            if (err && read == PROFILE_READ_STRICT) {
                git_tree_entry_free(entry);
                return err;
            }
            const metadata_item_t *item = metadata_lookup(profile->sheet, storage_path);
            if (item && item->kind == PATH_KIND_DIRECTORY) item = NULL;

            /* Decoded as the walk decodes the blob, and kept for the handle's
             * life, its name copied beside it: an answer outlives the caller's
             * argument */
            profile_claim_t *kept = arena_alloc(profile->arena, sizeof(*kept));
            *kept = profile_decode_blob(
                arena_strdup(profile->arena, storage_path), entry, item
            );
            git_tree_entry_free(entry);

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
    stage_t *stage;         /* The next tree, on the profile's branch */
    profile_t *base;        /* The profile at the tree it opened: never edited */
    metadata_t *sheet;      /* The base's sheet, copied: what the commit carries */
};

error_t profile_stage_open(git_repository *repo, const char *name, profile_stage_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(out);

    *out = NULL;

    /* The branch the profile is built on, by Git's branch rule, before anything
     * is opened (sys/gitops.h gitops_branch_refname) */
    char refname[DOTTA_REFNAME_MAX];
    error_t err = gitops_branch_refname(refname, sizeof(refname), name);
    if (err) return err;

    /* The stage at its head, refused in gitops' words where none stands, and
     * the base at the tree the stage opened, its sheet read now and strictly: a
     * writer refuses a sheet that will not load before its preview. The struct
     * holds each from its first allocation, so every failure releases through
     * profile_stage_free, and the sheet's failure outlives the base that kept
     * it (base/error.h "Lifetime") */
    profile_stage_t *stage = heap_calloc(1, sizeof(*stage));
    err = stage_open(repo, refname, &stage->stage);
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

            /* And its item with it, where the item is a file's: the sheet holds
             * one item a name, so its kind is asked, and a directory claim at
             * the name stays — carried, it stands again once the blob is gone */
            const metadata_item_t *item = metadata_lookup(stage->sheet, storage_path);
            if (item && item->kind == PATH_KIND_FILE) {
                metadata_remove_item(stage->sheet, storage_path);
            }

            return NULL;
        }

        case PATH_KIND_DIRECTORY: {
            /* A directory claim's whole footprint is its item, so none of that
             * kind at the name is the sheet's refusal, naming the profile */
            const metadata_item_t *item = metadata_lookup(stage->sheet, storage_path);
            if (!item || item->kind != PATH_KIND_DIRECTORY) {
                return error_create(
                    ERR_NOT_FOUND, "Profile '%s' claims no directory at '%s'",
                    profile_name(stage->base), storage_path
                );
            }
            metadata_remove_item(stage->sheet, storage_path);

            return NULL;
        }
    }

    CHECK_ARG(false, "a path kind no enumerator names");
}

error_t profile_stage_commit(
    profile_stage_t *stage, const char *message, string_array_t *pruned
) {
    CHECK_NULL(stage);
    CHECK_NULL(message);
    CHECK_NULL(pruned);

    /* The prune, against the stage's index — the tree the commit will record,
     * the removed file claims gone from it (the judge's own contract,
     * core/metadata.h metadata_prune_ancestors): removing a file may leave the
     * derived claim above it with nothing tracked beneath. The index answers
     * that for every path a tree can hold — never the sheet's items, which omit
     * unelevated symlinks — and the copy's own tracked claims answer it for the
     * one path it cannot, an empty directory. */
    error_t err = metadata_prune_ancestors(stage->sheet, stage_index(stage->stage), pruned);
    if (err) return err;

    /* The sheet, saved only where its claims are no longer the base's: a commit
     * whose edits took no item and pruned none keeps the sheet's bytes as they
     * stand, a hand's spelling included, as the stage keeps a tree no edit moved
     * (core/metadata.h metadata_same) */
    err = metadata_same(stage->sheet, stage->base->sheet)
        ? NULL : metadata_save_to_stage(stage->stage, stage->sheet);
    if (err) return err;

    /* One commit, the tree and the sheet in one tree write: none where the tree
     * is the one the stage opened, and a head another writer moved since the
     * open is refused (sys/stage.h stage_commit) */
    return stage_commit(stage->stage, message, NULL);
}

void profile_stage_free(profile_stage_t *stage) {
    if (!stage) return;

    /* The copy; then the base, before the stage whose tree it borrows; then the
     * stage, which undoes nothing in the repository (sys/stage.h stage_free) */
    metadata_free(stage->sheet);
    profile_free(stage->base);
    stage_free(stage->stage);
    free(stage);
}
