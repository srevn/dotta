/**
 * profiles.c - A profile: what its name says, what it claims at a tree, and the
 * draft of its next commit
 *
 * The name's questions: which names this machine layers (the host's), in what
 * order (the names' alone), and whether a profile's branch stands (Git's). The
 * handle is a tree and the sheet read from it once, at the first question, its
 * failure kept beside it; the handle itself stands in an arena of its own, with
 * its name, its sheet and every claim it lends. The walk is the decode
 * core/profiles.h states, in two halves: one walk of the tree for the blobs
 * (profile_step), then the sheet's directory items, each asked the one question
 * that classifies it, whether a blob stands at its name or at a rung above it
 * (profile_blob_above) — the items a blob stands over are profile_contradicted's.
 * The point questions ask the decode of one name: what the tree holds there,
 * Git's one-entry rule (profile_entry); a blob's claim through the walk's own
 * decode (profile_decode_blob), over the entry that rule answers; and the directory
 * claim standing at a name through the question the walk asks of each item
 * (profile_directory_item), decoded as the walk decodes it
 * (profile_decode_directory). The seal at a name is the blob's, asked of its
 * two witnesses: its stamp through the same decode, its bytes where the stamp
 * says none (profile_sealed). The counts and the need of a target are the walk,
 * folded (profile_counts, profile_needs_target). A name's departure is its
 * history's one walk from a head (sys/history.h), read through the one table of
 * what each removal's action means (profile_departures). The draft is three things
 * in an arena of its own: a sys/stage, opened at the profile's head, over Git's
 * empty tree for a profile the commit creates, or over a merge of the head with
 * another commit; the base, the profile at the tree the stage opened, its sheet
 * read at the open; and the sheet the commit carries — that sheet copied, or
 * the claims a merge composed. An admission asks a name chosen before its bytes
 * of the copy and of the tree as chosen so far, claiming a directory in the copy
 * as it admits it; a removal edits the stage and the copy; a capture authors
 * its claim off the look, asks the base what stands in its way, puts its bytes
 * and writes the claim into the copy, and the climbs claim the way to a leaf
 * off the disk — the first capture where the profile does not pass through a
 * rung yet, the named re-derivation again where a run's paths select one; a restore
 * asks the base the same, puts its entry by id and writes its claim, and its
 * way where the profile does not pass through it, into the copy; dotta's own
 * file is put beside the claims. A merge composes its tree first — each name
 * Git could not compose settled by a rule, or for the run's side — then its claims,
 * one pass a kind over the three sides' sheets in step, each claim a side moved
 * composed from the three sides' words, each read over its own tree, and standing
 * where the merged tree leaves it room. The change test holds each document against
 * the one the draft opened, and the changes merge what each says moved into the
 * explicit claims the commit adds, updates and removes; and the commit, where
 * an edit moved either, prunes the sheet it carries, saves it where its claims
 * are no longer the base's, renders its message from the writer's words over
 * those changes and commits.
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
#include "core/ignore.h"
#include "core/metadata.h"
#include "infra/commit.h"
#include "infra/content.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/pathspec.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/history.h"
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
    string_array_init(&profiles, arena, 0);

    /* 1. "global", where available */
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
    CHECK_NULL(names);

    if (names->count < 2) {
        return;
    }

    qsort(names->entries, names->count, sizeof(*names->entries), profile_rank_order);
}

error_t profile_require(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    /* Git's answer or Git's error: an unreadable or corrupt loose ref is an error,
     * never an absence — a bool that read it as "no" sent the user to fetch a
     * profile that was here, and let --force delete nothing and call it done */
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
        case PATH_TYPE_FILE:       return 0644;
        case PATH_TYPE_EXECUTABLE: return 0755;
        case PATH_TYPE_SYMLINK:    return 0;   /* the row's don't-care: no mode stands on a link */
        case PATH_TYPE_DIRECTORY:  return DIR_MODE_DEFAULT;
    }

    CHECK_ARG(false, "a path type no enumerator names");
}

struct profile {
    arena_t *arena;         /* The handle's own: the handle, its name, the claims it lends */
    const char *name;       /* Whose claims these are, named over every failure */
    const git_tree *tree;   /* The caller's, or `own` */
    git_tree *own;          /* The head profile_load read; NULL at a caller's tree */
    metadata_t *sheet;      /* In the arena; NULL until a question loads it, and beside a failure */
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
     * then the arena, and the handle with it, its name, its sheet and every claim
     * it lent */
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
     * metadata_load_from_tree, untouched on failure). The sheet is the handle's
     * own, in its arena, read off its tree */
    if (!profile->sheet && !profile->sheet_failure) {
        profile->sheet_failure = metadata_load_from_tree(
            profile->tree, profile->name, profile->arena, &profile->sheet
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
 * profile_sealed, at the blob a seal is asked of — so the stamp it reads is the
 * one the screens read off the walk's claim; profile_capture_file, at the blob
 * it put — so the claim a capture answers is the one the next walk shows there;
 * and profile_merge_file, at each side's blob beside an axis both sides moved
 * apart — so a conflict says each side's claim as that side's walk shows it.
 *
 * @param path The claim's name, which the claim keeps (must not be NULL)
 * @param id The blob's id (must not be NULL)
 * @param filemode The blob's filemode, as its tree records it
 * @param item The FILE item at the name, or NULL where the sheet holds none there
 * @return The claim, by value: a function of its four inputs, which cannot fail
 */
static profile_claim_t profile_decode_blob(
    const char *path, const git_oid *id, git_filemode_t filemode,
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
 * directory claim a point question answers is the walk's;
 * profile_capture_directory, at the item it wrote; and profile_merge_directory,
 * at each side's item beside an axis both sides moved apart.
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
 * profile_directory_item, for the point questions; and a profile's draft, whose
 * admission and put rule ask the base (profile_refuse_beneath, profile_convert).
 * A merge asks the rule of its stage, whose tree is not written yet
 * (profile_merge_contradicted): one rule, two trees.
 *
 * @param profile Handle
 * @param storage_path A validated storage path
 * @param out The length of the blob's name — a prefix of storage_path, or the
 *            whole of it — or 0 where none stands at or above it
 * @return Error or NULL on success: a subtree on the way that will not load,
 *         under "Cannot read '%s' in profile '%s'", naming the claim's name
 */
static error_t profile_blob_above(
    profile_t *profile, const char *storage_path, size_t *out
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
         * found — a claim costs its own components, the lookups a question at
         * the name alone makes (lib/libgit2/src/libgit2/tree.c
         * git_tree_entry_bypath); a climb from the name would descend from the
         * root at every rung. A blob answers, as the length of the name it stands
         * at */
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
    profile_t *profile, profile_read_t read, const char *storage_path,
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
 * A blob is a file, whatever its type, counted again where its stamp says
 * encrypted; a directory claim counts where the profile tracks it, and an ancestor
 * claim not at all (profile_counts_t).
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The counts so far (profile_counts_t)
 * @return NULL: a tally fails nowhere
 */
static error_t profile_count_claim(const profile_claim_t *claim, void *payload) {
    profile_counts_t *counts = payload;

    if (claim->type != PATH_TYPE_DIRECTORY) {
        counts->file_count++;
        if (claim->encrypted) counts->encrypted_count++;
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

error_t profile_sealed(profile_t *profile, const char *storage_path, bool *out) {
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    *out = false;

    /* The blob at the name, or no seal: the tree's answer, the sheet unread where
     * it gives none (profile_entry) */
    profile_held_t held;
    error_t err = profile_entry(profile, storage_path, &held);
    if (err || held.kind != PROFILE_HELD_FILE) return err;

    /* The stamp first, off the sheet the handle holds, where the bytes cost the
     * blob loaded whole to reach six of them: the blob's claim decoded as the
     * walk decodes it, so a link carries none (profile_decode_blob). A stamp
     * that says sealed is the answer, whatever bytes another writer committed
     * under it. */
    err = profile_load_sheet(profile);
    if (err) return err;
    const profile_claim_t claim = profile_decode_blob(
        storage_path, &held.oid, held.filemode,
        metadata_find_item(profile->sheet, PATH_KIND_FILE, storage_path)
    );
    if (claim.encrypted) {
        *out = true;
        return NULL;
    }

    /* Then the bytes, which stay sealed where the stamp was lost over them — a
     * hand's edit, a directory's item at the name: judged by the entry's mode,
     * so a link's target is no seal whatever it begins with, and sealed at any
     * cipher version, this build's or another. A blob that will not load is this
     * question failing, never "not sealed": a sniff that defaulted would flip
     * the policy silently. */
    content_kind_t kind;
    err = content_classify(
        git_tree_owner(profile->tree), &held.oid, held.filemode, &kind, NULL
    );
    if (err) {
        return error_wrap(
            err, "Cannot read '%s' in profile '%s'", storage_path, profile->name
        );
    }

    *out = kind != CONTENT_PLAINTEXT;
    return NULL;
}

void profile_departures(
    git_repository *repo, const git_oid *head, const char *const *storage_paths,
    size_t count, profile_departure_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    if (count == 0) return;
    CHECK_NULL(storage_paths);

    /* No head: the branch is gone, and with it every byte only it reached */
    if (!head) {
        for (size_t i = 0; i < count; i++) {
            out[i] = (profile_departure_t){ .kind = PROFILE_DEPARTURE_GONE };
        }
        return;
    }

    /* The walk's answers live and die in this call: the deciding commit is copied
     * out by value */
    arena_t *frame = arena_create(0);
    history_removals_t *found = arena_calloc(frame, count, sizeof(*found));
    history_removals(repo, head, storage_paths, count, frame, found);

    /* The one table: update's and revert's removals delete the files they take,
     * and every other action's — none's too — keep them; a removal that keeps
     * decides beside every other removal and every line unread */
    const char *update = commit_action_word(COMMIT_ACTION_UPDATE);
    const char *revert = commit_action_word(COMMIT_ACTION_REVERT);
    for (size_t i = 0; i < count; i++) {
        const history_removals_t *removals = &found[i];

        const history_removal_t *kept = NULL;
        for (size_t k = 0; k < removals->count && !kept; k++) {
            const char *action = removals->entries[k].action;
            if (!str_equal(action, update) && !str_equal(action, revert)) {
                kept = &removals->entries[k];
            }
        }

        if (removals->holding == HISTORY_HOLDING_HELD) {
            out[i] = (profile_departure_t){ .kind = PROFILE_DEPARTURE_HELD };
        } else if (kept) {
            out[i] = (profile_departure_t){
                .kind = PROFILE_DEPARTURE_REMOVED,
                .removal = kept->oid,
            };
        } else if (removals->holding == HISTORY_HOLDING_UNREAD) {
            out[i] = (profile_departure_t){ .kind = PROFILE_DEPARTURE_UNVERIFIED };
        } else if (removals->count == 0) {
            out[i] = (profile_departure_t){ .kind = PROFILE_DEPARTURE_NEVER_HELD };
        } else {
            out[i] = (profile_departure_t){
                .kind = PROFILE_DEPARTURE_DELETED,
                .removal = removals->entries[0].oid,
            };
        }
    }

    arena_free(frame);
}

struct profile_draft {
    arena_t *arena;                 /* Its own: the struct, the sheet, the names it spells, its message */
    stage_t *stage;                 /* The next commit, on the profile's branch */
    profile_t *base;                /* The profile at the tree it opened: never edited */
    metadata_t *sheet;              /* What the commit carries: the base's copied, or a merge's claims */
    stage_admission_t *admission;   /* The tree as a writer chooses its names; NULL until it asks */
};

/**
 * A profile's draft over the stage its opener opened: the base at the stage's
 * tree, its sheet read now and strictly
 *
 * Each opener builds the branch's reference by Git's branch rule and opens its
 * stage at what the writer expects of the branch — stage_open where it stands,
 * stage_orphan where the commit creates it, stage_merge where it stands and another
 * commit is merged into it — refused in the stage's own words otherwise; then
 * seeds here, and writes the sheet its commit carries: the base's, copied, or
 * the claims a merge composes. The stage is the draft's from the call, released
 * with it on a failure.
 *
 * Readers: profile_draft_open, profile_draft_orphan and profile_draft_merge.
 *
 * @param name The profile's name
 * @param stage The stage its opener opened (the draft's from the call)
 * @param out The draft (written on success alone)
 * @return Error or NULL on success: the sheet's, in the loader's words
 */
static error_t profile_draft_seed(const char *name, stage_t *stage, profile_draft_t **out) {
    /* The draft in an arena of its own, made here and freed with it, as the profile
     * handle stands in its own, and the stage its own from here on. Then the
     * base at the tree the stage opened — the head's, or Git's empty tree, which
     * holds no sheet and so an empty one — its sheet read now and strictly: a
     * writer refuses a sheet that will not load before its preview. The struct
     * holds each from its first allocation, so the sheet's failure releases all
     * of them through profile_draft_free, and outlives the base that kept it
     * (base/error.h "Lifetime") */
    arena_t *arena = arena_create(0);
    profile_draft_t *draft = arena_calloc(arena, 1, sizeof(*draft));
    draft->arena = arena;
    draft->stage = stage;
    draft->base = profile_open(name, stage_tree(stage));

    error_t err = profile_load_sheet(draft->base);
    if (err) {
        profile_draft_free(draft);
        return err;
    }

    *out = draft;
    return NULL;
}

error_t profile_draft_open(git_repository *repo, const char *name, profile_draft_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(out);

    *out = NULL;

    /* The branch the profile is built on, by Git's branch rule (sys/gitops.h
     * gitops_branch_refname); its stage at the head, refused in the stage's words
     * where the branch does not stand (sys/stage.h stage_open); and the draft
     * over it */
    char refname[DOTTA_REFNAME_MAX];
    stage_t *stage = NULL;
    profile_draft_t *draft = NULL;
    error_t err = gitops_branch_refname(refname, sizeof(refname), name);
    if (!err) err = stage_open(repo, refname, &stage);
    if (!err) err = profile_draft_seed(name, stage, &draft);
    if (err) return err;

    /* The sheet the commit carries: the base's, copied into the draft's arena,
     * so every claim the base lends stands whatever the edits do, and the commit
     * has the base's to compare it with */
    draft->sheet = metadata_clone(draft->arena, draft->base->sheet);

    *out = draft;
    return NULL;
}

error_t profile_draft_orphan(git_repository *repo, const char *name, profile_draft_t **out) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(out);

    *out = NULL;

    /* The branch the commit creates, by Git's branch rule (sys/gitops.h
     * gitops_branch_refname); its stage over Git's empty tree, refused in the
     * stage's words where the branch stands (sys/stage.h stage_orphan); and the
     * draft over it */
    char refname[DOTTA_REFNAME_MAX];
    stage_t *stage = NULL;
    profile_draft_t *draft = NULL;
    error_t err = gitops_branch_refname(refname, sizeof(refname), name);
    if (!err) err = stage_orphan(repo, refname, &stage);
    if (!err) err = profile_draft_seed(name, stage, &draft);
    if (err) return err;

    /* The sheet the commit carries: the base's, an empty one, copied as
     * profile_draft_open copies it */
    draft->sheet = metadata_clone(draft->arena, draft->base->sheet);

    *out = draft;
    return NULL;
}

profile_t *profile_draft_base(const profile_draft_t *draft) {
    CHECK_NULL(draft);

    return draft->base;
}

error_t profile_remove(profile_draft_t *draft, path_kind_t kind, const char *storage_path) {
    CHECK_NULL(draft);
    CHECK_NULL(storage_path);

    switch (kind) {
        case PATH_KIND_FILE: {
            /* The blob leaves the tree, refused in the stage's words where the
             * tree holds none, so a refusal leaves the sheet as it was */
            error_t err = stage_remove(draft->stage, storage_path);
            if (err) return err;

            /* And its FILE item with it, where one stands: its own kind alone,
             * so a directory claim at the name stays — carried, it stands again
             * once the blob is gone */
            metadata_remove_item(draft->sheet, PATH_KIND_FILE, storage_path);

            return NULL;
        }

        case PATH_KIND_DIRECTORY: {
            /* A directory claim's whole footprint is its item, so a name the
             * sheet tracks nothing at is the sheet's refusal, naming the profile
             * — no claim there, or a derivation, which stands for what stands
             * beneath it and is no writer's to take */
            const metadata_item_t *claim = metadata_find_item(
                draft->sheet, PATH_KIND_DIRECTORY, storage_path
            );
            if (!claim || !claim->tracked) {
                return error_create(
                    ERR_NOT_FOUND, "Profile '%s' tracks no directory at '%s'",
                    draft->base->name, storage_path
                );
            }

            /* The tracking goes, never the way to what stays beneath it: the
             * claim stays a derivation, the attributes it claimed kept, so another
             * machine creates the directory as this one had it — the prune's to
             * take at the commit where nothing tracked stands beneath it once
             * every edit is in, whatever order the writer made them in
             * (profile_prune_ancestors) */
            const metadata_item_t derivation = {
                .kind  = PATH_KIND_DIRECTORY,
                .key   = claim->key,
                .mode  = claim->mode,
                .owner = claim->owner,
                .group = claim->group,
            };
            metadata_write_item(draft->sheet, &derivation);

            return NULL;
        }
    }

    CHECK_ARG(false, "a path kind no enumerator names");
}

/**
 * The claim's half of a capture's refusals: a look whose owner or group this
 * host cannot name
 *
 * The capture answers which half (core/metadata.h metadata_capture_ownership),
 * and the refusal is worded here, where add and update capture: the user is at
 * the terminal and the path is still theirs to fix, rather than a silence for
 * deploy to act on a year later on another machine. "Cannot resolve" rather than
 * "does not exist": the half is an absent entry or a lookup that failed alike.
 * The refusal names the path it was handed, so no caller names it again.
 *
 * Readers: profile_capture_file and profile_capture_directory, each first. A
 * climb's rung reads the answer itself and refuses nothing (profile_capture_rung).
 *
 * @param ownership The capture's answer
 * @param storage_path The name the look is captured under
 * @param st The look, for the id this host cannot name
 * @return The refusal, ERR_NOT_FOUND naming the id and the name; or NULL where
 *         the answer is RESOLVED
 */
static error_t profile_refuse_ownership(
    metadata_ownership_t ownership, const char *storage_path, const struct stat *st
) {
    switch (ownership) {
        case METADATA_OWNERSHIP_RESOLVED:
            return NULL;

        case METADATA_OWNERSHIP_NO_SUCH_USER:
            return error_create(
                ERR_NOT_FOUND, "Cannot resolve UID %u, the owner of '%s', to a user "
                "name on this system", (unsigned) st->st_uid, storage_path
            );

        case METADATA_OWNERSHIP_NO_SUCH_GROUP:
            return error_create(
                ERR_NOT_FOUND, "Cannot resolve GID %u, the group of '%s', to a group "
                "name on this system", (unsigned) st->st_gid, storage_path
            );
    }

    CHECK_ARG(false, "an ownership answer no enumerator names");
}

/**
 * The sheet's half of the admission at `storage_path`: refused where a tracked
 * directory claim the commit carries stands strictly beneath the name, one the
 * base does not contradict
 *
 * The copy is the state: a claim this commit removed, or one a blob's put took
 * the place of, answers nothing, and nothing beside the sheet says so. A derived
 * claim is not asked — what stands beneath it refuses on its own, a tracked claim
 * here or an entry the tree's half finds, and the prune takes one nothing stands
 * beneath — nor is one a blob in the base stands at or above, a claim void before
 * the commit and void after it, whatever this commit writes above it. Named by
 * the byte-least such claim — the copy's key order — so a commit's claims say
 * one sentence whatever order its writer made them in.
 *
 * Readers: profile_admit, of a blob a writer chooses before it reads it; and
 * profile_capture_file and profile_restore_file, each before its put.
 *
 * @param draft The draft
 * @param storage_path The name a blob would stand at
 * @return The refusal, ERR_CONFLICT naming the claim; the classification's failure,
 *         a subtree of the base that will not load; or NULL
 */
static error_t profile_refuse_beneath(const profile_draft_t *draft, const char *storage_path) {
    /* The directory claims strictly beneath the name, one slice of the copy's
     * key order: one at the name is the put rule's, and one above it the way
     * every path has. None, in the common case, found in one search */
    const metadata_items_t beneath = metadata_items_beneath(
        draft->sheet, PATH_KIND_DIRECTORY, storage_path
    );

    for (size_t i = 0; i < beneath.count; i++) {
        /* A tracked claim: a derived one is not asked (above) */
        const metadata_item_t *dir = beneath.entries[i];
        if (!dir->tracked) continue;

        /* As the base classifies it (profile_blob_above): a claim a blob in the
         * base stands at or above claims nothing, and is in nothing's way */
        size_t above = 0;
        error_t err = profile_blob_above(draft->base, dir->key, &above);
        if (err) return err;
        if (above > 0) continue;

        return error_create(
            ERR_CONFLICT, "Cannot stage '%s': '%s' is a directory profile '%s' "
            "claims beneath it", storage_path, dir->key, draft->base->name
        );
    }

    return NULL;
}

error_t profile_admit(profile_draft_t *draft, path_kind_t kind, const char *storage_path) {
    CHECK_NULL(draft);
    CHECK_NULL(storage_path);

    /* The tree as the writer chooses its names, made at its first question: only
     * a writer that chooses its names before it reads them asks, and an index
     * of the whole tree at every other open would buy those nothing */
    if (!draft->admission) {
        error_t err = stage_admission_create(draft->stage, &draft->admission);
        if (err) return err;
    }

    switch (kind) {
        case PATH_KIND_FILE: {
            /* The sheet's half first: a directory the commit claims beneath the
             * name has no tree entry for the tree's half to find. Then the tree's,
             * which records the blob, so the next name is asked of a tree that
             * holds it */
            error_t err = profile_refuse_beneath(draft, storage_path);
            if (err) return err;

            return stage_admit_blob(draft->admission, storage_path);
        }

        case PATH_KIND_DIRECTORY: {
            /* The tree's half: a blob at the name or above it — the opened tree's,
             * or one admitted since — leaves the directory none */
            error_t err = stage_admit_subtree(draft->admission, storage_path);
            if (err) return err;

            /* And the walk's word, in the sheet the commit carries, its attributes
             * left to the look its capture takes (profile_capture_directory): a
             * blob chosen above it later meets it at its own admission, as one
             * above a claim the base holds does. A claim the profile tracks there
             * already says it */
            const metadata_item_t *held = metadata_find_item(
                draft->sheet, PATH_KIND_DIRECTORY, storage_path
            );
            if (held && held->tracked) return NULL;

            const metadata_item_t item = {
                .kind    = PATH_KIND_DIRECTORY,
                .key     = storage_path,
                .mode    = MODE_UNCLAIMED,
                .tracked = true,
            };
            metadata_write_item(draft->sheet, &item);

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
 * put pays one search, and of the base, so a claim void before the commit — a
 * blob at its name or above it — is carried, and stands again once that blob goes.
 *
 * Readers: profile_capture_file and profile_restore_file, each after its put.
 *
 * @param draft The draft
 * @param storage_path The name the blob was written at
 * @return Error or NULL on success: the classification's, a subtree of the base
 *         that will not load
 */
static error_t profile_convert(profile_draft_t *draft, const char *storage_path) {
    if (!metadata_find_item(draft->sheet, PATH_KIND_DIRECTORY, storage_path)) {
        return NULL;
    }

    /* As the base classifies it (profile_blob_above): a blob there contradicts
     * the claim, which rides the write */
    size_t above = 0;
    error_t err = profile_blob_above(draft->base, storage_path, &above);
    if (err || above > 0) return err;

    metadata_remove_item(draft->sheet, PATH_KIND_DIRECTORY, storage_path);
    return NULL;
}

error_t profile_capture_file(
    profile_draft_t *draft, const char *storage_path, const content_capture_t *capture,
    arena_t *arena, profile_claim_t *out
) {
    CHECK_NULL(draft);
    CHECK_NULL(storage_path);
    CHECK_NULL(capture);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* Every refusal before anything moves: the claim off the look first, which
     * an owner this host cannot name refuses (profile_refuse_ownership), its
     * names spelled in the caller's arena — the record built from the claim is
     * read past the draft; then the admission's two halves, the sheet's and the
     * tree's, the put asking the second of the index it writes and writing the
     * blob only once it is admitted */
    metadata_item_t item;
    git_oid blob;
    error_t err = profile_refuse_ownership(
        metadata_capture_file(storage_path, &capture->st, capture->encrypted, arena, &item),
        storage_path, &capture->st
    );
    if (!err) err = profile_refuse_beneath(draft, storage_path);
    if (!err) {
        err = stage_put(
            draft->stage, storage_path, capture->bytes.data, capture->bytes.size,
            capture->mode, &blob
        );
    }

    /* Then the put rule at the name, whose one failure — a subtree of the base
     * that will not load — leaves the put made, a draft its writer abandons */
    if (!err) err = profile_convert(draft, storage_path);
    if (err) return err;

    /* The claim the commit now carries at the name, by the walk's own decode
     * over the blob the put wrote and the claim off the look; then that claim
     * at its own kind, the sheet's copy of it — or, where it claims nothing,
     * the retire of the item standing there (core/metadata.h
     * metadata_write_item) */
    *out = profile_decode_blob(storage_path, &blob, capture->mode, &item);
    metadata_write_item(draft->sheet, &item);

    return NULL;
}

error_t profile_capture_directory(
    profile_draft_t *draft, const char *storage_path, const struct stat *st,
    arena_t *arena, profile_claim_t *out
) {
    CHECK_NULL(draft);
    CHECK_NULL(storage_path);
    CHECK_NULL(st);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The claim off the look, tracked: a writer captures only a directory the
     * profile tracks. Its one refusal, an owner this host cannot name, comes
     * before anything moves (profile_refuse_ownership); its names are spelled
     * in the caller's arena */
    metadata_item_t item;
    error_t err = profile_refuse_ownership(
        metadata_capture_directory(storage_path, st, true, arena, &item),
        storage_path, st
    );
    if (err) return err;

    /* The claim as the walk decodes it; then the sheet's copy of it, at its own
     * kind, over the directory claim at the name whatever it said: a FILE item
     * no blob backs there is the other kind's, and rides */
    *out = profile_decode_directory(&item);
    metadata_write_item(draft->sheet, &item);

    return NULL;
}

/**
 * Does a tracked claim stand beneath this key in `sheet`?
 *
 * The sheet's half of the tracked set. An empty directory is named by its own
 * claim and by nothing else, so a tracked claim is the one thing beneath a key
 * that no tree and no index can name. Nothing derived keeps another standing —
 * a derivation survives by what stands beneath it, and letting one keep another
 * would hold a doomed chain alive a rung per command. The word that decides the
 * prune's subject decides this too, so the two readings cannot drift: they are
 * one field.
 *
 * Strictly beneath, at a component boundary: a claim AT the key is the key, and
 * one above it is the ancestry every path has — so the claims asked are one slice
 * of the sheet's key order (core/metadata.h metadata_items_beneath).
 *
 * Readers: profile_passes, of a profile's sheet at a rung of a way — a draft's
 * base, or a merge's side; and profile_prune_ancestors, of the sheet a draft's
 * commit carries at a derivation's key.
 *
 * @param sheet The sheet asked: a profile's, or the one a draft's commit carries
 * @param key The key
 * @return true iff a tracked directory claim stands strictly beneath it
 */
static bool profile_tracked_beneath(const metadata_t *sheet, const char *key) {
    const metadata_items_t beneath = metadata_items_beneath(
        sheet, PATH_KIND_DIRECTORY, key
    );

    for (size_t i = 0; i < beneath.count; i++) {
        if (beneath.entries[i]->tracked) return true;
    }

    return false;
}

/**
 * Whether the profile passes through `rung`: whether it holds anything there,
 * or a directory it tracks beneath it
 *
 * The question each writer of the way asks of the base before it writes a rung
 * — the climbs from the disk, a restore from its commit — so the writers cannot
 * part over whether a rung is new to the profile; and the one a merge asks of
 * each side at a merge-base directory claim it lacks, whether the side removed
 * the claim or its prune took it. Two halves, each a footprint of what the profile
 * claims at or beneath the rung: what it holds there, by the namespace's own
 * question (profile_holds) — a subtree, which holds what stands beneath it, or
 * a directory claim, the profile's word on the rung — and, where the tree is
 * silent, a directory the profile tracks beneath it, the one claim no tree can
 * hold (an empty directory, or one whose every file is ignored). A rung the profile
 * passes through and claims nothing at is the user's way, kept as a claim is.
 *
 * A writer asks at a rung of a leaf the base holds or the commit puts: no blob
 * stands above the rung, so every tracked claim beneath it stands, and none is
 * asked whether a blob contradicts it. A merge's side may hold a blob above the
 * rung: a tracked claim the blob contradicts beneath it then answers that the
 * side passes through — a removal — and wherever the merged tree keeps that blob,
 * no directory claim beneath it stands (profile_merge_contradicted).
 *
 * Readers: profile_capture_ancestors and profile_derive_ancestors, at each rung
 * a directory stands at; profile_restore_ancestors, at each rung of the way it
 * brings back; and profile_merge_directory, at a merge-base directory claim a
 * side lacks.
 *
 * @param profile The profile asked, its sheet read: a draft's base, or a merge's
 *                side
 * @param rung The rung's name
 * @param out Whether the profile passes through it (written on success alone)
 * @return Error or NULL on success: the tree's, under "Cannot read '%s' in profile
 *         '%s'"
 */
static error_t profile_passes(profile_t *profile, const char *rung, bool *out) {
    /* What the profile holds at the rung: the tree's entry, or the sheet's claim
     * where the tree is silent */
    profile_held_t held;
    error_t err = profile_holds(profile, rung, &held);
    if (err) return err;

    /* Else beneath it: a directory the profile tracks there, which no tree holds */
    *out = held.kind != PROFILE_HELD_NOTHING || profile_tracked_beneath(profile->sheet, rung);

    return NULL;
}

/**
 * The disk's answer at one rung of a way: the place a directory stands at, the
 * claims another kind contradicts retired
 *
 * One component of a leaf's name, cut by a climb, standing where its own name
 * resolves under the table the leaf was named under — the profile the base's,
 * whose bindings place a custom/ rung. The rule is the sheet's own, read one
 * level up: an item exists iff it claims something, so a rung the disk answers
 * anything but "directory" for retires every derived claim that said otherwise
 * — the answer is about the place, which the profile can derive under more than
 * one name — and a rung it does not answer at all leaves the copy exactly as it
 * found it. A directory is the one answer a claim is taken from, and whether
 * one is taken is each climb's own (profile_capture_ancestors,
 * profile_derive_ancestors).
 *
 * Both climbs look at every rung, whatever the profile holds there: the retire
 * is no climb's choice, and the look is what lets a capture through the user's
 * link retire the rung (cmds/add.c add_refuse_ancestry, the consent it is). It
 * cannot fail: every answer the disk gives is one of the three.
 *
 * Readers: profile_capture_ancestors and profile_derive_ancestors, each rung of
 * each leaf they climb.
 *
 * @param draft The draft: the copy the rung's claims are read and retired in,
 *              and the arena the rung's place and its names are spelled into
 * @param mounts The table the rung's name resolves through
 * @param rung The rung's name
 * @param st The look at the place, where a directory stands there
 * @param retired Incremented for each name whose claim goes
 * @return The rung's place, where a directory stands there; NULL where the climb
 *         is done with the rung — a claim the profile tracks at it, no answer,
 *         or another kind, whose contradicted claims are retired
 */
static const char *profile_look_rung(
    profile_draft_t *draft, const mount_table_t *mounts, const char *rung,
    struct stat *st, size_t *retired
) {
    /* The directory claim at the rung, the one a derivation may touch, and only
     * a derived one: a tracked claim is the walk's own word about a directory
     * the profile tracks, and nothing derived refreshes or retires it. A FILE
     * item at the rung's key is the other kind's, and no business of this rule:
     * a blob at the rung would have left the leaf beneath it no room, so the
     * item is residue no blob backs, carried as every write carries it, and the
     * rung is decided beside it — the way's mode is the claim another machine
     * creates the rung by. The prune is no authority over it either: it takes
     * derivations, and this item is not one. */
    const metadata_item_t *held = metadata_find_item(
        draft->sheet, PATH_KIND_DIRECTORY, rung
    );
    if (held && held->tracked) return NULL;

    /* Where the rung stands is where its own name resolves. The climb carries
     * one string, not a pair that must agree: a resolve is a root's spelling
     * and a tail, and truncating the leaf's path would land the same bytes — at
     * the cost of a second string the caller must have got right, which is what
     * the cross-check this shape deleted used to assert. One producer places a
     * name (infra/mount.h mount_resolve); the cost is one table scan per rung
     * per leaf, bounded by the profile count. */
    const char *filesystem_path = mount_resolve(
        draft->arena, mounts, draft->base->name, rung
    );

    /* A rung this machine cannot place — an unbound custom/ name — has no answer
     * to give, the same silence as a rung nothing stands at. */
    if (!filesystem_path) return NULL;

    fs_occupant_t occupant = fs_lstat_occupant(filesystem_path, st);

    /* Nothing there, or nothing this host could see: the rung has no answer,
     * and no answer is not an answer of "no". A chain the world moved under between
     * the leaf's capture and this climb keeps the claims it already had. */
    if (occupant == FS_OCCUPANT_NONE || occupant == FS_OCCUPANT_UNKNOWN) {
        return NULL;
    }

    /* Something stands here that is not a directory, so the profile passes through
     * no directory at this place and every claim that says it does has just been
     * contradicted by the disk. The case that matters is a symlink the user put
     * there after the first capture: writing through it is what they asked for,
     * and retiring the claims is what lets dotta — the row leaves the view with
     * them, so after the commit nothing requires a directory there, and the record
     * that named the path is the next apply's to decide, as of every claim a
     * commit lets go (core/workspace.c workspace_analyze_orphans). A symlink
     * that was there at capture time never authored a claim to retire; this is
     * the same consent, one command later.
     *
     * The answer is about the place, and a profile can derive one place under
     * more than one name: one bound after its first captures derives a chain
     * under each of its roots that encloses the place (core/manifest.h
     * manifest_lookup_claim's note). So every derived claim the profile holds
     * here goes, under each name a root of its own strictly above the place gives
     * it — the rung's own among them, the place being where that name resolves.
     * A tracked one is the walk's word under any name, and stays; and a root's
     * own word is no rung's, the climbs deriving nothing there
     * (profile_capture_ancestors). */
    if (occupant != FS_OCCUPANT_DIRECTORY) {
        for (label_t label = LABEL_HOME; label < LABEL_COUNT; label++) {
            /* The profile's root of this label, where it has one here — a custom/
             * bound nowhere has none — and the place's tail past it, where that
             * root encloses the place */
            const mount_root_t *root = mount_root_of(mounts, draft->base->name, label);
            if (!root) continue;

            const char *tail = str_path_beneath(
                filesystem_path, root->filesystem_path, strlen(root->filesystem_path)
            );
            if (!tail) continue;

            /* The place's name under that root, retired where the profile derives it */
            const char *name = label_compose(draft->arena, label, tail);
            const metadata_item_t *claim = metadata_find_item(
                draft->sheet, PATH_KIND_DIRECTORY, name
            );
            if (claim && !claim->tracked) {
                metadata_remove_item(draft->sheet, PATH_KIND_DIRECTORY, name);
                (*retired)++;
            }
        }
        return NULL;
    }

    /* A directory stands, the look's own kind: the one answer a claim is taken
     * from, and whether one is the climb's to decide */
    return filesystem_path;
}

/**
 * Claim one rung off its look: the directory standing there, derived
 *
 * Derived throughout: this rule authors the way, never intent, the claim binding
 * only dotta's own creation of the path (core/deploy.c, the ancestors' pass).
 * And it cannot fail: a look the capture cannot claim, an owner this host cannot
 * name, is the silence of a rung the disk does not answer.
 *
 * Readers: profile_capture_ancestors, at each rung new to the profile, and
 * profile_derive_ancestors, at those and at each rung the run's paths select.
 *
 * @param draft The draft: the copy the claim is written in, and the arena its
 *              names are spelled into
 * @param rung The rung's name
 * @param st The look that found a directory at the rung's place
 * @param captured Incremented where the rung's claim moved
 */
static void profile_capture_rung(
    profile_draft_t *draft, const char *rung, const struct stat *st, size_t *captured
) {
    /* A directory stands, the look's own kind, so the capture's one answer short
     * of a claim is an owner or a group this host cannot name (core/metadata.h
     * metadata_capture_directory) — the same silence as a path it cannot see: a
     * claim the capture cannot make is lost and nothing else, so the rung keeps
     * what it had and dotta creates it as it would have before. Nothing is refused,
     * and nothing minted. */
    metadata_item_t item;
    if (metadata_capture_directory(rung, st, false, draft->arena, &item) !=
        METADATA_OWNERSHIP_RESOLVED) {
        return;
    }

    /* The claim written, and counted where it moved the sheet: a re-derivation
     * that found nothing new moves nothing (core/metadata.h metadata_write_item),
     * so nothing is counted and the commit's gate never fires on a chain that
     * has not moved */
    if (metadata_write_item(draft->sheet, &item)) (*captured)++;
}

error_t profile_capture_ancestors(
    profile_draft_t *draft, const mount_table_t *mounts, const char *storage_path,
    size_t *captured, size_t *retired
) {
    CHECK_NULL(draft);
    CHECK_NULL(mounts);
    CHECK_NULL(storage_path);
    CHECK_NULL(captured);
    CHECK_NULL(retired);

    /* One copy of the leaf's name, cut from the leaf at each separator of its
     * label's tail in turn, as a restore cuts its way: the word is excluded by
     * where the tail starts and the leaf by the first cut — arithmetic, not a
     * special case — so a path directly beneath a root climbs nowhere. Each rung
     * is decided alone, so a rung the climb is done with puts nothing back. The
     * copy is the draft's arena's, as each rung's place is; what keeps a rung,
     * the copy's item, copies it. */
    char *rung = arena_strdup(draft->arena, storage_path);

    for (;;) {
        char *cut = strrchr(label_tail(rung), '/');
        if (!cut) return NULL;
        *cut = '\0';

        struct stat st;
        if (!profile_look_rung(draft, mounts, rung, &st, retired)) continue;

        /* A directory, claimed only where the profile does not pass through the
         * rung yet: the capture that first passes through a rung authors its
         * word, and every capture after it leaves that word as it stands — a
         * claim, or the user's way where the first met none — whichever machine's
         * disk it meets */
        bool passes = false;
        error_t err = profile_passes(draft->base, rung, &passes);
        if (err) return err;
        if (passes) continue;

        profile_capture_rung(draft, rung, &st, captured);
    }
}

error_t profile_derive_ancestors(
    profile_draft_t *draft, const mount_table_t *mounts, const char *storage_path,
    const pathspec_t *path_filter, size_t *captured, size_t *retired
) {
    CHECK_NULL(draft);
    CHECK_NULL(mounts);
    CHECK_NULL(storage_path);
    CHECK_NULL(path_filter);
    CHECK_NULL(captured);
    CHECK_NULL(retired);

    /* The first capture's cut (profile_capture_ancestors) */
    char *rung = arena_strdup(draft->arena, storage_path);

    for (;;) {
        char *cut = strrchr(label_tail(rung), '/');
        if (!cut) return NULL;
        *cut = '\0';

        struct stat st;
        const char *place = profile_look_rung(draft, mounts, rung, &st, retired);
        if (!place) continue;

        /* A directory the run's paths select, its place and its name asked as a
         * directory's, claims its attributes whatever the profile held there:
         * naming is consent, and the remedy for a rung the world moved under. A
         * rung they do not select is the first capture's */
        if (!pathspec_matches(path_filter, place, rung, PATH_KIND_DIRECTORY)) {
            bool passes = false;
            error_t err = profile_passes(draft->base, rung, &passes);
            if (err) return err;
            if (passes) continue;
        }

        profile_capture_rung(draft, rung, &st, captured);
    }
}

/**
 * The way a restored file stood on at the commit it came from
 *
 * Each rung of `storage_path` — a separator of its label's tail, the word and
 * the leaf excluded, as the climbs cut them (profile_capture_ancestors) — paired
 * from the leaf with a rung of `from_storage_path`: both names place one path,
 * so their tails end alike, and the pairing ends where either runs out. Each
 * rung is decided alone, since the base may hold a rung by a sheet claim with
 * nothing above it. A rung the profile passes through is the base's word on that
 * directory, kept as it stands — the rule a capture keeps from the disk; at one
 * it does not, `from`'s directory claim at the pair is written, derived. No disk
 * read: the commit is the source.
 *
 * Asked after the put, of the base, which the restore edited at the leaf alone:
 * the put admitted, no blob stands at or above any rung, so every claim at a
 * rung stands, and a claim written there replaces none the base contradicts.
 *
 * Reader: profile_restore_file.
 *
 * @param draft The draft
 * @param from The profile at the commit
 * @param from_storage_path The commit's name for the file
 * @param storage_path The name the restore writes
 * @return Error or NULL on success: a subtree that will not load, in either tree
 */
static error_t profile_restore_ancestors(
    profile_draft_t *draft, profile_t *from, const char *from_storage_path,
    const char *storage_path
) {
    /* Each name copied once into the draft's arena, as a climb spells its rungs,
     * and cut from the leaf in step, a rung of each at every cut: a name is read
     * past its label's word alone (infra/label.h label_tail), so the word is
     * never a rung */
    char *rung = arena_strdup(draft->arena, storage_path);
    char *pair = arena_strdup(draft->arena, from_storage_path);

    for (;;) {
        /* The next rung of each name, at its last separator left; a name with
         * none left ends the pairing */
        char *rung_cut = strrchr(label_tail(rung), '/');
        char *pair_cut = strrchr(label_tail(pair), '/');
        if (!rung_cut || !pair_cut) return NULL;
        *rung_cut = '\0';
        *pair_cut = '\0';

        /* A rung the profile passes through — anything the base holds at it, a
         * directory it tracks beneath it — is the base's, by the question each
         * writer of the way asks there (profile_passes) */
        bool passes = false;
        error_t err = profile_passes(draft->base, rung, &passes);
        if (err) return err;
        if (passes) continue;

        /* The commit's claim at the pair, as its walk shows it — none where the
         * commit claimed none there — restored derived: the restore brings a
         * file's way, never a directory's tracking. A FILE item no blob backs
         * at the rung is the other kind's, and stays beside it */
        const profile_claim_t *claim = NULL;
        err = profile_find(
            from, PROFILE_READ_STRICT, PATH_KIND_DIRECTORY, pair, &claim
        );
        if (err) return err;
        if (!claim) continue;

        const metadata_item_t item = {
            .kind  = PATH_KIND_DIRECTORY,
            .key   = rung,
            .mode  = claim->mode,
            .owner = claim->owner,
            .group = claim->group,
        };
        metadata_write_item(draft->sheet, &item);
    }
}

error_t profile_restore_file(
    profile_draft_t *draft, const profile_claim_t *claim, profile_t *from,
    const char *from_storage_path
) {
    CHECK_NULL(draft);
    CHECK_NULL(claim);
    CHECK_NULL(from);
    CHECK_NULL(from_storage_path);

    /* The admission's two halves, each refusing before anything moves: the sheet's,
     * then the tree's, which the put asks of the index it writes — the entry at
     * its id, an object the ODB holds by the commit, so nothing is written here */
    error_t err = profile_refuse_beneath(draft, claim->storage_path);
    if (!err) {
        err = stage_put_blob(
            draft->stage, claim->storage_path, &claim->blob_oid,
            gitops_type_filemode(claim->type)
        );
    }

    /* Then the put rule at the name, and the way the commit stood the file on */
    if (!err) err = profile_convert(draft, claim->storage_path);
    if (!err) {
        err = profile_restore_ancestors(
            draft, from, from_storage_path, claim->storage_path
        );
    }
    if (err) return err;

    /* The claim at its own kind, the sheet's copy of it — or, where it claims
     * nothing, a link the commit records no ownership for, the retire of the
     * item standing at the name (core/metadata.h metadata_write_item) */
    const metadata_item_t item = {
        .kind      = PATH_KIND_FILE,
        .key       = claim->storage_path,
        .mode      = claim->mode,
        .owner     = claim->owner,
        .group     = claim->group,
        .encrypted = claim->encrypted,
    };
    metadata_write_item(draft->sheet, &item);

    return NULL;
}

error_t profile_put_machinery(
    profile_draft_t *draft, const char *name, const void *bytes, size_t size
) {
    CHECK_NULL(draft);
    CHECK_NULL(name);

    /* The put's contract, and no refusal of a user's: a name in the grammar is
     * a claim's, which this put would take past the admission and the put rule,
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
    return stage_put(draft->stage, name, bytes, size, GIT_FILEMODE_BLOB, NULL);
}

/**
 * A merge as it composes (profile_draft_merge): its draft, the profiles at the
 * merge base and at theirs beside the draft's base, which is ours; the run's
 * side; the claims composed so far; and the conflicts met, a list for the content
 * and one for each kind of claim, each list in name order
 *
 * Readers: profile_draft_merge, which makes it, and the statics it calls, from
 * profile_merge_note to profile_merge_conflicts.
 */
typedef struct {
    profile_draft_t *draft;            /* Its draft: the stage, the base — ours — and its arena */
    profile_t *merge_base;             /* The profile at the merge base */
    profile_t *theirs;                 /* The profile at theirs */
    profile_side_t side;               /* The run's side, PROFILE_SIDE_NONE where it named none */
    metadata_t *sheet;                 /* The claims composed so far, in the draft's arena */
    arena_t *arena;                    /* The caller's: every conflict, and the words that say it */
    ptr_array_t content_conflicts;     /* Names Git could not compose, nor any rule */
    ptr_array_t file_conflicts;        /* An axis of a file's claim both sides moved apart */
    ptr_array_t directory_conflicts;   /* An axis of a directory's claim, likewise */
} profile_merge_t;

/**
 * A claim's axis both sides moved apart, noted in its list: the name, the axis
 * and each side's claim — all of it copied into the caller's arena, since the
 * profiles a claim was read from go with the open and the words that say a conflict
 * outlive it
 *
 * Readers: profile_merge_file and profile_merge_directory, each axis apart.
 *
 * @param merge The merge
 * @param list The list the conflict is noted in
 * @param storage_path The name
 * @param axis The claim's axis both sides moved apart there
 * @param claim_ours Ours' claim, decoded
 * @param claim_theirs Theirs', likewise
 */
static void profile_merge_note(
    profile_merge_t *merge, ptr_array_t *list, const char *storage_path, profile_axis_t axis,
    const profile_claim_t *claim_ours, const profile_claim_t *claim_theirs
) {
    profile_conflict_t *conflict = arena_alloc(merge->arena, sizeof(*conflict));
    *conflict = (profile_conflict_t){
        .storage_path = arena_strdup(merge->arena, storage_path),
        .axis = axis,
    };

    /* Each side's claim as the merge read it, under the conflict's name, its
     * owner and group copied off the sheet they were read from */
    profile_claim_t *claims = arena_calloc(merge->arena, 2, sizeof(*claims));
    claims[0] = *claim_ours;
    claims[1] = *claim_theirs;
    for (size_t s = 0; s < 2; s++) {
        claims[s].storage_path = conflict->storage_path;
        claims[s].owner = arena_strdup(merge->arena, claims[s].owner);
        claims[s].group = arena_strdup(merge->arena, claims[s].group);
    }
    conflict->claim_ours = &claims[0];
    conflict->claim_theirs = &claims[1];

    ptr_array_push(list, conflict);
}

/**
 * The word an axis both sides moved apart keeps: the run's side's, none where
 * it named none
 *
 * Readers: profile_merge_file and profile_merge_directory, each axis apart.
 *
 * @param side The run's side
 * @param ours Ours' word on the axis
 * @param theirs Theirs'
 * @return The kept word, or NULL under PROFILE_SIDE_NONE
 */
static const metadata_item_t *profile_merge_kept(
    profile_side_t side, const metadata_item_t *ours, const metadata_item_t *theirs
) {
    switch (side) {
        case PROFILE_SIDE_NONE:   return NULL;
        case PROFILE_SIDE_OURS:   return ours;
        case PROFILE_SIDE_THEIRS: return theirs;
    }

    CHECK_ARG(false, "a side no enumerator names");
}

/**
 * Whether a name is a removal beside a change of the executable bit alone, `flip`
 * the side that changed the bit and `removal` the other
 *
 * The merge base a regular file there; `flip` the same blob under the other regular
 * filemode; `removal` no regular file — nothing, a directory or a link, the file
 * replaced by another kind — and no gitlink either, which a settle refuses, so
 * it stays the content conflict it is. A type change at one blob is no bit's: a
 * link holding the file's bytes changed the file, and never flips it.
 *
 * Reader: profile_merge_name, each side as the flip in turn.
 *
 * @param merge_base What the merge base's tree holds at the name
 * @param flip What one side's holds
 * @param removal What the other side's holds
 * @return true where the name is the removal, `removal`'s tree its settle
 */
static bool profile_merge_removed(
    const profile_held_t *merge_base, const profile_held_t *flip, const profile_held_t *removal
) {
    /* The merge base a regular file, and `flip` its blob under the other regular
     * filemode: the bit, changed alone */
    if (merge_base->kind != PROFILE_HELD_FILE || merge_base->filemode == GIT_FILEMODE_LINK ||
        flip->kind != PROFILE_HELD_FILE || flip->filemode == GIT_FILEMODE_LINK ||
        flip->filemode == merge_base->filemode || !git_oid_equal(&flip->oid, &merge_base->oid)) {
        return false;
    }

    /* And no regular file on the other side, nor a gitlink */
    return removal->kind == PROFILE_HELD_NOTHING || removal->kind == PROFILE_HELD_DIRECTORY ||
           (removal->kind == PROFILE_HELD_FILE && removal->filemode == GIT_FILEMODE_LINK);
}

/**
 * One name Git's merge left in conflict: composed by a rule, or noted as the
 * content conflict it is
 *
 * What each side's tree holds at the name decides (profile_entry), machinery's
 * names among them, which a tree answers alike. In order:
 *   - a removal beside a change of the executable bit alone is the removal, at
 *     any name (profile_merge_removed): the name settled from the side holding
 *     no regular file there;
 *   - the profile's ignore file holds its two sides' rules (sys/stage.h
 *     stage_unite); a union refused — a side holding nothing there, a version
 *     Git reads as binary — is the content conflict it is;
 *   - any other is a content conflict, noted beside what each side's tree holds
 *     at the name, and settled for the run's side once every rule is in
 *     (profile_merge_tree).
 *
 * Reader: profile_merge_tree, each name in name order.
 *
 * @param merge The merge
 * @param name A name Git's merge left in conflict
 * @return Error or NULL on success: a tree's, under "Cannot read '%s' in profile
 *         '%s'"; a settle's or a union's own
 */
static error_t profile_merge_name(profile_merge_t *merge, const char *name) {
    stage_t *stage = merge->draft->stage;

    /* What each side's tree holds at the name */
    profile_held_t entry_merge_base, entry_ours, entry_theirs;
    error_t err = profile_entry(merge->merge_base, name, &entry_merge_base);
    if (!err) err = profile_entry(merge->draft->base, name, &entry_ours);
    if (!err) err = profile_entry(merge->theirs, name, &entry_theirs);
    if (err) return err;

    /* A removal beside a change of the executable bit alone: the removal, settled
     * from the side holding no regular file there */
    if (profile_merge_removed(&entry_merge_base, &entry_ours, &entry_theirs)) {
        return stage_settle(stage, name, stage_theirs(stage));
    }
    if (profile_merge_removed(&entry_merge_base, &entry_theirs, &entry_ours)) {
        return stage_settle(stage, name, stage_tree(stage));
    }

    /* The profile's ignore file: both sides' rules, a set by its lines. A union
     * the stage refuses leaves the conflict standing, and is the content's */
    if (strcmp(name, IGNORE_FILE_NAME) == 0) {
        err = stage_unite(stage, name);
        if (error_code(err) != ERR_CONFLICT) return err;
    }

    /* Any other: the content, both sides' moves of it apart, noted beside what
     * each side's tree holds at the name — values, so the name is all the caller's
     * arena copies */
    profile_conflict_t *conflict = arena_alloc(merge->arena, sizeof(*conflict));
    *conflict = (profile_conflict_t){
        .storage_path = arena_strdup(merge->arena, name),
        .axis = PROFILE_AXIS_CONTENT,
        .entry_ours = entry_ours,
        .entry_theirs = entry_theirs,
    };
    ptr_array_push(&merge->content_conflicts, conflict);

    return NULL;
}

/**
 * A merge's tree: the sheet's own name, each name Git's merge could not compose,
 * and the run's side at each content conflict
 *
 * The sheet's own name holds the base's sheet, as every draft's index does: Git's
 * merge of it — a clean take of theirs' bytes, or its text merge — is no document
 * dotta reads, and the commit's save stands as written, the composed claims put
 * there where they are no longer the base's and its bytes kept otherwise. Then
 * each name Git could not compose, in name order, by a rule or as a content
 * conflict (profile_merge_name); and once every rule is in, the side's bytes at
 * each content conflict — its entries at and beneath the name, from its tree —
 * so a settle above a name a rule composed takes the side's whole name, and every
 * claim composed after reads the tree the commit will record.
 *
 * Reader: profile_draft_merge, the tree before the claims.
 *
 * @param merge The merge
 * @return Error or NULL on success: a settle's, the conflicts' read, or a name's
 */
static error_t profile_merge_tree(profile_merge_t *merge) {
    stage_t *stage = merge->draft->stage;

    /* The sheet's own name, the base's */
    error_t err = stage_settle(stage, METADATA_FILE_PATH, stage_tree(stage));

    /* Each name Git could not compose: a rule's, or a content conflict */
    string_array_t names = { 0 };
    if (!err) err = stage_conflicts(stage, merge->arena, &names);
    for (size_t i = 0; !err && i < names.count; i++) {
        err = profile_merge_name(merge, names.entries[i]);
    }

    /* The side's bytes at each content conflict, from its tree — none where the
     * run named none: the conflicts refuse the open */
    if (err || merge->side == PROFILE_SIDE_NONE) return err;
    const git_tree *tree = merge->side == PROFILE_SIDE_OURS
        ? stage_tree(stage) : stage_theirs(stage);
    for (size_t i = 0; !err && i < merge->content_conflicts.count; i++) {
        const profile_conflict_t *conflict = merge->content_conflicts.entries[i];
        err = stage_settle(stage, conflict->storage_path, tree);
    }

    return err;
}

/**
 * A side's word on a file's claim, grain by grain: its claim's — the claim of
 * none where it holds the blob and no item, absence a value — on each grain its
 * node at the name carries, and `silence`'s on each it does not
 *
 * Any blob carries the ownership, the owner and group as a pair; a regular file
 * the mode besides, and the stamp where its bytes are `bytes`, the blob the claim
 * stands with — a stamp speaks for its own bytes alone. Nothing, a directory or
 * a gitlink says nothing of any grain, and a link nothing of the mode or the stamp.
 *
 * Reader: profile_merge_file — the merge base's word over the claim of none,
 * its stamp over its own bytes, and each side's over the merge base's, its stamp
 * over the merged blob's.
 *
 * @param entry What the side's tree holds at the name
 * @param claim The side's FILE item there, or NULL
 * @param bytes The blob whose bytes the side's stamp must be to speak
 * @param silence The word on each grain the node does not carry
 * @return The word: a claim of the name, by value
 */
static metadata_item_t profile_merge_word(
    const profile_held_t *entry, const metadata_item_t *claim, const git_oid *bytes,
    const metadata_item_t *silence
) {
    metadata_item_t word = *silence;
    if (entry->kind != PROFILE_HELD_FILE) return word;

    word.owner = claim ? claim->owner : NULL;
    word.group = claim ? claim->group : NULL;
    if (entry->filemode == GIT_FILEMODE_LINK) return word;

    word.mode = claim ? claim->mode : MODE_UNCLAIMED;
    if (git_oid_equal(&entry->oid, bytes)) word.encrypted = claim && claim->encrypted;

    return word;
}

/**
 * A file's claim a side moved: composed from the three sides' words, each read
 * over its own node, and standing where the merged tree holds a blob at its name
 *
 * Each side's word (profile_merge_word): the merge base's over the claim of none,
 * each side's over the merge base's, which a side silent on a grain says. Each
 * axis by its three-way (core/metadata.h metadata_merge_axis); one both sides
 * moved apart is a conflict — both hold a blob there, a silent side moving nothing
 * — noted beside each side's claim decoded over its own blob, and keeps the run's
 * side's word, none where it named none. The axes read the three sides alone,
 * so the conflicts at a name are the same whatever the merged tree holds there:
 * those at a content conflict's name are listed under no side as under either.
 *
 * Then the merged tree, read for what stands: no blob at the name — nothing, a
 * subtree, a conflict's stages, a gitlink — or an axis left without a value,
 * and nothing is written, the claim going with its name or the open refused. A
 * blob stands with the claim, its axes that blob's type's — a link's ownership
 * alone — and the stamp by the flags' rule over the three sides' words, theirs'
 * where ours' is the merge base's, else ours': the stamp of the side whose bytes
 * stand, and the merge base's where Git composed bytes neither side holds.
 *
 * Reader: profile_merge_claims, each file's claim the three sheets do not hold
 * alike.
 *
 * @param merge The merge
 * @param key The claim's name
 * @param merge_base The merge base's FILE item at the name, or NULL
 * @param ours Ours', or NULL
 * @param theirs Theirs', or NULL
 * @return Error or NULL on success: a tree's, under "Cannot read '%s' in profile
 *         '%s'"
 */
static error_t profile_merge_file(
    profile_merge_t *merge, const char *key, const metadata_item_t *merge_base,
    const metadata_item_t *ours, const metadata_item_t *theirs
) {
    /* What each side's tree holds at the name, and the merged tree */
    profile_held_t entry_merge_base, entry_ours, entry_theirs;
    error_t err = profile_entry(merge->merge_base, key, &entry_merge_base);
    if (!err) err = profile_entry(merge->draft->base, key, &entry_ours);
    if (!err) err = profile_entry(merge->theirs, key, &entry_theirs);
    if (err) return err;
    const stage_held_t held = stage_holds(merge->draft->stage, key);

    /* Each side's word: the merge base's over the claim of none, a side's over
     * the merge base's */
    const metadata_item_t none = { .kind = PATH_KIND_FILE, .key = key, .mode = MODE_UNCLAIMED };
    const metadata_item_t word_merge_base = profile_merge_word(
        &entry_merge_base, merge_base, &entry_merge_base.oid, &none
    );
    const metadata_item_t word_ours = profile_merge_word(
        &entry_ours, ours, &held.oid, &word_merge_base
    );
    const metadata_item_t word_theirs = profile_merge_word(
        &entry_theirs, theirs, &held.oid, &word_merge_base
    );

    /* Each axis by its three-way; one both sides moved apart a conflict, noted
     * beside each side's claim, and the run's side's word kept */
    const metadata_item_t *mode = metadata_merge_axis(
        METADATA_AXIS_MODE, &word_merge_base, &word_ours, &word_theirs
    );
    const metadata_item_t *ownership = metadata_merge_axis(
        METADATA_AXIS_OWNERSHIP, &word_merge_base, &word_ours, &word_theirs
    );
    if (!mode || !ownership) {
        const profile_claim_t claim_ours = profile_decode_blob(
            key, &entry_ours.oid, entry_ours.filemode, ours
        );
        const profile_claim_t claim_theirs = profile_decode_blob(
            key, &entry_theirs.oid, entry_theirs.filemode, theirs
        );
        if (!mode) {
            profile_merge_note(
                merge, &merge->file_conflicts, key, PROFILE_AXIS_MODE, &claim_ours,
                &claim_theirs
            );
            mode = profile_merge_kept(merge->side, &word_ours, &word_theirs);
        }
        if (!ownership) {
            profile_merge_note(
                merge, &merge->file_conflicts, key, PROFILE_AXIS_OWNERSHIP, &claim_ours,
                &claim_theirs
            );
            ownership = profile_merge_kept(merge->side, &word_ours, &word_theirs);
        }
    }

    /* The claim stands with a blob at its name, every axis valued */
    if (held.type != GIT_OBJECT_BLOB || !mode || !ownership) return NULL;

    /* Its axes the blob's type's, a link claiming no mode and no stamp; the stamp
     * the flags' rule over the three sides' words */
    const bool stamp = word_ours.encrypted == word_merge_base.encrypted
        ? word_theirs.encrypted : word_ours.encrypted;
    const metadata_item_t claim = {
        .kind      = PATH_KIND_FILE,
        .key       = key,
        .mode      = held.filemode == GIT_FILEMODE_LINK ? MODE_UNCLAIMED : mode->mode,
        .owner     = ownership->owner,
        .group     = ownership->group,
        .encrypted = held.filemode != GIT_FILEMODE_LINK && stamp,
    };
    metadata_write_item(merge->sheet, &claim);

    return NULL;
}

/**
 * Whether the tree the merge's commit will record leaves a directory claim at
 * `key` no room: a blob at its name, or at a rung above it
 *
 * The decode's rule (profile_blob_above), asked of the merge's stage, whose tree
 * is not written yet: each rung top-down, the label's word among them, then the
 * name, each by what the stage holds there (sys/stage.h stage_holds). A blob
 * answers. A gitlink places nothing on disk and contradicts nothing, and nothing
 * stands beneath one; nothing at a rung, or a subtree, holds no blob there either.
 * The rungs are spelled in the draft's arena, as a climb spells its own.
 *
 * Reader: profile_merge_directory, each claim it composes.
 *
 * @param merge The merge
 * @param key The claim's name
 * @return true where a blob stands at the name or above it
 */
static bool profile_merge_contradicted(const profile_merge_t *merge, const char *key) {
    char *rung = arena_strdup(merge->draft->arena, key);

    for (char *slash = strchr(rung, '/');; slash = strchr(slash + 1, '/')) {
        if (slash) *slash = '\0';
        if (stage_holds(merge->draft->stage, rung).type == GIT_OBJECT_BLOB) return true;
        if (!slash) return false;
        *slash = '/';
    }
}

/**
 * A directory's claim a side moved: composed from the three sides' claims, a
 * side's absence read through its own tree, and standing where the merged tree
 * leaves its name a directory
 *
 * The merge base's claim, derived — its attributes, none where it makes no claim,
 * and no class — is the word of a side that says nothing of a claim's attributes:
 * one whose prune took the merge base's claim, and a derived side beside a tracked
 * claim; and the attributes' merge base. A side lacking the merge base's claim
 * is read through its own tree (profile_passes): passing through the name — a
 * blob put there, the climb's retire at another kind — it removed it; passing
 * through none, its prune took it once nothing tracked stood beneath it, no word
 * on the attributes, the derived claim its word.
 *
 * Then the claim: where a side holds none, an addition stands — the merge base
 * held none — and otherwise the removal, beside the other side's move of it or
 * not, the claim's move needing its name. Two derivations, neither the merge
 * base's claim derived, are ours', the merging machine's: a derivation binds
 * dotta's own creation of its path alone, and each side's is one look's whole.
 * Otherwise the claim is composed: the class by the flags' rule — theirs' where
 * ours moved nothing on it, else ours' — a derived side saying nothing of a tracked
 * claim's attributes, and each attribute by its three-way (core/metadata.h
 * metadata_merge_axis), one both sides moved apart a conflict, noted beside each
 * side's claim, keeping the run's side's word, none where it named none.
 *
 * The claim stands where the merged tree holds no blob at its name or above it
 * (profile_merge_contradicted), the decode's rule; a derivation, besides, where
 * something stands beneath it, which the commit's prune asks as every commit's
 * does. Where it stands nowhere, or an attribute is left without a value, nothing
 * is written.
 *
 * Reader: profile_merge_claims, each directory's claim the three sheets do not
 * hold alike.
 *
 * @param merge The merge
 * @param key The claim's name
 * @param merge_base The merge base's DIRECTORY item at the name, or NULL
 * @param ours Ours', or NULL
 * @param theirs Theirs', or NULL
 * @return Error or NULL on success: a side's tree's, under "Cannot read '%s' in
 *         profile '%s'"
 */
static error_t profile_merge_directory(
    profile_merge_t *merge, const char *key, const metadata_item_t *merge_base,
    const metadata_item_t *ours, const metadata_item_t *theirs
) {
    /* The merge base's claim, derived */
    const metadata_item_t derived = {
        .kind  = PATH_KIND_DIRECTORY,
        .key   = key,
        .mode  = merge_base ? merge_base->mode : MODE_UNCLAIMED,
        .owner = merge_base ? merge_base->owner : NULL,
        .group = merge_base ? merge_base->group : NULL,
    };

    /* A side lacking the merge base's claim: removed where it passes through
     * the name, its prune's where it passes through none */
    if (merge_base && !ours) {
        bool passes = false;
        error_t err = profile_passes(merge->draft->base, key, &passes);
        if (err) return err;
        if (!passes) ours = &derived;
    }
    if (merge_base && !theirs) {
        bool passes = false;
        error_t err = profile_passes(merge->theirs, key, &passes);
        if (err) return err;
        if (!passes) theirs = &derived;
    }

    metadata_item_t composed;
    const metadata_item_t *claim = NULL;
    if (!ours || !theirs) {
        /* A side holding none: the other's addition where the merge base held
         * none, and the removal otherwise, beside a move of it or not */
        claim = merge_base ? NULL : ours ? ours : theirs;
    } else if (!ours->tracked && !theirs->tracked &&
        !metadata_same_claim(&derived, ours) && !metadata_same_claim(&derived, theirs)) {
        /* Two derivations, each moved off the merge base's: ours', each side's
         * one look's whole */
        claim = ours;
    } else {
        /* Composed: the class by the flags' rule, and a derived side's word on
         * a tracked claim's attributes the merge base's */
        const bool tracked = ours->tracked == (merge_base && merge_base->tracked)
            ? theirs->tracked : ours->tracked;
        const metadata_item_t *word_ours = tracked && !ours->tracked ? &derived : ours;
        const metadata_item_t *word_theirs = tracked && !theirs->tracked ? &derived : theirs;

        /* Each attribute by its three-way; one both sides moved apart a conflict,
         * noted beside each side's claim, and the run's side's word kept */
        const metadata_item_t *mode = metadata_merge_axis(
            METADATA_AXIS_MODE, &derived, word_ours, word_theirs
        );
        const metadata_item_t *ownership = metadata_merge_axis(
            METADATA_AXIS_OWNERSHIP, &derived, word_ours, word_theirs
        );
        if (!mode || !ownership) {
            const profile_claim_t claim_ours = profile_decode_directory(ours);
            const profile_claim_t claim_theirs = profile_decode_directory(theirs);
            if (!mode) {
                profile_merge_note(
                    merge, &merge->directory_conflicts, key, PROFILE_AXIS_MODE,
                    &claim_ours, &claim_theirs
                );
                mode = profile_merge_kept(merge->side, word_ours, word_theirs);
            }
            if (!ownership) {
                profile_merge_note(
                    merge, &merge->directory_conflicts, key, PROFILE_AXIS_OWNERSHIP,
                    &claim_ours, &claim_theirs
                );
                ownership = profile_merge_kept(merge->side, word_ours, word_theirs);
            }
        }

        if (mode && ownership) {
            composed = (metadata_item_t){
                .kind = PATH_KIND_DIRECTORY,
                .key = key,
                .mode = mode->mode,
                .owner = ownership->owner,
                .group = ownership->group,
                .tracked = tracked,
            };
            claim = &composed;
        }
    }

    /* The claim stands where the merged tree leaves its name a directory */
    if (!claim || profile_merge_contradicted(merge, key)) return NULL;
    metadata_write_item(merge->sheet, claim);

    return NULL;
}

/**
 * One kind's claims of a merge: the three sheets' read in step, each claim composed
 * at its key and written past the last
 *
 * Each sheet's claims of the kind in key order (core/metadata.h metadata_items),
 * and at each key the three sheets' claims there, or none. A claim the three
 * hold alike, as each sheet holds it — never a side's word read off its tree —
 * is no side's move since the merge base: carried as it stands, residue and a
 * contradiction among it, as every write carries what it does not aim at. One a
 * side moved is the kind's to compose (profile_merge_file,
 * profile_merge_directory).
 *
 * Reader: profile_draft_merge, the files' claims then the directories'.
 *
 * @param merge The merge
 * @param kind Which kind's claims
 * @return Error or NULL on success: a claim's composition's, as it came
 */
static error_t profile_merge_claims(profile_merge_t *merge, path_kind_t kind) {
    const metadata_items_t in_merge_base = metadata_items(merge->merge_base->sheet, kind);
    const metadata_items_t in_ours = metadata_items(merge->draft->base->sheet, kind);
    const metadata_items_t in_theirs = metadata_items(merge->theirs->sheet, kind);

    for (size_t b = 0, o = 0, t = 0;;) {
        /* The byte-least key the three sheets hold next, read where it falls: a
         * claim stands where it was written, so stepping past one leaves its
         * key standing */
        const char *key = b < in_merge_base.count ? in_merge_base.entries[b]->key : NULL;
        if (o < in_ours.count && (!key || strcmp(in_ours.entries[o]->key, key) < 0)) {
            key = in_ours.entries[o]->key;
        }
        if (t < in_theirs.count && (!key || strcmp(in_theirs.entries[t]->key, key) < 0)) {
            key = in_theirs.entries[t]->key;
        }
        if (!key) return NULL;

        /* Each sheet's claim at the key, or none, each stepped past it */
        const metadata_item_t *merge_base = NULL;
        if (b < in_merge_base.count && strcmp(in_merge_base.entries[b]->key, key) == 0) {
            merge_base = in_merge_base.entries[b++];
        }
        const metadata_item_t *ours = NULL;
        if (o < in_ours.count && strcmp(in_ours.entries[o]->key, key) == 0) {
            ours = in_ours.entries[o++];
        }
        const metadata_item_t *theirs = NULL;
        if (t < in_theirs.count && strcmp(in_theirs.entries[t]->key, key) == 0) {
            theirs = in_theirs.entries[t++];
        }

        /* The three alike: carried as it stands */
        if (metadata_same_claim(merge_base, ours) && metadata_same_claim(merge_base, theirs)) {
            metadata_write_item(merge->sheet, merge_base);
            continue;
        }

        /* A side moved it: composed by its kind */
        error_t err = kind == PATH_KIND_FILE
            ? profile_merge_file(merge, key, merge_base, ours, theirs)
            : profile_merge_directory(merge, key, merge_base, ours, theirs);
        if (err) return err;
    }
}

/**
 * The conflicts a merge met, in name order, one list in the caller's arena
 *
 * Its three lists, each in name order — the content's, a file's claims', a
 * directory's — merged as profile_changes merges its three lists, nothing sorted:
 * at one name the earlier list's first, and in a list its order, a claim's mode
 * before its ownership.
 *
 * Reader: profile_draft_merge, the conflicts it answers.
 *
 * @param merge The merge, every conflict noted
 * @return The conflicts, by value
 */
static profile_conflicts_t profile_merge_conflicts(const profile_merge_t *merge) {
    const ptr_array_t *const lists[] = {
        &merge->content_conflicts,
        &merge->file_conflicts,
        &merge->directory_conflicts,
    };
    size_t next[] = { 0, 0, 0 };
    const size_t count = lists[0]->count + lists[1]->count + lists[2]->count;
    profile_conflict_t *entries = arena_calloc(merge->arena, count, sizeof(*entries));

    for (size_t n = 0; n < count; n++) {
        /* The byte-least name a list holds next, the earlier list's where two
         * hold one name */
        size_t from = 0;
        const profile_conflict_t *least = NULL;
        for (size_t k = 0; k < sizeof(lists) / sizeof(lists[0]); k++) {
            if (next[k] == lists[k]->count) continue;
            const profile_conflict_t *conflict = lists[k]->entries[next[k]];
            if (!least || strcmp(conflict->storage_path, least->storage_path) < 0) {
                least = conflict;
                from = k;
            }
        }

        entries[n] = *least;
        next[from]++;
    }

    return (profile_conflicts_t){ .entries = entries, .count = count };
}

error_t profile_draft_merge(
    git_repository *repo, const char *name, const git_oid *theirs, profile_side_t side,
    arena_t *arena, profile_conflicts_t *out_conflicts, profile_draft_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(theirs);
    CHECK_NULL(arena);
    CHECK_NULL(out_conflicts);
    CHECK_NULL(out);

    *out_conflicts = (profile_conflicts_t){ 0 };
    *out = NULL;

    /* The branch the profile is built on, by Git's branch rule (sys/gitops.h
     * gitops_branch_refname); its stage over the merge with `theirs`, refused
     * in the stage's words where the branch does not stand (sys/stage.h
     * stage_merge); and the draft over it, its base ours */
    char refname[DOTTA_REFNAME_MAX];
    stage_t *stage = NULL;
    profile_draft_t *draft = NULL;
    error_t err = gitops_branch_refname(refname, sizeof(refname), name);
    if (!err) err = stage_merge(repo, refname, theirs, &stage);
    if (!err) err = profile_draft_seed(name, stage, &draft);
    if (err) return err;

    /* The merge as it composes, into a sheet of the draft's own: the profiles
     * at the merge base and at theirs beside the base, and a list of conflicts
     * for the content and for each kind of claim */
    profile_merge_t merge = {
        .draft      = draft,
        .merge_base = profile_open(name, stage_merge_base(stage)),
        .theirs     = profile_open(name, stage_theirs(stage)),
        .side       = side,
        .sheet      = metadata_create(draft->arena),
        .arena      = arena,
    };
    ptr_array_init(&merge.content_conflicts, arena, 0);
    ptr_array_init(&merge.file_conflicts, arena, 0);
    ptr_array_init(&merge.directory_conflicts, arena, 0);

    /* Every sheet read strictly: ours' by the seed, in the loader's words; theirs'
     * and the merge base's said by theirs' commit, seven characters as every
     * screen spells a commit, over the loader's words, as revert says its target's
     * (cmds/revert.c cmd_revert) */
    char commit[8];
    git_oid_tostr(commit, sizeof(commit), theirs);
    err = profile_load_sheet(merge.theirs);
    if (err) {
        err = error_wrap(
            err, "Failed to load metadata from commit %s, merged in", commit
        );
    }
    if (!err) {
        err = profile_load_sheet(merge.merge_base);
        if (err) {
            err = error_wrap(
                err, "Failed to load metadata from the merge base with commit %s", commit
            );
        }
    }

    /* The tree first, then the claims over it, one pass a kind */
    if (!err) err = profile_merge_tree(&merge);
    if (!err) err = profile_merge_claims(&merge, PATH_KIND_FILE);
    if (!err) err = profile_merge_claims(&merge, PATH_KIND_DIRECTORY);

    /* The two profiles go, before the stage whose trees they borrow */
    profile_free(merge.theirs);
    profile_free(merge.merge_base);
    if (err) {
        profile_draft_free(draft);
        return err;
    }

    /* The conflicts, settled or refusing; with no side to settle them, the refusal,
     * and no draft */
    *out_conflicts = profile_merge_conflicts(&merge);
    if (out_conflicts->count > 0 && side == PROFILE_SIDE_NONE) {
        profile_draft_free(draft);
        return error_create(
            ERR_CONFLICT, "Merging profile '%s' met %zu conflict%s", name,
            out_conflicts->count, out_conflicts->count == 1 ? "" : "s"
        );
    }

    /* The draft, its sheet the claims composed */
    draft->sheet = merge.sheet;
    *out = draft;
    return NULL;
}

error_t profile_changed(const profile_draft_t *draft, bool *out) {
    CHECK_NULL(draft);
    CHECK_NULL(out);

    /* Each document against the one the draft opened, by its owner: the sheet
     * claim by claim, which reads nothing; then the tree, entry by entry */
    if (!metadata_same(draft->sheet, draft->base->sheet)) {
        *out = true;
        return NULL;
    }

    return stage_changed(draft->stage, out);
}

error_t profile_changes(
    const profile_draft_t *draft, arena_t *arena, commit_changes_t *out
) {
    CHECK_NULL(draft);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* What each document says moved, each list in byte order: the tree's entries
     * (sys/stage.h stage_changes), and the sheet's keys, one list a kind
     * (core/metadata.h metadata_changes) */
    stage_changes_t tree;
    error_t err = stage_changes(draft->stage, arena, &tree);
    if (err) return err;
    const string_array_t files = metadata_changes(
        arena, draft->base->sheet, draft->sheet, PATH_KIND_FILE
    );
    const string_array_t dirs = metadata_changes(
        arena, draft->base->sheet, draft->sheet, PATH_KIND_DIRECTORY
    );

    commit_changes_t changes;
    string_array_init(&changes.added, arena, 0);
    string_array_init(&changes.updated, arena, 0);
    string_array_init(&changes.removed, arena, 0);

    for (size_t e = 0, f = 0, d = 0;;) {
        /* The byte-least name the three lists hold next, read where it falls,
         * so each name comes once and nothing is sorted: the list's own string,
         * in the arena, which stepping past leaves standing */
        const char *name = e < tree.count ? tree.entries[e].path : NULL;
        if (f < files.count && (!name || strcmp(files.entries[f], name) < 0)) {
            name = files.entries[f];
        }
        if (d < dirs.count && (!name || strcmp(dirs.entries[d], name) < 0)) {
            name = dirs.entries[d];
        }
        if (!name) break;

        /* What moved at the name — the tree's entry, the FILE item, the directory
         * item — each list stepped past it where it holds it */
        const stage_change_t *entry = NULL;
        if (e < tree.count && strcmp(tree.entries[e].path, name) == 0) {
            entry = &tree.entries[e++];
        }
        const bool file_moved = f < files.count && strcmp(files.entries[f], name) == 0;
        if (file_moved) f++;
        const bool dir_moved = d < dirs.count && strcmp(dirs.entries[d], name) == 0;
        if (dir_moved) d++;

        /* dotta's own files claim nothing (infra/label.h label_prefixes) */
        if (!label_prefixes(name)) continue;

        /* The tracked claim at the name on each side, as each sheet holds it,
         * and whether it moved: a derived claim's move is the way's, never named,
         * so a name where only the way moved is passed by before the tree is
         * asked */
        const metadata_item_t *dir_before = metadata_find_item(
            draft->base->sheet, PATH_KIND_DIRECTORY, name
        );
        const metadata_item_t *dir_after = metadata_find_item(
            draft->sheet, PATH_KIND_DIRECTORY, name
        );
        const bool tracked_before = dir_before && dir_before->tracked;
        const bool tracked_after = dir_after && dir_after->tracked;
        const bool tracked_moved = dir_moved && (tracked_before || tracked_after);
        if (!entry && !file_moved && !tracked_moved) continue;

        /* The blob at the name on each side: the entry's two sides where the
         * tree moved it, a blob of any mode as the walk reads one (profile_step);
         * else the base's, which the commit holds there as it stands
         * (profile_entry) */
        bool blob_before;
        bool blob_after;
        if (entry) {
            blob_before = entry->before == GIT_OBJECT_BLOB;
            blob_after = entry->after == GIT_OBJECT_BLOB;
        } else {
            profile_held_t held;
            err = profile_entry(draft->base, name, &held);
            if (err) return err;
            blob_before = held.kind == PROFILE_HELD_FILE;
            blob_after = blob_before;
        }

        /* A move of what claims nothing — a FILE item no blob backs, a gitlink
         * — is no explicit claim's */
        if (!tracked_moved && !blob_before && !blob_after) continue;

        /* The name, under its change: the base claims nothing explicit there,
         * or the commit claims nothing, or both claim another thing */
        if (!blob_before && !tracked_before) {
            string_array_push(&changes.added, name);
        } else if (!blob_after && !tracked_after) {
            string_array_push(&changes.removed, name);
        } else {
            string_array_push(&changes.updated, name);
        }
    }

    *out = changes;
    return NULL;
}

/**
 * Prune the derivations nothing stands beneath
 *
 * The ancestors' last edit (profile_draft_t): the climbs and the way author a
 * derived claim at a rung because something beneath it stands, a directory claim's
 * removal leaves one where the claim stood, and this removes one the moment nothing
 * does. A tracked claim is not this pass's subject at all — the walk's own word
 * stands with nothing beneath it and at any attributes, and only a verb takes
 * it (profile_remove, core/metadata.h) — so the pass reads one field and asks
 * one question of what is left:
 *
 *   Is anything tracked beneath it? The profile's tracked set is the tree's paths
 *   and the copy's own tracked claims together. The tree is the sole authority
 *   for every path it can hold — deliberately not the sheet's items, which are
 *   sparse by design (a symlink carries an item only where its owner is one absence
 *   would misstate), so a directory whose only tracked content is an item-less
 *   symlink has the tree's entry beneath it and survives. What no tree can hold
 *   is an empty directory, and only a tracked claim names one — a derivation
 *   keeps nothing standing, since it survives solely by what stands beneath it
 *   and would otherwise hold a doomed chain alive one command per rung.
 *
 * What stands beneath is asked of the tree the commit will record, past every
 * edit (sys/stage.h stage_holds_beneath), so the prune sees the commit's exact
 * tracked set and lands in the same commit as the removals that left a derivation
 * nothing beneath it. Such a derivation has no role in any downstream pipeline:
 * the view would claim it as an [ancestor] row over an emptied subtree, and
 * divergence detection has nothing to compare against — typically the tail of
 * an ancestry whose leaf has just gone (`dotta add ~/dir/f.conf`, then `dotta
 * remove` of that file). One forward pass decides each derivation where it meets
 * it and removes it there: a decision reads the tree and the tracked claims alone,
 * and the prune moves neither, so a removal changes no later decision.
 *
 * The count is of the paths the commit lets go that the writer did not name: a
 * claim the base tracked is derived here only where a writer's removal took its
 * tracking, and that writer names it, so a removal reports its claim once whatever
 * order it took the claims beneath in.
 *
 * Reader: profile_commit, past its gate.
 *
 * @param draft The draft
 * @param out_pruned Counts each derivation pruned but a claim the base tracked;
 *                   NULL where the writer counts none
 * @return Error or NULL on success: a failed look at the tree, which must not prune
 */
static error_t profile_prune_ancestors(profile_draft_t *draft, size_t *out_pruned) {
    metadata_items_t directories = metadata_items(draft->sheet, PATH_KIND_DIRECTORY);
    for (size_t d = 0; d < directories.count;) {
        const metadata_item_t *dir = directories.entries[d];

        /* The subject: a derivation, which exists because something beneath it
         * does. A tracked claim is the walk's own word that the profile tracks
         * the directory — it stands with nothing beneath it and at any attributes,
         * and it leaves the sheet where a verb takes it, never by inference
         * (core/metadata.h). The field the climbs' look reads to leave a standing
         * claim alone (profile_look_rung), asked here for the same reason. */
        if (dir->tracked) {
            d++;
            continue;
        }

        /* Half of what stands beneath: any path under the directory that a tree
         * can hold. The sheet's items are not the universe there — a symlink
         * tracked without elevation carries no item, yet still stands beneath
         * its parent — so the tree the commit will record is the authority; a
         * failed look must not prune. */
        bool beneath = false;
        error_t err = stage_holds_beneath(draft->stage, dir->key, &beneath);
        if (err) return err;

        /* And the other half: the one path a tree cannot hold. With either beneath
         * it, the derivation stands, and the cursor moves past it. */
        if (beneath || profile_tracked_beneath(draft->sheet, dir->key)) {
            d++;
            continue;
        }

        /* Nothing stands beneath it: counted where the writer counts — but a
         * claim the base tracked, whose tracking a writer's removal took
         * (profile_remove), and which that writer names itself; then the derivation
         * goes, and the slice is read again, the removal having moved every entry
         * past the cursor down one */
        const metadata_item_t *was = metadata_find_item(
            draft->base->sheet, PATH_KIND_DIRECTORY, dir->key
        );
        if (out_pruned && !(was && was->tracked)) (*out_pruned)++;
        metadata_remove_item(draft->sheet, PATH_KIND_DIRECTORY, dir->key);
        directories = metadata_items(draft->sheet, PATH_KIND_DIRECTORY);
    }

    return NULL;
}

error_t profile_commit(
    profile_draft_t *draft, const commit_words_t *words, git_oid *out_commit, size_t *out_pruned
) {
    CHECK_NULL(draft);
    CHECK_NULL(words);

    /* No commit until the tree write answers one, and nothing pruned until the
     * prune counts it: a return before either says so */
    if (out_commit) *out_commit = (git_oid) GIT_OID_SHA1_ZERO;
    if (out_pruned) *out_pruned = 0;

    /* Nothing an edit moved: nothing prunes, nothing is saved, no message is
     * rendered and nothing commits — imported redundancy rides a commit and never
     * drives one */
    bool changed = false;
    error_t err = profile_changed(draft, &changed);
    if (err || !changed) return err;

    /* The prune, against the tree the commit will record, the removed file claims
     * gone from it (the judge's own contract, profile_prune_ancestors): removing
     * a file may leave the derived claim above it with nothing tracked beneath,
     * and removing a directory claim leaves the derivation it was. The tree answers
     * that for every path it can hold — never the sheet's items, which omit
     * unelevated symlinks — and the copy's own tracked claims answer it for the
     * one path it cannot, an empty directory. What it takes is counted for a
     * writer that asks. */
    err = profile_prune_ancestors(draft, out_pruned);
    if (err) return err;

    /* The sheet, saved only where its claims are no longer the base's: a commit
     * whose edits took no item and pruned none keeps the sheet's bytes as they
     * stand, a hand's spelling included, as the stage keeps a tree no edit moved
     * (core/metadata.h metadata_same) */
    err = metadata_same(draft->sheet, draft->base->sheet)
        ? NULL : metadata_save_to_stage(draft->stage, draft->sheet);
    if (err) return err;

    /* What the commit changes of the profile's explicit claims, asked with every
     * edit, the prune and the save in — neither of which moves one — and named
     * in the message the writer's words render, never in the writer's own lists */
    commit_changes_t changes;
    err = profile_changes(draft, draft->arena, &changes);
    if (err) return err;

    /* One commit, the tree and the sheet in one tree write, naming its writer's
     * action; the commit it made, the write's own answer: none where the tree
     * is the one the stage opened, and a head another writer moved or deleted
     * since the open is refused (sys/stage.h stage_commit) */
    return stage_commit(
        draft->stage, commit_message(draft->arena, words, draft->base->name, &changes),
        commit_action_word(words->action), out_commit
    );
}

void profile_draft_free(profile_draft_t *draft) {
    if (!draft) return;

    /* The admission, its own; then the base, before the stage whose tree it
     * borrows; then the stage, which undoes nothing in the repository (sys/stage.h
     * stage_free); then the arena, the struct and the copy with it */
    stage_admission_free(draft->admission);
    profile_free(draft->base);
    stage_free(draft->stage);
    arena_free(draft->arena);
}
