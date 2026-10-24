/**
 * history.c - A branch's history, asked about paths
 *
 * One walk a call, its state in a frame of its own (history_walk_t): every commit
 * the walk reached, by its id, with the paths waiting there to be read and the
 * paths it was read for; a queue of the commits with paths waiting, by commit
 * time; and per path, what its answer holds so far. A set of paths is one bit a
 * path, by its place in the walk's order (history_path_order), one word per 64.
 */

#include "sys/history.h"

#include <git2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/hashmap.h"
#include "sys/gitops.h"

/* A path asked, beside its slot in the caller's array: the walk's order is its own */
typedef struct {
    const char *path;               /* The caller's */
    size_t index;                   /* Its slot in the caller's paths, and its answer's */
} history_path_t;

/* A commit the walk reached */
typedef struct {
    git_oid oid;
    git_time_t time;                /* Its commit time: its place in the queue */
    uint64_t *waiting;              /* The paths that reached it, not yet read: queued iff any */
    uint64_t *read;                 /* The paths it was read for, each once */
} history_commit_t;

/* One path's removals as the walk finds them, grown in the caller's arena */
typedef struct {
    history_removal_t *entries;
    size_t count;
    size_t capacity;
} history_found_t;

/* The walk: what one call reads, and where it stands */
typedef struct {
    git_repository *repo;           /* The head's */
    arena_t *frame;                 /* The walk's own, freed at its end */
    arena_t *arena;                 /* The caller's: each answer's removals and words */
    history_path_t *paths;          /* The paths asked, in the walk's order */
    size_t count;
    size_t words;                   /* A set's words: one per 64 paths */
    char *component;                /* The name the descent looks up, NUL-terminated */
    hashmap_t *commits;             /* Hex id → history_commit_t: every commit reached */
    history_commit_t **queue;       /* The commits with paths waiting, oldest first: the newest is read next */
    size_t queue_count;
    size_t queue_capacity;

    /* The answers, by place in the walk's order */
    uint64_t *held;                 /* The paths the head holds */
    uint64_t *unread;               /* The paths a line of which went unread */
    history_found_t *found;         /* The removals each path's lines ended at */

    /* One commit's read at a time: made once, reused at each */
    size_t *positions;              /* The paths it reads, in the walk's order */
    uint64_t *reading;              /* The same, as a set */
    uint64_t *taken;                /* Of those, the paths every parent so far holds */
    uint64_t *parent_held;          /* The paths one parent holds */
    uint64_t *parent_unread;        /* The paths one parent's trees would not read the way to */
    uint64_t *lacking;              /* The paths a commit lacks, which go on to it */
} history_walk_t;

/* Whether a set holds the path at `position` */
static bool history_set_has(const uint64_t *set, size_t position) {
    return set[position / 64] >> (position % 64) & 1;
}

/* Put the path at `position` in a set */
static void history_set_add(uint64_t *set, size_t position) {
    set[position / 64] |= (uint64_t) 1 << (position % 64);
}

/* A byte's rank in the walk's order: a name's end, then '/', then every other byte */
static int history_rank(unsigned char byte) {
    return byte == '\0' ? 0 : byte == '/' ? 1 : byte + 1;
}

/**
 * The walk's order (qsort's): byte order, with '/' ranked right after a name's end
 *
 * So the paths beneath one component sort together, after the component itself
 * and before every name it prefixes — "home/a", "home/a/y", then "home/a-x" —
 * and the paths a descent reads at one name are one run of its positions
 * (history_descend). Plain byte order puts '-' before '/', and "home/a-x" between
 * the other two.
 */
static int history_path_order(const void *a, const void *b) {
    const unsigned char *x = (const unsigned char *) ((const history_path_t *) a)->path;
    const unsigned char *y = (const unsigned char *) ((const history_path_t *) b)->path;

    while (*x != '\0' && *x == *y) {
        x++;
        y++;
    }

    return history_rank(*x) - history_rank(*y);
}

/**
 * Which of a run of paths a parent's tree holds, and which it would not read
 * the way to
 *
 * The paths are the walk's at `positions`, in its order and sharing their first
 * `offset` bytes — the names above this tree — and the child lacks every one:
 * each reached it because it did, or the child is the head and there is none.
 * Each run of paths sharing the next component is one lookup in each tree. The
 * paths neither held nor unread the parent lacks.
 *
 * @param walk The walk (must not be NULL)
 * @param parent The parent's tree at the names above (must not be NULL)
 * @param child The child's tree there, or NULL: the head's own read has none,
 *              and one that would not load leaves none
 * @param positions The run's paths, by place in the walk's order
 * @param n How many
 * @param offset Where the next component begins, in each of their paths
 * @param held Gains each path the parent holds
 * @param unread Gains each path whose way the parent's trees would not read
 */
static void history_descend(
    history_walk_t *walk,
    const git_tree *parent,
    const git_tree *child,
    const size_t *positions,
    size_t n,
    size_t offset,
    uint64_t *held,
    uint64_t *unread
) {
    for (size_t i = 0; i < n;) {
        const char *name = walk->paths[positions[i]].path + offset;
        const size_t len = strcspn(name, "/");

        /* The run of paths at this name: one in the walk's order, so its end is
         * the first path past it, found by a search */
        size_t end = n;
        for (size_t lo = i + 1; lo < end;) {
            const size_t mid = lo + (end - lo) / 2;
            const char *other = walk->paths[positions[mid]].path + offset;

            if (strncmp(other, name, len) == 0 && (other[len] == '\0' || other[len] == '/')) {
                lo = mid + 1;
            } else {
                end = mid;
            }
        }

        memcpy(walk->component, name, len);
        walk->component[len] = '\0';

        const git_tree_entry *entry = git_tree_entry_byname(parent, walk->component);
        const git_tree_entry *child_entry = child
            ? git_tree_entry_byname(child, walk->component) : NULL;

        /* Nothing at the name, or the child's own entry: the parent lacks the
         * run as the child does, whatever lies beneath — so a commit that touched
         * none of the paths costs one lookup at its root */
        if (!entry || (child_entry &&
            git_oid_equal(git_tree_entry_id(child_entry), git_tree_entry_id(entry)))) {
            i = end;
            continue;
        }

        /* The paths that end at the name sort first in the run: held where a
         * blob of any filemode stands there */
        const git_object_t type = git_tree_entry_type(entry);
        size_t k = i;
        for (; k < end && walk->paths[positions[k]].path[offset + len] == '\0'; k++) {
            if (type == GIT_OBJECT_BLOB) history_set_add(held, positions[k]);
        }

        /* The paths beneath it: a subtree holds them, and a blob or a gitlink
         * above them leaves them lacking. The parent's subtree that will not
         * load leaves them unread; the child's buys the shortcut alone, and one
         * that will not load costs that and no answer */
        if (k < end && type == GIT_OBJECT_TREE) {
            git_tree *parent_subtree = NULL;
            if (git_tree_lookup(&parent_subtree, walk->repo, git_tree_entry_id(entry)) < 0) {
                for (size_t q = k; q < end; q++) history_set_add(unread, positions[q]);
            } else {
                git_tree *child_subtree = NULL;
                if (child_entry && git_tree_entry_type(child_entry) == GIT_OBJECT_TREE) {
                    (void) git_tree_lookup(
                        &child_subtree, walk->repo, git_tree_entry_id(child_entry)
                    );
                }
                history_descend(
                    walk, parent_subtree, child_subtree, positions + k, end - k,
                    offset + len + 1, held, unread
                );
                git_tree_free(child_subtree);
                git_tree_free(parent_subtree);
            }
        }

        i = end;
    }
}

/**
 * Paths reach a commit: the head, or a parent of a commit read that lacks them
 *
 * The commit is kept by its id from the first path that reaches it, and queued
 * when a path starts waiting there; a path it was read for arrives nowhere.
 *
 * @param walk The walk (must not be NULL)
 * @param commit The commit (must not be NULL)
 * @param paths The paths that reach it (must not be NULL)
 */
static void history_arrive(history_walk_t *walk, const git_commit *commit, const uint64_t *paths) {
    /* Nothing arrives where no path does: a parent that holds them all, or reads none */
    uint64_t arriving = 0;
    for (size_t k = 0; k < walk->words; k++) arriving |= paths[k];
    if (arriving == 0) return;

    char hex[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(hex, sizeof(hex), git_commit_id(commit));

    history_commit_t *reached = hashmap_get(walk->commits, hex);
    if (!reached) {
        reached = arena_calloc(walk->frame, 1, sizeof(*reached));
        reached->oid = *git_commit_id(commit);
        reached->time = git_commit_time(commit);
        reached->waiting = arena_calloc(walk->frame, walk->words, sizeof(*reached->waiting));
        reached->read = arena_calloc(walk->frame, walk->words, sizeof(*reached->read));
        hashmap_set(walk->commits, hex, reached);
    }

    /* A commit is in the queue while a path waits there: queued already where
     * one waited before this arrival, and queued now where one waits after it.
     * A path the commit was read for waits there no more, which is what ends
     * every walk, a hand's grafts included */
    uint64_t before = 0;
    uint64_t after = 0;
    for (size_t k = 0; k < walk->words; k++) {
        before |= reached->waiting[k];
        reached->waiting[k] |= paths[k] & ~reached->read[k];
        after |= reached->waiting[k];
    }
    if (before != 0 || after == 0) return;

    walk->queue = arena_grow(
        walk->frame, walk->queue, &walk->queue_capacity, walk->queue_count + 1,
        sizeof(*walk->queue)
    );

    /* Past every commit older, before every commit as new: git's own order
     * (lib/libgit2/src/libgit2/commit_list.c git_commit_list_insert_by_date),
     * the newest read next and, of two of one age, the one queued first — so a
     * history made within one second is walked a line at a time across its merges,
     * never one line to its root before the other reaches their common commits */
    size_t at = walk->queue_count++;
    for (; at > 0 && walk->queue[at - 1]->time >= reached->time; at--) {
        walk->queue[at] = walk->queue[at - 1];
    }
    walk->queue[at] = reached;
}

/**
 * Read a commit for the paths waiting there
 *
 * Each parent's tree descended beside the commit's own along them
 * (history_descend), the paths a parent lacks sent on to it (history_arrive),
 * and the paths every parent holds taken away by the commit: a removal of each,
 * under the word its header names.
 *
 * @param walk The walk (must not be NULL)
 * @param reached The commit, just taken off the queue (must not be NULL)
 */
static void history_read(history_walk_t *walk, history_commit_t *reached) {
    /* The waiting paths, taken off the commit and read for once: a path that
     * reaches it after this read waits for the next */
    size_t n = 0;
    for (size_t k = 0; k < walk->words; k++) {
        walk->reading[k] = reached->waiting[k];
        reached->read[k] |= reached->waiting[k];
        reached->waiting[k] = 0;

        for (uint64_t bits = walk->reading[k], bit = 0; bits != 0; bits >>= 1, bit++) {
            if (bits & 1) walk->positions[n++] = k * 64 + bit;
        }
    }

    /* Its child's read loaded it, so one that will not load now is the store
     * moving under the walk: every line that reached it unread */
    git_commit *commit = NULL;
    if (git_commit_lookup(&commit, walk->repo, &reached->oid) < 0) {
        for (size_t k = 0; k < walk->words; k++) walk->unread[k] |= walk->reading[k];
        return;
    }

    /* A root: every line that reached it never held its path */
    const unsigned int parent_count = git_commit_parentcount(commit);
    if (parent_count == 0) {
        git_commit_free(commit);
        return;
    }

    /* Its own tree buys the shortcut alone, every path read here being one it
     * lacks: one that will not load now costs that and no answer */
    git_tree *tree = NULL;
    (void) git_commit_tree(&tree, commit);

    memcpy(walk->taken, walk->reading, walk->words * sizeof(*walk->taken));
    for (unsigned int i = 0; i < parent_count; i++) {
        git_commit *parent = NULL;
        git_tree *parent_tree = NULL;

        /* A parent that will not load: whether it holds the paths is unknown,
         * so none is taken here and every line through it is unread */
        if (git_commit_parent(&parent, commit, i) < 0 ||
            git_commit_tree(&parent_tree, parent) < 0) {
            for (size_t k = 0; k < walk->words; k++) {
                walk->unread[k] |= walk->reading[k];
                walk->taken[k] = 0;
            }
            git_commit_free(parent);
            continue;
        }

        memset(walk->parent_held, 0, walk->words * sizeof(*walk->parent_held));
        memset(walk->parent_unread, 0, walk->words * sizeof(*walk->parent_unread));
        history_descend(
            walk, parent_tree, tree, walk->positions, n, 0, walk->parent_held,
            walk->parent_unread
        );

        for (size_t k = 0; k < walk->words; k++) {
            walk->unread[k] |= walk->parent_unread[k];
            walk->taken[k] &= walk->parent_held[k];
            walk->lacking[k] = walk->reading[k] & ~(walk->parent_held[k] | walk->parent_unread[k]);
        }
        history_arrive(walk, parent, walk->lacking);

        git_tree_free(parent_tree);
        git_commit_free(parent);
    }

    /* The paths every parent holds: this commit took them away, and its word,
     * read once, says what it was. A header that will not read leaves them unread,
     * its failure minted for this commit and dropped — the walk's bound */
    uint64_t took = 0;
    for (size_t k = 0; k < walk->words; k++) took |= walk->taken[k];

    if (took != 0) {
        const char *action = NULL;
        error_t err = gitops_commit_action(commit, walk->arena, &action);

        if (err) {
            for (size_t k = 0; k < walk->words; k++) walk->unread[k] |= walk->taken[k];
        } else {
            for (size_t i = 0; i < n; i++) {
                if (!history_set_has(walk->taken, walk->positions[i])) continue;

                history_found_t *found = &walk->found[walk->positions[i]];
                found->entries = arena_grow(
                    walk->arena, found->entries, &found->capacity, found->count + 1,
                    sizeof(*found->entries)
                );
                found->entries[found->count++] = (history_removal_t){
                    .oid = reached->oid,
                    .action = action,
                };
            }
        }
    }

    git_tree_free(tree);
    git_commit_free(commit);
}

void history_removals(
    const git_commit *head,
    const char *const *paths,
    size_t count,
    arena_t *arena,
    history_removals_t *out
) {
    CHECK_NULL(head);
    CHECK_NULL(arena);
    CHECK_NULL(out);
    if (count == 0) return;
    CHECK_NULL(paths);

    /* All the walk keeps is the frame's, sized by the paths asked: the answers'
     * removals and words alone are the caller's */
    history_walk_t walk = {
        .repo  = git_commit_owner(head),
        .frame = arena_create(0),
        .arena = arena,
        .count = count,
        .words = (count + 63) / 64,
    };
    walk.commits = hashmap_create(walk.frame, 0);
    walk.held = arena_calloc(walk.frame, walk.words, sizeof(*walk.held));
    walk.unread = arena_calloc(walk.frame, walk.words, sizeof(*walk.unread));
    walk.found = arena_calloc(walk.frame, count, sizeof(*walk.found));
    walk.positions = arena_calloc(walk.frame, count, sizeof(*walk.positions));
    walk.reading = arena_calloc(walk.frame, walk.words, sizeof(*walk.reading));
    walk.taken = arena_calloc(walk.frame, walk.words, sizeof(*walk.taken));
    walk.parent_held = arena_calloc(walk.frame, walk.words, sizeof(*walk.parent_held));
    walk.parent_unread = arena_calloc(walk.frame, walk.words, sizeof(*walk.parent_unread));
    walk.lacking = arena_calloc(walk.frame, walk.words, sizeof(*walk.lacking));

    /* The paths in the walk's order, each beside its slot, and room for the longest
     * component a descent names */
    walk.paths = arena_calloc(walk.frame, count, sizeof(*walk.paths));
    size_t longest = 0;
    for (size_t i = 0; i < count; i++) {
        walk.paths[i] = (history_path_t){ .path = paths[i], .index = i };
        const size_t len = strlen(paths[i]);
        if (len > longest) longest = len;
    }
    qsort(walk.paths, count, sizeof(*walk.paths), history_path_order);
    walk.component = arena_alloc(walk.frame, longest + 1);

    /* The head first, on its own: a path it holds has not left, and nothing behind
     * it is walked for it; one whose way its tree would not read is unread there.
     * A tree that will not load is every path's unread, and nothing is walked
     * at all. */
    git_tree *tree = NULL;
    if (git_commit_tree(&tree, head) < 0) {
        for (size_t p = 0; p < count; p++) history_set_add(walk.unread, p);
    } else {
        for (size_t p = 0; p < count; p++) {
            walk.positions[p] = p;
            history_set_add(walk.reading, p);
        }
        history_descend(&walk, tree, NULL, walk.positions, count, 0, walk.held, walk.unread);
        git_tree_free(tree);

        for (size_t k = 0; k < walk.words; k++) {
            walk.lacking[k] = walk.reading[k] & ~(walk.held[k] | walk.unread[k]);
        }
        history_arrive(&walk, head, walk.lacking);
    }

    /* Newest first, each commit read for the paths waiting there. libgit2's revwalk
     * is no queue for this (lib/libgit2/src/libgit2/revwalk.c): sorted, or with
     * a hide callback, it reads every commit the head reaches before it yields
     * one (limit_list); unsorted it yields each once by date (add_parents_to_list),
     * losing a path that reaches a commit after its turn; and one commit that
     * will not parse fails it whole, where here it costs only the paths whose
     * lines reach it. */
    while (walk.queue_count > 0) {
        history_read(&walk, walk.queue[--walk.queue_count]);
    }

    /* Each path's answer into its caller's slot: the removals the arena holds,
     * and its two bits */
    for (size_t p = 0; p < count; p++) {
        out[walk.paths[p].index] = (history_removals_t){
            .entries = walk.found[p].entries,
            .count = walk.found[p].count,
            .held = history_set_has(walk.held, p),
            .unread = history_set_has(walk.unread, p),
        };
    }

    arena_free(walk.frame);
}
