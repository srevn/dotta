/**
 * mount.c - Where a label lands: the per-machine table of roots
 *
 * Traversal is refused at the boundary (infra/label.h label_validate_storage,
 * mount_validate_target) and trusted below it (infra/mount.h).
 */

#include "infra/mount.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "base/arena.h"
#include "base/error.h"
#include "infra/label.h"
#include "sys/filesystem.h"
#include "sys/identity.h"

/**
 * What each label implies — the single source of truth.
 *
 * Indexed by `label_t` and sized by the arity the grammar publishes, so the enum
 * declares the label set once and the array's extent is that declaration rather
 * than a second one that happens to agree. Designated initializers keep the row
 * order in lockstep with the ordinals, which is what lets a reader subscript by
 * the label it holds.
 *
 * Defined here and read nowhere in this file: the noun that was its third column
 * is rendered from a root now (mount_root_describe), and what the two survivors
 * say belongs to core/cleanup and core/metadata (infra/mount.h).
 */
const mount_spec_t mount_kinds[LABEL_COUNT] = {
    [LABEL_HOME] =   { false, false },
    [LABEL_ROOT] =   { false, true  },
    [LABEL_CUSTOM] = { true,  true  },
};

error_t *mount_validate_target(const char *target, dev_t store_dev, ino_t store_ino) {
    CHECK_NULL(target);

    /* The shape: absolute and folded, as the normalizer spells every argument
     * (infra/path.h), so of the binders' input only the interactive save's raw
     * text — kept as typed where a resolve refused it — can fail here; the sentence
     * names the whole rule for it. "/" is included: a target at the root is a
     * binding like any other, and the table keeps it as it stands
     * (mount_table_build). */
    if (!fs_is_folded(target)) {
        return ERROR(
            ERR_INVALID_ARG,
            "Target must be an absolute path with no '.', '..', '//' or "
            "trailing slash (got '%s')", target
        );
    }

    /* The place: it stands, and it is a directory — one stat, through a link
     * standing at the spelling, because a binding means the directory the link
     * reaches, which is what mount_same_target reads of it too. Absence has a
     * remedy only when nothing is there: a link standing at the spelling reaches
     * nothing, and a mkdir would meet the link rather than make the directory.
     * Every other reason is the kernel's own words — a component that is a file
     * reads "Not a directory", where a mkdir -p would fail too. */
    struct stat st;
    if (fs_stat(target, &st) != 0) {
        if (errno != ENOENT) {
            return error_from_errno(errno, "Cannot stat target '%s'", target);
        }
        if (fs_lstat(target, &st) == 0 && S_ISLNK(st.st_mode)) {
            return ERROR(
                ERR_INVALID_ARG, "Target '%s' is a link to nothing", target
            );
        }
        return ERROR(
            ERR_INVALID_ARG, "Target directory does not exist: '%s'\n"
            "Create it first: mkdir -p '%s'", target, target
        );
    }
    if (!S_ISDIR(st.st_mode)) {
        return ERROR(
            ERR_INVALID_ARG, "Target must be a directory: '%s'", target
        );
    }

    /* The store: the one directory no binding may reach, however it is spelled.
     * A profile's custom/ tree deployed there lands over the store's own files
     * — measured: one `apply --force` wrote a profile's blob over `config`, and
     * every verb then read "not a dotta store". By identity, off the stat above:
     * a link to it reaches it, and a second spelling is the same directory. No
     * remedy is named, as the walkers name none (cmds/add.c): the store has no
     * inside a profile may hold. */
    if (st.st_dev == store_dev && st.st_ino == store_ino) {
        return ERROR(
            ERR_INVALID_ARG,
            "Target '%s' is dotta's own store, and a profile holds no part of it",
            target
        );
    }

    return NULL;
}

bool mount_same_target(const char *a, const char *b) {
    if (strcmp(a, b) == 0) return true;

    struct stat st_a, st_b;
    return fs_stat(a, &st_a) == 0 && fs_stat(b, &st_b) == 0 &&
           st_a.st_dev == st_b.st_dev && st_a.st_ino == st_b.st_ino;
}

struct mount_table {
    mount_root_t *roots;    /* Customs in position order, then HOME, then ROOT */
    size_t root_count;      /* The customs that named a target, plus those two */
};

/**
 * Does the asker's namespace hold this root?
 *
 * A binding is a profile's (mount_t); a root no profile bound — HOME, the sentinel
 * — is every namespace's, and the build refuses a binding that names no profile
 * (mount_table_build), so a missing binder reads as "shared" and never as
 * "unknown". A NULL asker meets the shared roots alone: it names nothing beneath
 * another profile's binding and places no custom/ claim.
 *
 * One rule, read by the search over the roots (mount_root_above) and the lookup
 * by label (mount_root_of).
 */
static bool namespace_holds(const char *profile, const mount_root_t *m) {
    return !m->profile || (profile && strcmp(m->profile, profile) == 0);
}

/**
 * The prefix a location is matched against and joined beneath.
 *
 * A root is a path wherever it is read (infra/mount.h), and the root directory
 * is the one root that *is* its separator: the two string verbs read it one byte
 * shorter, as "", which is the prefix that joins a tail with one slash and encloses
 * every absolute path at depth zero. Every other root is its own prefix, the
 * same pointer. The reading is made here and nowhere else — the sentinel, a HOME
 * of "/" and a binding whose target is "/" all reach it — so the build stores
 * one string per root and no consumer of a root can hold the form that is not a
 * path.
 *
 * Two readers: the search over the roots (mount_root_above) and the join
 * (mount_resolve).
 */
static const char *join_prefix(const mount_root_t *root) {
    return root->location[1] ? root->location : "";
}

/**
 * The tail of `location` past `prefix`, on a component boundary.
 *
 *   /home/user encloses /home/user/.bashrc; it does NOT enclose
 *   /home/username/.bashrc
 *
 * `prefix` is a root's, as join_prefix reads it — never a `--target` as such.
 * Returns NULL when it does not enclose `location` or the boundary fails; otherwise
 * a pointer into `location` — the empty string when the two name one directory,
 * the tail past it otherwise. The root directory's "" encloses every absolute
 * path at depth zero, and only those: a relative path's first byte is no boundary.
 */
static const char *tail_under_root(const char *location, const char *prefix) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(location, prefix, prefix_len) != 0) return NULL;

    /* Boundary: next character must be '/' or '\0'. */
    char boundary = location[prefix_len];
    if (boundary != '/' && boundary != '\0') return NULL;

    const char *tail = location + prefix_len;
    if (*tail == '/') tail++;

    return tail;  /* "" when the two name one directory, non-empty otherwise */
}

/* The search, whose contract — the tie, the boundary, the absence — is the header's
 * (infra/mount.h). A root encloses the location iff its prefix is a prefix of
 * it on a component boundary (tail_under_root), the root itself included with
 * the empty tail: every key is a string of the rows' own, so no second spelling
 * of a root is owed a match. */
const mount_root_t *mount_root_above(
    const mount_table_t *table, const char *profile, const char *location,
    const char **out_tail
) {
    const mount_root_t *winner = NULL;
    const char *deepest = NULL;

    for (size_t i = 0; i < table->root_count; i++) {
        const mount_root_t *m = &table->roots[i];

        /* The asker's own roots first: another profile's binding is an ordinary
         * directory in this namespace, and never competes on depth. */
        if (!namespace_holds(profile, m)) continue;

        const char *tail = tail_under_root(location, join_prefix(m));
        if (!tail) continue;

        /* Every tail points into `location` at its root's length, so pointer
         * order is depth order. The tie reads as the incumbent's veto and holds
         * under any row order: it keeps an equal depth when it is a binding —
         * the more specific statement, the row's own fact — or when the challenger
         * is HOME, which the portable name outranks. The one comparison a label
         * is load-bearing for, a HOME of "/" and the sentinel standing at one
         * directory with neither owned. */
        if (winner && tail < deepest) continue;
        if (winner && tail == deepest &&
            (winner->profile || m->label == LABEL_HOME)) {
            continue;
        }

        winner = m;
        deepest = tail;
    }

    if (!winner) return NULL;

    *out_tail = deepest;
    return winner;
}

error_t *mount_table_build(
    arena_t *arena, const mount_t *mounts, size_t mount_count, mount_table_t **out
) {
    CHECK_NULL(arena);
    CHECK_NULL(out);
    if (mount_count > 0) CHECK_NULL(mounts);

    *out = NULL;

    /* Slot reserve: every mount, whether or not it contributes, plus HOME and
     * the sentinel — a reservation, not a count, so the rows are read once. */
    mount_table_t *table = arena_calloc(arena, 1, sizeof(*table));
    mount_root_t *roots = arena_calloc(arena, mount_count + 2U, sizeof(*roots));
    if (!table || !roots) {
        return ERROR(ERR_MEMORY, "Failed to allocate mount table");
    }

    /* Customs first (input order), then HOME, then the sentinel; no reader depends
     * on the order — mount_root_above breaks its ties on the binder and one label,
     * and mount_root_of answers a label whose row is unique to it (infra/mount.h).
     *
     * The profile is the type's contract (mount_t) and is refused whatever the
     * target: a nameless binding is a caller's bug, and it would be a root of
     * every namespace — the machine-wide name this module does not produce.
     * Establishing it here is what lets namespace_holds read `m->profile` as
     * the whole of whose a root is, for both views at once, and lets the noun
     * name a binder without asking whether there is one (mount_root_describe).
     * The target is the type's contract too, and is refused when it is not absolute
     * and folded (sys/filesystem.h fs_is_folded): a relative row is no path on
     * this machine, and a `//`, a `.` or a trailing slash would key claims no
     * argument can spell. Neither reaches here — a row's target is the store's,
     * whose column holds no other shape (core/state.c), and a command's own binding
     * passed mount_validate_target — so one arriving is a caller's bug, refused
     * as a nameless binding is, naming the profile. Establishing both here is
     * what lets mount_resolve join every root with one separator, unconditionally.
     * NULL contributes no mount: the profile is bound nowhere in this table,
     * which the view records (core/manifest.h manifest_unbound). */
    size_t n = 0;
    for (size_t i = 0; i < mount_count; i++) {
        if (!mounts[i].profile) {
            return ERROR(
                ERR_INVALID_ARG, "A binding names its profile (entry %zu)", i
            );
        }
        const char *raw = mounts[i].target;
        if (!raw) continue;
        if (!fs_is_folded(raw)) {
            return ERROR(
                ERR_INVALID_ARG, "A binding's target is an absolute, folded path "
                "(profile '%s': '%s')", mounts[i].profile, raw
            );
        }

        /* Copied like the name: the table keeps nothing of the caller's past
         * the call, so it stands for the arena's lifetime whatever happens to
         * the rows it was built from. A target of "/" is kept as it stands, as
         * HOME and the sentinel are below — a root is a path here, and the one
         * that is its own separator is read a byte shorter where it is matched
         * and joined (join_prefix); the tie between the three is
         * mount_root_above's. */
        const char *location = arena_strdup(arena, raw);
        const char *profile = arena_strdup(arena, mounts[i].profile);
        if (!location || !profile) {
            return ERROR(ERR_MEMORY, "Failed to copy a binding into the arena");
        }
        roots[n++] = (mount_root_t){
            .label = LABEL_CUSTOM, .location = location, .profile = profile,
        };
    }

    /* The invoker's HOME as the identity spells it (sys/identity), "/" included
     * — a container's bare uid, which then stands at the sentinel's own directory
     * and loses the naming tie to it. */
    const identity_t *id = identity();
    const char *home = arena_strdup(arena, id->home);
    if (!home) {
        return ERROR(ERR_MEMORY, "Failed to copy the home directory into the arena");
    }
    roots[n++] = (mount_root_t){
        .label = LABEL_HOME, .location = home, .profile = NULL,
    };
    /* The sentinel: every absolute path stands under the root directory at depth
     * zero, so the fallback needs no case of its own anywhere. A literal, not
     * the arena's. */
    roots[n++] = (mount_root_t){
        .label = LABEL_ROOT, .location = "/", .profile = NULL,
    };

    table->roots = roots;
    table->root_count = n;
    *out = table;

    return NULL;
}

const mount_root_t *mount_root_at(
    const mount_table_t *table, const char *profile, const char *location
) {
    const char *tail = NULL;
    const mount_root_t *root =
        mount_root_above(table, profile, location, &tail);

    return root && *tail == '\0' ? root : NULL;
}

const mount_root_t *mount_root_of(
    const mount_table_t *table, const char *profile, label_t label
) {
    for (size_t i = 0; i < table->root_count; i++) {
        const mount_root_t *m = &table->roots[i];
        if (m->label == label && namespace_holds(profile, m)) return m;
    }

    return NULL;
}

const char *mount_root_describe(
    const mount_root_t *root, char *buf, size_t size
) {
    /* The one switch over a label's meaning on a screen. A bound root names its
     * binder: the profile is the build's, refused when a binding names none
     * (mount_table_build), so there is no arm where it could be absent. */
    switch (root->label) {
        case LABEL_HOME:
            snprintf(buf, size, "your home directory");
            break;
        case LABEL_ROOT:
            snprintf(buf, size, "the filesystem root");
            break;
        case LABEL_CUSTOM:
            snprintf(buf, size, "the deployment target of profile '%s'", root->profile);
            break;
    }

    return buf;
}

/* The one sentence four verbs share, said of the root and nothing else: the place
 * is the root's own spelling, which is the argument's too — a key is folded where
 * it is made and a find answers by exact equality (infra/mount.h). */
error_t *mount_root_refuse(const mount_root_t *root) {
    char buf[MOUNT_NOUN_MAX];

    return ERROR(
        ERR_INVALID_ARG, "'%s' is %s: name what is inside it", root->location,
        mount_root_describe(root, buf, sizeof(buf))
    );
}

error_t *mount_resolve(
    const mount_table_t *table, const char *profile, const char *storage_path,
    arena_t *arena, const char **out_location
) {
    CHECK_NULL(table);
    CHECK_NULL(storage_path);
    CHECK_NULL(arena);
    CHECK_NULL(out_location);

    *out_location = NULL;

    /* Storage paths arriving here are validated at their write boundary —
     * metadata.json parse (metadata.c), Git tree commit (add.c, update.c validate
     * before commit), state DB INSERT (validated upstream), or an explicit
     * CLI-input check at the calling site (add.c). The split below tolerates
     * any non-validated leading-label input by surfacing ERR_INTERNAL — but the
     * invariant is upstream, not here. */
    label_split_t split = label_split(storage_path);
    if (!split.tail) {
        return ERROR(
            ERR_INTERNAL, "mount_resolve received non-storage path '%s'",
            storage_path
        );
    }

    /* The find, whose absence is this verb's: only CUSTOM can miss — HOME and
     * the sentinel are unconditional (mount_table_build adds them every time) —
     * and a CUSTOM miss means the profile has no --target on this machine, e.g.
     * a clone before the user has configured one. The answer is that absence
     * itself; malformed-input failures surfaced as ERR_INTERNAL above. */
    const mount_root_t *root = mount_root_of(table, profile, split.label);
    if (!root) return NULL;

    /* The join: the root's prefix, "/", the tail — the key of the claim, which
     * every producer of a key agrees on because every one is this join over the
     * same strings (infra/mount.h). Uniform across the three labels, the root
     * directory reading as "" (join_prefix):
     *   ROOT:   "" + "/" + "etc/hosts"         -> "/etc/hosts"
     *   HOME:   "/home/user" + "/" + ".bashrc" -> "/home/user/.bashrc"
     *   CUSTOM: "/jail/web" + "/" + "etc/foo"  -> "/jail/web/etc/foo"
     * The tail is non-empty (label_validate_storage rejects trailing slashes)
     * and no prefix ends in a slash: the root directory's is "", HOME is folded
     * by the identity (sys/identity), and a target is absolute and folded, the
     * build's own refusal (mount_table_build) — so the join is unconditional. */
    *out_location = arena_str_format(arena, "%s/%s", join_prefix(root), split.tail);
    if (!*out_location) {
        return ERROR(ERR_MEMORY, "Failed to allocate filesystem path");
    }

    return NULL;
}
