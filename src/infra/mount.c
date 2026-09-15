/**
 * mount.c - Storage labels and per-machine deployment mount table
 *
 * SECURITY: All path conversions validate against path traversal.
 */

#include "infra/mount.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "base/arena.h"
#include "base/error.h"
#include "sys/filesystem.h"
#include "sys/identity.h"

/**
 * Per-kind behavioral attributes — the single source of truth.
 *
 * Indexed by `mount_kind_t` and sized by the arity the header publishes, so the
 * enum declares the label set once and the array's extent is that declaration
 * rather than a second one that happens to agree. Designated initializers keep
 * the row order in lockstep with the ordinals, which is what lets a row's kind
 * be its position (mount_spec_kind) rather than a field that would have to agree
 * with it. Adding a fourth kind is one row here plus a matching enum entry; every
 * consumer that asks "does this kind track ownership?" etc. reads spec attributes
 * — no switches to update.
 */
static const mount_spec_t SPECS[MOUNT_KIND_COUNT] = {
    [MOUNT_HOME] =   { "home",   "your home directory",   false, false },
    [MOUNT_ROOT] =   { "root",   "the filesystem root",   false, true  },
    [MOUNT_CUSTOM] = { "custom", "the deployment target", true,  true  },
};

const mount_spec_t *mount_spec_for_kind(mount_kind_t kind) {
    if ((unsigned int) kind >= MOUNT_KIND_COUNT) return NULL;
    return &SPECS[kind];
}

mount_kind_t mount_spec_kind(const mount_spec_t *spec) {
    return (mount_kind_t) (spec - SPECS);
}

/**
 * Decode a storage path's leading label.
 *
 * Single source of truth for the `home/` | `root/` | `custom/` -> kind
 * mapping. Both outputs are optional — pass NULL for either to discard.
 *
 *   storage_path = "home/.bashrc"   -> *kind=MOUNT_HOME,   *tail=".bashrc"
 *   storage_path = "custom/etc/foo" -> *kind=MOUNT_CUSTOM, *tail="etc/foo"
 *   storage_path = "/abs/path"      -> false, outputs unchanged
 *   storage_path = NULL             -> false, outputs unchanged
 *
 * The returned tail aliases `storage_path`; it shares the input's lifetime. Walks
 * SPECS so the label set has one canonical home — adding a fourth kind needs no
 * edit here.
 */
static bool mount_decode_label(
    const char *storage_path, mount_kind_t *out_kind, const char **out_tail
) {
    if (!storage_path) return false;

    for (size_t i = 0; i < MOUNT_KIND_COUNT; i++) {
        const char *label = SPECS[i].label;
        size_t label_len = strlen(label);

        if (strncmp(storage_path, label, label_len) != 0) continue;
        if (storage_path[label_len] != '/') continue;

        if (out_kind) *out_kind = (mount_kind_t) i;
        if (out_tail) *out_tail = storage_path + label_len + 1;
        return true;
    }

    return false;
}

const mount_spec_t *mount_spec_for_path(const char *storage_path) {
    mount_kind_t kind;
    if (!mount_decode_label(storage_path, &kind, NULL)) return NULL;
    /* mount_decode_label only emits in-range kinds, so the bounds check inside
     * mount_spec_for_kind is redundant — but borrowing the accessor keeps a single
     * chokepoint for kind→spec resolution. */
    return mount_spec_for_kind(kind);
}

const mount_spec_t *mount_spec_for_label(const char *label) {
    if (!label) return NULL;

    for (size_t i = 0; i < MOUNT_KIND_COUNT; i++) {
        if (strcmp(label, SPECS[i].label) == 0) return &SPECS[i];
    }

    return NULL;
}

const char *mount_strip_label(const char *storage_path) {
    if (!storage_path) return NULL;
    const char *tail = NULL;

    return mount_decode_label(storage_path, NULL, &tail) ? tail : storage_path;
}

error_t *mount_validate_storage(const char *storage_path) {
    CHECK_NULL(storage_path);

    if (storage_path[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Storage path cannot be empty");
    }

    /* SECURITY: Reject absolute paths */
    if (storage_path[0] == '/') {
        return ERROR(
            ERR_INVALID_ARG, "Storage path must be relative (got '%s')",
            storage_path
        );
    }

    /* SECURITY: Must start with home/, root/, or custom/ */
    const char *tail = NULL;
    if (!mount_decode_label(storage_path, NULL, &tail)) {
        return ERROR(
            ERR_INVALID_ARG, "Storage path must start with "
            "'home/', 'root/', or 'custom/' (got '%s')", storage_path
        );
    }

    /* Must reference a file, not just a label directory */
    if (storage_path[strlen(storage_path) - 1] == '/') {
        return ERROR(
            ERR_INVALID_ARG, "Storage path must not end with '/': '%s'",
            storage_path
        );
    }

    /* Reject consecutive slashes */
    if (strstr(storage_path, "//") != NULL) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid path format ('//'): '%s'",
            storage_path
        );
    }

    /* SECURITY: Tail components must not be `.` or `..`. A component is one by
     * its first bytes and whatever ends it, so the walk reads neither a length
     * nor a token; the label itself ("home"/"root"/"custom") is constant and
     * never a traversal token, so only the tail is walked. An empty component —
     * the one a `//` or a trailing `/` leaves — was refused above in its own
     * words and does not reach here. The message names the path the user typed,
     * not the tail it is walking. */
    for (const char *comp = tail; comp != NULL;) {
        if (comp[0] == '.' &&
            comp[1] == '.' && (comp[2] == '/' || comp[2] == '\0')) {
            return ERROR(
                ERR_INVALID_ARG, "Path traversal not allowed "
                "(component '..' in '%s')", storage_path
            );
        }
        if (comp[0] == '.' && (comp[1] == '/' || comp[1] == '\0')) {
            return ERROR(
                ERR_INVALID_ARG, "Invalid path component '.' in '%s'",
                storage_path
            );
        }

        const char *slash = strchr(comp, '/');
        comp = slash ? slash + 1 : NULL;
    }

    return NULL;
}

error_t *mount_validate_target(const char *target, dev_t store_dev, ino_t store_ino) {
    CHECK_NULL(target);

    /* The shape: absolute and folded, as the normalizer spells every argument
     * (infra/path.h), so of the binders' input only the interactive save's raw
     * text — kept as typed where a resolve refused it — can fail here; the sentence
     * names the whole rule for it. "/" is included: a target at the root is a
     * binding like any other, spelled "" in the table (mount_table_build). */
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

/**
 * One mount: the spelling it is known by, and whose it is. Both views (forward
 * name, backward resolve) walk this same array.
 *
 * - spelling: as its binder typed it — HOME as the identity spells it, "" for a
 *           root at "/" (the sentinel's, HOME's when HOME is "/", and a binding's
 *           when its target is "/"). The key of every location beneath it: a
 *           location is this joined with a tail, and nothing is read through
 *           (infra/mount.h).
 * - kind:   mount kind for this entry's storage label.
 * - profile: NULL for the shared roots (HOME, ROOT), which belong to every
 *           namespace. For CUSTOM mounts, the owning profile name — always set,
 *           mount_table_build refusing a binding that names none; it is the whole
 *           of whose an entry is, and both views read it through one predicate
 *           (namespace_holds).
 *
 * Every string is the arena's — copied at build — so the table borrows nothing
 * and stands for the arena's lifetime; the sentinel's is the literal "", which
 * outlives every arena.
 */
typedef struct {
    const char *spelling;    /* As its binder typed it */
    mount_kind_t kind;       /* The storage label paths under it take */
    const char *profile;     /* The binding's owner; NULL for HOME and ROOT */
} mount_entry_t;

struct mount_table {
    mount_entry_t *entries;    /* Customs in position order, then HOME, then ROOT */
    size_t entry_count;        /* The customs that named a target, plus those two */
};

/**
 * Does the asker's namespace hold this entry?
 *
 * A binding is a profile's (mount_t); an entry with none — HOME, the sentinel —
 * is every namespace's, and the build refuses a binding that names no profile
 * (mount_table_build), so a missing profile reads as "shared" and never as
 * "unknown". A NULL asker meets the shared roots alone: it names nothing beneath
 * another profile's binding and places no custom/ claim.
 *
 * One rule, read by the forward name (deepest_root) and the backward resolve
 * (find_entry).
 */
static bool namespace_holds(const char *profile, const mount_entry_t *m) {
    return !m->profile || (profile && strcmp(m->profile, profile) == 0);
}

/**
 * The tail of `location` past `root`, on a component boundary.
 *
 *   /home/user encloses /home/user/.bashrc; it does NOT enclose
 *   /home/username/.bashrc
 *
 * `root` is any of the table's — a mount's spelling, HOME's, or the sentinel's
 * "" — never a `--target` as such, so the parameter is named for what the table
 * calls it. Returns NULL when `root` does not enclose `location` or the boundary
 * fails; otherwise a pointer into `location` — the empty string when the two
 * name one directory, the tail past it otherwise. The root's "" encloses every
 * absolute path at depth zero, and only those: a relative path's first byte is
 * no boundary.
 */
static const char *tail_under_root(const char *location, const char *root) {
    size_t root_len = strlen(root);
    if (strncmp(location, root, root_len) != 0) return NULL;

    /* Boundary: next character must be '/' or '\0'. */
    char boundary = location[root_len];
    if (boundary != '/' && boundary != '\0') return NULL;

    const char *tail = location + root_len;
    if (*tail == '/') tail++;

    return tail;  /* "" when the two name one directory, non-empty otherwise */
}

/**
 * The deepest root of `profile` the location stands under, and the tail past it.
 *
 * A namespace is one profile's: the shared roots (HOME, the sentinel, both
 * profile-less) and its own binding; another profile's target is skipped before
 * it can win (namespace_holds). Tightest container wins. At an equal depth two
 * of the asker's own roots stand at one directory, and the more specific statement
 * takes it — a binding over the shared roots, and the sentinel over a HOME that
 * is "/": `~/.rc` under a binding at $HOME is `custom/.rc`, and a capture at
 * `/etc/x` on a machine whose HOME is "/" (a container's bare uid) is `root/etc/x`,
 * the reading that means the same directory on every other machine. Three roots
 * can stand at "": the sentinel always, HOME when it is "/", and a binding whose
 * target is "/". The binding takes both ties by the rule above — every path of
 * that profile outside a deeper root is `custom/`, which is what binding a profile
 * at the root means: a container's own root here, and the same profile bound at
 * a jail on the host — and between HOME and the sentinel the portable name wins.
 * One profile has one binding.
 *
 * A root encloses the location iff its spelling is a prefix of it on a component
 * boundary (tail_under_root), the root itself included with the empty tail: every
 * key is a string of the rows' own (infra/mount.h), so no second spelling of a
 * root is owed a match.
 *
 * `*out_tail` is empty when the location is the root itself, and is written only
 * when an entry matched — NULL when none did, which with the sentinel present
 * means only a malformed table or a location that is not absolute.
 */
static const mount_spec_t *deepest_root(
    const mount_table_t *table, const char *profile, const char *location,
    const char **out_tail
) {
    const mount_entry_t *winner = NULL;
    const char *deepest = NULL;

    for (size_t i = 0; i < table->entry_count; i++) {
        const mount_entry_t *m = &table->entries[i];

        /* The asker's own entries first: another profile's binding is an ordinary
         * directory in this namespace, and never competes on depth. */
        if (!namespace_holds(profile, m)) continue;

        const char *tail = tail_under_root(location, m->spelling);
        if (!tail) continue;

        /* Every tail points into `location` at its root's length, so pointer
         * order is depth order. The tie reads as the incumbent's veto and holds
         * under any entry order: it keeps an equal depth when it is the binding
         * — the more specific statement — or when the challenger is HOME, which
         * the portable name outranks. */
        if (winner && tail < deepest) continue;
        if (winner && tail == deepest &&
            (winner->kind == MOUNT_CUSTOM || m->kind == MOUNT_HOME)) {
            continue;
        }

        winner = m;
        deepest = tail;
    }

    if (!winner) return NULL;

    *out_tail = deepest;

    return mount_spec_for_kind(winner->kind);
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
    mount_entry_t *entries = arena_calloc(arena, mount_count + 2U, sizeof(*entries));
    if (!table || !entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate mount table");
    }

    /* Customs first (input order), then HOME, then the sentinel; no reader depends
     * on the order — deepest_root breaks its ties on the kinds.
     *
     * The profile is the type's contract (mount_t) and is refused whatever the
     * target: a nameless binding is a caller's bug, and it would be a root of
     * every namespace — the machine-wide name this module does not produce.
     * Establishing it here is what lets namespace_holds read `m->profile` as
     * the whole of whose an entry is, for both views at once. The target is the
     * type's contract too, and is refused when it is not absolute and folded
     * (sys/filesystem.h fs_is_folded): a relative row is no path on this machine,
     * and a `//`, a `.` or a trailing slash would key claims no argument can
     * spell. Neither reaches here — a row's target is the store's, whose column
     * holds no other shape (core/state.c), and a command's own binding passed
     * mount_validate_target — so one arriving is a caller's bug, refused as a
     * nameless binding is, naming the profile. Establishing both here is what
     * lets mount_resolve join every spelling with one separator, unconditionally.
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
         * the rows it was built from. "/" is spelled "" as a HOME of "/" is below
         * — the one spelling that joins a tail with one slash and encloses every
         * absolute path at depth zero, which is the sentinel's own; the tie between
         * the three is deepest_root's. */
        const char *spelling = arena_strdup(arena, raw[1] ? raw : "");
        const char *profile = arena_strdup(arena, mounts[i].profile);
        if (!spelling || !profile) {
            return ERROR(ERR_MEMORY, "Failed to copy a binding into the arena");
        }
        entries[n++] = (mount_entry_t){
            .spelling = spelling, .kind = MOUNT_CUSTOM, .profile = profile,
        };
    }

    /* The invoker's HOME as the identity spells it (sys/identity) — "" when it
     * is "/", a container's bare uid: the one spelling that joins a tail with
     * one slash and encloses every absolute path at depth zero, which is the
     * sentinel's own; the tie between the two is deepest_root's. */
    const identity_t *id = identity();
    const char *home = arena_strdup(arena, id->home[1] ? id->home : "");
    if (!home) {
        return ERROR(ERR_MEMORY, "Failed to copy the home directory into the arena");
    }
    entries[n++] = (mount_entry_t){
        .spelling = home, .kind = MOUNT_HOME, .profile = NULL,
    };
    /* The sentinel: "" encloses every absolute path at depth zero and joins a
     * tail with one slash, so the fallback needs no case of its own anywhere. A
     * literal, not the arena's. */
    entries[n++] = (mount_entry_t){
        .spelling = "", .kind = MOUNT_ROOT, .profile = NULL,
    };

    table->entries = entries;
    table->entry_count = n;
    *out = table;

    return NULL;
}

error_t *mount_name(
    const mount_table_t *table, const char *profile, const char *location,
    arena_t *arena, const char **out_storage
) {
    CHECK_NULL(table);
    CHECK_NULL(location);
    CHECK_NULL(arena);
    CHECK_NULL(out_storage);

    *out_storage = NULL;

    const char *tail = NULL;
    const mount_spec_t *root = deepest_root(table, profile, location, &tail);
    if (!root) {
        return ERROR(ERR_INTERNAL, "No root encloses '%s'", location);
    }

    /* A root has no name: the answer is the absence, already written. */
    if (*tail == '\0') return NULL;

    *out_storage = arena_str_format(arena, "%s/%s", root->label, tail);
    if (!*out_storage) {
        return ERROR(ERR_MEMORY, "Failed to format storage path");
    }

    return NULL;
}

const mount_spec_t *mount_root(
    const mount_table_t *table, const char *profile, const char *location
) {
    const char *tail = NULL;
    const mount_spec_t *root = deepest_root(table, profile, location, &tail);

    return root && *tail == '\0' ? root : NULL;
}

const char *mount_root_describe(
    const mount_spec_t *root, const char *profile, char *buf, size_t size
) {
    /* The owner is named where there is one to name. A root found in a table
     * was found by its own profile, so a per_profile spec arrives with its asker;
     * a root named by its label alone was found by nobody, and the noun is then
     * the label's own (infra/mount.h). */
    if (root->per_profile && profile) {
        snprintf(buf, size, "%s of profile '%s'", root->noun, profile);
    } else {
        snprintf(buf, size, "%s", root->noun);
    }

    return buf;
}

/**
 * The entry of `kind` in the asker's namespace, or NULL when none is.
 *
 * HOME and the sentinel are every asker's, so they answer whoever asks; a CUSTOM
 * entry is its own profile's alone, so a NULL asker finds no binding and places
 * no custom/ claim (namespace_holds).
 *
 * Two readers: mount_resolve, which joins beneath the spelling, and
 * mount_root_location, which hands it out as a path.
 */
static const mount_entry_t *find_entry(
    const mount_table_t *table, mount_kind_t kind, const char *profile
) {
    for (size_t i = 0; i < table->entry_count; i++) {
        const mount_entry_t *m = &table->entries[i];
        if (m->kind == kind && namespace_holds(profile, m)) return m;
    }

    return NULL;
}

const char *mount_root_location(
    const mount_table_t *table, const char *profile, mount_kind_t kind
) {
    const mount_entry_t *entry = find_entry(table, kind, profile);
    if (!entry) return NULL;

    /* The one reader that turns the table's "" back into the path it spells:
     * every other verb joins beneath the spelling (mount_resolve) or matches it
     * as a prefix (deepest_root), and neither wants the slash. */
    return entry->spelling[0] ? entry->spelling : "/";
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
     * CLI-input check at the calling site (add.c). The decode-label path below
     * tolerates any non-validated leading-label input by surfacing ERR_INTERNAL
     * — but the invariant is upstream, not here. */
    mount_kind_t kind;
    const char *tail = NULL;
    if (!mount_decode_label(storage_path, &kind, &tail)) {
        return ERROR(
            ERR_INTERNAL, "mount_resolve received non-storage path '%s'",
            storage_path
        );
    }

    /* Only CUSTOM lookups can miss here: HOME and ROOT entries are unconditional
     * (mount_table_build adds them every time). A CUSTOM miss means the profile
     * has no --target on this machine — e.g., a clone before the user has
     * configured a target — and the answer is the absence itself; malformed-input
     * failures surface as ERR_INTERNAL above. */
    const mount_entry_t *entry = find_entry(table, kind, profile);
    if (!entry) return NULL;

    /* The join: the root's spelling, "/", the tail — the key of the claim, which
     * every producer of a key agrees on because every one is this join over the
     * same strings (infra/mount.h). Uniform across the three kinds — the sentinel's
     * "" and a HOME of "/" join with one slash:
     *   ROOT:   "" + "/" + "etc/hosts"         -> "/etc/hosts"
     *   HOME:   "/home/user" + "/" + ".bashrc" -> "/home/user/.bashrc"
     *   CUSTOM: "/jail/web" + "/" + "etc/foo"  -> "/jail/web/etc/foo"
     * `tail` is non-empty (mount_validate_storage rejects trailing slashes) and
     * no spelling ends in a slash: the sentinel's, a HOME of "/" and a binding
     * at "/" are "", HOME is folded by the identity (sys/identity), and a target
     * is absolute and folded, the build's own refusal (mount_table_build) — so
     * the join is unconditional. */
    *out_location = arena_str_format(arena, "%s/%s", entry->spelling, tail);
    if (!*out_location) {
        return ERROR(ERR_MEMORY, "Failed to allocate filesystem path");
    }

    return NULL;
}
