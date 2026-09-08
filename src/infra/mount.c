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
 * the row order in lockstep with the ordinals. Adding a fourth kind is one row
 * here plus a matching enum entry; every consumer that asks "does this kind track
 * ownership?" etc. reads spec attributes — no switches to update.
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

/**
 * Reject `.` and `..` components in a slash-delimited path.
 *
 * Pure rule check shared by mount_validate_storage and mount_validate_target.
 * `components` is the substring to walk (storage paths start at byte 0; targets
 * start at byte 1 to skip the leading '/'); `display_path` is the original
 * user-visible string used only in error messages — separated so each caller
 * surfaces the form the user typed, not its tail.
 *
 * A component is `.` or `..` by its first bytes and whatever ends it, so the
 * walk reads neither a length nor a token. An empty component — the one a `//`
 * or a trailing `/` leaves — is neither, and passes here exactly as it passed
 * the tokenizer that used to skip it; both callers refuse those two shapes on
 * their own, in their own words.
 *
 * No filesystem access, no allocation: the tail is walked in place.
 */
static error_t *validate_path_components(
    const char *components, const char *display_path
) {
    for (const char *comp = components; comp != NULL;) {
        if (comp[0] == '.' && comp[1] == '.' && (comp[2] == '/' || comp[2] == '\0')) {
            return ERROR(
                ERR_INVALID_ARG, "Path traversal not allowed "
                "(component '..' in '%s')", display_path
            );
        }
        if (comp[0] == '.' && (comp[1] == '/' || comp[1] == '\0')) {
            return ERROR(
                ERR_INVALID_ARG, "Invalid path component '.' in '%s'",
                display_path
            );
        }

        const char *slash = strchr(comp, '/');
        comp = slash ? slash + 1 : NULL;
    }

    return NULL;
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

    /* SECURITY: Tail components must not be `.`, `..`, or empty. The label itself
     * ("home"/"root"/"custom") is constant and never a traversal token — walking
     * only the tail saves one iteration. */
    return validate_path_components(tail, storage_path);
}

const char *mount_strip_label(const char *storage_path) {
    if (!storage_path) return NULL;
    const char *tail = NULL;
    return mount_decode_label(storage_path, NULL, &tail) ? tail : storage_path;
}

error_t *mount_validate_target(const char *target) {
    CHECK_NULL(target);

    /* 1. Must be absolute */
    if (target[0] != '/') {
        return ERROR(
            ERR_INVALID_ARG,
            "Target must be absolute path (got '%s')\n"
            "Example: --target /mnt/jails/web", target
        );
    }

    /* 2. No path traversal or redundant components */
    if (strstr(target, "//") != NULL) {
        return ERROR(
            ERR_INVALID_ARG, "Target contains '//': '%s'",
            target
        );
    }

    /* 3. Validate each component (catches . and .. at any position). Skip the
     *    leading '/' — a target is always absolute. */
    error_t *comp_err = validate_path_components(target + 1, target);
    if (comp_err) {
        return error_wrap(
            comp_err,
            "Use canonical paths without '.', '..', or '//'"
        );
    }

    /* 4. Must not end with slash */
    size_t len = strlen(target);
    if (len > 1 && target[len - 1] == '/') {
        return ERROR(
            ERR_INVALID_ARG,
            "Target must not end with slash: '%s'\n"
            "Use: %.*s", target, (int) (len - 1), target
        );
    }

    /* 5. Normalize and verify existence through the canonical form */
    char *resolved = NULL;
    error_t *resolve_err = fs_canonicalize_path(target, &resolved);
    if (resolve_err) {
        if (error_code(resolve_err) == ERR_NOT_FOUND) {
            error_free(resolve_err);
            return ERROR(
                ERR_INVALID_ARG,
                "Target directory does not exist: '%s'\n"
                "Create it first: mkdir -p '%s'", target, target
            );
        }
        return error_wrap(
            resolve_err, "Cannot resolve target '%s'", target
        );
    }

    /* 6. Reject the filesystem root, whatever spelling reaches it — "/" itself,
     *    or a symlink to it, which the raw string would not show. A mount at
     *    "/" is always a misconfiguration: its claims would re-root under every
     *    path on the machine. */
    if (resolved[1] == '\0') {
        free(resolved);
        return ERROR(
            ERR_INVALID_ARG,
            "Target '%s' cannot be the filesystem root '/'\n"
            "Choose a specific directory: --target /mnt/jails/web", target
        );
    }

    /* 7. Verify it's a directory */
    struct stat st;
    if (fs_stat(resolved, &st) != 0) {
        free(resolved);
        return ERROR(
            ERR_INVALID_ARG, "Cannot stat target: %s",
            strerror(errno)
        );
    }
    if (!S_ISDIR(st.st_mode)) {
        free(resolved);
        return ERROR(
            ERR_INVALID_ARG, "Target must be a directory: '%s'",
            target
        );
    }
    free(resolved);

    return NULL;
}

bool mount_same_target(const char *a, const char *b) {
    if (strcmp(a, b) == 0) return true;

    struct stat st_a, st_b;
    return fs_stat(a, &st_a) == 0 && fs_stat(b, &st_b) == 0 &&
           st_a.st_dev == st_b.st_dev && st_a.st_ino == st_b.st_ino;
}

/**
 * One mount: the spellings it is known by, and where it is. Both views (forward
 * classify, backward resolve) walk this same array.
 *
 * - spelling: as its binder typed it — HOME as the identity spells it, "" for a
 *           root at "/" — read through every enclosing alias the table knows: a
 *           target typed `~/link` under a HOME that is itself a link is known
 *           as `<HOME's physical>/link`, which is how a path read through HOME
 *           meets it (mount_table_build).
 * - physical: what it reaches, as realpath spells it — and, when realpath cannot
 *           answer (a target gone since it was bound, EACCES), the entry's own
 *           settled spelling, which is as far as the table knows it reaches.
 *           NULL between the two, inside mount_table_build alone: the alias rounds
 *           read it that way, and no reader outside the build meets one. An alias
 *           is a mount whose spelling is not its physical; the sentinel and a
 *           mount bound under no link are not one.
 * - kind:   mount kind for this entry's storage label.
 * - profile: NULL for the shared roots (HOME, ROOT), which belong to every
 *           namespace. For CUSTOM mounts, the owning profile name — always set,
 *           mount_table_build refusing a binding that names none; it keys the
 *           backward resolution and narrows the forward one to the asker's own
 *           roots (deepest_root).
 *
 * Every string is the arena's — copied at build — so the table borrows nothing
 * and stands for the arena's lifetime; the sentinel's two are the literal "",
 * which outlives every arena.
 */
typedef struct {
    const char *spelling;    /* As its binder typed it, enclosing aliases resolved */
    const char *physical;    /* What it reaches, as realpath spells it */
    mount_kind_t kind;       /* The storage label paths under it take */
    const char *profile;     /* The binding's owner; NULL for HOME and ROOT */
} mount_entry_t;

struct mount_table {
    mount_entry_t *entries;    /* Customs in position order, then HOME, then ROOT */
    size_t entry_count;        /* The customs that named a target, plus those two */
};

/**
 * A directory's spelling in the table: an arena copy, the root directory as "".
 *
 * "" is the one spelling that joins a tail with one slash and encloses every
 * absolute path at depth zero — the sentinel's, and HOME's when HOME is "/" (a
 * container's bare uid) or reaches it through a link.
 */
static const char *table_spelling(arena_t *arena, const char *path) {
    return arena_strdup(arena, strcmp(path, "/") == 0 ? "" : path);
}

/**
 * Where a spelling reaches, as realpath spells it, or NULL when realpath cannot
 * answer — a target deleted since it was bound, EACCES.
 *
 * The entry's physical is then settled from its own spelling, once the rounds
 * have read every declared alias above it through (mount_table_build): that is
 * as far as the table can say it reaches, and it is the same reading a claim
 * beneath the binding gets (mount_resolve), so name and resolve place one location.
 * Handing the spelling back here instead would settle it before the rounds and
 * make the entry look like a non-alias to them — the alias test is the two fields
 * — so a binding under a declared link would be resolved through the link and
 * named through HOME.
 *
 * A root spelled "" is asked for as "/", the one spelling of it realpath takes.
 * ERR_MEMORY on arena exhaustion — the one failure that is not "cannot answer".
 */
static error_t *physical_spelling(
    arena_t *arena, const char *spelling, const char **out
) {
    *out = NULL;

    char *resolved = NULL;
    error_t *err = fs_canonicalize_path(*spelling ? spelling : "/", &resolved);
    if (err) {
        error_free(err);
        return NULL;
    }

    *out = table_spelling(arena, resolved);
    free(resolved);

    return *out
        ? NULL : ERROR(ERR_MEMORY, "Failed to copy physical path into arena");
}

/**
 * Is this mount known by two spellings?
 *
 * The sentinel and a mount bound under no link have one spelling for one directory.
 * So has one whose physical is not known yet: nothing may be read through a
 * spelling whose destination the table does not have, and inside mount_table_build
 * that entry is the rounds' subject, never their source.
 */
static bool mount_is_alias(const mount_entry_t *m) {
    return m->physical && strcmp(m->spelling, m->physical) != 0;
}

/**
 * The tail of `absolute` past `root`, on a component boundary.
 *
 *   /home/user encloses /home/user/.bashrc; it does NOT enclose
 *   /home/username/.bashrc
 *
 * `root` is any of the table's — a mount's spelling or its physical, HOME, or
 * the sentinel's "" — never a `--target` as such, so the parameter is named for
 * what the table calls it. Returns NULL when `root` does not enclose `absolute`
 * or the boundary fails; otherwise a pointer into `absolute` — the empty string
 * when the two name one directory, the tail past it otherwise. The root's ""
 * encloses every absolute path at depth zero, and only those: a relative path's
 * first byte is no boundary.
 */
static const char *tail_under_root(const char *absolute, const char *root) {
    size_t root_len = strlen(root);
    if (strncmp(absolute, root, root_len) != 0) return NULL;

    /* Boundary: next character must be '/' or '\0'. */
    char boundary = absolute[root_len];
    if (boundary != '/' && boundary != '\0') return NULL;

    const char *tail = absolute + root_len;
    if (*tail == '/') tail++;

    return tail;  /* "" when the two name one directory, non-empty otherwise */
}

/**
 * The deepest alias enclosing the path with something beneath it, and the tail
 * past its spelling. NULL when none does, and `*out_tail` is then untouched.
 *
 * A path that is an alias's own spelling is not enclosed by it — the tail must
 * be non-empty, which is how the final component stays out of the pass below.
 */
static const mount_entry_t *deepest_alias(
    const mount_table_t *table, const char *path, const char **out_tail
) {
    const mount_entry_t *alias = NULL;
    const char *deepest = NULL;

    for (size_t i = 0; i < table->entry_count; i++) {
        const mount_entry_t *m = &table->entries[i];
        if (!mount_is_alias(m)) continue;
        const char *tail = tail_under_root(path, m->spelling);
        if (!tail || *tail == '\0') continue;
        /* Every tail points into `path` at its spelling's length, so pointer
         * order is depth order: the later one stands under the longer spelling. */
        if (alias && tail <= deepest) continue;
        alias = m;
        deepest = tail;
    }

    if (alias) *out_tail = deepest;

    return alias;
}

/**
 * A path's ancestors spelled physically, as far as the table knows them.
 *
 * A declared alias enclosing the path with something beneath it is read through
 * what it reaches, the deepest first, again until none does. The final component
 * is never rewritten: a path that is an alias's own spelling names the link
 * standing there, not the directory it reaches, so a claim of the link stays a
 * claim of the link. A path spelled physically, or one through a link no binding
 * names, is left as it is: `*path` is replaced only when an ancestor was read
 * through, by an arena string. Every pass moves one declared link into the physical
 * prefix and adds none — a physical has no link in it — so it ends.
 */
static error_t *spell_ancestors(
    const mount_table_t *table, arena_t *arena, const char **path
) {
    for (;;) {
        const char *tail = NULL;
        const mount_entry_t *alias = deepest_alias(table, *path, &tail);
        if (!alias) return NULL;

        *path = arena_str_format(arena, "%s/%s", alias->physical, tail);
        if (!*path) {
            return ERROR(ERR_MEMORY, "Failed to spell the path physically");
        }
    }
}

/**
 * The deepest root of `profile` the location stands under, and the tail past it.
 *
 * A namespace is one profile's: the shared roots (HOME, the sentinel, both
 * profile-less) and its own binding; another profile's target is skipped before
 * it can win. Tightest container wins. At an equal depth two of the asker's own
 * roots stand at one directory, and the more specific statement takes it — a
 * binding over the shared roots, and the sentinel over a HOME that is "/": `~/.rc`
 * under a binding at $HOME is `custom/.rc`, and a capture at `/etc/x` on a machine
 * whose HOME is "/" (a container's bare uid, or a HOME that reaches "/" through
 * a link) is `root/etc/x`, the reading that means the same directory on every
 * other machine. Those are the only two ties there are: mount_validate_target
 * refuses "/", so a binding never meets the sentinel, and one profile has one
 * binding.
 *
 * A location is matched against the root's physical, which is what every location
 * is spelled as — and, when the location *is* the binder's own spelling, against
 * that. Two questions hand over such a spelling: a walk joins `<parent
 * location>/<name>` for a leaf without locating, and mount_resolve answers a
 * claim of a declared alias's own spelling with that spelling. Both leave at
 * most the last component unresolved (mount_table_build reads every enclosing
 * alias through, and so do locate and resolve), so exact equality is the whole
 * test and no prefix match over a spelling is owed.
 *
 * The spelling branch yields the end-of-string pointer, which is deeper than
 * any enclosing root's tail — so a root reached by its binder's spelling beats
 * HOME and the sentinel exactly as reaching it by its physical does. It is also
 * the empty tail, so the branch can only ever answer "the root itself": a *name*
 * is composed beneath a physical alone, which is what lets mount_resolve place
 * one back at the location it was composed from.
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

        /* A binding is a profile's (mount_t); an entry with none — HOME, the
         * sentinel — is every namespace's. */
        if (m->profile && (!profile || strcmp(m->profile, profile) != 0)) {
            continue;
        }

        const char *tail = tail_under_root(location, m->physical);
        if (!tail && strcmp(location, m->spelling) == 0) {
            /* The root itself, by its binder's own spelling. */
            tail = location + strlen(location);
        }
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

    /* Count CUSTOM mounts: input mounts with a non-empty target. Drop those with
     * NULL/empty target — they were dead weight in the prior architecture (their
     * profile-only entries served no observable purpose).
     *
     * The profile is required by the type's contract and not by the entry's fate,
     * so it is checked whatever the target: a nameless binding would be a root
     * of every namespace, which is the machine-wide name this module does not
     * produce (infra/mount.h mount_t). Establishing it here is what lets
     * deepest_root and find_entry read `m->profile` as a fact. */
    size_t custom_count = 0;
    for (size_t i = 0; i < mount_count; i++) {
        if (!mounts[i].profile) {
            return ERROR(
                ERR_INVALID_ARG, "A binding names its profile (entry %zu)", i
            );
        }
        if (mounts[i].target && mounts[i].target[0] != '\0') custom_count++;
    }

    /* Slot reserve: one entry per custom + HOME + ROOT sentinel. */
    size_t cap = custom_count + 1U + 1U;

    mount_table_t *table = arena_calloc(arena, 1, sizeof(*table));
    if (!table) {
        return ERROR(ERR_MEMORY, "Failed to allocate mount table");
    }

    mount_entry_t *entries = arena_calloc(arena, cap, sizeof(*entries));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate mount entries");
    }

    /* Populate: customs first (input order), then HOME, then ROOT sentinel. Each
     * mount is spelled as its binder typed it and as realpath reads it; the
     * enclosing aliases are read below, once every spelling is in. No reader
     * depends on this order — deepest_root breaks its ties on the kinds. */
    size_t n = 0;
    for (size_t i = 0; i < mount_count; i++) {
        const char *raw = mounts[i].target;
        if (!raw || raw[0] == '\0') continue;

        const char *spelling = table_spelling(arena, raw);
        if (!spelling) {
            return ERROR(ERR_MEMORY, "Failed to copy path into arena");
        }
        const char *physical = NULL;
        error_t *err = physical_spelling(arena, spelling, &physical);
        if (err) return err;

        /* The name is copied like the target: the table keeps nothing of the
         * caller's past the call, so it stands for the arena's lifetime whatever
         * happens to the rows it was built from. */
        const char *profile = NULL;
        if (mounts[i].profile) {
            profile = arena_strdup(arena, mounts[i].profile);
            if (!profile) {
                return ERROR(ERR_MEMORY, "Failed to copy profile name into arena");
            }
        }

        entries[n++] = (mount_entry_t){
            .spelling = spelling, .physical = physical, .kind = MOUNT_CUSTOM,
            .profile = profile,
        };
    }

    /* The invoker's HOME (sys/identity), and what it reaches: a symlinked HOME
     * (macOS's /tmp -> /private/tmp, an NFS bind mount) is one root under both
     * spellings, keyed by the physical. */
    const char *home = table_spelling(arena, identity()->home);
    if (!home) {
        return ERROR(ERR_MEMORY, "Failed to copy path into arena");
    }
    const char *home_physical = NULL;
    error_t *err = physical_spelling(arena, home, &home_physical);
    if (err) return err;

    entries[n++] = (mount_entry_t){
        .spelling = home, .physical = home_physical, .kind = MOUNT_HOME,
        .profile = NULL,
    };
    /* The sentinel: "" encloses every absolute path at depth zero and joins a
     * tail with one slash, so the fallback needs no case of its own anywhere.
     * Its two spellings are literals, not the arena's. */
    entries[n++] = (mount_entry_t){
        .spelling = "", .physical = "", .kind = MOUNT_ROOT, .profile = NULL,
    };

    table->entries = entries;
    table->entry_count = n;

    /* The spellings, read through every enclosing alias: each spelling read through
     * the table, once per custom — a round settles the outermost unresolved entry
     * of every chain, and no chain of entries is longer than the table. Every
     * custom is asked: a spelling with no declared alias above it is already
     * its own answer, and one whose physical realpath could not give is exactly
     * the entry that must not be skipped — it is no alias, so a guard on that
     * test would exclude the one class this pass exists for. */
    for (size_t round = 0; round < custom_count; round++) {
        for (size_t i = 0; i < custom_count; i++) {
            err = spell_ancestors(table, arena, &entries[i].spelling);
            if (err) return err;
        }
    }

    /* Where a binding realpath could not answer reaches, as far as the table
     * knows: its own settled spelling. Asked after the rounds, whose alias test
     * reads the physicals — and past this line no reader meets an unknown one. */
    for (size_t i = 0; i < n; i++) {
        if (!entries[i].physical) entries[i].physical = entries[i].spelling;
    }

    *out = table;

    return NULL;
}

error_t *mount_locate(
    const mount_table_t *table, const char *fs_path, arena_t *arena,
    const char **out_location
) {
    CHECK_NULL(table);
    CHECK_NULL(fs_path);
    CHECK_NULL(arena);
    CHECK_NULL(out_location);

    *out_location = NULL;

    /* The typed spelling, its declared aliases resolved above its final component.
     * The copy is the answer's lifetime: a spelling nothing was read through is
     * handed back as the arena's, like one that was. */
    const char *location = arena_strdup(arena, fs_path);
    if (!location) {
        return ERROR(ERR_MEMORY, "Failed to copy path into arena");
    }
    error_t *err = spell_ancestors(table, arena, &location);
    if (err) return err;

    /* A root's own spelling — a target typed through the link its binder declared,
     * HOME as the identity spells it under links no binding names — is what the
     * ancestor pass leaves to the final component, and is the directory the binding
     * names: every binding of that directory stands there for the tie, and a
     * row keyed beneath the physical is reached from it. */
    for (size_t i = 0; i < table->entry_count; i++) {
        if (strcmp(table->entries[i].spelling, location) == 0) {
            /* Two bindings at one directory share a physical, so the first match
             * answers for both. */
            location = table->entries[i].physical;
            break;
        }
    }

    *out_location = location;

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
    if (root->per_profile) {
        snprintf(buf, size, "%s of profile '%s'", root->noun, profile);
    } else {
        snprintf(buf, size, "%s", root->noun);
    }

    return buf;
}

/**
 * Look up the entry for a (kind, profile) pair.
 *
 * Profile-less kinds (per_profile == false: HOME, ROOT) contribute exactly one
 * entry; the first kind match wins. Profile-keyed kinds (per_profile == true:
 * CUSTOM) require a caller profile equal to the entry's stored one — which every
 * CUSTOM entry has, mount_table_build refusing a binding that names none — so a
 * NULL caller profile places no custom/ claim. Returns NULL when no entry satisfies
 * the query.
 *
 * Sole consumer today is mount_resolve.
 */
static const mount_entry_t *find_entry(
    const mount_table_t *table, mount_kind_t kind, const char *profile
) {
    const mount_spec_t *spec = mount_spec_for_kind(kind);
    if (!spec) return NULL;

    for (size_t i = 0; i < table->entry_count; i++) {
        const mount_entry_t *m = &table->entries[i];
        if (m->kind != kind) continue;
        if (!spec->per_profile) return m;
        if (profile && strcmp(m->profile, profile) == 0) {
            return m;
        }
    }

    return NULL;
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

    /* The join: the mount's physical, "/", the tail. Uniform across the three
     * kinds — the sentinel's "" and a HOME of "/" join with one slash:
     *   ROOT:   "" + "/" + "etc/hosts"         -> "/etc/hosts"
     *   HOME:   "/home/user" + "/" + ".bashrc" -> "/home/user/.bashrc"
     *   CUSTOM: "/jail/web" + "/" + "etc/foo"  -> "/jail/web/etc/foo"
     * `tail` is non-empty (mount_validate_storage rejects trailing slashes) and
     * no physical ends in a slash (realpath's, or a spelling that passed
     * mount_validate_target; HOME is normalised by the identity). */
    const char *location = arena_str_format(arena, "%s/%s", entry->physical, tail);
    if (!location) {
        return ERROR(ERR_MEMORY, "Failed to allocate filesystem path");
    }

    /* A claim beneath a declared alias — a target some profile is bound at through
     * a link inside this mount — stands where the link reaches, so p's home/link/x
     * and q's custom/x are one key; a claim at the alias's own spelling is the
     * link standing there, and stands as joined. */
    error_t *err = spell_ancestors(table, arena, &location);
    if (err) return err;
    *out_location = location;

    return NULL;
}
