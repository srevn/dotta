/**
 * mount.c - Storage labels and per-machine deployment mount table
 *
 * SECURITY: All path conversions validate against path traversal.
 */

#include "infra/mount.h"

#include <errno.h>
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
 * Indexed by `mount_kind_t`; designated initializers keep the row order in lockstep
 * with the enum ordinals. Adding a fourth kind is one row here plus a matching
 * enum entry; every consumer that asks "does this kind track ownership?" etc.
 * reads spec attributes — no switches to update.
 */
static const mount_spec_t SPECS[] = {
    [MOUNT_HOME] =   { "home",   "HOME",              false, false },
    [MOUNT_ROOT] =   { "root",   "root",              false, true  },
    [MOUNT_CUSTOM] = { "custom", "deployment target", true,  true  },
};

#define SPECS_COUNT (sizeof(SPECS) / sizeof(SPECS[0]))

const mount_spec_t *mount_spec_for_kind(mount_kind_t kind) {
    if ((unsigned int) kind >= SPECS_COUNT) return NULL;
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

    for (size_t i = 0; i < SPECS_COUNT; i++) {
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
            "Mount target must be absolute path (got '%s')\n"
            "Example: --target /mnt/jails/web", target
        );
    }

    /* 2. No path traversal or redundant components */
    if (strstr(target, "//") != NULL) {
        return ERROR(
            ERR_INVALID_ARG, "Mount target contains '//': '%s'",
            target
        );
    }

    /* 3. Validate each component (catches . and .. at any position). Skip the
     *    leading '/' — mount targets are always absolute. */
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
            "Mount target must not end with slash: '%s'\n"
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
                "Mount target directory does not exist: '%s'\n"
                "Create it first: mkdir -p '%s'", target, target
            );
        }
        return error_wrap(
            resolve_err, "Cannot resolve mount target '%s'", target
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
            "Mount target '%s' cannot be the filesystem root '/'\n"
            "Choose a specific directory: --target /mnt/jails/web", target
        );
    }

    /* 7. Verify it's a directory */
    struct stat st;
    if (fs_stat(resolved, &st) != 0) {
        free(resolved);
        return ERROR(
            ERR_INVALID_ARG, "Cannot stat mount target: %s",
            strerror(errno)
        );
    }
    if (!S_ISDIR(st.st_mode)) {
        free(resolved);
        return ERROR(
            ERR_INVALID_ARG, "Mount target must be a directory: '%s'",
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
 * - physical: what it reaches, as realpath spells it — the spelling itself when
 *           realpath agrees or cannot answer (a target gone since it was bound).
 *           An alias is a mount whose spelling is not its physical; the sentinel
 *           and a mount bound under no link are not one.
 * - kind:   mount kind for this entry's storage label.
 * - profile: NULL for static mounts (HOME, ROOT). For CUSTOM mounts, the owning
 *           profile name; participates in profile-keyed backward resolution.
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
 * Where a spelling reaches, as realpath spells it, or the spelling itself.
 *
 * Best-effort: a spelling realpath cannot answer (a target deleted since it was
 * bound, EACCES) reaches itself, and the mount is no alias — its claims key under
 * the spelling, and have no files. A root spelled "" is asked for as "/", the
 * one spelling of it realpath takes. NULL on arena exhaustion, as table_spelling
 * beside it answers that.
 */
static const char *physical_spelling(arena_t *arena, const char *spelling) {
    char *resolved = NULL;
    error_t *err = fs_canonicalize_path(*spelling ? spelling : "/", &resolved);
    if (err) {
        error_free(err);
        return spelling;
    }

    const char *physical = table_spelling(arena, resolved);
    free(resolved);

    return physical;
}

/**
 * Is this mount known by two spellings?
 *
 * The sentinel, a mount bound under no link, and one realpath could not answer
 * (physical_spelling hands the spelling back) all have one spelling for one
 * directory: none of them takes part in spelling a path physically.
 */
static bool mount_is_alias(const mount_entry_t *m) {
    return strcmp(m->spelling, m->physical) != 0;
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
 * The deepest mount a physically spelled path is under, and the tail past it.
 *
 * Tightest container wins; at equal depth — two mounts at one directory — the
 * earlier entry (stable: the customs in position order, then HOME, then the
 * sentinel). `*out_tail` is empty when the path is the mount's root itself, and
 * is written only when a mount matched. Returns NULL when none does; with the
 * sentinel present, this only happens for a malformed table.
 */
static const mount_entry_t *deepest_mount(
    const mount_table_t *table, const char *physical, const char **out_tail
) {
    const mount_entry_t *winner = NULL;
    const char *deepest = NULL;

    for (size_t i = 0; i < table->entry_count; i++) {
        const mount_entry_t *m = &table->entries[i];
        const char *tail = tail_under_root(physical, m->physical);
        if (!tail) continue;
        /* Every tail points into `physical` at its root's length, so pointer
         * order is depth order: the later one stands under the longer root. An
         * equal one is two mounts at one directory, and the earlier entry keeps
         * it. */
        if (winner && tail <= deepest) continue;
        winner = m;
        deepest = tail;
    }

    if (winner) *out_tail = deepest;

    return winner;
}

error_t *mount_table_build(
    arena_t *arena, const mount_t *mounts, size_t mount_count,
    mount_table_t **out
) {
    CHECK_NULL(arena);
    CHECK_NULL(out);
    if (mount_count > 0) CHECK_NULL(mounts);

    *out = NULL;

    /* Count CUSTOM mounts: input mounts with a non-empty target. Drop those with
     * NULL/empty target — they were dead weight in the prior architecture (their
     * profile-only entries served no observable purpose). */
    size_t custom_count = 0;
    for (size_t i = 0; i < mount_count; i++) {
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

    /* Populate: customs first (input order — stable tiebreak in the classifier),
     * then HOME, then ROOT sentinel. Each mount is spelled as its binder typed
     * it and as realpath reads it; the enclosing aliases are read below, once
     * every spelling is in. */
    size_t n = 0;
    for (size_t i = 0; i < mount_count; i++) {
        const char *raw = mounts[i].target;
        if (!raw || raw[0] == '\0') continue;

        const char *spelling = table_spelling(arena, raw);
        if (!spelling) {
            return ERROR(ERR_MEMORY, "Failed to copy path into arena");
        }
        const char *physical = physical_spelling(arena, spelling);
        if (!physical) {
            return ERROR(ERR_MEMORY, "Failed to copy physical path into arena");
        }

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
    const char *home_physical = physical_spelling(arena, home);
    if (!home_physical) {
        return ERROR(ERR_MEMORY, "Failed to copy physical path into arena");
    }

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

    /* The spellings, read through every enclosing alias: each alias read through
     * the table, once per custom — a round settles the outermost unresolved alias
     * of every chain, and no chain is longer than the table. An entry that has
     * been read all the way through to its own physical is no longer an alias
     * and falls out of the later rounds on its own. */
    for (size_t round = 0; round < custom_count; round++) {
        for (size_t i = 0; i < custom_count; i++) {
            mount_entry_t *m = &entries[i];
            if (!mount_is_alias(m)) continue;
            error_t *err = spell_ancestors(table, arena, &m->spelling);
            if (err) return err;
        }
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

error_t *mount_classify(
    const mount_table_t *table, const char *fs_path, arena_t *arena,
    mount_classify_outcome_t *outcome, const char **out_storage,
    const mount_spec_t **out_spec
) {
    CHECK_NULL(table);
    CHECK_NULL(fs_path);
    CHECK_NULL(arena);
    CHECK_NULL(outcome);
    CHECK_NULL(out_storage);

    /* Where the spelling stands; a location is its own answer, so a caller that
     * already holds one loses nothing by asking again. */
    const char *location = NULL;
    error_t *err = mount_locate(table, fs_path, arena, &location);
    if (err) return err;

    /* The mount, in physical space. */
    const char *tail = NULL;
    const mount_entry_t *winner = deepest_mount(table, location, &tail);
    if (!winner) {
        return ERROR(ERR_INTERNAL, "No mount matched: %s", fs_path);
    }

    /* The spec is the vocabulary view of the winning mount: its label string
     * (used to format the storage path) plus the per_profile and tracks_ownership
     * attributes that callers consume. Expose it in both outcomes so a single
     * call answers "what kind of mount matched?" without forcing the caller through
     * a second lookup. */
    const mount_spec_t *spec = mount_spec_for_kind(winner->kind);
    if (out_spec) *out_spec = spec;

    if (*tail == '\0') {
        /* Path equals the winning mount root exactly. No storage-path encoding
         * exists for the mount root itself. Surface as ROOT; callers walking a
         * directory tree treat this as "skip this entry, descendants appear
         * separately"; callers expecting a file translate ROOT into their own
         * error. */
        *outcome = MOUNT_CLASSIFY_ROOT;
        *out_storage = NULL;
        return NULL;
    }

    const char *result = arena_str_format(arena, "%s/%s", spec->label, tail);
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to format storage path");
    }
    *out_storage = result;
    *outcome = MOUNT_CLASSIFY_TAIL;

    return NULL;
}

/**
 * Look up the entry for a (kind, profile) pair.
 *
 * Profile-less kinds (per_profile == false: HOME, ROOT) contribute exactly one
 * entry; the first kind match wins. Profile-keyed kinds (per_profile == true:
 * CUSTOM) require a non-NULL caller profile that equals the entry's stored profile;
 * a NULL on either side defensively excludes the match. Returns NULL when no
 * entry satisfies the query.
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
        if (profile && m->profile && strcmp(m->profile, profile) == 0) {
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
