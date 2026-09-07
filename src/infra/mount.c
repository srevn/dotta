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
    const char *storage_path,
    mount_kind_t *out_kind,
    const char **out_tail
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
    const char *components,
    const char *display_path
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

    struct stat at_a, at_b;
    return fs_stat(a, &at_a) == 0 && fs_stat(b, &at_b) == 0 &&
           at_a.st_dev == at_b.st_dev && at_a.st_ino == at_b.st_ino;
}

/**
 * One mount: the spellings it is known by, and where it is. Both views (forward
 * classify, backward resolve) walk this same array.
 *
 * - spelling: as its binder typed it — HOME as the identity spells it, "" for a
 *           root at "/" — read through every enclosing alias the table knows: a
 *           target typed `~/link` under a HOME that is itself a link is known
 *           as `<HOME's physical>/link`, which is how a path respelled through
 *           HOME meets it (mount_table_build).
 * - physical: what it reaches, as realpath spells it — the spelling itself when
 *           realpath agrees or cannot answer (a target gone since it was bound).
 *           An alias is a mount whose spelling is not its physical; the sentinel
 *           and a mount bound under no link are not one.
 * - kind:   mount kind for this entry's storage label.
 * - profile: NULL for static mounts (HOME, ROOT). For CUSTOM mounts, the owning
 *           profile name; participates in profile-keyed backward resolution.
 *
 * Every string is the arena's — copied at build — so the table borrows nothing
 * and stands for the arena's lifetime.
 */
typedef struct {
    const char *spelling;
    const char *physical;
    mount_kind_t kind;
    const char *profile;
} mount_entry_t;

struct mount_table {
    mount_entry_t *entries;
    size_t entry_count;
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
 * the spelling, and have no files.
 */
static error_t *physical_of(
    arena_t *arena,
    const char *spelling,
    const char **out
) {
    char *resolved = NULL;
    error_t *err = fs_canonicalize_path(*spelling ? spelling : "/", &resolved);
    if (err) {
        error_free(err);
        *out = spelling;
        return NULL;
    }
    *out = table_spelling(arena, resolved);
    free(resolved);
    if (!*out) {
        return ERROR(ERR_MEMORY, "Failed to copy physical path into arena");
    }

    return NULL;
}

/**
 * Return the relative part of `absolute` after stripping `target`, with
 * path-component boundary verification.
 *
 *   /home/user matches /home/user/.bashrc /home/user does NOT match
 *   /home/username/.bashrc
 *
 * Returns NULL when `target` doesn't match or boundary fails. Returns a pointer
 * into `absolute` otherwise — empty string when they match exactly, the relative
 * tail otherwise. The root's "" matches every absolute path at depth zero.
 */
static const char *relative_after_target(
    const char *absolute,
    const char *target
) {
    size_t target_len = strlen(target);
    if (strncmp(absolute, target, target_len) != 0) return NULL;

    /* Boundary: next character must be '/' or '\0'. */
    char boundary = absolute[target_len];
    if (boundary != '/' && boundary != '\0') return NULL;

    const char *relative = absolute + target_len;
    if (*relative == '/') relative++;

    return relative;  /* "" on exact match, non-empty otherwise */
}

/**
 * The physical spelling of a path above its entry, as far as the table knows.
 *
 * A declared alias enclosing the path with something beneath it is respelled
 * through its physical, the deepest first, again until none does. The entry is
 * never respelled: a path that is an alias's own spelling names the entry there
 * — the link — not the directory it reaches, so a claim of the link stays a claim
 * of the link. A path spelled physically, or through a link no binding names,
 * is left as it is: `*path` is replaced only when respelled, by an arena string.
 * Every respell moves one declared link into the physical prefix and adds none
 * — a physical has no link in it — so it ends.
 */
static error_t *respell_above_entry(
    const mount_table_t *table,
    arena_t *arena,
    const char **path
) {
    for (;;) {
        const mount_entry_t *alias = NULL;
        const char *tail = NULL;
        for (size_t i = 0; i < table->entry_count; i++) {
            const mount_entry_t *m = &table->entries[i];
            if (strcmp(m->spelling, m->physical) == 0) continue;
            const char *t = relative_after_target(*path, m->spelling);
            if (!t || *t == '\0') continue;
            /* Both tails point into *path: the later one is the deeper alias. */
            if (!alias || t > tail) {
                alias = m;
                tail = t;
            }
        }
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
 * sentinel). `*out_tail` is empty when the path is the mount's root itself. Returns
 * NULL when no entry matches; with the sentinel present, this only happens for
 * a malformed table.
 */
static const mount_entry_t *deepest_mount(
    const mount_table_t *table,
    const char *physical,
    const char **out_tail
) {
    const mount_entry_t *winner = NULL;

    for (size_t i = 0; i < table->entry_count; i++) {
        const mount_entry_t *m = &table->entries[i];
        const char *tail = relative_after_target(physical, m->physical);
        if (!tail) continue;
        /* Both tails point into `physical`: the later one is the deeper root. */
        if (!winner || tail > *out_tail) {
            winner = m;
            *out_tail = tail;
        }
    }

    return winner;
}

error_t *mount_table_build(
    arena_t *arena,
    const mount_t *mounts,
    size_t mount_count,
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
    error_t *err = NULL;
    for (size_t i = 0; i < mount_count; i++) {
        const char *raw = mounts[i].target;
        if (!raw || raw[0] == '\0') continue;

        const char *spelling = table_spelling(arena, raw);
        if (!spelling) {
            return ERROR(ERR_MEMORY, "Failed to copy path into arena");
        }
        const char *physical = NULL;
        err = physical_of(arena, spelling, &physical);
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
            .spelling = spelling,
            .physical = physical,
            .kind = MOUNT_CUSTOM,
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
    err = physical_of(arena, home, &home_physical);
    if (err) return err;

    entries[n++] = (mount_entry_t){
        .spelling = home,
        .physical = home_physical,
        .kind = MOUNT_HOME,
        .profile = NULL,
    };
    entries[n++] = (mount_entry_t){
        .spelling = "",
        .physical = "",
        .kind = MOUNT_ROOT,
        .profile = NULL,
    };

    table->entries = entries;
    table->entry_count = n;

    /* The spellings, read through every enclosing alias: each alias respelled
     * over the table, once per custom — a round settles the outermost unresolved
     * alias of every chain, and no chain is longer than the table. A mount realpath
     * could not answer is no alias, and is left. */
    for (size_t round = 0; round < custom_count; round++) {
        for (size_t i = 0; i < custom_count; i++) {
            mount_entry_t *m = &entries[i];
            if (strcmp(m->spelling, m->physical) == 0) continue;
            err = respell_above_entry(table, arena, &m->spelling);
            if (err) return err;
        }
    }

    *out = table;

    return NULL;
}

error_t *mount_classify(
    const mount_table_t *table,
    const char *fs_path,
    arena_t *arena,
    mount_classify_outcome_t *outcome,
    const char **out_storage,
    const mount_spec_t **out_spec
) {
    CHECK_NULL(table);
    CHECK_NULL(fs_path);
    CHECK_NULL(arena);
    CHECK_NULL(outcome);
    CHECK_NULL(out_storage);

    /* The physical spelling, as far as the table knows: the typed path, its
     * declared aliases resolved above the entry. */
    const char *physical = arena_strdup(arena, fs_path);
    if (!physical) {
        return ERROR(ERR_MEMORY, "Failed to copy path into arena");
    }
    error_t *err = respell_above_entry(table, arena, &physical);
    if (err) return err;

    /* A root typed through its link — the settled path is an alias's own spelling,
     * which the respell leaves to the entry — is, to a query, the directory the
     * binding names: every binding of that directory stands there for the tie. */
    for (size_t i = 0; i < table->entry_count; i++) {
        if (strcmp(table->entries[i].spelling, physical) == 0) {
            physical = table->entries[i].physical;
            break;
        }
    }

    /* The mount, in physical space. */
    const char *tail = NULL;
    const mount_entry_t *winner = deepest_mount(table, physical, &tail);
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
static const mount_entry_t *find_entry_for(
    const mount_table_t *table,
    mount_kind_t kind,
    const char *profile
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
    const mount_table_t *table,
    const char *profile,
    const char *storage_path,
    arena_t *arena,
    const char **out_location
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
    const mount_entry_t *entry = find_entry_for(table, kind, profile);
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
     * entry there, the link, and stands as joined. */
    error_t *err = respell_above_entry(table, arena, &location);
    if (err) return err;
    *out_location = location;

    return NULL;
}
