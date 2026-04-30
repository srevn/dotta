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

/**
 * Per-kind behavioral attributes — the single source of truth.
 *
 * Indexed by `mount_kind_t`. The _Static_assert below pins the enum
 * ordinals so designated initializers and direct indexing stay in
 * lockstep. Adding a fourth kind is one row here plus a matching enum
 * entry; every consumer that asks "does this kind track ownership?"
 * etc. reads spec attributes — no switches to update.
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
 * The returned tail aliases `storage_path`; it shares the input's
 * lifetime. Walks SPECS so the label set has one canonical home —
 * adding a fourth kind needs no edit here.
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

const mount_spec_t *mount_spec_for_label(const char *storage_path) {
    mount_kind_t kind;
    if (!mount_decode_label(storage_path, &kind, NULL)) return NULL;
    /* mount_decode_label only emits in-range kinds, so the bounds check
     * inside mount_spec_for_kind is redundant — but borrowing the
     * accessor keeps a single chokepoint for kind→spec resolution. */
    return mount_spec_for_kind(kind);
}

/**
 * Reject `..`, `.`, and empty components in a slash-delimited path.
 *
 * Pure rule check shared by mount_validate_storage and
 * mount_validate_target. `components` is the substring to tokenize
 * (storage paths start at byte 0; targets start at byte 1 to skip the
 * leading '/'); `display_path` is the original user-visible string used
 * only in error messages — separated so each caller surfaces the form
 * the user typed, not its tail.
 *
 * No filesystem access; no arena. Heap-strdups for tokenization, frees
 * before return.
 */
static error_t *validate_path_components(
    const char *components,
    const char *display_path
) {
    char *path_copy = strdup(components);
    if (!path_copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate path copy");
    }

    error_t *err = NULL;
    char *saveptr = NULL;
    char *component = strtok_r(path_copy, "/", &saveptr);
    while (component != NULL) {
        if (strcmp(component, "..") == 0) {
            err = ERROR(
                ERR_INVALID_ARG, "Path traversal not allowed "
                "(component '..' in '%s')", display_path
            );
            break;
        }
        if (strcmp(component, ".") == 0) {
            err = ERROR(
                ERR_INVALID_ARG, "Invalid path component '.' in '%s'",
                display_path
            );
            break;
        }
        component = strtok_r(NULL, "/", &saveptr);
    }
    free(path_copy);
    return err;
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

    /* SECURITY: Tail components must not be `.`, `..`, or empty. The
     * label itself ("home"/"root"/"custom") is constant and never a
     * traversal token — walking only the tail saves one iteration. */
    return validate_path_components(tail, storage_path);
}

const char *mount_strip_label(const char *storage_path) {
    if (!storage_path) return NULL;
    const char *tail = NULL;
    return mount_decode_label(storage_path, NULL, &tail) ? tail : storage_path;
}

bool mount_kind_extract(const char *storage_path, mount_kind_t *out_kind) {
    if (!out_kind) return false;
    return mount_decode_label(storage_path, out_kind, NULL);
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

    /* 2. Reject the filesystem root — inert at classify time (boundary
     * check rejects any match) but always a misconfiguration. */
    if (target[1] == '\0') {
        return ERROR(
            ERR_INVALID_ARG,
            "Mount target cannot be the filesystem root '/'\n"
            "Choose a specific directory: --target /mnt/jails/web"
        );
    }

    /* 3. No path traversal or redundant components */
    if (strstr(target, "//") != NULL) {
        return ERROR(
            ERR_INVALID_ARG, "Mount target contains '//': '%s'",
            target
        );
    }

    /* 4. Validate each component (catches . and .. at any position).
     *    Skip the leading '/' — mount targets are always absolute. */
    error_t *comp_err = validate_path_components(target + 1, target);
    if (comp_err) {
        return error_wrap(
            comp_err,
            "Use canonical paths without '.', '..', or '//'"
        );
    }

    /* 5. Must not end with slash */
    size_t len = strlen(target);
    if (len > 1 && target[len - 1] == '/') {
        return ERROR(
            ERR_INVALID_ARG,
            "Mount target must not end with slash: '%s'\n"
            "Use: %.*s", target, (int) (len - 1), target
        );
    }

    /* 6. Normalize and verify existence with realpath() */
    char *resolved = realpath(target, NULL);
    if (!resolved) {
        if (errno == ENOENT) {
            return ERROR(
                ERR_INVALID_ARG,
                "Mount target directory does not exist: '%s'\n"
                "Create it first: mkdir -p '%s'", target, target
            );
        }
        return ERROR(
            ERR_INVALID_ARG, "Cannot resolve mount target '%s': %s",
            target, strerror(errno)
        );
    }

    /* 7. Verify it's a directory */
    struct stat st;
    if (stat(resolved, &st) != 0) {
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

/**
 * One mount entry — a symlink-aware equivalence class for one mount.
 * Both views (forward classify, backward resolve) walk this same array.
 *
 * - target_raw: filesystem prefix as supplied by the caller (the form
 *           the user typed; "" for the universal root sentinel).
 * - target_canonical: realpath(target_raw); NULL when same as raw or
 *           when realpath() failed at build time. The two forms are
 *           treated as equivalent for forward classification — a path
 *           matching either surface form belongs to this mount.
 * - kind:   storage label class.
 * - profile: NULL for static mounts (HOME, ROOT). For CUSTOM mounts,
 *           the owning profile name; participates in profile-keyed
 *           backward resolution.
 *
 * Borrowed pointers — every string outlives the table because the
 * arena holds them.
 */
typedef struct {
    const char *target_raw;
    const char *target_canonical;
    mount_kind_t kind;
    const char *profile;
} mount_entry_t;

struct mount_table {
    mount_entry_t *entries;
    size_t entry_count;
};

/**
 * Resolve a path into its raw + realpath-canonical surface forms,
 * arena-allocating both.
 *
 * On success, *out_raw is non-NULL and arena-allocated. *out_canonical
 * is set only when realpath(3) succeeds AND the canonical form differs
 * from the raw value — leaving it NULL when same lets the classifier
 * short-circuit a redundant second-form check.
 *
 * Best-effort on canonicalization: realpath() failure (e.g., target
 * deleted since validation, EACCES) is non-fatal — *out_canonical
 * stays NULL and the caller still classifies correctly against the
 * raw form alone.
 *
 * The raw input is only borrowed — the function arena-copies it before
 * returning, so the caller may free `raw_path` after the call.
 */
static error_t *resolve_path_pair(
    arena_t *arena,
    const char *raw_path,
    const char **out_raw,
    const char **out_canonical
) {
    *out_raw = NULL;
    *out_canonical = NULL;

    const char *arena_raw = arena_strdup(arena, raw_path);
    if (!arena_raw) {
        return ERROR(ERR_MEMORY, "Failed to copy path into arena");
    }

    char *raw_canonical = NULL;
    error_t *canon_err = fs_canonicalize_path(arena_raw, &raw_canonical);
    if (canon_err) {
        error_free(canon_err);
        *out_raw = arena_raw;
        return NULL;
    }

    if (strcmp(raw_canonical, arena_raw) != 0) {
        const char *arena_canonical = arena_strdup(arena, raw_canonical);
        if (!arena_canonical) {
            free(raw_canonical);
            return ERROR(ERR_MEMORY, "Failed to copy canonical path into arena");
        }
        *out_canonical = arena_canonical;
    }
    free(raw_canonical);

    *out_raw = arena_raw;

    return NULL;
}

/**
 * HOME-specific wrapper around resolve_path_pair: fetches $HOME via
 * fs_get_home and delegates the dual-form materialization. Catches the
 * canonical HOME at build time so symlinked HOMEs (macOS's
 * /tmp -> /private/tmp, NFS bind mounts, etc.) classify correctly.
 */
static error_t *resolve_home_pair(
    arena_t *arena,
    const char **out_home,
    const char **out_canonical
) {
    char *raw_home = NULL;
    error_t *err = fs_get_home(&raw_home);
    if (err) return err;

    err = resolve_path_pair(arena, raw_home, out_home, out_canonical);
    free(raw_home);
    return err;
}

/**
 * Return the relative part of `absolute` after stripping `target`,
 * with path-component boundary verification.
 *
 *   /home/user matches /home/user/.bashrc
 *   /home/user does NOT match /home/username/.bashrc
 *
 * Returns NULL when `target` doesn't match or boundary fails. Returns
 * a pointer into `absolute` otherwise — empty string when they match
 * exactly, the relative tail otherwise.
 */
static const char *relative_after_target(
    const char *absolute,
    const char *target
) {
    if (!absolute || !target) return NULL;

    size_t target_len = strlen(target);
    if (strncmp(absolute, target, target_len) != 0) return NULL;

    /* Boundary: next character must be '/' or '\0'. */
    char boundary = absolute[target_len];
    if (boundary != '/' && boundary != '\0') return NULL;

    const char *relative = absolute + target_len;
    if (*relative == '/') relative++;

    return relative;  /* "" on exact match, non-empty otherwise */
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

    const char *home = NULL;
    const char *home_canonical = NULL;
    error_t *err = resolve_home_pair(arena, &home, &home_canonical);
    if (err) return err;

    /* Count CUSTOM mounts: input mounts with a non-empty target. Drop
     * those with NULL/empty target — they were dead weight in the prior
     * architecture (their profile-only entries served no observable
     * purpose). */
    size_t custom_count = 0;
    for (size_t i = 0; i < mount_count; i++) {
        if (mounts[i].target && mounts[i].target[0] != '\0') custom_count++;
    }

    /* Slot reserve: one entry per custom + HOME + ROOT sentinel. Each
     * entry now carries its own raw/canonical pair internally — no
     * separate row for canonical HOME. */
    size_t cap = custom_count + 1U + 1U;

    mount_table_t *table = arena_calloc(arena, 1, sizeof(*table));
    if (!table) {
        return ERROR(ERR_MEMORY, "Failed to allocate mount table");
    }

    mount_entry_t *entries = arena_calloc(arena, cap, sizeof(*entries));
    if (!entries) {
        return ERROR(ERR_MEMORY, "Failed to allocate mount entries");
    }

    /* Populate: customs first (input order — stable tiebreak in the
     * classifier), then HOME, then ROOT sentinel. Each custom resolves
     * to its own (raw, canonical) pair so symlinked --target arguments
     * (e.g., /tmp/jail when /tmp -> /private/tmp) classify both the raw
     * and resolved surface forms. */
    size_t n = 0;
    for (size_t i = 0; i < mount_count; i++) {
        const char *raw = mounts[i].target;
        if (!raw || raw[0] == '\0') continue;

        const char *target_raw = NULL;
        const char *target_canonical = NULL;
        err = resolve_path_pair(arena, raw, &target_raw, &target_canonical);
        if (err) return err;

        entries[n++] = (mount_entry_t){
            .target_raw = target_raw,
            .target_canonical = target_canonical,
            .kind = MOUNT_CUSTOM,
            .profile = mounts[i].profile,
        };
    }
    entries[n++] = (mount_entry_t){
        .target_raw = home,
        .target_canonical = home_canonical,
        .kind = MOUNT_HOME,
        .profile = NULL,
    };
    entries[n++] = (mount_entry_t){
        .target_raw = "",
        .target_canonical = NULL,
        .kind = MOUNT_ROOT,
        .profile = NULL,
    };

    table->entries = entries;
    table->entry_count = n;

    *out = table;

    return NULL;
}

/**
 * Pick the longest matching surface form within one mount entry.
 *
 * Each entry contributes up to two forms (raw, canonical). When both
 * match the same `fs_path`, the longer surface form wins as the
 * intra-entry representative; the outer scan in mount_classify then
 * picks the longest match across all entries. Stable tiebreak: the
 * raw form is tried first and wins ties on equal length.
 *
 * Returns true on any match, with `*out_relative` and `*out_target_len`
 * populated for the winning surface form. Returns false (and leaves
 * the outputs untouched) when neither form matches.
 */
static bool entry_match_longest(
    const mount_entry_t *entry,
    const char *fs_path,
    const char **out_relative,
    size_t *out_target_len
) {
    const char *forms[2] = { entry->target_raw, entry->target_canonical };

    bool any = false;
    size_t best_len = 0;
    const char *best_relative = NULL;

    for (int f = 0; f < 2; f++) {
        if (!forms[f]) continue;
        const char *relative = relative_after_target(fs_path, forms[f]);
        if (!relative) continue;

        size_t len = strlen(forms[f]);
        if (!any || len > best_len) {
            any = true;
            best_relative = relative;
            best_len = len;
        }
    }

    if (!any) return false;
    *out_relative = best_relative;
    *out_target_len = best_len;
    return true;
}

/**
 * Inner winner-pick: longest matching surface form across all entries.
 *
 * Tightest container wins. Each entry contributes up to two forms (raw
 * and realpath-canonical); intra-entry tiebreak picks the longer
 * surface form (entry_match_longest), inter-entry tiebreak keeps the
 * earlier-declared mount (stable). On match, *out_relative is the tail
 * after the winning prefix — empty when fs_path equals the mount root,
 * non-empty otherwise. Returns NULL when no entry matches; with the
 * ROOT sentinel ("" target) present, this only happens for malformed
 * tables.
 */
static const mount_entry_t *find_classify_winner(
    const mount_table_t *table,
    const char *fs_path,
    const char **out_relative
) {
    const mount_entry_t *winner = NULL;
    const char *winner_relative = NULL;
    size_t winner_len = 0;

    for (size_t i = 0; i < table->entry_count; i++) {
        const mount_entry_t *m = &table->entries[i];

        const char *relative = NULL;
        size_t len = 0;
        if (!entry_match_longest(m, fs_path, &relative, &len)) continue;

        if (!winner || len > winner_len) {
            winner = m;
            winner_relative = relative;
            winner_len = len;
        }
    }

    if (winner && out_relative) *out_relative = winner_relative;
    return winner;
}

error_t *mount_classify(
    const mount_table_t *table,
    const char *fs_path,
    arena_t *arena,
    mount_classify_outcome_t *outcome,
    const char **out_storage,
    mount_kind_t *out_kind
) {
    CHECK_NULL(table);
    CHECK_NULL(fs_path);
    CHECK_NULL(arena);
    CHECK_NULL(outcome);
    CHECK_NULL(out_storage);

    const char *winner_relative = NULL;
    const mount_entry_t *winner =
        find_classify_winner(table, fs_path, &winner_relative);

    if (!winner) {
        return ERROR(ERR_INTERNAL, "No mount matched: %s", fs_path);
    }

    if (out_kind) *out_kind = winner->kind;

    if (*winner_relative == '\0') {
        /* Path equals the winning mount root exactly. No storage-path
         * encoding exists for the mount root itself. Surface as ROOT;
         * callers walking a directory tree treat this as "skip this
         * entry, descendants appear separately"; callers expecting a
         * file translate ROOT into their own error. */
        *outcome = MOUNT_CLASSIFY_ROOT;
        *out_storage = NULL;
        return NULL;
    }

    const mount_spec_t *spec = mount_spec_for_kind(winner->kind);
    const char *result =
        arena_str_format(arena, "%s/%s", spec->label, winner_relative);
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
 * Profile-less kinds (per_profile == false: HOME, ROOT) contribute
 * exactly one entry; the first kind match wins. Profile-keyed kinds
 * (per_profile == true: CUSTOM) require a non-NULL caller profile that
 * equals the entry's stored profile; a NULL on either side defensively
 * excludes the match. Returns NULL when no entry satisfies the query.
 *
 * Sole consumer today is mount_resolve. The intra-entry surface-form
 * walk for forward classification stays in entry_match_longest.
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

/**
 * Concatenate a mount target prefix with a label-stripped tail into an
 * arena-borrowed filesystem path.
 *
 * Format `"%s/%s"` is uniform across all three kinds:
 *   ROOT:   "" + "/" + "etc/hosts"         -> "/etc/hosts"
 *   HOME:   "/home/user" + "/" + ".bashrc" -> "/home/user/.bashrc"
 *   CUSTOM: "/jail/web" + "/" + "etc/foo"  -> "/jail/web/etc/foo"
 *
 * `tail` is non-empty (mount_validate_storage rejects trailing slashes
 * on the storage path). A defensive trailing-slash strip on
 * `target_raw` keeps a malformed `$HOME` like `/home/user/` from
 * producing `/home/user//.bashrc`; CUSTOM targets are validated to have
 * no trailing slash, ROOT is always empty.
 */
static error_t *join_target_with_tail(
    arena_t *arena,
    const char *target_raw,
    const char *tail,
    const char **out
) {
    size_t target_len = strlen(target_raw);
    if (target_len > 0 && target_raw[target_len - 1] == '/') {
        target_len--;
    }
    const char *result =
        arena_str_format(arena, "%.*s/%s", (int) target_len, target_raw, tail);
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate filesystem path");
    }
    *out = result;
    return NULL;
}

error_t *mount_resolve(
    const mount_table_t *table,
    const char *profile,
    const char *storage_path,
    arena_t *arena,
    mount_resolve_outcome_t *outcome,
    const char **out_fs
) {
    CHECK_NULL(table);
    CHECK_NULL(storage_path);
    CHECK_NULL(arena);
    CHECK_NULL(outcome);
    CHECK_NULL(out_fs);

    /* Storage paths arriving here are validated at their write boundary —
     * metadata.json parse (metadata.c), Git tree commit (add.c, update.c
     * validate before commit), state DB INSERT (validated upstream), or
     * an explicit CLI-input check at the calling site (add.c). The
     * decode-label path below tolerates any non-validated leading-label
     * input by surfacing ERR_INTERNAL — but the invariant is upstream,
     * not here. */
    mount_kind_t kind;
    const char *tail = NULL;
    if (!mount_decode_label(storage_path, &kind, &tail)) {
        return ERROR(
            ERR_INTERNAL, "mount_resolve received non-storage path '%s'",
            storage_path
        );
    }

    const mount_entry_t *entry = find_entry_for(table, kind, profile);
    if (!entry) {
        /* Only CUSTOM lookups can miss here: HOME and ROOT entries are
         * unconditional (mount_table_build adds them every time). A
         * CUSTOM miss means the profile has no --target on this machine
         * — e.g., a clone before the user has configured a target.
         * Surface as UNBOUND so callers branch on outcome rather than
         * pattern-matching on a NULL pointer; malformed-input failures
         * still surface as ERR_INTERNAL above. */
        *outcome = MOUNT_RESOLVE_UNBOUND;
        return NULL;
    }

    error_t *err = join_target_with_tail(arena, entry->target_raw, tail, out_fs);
    if (err) return err;

    *outcome = MOUNT_RESOLVE_BOUND;
    return NULL;
}
