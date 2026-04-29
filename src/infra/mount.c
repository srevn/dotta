/**
 * mount.c - Storage labels and per-machine deployment mount table
 *
 * SECURITY: All path conversions validate against path traversal.
 */

#include "infra/mount.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/string.h"
#include "sys/filesystem.h"

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
    if (!str_starts_with(storage_path, "home/") &&
        !str_starts_with(storage_path, "root/") &&
        !str_starts_with(storage_path, "custom/")) {
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

    /* SECURITY: Validate path component-by-component to catch traversal. */
    char *path_copy = strdup(storage_path);
    if (!path_copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate path copy");
    }

    char *saveptr = NULL;
    char *component = strtok_r(path_copy, "/", &saveptr);
    while (component != NULL) {
        if (strcmp(component, "..") == 0) {
            free(path_copy);
            return ERROR(
                ERR_INVALID_ARG, "Path traversal not allowed "
                "(component '..' in '%s')", storage_path
            );
        }
        if (strcmp(component, ".") == 0) {
            free(path_copy);
            return ERROR(
                ERR_INVALID_ARG, "Invalid path component '.' in '%s'",
                storage_path
            );
        }
        component = strtok_r(NULL, "/", &saveptr);
    }
    free(path_copy);

    return NULL;
}

const char *mount_strip_label(const char *storage_path) {
    if (!storage_path) return NULL;
    /* "home/" and "root/" are 5 chars; "custom/" is 7. */
    if (str_starts_with(storage_path, "home/") ||
        str_starts_with(storage_path, "root/")) {
        return storage_path + 5;
    }

    if (str_starts_with(storage_path, "custom/")) {
        return storage_path + 7;
    }

    return storage_path;
}

bool mount_kind_extract(const char *storage_path, mount_kind_t *out_kind) {
    if (!storage_path || !out_kind) return false;

    if (str_starts_with(storage_path, "home/")) {
        *out_kind = MOUNT_HOME;
        return true;
    }

    if (str_starts_with(storage_path, "root/")) {
        *out_kind = MOUNT_ROOT;
        return true;
    }

    if (str_starts_with(storage_path, "custom/")) {
        *out_kind = MOUNT_CUSTOM;
        return true;
    }

    return false;
}

bool mount_is_storage_path(const char *path) {
    if (!path) return false;

    return str_starts_with(path, "home/") ||
           str_starts_with(path, "root/") ||
           str_starts_with(path, "custom/");
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

    /* 4. Validate each component (catches . and .. at any position) */
    char *target_copy = strdup(target + 1);  /* skip leading / */
    if (!target_copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate path copy");
    }
    char *saveptr = NULL;
    char *comp = strtok_r(target_copy, "/", &saveptr);
    while (comp) {
        if (strcmp(comp, ".") == 0 || strcmp(comp, "..") == 0) {
            const char *bad = strcmp(comp, ".") == 0 ? "." : "..";
            free(target_copy);
            return ERROR(
                ERR_INVALID_ARG,
                "Mount target contains '%s' component: '%s'\n"
                "Use canonical paths without '.', '..', or '//'",
                bad, target
            );
        }
        comp = strtok_r(NULL, "/", &saveptr);
    }
    free(target_copy);

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
 * Storage label and human-readable display name for a kind.
 * Lookup tables instead of per-mount fields — derivable from kind.
 */
static const char *mount_kind_label(mount_kind_t kind) {
    switch (kind) {
        case MOUNT_HOME:   return "home";
        case MOUNT_ROOT:   return "root";
        case MOUNT_CUSTOM: return "custom";
    }
    return "";  /* unreachable */
}

static const char *mount_kind_display(mount_kind_t kind) {
    switch (kind) {
        case MOUNT_HOME:   return "HOME";
        case MOUNT_ROOT:   return "root";
        case MOUNT_CUSTOM: return "deployment target";
    }
    return "";  /* unreachable */
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
    const char *home;         /* Cached raw $HOME */
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
    table->home = home;

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

error_t *mount_classify(
    const mount_table_t *table,
    const char *fs_path,
    char **out_storage,
    mount_kind_t *out_kind
) {
    CHECK_NULL(table);
    CHECK_NULL(fs_path);
    CHECK_NULL(out_storage);

    /* Tightest container wins: longest matching surface form across
     * all entries. Each entry contributes up to two forms (raw and
     * realpath-canonical); intra-entry tiebreak picks the longer
     * surface form, inter-entry tiebreak keeps the earlier-declared
     * mount (stable). */
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

    if (!winner) {
        /* Unreachable when the ROOT sentinel ("" target) is present;
         * defensive guard for callers that build malformed tables. */
        return ERROR(
            ERR_INTERNAL, "No mount matched: %s", fs_path
        );
    }

    if (*winner_relative == '\0') {
        /* Path equals the winning mount root exactly. No storage-path
         * encoding exists for the mount root itself. Callers walking a
         * directory tree handle this as "skip this entry, descendants
         * appear separately"; callers expecting a file get an error. */
        return ERROR(
            ERR_INVALID_ARG,
            "Path equals the %s classification root; "
            "no storage-path representation",
            mount_kind_display(winner->kind)
        );
    }

    char *result = str_format(
        "%s/%s", mount_kind_label(winner->kind), winner_relative
    );
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to format storage path");
    }
    *out_storage = result;
    if (out_kind) *out_kind = winner->kind;

    return NULL;
}

/**
 * Look up the deployment target string for a profile's CUSTOM mount.
 *
 * Sole consumer is mount_resolve below — kept private since storage <->
 * filesystem conversion is the only documented use, and external callers
 * already go through mount_resolve / mount_classify for that.
 *
 * Returns the raw (user-supplied) form: backward resolution should
 * surface the path the user typed, not its realpath-resolved sibling.
 * NULL when `table` is NULL, `profile` is NULL, or no CUSTOM mount for
 * `profile` exists. The returned pointer borrows into the arena.
 */
static const char *mount_target_for_profile(
    const mount_table_t *table,
    const char *profile
) {
    if (!table || !profile) return NULL;

    for (size_t i = 0; i < table->entry_count; i++) {
        const mount_entry_t *m = &table->entries[i];
        if (m->kind != MOUNT_CUSTOM) continue;
        if (!m->profile) continue;
        if (strcmp(m->profile, profile) == 0) return m->target_raw;
    }

    return NULL;
}

error_t *mount_resolve(
    const mount_table_t *table,
    const char *profile,
    const char *storage_path,
    char **out_fs
) {
    CHECK_NULL(table);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_fs);

    error_t *err = mount_validate_storage(storage_path);
    if (err) return err;

    if (str_starts_with(storage_path, "home/")) {
        const char *relative = storage_path + strlen("home/");
        return fs_path_join(table->home, relative, out_fs);
    }

    if (str_starts_with(storage_path, "root/")) {
        /* root/etc/hosts -> /etc/hosts (skip "root", keep leading slash) */
        const char *abs = storage_path + strlen("root");
        char *result = strdup(abs);
        if (!result) {
            return ERROR(ERR_MEMORY, "Failed to allocate filesystem path");
        }
        *out_fs = result;
        return NULL;
    }

    if (str_starts_with(storage_path, "custom/")) {
        const char *target = mount_target_for_profile(table, profile);
        if (!target) {
            /* Lookup miss, not malformed input. ERR_NOT_FOUND lets callers
             * silently skip when a profile has no --target on this machine
             * (e.g., a clone before `dotta key set --target`) without
             * collapsing genuine path validation failures into the same
             * branch. mount_validate_storage above keeps surfacing
             * ERR_INVALID_ARG for malformed storage paths. */
            return ERROR(
                ERR_NOT_FOUND,
                "Storage path '%s' has no mount target for profile '%s'\n"
                "Profile not enabled with --target on this machine",
                storage_path, profile ? profile : "(none)"
            );
        }
        /* custom/etc/nginx.conf -> <target>/etc/nginx.conf
         * (skip "custom", keep leading slash; target has no trailing slash). */
        const char *relative = storage_path + strlen("custom");
        char *result = str_format("%s%s", target, relative);
        if (!result) {
            return ERROR(ERR_MEMORY, "Failed to format custom filesystem path");
        }
        *out_fs = result;
        return NULL;
    }

    /* Unreachable: mount_validate_storage rejects anything else. */
    return ERROR(ERR_INTERNAL, "Invalid storage path label: '%s'", storage_path);
}

/**
 * Resolve a relative path to absolute using CWD.
 * Pure string operation — does not check file existence.
 *
 * Handles:
 *   ./foo         -> $CWD/foo (strips leading ./)
 *   ../bar        -> $CWD/../bar (keeps ..)
 *   relative/path -> $CWD/relative/path
 */
static error_t *resolve_relative(const char *relative_path, char **out) {
    CHECK_NULL(relative_path);
    CHECK_NULL(out);

    if (relative_path[0] == '/') {
        *out = strdup(relative_path);
        if (!*out) return ERROR(ERR_MEMORY, "Failed to duplicate path");
        return NULL;
    }

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return ERROR(
            ERR_FS, "Failed to get current working directory: %s",
            strerror(errno)
        );
    }

    const char *clean = relative_path;
    while (clean[0] == '.' && clean[1] == '/') {
        clean += 2;
        while (*clean == '/') clean++;
    }

    /* Edge case: input was just "./" or "." */
    if (*clean == '\0' || (clean[0] == '.' && clean[1] == '\0')) {
        *out = strdup(cwd);
        if (!*out) return ERROR(ERR_MEMORY, "Failed to duplicate CWD");
        return NULL;
    }

    return fs_path_join(cwd, clean, out);
}

/**
 * Test whether an input string looks like a relative path.
 *
 * Relative:    ./foo, ../bar, .hidden, paths with / not starting with a label
 * NOT relative: absolute (/...), tilde (~...), storage paths (home/...)
 */
static bool input_is_relative(const char *input) {
    if (!input || input[0] == '\0') return false;
    if (input[0] == '.') return true;
    if (input[0] == '/' || input[0] == '~') return false;
    if (str_starts_with(input, "home/") ||
        str_starts_with(input, "root/") ||
        str_starts_with(input, "custom/")) return false;
    /* Contains slash but not a storage label — treat as relative. */
    if (strchr(input, '/') != NULL) return true;
    /* Single component without slash — ambiguous, not relative.
     * User should use ./X for clarity. */
    return false;
}

error_t *mount_resolve_input(
    const char *input,
    const mount_table_t *table,
    char **out_storage
) {
    CHECK_NULL(input);
    CHECK_NULL(table);
    CHECK_NULL(out_storage);

    error_t *err = NULL;
    char *storage_path = NULL;
    char *expanded = NULL;
    char *absolute = NULL;
    char *normalized = NULL;

    if (input[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Path cannot be empty");
    }

    /* Case 1: Storage path — validate and return a duplicate. */
    if (str_starts_with(input, "home/") ||
        str_starts_with(input, "root/") ||
        str_starts_with(input, "custom/")) {

        err = mount_validate_storage(input);
        if (err) {
            err = error_wrap(err, "Invalid storage path '%s'", input);
            goto cleanup;
        }

        storage_path = strdup(input);
        if (!storage_path) {
            err = ERROR(ERR_MEMORY, "Failed to allocate storage path");
        }
        goto cleanup;
    }

    /* Case 2: Filesystem path (absolute or tilde-prefixed) */
    if (input[0] == '/' || input[0] == '~') {
        if (input[0] == '~') {
            err = fs_expand_tilde(input, &expanded);
            if (err) {
                err = error_wrap(err, "Failed to expand path '%s'", input);
                goto cleanup;
            }
        } else {
            expanded = strdup(input);
            if (!expanded) {
                err = ERROR(ERR_MEMORY, "Failed to allocate path");
                goto cleanup;
            }
        }
        err = fs_make_absolute(expanded, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve path '%s'", input);
            goto cleanup;
        }
    }
    /* Case 3: Relative path (./foo, ../bar, or path with /) */
    else if (input_is_relative(input)) {
        err = resolve_relative(input, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve relative path '%s'", input);
            goto cleanup;
        }
    }
    /* Case 4: Ambiguous — single-component with no slash and no leading . */
    else {
        err = ERROR(
            ERR_INVALID_ARG,
            "Path '%s' is neither a valid filesystem path nor storage path\n"
            "Hint: Use absolute (/path), tilde (~/.file), relative (./path), or\n"
            "      storage format (home/..., root/..., custom/...)", input
        );
        goto cleanup;
    }

    /* Normalize ., .., and consecutive slashes before classification.
     * Each mount entry carries up to two surface forms (raw and
     * realpath-canonical), so canonical inputs (e.g., from getcwd
     * returning a symlink-resolved CWD on Case 3) classify correctly
     * against raw-stored targets without input canonicalization here. */
    err = fs_normalize_path(absolute, &normalized);
    if (err) {
        err = error_wrap(err, "Failed to normalize path '%s'", input);
        goto cleanup;
    }

    err = mount_classify(table, normalized, &storage_path, NULL);
    if (err) goto cleanup;

    err = mount_validate_storage(storage_path);
    if (err) goto cleanup;

cleanup:
    free(expanded);
    free(absolute);
    free(normalized);

    if (err) {
        free(storage_path);
        return err;
    }

    *out_storage = storage_path;
    return NULL;
}
