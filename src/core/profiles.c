/**
 * profiles.c - Profile management implementation
 */

#include "core/profiles.h"

#include <ctype.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/string.h"
#include "core/branch.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "sys/gitops.h"

/**
 * Is there a profile of this name here, or refuse
 */
error_t profile_require(git_repository *repo, const char *name) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    bool exists = false;
    error_t err = gitops_branch_exists(repo, name, &exists);
    if (err) return err;
    if (!exists) {
        return error_create(
            ERR_NOT_FOUND, "Profile '%s' doesn't exist locally; 'dotta profile fetch %s' "
            "brings it from a remote that holds it", name, name
        );
    }

    return NULL;
}

/**
 * Match hierarchical profiles from available branches
 *
 * Appends the base match (exact prefix) and its sub-matches (prefix/variant,
 * one level deep only) to `out`, in the order `available` holds them. Selection
 * only: the ordering is profile_detect's, which sorts everything it selected
 * with profile_order once the three steps have run.
 *
 * @param available Available branch names to match against
 * @param prefix Prefix to match (e.g., "darwin", "hosts/myhost")
 * @param out Output array to append matches to
 */
static void match_hierarchical_profiles(
    const string_array_t *available,
    const char *prefix,
    string_array_t *out
) {
    size_t prefix_len = strlen(prefix);

    for (size_t i = 0; i < available->count; i++) {
        const char *profile = available->entries[i];

        /* Check if branch starts with prefix */
        if (!str_starts_with(profile, prefix)) {
            continue;
        }

        const char *suffix = profile + prefix_len;

        if (suffix[0] == '\0') {
            /* Exact match: base profile */
            string_array_push(out, profile);
        } else if (suffix[0] == '/') {
            const char *variant = suffix + 1;
            /* One level deep only: non-empty variant with no further '/' */
            if (variant[0] != '\0' && strchr(variant, '/') == NULL) {
                string_array_push(out, profile);
            }
        }
    }
}

/**
 * The layer a profile name stands in — see profile_order.
 */
static int profile_rank(const char *name) {
    if (strcmp(name, "global") == 0) return 0;
    if (str_starts_with(name, "hosts/")) return 2;
    return 1;
}

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

/**
 * Detect matching profile names from a list of available branches
 */
string_array_t profile_detect(arena_t *arena, const string_array_t *available_branches) {
    CHECK_NULL(available_branches);

    string_array_t profiles;
    string_array_init(&profiles, arena);

    /* 1. "global" — always first if present */
    if (string_array_contains(available_branches, "global")) {
        string_array_push(&profiles, "global");
    }

    /* 2. OS-specific profiles (darwin, linux, freebsd, ...), the system's name
     *    lowered where uname wrote it */
    struct utsname uts;
    if (uname(&uts) == 0) {
        /* Safe tolower: cast to unsigned char to avoid UB with negative values */
        for (char *p = uts.sysname; *p; p++) {
            *p = (char) tolower((unsigned char) *p);
        }

        match_hierarchical_profiles(available_branches, uts.sysname, &profiles);
    }
    /* Non-fatal: skip OS profiles if uname() fails */

    /* 3. Host-specific profiles (hosts/<hostname>, hosts/<hostname>/variant) */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1] = '\0';

        char host_prefix[DOTTA_REFNAME_MAX];
        int n = snprintf(
            host_prefix, sizeof(host_prefix), "hosts/%s", hostname
        );
        if (n >= 0 && (size_t) n < sizeof(host_prefix)) {
            match_hierarchical_profiles(available_branches, host_prefix, &profiles);
        }
    }
    /* Non-fatal: continue if gethostname() fails */

    /* The three steps above answer *which* names this machine layers; this is
     * the order they are seeded in. Each step appends in branch-listing order,
     * so the one sort is what makes the answer the convention's — the same sort
     * every --all runs over its own set. */
    profile_order(&profiles);

    return profiles;
}

/**
 * Walk visitor: the label a claim stands under, noted
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The labels noted so far (bool[LABEL_COUNT])
 * @return NULL: noting a label fails nowhere
 */
static error_t profile_note_label(const branch_claim_t *claim, void *payload) {
    bool *claimed = payload;

    /* Every name the walk shows is under a label: a blob's passed the walk's
     * own gate and shape check, a directory claim's key the sheet's parse
     * (core/branch.h) */
    claimed[label_of(claim->storage_path)] = true;

    return NULL;
}

/**
 * Does this profile's branch need a deployment target?
 *
 * The labels its walk shows, each asked of a table that binds nothing — HOME
 * and the sentinel alone — in a frame of the call's own: a label with no root
 * there is one only a binding places, and the product is a bool.
 */
error_t profile_needs_target(branch_t *branch, bool *needs_target) {
    CHECK_NULL(branch);
    CHECK_NULL(needs_target);

    *needs_target = false;

    /* The labels the branch claims anything under, read as the view is shown
     * them: one strict walk, so a sheet that will not load and a tree the walk
     * refuses are the answer's failure here, as they are the view build's */
    bool claimed[LABEL_COUNT] = { false };
    error_t err = branch_walk(branch, BRANCH_READ_STRICT, profile_note_label, claimed);
    if (err) return err;

    /* Each asked of the table no state row can produce, for the profile's own
     * root of it: one with none there is placed by a binding alone, and which
     * labels a binding places is the table's to say (infra/mount.h
     * mount_table_build), so no label is named here */
    arena_t *frame = arena_create(0);
    mount_table_t *mounts = NULL;
    err = mount_table_build(frame, NULL, 0, &mounts);
    for (label_t label = LABEL_HOME; !err && label < LABEL_COUNT; label++) {
        if (claimed[label] && !mount_root_of(mounts, branch_profile(branch), label)) {
            *needs_target = true;
        }
    }
    arena_free(frame);

    return err;
}
