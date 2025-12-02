/**
 * workspace.c - Workspace abstraction implementation
 *
 * Manages three-state consistency: Profile (git), Deployment (state.db), Filesystem (disk).
 * Detects and categorizes divergence to prevent data loss and enable safe operations.
 *
 * Metadata Architecture:
 * Profiles layer with precedence (global < OS < host). The merged_metadata map
 * pre-applies precedence during workspace_load(), ensuring all analysis functions
 * compare against the "winning" metadata. This prevents false divergence when
 * multiple profiles track the same path with different metadata.
 *
 * Key Design:
 * - merged_metadata: Single hashmap with precedence already applied
 * - Maps: key -> metadata_item_t* (borrowed pointers from metadata_cache)
 * - Key interpretation: Both FILES and DIRECTORIES use storage_path (portable)
 * - Built once in workspace_load(), used by all analysis functions
 */

#include "workspace.h"

#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "core/ignore.h"
#include "crypto/encryption.h"
#include "crypto/keymanager.h"
#include "crypto/policy.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "utils/config.h"
#include "utils/hashmap.h"
#include "utils/privilege.h"
#include "utils/string.h"

/**
 * Merged metadata entry (internal structure)
 *
 * Pairs a metadata item with its source profile name to track provenance
 * after profile precedence is applied.
 */
typedef struct {
    const metadata_item_t *item;      /* Borrowed from metadata_cache */
    const char *profile_name;         /* Which profile provided this (borrowed) */
} merged_metadata_entry_t;

/**
 * Workspace structure
 *
 * Contains indexed views of all three states plus divergence analysis.
 * Uses hashmaps for O(1) lookups during analysis.
 */
struct workspace {
    git_repository *repo;            /* Borrowed reference */

    /* State data */
    manifest_t *manifest;            /* Profile state (owned) */
    state_t *state;                  /* Deployment state (owned or borrowed) */
    bool owns_state;                 /* True if state is owned, false if borrowed */
    profile_list_t *profiles;        /* Selected profiles for this workspace (borrowed) */
    hashmap_t *profile_index;        /* Maps profile_name -> profile_t* (for O(1) lookup) */

    /* Encryption and caching infrastructure */
    keymanager_t *keymanager;        /* Borrowed from global */
    content_cache_t *content_cache;  /* Owned - caches decrypted content */
    hashmap_t *metadata_cache;       /* Owned - maps profile_name -> metadata_t* */

    /* Unified metadata view with profile precedence applied */
    hashmap_t *merged_metadata;      /* Owned map: key -> merged_metadata_entry_t* */
    merged_metadata_entry_t *merged_entries;  /* Owned array of entries */
    size_t merged_count;
    size_t merged_capacity;

    /* Divergence tracking */
    workspace_item_t *diverged;      /* Array of diverged items (files and directories) */
    size_t diverged_count;
    size_t diverged_capacity;
    hashmap_t *diverged_index;       /* Maps filesystem_path -> array index+1 (as void*) */

    /* Status cache */
    workspace_status_t status;
    bool status_computed;
};

/**
 * Get cached metadata for profile
 *
 * Helper function to retrieve metadata from the workspace cache.
 * Returns NULL if profile has no metadata (non-fatal).
 *
 * @param ws Workspace (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @return Metadata or NULL if not available
 */
static const metadata_t *ws_get_metadata(
    const workspace_t *ws,
    const char *profile_name
) {
    if (!ws || !ws->metadata_cache || !profile_name) {
        return NULL;
    }
    return hashmap_get(ws->metadata_cache, profile_name);
}

/**
 * Create empty workspace
 */
static error_t *workspace_create_empty(
    git_repository *repo,
    profile_list_t *profiles,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    workspace_t *ws = calloc(1, sizeof(workspace_t));
    if (!ws) {
        return ERROR(ERR_MEMORY, "Failed to allocate workspace");
    }

    ws->repo = repo;
    ws->profiles = profiles;  /* Borrowed reference */

    ws->profile_index = hashmap_create(32);  /* Initial capacity for profiles */
    if (!ws->profile_index) {
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create profile index");
    }

    ws->diverged_index = hashmap_create(256);  /* Initial capacity */
    if (!ws->diverged_index) {
        hashmap_free(ws->profile_index, NULL);
        free(ws);
        return ERROR(ERR_MEMORY, "Failed to create diverged index");
    }

    /* Build profile index for O(1) profile lookup */
    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];
        error_t *err = hashmap_set(ws->profile_index, profile->name, profile);
        if (err) {
            hashmap_free(ws->diverged_index, NULL);
            hashmap_free(ws->profile_index, NULL);
            free(ws);
            return error_wrap(err, "Failed to index profile");
        }
    }

    ws->diverged = NULL;
    ws->diverged_count = 0;
    ws->diverged_capacity = 0;

    ws->status = WORKSPACE_CLEAN;
    ws->status_computed = false;

    *out = ws;
    return NULL;
}

/**
 * Check for metadata (mode and ownership) divergence (data-centric design)
 *
 * Compares filesystem metadata with expected values to detect changes in
 * permissions (mode) and ownership (user/group). Always checks both mode and
 * ownership independently, setting flags for each.
 *
 * Data-centric approach: Accepts values directly instead of structs, enabling use with
 * both VWD cache (file_entry_t) and metadata (metadata_item_t) without conversion.
 * This eliminates Git loads for files (uses VWD cache) while preserving metadata
 * functionality for directories.
 *
 * @param expected_mode Expected permission mode (0 = skip mode check, no metadata tracked)
 * @param expected_owner Expected owner username (NULL = skip owner check)
 * @param expected_group Expected group name (NULL = skip group check)
 * @param fs_path Filesystem path to check (must not be NULL, for error messages)
 * @param st File stat data (must not be NULL, pre-captured by caller)
 * @param out_mode_differs Output flag for mode divergence (must not be NULL)
 * @param out_ownership_differs Output flag for ownership divergence (must not be NULL)
 * @return Error or NULL on success
 */
error_t *check_item_metadata_divergence(
    mode_t expected_mode,
    const char *expected_owner,
    const char *expected_group,
    const struct stat *st,
    bool *out_mode_differs,
    bool *out_ownership_differs
) {
    CHECK_NULL(st);
    CHECK_NULL(out_mode_differs);
    CHECK_NULL(out_ownership_differs);

    /* Clear output flags */
    *out_mode_differs = false;
    *out_ownership_differs = false;

    /* Check full mode (all permission bits, not just executable) */
    if (expected_mode > 0) {
        mode_t actual_mode = st->st_mode & 0777;
        if (actual_mode != expected_mode) {
            *out_mode_differs = true;
        }
    }

    /* Check ownership - only when running as root AND expected values provided */
    bool running_as_root = privilege_is_elevated();
    bool has_ownership = (expected_owner != NULL || expected_group != NULL);

    if (running_as_root && has_ownership) {
        bool owner_differs = false;
        bool group_differs = false;

        /* Check owner independently */
        if (expected_owner) {
            struct passwd *pwd = getpwuid(st->st_uid);
            if (pwd && pwd->pw_name) {
                if (strcmp(expected_owner, pwd->pw_name) != 0) {
                    owner_differs = true;
                }
            } else {
                /* getpwuid failed - orphaned UID or system error
                 * Treat as divergence: unknown ≠ expected (security-first) */
                owner_differs = true;
            }
        }

        /* Check group independently - no short-circuit */
        if (expected_group) {
            struct group *grp = getgrgid(st->st_gid);
            if (grp && grp->gr_name) {
                if (strcmp(expected_group, grp->gr_name) != 0) {
                    group_differs = true;
                }
            } else {
                /* getgrgid failed - orphaned GID or system error
                 * Treat as divergence: unknown ≠ expected (security-first) */
                group_differs = true;
            }
        }

        if (owner_differs || group_differs) {
            *out_ownership_differs = true;
        }
    }

    return NULL;
}

/**
 * Add diverged item to workspace
 *
 * Adds a file or directory with divergence to the workspace tracking list.
 *
 * @param ws Workspace context (must not be NULL)
 * @param filesystem_path Target path on filesystem (must not be NULL)
 * @param storage_path Path in profile (can be NULL for directories)
 * @param profile Source profile name (can be NULL for orphans)
 * @param old_profile Previous profile from state (can be NULL, caller must free on error)
 * @param state Where the item exists (deployed/undeployed/etc.)
 * @param divergence What's wrong with it (bit flags, can combine)
 * @param item_kind FILE or DIRECTORY (explicit type)
 * @param on_filesystem Exists on actual filesystem
 * @param profile_enabled Is source profile in enabled list?
 * @param profile_changed Has owning profile changed vs state?
 */
static error_t *workspace_add_diverged(
    workspace_t *ws,
    const char *filesystem_path,
    const char *storage_path,
    const char *profile,
    char *old_profile,
    workspace_state_t state,
    divergence_type_t divergence,
    workspace_item_kind_t item_kind,
    bool on_filesystem,
    bool profile_enabled,
    bool profile_changed
) {
    CHECK_NULL(ws);
    CHECK_NULL(filesystem_path);

    /* Grow array if needed */
    if (ws->diverged_count >= ws->diverged_capacity) {
        size_t new_capacity = ws->diverged_capacity == 0 ? 32 : ws->diverged_capacity * 2;
        workspace_item_t *new_diverged = realloc(ws->diverged,
                                                 new_capacity * sizeof(workspace_item_t));
        if (!new_diverged) {
            return ERROR(ERR_MEMORY, "Failed to grow diverged array");
        }
        ws->diverged = new_diverged;
        ws->diverged_capacity = new_capacity;
    }

    /* Add entry */
    workspace_item_t *entry = &ws->diverged[ws->diverged_count];
    memset(entry, 0, sizeof(workspace_item_t));

    entry->filesystem_path = strdup(filesystem_path);
    entry->storage_path = storage_path ? strdup(storage_path) : NULL;
    entry->profile = profile ? strdup(profile) : NULL;
    entry->metadata_profile = NULL;  /* Will be set below if metadata exists */

    /* Lookup profile pointer from profile_index (borrowed, can be NULL if profile not in enabled set) */
    entry->source_profile = profile ? hashmap_get(ws->profile_index, profile) : NULL;

    entry->state = state;
    entry->divergence = divergence;
    entry->item_kind = item_kind;
    entry->on_filesystem = on_filesystem;
    entry->profile_enabled = profile_enabled;
    entry->profile_changed = profile_changed;
    entry->old_profile = old_profile;  /* Ownership transfers on success (can be NULL) */

    if (!entry->filesystem_path ||
        (storage_path && !entry->storage_path) ||
        (profile && !entry->profile)) {
        free(entry->filesystem_path);
        free(entry->storage_path);
        free(entry->profile);
        return ERROR(ERR_MEMORY, "Failed to allocate diverged entry");
    }

    /* Check if this item has metadata in merged_metadata and populate provenance
     * Both files and directories use storage_path as key (portable) */
    if (ws->merged_metadata) {
        const char *lookup_key = storage_path;

        if (lookup_key) {
            const merged_metadata_entry_t *meta_entry = hashmap_get(ws->merged_metadata, lookup_key);
            if (meta_entry && meta_entry->profile_name) {
                entry->metadata_profile = strdup(meta_entry->profile_name);
                if (!entry->metadata_profile) {
                    free(entry->filesystem_path);
                    free(entry->storage_path);
                    free(entry->profile);
                    return ERROR(ERR_MEMORY, "Failed to allocate metadata_profile");
                }
            }
        }
    }

    /* Store array index in hashmap for O(1) lookup */
    error_t *err = hashmap_set(ws->diverged_index, entry->filesystem_path,
                              (void *)(uintptr_t)(ws->diverged_count + 1));
    if (err) {
        free(entry->filesystem_path);
        free(entry->storage_path);
        free(entry->profile);
        free(entry->metadata_profile);
        return error_wrap(err, "Failed to index diverged entry");
    }

    ws->diverged_count++;

    return NULL;
}

/**
 * Fast OID-based content verification for non-encrypted files
 *
 * Computes SHA-1 hash of filesystem file and compares to expected blob OID.
 * This optimization avoids expensive Git blob loading from pack files
 *
 * IMPORTANT: Only call for NON-ENCRYPTED files. For encrypted files, the
 * blob_oid is the hash of ciphertext, while the filesystem contains plaintext.
 *
 * Returns standard compare_result_t for seamless integration:
 * - CMP_EQUAL:     Hash matches (file content unchanged)
 * - CMP_DIFFERENT: Hash differs (content was modified)
 * - CMP_TYPE_DIFF: Type mismatch (expected file but found symlink, or vice versa)
 * - CMP_MISSING:   File doesn't exist (TOCTOU safety - deleted after initial check)
 *
 * STAT PROPAGATION: Always captures stat when file exists, enabling caller's
 * permission checking without redundant syscall. This is critical for the
 * two-phase permission checking in analyze_file_divergence().
 *
 * @param blob_oid Expected blob OID from manifest (must not be NULL)
 * @param filesystem_path Path to file on disk (must not be NULL)
 * @param expected_mode Expected git filemode (BLOB, BLOB_EXECUTABLE, or LINK)
 * @param result Output: comparison result (must not be NULL)
 * @param out_stat Output: captured stat for permission checking (can be NULL)
 * @return Error or NULL on success
 */
static error_t *verify_oid_matches_disk(
    const git_oid *blob_oid,
    const char *filesystem_path,
    git_filemode_t expected_mode,
    compare_result_t *result,
    struct stat *out_stat
) {
    CHECK_NULL(blob_oid);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(result);

    /* Step 1: Stat file for type check and stat propagation
     *
     * We must stat the file to:
     * 1. Verify file type matches expected (file vs symlink)
     * 2. Capture stat for caller's permission checking
     *
     * Using lstat() to not follow symlinks - we need to detect symlinks.
     */
    struct stat st;
    if (lstat(filesystem_path, &st) != 0) {
        if (errno == ENOENT) {
            /* File doesn't exist - TOCTOU race: deleted after initial check */
            *result = CMP_MISSING;
            if (out_stat) {
                memset(out_stat, 0, sizeof(*out_stat));
            }
            return NULL;
        }
        return ERROR(ERR_FS, "Failed to stat '%s': %s", filesystem_path, strerror(errno));
    }

    /* Propagate stat to caller for permission checking */
    if (out_stat) {
        memcpy(out_stat, &st, sizeof(struct stat));
    }

    /* Step 2: Type verification and hash computation */
    git_oid computed;

    if (expected_mode == GIT_FILEMODE_LINK) {
        /* Expected symlink - verify type matches */
        if (!S_ISLNK(st.st_mode)) {
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        /* Hash symlink target string
         *
         * Git stores symlinks as blobs containing the target path as raw bytes.
         * We read the target and hash it identically to how Git would.
         */
        char *target = NULL;
        error_t *err = fs_read_symlink(filesystem_path, &target);
        if (err) {
            return error_wrap(err, "Failed to read symlink '%s'", filesystem_path);
        }

        int ret = git_odb_hash(&computed, target, strlen(target), GIT_OBJECT_BLOB);
        free(target);

        if (ret != 0) {
            const git_error *git_err = git_error_last();
            return ERROR(ERR_GIT, "Failed to hash symlink target: %s",
                         git_err ? git_err->message : "unknown error");
        }
    } else {
        /* Expected regular file (BLOB or BLOB_EXECUTABLE) */
        if (S_ISLNK(st.st_mode)) {
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        if (!S_ISREG(st.st_mode)) {
            /* Not a regular file (directory, device, FIFO, socket, etc.) */
            *result = CMP_TYPE_DIFF;
            return NULL;
        }

        /* Hash file directly from path
         *
         * git_odb_hashfile() streams the file content and computes the
         * standard Git blob hash: SHA-1("blob <size>\0" + content).
         * This uses constant memory regardless of file size.
         */
        int ret = git_odb_hashfile(&computed, filesystem_path, GIT_OBJECT_BLOB);
        if (ret != 0) {
            const git_error *git_err = git_error_last();
            return ERROR(ERR_GIT, "Failed to hash file '%s': %s", filesystem_path,
                         git_err ? git_err->message : "unknown error");
        }
    }

    /* Step 3: Compare computed hash to expected blob OID */
    *result = git_oid_equal(blob_oid, &computed) ? CMP_EQUAL : CMP_DIFFERENT;
    return NULL;
}

/**
 * Analyze divergence for a single file using VWD cache
 *
 * This function uses the VWD (Virtual Working Directory) cache stored in
 * manifest_entry to perform divergence detection without database queries.
 * All expected state (blob_oid, type, deployed_at, etc.) is cached in
 * the manifest entry during workspace load.
 *
 * @param ws Workspace (must not be NULL)
 * @param manifest_entry Manifest entry with VWD cache (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *analyze_file_divergence(
    workspace_t *ws,
    const file_entry_t *manifest_entry
) {
    CHECK_NULL(ws);
    CHECK_NULL(manifest_entry);

    const char *fs_path = manifest_entry->filesystem_path;
    const char *storage_path = manifest_entry->storage_path;
    const char *profile = manifest_entry->source_profile->name;

    /* Determine if entry came from state database using VWD cache
     *
     * If manifest was built from state, VWD fields are populated (blob_oid != NULL).
     * If manifest was built from Git, VWD fields are NULL/0.
     *
     * blob_oid is the most reliable indicator because it's always populated
     * during sync_entry_to_state() when writing to the manifest table.
     */
    bool in_state = (manifest_entry->blob_oid != NULL);

    bool on_filesystem = fs_lexists(fs_path);

    /* Divergence accumulator (bit flags, can combine) */
    divergence_type_t divergence = DIVERGENCE_NONE;

    /* State will be determined in PHASE 2 based on deployment status */
    workspace_state_t state = WORKSPACE_STATE_DEPLOYED;

    /* PHASE 1: Content and type analysis (if file exists and in state)
     * Buffer-based comparison for accurate divergence detection.
     *
     * Architecture:
     * - Use blob_oid from VWD cache (when in_state) for content loading
     * - Extract expected mode from VWD cache type field
     * - Compare directly to filesystem file (compare_buffer_to_disk)
     * - Capture stat for permission checking (zero extra syscalls)
     *
     * This provides:
     * - Architectural consistency (blob_oid unification)
     * - Accurate byte-level comparison with early exit
     * - Transparent encryption handling via content cache
     * - Stat propagation (single stat used for all checks)
     * - TOCTOU-aware (handles files deleted during analysis)
     */
    if (on_filesystem && in_state && manifest_entry->blob_oid) {
        /* Parse blob_oid from VWD cache (defensive validation) */
        git_oid blob_oid;
        if (git_oid_fromstr(&blob_oid, manifest_entry->blob_oid) != 0) {
            return ERROR(ERR_INTERNAL, "Invalid blob_oid '%s' for '%s' (database corruption?)",
                         manifest_entry->blob_oid, fs_path);
        }

        /* Extract expected filemode from VWD cache type field
         *
         * Extracted before comparison strategy selection because both paths
         * need this value. Uses shared helper for consistent mapping.
         */
        git_filemode_t expected_mode = state_type_to_git_filemode(manifest_entry->type);

        /* Prepare for comparison - both paths capture stat for permission checking */
        struct stat file_stat;
        memset(&file_stat, 0, sizeof(file_stat));
        compare_result_t cmp_result;
        error_t *err = NULL;

        /* Comparison strategy selection based on encryption status
         *
         * Non-encrypted: Hash filesystem file and compare OID directly.
         * Encrypted: blob_oid is ciphertext hash; must load, decrypt, compare.
         */
        if (!manifest_entry->encrypted) {
            /* Fast path: OID hash verification */
            err = verify_oid_matches_disk(
                &blob_oid,
                fs_path,
                expected_mode,
                &cmp_result,
                &file_stat
            );
        } else {
            /* SLOW PATH: Content comparison for encrypted files
             *
             * Content cache provides:
             * - Automatic decryption (uses encrypted flag from VWD cache)
             * - Caching (repeated checks for same blob don't re-decrypt)
             * - Error handling (missing key, corrupt data, etc.)
             */
            const buffer_t *expected_content = NULL;
            err = content_cache_get_from_blob_oid(
                ws->content_cache,
                &blob_oid,
                storage_path,
                profile,
                manifest_entry->encrypted,
                &expected_content
            );

            if (!err) {
                err = compare_buffer_to_disk(
                    expected_content,
                    fs_path,
                    expected_mode,
                    NULL,           /* in_stat: let compare_buffer_to_disk stat */
                    &cmp_result,
                    &file_stat      /* out_stat: capture for permission checking */
                );
            }
            /* Note: Don't free expected_content - cache owns it! */
        }

        if (err) {
            return error_wrap(err, "Failed to verify '%s'", fs_path);
        }

        /* Set divergence flags based on comparison result */
        switch (cmp_result) {
            case CMP_EQUAL:
                /* Content and type match - no divergence from content comparison.
                 * Permission checking happens below. */
                break;

            case CMP_DIFFERENT:
                /* Content differs - accumulate CONTENT flag */
                divergence |= DIVERGENCE_CONTENT;
                break;

            case CMP_TYPE_DIFF:
                /* Type differs (file vs symlink) - this is a blocking condition.
                 * Return immediately with TYPE divergence. */
                return workspace_add_diverged(ws, fs_path, storage_path, profile, NULL,
                                              WORKSPACE_STATE_DEPLOYED, DIVERGENCE_TYPE,
                                              WORKSPACE_ITEM_FILE, on_filesystem, true, false);

            case CMP_MISSING:
                /* TOCTOU race condition: File deleted between fs_lexists() and compare.
                 * Update flag and skip permission checks below. */
                on_filesystem = false;
                break;

            case CMP_UNVERIFIED:
                /* Verification could not be completed.
                 *
                 * This is a defensive fallback for rare edge cases where
                 * comparison could not determine file state. Accumulate
                 * UNVERIFIED flag and continue to permission checks.
                 */
                divergence |= DIVERGENCE_UNVERIFIED;
                break;
        }

        /* PERMISSION CHECKING: Two-phase approach
         *
         * Only check permissions if file still exists and no critical divergence.
         * Guards against TOCTOU race (file deleted during compare) and avoids
         * redundant checks on files with type mismatches.
         *
         * PHASE A: Git filemode (executable bit)
         *   - Check using VWD cache type field (converted to expected_mode)
         *   - Skip symlinks (exec bit doesn't apply)
         *   - Catches: file is 0755 in git but 0644 on disk (or vice versa)
         *
         * PHASE B: Full metadata (all permission bits + ownership)
         *   - Only if metadata exists for this file
         *   - Catches: granular changes like 0600→0644, ownership changes
         *
         * Both phases use the SAME file_stat (captured above), so no
         * extra syscalls. Flags are accumulated with |=.
         */
        if (on_filesystem && cmp_result != CMP_TYPE_DIFF && cmp_result != CMP_MISSING) {
            /* PHASE A: Check executable bit (skip symlinks) */
            if (expected_mode != GIT_FILEMODE_LINK) {
                bool expect_exec = (expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
                bool is_exec = fs_stat_is_executable(&file_stat);

                if (expect_exec != is_exec) {
                    /* Executable bit differs between git and filesystem */
                    divergence |= DIVERGENCE_MODE;
                }
            }

            /* PHASE B: Check full metadata using VWD cache
             *
             * Mode sentinel: manifest_entry->mode == 0 means "no metadata tracked",
             * check will be skipped by check_item_metadata_divergence().
             */
            bool mode_differs = false;
            bool ownership_differs = false;

            error_t *check_err = check_item_metadata_divergence(
                manifest_entry->mode,     /* From VWD cache (mode_t, 0 = no metadata) */
                manifest_entry->owner,    /* From VWD cache (can be NULL) */
                manifest_entry->group,    /* From VWD cache (can be NULL) */
                &file_stat,
                &mode_differs,
                &ownership_differs
            );

            if (check_err) {
                return error_wrap(check_err, "Failed to check metadata for '%s'", fs_path);
            }

            /* Accumulate metadata divergence flags
             *
             * Examples of detected divergence:
             * - Phase A passed (both non-exec), but file is 0600 in VWD, 0644 on disk
             * - Phase A detected exec bit diff, also detects group/other bits differ */
            if (mode_differs) divergence |= DIVERGENCE_MODE;
            if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;
        }
    }

    /* PHASE 2: Reality-based classification
     *
     * SCOPE-BASED ARCHITECTURE:
     * Use deployed_at timestamp to distinguish lifecycle states.
     *
     * deployed_at semantics (from SCOPE_BASED_ARCHITECTURE_PLAN.md Annex A):
     * - deployed_at = 0 → File never deployed by dotta
     * - deployed_at > 0 → File known to dotta (deployed or pre-existing)
     *
     * Classification:
     * 1. File missing + deployed_at = 0 → UNDEPLOYED (needs initial deployment)
     * 2. File missing + deployed_at > 0 → DELETED (was deployed, needs restoration)
     * 3. File present → DEPLOYED (may have divergence)
     */
    if (!on_filesystem) {
        /* File in manifest but missing from filesystem */

        /* Use deployed_at from VWD cache to distinguish never-deployed vs deleted
         *
         * The VWD cache stores the lifecycle timestamp:
         * - deployed_at = 0: File never deployed by dotta
         * - deployed_at > 0: File was deployed or known to dotta */
        if (in_state && manifest_entry->deployed_at > 0) {
            /* File was deployed/known (deployed_at > 0), now deleted */
            state = WORKSPACE_STATE_DELETED;
        } else {
            /* File never deployed (deployed_at = 0) or not in state (manifest from Git) */
            state = WORKSPACE_STATE_UNDEPLOYED;
        }

        /* Clear divergence flags - can't detect divergence on missing files */
        divergence = DIVERGENCE_NONE;
    } else {
        /* File in manifest and on filesystem */
        state = WORKSPACE_STATE_DEPLOYED;
        /* Keep accumulated divergence flags from Phase 1 */
    }

    /* PHASE 3: Profile ownership change detection
     *
     * Check VWD cache for old_profile to detect ownership changes.
     * old_profile is set by manifest layer when file ownership changes
     * (e.g., removed from high-precedence profile, fell back to lower).
     *
     * The old_profile field is persisted in the database and populated
     * into the VWD cache during workspace_build_manifest_from_state().
     * It remains set until acknowledged by successful deployment.
     */
    bool profile_changed = (manifest_entry->old_profile != NULL);
    char *old_profile = profile_changed ? strdup(manifest_entry->old_profile) : NULL;

    /* Add to workspace if there's any state change or divergence */
    if (state != WORKSPACE_STATE_DEPLOYED || divergence != DIVERGENCE_NONE || profile_changed) {
        error_t *err = workspace_add_diverged(ws, fs_path, storage_path, profile, old_profile,
                                              state, divergence, WORKSPACE_ITEM_FILE,
                                              on_filesystem, true, profile_changed);
        if (err) {
            /* On error, free old_profile (ownership only transfers on success) */
            free(old_profile);
            return err;
        }
    } else {
        /* No divergence - free old_profile if allocated */
        free(old_profile);
    }

    return NULL;
}

/**
 * Compute divergence for orphaned file
 *
 * Mirrors analyze_file_divergence() logic but optimized for orphan context.
 * Compares filesystem state against expected state from state database entry.
 *
 * Architecture:
 * - Uses VWD cached metadata (blob_oid, encrypted, mode, owner, group)
 * - Leverages content cache with transparent encryption handling
 * - Two-phase permission checking (exec bit + full metadata)
 * - TOCTOU-aware (handles files deleted/modified during analysis)
 *
 * Performance Safeguards:
 * - 100MB size limit (prevents loading huge files into memory)
 * - Early return on missing files (no wasted work)
 * - Content cache (reuses decrypted content across checks)
 *
 * @param ws Workspace (provides content_cache, repo)
 * @param state_entry State database entry with expected state (VWD cache)
 * @param fs_path Filesystem path
 * @param storage_path Storage path (for AAD in encryption)
 * @param profile Profile name
 * @return Divergence flags or DIVERGENCE_UNVERIFIED on error
 */
static divergence_type_t compute_orphan_divergence(
    workspace_t *ws,
    const state_file_entry_t *state_entry,
    const char *fs_path,
    const char *storage_path,
    const char *profile
) {
    /* Defensive NULL checks */
    if (!ws || !state_entry || !fs_path) {
        return DIVERGENCE_UNVERIFIED;
    }

    /* Step 1: Initial stat for existence check
     *
     * Note: A fresh stat will be captured later by compare_buffer_to_disk()
     * for TOCTOU safety. This initial stat is only for existence validation.
     */
    struct stat initial_stat;
    if (lstat(fs_path, &initial_stat) != 0) {
        /* File doesn't exist - not an error, just means orphan was already removed */
        return DIVERGENCE_NONE;
    }

    /* Step 2: Validate blob_oid (defensive programming)
     *
     * Every state entry SHOULD have blob_oid. If missing, it's data corruption.
     * Handle gracefully rather than crashing.
     */
    if (!state_entry->blob_oid) {
        /* Data corruption: state entry without blob_oid
         * This should never happen, but handle gracefully */
        return DIVERGENCE_UNVERIFIED;
    }

    /* Parse blob OID string to git_oid struct */
    git_oid blob_oid;
    if (git_oid_fromstr(&blob_oid, state_entry->blob_oid) != 0) {
        /* Invalid OID string in state database (corruption) */
        return DIVERGENCE_UNVERIFIED;
    }

    /* Step 3: Extract expected filemode from type field
     *
     * Calculate once, use for both content comparison and mode checking.
     * Uses shared helper for consistent mapping across modules.
     */
    git_filemode_t expected_mode = state_type_to_git_filemode(state_entry->type);

    /* Capture stat for permission checking */
    struct stat fresh_stat;
    memset(&fresh_stat, 0, sizeof(fresh_stat));
    compare_result_t cmp_result;
    error_t *err = NULL;

    /* Step 4: Content and type comparison with strategy selection
     *
     * Non-encrypted: Hash filesystem file and compare OID directly.
     * Encrypted: blob_oid is ciphertext hash; must load, decrypt, compare.
     */
    if (!state_entry->encrypted) {
        /* Fast path: OID hash verification */
        err = verify_oid_matches_disk(
            &blob_oid,
            fs_path,
            expected_mode,
            &cmp_result,
            &fresh_stat
        );

        if (err) {
            /* Hash verification failed (I/O error, permissions, etc.)
             * Return UNVERIFIED to prevent false "clean" indication. */
            error_free(err);
            return DIVERGENCE_UNVERIFIED;
        }
    } else {
        /* SLOW PATH: Content comparison for encrypted files
         *
         * Content cache provides:
         * - Automatic decryption (uses state_entry->encrypted flag)
         * - Caching (repeated checks for same blob don't re-decrypt)
         * - Error handling (missing key, corrupt data, etc.)
         *
         * VWD Pattern: Use state_entry->encrypted directly.
         * This flag was set atomically with blob_oid when entry was synced.
         */
        const buffer_t *expected_content = NULL;
        err = content_cache_get_from_blob_oid(
            ws->content_cache,
            &blob_oid,
            storage_path,
            profile,
            state_entry->encrypted, /* VWD pattern: use cached flag */
            &expected_content
        );

        if (err) {
            /* Cannot load/decrypt content
             *
             * Possible causes:
             * - Encrypted file but no passphrase available (missing key)
             * - Decryption failed (wrong passphrase, corrupted ciphertext)
             * - I/O error reading blob from git
             * - Blob missing from repository (corruption)
             *
             * Conservative approach: Return UNVERIFIED to prevent false "clean" indication.
             * User will see [orphaned, unverified] and can investigate.
             */
            error_free(err);
            return DIVERGENCE_UNVERIFIED;
        }

        /* Step 5: Content and type comparison with stat capture
         *
         * compare_buffer_to_disk() performs:
         * 1. Fresh lstat() (TOCTOU-safe, may detect file deleted/replaced)
         * 2. Type checking (file vs symlink)
         * 3. Content comparison (byte-by-byte)
         *
         * We pass NULL for in_stat to force fresh stat (catches TOCTOU races).
         * We capture out_stat for metadata checking (reuse stat).
         */
        err = compare_buffer_to_disk(
            expected_content,
            fs_path,
            expected_mode,
            NULL,         /* in_stat: Force fresh stat for TOCTOU safety */
            &cmp_result,
            &fresh_stat   /* out_stat: Capture for metadata checking */
        );
        /* Note: Don't free expected_content - cache owns it! */

        if (err) {
            /* Comparison failed (I/O error, permissions, etc.) */
            error_free(err);
            return DIVERGENCE_UNVERIFIED;
        }
    }

    /* Step 6: Interpret comparison result
     *
     * Use switch statement (not if-else) for exhaustive handling.
     * Pattern from analyze_file_divergence() lines 524-549.
     */
    divergence_type_t divergence = DIVERGENCE_NONE;
    bool file_exists = true;  /* Track for permission checking guard */

    switch (cmp_result) {
        case CMP_EQUAL:
            /* Content and type match - continue to permission checking */
            break;

        case CMP_DIFFERENT:
            /* Content differs between Git and filesystem */
            divergence |= DIVERGENCE_CONTENT;
            break;

        case CMP_TYPE_DIFF:
            /* Type differs (file vs symlink vs directory)
             *
             * Note: analyze_file_divergence returns early here, but for orphans
             * we accumulate divergence and check metadata too. This provides
             * more information to the user (e.g., "type + mode divergence").
             */
            divergence |= DIVERGENCE_TYPE;
            break;

        case CMP_MISSING:
            /* TOCTOU race: File deleted between initial lstat() and compare
             *
             * File no longer exists on filesystem. This is not an error - it just
             * means the orphan was already manually removed. Safe to report as
             * DIVERGENCE_NONE (apply will skip it, state will be pruned).
             */
            file_exists = false;
            break;

        case CMP_UNVERIFIED:
            /* Verification could not be completed.
             *
             * This is a defensive fallback for rare edge cases where
             * comparison could not determine file state. Accumulate
             * UNVERIFIED flag and continue to permission checks.
             */
            divergence |= DIVERGENCE_UNVERIFIED;
            break;
    }

    /* Step 7: Permission checking (two-phase, if file still exists)
     *
     * Only check permissions if:
     * 1. File still exists (not deleted in TOCTOU race)
     * 2. No type divergence (type mismatch makes mode checking nonsensical)
     * 3. Verification didn't fail (we have fresh_stat from compare)
     *
     * PHASE A: Git filemode (executable bit)
     *   - Uses expected_mode from Step 5
     *   - Skips symlinks (exec bit doesn't apply)
     *   - Catches: file is 0755 in git but 0644 on disk (or vice versa)
     *
     * PHASE B: Full metadata (all permission bits + ownership)
     *   - Uses check_item_metadata_divergence() helper
     *   - Reuses fresh_stat from Step 6 (zero extra syscalls)
     *   - Skipped if state_entry->mode == 0 (no metadata tracked)
     *   - Separately tracks MODE and OWNERSHIP divergence
     */
    if (file_exists && !(divergence & DIVERGENCE_TYPE)) {
        /* PHASE A: Check executable bit (skip symlinks) */
        if (expected_mode != GIT_FILEMODE_LINK) {
            bool expect_exec = (expected_mode == GIT_FILEMODE_BLOB_EXECUTABLE);
            bool is_exec = fs_stat_is_executable(&fresh_stat);

            if (expect_exec != is_exec) {
                /* Executable bit differs between git and filesystem */
                divergence |= DIVERGENCE_MODE;
            }
        }

        /* PHASE B: Check full metadata using helper function
         *
         * Mode sentinel: state_entry->mode == 0 means "no metadata tracked",
         * check will be skipped by check_item_metadata_divergence().
         *
         * Uses fresh_stat from compare (TOCTOU-safe, consistent view).
         */
        bool mode_differs = false;
        bool ownership_differs = false;

        error_t *check_err = check_item_metadata_divergence(
            state_entry->mode,    /* From VWD cache (mode_t, 0 = no metadata) */
            state_entry->owner,   /* From VWD cache (can be NULL) */
            state_entry->group,   /* From VWD cache (can be NULL) */
            &fresh_stat,          /* Reuse stat from compare (CRITICAL: not initial_stat!) */
            &mode_differs,
            &ownership_differs
        );

        if (check_err) {
            /* Metadata check failed (rare: getpwuid/getgrgid failure)
             * Treat as unverified rather than crashing */
            error_free(check_err);
            return DIVERGENCE_UNVERIFIED;
        }

        /* Accumulate metadata divergence flags
         *
         * OWNERSHIP is tracked separately for granular reporting.
         */
        if (mode_differs) divergence |= DIVERGENCE_MODE;
        if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;
    }

    return divergence;
}

/**
 * Analyze state for orphaned file entries
 *
 * Detects ALL orphaned files (enabled + disabled profiles) using cleanup
 * module's robust algorithm. Each orphan is marked with profile_enabled
 * flag to enable caller filtering.
 *
 * An entry is orphaned if it exists in state but not in manifest.
 * - Enabled profile orphans: File removed from branch (profile_enabled=true)
 * - Disabled profile orphans: Profile disabled, needs cleanup (profile_enabled=false)
 *
 * Callers filter by profile_enabled:
 * - status: only show profile_enabled=true (enabled profiles)
 * - apply: use all (cleanup disabled profiles too)
 */
static error_t *analyze_orphaned_files(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->manifest);
    CHECK_NULL(ws->manifest->index);
    CHECK_NULL(ws->profile_index);

    error_t *err = NULL;
    state_file_entry_t *state_files = NULL;
    size_t state_count = 0;

    /* Get all files in state */
    err = state_get_all_files(ws->state, &state_files, &state_count);
    if (err) {
        return error_wrap(err, "Failed to get state files");
    }

    /* Early exit: no files in state means no orphans */
    if (state_count == 0) {
        state_free_all_files(state_files, state_count);
        return NULL;
    }

    /* Identify orphans: in state, not in manifest */
    for (size_t i = 0; i < state_count; i++) {
        const state_file_entry_t *state_entry = &state_files[i];

        const char *fs_path = state_entry->filesystem_path;
        const char *storage_path = state_entry->storage_path;
        const char *profile = state_entry->profile;

        /* Check if file exists in manifest (O(1) lookup using index) */
        void *idx_ptr = hashmap_get(ws->manifest->index, fs_path);
        file_entry_t *manifest_entry = NULL;
        if (idx_ptr) {
            size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
            manifest_entry = &ws->manifest->entries[idx];
        }

        if (!manifest_entry) {
            /* Orphaned: in state, not in manifest (out of scope) */
            bool profile_enabled = (hashmap_get(ws->profile_index, profile) != NULL);
            bool on_filesystem = fs_lexists(fs_path);

            /* Compute divergence for orphaned file
             *
             * Only check divergence if file exists on filesystem. If file already
             * deleted, divergence is meaningless (can't compare to non-existent file).
             *
             * This analysis enables status to predict apply behavior:
             * - DIVERGENCE_NONE → Clean orphan, will be removed
             * - DIVERGENCE_CONTENT/TYPE → Modified, apply will skip (safety check)
             * - DIVERGENCE_MODE/OWNERSHIP → Metadata changed, apply will skip
             * - DIVERGENCE_UNVERIFIED → Cannot verify, apply will skip
             */
            divergence_type_t divergence = DIVERGENCE_NONE;
            if (on_filesystem) {
                divergence = compute_orphan_divergence(
                    ws,
                    state_entry,
                    fs_path,
                    storage_path,
                    profile
                );
            }

            err = workspace_add_diverged(
                ws,
                fs_path,
                storage_path,
                profile,
                NULL,             /* No old_profile for orphans */
                WORKSPACE_STATE_ORPHANED,  /* State: in deployment state, not in profile */
                divergence,       /* Divergence: computed from filesystem comparison */
                WORKSPACE_ITEM_FILE,
                on_filesystem,
                profile_enabled,
                false             /* No profile change for orphans */
            );

            if (err) {
                state_free_all_files(state_files, state_count);
                return error_wrap(err, "Failed to add orphaned file");
            }
        }
    }

    state_free_all_files(state_files, state_count);
    return NULL;
}

/**
 * Analyze state for orphaned directory entries
 *
 * Mirrors analyze_orphaned_files but compares state directories
 * against merged_metadata instead of manifest.
 *
 * Detects ALL orphaned directories (enabled + disabled profiles) and
 * marks each with profile_enabled flag for caller filtering.
 *
 * Directories in state but not in any profile's metadata are orphaned
 * and should be pruned.
 */
static error_t *analyze_orphaned_directories(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->merged_metadata);
    CHECK_NULL(ws->profile_index);

    error_t *err = NULL;
    state_directory_entry_t *state_dirs = NULL;
    size_t state_count = 0;

    /* Get all directories in state */
    err = state_get_all_directories(ws->state, &state_dirs, &state_count);
    if (err) {
        return error_wrap(err, "Failed to get state directories");
    }

    /* Early exit: no directories in state means no orphans */
    if (state_count == 0) {
        state_free_all_directories(state_dirs, state_count);
        return NULL;
    }

    /* Identify orphans: in state, not in merged_metadata */
    for (size_t i = 0; i < state_count; i++) {
        const state_directory_entry_t *state_entry = &state_dirs[i];
        const char *dir_path = state_entry->filesystem_path;
        const char *storage_path = state_entry->storage_path;
        const char *profile = state_entry->profile;

        /* Check if directory exists in merged_metadata (O(1) lookup)
         * For directories: key in merged_metadata = storage_path (portable) */
        const merged_metadata_entry_t *meta_entry =
            hashmap_get(ws->merged_metadata, storage_path);

        /* Orphaned if: not in metadata OR wrong kind (defensive check) */
        bool is_orphaned = (!meta_entry ||
                            meta_entry->item->kind != METADATA_ITEM_DIRECTORY);

        if (is_orphaned) {
            /* Orphaned: in state, not in metadata */
            bool profile_enabled = (hashmap_get(ws->profile_index, profile) != NULL);
            bool on_filesystem = fs_exists(dir_path);

            err = workspace_add_diverged(
                ws,
                dir_path,
                storage_path,
                profile,
                NULL,             /* No old_profile for orphans */
                WORKSPACE_STATE_ORPHANED,  /* State: in state, not in profile */
                DIVERGENCE_NONE,           /* Divergence: none */
                WORKSPACE_ITEM_DIRECTORY,
                on_filesystem,
                profile_enabled,
                false             /* No profile change for orphans */
            );

            if (err) {
                state_free_all_directories(state_dirs, state_count);
                return error_wrap(err, "Failed to add orphaned directory");
            }
        }
    }

    state_free_all_directories(state_dirs, state_count);
    return NULL;
}

/**
 * Analyze state for orphaned entries (files + directories)
 *
 * Unified orphan detection for both files and directories.
 * Detects ALL orphans regardless of profile scope, marking each
 * with profile_enabled flag for caller filtering.
 */
static error_t *analyze_orphaned_state(workspace_t *ws) {
    CHECK_NULL(ws);

    error_t *err = NULL;

    /* Analyze file orphans */
    err = analyze_orphaned_files(ws);
    if (err) {
        return error_wrap(err, "Failed to analyze orphaned files");
    }

    /* Analyze directory orphans */
    err = analyze_orphaned_directories(ws);
    if (err) {
        return error_wrap(err, "Failed to analyze orphaned directories");
    }

    return NULL;
}

/**
 * Analyze divergence for all files in manifest using VWD cache
 *
 * Compares each file in the manifest against filesystem reality to detect
 * modifications, deletions, and undeployed files.
 *
 * Performance: O(N) where N = manifest count. No database queries needed
 * because all expected state is cached in the manifest entries (VWD cache).
 * This eliminates the previous N+1 query problem.
 */
static error_t *analyze_files_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);
    CHECK_NULL(ws->state);

    /* Analyze each file in manifest using VWD cache
     *
     * The manifest_entry contains all necessary state information in its
     * VWD cache fields (blob_oid, type, deployed_at, etc.), so we
     * don't need to query the database for each file. This eliminates
     * N individual state_get_file() queries. */
    for (size_t i = 0; i < ws->manifest->count; i++) {
        const file_entry_t *manifest_entry = &ws->manifest->entries[i];

        /* Analyze this file using VWD cache (no database query needed) */
        error_t *err = analyze_file_divergence(ws, manifest_entry);

        if (err) {
            return err;
        }
    }

    return NULL;
}

/**
 * Compute workspace status
 */
static workspace_status_t compute_workspace_status(const workspace_t *ws) {
    if (!ws) {
        return WORKSPACE_INVALID;
    }

    bool has_orphaned = false;
    bool has_warnings = false;

    for (size_t i = 0; i < ws->diverged_count; i++) {
        const workspace_item_t *item = &ws->diverged[i];

        switch (item->state) {
            case WORKSPACE_STATE_ORPHANED:
                has_orphaned = true;
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_DELETED:
            case WORKSPACE_STATE_UNTRACKED:
                has_warnings = true;
                break;

            case WORKSPACE_STATE_DEPLOYED:
                /* Check metadata divergence */
                if (item->divergence != DIVERGENCE_NONE) {
                    has_warnings = true;
                }
                break;
        }
    }

    if (has_orphaned) {
        return WORKSPACE_INVALID;
    } else if (has_warnings) {
        return WORKSPACE_DIRTY;
    } else {
        return WORKSPACE_CLEAN;
    }
}

/**
 * Recursively scan directory for untracked files
 */
static error_t *scan_directory_for_untracked(
    const char *dir_path,
    const char *storage_prefix,
    const char *profile,
    ignore_context_t *ignore_ctx,
    workspace_t *ws
) {
    CHECK_NULL(dir_path);
    CHECK_NULL(storage_prefix);
    CHECK_NULL(profile);
    CHECK_NULL(ws);

    DIR *dir = opendir(dir_path);
    if (!dir) {
        /* Non-fatal: directory might have been deleted or permissions issue */
        return NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Build full path */
        char *full_path = str_format("%s/%s", dir_path, entry->d_name);
        if (!full_path) {
            closedir(dir);
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }

        /* Check if path exists and get its type (single syscall, don't follow symlinks) */
        struct stat st;
        if (lstat(full_path, &st) != 0) {
            /* Path might have been deleted (race condition) */
            free(full_path);
            continue;
        }

        /* Check if ignored */
        bool is_dir = S_ISDIR(st.st_mode);
        if (ignore_ctx) {
            bool ignored = false;
            error_t *err = ignore_should_ignore(ignore_ctx, full_path, is_dir, &ignored);
            if (!err && ignored) {
                free(full_path);
                continue;
            }
            error_free(err);  /* Ignore errors in ignore checking */
        }

        if (is_dir) {
            /* Recurse into subdirectory */
            char *sub_storage_prefix = str_format("%s/%s", storage_prefix, entry->d_name);
            if (!sub_storage_prefix) {
                free(full_path);
                closedir(dir);
                return ERROR(ERR_MEMORY, "Failed to allocate storage prefix");
            }

            error_t *err = scan_directory_for_untracked(
                full_path,
                sub_storage_prefix,
                profile,
                ignore_ctx,
                ws
            );

            free(sub_storage_prefix);
            free(full_path);

            if (err) {
                closedir(dir);
                return err;
            }
        } else {
            /* Check if this file is already in manifest (O(1) lookup using index) */
            void *idx_ptr = hashmap_get(ws->manifest->index, full_path);
            file_entry_t *manifest_entry = NULL;
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
                manifest_entry = &ws->manifest->entries[idx];
            }

            if (!manifest_entry) {
                /* This is an untracked file! */
                char *storage_path = str_format("%s/%s", storage_prefix, entry->d_name);
                if (!storage_path) {
                    free(full_path);
                    closedir(dir);
                    return ERROR(ERR_MEMORY, "Failed to allocate storage path");
                }

                error_t *err = workspace_add_diverged(
                    ws,
                    full_path,
                    storage_path,
                    profile,
                    NULL,  /* No old_profile for untracked */
                    WORKSPACE_STATE_UNTRACKED,  /* State: on filesystem in tracked dir */
                    DIVERGENCE_NONE,            /* Divergence: none */
                    WORKSPACE_ITEM_FILE,
                    true,   /* on filesystem */
                    true,   /* profile_enabled */
                    false   /* No profile change */
                );

                free(storage_path);
                free(full_path);

                if (err) {
                    closedir(dir);
                    return err;
                }
            } else {
                free(full_path);
            }
        }
    }

    closedir(dir);
    return NULL;
}

/**
 * Analyze tracked directories for untracked files
 *
 * Only scans tracked directories for profiles in the enabled profile list.
 */
static error_t *analyze_untracked_files(
    workspace_t *ws,
    const dotta_config_t *config
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->profiles);

    error_t *err = NULL;

    if (ws->profiles->count == 0) {
        return NULL;  /* No profiles to analyze */
    }

    /* Scan tracked directories from each enabled profile's state database */
    for (size_t p = 0; p < ws->profiles->count; p++) {
        const char *profile_name = ws->profiles->profiles[p].name;

        /* Get tracked directories from state database for this profile */
        state_directory_entry_t *directories = NULL;
        size_t dir_count = 0;
        err = state_get_directories_by_profile(ws->state, profile_name, &directories, &dir_count);
        if (err) {
            fprintf(stderr, "warning: failed to load directories for profile '%s': %s\n",
                    profile_name, err->message);
            error_free(err);
            err = NULL;
            continue;
        }

        if (dir_count == 0) {
            /* Profile has no tracked directories - skip */
            state_free_all_directories(directories, dir_count);
            continue;
        }

        /* Create profile-specific ignore context once for all directories */
        ignore_context_t *ignore_ctx = NULL;
        err = ignore_context_create(
            ws->repo,
            config,
            profile_name,
            NULL,
            0,
            &ignore_ctx
        );

        if (err) {
            /* Non-fatal: continue without ignore filtering */
            fprintf(stderr, "warning: failed to load ignore patterns for profile '%s': %s\n",
                    profile_name, err->message);
            error_free(err);
            err = NULL;
            ignore_ctx = NULL;
        }

        /* Scan each tracked directory */
        for (size_t i = 0; i < dir_count; i++) {
            const state_directory_entry_t *dir_entry = &directories[i];

            /* Skip STATE_INACTIVE directories - they're orphaned and shouldn't be scanned
             *
             * ARCHITECTURE: STATE_INACTIVE directories are staged for removal.
             * We should NOT scan them for untracked files because:
             * 1. The directory is being removed (profile disabled)
             * 2. Scanning would report spurious untracked files
             * 3. The profile may be re-enabled later (directories reactivated)
             *
             * This ensures untracked file detection only applies to active directories.
             */
            if (dir_entry->state && strcmp(dir_entry->state, STATE_INACTIVE) == 0) {
                continue;  /* Skip silently - these will be handled by orphan detection */
            }

            /* State directory entries contain:
             * - filesystem_path: Already resolved with custom_prefix (VWD principle)
             * - storage_path: Portable path for storage
             */

            /* Use filesystem path directly from state (already resolved) */
            const char *filesystem_path = dir_entry->filesystem_path;

            /* Check if directory still exists */
            if (!fs_exists(filesystem_path)) {
                continue;
            }

            /* Scan this directory for untracked files */
            err = scan_directory_for_untracked(
                filesystem_path,           /* Already resolved filesystem path */
                dir_entry->storage_path,   /* Portable storage path */
                profile_name,
                ignore_ctx,
                ws
            );

            if (err) {
                /* Non-fatal: continue with other directories */
                fprintf(stderr, "warning: failed to scan directory '%s' in profile '%s': %s\n",
                        filesystem_path, profile_name, err->message);
                error_free(err);
                err = NULL;
            }
        }

        /* Free ignore context after scanning all directories in this profile */
        ignore_context_free(ignore_ctx);

        /* Free state directory entries for this profile */
        state_free_all_directories(directories, dir_count);
    }

    return NULL;
}

/**
 * Analyze directory metadata for divergence
 *
 * Detects:
 * - DELETED state: Directory removed from filesystem
 * - DIVERGENCE_MODE: Directory permissions changed
 * - DIVERGENCE_OWNERSHIP: Directory owner/group changed (requires root)
 *
 * ARCHITECTURE: Uses state (VWD) instead of metadata (Git) for directory resolution.
 * State contains filesystem_path already resolved with custom_prefix, enabling
 * correct divergence detection for custom/ prefix directories.
 *
 * @param ws Workspace (must not be NULL, state must be initialized)
 * @return Error or NULL on success
 */
static error_t *analyze_directory_metadata_divergence(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);

    /* Get all tracked directories from state database */
    state_directory_entry_t *directories = NULL;
    size_t dir_count = 0;
    error_t *err = state_get_all_directories(ws->state, &directories, &dir_count);
    if (err) {
        return error_wrap(err, "Failed to load tracked directories from state");
    }

    if (dir_count == 0) {
        state_free_all_directories(directories, dir_count);
        return NULL;  /* No tracked directories */
    }

    /* Check each tracked directory for divergence */
    for (size_t i = 0; i < dir_count; i++) {
        const state_directory_entry_t *dir_entry = &directories[i];

        /* Skip STATE_INACTIVE directories - they're staged for removal
         *
         * ARCHITECTURE: STATE_INACTIVE directories are orphaned and shouldn't
         * participate in divergence analysis. They'll be detected as orphans
         * by analyze_orphaned_directories() and cleaned by apply.
         *
         * This mirrors file handling pattern (workspace.c:1669-1674).
         */
        if (dir_entry->state && strcmp(dir_entry->state, STATE_INACTIVE) == 0) {
            continue;  /* Skip silently - orphan detection will handle this */
        }

        /* State directory entries contain:
         * - filesystem_path: Already resolved with custom_prefix (VWD principle)
         * - storage_path: Portable path
         * - profile: Source profile
         * - mode, owner, group: Expected metadata
         */

        /* Use filesystem path directly from state (already resolved) */
        const char *filesystem_path = dir_entry->filesystem_path;
        const char *storage_path = dir_entry->storage_path;
        const char *profile_name = dir_entry->profile;

        /* Stat directory to get current metadata
         *
         * Use lstat() for both existence and type checking:
         * - ENOENT: Directory truly deleted
         * - Success + !S_ISDIR: Type changed (file, symlink - including broken ones)
         * - Success + S_ISDIR: Actual directory, check metadata  */
        struct stat dir_stat;
        if (lstat(filesystem_path, &dir_stat) != 0) {
            if (errno == ENOENT) {
                /* Directory truly deleted - record divergence */
                err = workspace_add_diverged(
                    ws,
                    filesystem_path,
                    storage_path,
                    profile_name,
                    NULL,  /* No old_profile for directories */
                    WORKSPACE_STATE_DELETED,  /* State: was in profile, removed from filesystem */
                    DIVERGENCE_NONE,          /* Divergence: none (file is gone) */
                    WORKSPACE_ITEM_DIRECTORY,
                    false,  /* on_filesystem (deleted) */
                    true,   /* profile_enabled */
                    false   /* No profile change */
                );

                if (err) {
                    state_free_all_directories(directories, dir_count);
                    return error_wrap(err, "Failed to record deleted directory '%s'",
                                      filesystem_path);
                }
                continue;  /* Successfully recorded, check next directory */
            }

            /* Stat failed for other reason: race condition or permission issue */
            fprintf(stderr, "warning: failed to stat directory '%s': %s\n",
                    filesystem_path, strerror(errno));
            continue;  /* Non-fatal, skip this directory */
        }

        /* Verify it's actually a directory (type may have changed)
         *
         * Type changes (dir → file, dir → symlink) are detected here because:
         * 1. lstat() doesn't follow symlinks, so symlinks are caught
         * 2. S_ISDIR() fails for regular files and symlinks
         *
         * Record DIVERGENCE_TYPE to enable:
         * - status shows [type] divergence
         * - preflight blocks without --force
         * - apply clears and recreates with --force
         */
        if (!S_ISDIR(dir_stat.st_mode)) {
            err = workspace_add_diverged(
                ws,
                filesystem_path,
                storage_path,
                profile_name,
                NULL,  /* No old_profile for directories */
                WORKSPACE_STATE_DEPLOYED,  /* Path exists, just wrong type */
                DIVERGENCE_TYPE,           /* Type changed (dir → file/symlink) */
                WORKSPACE_ITEM_DIRECTORY,
                true,   /* on_filesystem (path exists, wrong type) */
                true,   /* profile_enabled */
                false   /* No profile change */
            );

            if (err) {
                state_free_all_directories(directories, dir_count);
                return error_wrap(err, "Failed to record type change for directory '%s'",
                                  filesystem_path);
            }
            continue;  /* Recorded, move to next directory */
        }

        /* Check metadata divergence using unified helper */
        bool mode_differs = false;
        bool ownership_differs = false;

        err = check_item_metadata_divergence(
            dir_entry->mode,   /* Expected mode from state */
            dir_entry->owner,  /* Expected owner from state */
            dir_entry->group,  /* Expected group from state */
            &dir_stat,
            &mode_differs,
            &ownership_differs
        );

        if (err) {
            state_free_all_directories(directories, dir_count);
            return error_wrap(err, "Failed to check metadata for directory '%s'",
                              filesystem_path);
        }

        /* Record divergence if any metadata differs */
        if (mode_differs || ownership_differs) {
            /* Accumulate divergence flags */
            divergence_type_t divergence = DIVERGENCE_NONE;
            if (mode_differs) divergence |= DIVERGENCE_MODE;
            if (ownership_differs) divergence |= DIVERGENCE_OWNERSHIP;

            err = workspace_add_diverged(
                ws,
                filesystem_path,
                storage_path,
                profile_name,
                NULL,  /* No old_profile for directories */
                WORKSPACE_STATE_DEPLOYED,  /* State: directory exists as expected */
                divergence,                /* Divergence: mode/ownership flags */
                WORKSPACE_ITEM_DIRECTORY,
                true,   /* on_filesystem */
                true,   /* profile_enabled */
                false   /* No profile change */
            );

            if (err) {
                state_free_all_directories(directories, dir_count);
                return error_wrap(err, "Failed to record directory metadata divergence for '%s'",
                                  filesystem_path);
            }
        }
    }

    /* Free state directory entries */
    state_free_all_directories(directories, dir_count);

    return NULL;  /* Success - all directories checked */
}

/**
 * Analyze encryption policy mismatches
 *
 * Detects files that should be encrypted (per auto-encrypt patterns)
 * but are stored as plaintext in the profile.
 *
 * Uses two-tier validation to determine actual encryption state:
 * - Tier 1 (Source of Truth): Checks magic header in git blob
 * - Tier 2 (Defense in Depth): Cross-validates with metadata
 *
 * If magic header and metadata disagree, warns about corruption but
 * uses magic header truth for policy enforcement. This ensures policy
 * violations are always detected even with corrupted metadata.
 *
 * Only checks if:
 * - Encryption is globally enabled
 * - Auto-encrypt patterns are configured
 *
 * Error handling:
 * - Git read errors: Non-fatal, warns and skips file
 * - Metadata corruption: Non-fatal, warns and uses magic header
 * - Pattern match errors: Non-fatal, skips file
 *
 * This is a security-focused check: files matching sensitive patterns
 * (e.g., "*.key", ".ssh/id_*") should be encrypted.
 */
static error_t *analyze_encryption_policy_mismatch(
    workspace_t *ws,
    const dotta_config_t *config
) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->manifest);

    /* Skip if encryption disabled globally */
    if (!config || !config->encryption_enabled) {
        return NULL;
    }

    /* Skip if no auto-encrypt patterns configured */
    if (!config->auto_encrypt_patterns || config->auto_encrypt_pattern_count == 0) {
        return NULL;
    }

    /* Check each file in manifest */
    for (size_t i = 0; i < ws->manifest->count; i++) {
        const file_entry_t *manifest_entry = &ws->manifest->entries[i];
        const char *storage_path = manifest_entry->storage_path;
        const char *profile_name = manifest_entry->source_profile->name;

        /* Check if file should be auto-encrypted */
        bool should_auto_encrypt = false;
        error_t *err = encryption_policy_matches_auto_patterns(
            config,
            storage_path,
            &should_auto_encrypt
        );
        if (err) {
            /* Non-fatal: pattern matching errors shouldn't block status */
            error_free(err);
            continue;
        }

        /* If file doesn't match patterns, no mismatch */
        if (!should_auto_encrypt) {
            continue;
        }

        /* Validate actual encryption state using two-tier validation */
        bool is_encrypted = false;

        /* Lazy-load tree entry for encryption magic header check */
        err = file_entry_ensure_tree_entry((file_entry_t *)manifest_entry, ws->repo);
        if (err) {
            /* Non-fatal: encryption analysis is advisory, skip if unavailable */
            fprintf(stderr, "warning: failed to load tree entry for '%s' in profile '%s': %s\n",
                    storage_path, profile_name, err->message ? err->message : "unknown error");
            error_free(err);
            continue;
        }

        /* Tier 1: Check magic header in blob (source of truth) */
        const git_oid *blob_oid = git_tree_entry_id(manifest_entry->entry);
        git_blob *blob = NULL;
        int git_err = git_blob_lookup(&blob, ws->repo, blob_oid);

        if (git_err != 0) {
            /* Non-fatal: can't read blob - skip this file */
            fprintf(stderr, "warning: failed to read blob for '%s' in profile '%s': %s\n",
                    storage_path, profile_name,
                    git_error_last() ? git_error_last()->message : "unknown error");
            continue;
        }

        const unsigned char *blob_data = git_blob_rawcontent(blob);
        size_t blob_size = (size_t)git_blob_rawsize(blob);
        is_encrypted = encryption_is_encrypted(blob_data, blob_size);

        /* Tier 2: Cross-validate with metadata (defense in depth) */
        const metadata_t *metadata = ws_get_metadata(ws, profile_name);
        if (metadata) {
            const metadata_item_t *meta_entry = NULL;
            error_t *lookup_err = metadata_get_item(metadata, storage_path, &meta_entry);

            if (lookup_err == NULL && meta_entry) {
                /* Validate kind: encryption metadata only applies to files.
                 * This should always be FILE (manifest contains only files), but
                 * check defensively since this is corruption detection code. */
                if (meta_entry->kind != METADATA_ITEM_FILE) {
                    fprintf(stderr,
                        "warning: metadata corruption for '%s' in profile '%s': "
                        "expected FILE, got DIRECTORY. Skipping encryption validation.\n",
                        storage_path, profile_name);
                } else {
                    /* Detect mismatch between magic header and metadata */
                    if (is_encrypted != meta_entry->file.encrypted) {
                        fprintf(stderr,
                            "warning: metadata corruption detected for '%s' in profile '%s'\n"
                            "  Magic header says: %s\n"
                            "  Metadata says: %s\n"
                            "  Using actual state from magic header. To fix, run:\n"
                            "    dotta update -p %s '%s'\n",
                            storage_path, profile_name,
                            is_encrypted ? "encrypted" : "plaintext",
                            is_encrypted ? "plaintext" : "encrypted",
                            profile_name, storage_path);
                    }
                }
            }

            error_free(lookup_err);
        }

        git_blob_free(blob);

        /* Policy mismatch: should be encrypted but isn't */
        if (should_auto_encrypt && !is_encrypted) {
            /* Check if file already has divergence (O(1) index lookup).
             * This prevents last-write-wins bug when multiple analysis functions
             * detect different divergence types for the same file. */
            void *idx_ptr = hashmap_get(ws->diverged_index, manifest_entry->filesystem_path);
            workspace_item_t *existing = NULL;
            if (idx_ptr) {
                size_t idx = (size_t)(uintptr_t)idx_ptr - 1;  /* Convert index+1 back to index */
                existing = &ws->diverged[idx];
            }

            if (existing) {
                /* File already diverged - accumulate encryption flag
                 *
                 * Example: File is DEPLOYED with CONTENT divergence AND violates encryption
                 * policy. We accumulate: divergence |= DIVERGENCE_ENCRYPTION.
                 * Result: User sees both flags: "modified [encryption]" in status. */
                existing->divergence |= DIVERGENCE_ENCRYPTION;
            } else {
                /* File has NO other divergence - encryption policy is the only issue.
                 * Determine state: if in state, it's deployed; otherwise undeployed. */
                bool in_state = false;

                if (ws->state) {
                    state_file_entry_t *state_entry = NULL;
                    error_t *state_err = state_get_file(ws->state,
                                            manifest_entry->filesystem_path, &state_entry);
                    if (state_err == NULL && state_entry) {
                        in_state = true;
                        state_free_entry(state_entry);
                    }
                    error_free(state_err);
                }

                workspace_state_t item_state = in_state ?
                    WORKSPACE_STATE_DEPLOYED : WORKSPACE_STATE_UNDEPLOYED;

                err = workspace_add_diverged(
                    ws,
                    manifest_entry->filesystem_path,
                    storage_path,
                    profile_name,
                    NULL,
                    item_state,            /* State: deployed or undeployed */
                    DIVERGENCE_ENCRYPTION, /* Divergence: encryption policy violated */
                    WORKSPACE_ITEM_FILE,
                    false, /* on_filesystem (unknown, encryption check is in-repo only) */
                    true,  /* profile_enabled */
                    false  /* No profile change */
                );

                if (err) {
                    return err;
                }
            }
        }
    }

    return NULL;
}

/**
 * Build in-memory manifest from state manifest table
 *
 * Reads manifest entries from state DB and constructs manifest_t structure.
 * Does NOT load git_tree_entry* pointers (set to NULL). Tree entries are
 * lazy-loaded only when needed for content display (diffs, conflict resolution).
 *
 * This is the core of the Virtual Working Directory architecture - we read
 * the expected state cache (manifest table) instead of walking Git trees. This makes
 * status operations O(M × DB) where M = entries in manifest.
 *
 * Files from profiles not in the workspace scope are filtered out with a warning.
 * This can happen if a profile is disabled but manifest still has orphaned entries.
 *
 * Performance: O(M × DB) where M = entries in manifest table
 *
 * @param ws Workspace (must not be NULL, state must be loaded)
 * @return Error or NULL on success
 */
static error_t *workspace_build_manifest_from_state(workspace_t *ws) {
    CHECK_NULL(ws);
    CHECK_NULL(ws->state);
    CHECK_NULL(ws->profile_index);

    error_t *err = NULL;
    state_file_entry_t *state_entries = NULL;
    size_t state_count = 0;

    /* Read all entries from manifest table */
    err = state_get_all_files(ws->state, &state_entries, &state_count);
    if (err) {
        return error_wrap(err, "Failed to read manifest from state");
    }

    /* Allocate manifest structure */
    ws->manifest = calloc(1, sizeof(manifest_t));
    if (!ws->manifest) {
        state_free_all_files(state_entries, state_count);
        return ERROR(ERR_MEMORY, "Failed to allocate manifest");
    }

    /* Allocate entries array (max size = state_count) */
    ws->manifest->entries = calloc(state_count, sizeof(file_entry_t));
    if (!ws->manifest->entries) {
        free(ws->manifest);
        ws->manifest = NULL;
        state_free_all_files(state_entries, state_count);
        return ERROR(ERR_MEMORY, "Failed to allocate manifest entries");
    }

    /*
     * Create hash map for O(1) lookups
     * Maps: filesystem_path -> index in entries array (offset by 1)
     * Use state_count as initial capacity (optimal sizing, no rehashing needed)
     */
    hashmap_t *path_map = hashmap_create(state_count > 0 ? state_count : 64);
    if (!path_map) {
        free(ws->manifest->entries);
        free(ws->manifest);
        ws->manifest = NULL;
        state_free_all_files(state_entries, state_count);
        return ERROR(ERR_MEMORY, "Failed to create manifest index");
    }

    size_t manifest_idx = 0;

    /* Build manifest entries from state */
    for (size_t i = 0; i < state_count; i++) {
        const state_file_entry_t *state_entry = &state_entries[i];
        file_entry_t *entry = &ws->manifest->entries[manifest_idx];

        /* Find profile in workspace's profile list (O(1) hashmap lookup) */
        entry->source_profile = hashmap_get(ws->profile_index, state_entry->profile);

        if (!entry->source_profile) {
            /* Profile not in workspace scope - this is expected when:
             * 1. Profile was disabled but manifest has orphaned entries
             * 2. Profile branch was deleted outside dotta
             *
             * Skip silently. Orphan detection (analyze_orphaned_files) will identify
             * these entries and status will show them clearly to the user. This
             * follows the Git staging model where profile disable stages removal
             * and apply executes it. */
            continue;
        }

        /* Copy paths (owned by manifest) */
        entry->storage_path = strdup(state_entry->storage_path);
        entry->filesystem_path = strdup(state_entry->filesystem_path);

        if (!entry->storage_path || !entry->filesystem_path) {
            /* Cleanup on allocation failure */
            free(entry->storage_path);
            free(entry->filesystem_path);

            /* Free previously allocated entries */
            for (size_t j = 0; j < manifest_idx; j++) {
                free(ws->manifest->entries[j].storage_path);
                free(ws->manifest->entries[j].filesystem_path);
                free(ws->manifest->entries[j].old_profile);
                free(ws->manifest->entries[j].git_oid);
                free(ws->manifest->entries[j].blob_oid);
                free(ws->manifest->entries[j].owner);
                free(ws->manifest->entries[j].group);
                if (ws->manifest->entries[j].entry) {
                    git_tree_entry_free(ws->manifest->entries[j].entry);
                }
            }
            hashmap_free(path_map, NULL);
            free(ws->manifest->entries);
            free(ws->manifest);
            ws->manifest = NULL;
            state_free_all_files(state_entries, state_count);
            return ERROR(ERR_MEMORY, "Failed to allocate manifest entry paths");
        }

        /* Check if this entry is inactive (marked for removal)
         *
         * Inactive entries are explicitly marked by the manifest layer when a file
         * is removed or a profile is disabled with no fallback. These entries are
         * intentionally out of scope and should not be validated against Git.
         *
         * They remain in the manifest table for orphan detection. The orphan
         * detection phase (analyze_orphaned_files) will load these entries and
         * mark them as ORPHANED for cleanup by apply.
         *
         * This check eliminates false-positive warnings for expected removals.
         */
        if (state_entry->state && strcmp(state_entry->state, STATE_INACTIVE) == 0) {
            /* Inactive entry - skip silently, don't add to manifest */
            free(entry->storage_path);
            free(entry->filesystem_path);
            continue;  /* Don't increment manifest_idx */
        }

        /* Populate VWD expected state cache from database
         *
         * These fields enable O(1) divergence checking without N database queries.
         * They represent the cached expected state that workspace divergence
         * analysis will compare against filesystem reality.
         *
         * NULL fields: Some optional fields (mode, owner, group, git_oid, blob_oid)
         * may be NULL in state database. Use conditional strdup to handle gracefully.
         */
        entry->old_profile = state_entry->old_profile ? strdup(state_entry->old_profile) : NULL;
        entry->git_oid = state_entry->git_oid ? strdup(state_entry->git_oid) : NULL;
        entry->blob_oid = state_entry->blob_oid ? strdup(state_entry->blob_oid) : NULL;
        entry->type = state_entry->type;
        entry->mode = state_entry->mode;
        entry->owner = state_entry->owner ? strdup(state_entry->owner) : NULL;
        entry->group = state_entry->group ? strdup(state_entry->group) : NULL;
        entry->encrypted = state_entry->encrypted;
        entry->deployed_at = state_entry->deployed_at;

        /* Check for allocation failures in VWD fields */
        if ((state_entry->old_profile && !entry->old_profile) ||
            (state_entry->git_oid && !entry->git_oid) ||
            (state_entry->blob_oid && !entry->blob_oid) ||
            (state_entry->owner && !entry->owner) ||
            (state_entry->group && !entry->group)) {

            /* Cleanup current entry's allocated fields */
            free(entry->storage_path);
            free(entry->filesystem_path);
            free(entry->old_profile);
            free(entry->git_oid);
            free(entry->blob_oid);
            free(entry->owner);
            free(entry->group);

            /* Free previously allocated entries */
            for (size_t j = 0; j < manifest_idx; j++) {
                free(ws->manifest->entries[j].storage_path);
                free(ws->manifest->entries[j].filesystem_path);
                free(ws->manifest->entries[j].old_profile);
                free(ws->manifest->entries[j].git_oid);
                free(ws->manifest->entries[j].blob_oid);
                free(ws->manifest->entries[j].owner);
                free(ws->manifest->entries[j].group);
                if (ws->manifest->entries[j].entry) {
                    git_tree_entry_free(ws->manifest->entries[j].entry);
                }
            }
            hashmap_free(path_map, NULL);
            free(ws->manifest->entries);
            free(ws->manifest);
            ws->manifest = NULL;
            state_free_all_files(state_entries, state_count);
            return ERROR(ERR_MEMORY, "Failed to allocate VWD cache fields");
        }

        /* Set tree entry to NULL - lazy-loaded on demand.
         *
         * VWD Architecture: Manifest built from state DB, not Git trees.
         * Tree entries loaded when needed via file_entry_ensure_tree_entry().
         * This achieves true O(M × DB) performance for workspace loading. */
        entry->entry = NULL;

        /* Store index in hashmap (offset by 1 to distinguish from NULL).
         * We cast the index through uintptr_t to store it as a void pointer.
         * This is safe because:
         * 1. Array indices are always much smaller than SIZE_MAX
         * 2. uintptr_t can hold any pointer value (by definition)
         * 3. We never dereference these "pointers" - they're just tagged integers
         */
        err = hashmap_set(path_map, entry->filesystem_path,
                         (void *)(uintptr_t)(manifest_idx + 1));
        if (err) {
            /* Cleanup: free hashmap and all allocated entries */
            hashmap_free(path_map, NULL);
            for (size_t j = 0; j <= manifest_idx; j++) {
                free(ws->manifest->entries[j].storage_path);
                free(ws->manifest->entries[j].filesystem_path);
                free(ws->manifest->entries[j].old_profile);
                free(ws->manifest->entries[j].git_oid);
                free(ws->manifest->entries[j].blob_oid);
                free(ws->manifest->entries[j].owner);
                free(ws->manifest->entries[j].group);
                if (ws->manifest->entries[j].entry) {
                    git_tree_entry_free(ws->manifest->entries[j].entry);
                }
            }
            free(ws->manifest->entries);
            free(ws->manifest);
            ws->manifest = NULL;
            state_free_all_files(state_entries, state_count);
            return error_wrap(err, "Failed to populate manifest index");
        }

        manifest_idx++;
    }

    /* Transfer index ownership to manifest */
    ws->manifest->index = path_map;

    /* Set final count (may be less than state_count due to filtering) */
    ws->manifest->count = manifest_idx;

    state_free_all_files(state_entries, state_count);
    return NULL;
}

/**
 * Load workspace from repository
 */
error_t *workspace_load(
    git_repository *repo,
    state_t *state,
    profile_list_t *profiles,
    const dotta_config_t *config,
    const workspace_load_t *options,
    workspace_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(options);
    CHECK_NULL(out);

    /* Copy provided options */
    workspace_load_t resolved_opts = *options;

    /* Handle analysis dependencies.
     * Orphan analysis requires file analysis (can't detect orphans without
     * knowing what files exist in profiles). Auto-enable file analysis if
     * orphans are requested to prevent invalid state. */
    if (resolved_opts.analyze_orphans && !resolved_opts.analyze_files) {
        resolved_opts.analyze_files = true;
    }

    workspace_t *ws = NULL;
    error_t *err = NULL;

    /* Create empty workspace */
    err = workspace_create_empty(repo, profiles, &ws);
    if (err) {
        return err;
    }

    /* Initialize encryption infrastructure */
    /* Note: keymanager can be NULL if encryption is not configured - this is valid */
    ws->keymanager = keymanager_get_global(config);

    ws->content_cache = content_cache_create(ws->repo, ws->keymanager);
    if (!ws->content_cache) {
        workspace_free(ws);
        return ERROR(ERR_MEMORY, "Failed to create content cache");
    }

    ws->metadata_cache = hashmap_create(16);
    if (!ws->metadata_cache) {
        workspace_free(ws);
        return ERROR(ERR_MEMORY, "Failed to create metadata cache");
    }

    /* Pre-load metadata for all profiles (performance optimization) */
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile_name = profiles->profiles[i].name;
        metadata_t *metadata = NULL;

        error_t *meta_err = metadata_load_from_branch(repo, profile_name, &metadata);
        if (meta_err) {
            /* Graceful fallback: create empty metadata if loading fails.
             * This ensures content layer always has metadata for validation.
             * Empty metadata will cause "file not in metadata" errors during
             * divergence analysis, which is the correct behavior for profiles
             * without metadata (new profiles or corrupted metadata files). */
            error_free(meta_err);
            error_t *create_err = metadata_create_empty(&metadata);
            if (create_err) {
                workspace_free(ws);
                return error_wrap(create_err,
                    "Failed to create metadata for profile '%s'", profile_name);
            }
        }

        error_t *set_err = hashmap_set(ws->metadata_cache, profile_name, metadata);
        if (set_err) {
            metadata_free(metadata);
            workspace_free(ws);
            return error_wrap(set_err, "Failed to cache metadata for profile '%s'", profile_name);
        }
    }

    /* Build unified metadata view with profile precedence.
     * CRITICAL INVARIANT: profiles array is in precedence order (global → OS → host).
     * Iterating in order naturally implements "last profile wins" - we update existing
     * entries to track the winning profile. */

    /* Initialize merged entries array */
    ws->merged_entries = NULL;
    ws->merged_count = 0;
    ws->merged_capacity = 0;

    ws->merged_metadata = hashmap_create(256);
    if (!ws->merged_metadata) {
        workspace_free(ws);
        return ERROR(ERR_MEMORY, "Failed to create merged metadata map");
    }

    for (size_t p = 0; p < profiles->count; p++) {
        const char *profile_name = profiles->profiles[p].name;
        const metadata_t *metadata = hashmap_get(ws->metadata_cache, profile_name);

        if (!metadata) {
            /* Profile has no metadata - skip (empty metadata was created above) */
            continue;
        }

        /* Get ALL items from this profile (files + directories) */
        size_t item_count = 0;
        const metadata_item_t *items = metadata_get_all_items(metadata, &item_count);

        if (!items || item_count == 0) {
            continue;  /* No items in this profile */
        }

        /* Add/update items in merged map - last profile wins (precedence) */
        for (size_t i = 0; i < item_count; i++) {
            const metadata_item_t *item = &items[i];

            /* Use item's key field as map key.
             * - For FILES: key = storage_path (e.g., "home/.bashrc")
             * - For DIRECTORIES: key = storage_path (e.g., "home/.config")
             *
             * COLLISION HANDLING: A real filesystem cannot have both a file and directory
             * at the same path, so collisions should never occur in practice. However,
             * if different profiles track the same path with different kinds (file vs directory),
             * the last profile wins (precedence). This is safe because:
             * 1. Git enforces this constraint (a tree entry is either blob or tree, not both)
             * 2. Filesystem enforces this constraint (path is either file or dir, not both)
             * 3. The winning entry represents current filesystem reality */

            /* Check if entry exists (for updating profile_name on override) */
            merged_metadata_entry_t *existing = hashmap_get(ws->merged_metadata, item->key);

            if (existing) {
                /* Update existing entry - last profile wins (precedence) */
                existing->item = item;
                existing->profile_name = profile_name;
            } else {
                /* Grow array if needed */
                if (ws->merged_count >= ws->merged_capacity) {
                    size_t new_cap = ws->merged_capacity == 0 ? 256 : ws->merged_capacity * 2;
                    merged_metadata_entry_t *new_entries = realloc(
                        ws->merged_entries,
                        new_cap * sizeof(merged_metadata_entry_t)
                    );
                    if (!new_entries) {
                        workspace_free(ws);
                        return ERROR(ERR_MEMORY, "Failed to grow merged entries");
                    }
                    ws->merged_entries = new_entries;
                    ws->merged_capacity = new_cap;
                }

                /* Add new entry */
                merged_metadata_entry_t *entry = &ws->merged_entries[ws->merged_count++];
                entry->item = item;
                entry->profile_name = profile_name;

                /* Add to hashmap */
                error_t *map_err = hashmap_set(ws->merged_metadata, item->key, entry);
                if (map_err) {
                    workspace_free(ws);
                    return error_wrap(map_err, "Failed to add entry to merged metadata");
                }
            }
        }
    }

    /* Load or borrow deployment state */
    if (state) {
        /* Borrow caller's state (typically from state_load_for_update).
         * This ensures workspace analyzes state within the active transaction,
         * not a stale committed snapshot. Caller retains ownership. */
        ws->state = state;
        ws->owns_state = false;
    } else {
        /* Allocate our own state (read-only mode for status/diff commands).
         * Workspace owns this and will free it in workspace_free(). */
        err = state_load(repo, &ws->state);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to load state");
        }
        ws->owns_state = true;
    }

    /* Build manifest from state (Virtual Working Directory architecture)
     * This replaces the old profile_build_manifest() which walked Git trees.
     * Now we read from the manifest table (expected state cache) for O(M) performance
     * where M = entries in manifest, not O(N) where N = all files in Git. */
    err = workspace_build_manifest_from_state(ws);
    if (err) {
        workspace_free(ws);
        return error_wrap(err, "Failed to build manifest from state");
    }

    /* Verify manifest index was populated (architectural invariant)
     * This check ensures workspace_build_manifest_from_state() correctly
     * built the index, maintaining consistency with the write path pattern. */
    if (!ws->manifest->index) {
        workspace_free(ws);
        return ERROR(ERR_INTERNAL,
            "Manifest index not populated by workspace_build_manifest_from_state() - "
            "this is a programming error");
    }

    /* Execute analyses based on resolved_opts flags. Each analysis is
     * independently controllable for optimal performance. */

    /* Analyze file divergence (most common requirement) */
    if (resolved_opts.analyze_files) {
        err = analyze_files_divergence(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze file divergence");
        }
    }

    /* Analyze orphaned state entries (requires files) */
    if (resolved_opts.analyze_orphans) {
        err = analyze_orphaned_state(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze orphaned state");
        }
    }

    /* Analyze tracked directories for untracked files */
    if (resolved_opts.analyze_untracked) {
        err = analyze_untracked_files(ws, config);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze untracked files");
        }
    }

    /* Analyze directory metadata divergence */
    if (resolved_opts.analyze_directories) {
        err = analyze_directory_metadata_divergence(ws);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze directory metadata");
        }
    }

    /* Analyze encryption policy mismatches */
    if (resolved_opts.analyze_encryption) {
        err = analyze_encryption_policy_mismatch(ws, config);
        if (err) {
            workspace_free(ws);
            return error_wrap(err, "Failed to analyze encryption policy");
        }
    }

    /* Compute status */
    ws->status = compute_workspace_status(ws);
    ws->status_computed = true;

    *out = ws;
    return NULL;
}

/**
 * Get workspace status
 */
workspace_status_t workspace_get_status(const workspace_t *ws) {
    if (!ws) {
        return WORKSPACE_INVALID;
    }
    return ws->status;
}


/**
 * Get all diverged items
 */
const workspace_item_t *workspace_get_all_diverged(
    const workspace_t *ws,
    size_t *count
) {
    if (!ws || !count) {
        if (count) *count = 0;
        return NULL;
    }

    *count = ws->diverged_count;
    return ws->diverged;
}

/**
 * Extract orphaned files and directories from workspace
 *
 * Two-pass extraction: count by kind, then populate both arrays.
 * Caller owns returned arrays; items are borrowed from workspace.
 */
error_t *workspace_extract_orphans(
    const workspace_t *ws,
    const workspace_item_t ***out_file_orphans,
    size_t *out_file_count,
    const workspace_item_t ***out_dir_orphans,
    size_t *out_dir_count
) {
    CHECK_NULL(ws);

    /* Initialize all outputs to safe defaults */
    if (out_file_orphans) *out_file_orphans = NULL;
    if (out_file_count) *out_file_count = 0;
    if (out_dir_orphans) *out_dir_orphans = NULL;
    if (out_dir_count) *out_dir_count = 0;

    /* Early exit if nothing requested */
    bool want_files = (out_file_orphans != NULL);
    bool want_dirs = (out_dir_orphans != NULL);
    if (!want_files && !want_dirs) {
        return NULL;
    }

    /* Pass 1: Count orphans by kind */
    size_t file_count = 0, dir_count = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].state == WORKSPACE_STATE_ORPHANED) {
            if (ws->diverged[i].item_kind == WORKSPACE_ITEM_FILE) {
                file_count++;
            } else {
                dir_count++;
            }
        }
    }

    /* Early exit if no orphans found */
    if (file_count == 0 && dir_count == 0) {
        return NULL;
    }

    /* Allocate arrays for requested kinds */
    const workspace_item_t **file_arr = NULL;
    const workspace_item_t **dir_arr = NULL;

    if (want_files && file_count > 0) {
        file_arr = malloc(file_count * sizeof(workspace_item_t *));
        if (!file_arr) {
            return ERROR(ERR_MEMORY, "Failed to allocate file orphan array");
        }
    }

    if (want_dirs && dir_count > 0) {
        dir_arr = malloc(dir_count * sizeof(workspace_item_t *));
        if (!dir_arr) {
            free(file_arr);
            return ERROR(ERR_MEMORY, "Failed to allocate directory orphan array");
        }
    }

    /* Pass 2: Populate both arrays in single iteration */
    size_t f_idx = 0, d_idx = 0;
    for (size_t i = 0; i < ws->diverged_count; i++) {
        if (ws->diverged[i].state == WORKSPACE_STATE_ORPHANED) {
            if (ws->diverged[i].item_kind == WORKSPACE_ITEM_FILE) {
                if (file_arr) {
                    file_arr[f_idx++] = &ws->diverged[i];
                }
            } else {
                if (dir_arr) {
                    dir_arr[d_idx++] = &ws->diverged[i];
                }
            }
        }
    }

    /* Set outputs */
    if (out_file_orphans) *out_file_orphans = file_arr;
    if (out_file_count) *out_file_count = file_count;
    if (out_dir_orphans) *out_dir_orphans = dir_arr;
    if (out_dir_count) *out_dir_count = dir_count;

    return NULL;
}

/**
 * Get workspace item by filesystem path
 *
 * O(1) lookup via diverged_index hashmap. Returns NULL if item has no
 * divergence (CLEAN items are not indexed).
 */
const workspace_item_t *workspace_get_item(
    const workspace_t *ws,
    const char *filesystem_path
) {
    if (!ws || !filesystem_path) {
        return NULL;
    }

    /* O(1) lookup via index - returns NULL if not found or CLEAN */
    void *idx_ptr = hashmap_get(ws->diverged_index, filesystem_path);
    if (!idx_ptr) {
        return NULL;
    }

    /* Convert stored index+1 back to actual array index */
    size_t idx = (size_t)(uintptr_t)idx_ptr - 1;
    return &ws->diverged[idx];
}

/**
 * Get cached metadata for profile
 */
const metadata_t *workspace_get_metadata(
    const workspace_t *ws,
    const char *profile_name
) {
    return ws_get_metadata(ws, profile_name);
}

/**
 * Get the manifest of files managed by the workspace
 */
const manifest_t *workspace_get_manifest(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->manifest;
}

/**
 * Get the deployment state from workspace
 */
const state_t *workspace_get_state(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->state;
}

/**
 * Get keymanager from workspace
 *
 * Returns the keymanager borrowed from global configuration. This is used
 * for content hashing and encryption operations. Can be NULL if encryption
 * is not configured.
 *
 * @param ws Workspace (must not be NULL)
 * @return Keymanager (borrowed reference, do not free, can be NULL)
 */
keymanager_t *workspace_get_keymanager(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->keymanager;
}

/**
 * Get content cache from workspace
 *
 * Returns the content cache used by the workspace for transparent
 * encryption/decryption. The cache is pre-populated during workspace
 * analysis and can be reused by commands to avoid redundant decryption.
 *
 * @param ws Workspace (must not be NULL)
 * @return Content cache (borrowed reference, do not free, can be NULL)
 */
content_cache_t *workspace_get_content_cache(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->content_cache;
}

/**
 * Get metadata cache from workspace
 *
 * Returns the pre-loaded metadata cache (hashmap: profile_name → metadata_t*)
 * populated during workspace_load(). This cache remains valid for the
 * workspace's lifetime and can be passed to bulk operations that need
 * per-profile metadata without redundant loads.
 *
 * @param ws Workspace (must not be NULL)
 * @return Metadata cache hashmap (borrowed reference, do not free, can be NULL)
 */
const hashmap_t *workspace_get_metadata_cache(const workspace_t *ws) {
    if (!ws) {
        return NULL;
    }
    return ws->metadata_cache;
}

/**
 * Extract display tags and metadata from workspace item
 */
bool workspace_item_extract_display_info(
    const workspace_item_t *item,
    const char **tags_out,
    size_t *tag_count_out,
    output_color_t *color_out,
    char *metadata_buf,
    size_t metadata_size
) {
    /* Initialize all outputs defensively before validation */
    if (tag_count_out) {
        *tag_count_out = 0;
    }
    if (color_out) {
        *color_out = OUTPUT_COLOR_RESET;
    }
    if (metadata_buf && metadata_size > 0) {
        metadata_buf[0] = '\0';
    }

    /* Validate required parameters */
    if (!item || !tags_out || !tag_count_out || !color_out ||
        !metadata_buf || metadata_size < 32) {
        return false;
    }

    /* Validate item has a profile name (critical for metadata formatting) */
    if (!item->profile || item->profile[0] == '\0') {
        return false;
    }

    size_t tag_count = 0;
    *color_out = OUTPUT_COLOR_YELLOW;  /* Default color for most states */

    switch (item->state) {
        case WORKSPACE_STATE_UNDEPLOYED:
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "undeployed";
            }
            *color_out = OUTPUT_COLOR_CYAN;
            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;

        case WORKSPACE_STATE_DELETED:
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "deleted";
            }
            *color_out = OUTPUT_COLOR_RED;
            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;

        case WORKSPACE_STATE_DEPLOYED: {
            /* Primary tag based on most severe divergence
             *
             * Priority order (by severity):
             *   TYPE > CONTENT > MODE/OWNERSHIP/ENCRYPTION
             */
            if (item->divergence & DIVERGENCE_TYPE) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "type";
                }
                *color_out = OUTPUT_COLOR_RED;
            } else if (item->divergence & DIVERGENCE_CONTENT) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "modified";
                }
                /* Keep default YELLOW color */
            }

            /* Secondary tags for other divergence
             *
             * MODE: Skip if TYPE divergence present (type change makes mode irrelevant)
             *       The condition !((item->divergence & DIVERGENCE_TYPE) && tag_count > 0)
             *       prevents MODE from showing when TYPE is the primary tag
             * OWNERSHIP: Always show if present
             * ENCRYPTION: Always show if present
             * UNVERIFIED: Always show if present (file too large to verify)
             */
            if ((item->divergence & DIVERGENCE_MODE) &&
                !((item->divergence & DIVERGENCE_TYPE) && tag_count > 0)) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "mode";
                }
            }

            if (item->divergence & DIVERGENCE_OWNERSHIP) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "ownership";
                }
            }

            if (item->divergence & DIVERGENCE_ENCRYPTION) {
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unencrypted";
                }
                /* Upgrade color to MAGENTA if still default (not TYPE divergence)
                 * This gives encryption issues special visual treatment */
                if (*color_out == OUTPUT_COLOR_YELLOW) {
                    *color_out = OUTPUT_COLOR_MAGENTA;
                }
            }

            if (item->divergence & DIVERGENCE_UNVERIFIED) {
                /* Verification could not be completed (rare edge case).
                 *
                 * Cannot verify content match, so marked for conservative handling
                 * (redeployment on apply, skipped removal for orphans).
                 */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unverified";
                }
                /* Upgrade color to MAGENTA (special visual treatment for unverifiable state) */
                if (*color_out == OUTPUT_COLOR_YELLOW) {
                    *color_out = OUTPUT_COLOR_MAGENTA;
                }
            }

            /* Format metadata based on divergence type
             *
             * For mode/ownership divergence, show metadata profile if different
             * from content profile. This indicates metadata comes from a different
             * profile than the file content (split metadata scenario).
             */
            const char *meta_profile = item->metadata_profile ?
                item->metadata_profile : item->profile;

            if (item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
                snprintf(metadata_buf, metadata_size, "metadata from %s", meta_profile);
            } else {
                snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            }
            break;
        }

        case WORKSPACE_STATE_ORPHANED: {
            /* Primary tag (always shown) */
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "orphaned";
            }

            /* Determine color and secondary tags based on divergence */
            if (item->divergence & DIVERGENCE_UNVERIFIED) {
                /* Cannot verify state - could be large file, missing key, I/O error, etc.
                 * Conservative: Treat as modified (apply will skip). */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "unverified";
                }
                *color_out = OUTPUT_COLOR_MAGENTA;

            } else if (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_TYPE)) {
                /* Content or type divergence - blocking issue
                 * Apply will detect this via safety check and skip removal. */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "modified";
                }
                *color_out = OUTPUT_COLOR_RED;

            } else if (item->divergence & (DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP)) {
                /* Metadata divergence only - warning level
                 * File content matches but permissions changed.
                 * Apply will skip (safety check considers this a modification). */
                if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                    tags_out[tag_count++] = "mode";
                }
                *color_out = OUTPUT_COLOR_YELLOW;

            } else {
                /* No divergence - clean orphan
                 * File exactly matches last known state. Apply will remove it.
                 * Use RED to indicate action will be taken (file deletion). */
                *color_out = OUTPUT_COLOR_RED;
            }

            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;
        }

        case WORKSPACE_STATE_UNTRACKED:
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "new";
            }
            *color_out = OUTPUT_COLOR_CYAN;
            snprintf(metadata_buf, metadata_size, "in %s", item->profile);
            break;

        default:
            /* Unknown state - defensive fallback
             * Should never happen in normal operation, but handle gracefully */
            if (tag_count < WORKSPACE_ITEM_MAX_DISPLAY_TAGS) {
                tags_out[tag_count++] = "unknown";
            }
            *color_out = OUTPUT_COLOR_DIM;
            snprintf(metadata_buf, metadata_size, "from %s", item->profile);
            break;
    }

    *tag_count_out = tag_count;
    return true;
}

/**
 * Free workspace
 */
void workspace_free(workspace_t *ws) {
    if (!ws) {
        return;
    }

    /* Free diverged entries */
    for (size_t i = 0; i < ws->diverged_count; i++) {
        free(ws->diverged[i].filesystem_path);
        free(ws->diverged[i].storage_path);
        free(ws->diverged[i].profile);
        free(ws->diverged[i].metadata_profile);
        free(ws->diverged[i].old_profile);  /* Free profile change tracking */
    }
    free(ws->diverged);

    /* Free indices (values are borrowed, so pass NULL for value free function) */
    hashmap_free(ws->profile_index, NULL);
    hashmap_free(ws->diverged_index, NULL);

    /* Free merged_metadata BEFORE metadata_cache (borrowed pointers) */
    hashmap_free(ws->merged_metadata, NULL);  /* NULL = don't free values (they're in merged_entries) */

    /* Free merged_entries array (strings are borrowed, just free array) */
    free(ws->merged_entries);

    /* Free encryption infrastructure */
    if (ws->metadata_cache) {
        hashmap_free(ws->metadata_cache, metadata_free);
    }
    content_cache_free(ws->content_cache);
    /* Don't free keymanager - it's global */

    /* Free owned state */
    manifest_free(ws->manifest);

    /* Only free state if we own it (allocated via state_load).
     * If borrowed from caller (state_load_for_update), caller is responsible. */
    if (ws->owns_state) {
        state_free(ws->state);
    }

    free(ws);
}
