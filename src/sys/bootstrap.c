/**
 * bootstrap.c - Profile bootstrap script primitives
 *
 * See sys/bootstrap.h for the contract. This file is deliberately
 * narrow: pure Git-content operations, with no knowledge of process
 * spawning, output formatting, or profile iteration.
 */

#include "sys/bootstrap.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/string.h"
#include "sys/gitops.h"

/**
 * Load a profile's Git tree and look up its .bootstrap entry.
 *
 * On success: *out_tree is owned by the caller (git_tree_free) and
 * *out_entry is borrowed from the tree (same lifetime). On failure,
 * both outputs are left untouched.
 *
 * Returns ERR_NOT_FOUND if the tree exists but has no .bootstrap
 * entry; wraps any underlying Git error otherwise.
 */
static error_t *load_bootstrap_entry(
    git_repository *repo,
    const char *profile,
    git_tree **out_tree,
    const git_tree_entry **out_entry
) {
    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, profile, &tree, NULL);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for profile '%s'", profile
        );
    }

    const git_tree_entry *entry =
        git_tree_entry_byname(tree, BOOTSTRAP_SCRIPT_NAME);
    if (!entry) {
        git_tree_free(tree);
        return ERROR(
            ERR_NOT_FOUND,
            "Bootstrap script not found in profile '%s'", profile
        );
    }

    *out_tree = tree;
    *out_entry = entry;
    return NULL;
}

/**
 * Resolve the directory for temporary files.
 *
 * Honors TMPDIR when set and non-empty; falls back to "/tmp" which
 * POSIX guarantees exists.
 */
static const char *tmp_dir(void) {
    const char *d = getenv("TMPDIR");
    return (d && *d) ? d : "/tmp";
}

/**
 * Write exactly `size` bytes from `data` to `fd`, retrying on EINTR
 * and handling short writes. Returns NULL on success.
 */
static error_t *write_all(int fd, const void *data, size_t size) {
    const unsigned char *p = data;
    size_t written = 0;
    while (written < size) {
        ssize_t n = write(fd, p + written, size - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return ERROR(
                ERR_FS, "Write to temp file failed: %s", strerror(errno)
            );
        }
        written += (size_t) n;
    }

    return NULL;
}

bool bootstrap_exists(git_repository *repo, const char *profile) {
    if (!repo || !profile || *profile == '\0') return false;

    bool exists = false;
    error_t *err = gitops_branch_exists(repo, profile, &exists);
    if (err) {
        error_free(err);
        return false;
    }
    if (!exists) return false;

    git_tree *tree = NULL;
    err = gitops_load_branch_tree(repo, profile, &tree, NULL);
    if (err) {
        error_free(err);
        return false;
    }

    bool found = git_tree_entry_byname(tree, BOOTSTRAP_SCRIPT_NAME) != NULL;
    git_tree_free(tree);
    return found;
}

error_t *bootstrap_read(
    git_repository *repo,
    const char *profile,
    buffer_t *out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out_content);

    git_tree *tree = NULL;
    const git_tree_entry *entry = NULL;
    void *raw = NULL;
    buffer_t buf = BUFFER_INIT;
    error_t *err = NULL;

    err = load_bootstrap_entry(repo, profile, &tree, &entry);
    if (err) goto cleanup;

    /* Read blob content */
    size_t size = 0;
    err = gitops_read_blob_content(
        repo, git_tree_entry_id(entry), &raw, &size
    );
    if (err) goto cleanup;

    if (size > 0) {
        err = buffer_append(&buf, raw, size);
        if (err) {
            err = error_wrap(err, "Failed to buffer bootstrap content");
            goto cleanup;
        }
    }

    /* Transfer ownership to caller; local clears to a safe empty state. */
    *out_content = buf;
    buf = (buffer_t){ 0 };

cleanup:
    buffer_free(&buf);
    free(raw);
    if (tree) git_tree_free(tree);
    return err;
}

error_t *bootstrap_extract_to_temp(
    git_repository *repo,
    const char *profile,
    char **out_temp_path
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out_temp_path);

    git_tree *tree = NULL;
    const git_tree_entry *entry = NULL;
    void *raw = NULL;
    char *path = NULL;
    int fd = -1;
    error_t *err = NULL;

    err = load_bootstrap_entry(repo, profile, &tree, &entry);
    if (err) goto cleanup;

    size_t size = 0;
    err = gitops_read_blob_content(
        repo, git_tree_entry_id(entry), &raw, &size
    );
    if (err) goto cleanup;

    /* Validate BEFORE creating the temp file — a bad shebang never
     * produces a half-written artifact on disk. */
    err = bootstrap_validate((const unsigned char *) raw, size);
    if (err) {
        err = error_wrap(
            err, "Invalid bootstrap script in profile '%s'", profile
        );
        goto cleanup;
    }

    path = str_format("%s/dotta-bootstrap-XXXXXX", tmp_dir());
    if (!path) {
        err = ERROR(ERR_MEMORY, "Failed to allocate temp file path");
        goto cleanup;
    }

    fd = mkstemp(path);
    if (fd < 0) {
        err = ERROR(
            ERR_FS, "Failed to create temp file: %s", strerror(errno)
        );
        goto cleanup;
    }

    err = write_all(fd, raw, size);
    if (err) goto cleanup;

    if (fchmod(fd, 0700) != 0) {
        err = ERROR(
            ERR_FS, "Failed to set executable permissions on temp file: %s",
            strerror(errno)
        );
        goto cleanup;
    }

    if (close(fd) != 0) {
        fd = -1;
        err = ERROR(
            ERR_FS, "Failed to close temp file: %s", strerror(errno)
        );
        goto cleanup;
    }
    fd = -1;

    /* Transfer ownership of the path to the caller. */
    *out_temp_path = path;
    path = NULL;

cleanup:
    if (fd >= 0) close(fd);
    if (path) {
        unlink(path);
        free(path);
    }
    free(raw);
    if (tree) git_tree_free(tree);
    return err;
}

error_t *bootstrap_validate(const unsigned char *content, size_t size) {
    if (size == 0 || !content) {
        return ERROR(
            ERR_INVALID_ARG, "Bootstrap script is empty"
        );
    }

    if (size < 3) {
        return ERROR(
            ERR_INVALID_ARG,
            "Bootstrap script too short to contain a shebang line"
        );
    }

    if (content[0] != '#' || content[1] != '!') {
        return ERROR(
            ERR_INVALID_ARG,
            "Bootstrap script must start with a shebang (#!)"
        );
    }

    /* Find end of shebang line (first newline or end-of-buffer). */
    size_t line_end = 2;
    while (line_end < size && content[line_end] != '\n') line_end++;

    /* Skip whitespace between #! and interpreter path. */
    size_t p = 2;
    while (p < line_end && isspace(content[p])) p++;

    if (p >= line_end) {
        return ERROR(
            ERR_INVALID_ARG,
            "Shebang line missing interpreter path"
        );
    }

    if (content[p] != '/') {
        return ERROR(
            ERR_INVALID_ARG,
            "Shebang interpreter must be an absolute path (start with /)"
        );
    }

    return NULL;
}
