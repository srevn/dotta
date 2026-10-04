/**
 * bootstrap.c - Profile bootstrap script primitives
 *
 * See sys/bootstrap.h for the contract. This file is deliberately narrow: pure
 * Git-content operations, with no knowledge of process spawning, output formatting,
 * or profile iteration.
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
#include "base/heap.h"
#include "sys/gitops.h"

/**
 * Open a view on a profile's .bootstrap script: the one read of it
 *
 * The profile's tree is loaded, its .bootstrap entry found, the blob's view opened
 * and the tree let go: a view holds its blob, never the tree it was found in.
 * The caller closes the view (sys/gitops.h gitops_blob_view_close); on failure
 * it is the empty view, whose close does nothing.
 *
 * Returns ERR_NOT_FOUND if the tree exists but has no .bootstrap entry, and the
 * tree's load's own failure otherwise — its ERR_NOT_FOUND, for a branch that is
 * not there (sys/gitops.h gitops_load_branch_tree), naming the reference.
 */
static error_t bootstrap_open_script(
    git_repository *repo,
    const char *profile,
    gitops_blob_view_t *out
) {
    *out = (gitops_blob_view_t){ 0 };

    git_tree *tree = NULL;
    error_t err = gitops_load_branch_tree(repo, profile, &tree);
    if (err) return err;

    const git_tree_entry *entry =
        git_tree_entry_byname(tree, BOOTSTRAP_SCRIPT_NAME);
    if (!entry) {
        git_tree_free(tree);
        return error_create(
            ERR_NOT_FOUND,
            "Bootstrap script not found in profile '%s'", profile
        );
    }

    err = gitops_blob_view_open(repo, git_tree_entry_id(entry), out);
    git_tree_free(tree);
    return err;
}

/**
 * Resolve the directory for temporary files.
 *
 * Honors TMPDIR when set and non-empty; falls back to "/tmp" which POSIX guarantees
 * exists.
 */
static const char *tmp_dir(void) {
    const char *d = getenv("TMPDIR");
    return (d && *d) ? d : "/tmp";
}

/**
 * Write exactly `size` bytes from `data` to `fd`, retrying on EINTR and handling
 * short writes. Returns NULL on success.
 */
static error_t write_all(int fd, const void *data, size_t size) {
    const unsigned char *p = data;
    size_t written = 0;
    while (written < size) {
        ssize_t n = write(fd, p + written, size - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return error_errno(errno, "Write to temp file failed");
        }
        written += (size_t) n;
    }

    return NULL;
}

bool bootstrap_exists(git_repository *repo, const char *profile) {
    if (!repo || !profile || *profile == '\0') return false;

    /* A branch that is gone, cannot be asked about or will not load holds no
     * script to read: its error is dropped, one per such profile asked. */
    git_tree *tree = NULL;
    error_t err = gitops_branch_tree(repo, profile, &tree);
    if (err || !tree) return false;

    bool found = git_tree_entry_byname(tree, BOOTSTRAP_SCRIPT_NAME) != NULL;
    git_tree_free(tree);
    return found;
}

error_t bootstrap_read(
    git_repository *repo,
    const char *profile,
    buffer_t *out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out_content);

    *out_content = (buffer_t){ 0 };

    /* The script's bytes, copied once out of its view */
    gitops_blob_view_t script;
    error_t err = bootstrap_open_script(repo, profile, &script);
    if (err) return err;

    buffer_append(out_content, script.data, script.size);
    gitops_blob_view_close(&script);
    return NULL;
}

error_t bootstrap_extract_to_temp(
    git_repository *repo,
    const char *profile,
    char **out_temp_path
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);
    CHECK_NULL(out_temp_path);

    gitops_blob_view_t script;
    char *path = NULL;
    int fd = -1;

    error_t err = bootstrap_open_script(repo, profile, &script);
    if (err) goto cleanup;

    /* Validate BEFORE creating the temp file — a bad shebang never produces a
     * half-written artifact on disk. */
    err = bootstrap_validate((const unsigned char *) script.data, script.size);
    if (err) {
        err = error_wrap(
            err, "Invalid bootstrap script in profile '%s'", profile
        );
        goto cleanup;
    }

    path = heap_str_format("%s/dotta-bootstrap-XXXXXX", tmp_dir());

    fd = mkstemp(path);
    if (fd < 0) {
        err = error_errno(errno, "Failed to create temp file");
        goto cleanup;
    }

    err = write_all(fd, script.data, script.size);
    if (err) goto cleanup;

    if (fchmod(fd, 0700) != 0) {
        err = error_errno(
            errno, "Failed to set executable permissions on temp file"
        );
        goto cleanup;
    }

    if (close(fd) != 0) {
        fd = -1;
        err = error_errno(errno, "Failed to close temp file");
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
    gitops_blob_view_close(&script);
    return err;
}

error_t bootstrap_validate(const unsigned char *content, size_t size) {
    CHECK_ARG(content != NULL || size == 0, "content cannot be NULL with a size");

    if (size == 0) {
        return error_create(
            ERR_INVALID_ARG, "Bootstrap script is empty"
        );
    }

    if (size < 3) {
        return error_create(
            ERR_INVALID_ARG,
            "Bootstrap script too short to contain a shebang line"
        );
    }

    if (content[0] != '#' || content[1] != '!') {
        return error_create(
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
        return error_create(
            ERR_INVALID_ARG,
            "Shebang line missing interpreter path"
        );
    }

    if (content[p] != '/') {
        return error_create(
            ERR_INVALID_ARG,
            "Shebang interpreter must be an absolute path (start with /)"
        );
    }

    return NULL;
}
