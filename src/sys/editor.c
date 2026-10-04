/**
 * editor.c - Editor invocation utilities implementation
 */

#include "sys/editor.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/heap.h"
#include "sys/filesystem.h"
#include "sys/process.h"

/**
 * Get editor from environment with fallback chain
 *
 * Priority: DOTTA_EDITOR → VISUAL → EDITOR → vi
 */
const char *editor_from_env(void) {
    const char *editor = getenv("DOTTA_EDITOR");
    if (editor && *editor) {
        return editor;
    }

    editor = getenv("VISUAL");
    if (editor && *editor) {
        return editor;
    }

    editor = getenv("EDITOR");
    if (editor && *editor) {
        return editor;
    }

    return "vi";
}

/**
 * Launch editor for a file, in the foreground
 *
 * More secure than system() - no shell interpretation, better error handling.
 */
error_t editor_launch(const char *editor, const char *file_path) {
    CHECK_NULL(editor);
    CHECK_NULL(file_path);

    /* Validate editor is not empty */
    if (*editor == '\0') {
        return error_create(
            ERR_INVALID_ARG, "Editor command cannot be empty"
        );
    }

    /* The editor takes the terminal while it runs, and the keyboard's signals
     * are its own (sys/process.h process_foreground). */
    char *const argv[] = { (char *) editor, (char *) file_path, NULL };
    process_result_t result;
    error_t err = process_foreground(argv, &result);
    if (err) return err;

    /* An editor that could not be run says why: the errno's word, and ERR_NOT_FOUND
     * for a program no PATH entry holds (error_errno). */
    if (result.exec_failed) {
        return error_errno(
            result.exec_errno, "Editor '%s' could not be run", editor
        );
    }

    /* Killed, a Ctrl-C it did not answer among the causes: the edit is abandoned
     * and the caller's own cleanup runs, its temporary file included. */
    if (result.signal_num) {
        return error_create(
            ERR_INTERNAL, "Editor was terminated by signal: %d",
            result.signal_num
        );
    }

    /* A non-zero exit is the editor's own refusal, and the edit is not taken. */
    if (result.exit_code != 0) {
        return error_create(
            ERR_INTERNAL, "Editor exited with non-zero status: %d",
            result.exit_code
        );
    }

    return NULL;
}

/**
 * Launch editor for a file with environment-based selection
 *
 * Convenience function that combines editor_from_env() and editor_launch().
 */
error_t editor_launch_with_env(const char *file_path) {
    CHECK_NULL(file_path);

    return editor_launch(editor_from_env(), file_path);
}

error_t editor_edit(const char *prefix, buffer_t *bytes, char **out_path) {
    CHECK_NULL(prefix);
    CHECK_NULL(bytes);
    CHECK_NULL(out_path);

    *out_path = NULL;

    /* The edit's own file, made where every temporary file is. A template mkstemp
     * could not make is no file of this run's, whatever name it tried last, so
     * nothing is unlinked. */
    const char *dir = fs_temp_directory();
    char *path = heap_str_format("%s/%s-XXXXXX", dir, prefix);
    int fd = mkstemp(path);
    if (fd < 0) {
        error_t err = error_errno(errno, "Cannot create a temporary file in '%s'", dir);
        free(path);
        return err;
    }

    /* The bytes the editor opens on, then the editor. A file that would not take
     * them holds nothing of the user's, and an edit the editor refused is the
     * user's refusal: either way the file goes. */
    error_t err = fs_write_fd(fd, path, bytes->data, bytes->size);
    if (close(fd) != 0 && !err) {
        err = error_errno(errno, "Cannot close '%s'", path);
    }
    if (!err) err = editor_launch_with_env(path);
    if (err) {
        unlink(path);
        free(path);
        return err;
    }

    /* What the editor left is the edit from here on: read back into the one buffer,
     * the bytes it opened on released first. A read that fails leaves the file
     * where the editor left it, the user's work in it, and the refusal names it. */
    buffer_deinit(bytes);
    err = fs_read_file(path, bytes);
    if (err) {
        free(path);
        return err;
    }

    *out_path = path;
    return NULL;
}
