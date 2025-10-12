/**
 * editor.c - Editor invocation utilities implementation
 */

#include "editor.h"

#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base/error.h"

/**
 * Get editor from environment with fallback chain
 *
 * Priority: DOTTA_EDITOR → VISUAL → EDITOR → default_editor
 */
const char *editor_get_from_env(const char *default_editor) {
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

    return default_editor ? default_editor : "vi";
}

/**
 * Launch editor for a file using fork/exec pattern
 *
 * More secure than system() - no shell interpretation, better error handling.
 */
error_t *editor_launch(const char *editor, const char *file_path) {
    CHECK_NULL(editor);
    CHECK_NULL(file_path);

    /* Validate editor is not empty */
    if (*editor == '\0') {
        return ERROR(ERR_INVALID_ARG, "Editor command cannot be empty");
    }

    /* Fork and execute editor */
    pid_t pid = fork();
    if (pid == -1) {
        return ERROR(ERR_FS, "Failed to fork for editor");
    }

    if (pid == 0) {
        /* Child process */
        execlp(editor, editor, file_path, (char *)NULL);
        /* If execlp returns, it failed */
        _exit(127);
    }

    /* Parent process - wait for editor */
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        return ERROR(ERR_FS, "Failed to wait for editor");
    }

    /* Check exit status */
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 127) {
            return ERROR(ERR_NOT_FOUND, "Editor command not found: %s", editor);
        }
        if (exit_code != 0) {
            return ERROR(ERR_INTERNAL, "Editor exited with non-zero status: %d", exit_code);
        }
    } else if (WIFSIGNALED(status)) {
        return ERROR(ERR_INTERNAL, "Editor was terminated by signal: %d", WTERMSIG(status));
    }

    return NULL;
}

/**
 * Launch editor for a file with environment-based selection
 *
 * Convenience function that combines editor_get_from_env() and editor_launch().
 */
error_t *editor_launch_with_env(const char *file_path, const char *default_editor) {
    CHECK_NULL(file_path);

    const char *editor = editor_get_from_env(default_editor);
    return editor_launch(editor, file_path);
}
