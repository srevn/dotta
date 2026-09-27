/**
 * editor.c - Editor invocation utilities implementation
 */

#include "sys/editor.h"

#include <stdlib.h>

#include "base/error.h"
#include "sys/process.h"

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
 * Launch editor for a file, in the foreground
 *
 * More secure than system() - no shell interpretation, better error handling.
 */
error_t *editor_launch(const char *editor, const char *file_path) {
    CHECK_NULL(editor);
    CHECK_NULL(file_path);

    /* Validate editor is not empty */
    if (*editor == '\0') {
        return ERROR(
            ERR_INVALID_ARG, "Editor command cannot be empty"
        );
    }

    /* The editor takes the terminal while it runs, and the keyboard's signals
     * are its own (sys/process.h process_foreground). */
    char *const argv[] = { (char *) editor, (char *) file_path, NULL };
    process_result_t result;
    RETURN_IF_ERROR(process_foreground(argv, &result));

    /* An editor that could not be run says why: the errno's word, and ERR_NOT_FOUND
     * for a program no PATH entry holds (error_from_errno). */
    if (result.exec_failed) {
        return error_from_errno(
            result.exec_errno, "Editor '%s' could not be run", editor
        );
    }

    /* Killed, a Ctrl-C it did not answer among the causes: the edit is abandoned
     * and the caller's own cleanup runs, its temporary file included. */
    if (result.signal_num) {
        return ERROR(
            ERR_INTERNAL, "Editor was terminated by signal: %d",
            result.signal_num
        );
    }

    /* A non-zero exit is the editor's own refusal, and the edit is not taken. */
    if (result.exit_code != 0) {
        return ERROR(
            ERR_INTERNAL, "Editor exited with non-zero status: %d",
            result.exit_code
        );
    }

    return NULL;
}

/**
 * Launch editor for a file with environment-based selection
 *
 * Convenience function that combines editor_get_from_env() and editor_launch().
 */
error_t *editor_launch_with_env(
    const char *file_path,
    const char *default_editor
) {
    CHECK_NULL(file_path);

    const char *editor = editor_get_from_env(default_editor);
    return editor_launch(editor, file_path);
}
