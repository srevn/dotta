/**
 * editor.h - Editor invocation utilities
 *
 * Provides secure editor selection and invocation for interactive editing.
 * Uses fork()+execlp() pattern instead of system() for better security.
 */

#ifndef DOTTA_EDITOR_H
#define DOTTA_EDITOR_H

#include "base/error.h"

/**
 * Get editor from environment with fallback chain
 *
 * Priority: DOTTA_EDITOR → VISUAL → EDITOR → default_editor
 *
 * @param default_editor Default editor if no env vars set (e.g., "nano", "vi")
 * @return Editor command (never NULL, returns default_editor if nothing found)
 */
const char *editor_get_from_env(const char *default_editor);

/**
 * Launch editor for a file using fork/exec pattern
 *
 * More secure than system() - no shell interpretation, better error handling.
 * Blocks until editor exits.
 *
 * @param editor Editor command to launch (must not be NULL)
 * @param file_path Path to file to edit (must not be NULL)
 * @return Error or NULL on success
 */
error_t *editor_launch(const char *editor, const char *file_path);

/**
 * Launch editor for a file with environment-based selection
 *
 * Convenience function that combines editor_get_from_env() and editor_launch().
 *
 * @param file_path Path to file to edit (must not be NULL)
 * @param default_editor Default editor if no env vars set
 * @return Error or NULL on success
 */
error_t *editor_launch_with_env(const char *file_path, const char *default_editor);

#endif /* DOTTA_EDITOR_H */
