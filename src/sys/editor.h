/**
 * editor.h - Editor invocation utilities
 *
 * Provides secure editor selection and invocation for interactive editing. The
 * editor runs through sys/process's foreground primitive — fork and exec, no
 * shell — instead of system(), for better security.
 */

#ifndef DOTTA_EDITOR_H
#define DOTTA_EDITOR_H

#include <types.h>

/**
 * Get editor from environment with fallback chain
 *
 * Priority: DOTTA_EDITOR → VISUAL → EDITOR → vi. The fallback is this module's
 * alone, so every command that opens an editor opens the one its help names
 * (cmds/bootstrap.c, cmds/ignore.c).
 *
 * @return Editor command (never NULL; vi where no variable names one)
 */
const char *editor_get_from_env(void);

/**
 * Launch editor for a file, in the foreground
 *
 * More secure than system() - no shell interpretation, better error handling.
 * Blocks until editor exits. The editor takes the terminal, and the keyboard's
 * signals are its own while it runs (sys/process.h process_foreground): a Ctrl-C
 * it answers never ends dotta underneath it, and one that kills it abandons the
 * edit as any failure does, the caller's cleanup running.
 *
 * @param editor Editor command to launch (must not be NULL)
 * @param file_path Path to file to edit (must not be NULL)
 * @return Error or NULL on success: the program could not be run (ERR_NOT_FOUND
 *         when no PATH entry holds it), it was killed, or it exited non-zero
 */
error_t editor_launch(const char *editor, const char *file_path);

/**
 * Launch editor for a file with environment-based selection
 *
 * Convenience function that combines editor_get_from_env() and editor_launch().
 *
 * @param file_path Path to file to edit (must not be NULL)
 * @return Error or NULL on success
 */
error_t editor_launch_with_env(const char *file_path);

#endif /* DOTTA_EDITOR_H */
