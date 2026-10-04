/**
 * editor.h - Editor invocation utilities
 *
 * Provides secure editor selection and invocation for interactive editing, and
 * the file an edit is made in (editor_edit). The editor runs through sys/process's
 * foreground primitive — fork and exec, no shell — instead of system(), for better
 * security.
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
const char *editor_from_env(void);

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
 * Convenience function that combines editor_from_env() and editor_launch().
 *
 * @param file_path Path to file to edit (must not be NULL)
 * @return Error or NULL on success
 */
error_t editor_launch_with_env(const char *file_path);

/**
 * Bytes through the user's editor, in a file the caller keeps or lets go
 *
 * `bytes` go into a file of their own — mkstemp's, in the run's temporary directory
 * (sys/filesystem.h fs_temp_directory), named `<prefix>-XXXXXX`, 0600 and the
 * invoker's (an editor that saves by renaming over it leaves one of the invoker's
 * umask) — the user's editor runs on it (editor_launch_with_env), and what it
 * left there is read back into `bytes`, the bytes it opened on released first.
 * The file stands after the call, named by `*out_path`: the caller unlinks it
 * once the edit has gone where it was going, and keeps it where that is refused,
 * naming it in the refusal, so an edit the session cannot commit is never lost.
 *
 * Three ends leave the caller nothing to keep, `*out_path` NULL. An edit the
 * editor refused — a non-zero exit, a signal — is abandoned, the file unlinked;
 * so is a file that could not be made or written, which holds nothing of the
 * user's. An edit that cannot be read back is the user's all the same: the file
 * stays where the editor left it, and the refusal names it (sys/filesystem.h
 * fs_read_file).
 *
 * Readers: cmds/ignore.c ignore_edit, cmds/bootstrap.c bootstrap_edit.
 *
 * @param prefix The file's name before its six random characters (must not be NULL)
 * @param bytes What the editor opens on, and after it what the editor left (must
 *              not be NULL; on failure, whatever the failure left — the caller
 *              releases it either way)
 * @param out_path The file, the heap's (must not be NULL; NULL on failure)
 * @return Error or NULL on success
 */
error_t editor_edit(const char *prefix, buffer_t *bytes, char **out_path);

#endif /* DOTTA_EDITOR_H */
