/**
 * help.h - Help and usage functions
 *
 * Provides help text and usage information for all commands.
 */

#ifndef DOTTA_HELP_H
#define DOTTA_HELP_H

/**
 * Print general usage information
 */
void print_usage(const char *prog_name);

/**
 * Print version information
 */
void print_version(void);

/**
 * Print help for init command
 */
void print_init_help(const char *prog_name);

/**
 * Print help for clone command
 */
void print_clone_help(const char *prog_name);

/**
 * Print help for add command
 */
void print_add_help(const char *prog_name);

/**
 * Print help for remove command
 */
void print_remove_help(const char *prog_name);

/**
 * Print help for apply command
 */
void print_apply_help(const char *prog_name);

/**
 * Print help for status command
 */
void print_status_help(const char *prog_name);

/**
 * Print help for diff command
 */
void print_diff_help(const char *prog_name);

/**
 * Print help for list command
 */
void print_list_help(const char *prog_name);

/**
 * Print help for profile command
 */
void print_profile_help(const char *prog_name);

/**
 * Print help for show command
 */
void print_show_help(const char *prog_name);

/**
 * Print help for revert command
 */
void print_revert_help(const char *prog_name);

/**
 * Print help for remote command
 */
void print_remote_help(const char *prog_name);

/**
 * Print help for update command
 */
void print_update_help(const char *prog_name);

/**
 * Print help for sync command
 */
void print_sync_help(const char *prog_name);

/**
 * Print help for ignore command
 */
void print_ignore_help(const char *prog_name);

/**
 * Print help for bootstrap command
 */
void print_bootstrap_help(const char *prog_name);

/**
 * Print help for interactive mode
 */
void print_interactive_help(const char *prog_name);

/**
 * Print help for key command
 */
void print_key_help(const char *prog_name);

#endif /* DOTTA_HELP_H */
