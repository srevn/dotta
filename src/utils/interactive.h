/**
 * interactive.h - Interactive TUI for profile selection and ordering
 *
 * Provides an inline, fzf-style interactive interface for profile management.
 *
 * Features:
 * - Profile list with hierarchical display
 * - Toggle selection (space)
 * - Navigate with arrow keys
 * - Reorder profiles (J/K)
 * - Save profile selection and order to state (w)
 * - Clean inline rendering (preserves terminal state)
 *
 * Design principles:
 * - Built on terminal.h primitives
 * - No external TUI libraries
 * - Single responsibility: profile selection and ordering
 * - Proper cleanup on exit
 */

#ifndef DOTTA_INTERACTIVE_H
#define DOTTA_INTERACTIVE_H

#include <git2.h>
#include <stdbool.h>

#include "types.h"
#include "utils/terminal.h"

/**
 * Profile item in UI list
 *
 * Represents a single profile entry with selection state and metadata.
 */
typedef struct {
    char *name;              /* Profile name */
    bool selected;           /* Selected for operations */
    bool exists_locally;     /* Exists as local branch */
    int indent_level;        /* Indentation level (0=root, 1=sub-profile) */
    bool is_host_profile;    /* True for hosts/... profiles */
} profile_item_t;

/**
 * Interactive UI state (opaque)
 *
 * Tracks cursor position, profile list, selections, etc.
 */
typedef struct interactive_state interactive_state_t;

/**
 * Command result
 */
typedef enum {
    INTERACTIVE_CONTINUE,    /* Continue UI loop */
    INTERACTIVE_EXIT_OK,     /* Exit successfully */
    INTERACTIVE_EXIT_ERROR   /* Exit with error */
} interactive_result_t;

/* ========================================================================
 * Interactive Mode Entry Point
 * ======================================================================== */

/**
 * Run interactive profile selector
 *
 * Main entry point for `dotta --interactive`. Displays profile list,
 * handles user input, and executes commands.
 *
 * Workflow:
 * 1. Load available profiles from repository
 * 2. Load current state to determine selected profiles
 * 3. Enter interactive loop:
 *    - Render UI
 *    - Read user input
 *    - Update state or execute command
 * 4. Clean up and exit
 *
 * Terminal requirements:
 * - Must be a TTY (returns error if not)
 * - Must support ANSI escape sequences
 *
 * @param repo Repository (must not be NULL)
 * @return Error or NULL on success
 */
error_t *interactive_run(git_repository *repo);

/* ========================================================================
 * State Management (internal, exposed for testing)
 * ======================================================================== */

/**
 * Create interactive state
 *
 * Loads all profiles and current selections.
 *
 * @param repo Repository (must not be NULL)
 * @param out State (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t *interactive_state_create(
    git_repository *repo,
    interactive_state_t **out
);

/**
 * Free interactive state
 *
 * @param state State to free (can be NULL)
 */
void interactive_state_free(interactive_state_t *state);

/**
 * Get profile items
 *
 * Returns read-only view of profile list.
 *
 * @param state State (must not be NULL)
 * @param out_items Profile items array (must not be NULL)
 * @param out_count Item count (must not be NULL)
 */
void interactive_state_get_items(
    const interactive_state_t *state,
    const profile_item_t **out_items,
    size_t *out_count
);

/**
 * Get cursor position
 *
 * @param state State (must not be NULL)
 * @return Current cursor index (0-based)
 */
size_t interactive_state_get_cursor(const interactive_state_t *state);

/* ========================================================================
 * UI Rendering (internal)
 * ======================================================================== */

/**
 * Render UI
 *
 * Draws the profile list and status bar inline.
 *
 * Layout:
 * ```
 *   Profiles:
 *
 *     ✓ global
 *     ✓ darwin
 *     ✓ darwin/work
 *       linux
 *   ▶   hosts/macbook
 *       hosts/server
 *
 * ↑↓ navigate  space toggle  J/K move  q quit
 * ```
 *
 * @param state State (must not be NULL)
 * @return Number of lines rendered
 */
int interactive_render(const interactive_state_t *state);

/**
 * Calculate required screen lines
 *
 * @param state State (must not be NULL)
 * @return Number of lines needed (including header and footer)
 */
int interactive_get_required_lines(const interactive_state_t *state);

/* ========================================================================
 * Input Handling (internal)
 * ======================================================================== */

/**
 * Handle key press
 *
 * Processes user input and updates state or executes commands.
 *
 * @param state State (must not be NULL)
 * @param repo Repository (must not be NULL)
 * @param key Key code
 * @param term_ptr Terminal pointer (for restoring during commands, must not be NULL)
 * @return Command result
 */
interactive_result_t interactive_handle_key(
    interactive_state_t *state,
    git_repository *repo,
    int key,
    terminal_t **term_ptr
);

/* ========================================================================
 * Profile Item Utilities
 * ======================================================================== */

/**
 * Free profile item
 *
 * @param item Item to free (can be NULL)
 */
void profile_item_free(profile_item_t *item);

/**
 * Calculate indent level from profile name
 *
 * Examples:
 * - "global" -> 0
 * - "darwin" -> 0
 * - "darwin/work" -> 1
 * - "hosts/macbook" -> 0
 * - "hosts/macbook/personal" -> 1
 *
 * @param profile_name Profile name (must not be NULL)
 * @return Indent level
 */
int interactive_get_indent_level(const char *profile_name);

/**
 * Check if profile is host-based
 *
 * @param profile_name Profile name (must not be NULL)
 * @return true if starts with "hosts/"
 */
bool interactive_is_host_profile(const char *profile_name);

#endif /* DOTTA_INTERACTIVE_H */
