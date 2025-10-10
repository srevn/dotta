/**
 * help.c - Help and usage functions
 *
 * Provides help text and usage information for all commands.
 */

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dotta/version.h"

void print_usage(const char *prog_name) {
    printf("Dotta - Dotfile Manager\n\n");
    printf("Usage: %s <command> [options]\n\n", prog_name);
    printf("Commands:\n");
    printf("  init       Initialize a new dotta repository\n");
    printf("  clone      Clone a dotta repository\n");
    printf("  add        Add files to a profile\n");
    printf("  apply      Apply profiles to filesystem\n");
    printf("  status     Show status of managed files\n");
    printf("  diff       Show differences between profiles and filesystem\n");
    printf("  list       List profiles, files, and commit history\n");
    printf("  clean      Remove untracked managed files\n");
    printf("  show       Show file content from profile\n");
    printf("  revert     Revert file to previous commit state\n");
    printf("  remote     Manage remote repositories\n");
    printf("  update     Update profiles with modified files\n");
    printf("  sync       Intelligently sync with remote\n");
    printf("  ignore     Manage ignore patterns\n");
    printf("  git        Execute git commands in repository\n");
    printf("\nRun '%s <command> --help' for more information on a command.\n", prog_name);
}

void print_version(void) {
    int major, minor, rev;
    git_libgit2_version(&major, &minor, &rev);

    /* Print dotta version */
    printf("dotta version %s\n", dotta_version_string());

    /* Print build information */
    const char *commit = dotta_version_commit();
    if (commit && strcmp(commit, "unknown") != 0) {
        printf("Build: %s (commit %s)\n",
               dotta_version_build_date(),
               commit);
    } else {
        printf("Build: %s %s\n",
               dotta_version_build_date(),
               dotta_version_build_time());
    }

    /* Print libgit2 version */
    printf("Built with libgit2 %d.%d.%d\n", major, minor, rev);
}

void print_init_help(const char *prog_name) {
    printf("Usage: %s init [options] [path]\n\n", prog_name);
    printf("Initialize a new dotta repository\n\n");
    printf("Options:\n");
    printf("  -q, --quiet    Suppress output\n");
    printf("  --help         Show this help message\n");
    printf("\n");
}

void print_add_help(const char *prog_name) {
    printf("Usage: %s add [options] --profile <name> <file|dir>...\n\n", prog_name);
    printf("Add files to a profile\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>   Profile name (required)\n");
    printf("  -m, --message <msg>    Commit message\n");
    printf("  -e, --exclude <pattern> Exclude pattern (glob, can be repeated)\n");
    printf("  -f, --force            Overwrite existing files in profile\n");
    printf("  -v, --verbose          Print verbose output\n");
    printf("  --help                 Show this help message\n");
    printf("\nExclude Patterns:\n");
    printf("  Supports glob patterns: *, ?, [abc]\n");
    printf("  Examples:\n");
    printf("    --exclude '*.log'       Exclude all .log files\n");
    printf("    --exclude '.git/*'      Exclude .git directory\n");
    printf("    --exclude '*.tmp'       Exclude temporary files\n");
    printf("  Multiple patterns:\n");
    printf("    --exclude '*.log' --exclude '*.tmp'\n");
    printf("\n");
}

void print_apply_help(const char *prog_name) {
    printf("Usage: %s apply [options] [profile]...\n\n", prog_name);
    printf("Apply profiles to filesystem\n\n");
    printf("Options:\n");
    printf("  -f, --force            Overwrite modified files\n");
    printf("  -n, --dry-run          Don't actually deploy\n");
    printf("  --prune                Remove untracked managed files\n");
    printf("  --skip-existing        Skip files that already exist\n");
    printf("  --no-skip-unchanged    Disable smart skipping (default: enabled)\n");
    printf("  -v, --verbose          Print verbose output\n");
    printf("  --help                 Show this help message\n");
    printf("\n");
    printf("Smart Skipping:\n");
    printf("  By default, files that match profile content are skipped for efficiency.\n");
    printf("  Use --no-skip-unchanged to force deployment of all files.\n");
    printf("\n");
}

void print_status_help(const char *prog_name) {
    printf("Usage: %s status [options] [profile]...\n\n", prog_name);
    printf("Show status of managed files and remote sync state\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>   Check specific profile\n");
    printf("  -v, --verbose          Print verbose output\n");
    printf("\nScope:\n");
    printf("  --local                Show only filesystem status (files deployed/modified)\n");
    printf("  --remote               Show only remote sync status\n");
    printf("  (default)              Show both filesystem and remote status\n");
    printf("\nRemote options:\n");
    printf("  --no-fetch             Don't fetch before checking remote (faster, may be stale)\n");
    printf("\nHelp:\n");
    printf("  --help                 Show this help message\n");
    printf("\nRemote State Indicators:\n");
    printf("  =   up-to-date with remote\n");
    printf("  ↑n  n commits ahead of remote (ready to push)\n");
    printf("  ↓n  n commits behind remote (run 'dotta sync' to pull)\n");
    printf("  ↕   diverged from remote (needs resolution)\n");
    printf("  •   no remote tracking branch\n");
    printf("\nExamples:\n");
    printf("  %s status                     # Show complete status (local + remote)\n", prog_name);
    printf("  %s status --local             # Show only filesystem status\n", prog_name);
    printf("  %s status --remote            # Show only remote sync status\n", prog_name);
    printf("  %s status --no-fetch          # Fast check (use cached remote refs)\n", prog_name);
    printf("  %s status -v                  # Verbose output with details\n", prog_name);
    printf("  %s status global              # Check only 'global' profile\n", prog_name);
    printf("\n");
}

void print_list_help(const char *prog_name) {
    printf("Usage: %s list [options] [profile]\n\n", prog_name);
    printf("List profiles, files, or commit history\n\n");
    printf("Modes:\n");
    printf("  (default)               List all profiles\n");
    printf("  [profile]               List files in specified profile\n");
    printf("  --log [profile]         Show commit history\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>   Specify profile name\n");
    printf("  -v, --verbose          Show verbose output (file counts for profiles)\n");
    printf("  --remote               Show remote tracking state for profiles\n");
    printf("  --oneline              Show commits in one-line format (for --log)\n");
    printf("  -n <count>             Limit commits shown (for --log)\n");
    printf("  --help                 Show this help message\n");
    printf("\nRemote State Indicators (with --remote):\n");
    printf("  [=]   up-to-date with remote\n");
    printf("  [↑n]  n commits ahead of remote (run 'dotta sync' to push)\n");
    printf("  [↓n]  n commits behind remote (run 'dotta sync' to pull)\n");
    printf("  [↕]   diverged from remote (manual resolution needed)\n");
    printf("  [•]   no remote tracking branch (will be created on first sync)\n");
    printf("\nExamples:\n");
    printf("  %s list                   # List all profiles\n", prog_name);
    printf("  %s list --remote          # List profiles with remote state\n", prog_name);
    printf("  %s list global            # List files in 'global' profile\n", prog_name);
    printf("  %s list --log             # Show commit history for all profiles\n", prog_name);
    printf("  %s list --log global      # Show commit history for 'global' profile\n", prog_name);
    printf("  %s list --log --oneline -n 5  # Show last 5 commits, one per line\n", prog_name);
    printf("\n");
}

void print_diff_help(const char *prog_name) {
    printf("Usage: %s diff [options] [file]...\n\n", prog_name);
    printf("Show differences between profiles and filesystem\n\n");
    printf("Direction options:\n");
    printf("  --upstream       Show repo → filesystem (what 'apply' would change) [default]\n");
    printf("  --downstream     Show filesystem → repo (what 'update' would commit)\n");
    printf("  -a, --all        Show both upstream and downstream with headers\n");
    printf("\nOther options:\n");
    printf("  --name-only      Only show file names, not diffs\n");
    printf("  --help           Show this help message\n");
    printf("\nConcepts:\n");
    printf("  Upstream:   Repository (source of truth for configuration)\n");
    printf("  Downstream: Filesystem (deployed state)\n");
    printf("\n");
}

void print_clean_help(const char *prog_name) {
    printf("Usage: %s clean [options]\n\n", prog_name);
    printf("Remove orphaned files\n\n");
    printf("Options:\n");
    printf("  -n, --dry-run    Don't actually remove files\n");
    printf("  -f, --force      Remove without confirmation\n");
    printf("  -v, --verbose    Print verbose output\n");
    printf("  --help           Show this help message\n");
    printf("\n");
}

void print_clone_help(const char *prog_name) {
    printf("Usage: %s clone [options] <url> [path]\n\n", prog_name);
    printf("Clone a dotta repository from remote\n\n");
    printf("Arguments:\n");
    printf("  <url>            Remote repository URL\n");
    printf("  [path]           Local directory (default: derived from URL)\n");
    printf("\nOptions:\n");
    printf("  -q, --quiet      Suppress output\n");
    printf("  -v, --verbose    Print verbose output\n");
    printf("  --help           Show this help message\n");
    printf("\n");
}

void print_show_help(const char *prog_name) {
    printf("Usage: %s show [options] <file>\n\n", prog_name);
    printf("Show file content from a profile\n\n");
    printf("Arguments:\n");
    printf("  <file>           File path or basename to search for\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>  Profile name (searches all configured profiles if omitted)\n");
    printf("  -c, --commit <ref>    Show file from specific commit (requires --profile)\n");
    printf("                        Examples: HEAD, HEAD~3, abc123\n");
    printf("  --raw                 Show raw content without header\n");
    printf("  --help                Show this help message\n");
    printf("\nBehavior:\n");
    printf("  Without --profile: Searches for file by basename across all configured profiles\n");
    printf("  With --profile: Looks for exact file path in specified profile\n");
    printf("  With --commit: Shows file version from that commit in profile history\n");
    printf("\n");
}

void print_revert_help(const char *prog_name) {
    printf("Usage: %s revert [options] <file> <commit>\n\n", prog_name);
    printf("Revert a file in a profile to its state at a specific commit\n\n");
    printf("Arguments:\n");
    printf("  <file>           File path or basename to revert\n");
    printf("  <commit>         Target commit reference (e.g., HEAD~3, abc123)\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>  Profile name (required if file exists in multiple profiles)\n");
    printf("  --apply              Deploy reverted file to filesystem after reverting\n");
    printf("  --commit             Create a commit with the reverted changes\n");
    printf("  -m, --message <msg>  Commit message (requires --commit)\n");
    printf("  -f, --force          Skip confirmation and override conflicts\n");
    printf("  --dry-run            Preview changes without modifying anything\n");
    printf("  -v, --verbose        Print verbose output\n");
    printf("  --help               Show this help message\n");
    printf("\nBehavior:\n");
    printf("  1. Discovers file in profiles (exact path or basename search)\n");
    printf("  2. Resolves target commit in profile history\n");
    printf("  3. Shows diff preview between current and target state\n");
    printf("  4. Prompts for confirmation (unless --force)\n");
    printf("  5. Updates file in profile branch to target state\n");
    printf("  6. Optionally creates commit (with --commit)\n");
    printf("  7. Optionally deploys to filesystem (with --apply)\n");
    printf("\nExamples:\n");
    printf("  # Revert .bashrc to 3 commits ago\n");
    printf("  %s revert .bashrc HEAD~3\n\n", prog_name);
    printf("  # Revert and deploy\n");
    printf("  %s revert --apply .bashrc abc123\n\n", prog_name);
    printf("  # Revert with commit message\n");
    printf("  %s revert --commit -m \"Fix broken config\" .bashrc HEAD~1\n", prog_name);
    printf("\n");
}

void print_remote_help(const char *prog_name) {
    printf("Usage: %s remote [options] [subcommand]\n\n", prog_name);
    printf("Manage remote repositories\n\n");
    printf("Subcommands:\n");
    printf("  (none)                   List remotes\n");
    printf("  add <name> <url>         Add a new remote\n");
    printf("  remove <name>            Remove a remote\n");
    printf("  set-url <name> <url>     Change remote URL\n");
    printf("  rename <old> <new>       Rename a remote\n");
    printf("  show <name>              Show remote details\n");
    printf("\nOptions:\n");
    printf("  -v, --verbose    Show URLs (for list)\n");
    printf("  --help           Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s remote\n", prog_name);
    printf("  %s remote -v\n", prog_name);
    printf("  %s remote add origin git@github.com:user/dotfiles.git\n", prog_name);
    printf("  %s remote set-url origin https://github.com/user/dotfiles.git\n", prog_name);
    printf("\n");
}

void print_update_help(const char *prog_name) {
    printf("Usage: %s update [options] [file]...\n\n", prog_name);
    printf("Update profiles with modified files\n\n");
    printf("Syncs filesystem changes back into profile branches.\n");
    printf("This is the reverse of 'apply' (filesystem -> repo).\n\n");
    printf("Options:\n");
    printf("  -m, --message <msg>    Custom commit message\n");
    printf("  -p, --profile <name>   Only update files from this profile\n");
    printf("  -n, --dry-run          Show what would be updated\n");
    printf("  -i, --interactive      Prompt for confirmation\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  --include-new          Include new files from tracked directories\n");
    printf("  --only-new             Only process new files (ignore modified)\n");
    printf("  --help                 Show this help message\n");
    printf("\nNew File Detection:\n");
    printf("  By default, new files are auto-detected based on config settings:\n");
    printf("    - core.auto_detect_new_files controls automatic detection\n");
    printf("    - security.confirm_new_files controls confirmation prompts\n");
    printf("  Use --include-new or --only-new to explicitly override config.\n");
    printf("\nExamples:\n");
    printf("  %s update                        # Update all modified files\n", prog_name);
    printf("  %s update ~/.bashrc              # Update specific file\n", prog_name);
    printf("  %s update --include-new          # Update modified AND add new files\n", prog_name);
    printf("  %s update --only-new             # Only add new files\n", prog_name);
    printf("  %s update --profile global       # Update only global profile\n", prog_name);
    printf("  %s update --dry-run              # Preview changes\n", prog_name);
    printf("  %s update -m \"Update shell config\"  # Custom message\n", prog_name);
    printf("\n");
}

void print_sync_help(const char *prog_name) {
    printf("Usage: %s sync [options]\n\n", prog_name);
    printf("Intelligently synchronize with remote repository\n\n");
    printf("Combines update + fetch + conditional push/pull with safety checks.\n");
    printf("The 'do what I mean' command for dotfile synchronization.\n\n");
    printf("Options:\n");
    printf("  -m, --message <msg>        Custom commit message for updates\n");
    printf("  -p, --profile <name>       Only sync specific profile\n");
    printf("  -n, --dry-run              Show what would happen\n");
    printf("  --no-push                  Update locally but skip push\n");
    printf("  --no-pull                  Skip pulling remote changes (push-only)\n");
    printf("  --mode <mode>              Sync mode: local, auto, all\n");
    printf("                             local: All local branches + discover new (default)\n");
    printf("                             auto: Only auto-detected profiles\n");
    printf("                             all: Fetch and sync all remote branches\n");
    printf("  --diverged <strategy>      How to handle diverged branches:\n");
    printf("                             warn (default), rebase, merge, ours, theirs\n");
    printf("  -v, --verbose              Verbose output\n");
    printf("  --include-new              Include new files from tracked directories\n");
    printf("  --only-new                 Only sync new files (ignore modified)\n");
    printf("  --help                     Show this help message\n");
    printf("\nWhat it does:\n");
    printf("  1. Updates local profiles with any modified files (and new files if enabled)\n");
    printf("  2. Fetches latest changes from remote\n");
    printf("  3. Analyzes each branch (ahead/behind/diverged)\n");
    printf("  4. Auto-pulls when remote is ahead (fast-forward only)\n");
    printf("  5. Auto-pushes when local is ahead\n");
    printf("  6. Warns about diverged branches (or resolves based on --diverged strategy)\n");
    printf("\nConfiguration:\n");
    printf("  Set defaults in ~/.config/dotta/config.toml:\n");
    printf("    [sync]\n");
    printf("    mode = \"local\"              # local (default), auto, or all\n");
    printf("    auto_pull = true\n");
    printf("    diverged_strategy = \"warn\"\n");
    printf("\nExamples:\n");
    printf("  %s sync                       # Smart sync (default: mode=local)\n", prog_name);
    printf("  %s sync --mode=auto           # Only sync auto-detected profiles\n", prog_name);
    printf("  %s sync --mode=all            # Mirror entire remote (all branches)\n", prog_name);
    printf("  %s sync --include-new         # Sync modified AND new files\n", prog_name);
    printf("  %s sync --profile global      # Sync only specific profile\n", prog_name);
    printf("  %s sync --dry-run             # Preview sync actions\n", prog_name);
    printf("  %s sync --no-push             # Update but don't push\n", prog_name);
    printf("  %s sync --no-pull             # Push only, skip pulling\n", prog_name);
    printf("  %s sync --diverged=ours       # Keep local version on divergence\n", prog_name);
    printf("\nSync Modes:\n");
    printf("  local (default): Sync all local branches + discover new remote branches\n");
    printf("                   Perfect for variant profile workflows\n");
    printf("  auto:            Only sync global + OS + hosts/<hostname>\n");
    printf("                   Perfect for minimal/single-purpose machines\n");
    printf("  all:             Mirror entire remote repository\n");
    printf("                   Perfect for hub/backup servers\n");
    printf("\n");
}

void print_ignore_help(const char *prog_name) {
    printf("Usage: %s ignore [options]\n\n", prog_name);
    printf("Manage ignore patterns for dotfile tracking\n\n");
    printf("Modes:\n");
    printf("  Edit mode (default):  Opens .dottaignore in your editor\n");
    printf("  Test mode (--test):   Check if a path would be ignored\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>   Profile name (edit: edit profile .dottaignore,\n");
    printf("                         test: test against specific profile only)\n");
    printf("  --test <path>          Test if path would be ignored by active profiles\n");
    printf("  -v, --verbose          Print verbose output (test mode: show all patterns)\n");
    printf("  --help                 Show this help message\n");
    printf("\nIgnore Pattern Layers (in precedence order):\n");
    printf("  1. CLI patterns (--exclude flags, highest priority)\n");
    printf("  2. Combined .dottaignore (baseline + profile)\n");
    printf("     - Baseline .dottaignore (from dotta-worktree branch, applies to all profiles)\n");
    printf("     - Profile .dottaignore (extends baseline, can use ! to override)\n");
    printf("  3. Config file patterns\n");
    printf("  4. Source .gitignore (lowest priority)\n");
    printf("\nPattern Syntax:\n");
    printf("  *.log          # Ignore all .log files\n");
    printf("  node_modules/  # Ignore node_modules directories\n");
    printf("  !debug.log     # Negate (keep debug.log even if *.log matches)\n");
    printf("  .cache/        # Ignore .cache directories\n");
    printf("\nProfile .dottaignore Behavior:\n");
    printf("  - Profile .dottaignore files start EMPTY and inherit all baseline patterns\n");
    printf("  - Use negation (!) to override baseline patterns in specific profiles\n");
    printf("  - Example: Baseline has '*.log', profile adds '!important.log' → important.log NOT ignored\n");
    printf("\nEditor Selection (for edit mode):\n");
    printf("  $DOTTA_EDITOR → $VISUAL → $EDITOR → vi\n");
    printf("\nExamples:\n");
    printf("  # Edit baseline .dottaignore\n");
    printf("  %s ignore\n\n", prog_name);
    printf("  # Edit global profile .dottaignore\n");
    printf("  %s ignore --profile global\n\n", prog_name);
    printf("  # Test if path is ignored (checks all active profiles)\n");
    printf("  %s ignore --test ~/.config/nvim/node_modules\n\n", prog_name);
    printf("  # Test against specific profile only\n");
    printf("  %s ignore --test ~/.bashrc --profile global\n", prog_name);
    printf("\n");
}
