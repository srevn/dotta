/**
 * help.c - Help and usage functions
 *
 * Provides help text and usage information for all commands.
 */

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "version.h"

void print_usage(const char *prog_name) {
    printf("Dotta - Dotfile Manager\n\n");
    printf("Usage: %s <command> [options]\n\n", prog_name);
    printf("Commands:\n");
    printf("  init         Initialize a new dotta repository\n");
    printf("  clone        Clone a dotta repository\n");
    printf("  add          Add files to a profile\n");
    printf("  remove       Remove files from a profile or delete profile\n");
    printf("  apply        Apply profiles to filesystem\n");
    printf("  status       Show status of managed files\n");
    printf("  diff         Show differences between profiles and filesystem\n");
    printf("  list         List profiles, files, and commit history\n");
    printf("  profile      Manage profile lifecycle (list, fetch, activate, deactivate)\n");
    printf("  clean        Remove untracked managed files\n");
    printf("  show         Show file content from profile\n");
    printf("  revert       Revert file to previous commit state\n");
    printf("  remote       Manage remote repositories\n");
    printf("  update       Update profiles with modified files\n");
    printf("  sync         Intelligently sync with remote\n");
    printf("  ignore       Manage ignore patterns\n");
    printf("  bootstrap    Execute profile bootstrap scripts\n");
    printf("  git          Execute git commands in repository\n");
    printf("\nRun '%s <command> --help' for more information on a command.\n", prog_name);
}

void print_version(void) {
    int major, minor, rev;
    git_libgit2_version(&major, &minor, &rev);

    /* Print dotta version */
    printf("dotta version %s\n", dotta_version_string());

    /* Print git information */
    const char *commit = dotta_version_commit();
    const char *branch = dotta_version_branch();
    if (commit && strcmp(commit, "unknown") != 0) {
        printf("Git: %s", commit);
        if (branch && strcmp(branch, "unknown") != 0) {
            printf(" (%s)", branch);
        }
        printf("\n");
    }

    /* Print platform information */
    const char *build_os = dotta_version_build_os();
    const char *build_arch = dotta_version_build_arch();
    if (build_os && strcmp(build_os, "unknown") != 0 &&
        build_arch && strcmp(build_arch, "unknown") != 0) {
        printf("Platform: %s/%s\n", build_os, build_arch);
    }

    /* Print build information */
    const char *build_type = dotta_version_build_type();
    printf("Build: %s", build_type);
    if (build_type && strcmp(build_type, "debug") == 0) {
        printf(" (with sanitizers)");
    }
    printf(" - %s %s\n",
           dotta_version_build_date(),
           dotta_version_build_time());

    /* Print compiler information */
    const char *cc = dotta_version_build_cc();
    if (cc && strcmp(cc, "unknown") != 0) {
        printf("Compiler: %s\n", cc);
    }

    /* Print libgit2 version */
    printf("libgit2: %d.%d.%d\n", major, minor, rev);
}

void print_init_help(const char *prog_name) {
    printf("Usage: %s init [options] [path]\n\n", prog_name);
    printf("Initialize a new dotta repository\n\n");
    printf("Options:\n");
    printf("  -q, --quiet    Suppress output\n");
    printf("  --help         Show this help message\n");
    printf("\n");
}

void print_clone_help(const char *prog_name) {
    printf("Usage: %s clone [options] <url> [path]\n\n", prog_name);
    printf("Clone a dotta repository from remote\n\n");
    printf("Arguments:\n");
    printf("  <url>              Remote repository URL\n");
    printf("  [path]             Local directory (default: derived from URL)\n");
    printf("\nProfile Selection (choose one):\n");
    printf("  (default)          Auto-detect profiles for this system (global, OS, host)\n");
    printf("  --all              Fetch all remote profiles (hub/backup workflow)\n");
    printf("  -p, --profiles <name>...  Fetch specific profiles explicitly\n");
    printf("\nOther Options:\n");
    printf("  -q, --quiet        Suppress output\n");
    printf("  -v, --verbose      Print verbose output\n");
    printf("  --bootstrap        Automatically run bootstrap scripts after clone\n");
    printf("  --no-bootstrap     Skip bootstrap execution entirely\n");
    printf("  --help             Show this help message\n");
    printf("\nProfile Behavior:\n");
    printf("  By default, clone auto-detects profiles relevant to the current system\n");
    printf("  (e.g., 'global', 'darwin', 'hosts/macbook') and fetches only those.\n");
    printf("  This creates a safe default where only appropriate configs are active.\n\n");
    printf("  Fetched profiles are automatically activated and stored in state.\n");
    printf("  Use 'dotta profile list' to view active vs available profiles.\n");
    printf("\nBootstrap Integration:\n");
    printf("  After cloning, dotta checks for bootstrap scripts in detected profiles.\n");
    printf("  By default, you'll be prompted to run them. Use --bootstrap to auto-run\n");
    printf("  or --no-bootstrap to skip.\n");
    printf("\nExamples:\n");
    printf("  %s clone git@github.com:user/dotfiles.git\n", prog_name);
    printf("      Clone and auto-detect profiles for this system\n\n");
    printf("  %s clone <url> --all\n", prog_name);
    printf("      Hub mode: fetch all profiles (for backup/mirror machines)\n\n");
    printf("  %s clone <url> --profiles global darwin fish\n", prog_name);
    printf("      Fetch specific profiles explicitly\n\n");
    printf("  %s clone <url> --bootstrap\n", prog_name);
    printf("      Clone and automatically run bootstrap scripts\n");
    printf("\nAfter cloning:\n");
    printf("  %s profile list                         # View active profiles\n", prog_name);
    printf("  %s profile activate <name>              # Activate additional profiles\n", prog_name);
    printf("  %s bootstrap                            # Run bootstrap manually\n", prog_name);
    printf("  %s apply                                # Apply profiles\n", prog_name);
    printf("\n");
}

void print_add_help(const char *prog_name) {
    printf("Usage: %s add [options] --profile <name> <file|dir>...\n\n", prog_name);
    printf("Add files to a profile\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>      Profile name (required)\n");
    printf("  -m, --message <msg>       Commit message\n");
    printf("  -e, --exclude <pattern>   Exclude pattern (glob, can be repeated)\n");
    printf("  -f, --force               Overwrite existing files in profile\n");
    printf("  -v, --verbose             Print verbose output\n");
    printf("  --help                    Show this help message\n");
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

void print_remove_help(const char *prog_name) {
    printf("Usage: %s remove [options] --profile <name> <file|dir>...\n", prog_name);
    printf("       %s remove [options] --profile <name> --delete-profile\n\n", prog_name);
    printf("Remove files from a profile or delete entire profile\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>   Profile name (required)\n");
    printf("  --delete-profile       Delete entire profile branch\n");
    printf("  --keep-files           Keep deployed files on filesystem\n");
    printf("  -m, --message <msg>    Custom commit message\n");
    printf("  -n, --dry-run          Show what would be removed without doing it\n");
    printf("  -f, --force            Skip confirmations, ignore missing files\n");
    printf("  -i, --interactive      Prompt for each file\n");
    printf("  -v, --verbose          Print verbose output\n");
    printf("  -q, --quiet            Minimal output\n");
    printf("  --help                 Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s remove --profile global ~/.bashrc\n", prog_name);
    printf("      Remove ~/.bashrc from 'global' profile AND delete from filesystem\n\n");
    printf("  %s remove --profile global ~/.bashrc --keep-files\n", prog_name);
    printf("      Remove from profile only (keep deployed file on filesystem)\n\n");
    printf("  %s remove --profile global ~/.config/nvim\n", prog_name);
    printf("      Remove entire directory from profile and filesystem\n\n");
    printf("  %s remove --profile test --delete-profile\n", prog_name);
    printf("      Delete entire 'test' profile branch and remove deployed files\n\n");
    printf("  %s remove --profile test --delete-profile --keep-files\n", prog_name);
    printf("      Delete profile but keep deployed files on filesystem\n\n");
    printf("  %s remove --profile global ~/.bashrc --dry-run\n", prog_name);
    printf("      Preview what would be removed\n");
    printf("\nNotes:\n");
    printf("  - By default, files are removed from BOTH profile and filesystem (atomic operation)\n");
    printf("  - Use --keep-files to preserve files on filesystem after removal from profile\n");
    printf("  - Use 'dotta apply' later to clean up orphaned files\n");
    printf("  - Deleted profile branches can be recovered from remote if pushed\n");
    printf("\n");
}

void print_apply_help(const char *prog_name) {
    printf("Usage: %s apply [options] [profile]...\n\n", prog_name);
    printf("Synchronize filesystem with profiles\n\n");
    printf("Description:\n");
    printf("  Apply performs a complete synchronization:\n");
    printf("  • Deploys new and updated files from active profiles\n");
    printf("  • Removes orphaned files (from deactivated profiles)\n");
    printf("  • Updates state to reflect current deployment\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>   Specify profile(s) to apply\n");
    printf("  -f, --force            Overwrite modified files\n");
    printf("  -n, --dry-run          Don't actually deploy\n");
    printf("  --keep-orphans         Don't remove orphaned files (advanced)\n");
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
    printf("  --all                  Show all local profiles, not just active ones\n");
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

void print_diff_help(const char *prog_name) {
    printf("Usage: %s diff [options] [file]...\n\n", prog_name);
    printf("Show differences between profiles and filesystem\n\n");
    printf("Direction options:\n");
    printf("  --upstream       Show repo → filesystem (what 'apply' would change) [default]\n");
    printf("  --downstream     Show filesystem → repo (what 'update' would commit)\n");
    printf("  -a, --all        Show both upstream and downstream with headers\n");
    printf("\nOther options:\n");
    printf("  -p, --profile <name>  Check specific profile\n");
    printf("  --name-only           Only show file names, not diffs\n");
    printf("  --help                Show this help message\n");
    printf("\nConcepts:\n");
    printf("  Upstream:   Repository (source of truth for configuration)\n");
    printf("  Downstream: Filesystem (deployed state)\n");
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
    printf("  -p, --profile <name>    Specify profile name\n");
    printf("  -v, --verbose           Show verbose output (file counts for profiles)\n");
    printf("  --remote                Show remote tracking state for profiles\n");
    printf("  --oneline               Show commits in one-line format (for --log)\n");
    printf("  -n <count>              Limit commits shown (for --log)\n");
    printf("  --help                  Show this help message\n");
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

void print_profile_help(const char *prog_name) {
    printf("Usage: %s profile <subcommand> [options]\n\n", prog_name);
    printf("Manage profile lifecycle and activation state\n\n");
    printf("Profile lifecycle separates availability from activation:\n");
    printf("  • Available profiles exist locally but are not used by commands\n");
    printf("  • Active profiles are used by apply, update, sync, status, and diff\n");
    printf("  • Profile activation state persists in .git/dotta-state.json\n\n");
    printf("Subcommands:\n");
    printf("  list                     Show profiles with activation status\n");
    printf("  fetch <name>...          Download profiles from remote without activating\n");
    printf("  activate <name>...       Add profiles to active set\n");
    printf("  deactivate <name>...     Remove profiles from active set\n");
    printf("  reorder <name>...        Change order of active profiles (affects layering)\n");
    printf("  validate                 Check and fix state consistency\n");
    printf("\nOptions (list):\n");
    printf("  --remote                 Show remote profiles not yet fetched\n");
    printf("  --available              Show available (inactive) profiles\n");
    printf("  -v, --verbose            Show file counts per profile\n");
    printf("\nOptions (fetch/activate):\n");
    printf("  --all                    Operate on all profiles\n");
    printf("  -v, --verbose            Show detailed progress\n");
    printf("\nOptions (deactivate):\n");
    printf("  --all                    Deactivate all profiles\n");
    printf("  -n, --dry-run            Show what would change without doing it\n");
    printf("  -v, --verbose            Show detailed progress\n");
    printf("\nOptions (reorder):\n");
    printf("  -v, --verbose            Show before/after profile order\n");
    printf("\nOptions (validate):\n");
    printf("  --fix                    Auto-fix state inconsistencies\n");
    printf("  -v, --verbose            Show detailed validation checks\n");
    printf("\nCommon Options:\n");
    printf("  -q, --quiet              Suppress non-error output\n");
    printf("  --help                   Show this help message\n");
    printf("\nTypical Workflow:\n");
    printf("  1. Clone repo (profiles auto-activated based on system)\n");
    printf("  2. Check status:       %s profile list\n", prog_name);
    printf("  3. Fetch more:         %s profile fetch <name>\n", prog_name);
    printf("  4. Activate as needed: %s profile activate <name>\n", prog_name);
    printf("  5. Use in commands:    %s apply, %s status, etc.\n", prog_name, prog_name);
    printf("\nExamples:\n");
    printf("  %s profile list                       # Show active vs available\n", prog_name);
    printf("  %s profile list --remote -v           # Show remote + file counts\n", prog_name);
    printf("  %s profile fetch darwin linux         # Download specific profiles\n", prog_name);
    printf("  %s profile fetch --all                # Download all remote profiles\n", prog_name);
    printf("  %s profile activate darwin            # Activate for use\n", prog_name);
    printf("  %s profile activate fish zsh tmux     # Activate multiple\n", prog_name);
    printf("  %s profile deactivate --all           # Deactivate everything\n", prog_name);
    printf("  %s profile reorder darwin global      # Change profile order\n", prog_name);
    printf("  %s profile validate --fix             # Fix state issues\n", prog_name);
    printf("\n");
}

void print_clean_help(const char *prog_name) {
    printf("Usage: %s clean [options]\n\n", prog_name);
    printf("Remove orphaned files from filesystem\n\n");
    printf("Description:\n");
    printf("  Finds and removes files that were previously deployed by 'dotta apply'\n");
    printf("  but are no longer in any active profile.\n\n");
    printf("Options:\n");
    printf("  -n, --dry-run     Show what would be removed without doing it\n");
    printf("  -f, --force       Remove without confirmation\n");
    printf("  -v, --verbose     Print detailed output with status for each file\n");
    printf("  -q, --quiet       Minimal output (only errors)\n");
    printf("  --help            Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s clean\n", prog_name);
    printf("      Find and remove orphaned files (with confirmation)\n\n");
    printf("  %s clean --dry-run\n", prog_name);
    printf("      Preview what files would be removed\n\n");
    printf("  %s clean --force\n", prog_name);
    printf("      Remove orphaned files without confirmation\n\n");
    printf("  %s clean --verbose\n", prog_name);
    printf("      Show detailed status for each file being removed\n");
    printf("\nUse Cases:\n");
    printf("  - After manually deleting files from profile branches with git\n");
    printf("  - After removing files with 'dotta remove --keep-files'\n");
    printf("  - After deactivating profiles with 'dotta apply --keep-orphans'\n");
    printf("  - To clean up before switching to a different profile set\n");
    printf("\nAlternatives:\n");
    printf("  - 'dotta apply'                  Synchronize (deploy AND clean orphans)\n");
    printf("  - 'dotta remove <file>'          Remove from profile AND filesystem (atomic)\n");
    printf("\n");
}

void print_show_help(const char *prog_name) {
    printf("Usage: %s show [options] <file>\n\n", prog_name);
    printf("Show file content from a profile\n\n");
    printf("Arguments:\n");
    printf("  <file>                File path or basename to search for\n");
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
    printf("  <file>                File path or basename to revert\n");
    printf("  <commit>              Target commit reference (e.g., HEAD~3, abc123)\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>  Profile name (required if file exists in multiple profiles)\n");
    printf("  --apply               Deploy reverted file to filesystem after reverting\n");
    printf("  --commit              Create a commit with the reverted changes\n");
    printf("  -m, --message <msg>   Commit message (requires --commit)\n");
    printf("  -f, --force           Skip confirmation and override conflicts\n");
    printf("  --dry-run             Preview changes without modifying anything\n");
    printf("  -v, --verbose         Print verbose output\n");
    printf("  --help                Show this help message\n");
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
    printf("\nFile Detection:\n");
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
    printf("Synchronize local repository with remote repository\n\n");
    printf("Fetches from remote, analyzes branch states, and pushes/pulls as needed.\n");
    printf("Requires clean workspace - run 'dotta update' first to commit local changes.\n");
    printf("Operates only on active profiles (use 'dotta profile' to manage).\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>       Only sync specific profile (doesn't change state)\n");
    printf("  -n, --dry-run              Show what would happen\n");
    printf("  --no-push                  Fetch and analyze only, skip push\n");
    printf("  --no-pull                  Skip pulling remote changes (push-only)\n");
    printf("  -f, --force                Force sync even with uncommitted changes\n");
    printf("  --diverged <strategy>      How to handle diverged branches:\n");
    printf("                             warn (default), rebase, merge, ours, theirs\n");
    printf("  -v, --verbose              Verbose output\n");
    printf("  --help                     Show this help message\n");
    printf("\nWhat it does:\n");
    printf("  1. Validates workspace is clean (no uncommitted changes)\n");
    printf("  2. Fetches latest changes from remote for active profiles\n");
    printf("  3. Analyzes each active profile (ahead/behind/diverged)\n");
    printf("  4. Auto-pulls when remote is ahead (fast-forward only)\n");
    printf("  5. Auto-pushes when local is ahead\n");
    printf("  6. Resolves diverged branches using configured strategy\n");
    printf("\nTypical Workflow:\n");
    printf("  %s update                  # Commit local changes to profiles\n", prog_name);
    printf("  %s sync                    # Synchronize with remote\n", prog_name);
    printf("\nConfiguration:\n");
    printf("  Set defaults in ~/.config/dotta/config.toml:\n");
    printf("    [sync]\n");
    printf("    auto_pull = true\n");
    printf("    diverged_strategy = \"warn\"\n");
    printf("\nExamples:\n");
    printf("  %s sync                    # Sync active profiles with remote\n", prog_name);
    printf("  %s sync --profile global   # Sync only specific profile\n", prog_name);
    printf("  %s sync --dry-run          # Preview sync actions\n", prog_name);
    printf("  %s sync --force            # Sync even with uncommitted changes\n", prog_name);
    printf("  %s sync --no-pull          # Push only, skip pulling\n", prog_name);
    printf("  %s sync --diverged rebase  # Rebase on divergence\n", prog_name);
    printf("\n");
}

void print_ignore_help(const char *prog_name) {
    printf("Usage: %s ignore [options]\n\n", prog_name);
    printf("Manage ignore patterns for dotfile tracking\n\n");
    printf("Modes:\n");
    printf("  Edit mode (default):  Opens .dottaignore in your editor\n");
    printf("  Add/Remove mode:      Add or remove patterns programmatically\n");
    printf("  Test mode (--test):   Check if a path would be ignored\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>   Profile name (edit: edit profile .dottaignore,\n");
    printf("                         test: test against specific profile only,\n");
    printf("                         add/remove: modify profile .dottaignore)\n");
    printf("  --add <pattern>        Add pattern to .dottaignore (can be used multiple times)\n");
    printf("  --remove <pattern>     Remove pattern from .dottaignore (can be used multiple times)\n");
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
    printf("  # Add patterns to baseline .dottaignore\n");
    printf("  %s ignore --add '*.tmp' --add '*.log'\n\n", prog_name);
    printf("  # Remove pattern from profile .dottaignore\n");
    printf("  %s ignore --profile global --remove '.DS_Store'\n\n", prog_name);
    printf("  # Add and remove patterns in one command\n");
    printf("  %s ignore --add 'newpattern' --remove 'oldpattern'\n\n", prog_name);
    printf("  # Test if path is ignored (checks all active profiles)\n");
    printf("  %s ignore --test ~/.config/nvim/node_modules\n\n", prog_name);
    printf("  # Test against specific profile only\n");
    printf("  %s ignore --test ~/.bashrc --profile global\n", prog_name);
    printf("\n");
}

void print_bootstrap_help(const char *prog_name) {
    printf("Usage: %s bootstrap [options]\n\n", prog_name);
    printf("Execute bootstrap scripts for profile setup\n\n");
    printf("Bootstrap scripts are per-profile shell scripts stored in .dotta/bootstrap\n");
    printf("within each profile branch. They run during initial setup to install\n");
    printf("dependencies, configure system settings, and prepare the environment.\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>      Specify profile(s) to bootstrap (can be repeated)\n");
    printf("  --all                     Bootstrap all available profiles\n");
    printf("  -e, --edit                Edit bootstrap script (requires --profile)\n");
    printf("  --show                    Show bootstrap script content (requires --profile)\n");
    printf("  -l, --list                List all bootstrap scripts\n");
    printf("  -n, --dry-run             Show what would be executed without running\n");
    printf("  -y, --yes, --no-confirm   Skip confirmation prompts\n");
    printf("  --continue-on-error       Continue if a bootstrap script fails\n");
    printf("  --help                    Show this help message\n");
    printf("\nExecution Order:\n");
    printf("  Bootstrap scripts execute in profile resolution order:\n");
    printf("    1. global/.dotta/bootstrap\n");
    printf("    2. <os>/.dotta/bootstrap (darwin, linux, freebsd)\n");
    printf("    3. hosts/<hostname>/.dotta/bootstrap\n");
    printf("\nEnvironment Variables:\n");
    printf("  Scripts receive these environment variables:\n");
    printf("    DOTTA_REPO_DIR   - Path to dotta repository\n");
    printf("    DOTTA_PROFILE    - Current profile name\n");
    printf("    DOTTA_PROFILES   - Space-separated list of all profiles\n");
    printf("    HOME             - User home directory\n");
    printf("\nBootstrap Script Location:\n");
    printf("  Scripts are stored in: <repo>/<profile>/.dotta/bootstrap\n");
    printf("  They are version-controlled and travel with your dotfiles.\n");
    printf("\nEditor Selection (for --edit):\n");
    printf("  $DOTTA_EDITOR → $VISUAL → $EDITOR → nano\n");
    printf("\nExamples:\n");
    printf("  # Run bootstrap for auto-detected profiles\n");
    printf("  %s bootstrap\n\n", prog_name);
    printf("  # Run for specific profile\n");
    printf("  %s bootstrap --profile darwin\n\n", prog_name);
    printf("  # Create/edit bootstrap script for darwin profile\n");
    printf("  %s bootstrap --profile darwin --edit\n\n", prog_name);
    printf("  # List all bootstrap scripts\n");
    printf("  %s bootstrap --list\n\n", prog_name);
    printf("  # Show darwin bootstrap script\n");
    printf("  %s bootstrap --profile darwin --show\n\n", prog_name);
    printf("  # Dry-run (show what would execute)\n");
    printf("  %s bootstrap --dry-run\n\n", prog_name);
    printf("  # Run without prompts\n");
    printf("  %s bootstrap --yes\n", prog_name);
    printf("\nIntegration with Clone:\n");
    printf("  Bootstrap is automatically detected after cloning:\n");
    printf("    %s clone <url>                    # Prompts to run bootstrap\n", prog_name);
    printf("    %s clone <url> --bootstrap        # Auto-runs bootstrap\n", prog_name);
    printf("    %s clone <url> --no-bootstrap     # Skips bootstrap\n", prog_name);
    printf("\n");
    printf("  After clone, apply profiles:\n");
    printf("    %s apply                          # Deploy configurations\n", prog_name);
    printf("\n");
}
