/**
 * help.c - Help and usage functions
 *
 * Provides help text and usage information for all commands.
 */

#include <git2.h>
#include <stdio.h>
#include <string.h>

#include "version.h"

void print_usage(const char *prog_name) {
    printf("dotta - Dotfile Manager\n\n");
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
    printf("  profile      Manage profile selection and layering\n");
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
    printf("  -h, --help     Show this help message\n");
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
    printf("  -h, --help         Show this help message\n");
    printf("\nProfile Behavior:\n");
    printf("  By default, clone auto-detects profiles relevant to the current system\n");
    printf("  (e.g., 'global', 'darwin', 'hosts/macbook') and fetches only those.\n");
    printf("  This creates a safe default where only appropriate configs are active.\n\n");
    printf("  Fetched profiles are automatically selected and stored in state.\n");
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
    printf("  %s profile list                 # View active profiles\n", prog_name);
    printf("  %s profile select <name>        # Select additional profiles\n", prog_name);
    printf("  %s bootstrap                    # Run bootstrap manually\n", prog_name);
    printf("  %s apply                        # Apply profiles\n", prog_name);
    printf("\n");
}

void print_add_help(const char *prog_name) {
    printf("Usage: %s add <profile> <file|dir>...\n", prog_name);
    printf("   or: %s add [options] --profile <name> <file|dir>...\n\n", prog_name);
    printf("Add files to a profile\n\n");
    printf("Arguments:\n");
    printf("  <profile>                 Profile name (first argument, or use -p)\n");
    printf("  <file|dir>...             Files or directories to add\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>      Profile name\n");
    printf("  -m, --message <msg>       Commit message\n");
    printf("  -e, --exclude <pattern>   Exclude pattern (glob, can be repeated)\n");
    printf("  -f, --force               Overwrite existing files in profile\n");
    printf("  -v, --verbose             Print verbose output\n");
    printf("  -h, --help                Show this help message\n");
    printf("\nExclude Patterns:\n");
    printf("  Supports glob patterns: *, ?, [abc]\n");
    printf("  Examples:\n");
    printf("    --exclude '*.log'       Exclude all .log files\n");
    printf("    --exclude '.git/*'      Exclude .git directory\n");
    printf("    --exclude '*.tmp'       Exclude temporary files\n");
    printf("  Multiple patterns:\n");
    printf("    --exclude '*.log' --exclude '*.tmp'\n");
    printf("\nExamples:\n");
    printf("  %s add global ~/.bashrc\n", prog_name);
    printf("  %s add darwin ~/.config/nvim\n", prog_name);
    printf("  %s add global ~/.ssh/config --exclude '*.pub'\n", prog_name);
    printf("\n");
}

void print_remove_help(const char *prog_name) {
    printf("Usage: %s remove <profile> <file|dir>...\n", prog_name);
    printf("   or: %s remove <profile> --delete-profile\n", prog_name);
    printf("   or: %s remove [options] --profile <name> <file|dir>...\n\n", prog_name);
    printf("Remove files from a profile or delete entire profile\n\n");
    printf("Arguments:\n");
    printf("  <profile>              Profile name (first argument, or use -p)\n");
    printf("  <file|dir>...          Files or directories to remove\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>   Profile name\n");
    printf("  --delete-profile       Delete entire profile branch\n");
    printf("  -m, --message <msg>    Custom commit message\n");
    printf("  -n, --dry-run          Show what would be removed without doing it\n");
    printf("  -f, --force            Skip confirmations, ignore missing files\n");
    printf("  -i, --interactive      Prompt for each file\n");
    printf("  -v, --verbose          Print verbose output\n");
    printf("  -q, --quiet            Minimal output\n");
    printf("  -h, --help             Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s remove global ~/.bashrc\n", prog_name);
    printf("      Remove ~/.bashrc from 'global' profile\n\n");
    printf("  %s remove global ~/.config/nvim\n", prog_name);
    printf("      Remove entire directory from profile\n\n");
    printf("  %s remove test --delete-profile\n", prog_name);
    printf("      Delete entire 'test' profile branch\n\n");
    printf("  %s remove global ~/.bashrc --dry-run\n", prog_name);
    printf("      Preview what would be removed from profile\n");
    printf("\nWorkflow:\n");
    printf("  1. Remove files from profile (modifies Git repository only)\n");
    printf("  2. Run 'dotta apply' to sync filesystem (prunes orphaned files by default)\n");
    printf("\nNotes:\n");
    printf("  - This command modifies the Git repository only\n");
    printf("  - Deployed files remain on filesystem until 'dotta apply' is run\n");
    printf("  - This ensures proper global context when removing files from filesystem\n");
    printf("  - Deleted profile branches can be recovered from remote if pushed\n");
    printf("\n");
}

void print_apply_help(const char *prog_name) {
    printf("Usage: %s apply [options] [profile]...\n\n", prog_name);
    printf("Synchronize filesystem with profiles\n\n");
    printf("Description:\n");
    printf("  Apply performs a complete synchronization:\n");
    printf("  • Deploys new and updated files from active profiles\n");
    printf("  • Removes orphaned files (from unselected profiles)\n");
    printf("  • Updates state to reflect current deployment\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>   Specify profile(s) to apply\n");
    printf("  -f, --force            Overwrite modified files\n");
    printf("  -n, --dry-run          Don't actually deploy\n");
    printf("  --keep-orphans         Don't remove orphaned files (advanced)\n");
    printf("  --skip-existing        Skip files that already exist\n");
    printf("  --no-skip-unchanged    Disable smart skipping (default: enabled)\n");
    printf("  -v, --verbose          Print verbose output\n");
    printf("  -h, --help             Show this help message\n");
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
    printf("  -h, --help             Show this help message\n");
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
    printf("Usage: %s diff [options] [<commit>] [<commit>] [<file>...]\n\n", prog_name);
    printf("Show differences between commits, profiles, and filesystem\n\n");
    printf("Modes:\n");
    printf("  (no args)             Workspace diff (both directions)\n");
    printf("  <commit>              Commit to workspace\n");
    printf("  <commit> <commit>     Compare two commits\n");
    printf("  [<file>...]           Workspace diff for specific files\n\n");
    printf("Direction options (workspace mode only):\n");
    printf("  --upstream            Show repo → filesystem (what 'apply' would change) [default]\n");
    printf("  --downstream          Show filesystem → repo (what 'update' would commit)\n");
    printf("  -a, --all             Show both upstream and downstream with headers\n");
    printf("\nOther options:\n");
    printf("  -p, --profile <name>  Specify profile(s) for operation\n");
    printf("  --name-only           Show only file names, not diffs\n");
    printf("  -h, --help            Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s diff                     # Full workspace diff\n", prog_name);
    printf("  %s diff --upstream          # What apply would change\n", prog_name);
    printf("  %s diff a4f2c8e             # Commit vs workspace\n", prog_name);
    printf("  %s diff HEAD~1              # Previous commit vs workspace\n", prog_name);
    printf("  %s diff b3e1f9a a4f2c8e     # Compare commits\n", prog_name);
    printf("  %s diff home/.bashrc        # Workspace diff for one file\n", prog_name);
    printf("\nIntegration:\n");
    printf("  %s list global home/.bashrc # See history\n", prog_name);
    printf("  %s diff b3e1f9a a4f2c8e     # Compare those commits\n", prog_name);
    printf("\nConcepts:\n");
    printf("  Upstream:   Repository (source of truth for configuration)\n");
    printf("  Downstream: Filesystem (deployed state)\n");
    printf("\n");
}

void print_list_help(const char *prog_name) {
    printf("Usage: %s list [options] [profile] [file]\n\n", prog_name);
    printf("Hierarchical listing interface with three levels:\n");
    printf("  Level 1: Profiles       (default)\n");
    printf("  Level 2: Files          (with profile name)\n");
    printf("  Level 3: File history   (with profile name + file path)\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>    Specify profile name\n");
    printf("  -v, --verbose           Show detailed output\n");
    printf("  --remote                Show remote tracking state (Level 1 only)\n");
    printf("  -h, --help              Show this help message\n");
    printf("\nVerbose Mode Details:\n");
    printf("  Level 1: Add file count, total size, and last commit\n");
    printf("  Level 2: Add file sizes and per-file last commits\n");
    printf("  Level 3: Show full commit messages instead of oneline format\n");
    printf("\nRemote State Indicators (with --remote):\n");
    printf("  [=]   up-to-date with remote\n");
    printf("  [↑n]  n commits ahead of remote (run 'dotta sync' to push)\n");
    printf("  [↓n]  n commits behind remote (run 'dotta sync' to pull)\n");
    printf("  [↕]   diverged from remote (manual resolution needed)\n");
    printf("  [•]   no remote tracking branch (will be created on first sync)\n");
    printf("\nExamples:\n");
    printf("  # Level 1: List profiles\n");
    printf("  %s list                       # Simple: just names\n", prog_name);
    printf("  %s list -v                    # Verbose: with stats\n", prog_name);
    printf("  %s list --remote              # Show sync status\n", prog_name);
    printf("  %s list -v --remote           # Full details + sync status\n\n", prog_name);
    printf("  # Level 2: List files in profile\n");
    printf("  %s list global                # Simple: just paths\n", prog_name);
    printf("  %s list -p global             # Same using -p flag\n", prog_name);
    printf("  %s list global -v             # Verbose: with sizes and commits\n\n", prog_name);
    printf("  # Level 3: Show file history\n");
    printf("  %s list global home/.bashrc   # Oneline commits\n", prog_name);
    printf("  %s list global home/.bashrc -v  # Full commit messages\n", prog_name);
    printf("\nIntegration with other commands:\n");
    printf("  # Copy commit hash from list output, then:\n");
    printf("  %s show a4f2c8e               # Show specific commit\n", prog_name);
    printf("  %s diff b3e1f9a a4f2c8e       # Compare commits\n", prog_name);
    printf("\n");
}

void print_profile_help(const char *prog_name) {
    printf("Usage: %s profile <subcommand> [options]\n\n", prog_name);
    printf("Manage profile selection and layering\n\n");
    printf("Profile selection separates availability from activation:\n");
    printf("  • Available profiles exist locally but are not used by commands\n");
    printf("  • Active profiles are used by apply, update, sync, status, and diff\n");
    printf("  • Profile activation state persists in .git/dotta.db\n\n");
    printf("Subcommands:\n");
    printf("  list                     Show profiles with selection status\n");
    printf("  fetch <name>...          Download profiles from remote without selecting\n");
    printf("  select <name>...         Add profiles to active set\n");
    printf("  unselect <name>...       Remove profiles from active set\n");
    printf("  reorder <name>...        Change order of active profiles (affects layering)\n");
    printf("  validate                 Check and fix state consistency\n");
    printf("\nOptions (list):\n");
    printf("  --all                    Include remote profiles (not yet fetched)\n");
    printf("\nOptions (fetch):\n");
    printf("  --all                    Fetch all remote profiles\n");
    printf("  -v, --verbose            Show detailed progress\n");
    printf("\nOptions (select):\n");
    printf("  --all                    Select all local profiles\n");
    printf("  -v, --verbose            Show detailed progress\n");
    printf("  -q, --quiet              Suppress non-error output\n");
    printf("\nOptions (unselect):\n");
    printf("  --all                    Unselect all profiles\n");
    printf("  -n, --dry-run            Show what would change without doing it\n");
    printf("  -v, --verbose            Show detailed progress\n");
    printf("  -q, --quiet              Suppress non-error output\n");
    printf("\nOptions (reorder):\n");
    printf("  -v, --verbose            Show before/after profile order\n");
    printf("  -q, --quiet              Suppress non-error output\n");
    printf("\nOptions (validate):\n");
    printf("  --fix                    Auto-fix state inconsistencies\n");
    printf("\nCommon Options:\n");
    printf("  -h, --help               Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s profile list --all              # Show local and remote profiles\n", prog_name);
    printf("  %s profile fetch darwin            # Download a profile\n", prog_name);
    printf("  %s profile select darwin           # Activate a profile\n", prog_name);
    printf("  %s profile unselect --all          # Deactivate all profiles\n", prog_name);
    printf("  %s profile reorder global darwin   # Change layering priority\n", prog_name);
    printf("  %s profile validate --fix          # Fix state inconsistencies\n", prog_name);
    printf("\n");
}

void print_show_help(const char *prog_name) {
    printf("Usage: %s show [options] <target>\n", prog_name);
    printf("   or: %s show [options] <profile> <file> [<commit>]\n\n", prog_name);
    printf("Show file content or commit details with diff\n\n");

    printf("Syntax:\n");
    printf("  <commit>                      Show commit with diff\n");
    printf("  <file>                        Show file from active profiles (HEAD)\n");
    printf("  <file> <commit>               Show file at specific commit\n");
    printf("  <profile> <file>              Show file from profile (HEAD)\n");
    printf("  <profile> <file> <commit>     Show file from profile at commit\n");
    printf("  <file>@<commit>               Compact: file at commit\n");
    printf("  <profile>:<file>@<commit>     Compact: profile, file, and commit\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>  Override profile for file lookup or commit search\n");
    printf("  --raw                 Show raw content without formatting\n");
    printf("  -h, --help            Show this help message\n");
    printf("\nCommit Mode:\n");
    printf("  When argument looks like a git ref (SHA, HEAD, HEAD~1), shows commit:\n");
    printf("    - Commit metadata (SHA, date, author, message)\n");
    printf("    - File change statistics\n");
    printf("    - Full unified diff (like 'git show')\n");
    printf("  Searches active profiles (use -p to specify profile)\n");
    printf("\nFile Mode:\n");
    printf("  Shows file content from profile branches\n");
    printf("  Without profile: searches active profiles for exact path match\n");
    printf("  Accepts paths in either format (filesystem or storage):\n");
    printf("    • Filesystem: /etc/hosts, ~/.bashrc\n");
    printf("    • Storage: root/etc/hosts, home/.bashrc\n");
    printf("\nExamples:\n");
    printf("  # Show commit with diff\n");
    printf("  %s show a4f2c8e                        # From active profiles\n", prog_name);
    printf("  %s show -p global a4f2c8e              # From specific profile\n", prog_name);
    printf("\n");
    printf("  # Show file (current version)\n");
    printf("  %s show home/.bashrc                   # From active profiles\n", prog_name);
    printf("  %s show -p global home/.bashrc         # From specific profile\n", prog_name);
    printf("  %s show global:home/.bashrc            # Refspec syntax\n", prog_name);
    printf("\n");
    printf("  # Show file at specific commit\n");
    printf("  %s show darwin home/.bashrc a4f2c8e\n", prog_name);
    printf("  %s show home/.bashrc@a4f2c8e           # Refspec syntax (needs -p)\n", prog_name);
    printf("  %s show global:home/.bashrc@a4f2c8e    # Full refspec\n", prog_name);
    printf("\n");
}

void print_revert_help(const char *prog_name) {
    printf("Usage: %s revert [options] <file@commit>\n", prog_name);
    printf("   or: %s revert [options] <file> <commit>\n", prog_name);
    printf("   or: %s revert [options] <profile> <file@commit>\n", prog_name);
    printf("   or: %s revert [options] <profile> <file> <commit>\n\n", prog_name);
    printf("Revert a file in a profile to its state at a specific commit\n\n");
    printf("Syntax:\n");
    printf("  <file> <commit>               Revert file to commit (discover profile)\n");
    printf("  <profile> <file> <commit>     Revert file in profile to commit\n");
    printf("  <file>@<commit>               Compact: file at commit\n");
    printf("  <profile>:<file>@<commit>     Compact: profile, file, and commit\n");
    printf("\n");
    printf("Arguments:\n");
    printf("  profile                       Profile name (e.g., global, darwin/work)\n");
    printf("  file                          Filesystem or storage path (home/..., root/...)\n");
    printf("  commit                        Required commit ref (e.g., HEAD~3, abc123)\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>  Override profile (required if file is ambiguous)\n");
    printf("  --commit              Create a commit with the reverted changes\n");
    printf("  -m, --message <msg>   Commit message (requires --commit)\n");
    printf("  -f, --force           Skip confirmation and override conflicts\n");
    printf("  --dry-run             Preview changes without modifying anything\n");
    printf("  -v, --verbose         Print verbose output\n");
    printf("  -h, --help            Show this help message\n");
    printf("\nBehavior:\n");
    printf("  This command modifies the Git repository only. Run 'dotta apply' afterward\n");
    printf("  to deploy the reverted file to your filesystem.\n");
    printf("\n");
    printf("  1. Discovers file in profiles (exact path or basename search)\n");
    printf("  2. Resolves target commit in profile history\n");
    printf("  3. Shows diff preview between current and target state\n");
    printf("  4. Prompts for confirmation (unless --force)\n");
    printf("  5. Updates file in profile branch to target state\n");
    printf("  6. Optionally creates commit (with --commit)\n");
    printf("\nExamples:\n");
    printf("  %s revert home/.bashrc HEAD~3\n", prog_name);
    printf("  %s revert darwin home/.bashrc a4f2c8e\n", prog_name);
    printf("  %s revert darwin:home/.bashrc@a4f2c8e\n", prog_name);
    printf("  %s revert --commit -m \"Fix config\" home/.bashrc HEAD~1\n", prog_name);
    printf("  %s revert --dry-run darwin home/.config/nvim/init.lua HEAD~2\n", prog_name);
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
    printf("  -h, --help       Show this help message\n");
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
    printf("  -m, --message <msg>       Custom commit message\n");
    printf("  -p, --profile <name>      Only update files from this profile\n");
    printf("  -e, --exclude <pattern>   Exclude pattern (glob, can be repeated)\n");
    printf("  -n, --dry-run             Show what would be updated\n");
    printf("  -i, --interactive         Prompt for confirmation\n");
    printf("  -v, --verbose             Verbose output\n");
    printf("  --include-new             Include new files from tracked directories\n");
    printf("  --only-new                Only process new files (ignore modified)\n");
    printf("  -h, --help                Show this help message\n");
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
    printf("  %s update --exclude '*.log'      # Exclude log files from update\n", prog_name);
    printf("\n");
}

void print_sync_help(const char *prog_name) {
    printf("Usage: %s sync [profile]...\n", prog_name);
    printf("   or: %s sync [options]\n\n", prog_name);
    printf("Synchronize local repository with remote repository\n\n");
    printf("Fetches from remote, analyzes branch states, and pushes/pulls as needed.\n");
    printf("Requires clean workspace - run 'dotta update' first to commit local changes.\n");
    printf("Operates only on active profiles (use 'dotta profile' to manage).\n\n");
    printf("Arguments:\n");
    printf("  [profile]...           Optional profile(s) to sync (default: all active)\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>       Sync specific profile\n");
    printf("  -n, --dry-run              Show what would happen\n");
    printf("  --no-push                  Fetch and analyze only, skip push\n");
    printf("  --no-pull                  Skip pulling remote changes (push-only)\n");
    printf("  -f, --force                Force sync even with uncommitted changes\n");
    printf("  --diverged <strategy>      How to handle diverged branches:\n");
    printf("                             warn (default), rebase, merge, ours, theirs\n");
    printf("  -v, --verbose              Verbose output\n");
    printf("  -h, --help                 Show this help message\n");
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
    printf("  %s sync                    # Sync all active profiles with remote\n", prog_name);
    printf("  %s sync global             # Sync only specific profile\n", prog_name);
    printf("  %s sync global darwin      # Sync multiple specific profiles\n", prog_name);
    printf("  %s sync --dry-run          # Preview sync actions\n", prog_name);
    printf("  %s sync --force            # Sync even with uncommitted changes\n", prog_name);
    printf("  %s sync --no-pull          # Push only, skip pulling\n", prog_name);
    printf("  %s sync --diverged rebase  # Rebase on divergence\n", prog_name);
    printf("\n");
}

void print_ignore_help(const char *prog_name) {
    printf("Usage: %s ignore [profile]\n", prog_name);
    printf("   or: %s ignore [options] [profile]\n\n", prog_name);
    printf("Manage ignore patterns for dotfile tracking\n\n");
    printf("Arguments:\n");
    printf("  [profile]              Optional profile name (first argument, or use -p)\n");
    printf("                         Without profile: edit baseline .dottaignore\n");
    printf("                         With profile: edit profile-specific .dottaignore\n");
    printf("\nModes:\n");
    printf("  Edit mode (default):   Opens .dottaignore in your editor\n");
    printf("  Add/Remove mode:       Add or remove patterns programmatically\n");
    printf("  Test mode (--test):    Check if a path would be ignored\n\n");
    printf("Options:\n");
    printf("  -p, --profile <name>   Profile name\n");
    printf("  --add <pattern>        Add pattern to .dottaignore (can be used multiple times)\n");
    printf("  --remove <pattern>     Remove pattern from .dottaignore (can be used multiple times)\n");
    printf("  --test <path>          Test if path would be ignored by active profiles\n");
    printf("  -v, --verbose          Print verbose output (test mode: show all patterns)\n");
    printf("  -h, --help             Show this help message\n");
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
    printf("  %s ignore global\n\n", prog_name);
    printf("  # Add patterns to baseline .dottaignore\n");
    printf("  %s ignore --add '*.tmp' --add '*.log'\n\n", prog_name);
    printf("  # Remove pattern from global profile .dottaignore\n");
    printf("  %s ignore global --remove '.DS_Store'\n\n", prog_name);
    printf("  # Add and remove patterns in one command\n");
    printf("  %s ignore --add 'newpattern' --remove 'oldpattern'\n\n", prog_name);
    printf("  # Test if path is ignored (checks all active profiles)\n");
    printf("  %s ignore --test ~/.config/nvim/node_modules\n\n", prog_name);
    printf("  # Test against specific profile only\n");
    printf("  %s ignore global --test ~/.bashrc\n", prog_name);
    printf("\n");
}

void print_bootstrap_help(const char *prog_name) {
    printf("Usage: %s bootstrap [profile]...\n", prog_name);
    printf("   or: %s bootstrap [options]\n\n", prog_name);
    printf("Execute bootstrap scripts for profile setup\n\n");
    printf("Bootstrap scripts are per-profile shell scripts stored in .dotta/bootstrap\n");
    printf("within each profile branch. They run during initial setup to install\n");
    printf("dependencies, configure system settings, and prepare the environment.\n\n");
    printf("Arguments:\n");
    printf("  [profile]...              Optional profile(s) to bootstrap (default: auto-detect)\n");
    printf("\nOptions:\n");
    printf("  -p, --profile <name>      Specify profile(s) to bootstrap\n");
    printf("  --all                     Bootstrap all available profiles\n");
    printf("  -e, --edit                Edit bootstrap script (requires --profile)\n");
    printf("  --show                    Show bootstrap script content (requires --profile)\n");
    printf("  -l, --list                List all bootstrap scripts\n");
    printf("  -n, --dry-run             Show what would be executed without running\n");
    printf("  -y, --yes, --no-confirm   Skip confirmation prompts\n");
    printf("  --continue-on-error       Continue if a bootstrap script fails\n");
    printf("  -h, --help                Show this help message\n");
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
    printf("  %s bootstrap darwin\n\n", prog_name);
    printf("  # Run for multiple profiles\n");
    printf("  %s bootstrap darwin global\n\n", prog_name);
    printf("  # Create/edit bootstrap script for darwin profile\n");
    printf("  %s bootstrap darwin --edit\n\n", prog_name);
    printf("  # List all bootstrap scripts\n");
    printf("  %s bootstrap --list\n\n", prog_name);
    printf("  # Show darwin bootstrap script\n");
    printf("  %s bootstrap darwin --show\n\n", prog_name);
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

void print_interactive_help(const char *prog_name) {
    printf("Usage: %s --interactive\n\n", prog_name);
    printf("Interactive profile selection and ordering.\n\n");
    printf("Keybindings:\n");
    printf("  ↑↓, j/k, g/G    Navigate profiles\n");
    printf("  space, enter    Toggle profile selection\n");
    printf("  J/K             Move profile up/down\n");
    printf("  w               Save profile order\n");
    printf("  q, ESC          Quit\n\n");
    printf("Notes:\n");
    printf("  - Selected profiles are saved to state in the displayed order\n");
    printf("  - Profile order determines layering (later overrides earlier)\n");
    printf("  - Use regular commands (apply, update, sync) after selecting profiles\n");
}
