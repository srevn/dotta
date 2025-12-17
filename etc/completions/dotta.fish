# Dotta Fish Completions
# Shell completions for the dotta dotfile manager
#
# Installation:
#   make install-completions
#   # or manually:
#   cp etc/completions/dotta.fish ~/.config/fish/completions/
#
# These completions use `dotta __complete` for dynamic data.

# =============================================================================
# Helper Functions - Dynamic Completion via dotta __complete
# =============================================================================

function __dotta_is_repo
    dotta __complete check 2>/dev/null
end

function __dotta_profiles
    dotta __complete profiles 2>/dev/null
end

function __dotta_profiles_all
    dotta __complete profiles --all 2>/dev/null
end

function __dotta_files
    # Check if -p/--profile was specified on the command line
    set -l tokens (commandline -opc)
    set -l profile ""

    for i in (seq (count $tokens))
        if test "$tokens[$i]" = "-p" -o "$tokens[$i]" = "--profile"
            set -l next_idx (math $i + 1)
            if test $next_idx -le (count $tokens)
                set profile $tokens[$next_idx]
                break
            end
        end
    end

    if test -n "$profile"
        dotta __complete files -p "$profile" 2>/dev/null
    else
        # Try to find positional profile for certain commands
        set -l cmd ""
        set -l cmd_idx 0
        for i in (seq 2 (count $tokens))
            switch $tokens[$i]
                case '-*'
                    continue
                case '*'
                    set cmd $tokens[$i]
                    set cmd_idx $i
                    break
            end
        end

        switch $cmd
            case add remove list show revert ignore
                # First positional after command might be profile
                set -l pos_idx (math $cmd_idx + 1)
                if test $pos_idx -le (count $tokens)
                    # Check if tokens[pos_idx] is an option
                    if not string match -q -- "-*" $tokens[$pos_idx]
                        set profile $tokens[$pos_idx]
                    end
                end
        end

        if test -n "$profile"
            dotta __complete files -p "$profile" 2>/dev/null
        else
            dotta __complete files 2>/dev/null
        end
    end
end

function __dotta_files_storage
    dotta __complete files --storage 2>/dev/null
end

function __dotta_remotes
    dotta __complete remotes 2>/dev/null
end

function __dotta_commits
    # Check for profile flag
    set -l tokens (commandline -opc)
    set -l profile ""

    for i in (seq (count $tokens))
        if test "$tokens[$i]" = "-p" -o "$tokens[$i]" = "--profile"
            set -l next_idx (math $i + 1)
            if test $next_idx -le (count $tokens)
                set profile $tokens[$next_idx]
                break
            end
        end
    end

    if test -n "$profile"
        dotta __complete commits -p "$profile" --limit 20 2>/dev/null
    else
        dotta __complete commits --limit 20 2>/dev/null
    end
end

# =============================================================================
# Condition Helpers - Argument Position Detection
# =============================================================================

function __dotta_needs_command
    set -l tokens (commandline -opc)
    # Skip global options to find first non-option argument
    for tok in $tokens[2..-1]
        switch $tok
            case '-*'
                continue
            case '*'
                return 1  # Found a command
        end
    end
    return 0  # No command yet
end

function __dotta_using_command
    set -l cmd $argv[1]
    set -l tokens (commandline -opc)

    for tok in $tokens
        if test "$tok" = "$cmd"
            return 0
        end
    end
    return 1
end

function __dotta_using_subcommand
    set -l parent $argv[1]
    set -l sub $argv[2]
    set -l tokens (commandline -opc)
    set -l found_parent 0

    for tok in $tokens
        if test $found_parent -eq 1
            if test "$tok" = "$sub"
                return 0
            end
        end
        if test "$tok" = "$parent"
            set found_parent 1
        end
    end
    return 1
end

function __dotta_seen_option
    set -l tokens (commandline -opc)
    for opt in $argv
        if contains -- $opt $tokens
            return 0
        end
    end
    return 1
end

# Check if a subcommand exists for a parent command
function __dotta_needs_subcommand
    set -l parent $argv[1]
    set -l tokens (commandline -opc)
    set -l found_parent 0

    for tok in $tokens
        if test $found_parent -eq 1
            # Skip options
            switch $tok
                case '-*'
                    continue
                case '*'
                    return 1  # Found a subcommand
            end
        end
        if test "$tok" = "$parent"
            set found_parent 1
        end
    end
    return 0  # No subcommand yet
end

function __dotta_is_nth_arg
    set -l n $argv[1]
    set -l tokens (commandline -opc)
    set -l current (commandline -ct)

    set -l cmd_idx 0
    # tokens[1] is 'dotta'
    for i in (seq 2 (count $tokens))
        switch $tokens[$i]
            case '-*'
                continue
            case '*'
                set cmd_idx $i
                break
        end
    end

    if test $cmd_idx -eq 0
        return 1
    end

    set -l arg_count 0
    for i in (seq (math $cmd_idx + 1) (count $tokens))
        switch $tokens[$i]
            case '-*'
                continue
            case '*'
                set arg_count (math $arg_count + 1)
        end
    end

    if test -z "$current"
        set arg_count (math $arg_count + 1)
    end

    if test $arg_count -eq $n
        return 0
    end
    return 1
end

# =============================================================================
# Disable Default File Completion
# =============================================================================

complete -c dotta -f

# =============================================================================
# Global Options (available for all commands)
# =============================================================================

complete -c dotta -s h -l help -d "Show help"
complete -c dotta -s v -l version -d "Show version"
complete -c dotta -s i -l interactive -d "Interactive mode"

# =============================================================================
# Main Commands
# =============================================================================

complete -c dotta -n __dotta_needs_command -a init -d "Initialize repository"
complete -c dotta -n __dotta_needs_command -a clone -d "Clone remote repository"
complete -c dotta -n __dotta_needs_command -a add -d "Add files to profile"
complete -c dotta -n __dotta_needs_command -a remove -d "Remove files from profile"
complete -c dotta -n __dotta_needs_command -a apply -d "Deploy files to filesystem"
complete -c dotta -n __dotta_needs_command -a status -d "Show repository status"
complete -c dotta -n __dotta_needs_command -a list -d "List profiles or files"
complete -c dotta -n __dotta_needs_command -a profile -d "Profile management"
complete -c dotta -n __dotta_needs_command -a diff -d "Show differences"
complete -c dotta -n __dotta_needs_command -a show -d "Show file or commit"
complete -c dotta -n __dotta_needs_command -a revert -d "Revert file to previous state"
complete -c dotta -n __dotta_needs_command -a update -d "Update profiles with modified files"
complete -c dotta -n __dotta_needs_command -a sync -d "Synchronize with remote"
complete -c dotta -n __dotta_needs_command -a remote -d "Manage remotes"
complete -c dotta -n __dotta_needs_command -a ignore -d "Manage ignore patterns"
complete -c dotta -n __dotta_needs_command -a bootstrap -d "Execute bootstrap scripts"
complete -c dotta -n __dotta_needs_command -a key -d "Encryption key management"
complete -c dotta -n __dotta_needs_command -a git -d "Git passthrough"

# =============================================================================
# Profile Subcommands
# =============================================================================

complete -c dotta -n "__dotta_using_command profile; and __dotta_needs_subcommand profile" -a list -d "List profiles"
complete -c dotta -n "__dotta_using_command profile; and __dotta_needs_subcommand profile" -a fetch -d "Fetch remote profiles"
complete -c dotta -n "__dotta_using_command profile; and __dotta_needs_subcommand profile" -a enable -d "Enable profile"
complete -c dotta -n "__dotta_using_command profile; and __dotta_needs_subcommand profile" -a disable -d "Disable profile"
complete -c dotta -n "__dotta_using_command profile; and __dotta_needs_subcommand profile" -a reorder -d "Reorder profiles"
complete -c dotta -n "__dotta_using_command profile; and __dotta_needs_subcommand profile" -a validate -d "Validate profiles"

# Profile subcommand arguments
complete -c dotta -n "__dotta_using_subcommand profile enable" -xa "(__dotta_profiles_all)"
complete -c dotta -n "__dotta_using_subcommand profile disable" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_subcommand profile fetch" -xa "(__dotta_profiles_all)"
complete -c dotta -n "__dotta_using_subcommand profile reorder" -xa "(__dotta_profiles)"

# =============================================================================
# Remote Subcommands
# =============================================================================

complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a list -d "List remotes"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a add -d "Add remote"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a remove -d "Remove remote"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a set-url -d "Set remote URL"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a rename -d "Rename remote"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a show -d "Show remote"

# =============================================================================
# Key Subcommands
# =============================================================================

complete -c dotta -n "__dotta_using_command key; and __dotta_needs_subcommand key" -a set -d "Set encryption passphrase"
complete -c dotta -n "__dotta_using_command key; and __dotta_needs_subcommand key" -a clear -d "Clear cached passphrase"
complete -c dotta -n "__dotta_using_command key; and __dotta_needs_subcommand key" -a status -d "Show key status"

# =============================================================================
# Profile Flag (-p/--profile) - Available for many commands
# =============================================================================

complete -c dotta -n "__dotta_using_command add; or __dotta_using_command apply; or __dotta_using_command status; or __dotta_using_command list; or __dotta_using_command diff; or __dotta_using_command show; or __dotta_using_command update; or __dotta_using_command remove; or __dotta_using_command revert" -s p -l profile -xa "(__dotta_profiles)" -d "Profile name"

# =============================================================================
# Positional Arguments - Commands with Profile/File Arguments
#
# Critical: dotta commands have specific positional argument semantics:
#
# add <profile> <file>...     - First positional MUST be profile
# remove <profile> [<path>...] - First positional MUST be profile
# apply [<profile>|<file>]... - Can be profile OR file (heuristic-based)
# update [<profile>|<file>]... - Can be profile OR file (heuristic-based)
#
# For add/remove: offer profiles first, then files
# For apply/update: offer both profiles and files (fish filters by prefix)
# =============================================================================

# add: First positional is profile (required), remaining are filesystem paths
complete -c dotta -n "__dotta_using_command add; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles_all)"
complete -c dotta -n "__dotta_using_command add; and not __dotta_is_nth_arg 1" -xa "(__fish_complete_path)"

# remove: First positional is profile (required), remaining are managed files
complete -c dotta -n "__dotta_using_command remove; and not __dotta_seen_option --delete-profile; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command remove; and not __dotta_seen_option --delete-profile; and not __dotta_is_nth_arg 1" -xa "(__dotta_files)"

# apply: Can take profile names OR file paths (heuristic determines type)
complete -c dotta -n "__dotta_using_command apply" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command apply" -xa "(__dotta_files)"

# update: Can take profile name OR file paths (heuristic determines type)
complete -c dotta -n "__dotta_using_command update" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command update" -xa "(__dotta_files)"

# status: Positional arguments are profiles
complete -c dotta -n "__dotta_using_command status" -xa "(__dotta_profiles)"

# list: 1st arg is profile, 2nd is managed file
complete -c dotta -n "__dotta_using_command list; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command list; and __dotta_is_nth_arg 2" -xa "(__dotta_files)"

# diff: Takes managed files or profiles
complete -c dotta -n "__dotta_using_command diff" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command diff" -xa "(__dotta_files)"

# sync: Positional arguments are profiles
complete -c dotta -n "__dotta_using_command sync" -xa "(__dotta_profiles)"

# ignore: Positional argument is profile
complete -c dotta -n "__dotta_using_command ignore; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles)"

# show: Takes managed files or commits
complete -c dotta -n "__dotta_using_command show" -xa "(__dotta_files)"
complete -c dotta -n "__dotta_using_command show" -xa "(__dotta_commits)"

# revert: Takes managed files
complete -c dotta -n "__dotta_using_command revert" -xa "(__dotta_files)"

# =============================================================================
# Command-Specific Options
# =============================================================================

# --- init ---
complete -c dotta -n "__dotta_using_command init" -s q -l quiet -d "Suppress output"

# --- clone ---
complete -c dotta -n "__dotta_using_command clone" -l bootstrap -d "Run bootstrap"
complete -c dotta -n "__dotta_using_command clone" -l no-bootstrap -d "Skip bootstrap"
complete -c dotta -n "__dotta_using_command clone" -l all -d "Fetch all profiles"
complete -c dotta -n "__dotta_using_command clone" -s p -l profiles -xa "(__dotta_profiles_all)" -d "Specific profiles"
complete -c dotta -n "__dotta_using_command clone" -s q -l quiet -d "Suppress output"
complete -c dotta -n "__dotta_using_command clone" -s v -l verbose -d "Verbose output"

# --- add ---
complete -c dotta -n "__dotta_using_command add" -s m -l message -d "Commit message"
complete -c dotta -n "__dotta_using_command add" -s e -l exclude -d "Exclude pattern"
complete -c dotta -n "__dotta_using_command add" -s f -l force -d "Overwrite existing"
complete -c dotta -n "__dotta_using_command add" -l encrypt -d "Force encryption"
complete -c dotta -n "__dotta_using_command add" -l no-encrypt -d "Skip encryption"
complete -c dotta -n "__dotta_using_command add" -l prefix -d "Custom prefix"
complete -c dotta -n "__dotta_using_command add" -s v -l verbose -d "Verbose output"

# --- remove ---
complete -c dotta -n "__dotta_using_command remove" -s m -l message -d "Commit message"
complete -c dotta -n "__dotta_using_command remove" -l delete-profile -d "Delete entire profile"
complete -c dotta -n "__dotta_using_command remove" -s n -l dry-run -d "Preview only"
complete -c dotta -n "__dotta_using_command remove" -s f -l force -d "Skip confirmation"
complete -c dotta -n "__dotta_using_command remove" -s i -l interactive -d "Interactive mode"
complete -c dotta -n "__dotta_using_command remove" -s v -l verbose -d "Verbose output"
complete -c dotta -n "__dotta_using_command remove" -s q -l quiet -d "Quiet output"

# --- apply ---
complete -c dotta -n "__dotta_using_command apply" -s f -l force -d "Overwrite modified"
complete -c dotta -n "__dotta_using_command apply" -s n -l dry-run -d "Preview only"
complete -c dotta -n "__dotta_using_command apply" -l keep-orphans -d "Keep orphaned files"
complete -c dotta -n "__dotta_using_command apply" -l skip-existing -d "Skip existing files"
complete -c dotta -n "__dotta_using_command apply" -l no-skip-unchanged -d "Disable smart skipping"
complete -c dotta -n "__dotta_using_command apply" -s e -l exclude -d "Exclude pattern"
complete -c dotta -n "__dotta_using_command apply" -s v -l verbose -d "Verbose output"

# --- status ---
complete -c dotta -n "__dotta_using_command status" -l local -d "Local status only"
complete -c dotta -n "__dotta_using_command status" -l remote -d "Remote status only"
complete -c dotta -n "__dotta_using_command status" -l no-fetch -d "Skip fetch"
complete -c dotta -n "__dotta_using_command status" -l no-sudo -d "Skip privilege elevation"
complete -c dotta -n "__dotta_using_command status" -l all -d "All profiles"
complete -c dotta -n "__dotta_using_command status" -s v -l verbose -d "Verbose output"

# --- diff ---
complete -c dotta -n "__dotta_using_command diff" -l upstream -d "Repo to filesystem"
complete -c dotta -n "__dotta_using_command diff" -l downstream -d "Filesystem to repo"
complete -c dotta -n "__dotta_using_command diff" -s a -l all -d "Both directions"
complete -c dotta -n "__dotta_using_command diff" -l name-only -d "Names only"
complete -c dotta -n "__dotta_using_command diff" -s v -l verbose -d "Verbose output"
complete -c dotta -n "__dotta_using_command diff" -xa "(__dotta_commits)"

# --- list ---
complete -c dotta -n "__dotta_using_command list" -l remote -d "Show remote tracking"
complete -c dotta -n "__dotta_using_command list" -s v -l verbose -d "Verbose output"

# --- sync ---
complete -c dotta -n "__dotta_using_command sync" -s n -l dry-run -d "Preview only"
complete -c dotta -n "__dotta_using_command sync" -l no-push -d "Fetch only"
complete -c dotta -n "__dotta_using_command sync" -l no-pull -d "Push only"
complete -c dotta -n "__dotta_using_command sync" -s f -l force -d "Force with changes"
complete -c dotta -n "__dotta_using_command sync" -l diverged -xa "warn rebase merge ours theirs" -d "Divergence strategy"
complete -c dotta -n "__dotta_using_command sync" -s v -l verbose -d "Verbose output"

# --- update ---
complete -c dotta -n "__dotta_using_command update" -s m -l message -d "Commit message"
complete -c dotta -n "__dotta_using_command update" -s e -l exclude -d "Exclude pattern"
complete -c dotta -n "__dotta_using_command update" -s n -l dry-run -d "Preview only"
complete -c dotta -n "__dotta_using_command update" -l include-new -d "Include new files"
complete -c dotta -n "__dotta_using_command update" -l only-new -d "Only new files"
complete -c dotta -n "__dotta_using_command update" -s i -l interactive -d "Interactive mode"
complete -c dotta -n "__dotta_using_command update" -s v -l verbose -d "Verbose output"

# --- revert ---
complete -c dotta -n "__dotta_using_command revert" -s m -l message -d "Commit message"
complete -c dotta -n "__dotta_using_command revert" -s f -l force -d "Skip confirmation"
complete -c dotta -n "__dotta_using_command revert" -s n -l dry-run -d "Preview only"
complete -c dotta -n "__dotta_using_command revert" -s v -l verbose -d "Verbose output"
complete -c dotta -n "__dotta_using_command revert" -xa "(__dotta_commits)"

# --- show ---
complete -c dotta -n "__dotta_using_command show" -l raw -d "Raw content"

# --- ignore ---
complete -c dotta -n "__dotta_using_command ignore" -l add -d "Add pattern"
complete -c dotta -n "__dotta_using_command ignore" -l remove -d "Remove pattern"
complete -c dotta -n "__dotta_using_command ignore" -l test -xa "(__fish_complete_path)" -d "Test if path is ignored"
complete -c dotta -n "__dotta_using_command ignore" -s v -l verbose -d "Verbose output"

# --- bootstrap ---
complete -c dotta -n "__dotta_using_command bootstrap" -l all -d "All profiles"
complete -c dotta -n "__dotta_using_command bootstrap" -s e -l edit -d "Edit script"
complete -c dotta -n "__dotta_using_command bootstrap" -l show -d "Show script"
complete -c dotta -n "__dotta_using_command bootstrap" -s l -l list -d "List scripts"
complete -c dotta -n "__dotta_using_command bootstrap" -s n -l dry-run -d "Preview only"
complete -c dotta -n "__dotta_using_command bootstrap" -s y -l yes -l no-confirm -d "Skip confirmation"
complete -c dotta -n "__dotta_using_command bootstrap" -l continue-on-error -d "Continue on error"
complete -c dotta -n "__dotta_using_command bootstrap" -s v -l verbose -d "Verbose output"

# --- git ---
complete -c dotta -n "__dotta_using_command git" -xa "(__fish_complete_subcommand --command git)"

# --- profile ---
complete -c dotta -n "__dotta_using_subcommand profile list" -l all -d "All profiles"
complete -c dotta -n "__dotta_using_subcommand profile list" -l remote -d "Show remote tracking"
complete -c dotta -n "__dotta_using_subcommand profile list" -s v -l verbose -d "Verbose output"
complete -c dotta -n "__dotta_using_subcommand profile enable" -l all -d "Enable all local profiles"
complete -c dotta -n "__dotta_using_subcommand profile enable" -l prefix -d "Custom prefix"
complete -c dotta -n "__dotta_using_subcommand profile enable" -s n -l dry-run -d "Preview only"
complete -c dotta -n "__dotta_using_subcommand profile enable" -s q -l quiet -d "Suppress output"
complete -c dotta -n "__dotta_using_subcommand profile enable" -s v -l verbose -d "Verbose output"
complete -c dotta -n "__dotta_using_subcommand profile disable" -l all -d "Disable all enabled profiles"
complete -c dotta -n "__dotta_using_subcommand profile disable" -s n -l dry-run -d "Preview only"
complete -c dotta -n "__dotta_using_subcommand profile disable" -s f -l force -d "Force disable"
complete -c dotta -n "__dotta_using_subcommand profile disable" -s q -l quiet -d "Suppress output"
complete -c dotta -n "__dotta_using_subcommand profile disable" -s v -l verbose -d "Verbose output"
complete -c dotta -n "__dotta_using_subcommand profile fetch" -l all -d "Fetch all remote profiles"
complete -c dotta -n "__dotta_using_subcommand profile fetch" -s v -l verbose -d "Verbose output"
complete -c dotta -n "__dotta_using_subcommand profile reorder" -s q -l quiet -d "Suppress output"
complete -c dotta -n "__dotta_using_subcommand profile reorder" -s v -l verbose -d "Verbose output"
complete -c dotta -n "__dotta_using_subcommand profile validate" -l fix -d "Auto-fix issues"

# --- remote ---
complete -c dotta -n "__dotta_using_subcommand remote list" -s v -l verbose -d "Show URLs"
complete -c dotta -n "__dotta_using_subcommand remote remove" -xa "(__dotta_remotes)"
complete -c dotta -n "__dotta_using_subcommand remote set-url" -xa "(__dotta_remotes)"
complete -c dotta -n "__dotta_using_subcommand remote rename" -xa "(__dotta_remotes)"
complete -c dotta -n "__dotta_using_subcommand remote show" -xa "(__dotta_remotes)"

# --- key ---
complete -c dotta -n "__dotta_using_subcommand key status" -s v -l verbose -d "Show detailed information"
