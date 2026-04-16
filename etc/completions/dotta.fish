# Dotta Fish Completions — entry point
#
# Fish looks for completions under ~/.config/fish/completions (and other
# XDG paths) and auto-sources this file by command name. It holds every
# piece of the completion set that cannot be derived from the spec-engine
# registry, then sources the auto-generated schema at the bottom.
#
# What lives here (hand-maintained):
#
#   1. Dynamic helpers that shell out to `dotta __complete <mode>` for
#      data depending on the user's repo (profiles, files, commits,
#      remotes). These must run at completion time, not build time.
#
#   2. Condition helpers (__dotta_using_command et al.) referenced by
#      both this file and the generated schema.
#
#   3. Subcommand entries for commands whose router parses positionals
#      into an enum (remote, key) instead of declaring a
#      `.subcommands` tree. The generator can only project the spec's
#      declared subcommand table; router-internal routing stays here.
#
#   4. Positional completions and flag-value completions. The spec
#      engine carries no classifier for "this positional is a profile
#      name" vs "this positional is a managed file" — those rules are
#      command-specific and live here.
#
# What lives in dotta-completions.fish (auto-generated, sourced at the
# bottom of this file): root flags, command list, per-command flag
# tables, declared subcommand trees, and the `__dotta_value_flags` set
# used by the positional-arg counter below. Regenerate with
# `make completions` after editing any command spec; never hand-edit
# that file.
#
# Installation:
#   make install-completions
#   # or, manually, copy both *.fish files into
#   #   ~/.config/fish/completions/

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
        if contains -- "$tokens[$i]" -p --profile
            set -l next_idx (math $i + 1)
            if test $next_idx -le (count $tokens)
                set profile $tokens[$next_idx]
                break
            end
        end
    end

    if test -n "$profile"
        dotta __complete files --storage -p "$profile" 2>/dev/null
    else
        # Try to find positional profile for certain commands
        set -l cmd ""
        set -l cmd_idx 0
        set -l tc (count $tokens)
        if test $tc -ge 2
            for i in (seq 2 $tc)
                switch $tokens[$i]
                    case '-*'
                        continue
                    case '*'
                        set cmd $tokens[$i]
                        set cmd_idx $i
                        break
                end
            end
        end

        switch $cmd
            case apply update add remove list show revert ignore diff
                # Find first positional after command (skip flags and their values)
                set -l value_flags $__dotta_value_flags
                set -l skip_next 0
                set -l scan_start (math $cmd_idx + 1)
                if test $scan_start -le $tc
                    for i in (seq $scan_start $tc)
                        if test $skip_next -eq 1
                            set skip_next 0
                            continue
                        end
                        switch $tokens[$i]
                            case '-*'
                                if contains -- $tokens[$i] $value_flags
                                    set skip_next 1
                                end
                                continue
                            case '*'
                                set profile $tokens[$i]
                                break
                        end
                    end
                end
        end

        if test -n "$profile"
            dotta __complete files --storage -p "$profile" 2>/dev/null
        else
            dotta __complete files --storage 2>/dev/null
        end
    end
end

function __dotta_remotes
    dotta __complete remotes 2>/dev/null
end

function __dotta_commits
    # HEAD-based references (always valid for any profile branch)
    printf "HEAD\tCurrent commit\n"
    printf "HEAD~1\tPrevious commit\n"
    printf "HEAD~2\t2 commits ago\n"
    printf "HEAD~3\t3 commits ago\n"

    # Hash-based references from profile commit history
    set -l tokens (commandline -opc)
    set -l profile ""

    for i in (seq (count $tokens))
        if contains -- "$tokens[$i]" -p --profile
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

function __dotta_refspec_commits
    set -l token (commandline -ct)

    # Only activate when current token contains @
    if not string match -q '*@*' -- $token
        return
    end

    # Extract file prefix (everything before the last @)
    set -l prefix (string replace -r '@[^@]*$' '' -- $token)

    # Prefix each commit reference with file@
    for line in (__dotta_commits)
        set -l parts (string split \t -- $line)
        printf "%s@%s\t%s\n" $prefix $parts[1] $parts[2]
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
    # Match only the first non-option token (the top-level command)
    for tok in $tokens[2..-1]
        switch $tok
            case '-*'
                continue
            case '*'
                test "$tok" = "$cmd"
                return $status
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
    set -l tc (count $tokens)

    set -l value_flags $__dotta_value_flags

    set -l cmd_idx 0
    # tokens[1] is 'dotta'; find the subcommand
    if test $tc -ge 2
        for i in (seq 2 $tc)
            switch $tokens[$i]
                case '-*'
                    continue
                case '*'
                    set cmd_idx $i
                    break
            end
        end
    end

    if test $cmd_idx -eq 0
        return 1
    end

    # Count positional args after the subcommand, skipping flag values
    set -l arg_count 0
    set -l skip_next 0
    set -l arg_start (math $cmd_idx + 1)
    if test $arg_start -le $tc
        for i in (seq $arg_start $tc)
            if test $skip_next -eq 1
                set skip_next 0
                continue
            end
            switch $tokens[$i]
                case '-*'
                    if contains -- $tokens[$i] $value_flags
                        set skip_next 1
                    end
                    continue
                case '*'
                    set arg_count (math $arg_count + 1)
            end
        end
    end

    set arg_count (math $arg_count + 1)

    if test $arg_count -eq $n
        return 0
    end
    return 1
end

# =============================================================================
# Subcommand Lists for Router-Based Commands
#
# `remote` and `key` parse their subcommand from a positional bucket in
# post_parse rather than declaring it via `.subcommands` on the spec.
# The generator can only project declared trees, so the subcommand
# names need to be listed here. If either command is converted to a
# declared subcommand tree in the future, delete the corresponding
# block below and regenerate.
# =============================================================================

# --- remote subcommands ---
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a list    -d "List remotes"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a add     -d "Add remote"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a remove  -d "Remove remote"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a set-url -d "Set remote URL"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a rename  -d "Rename remote"
complete -c dotta -n "__dotta_using_command remote; and __dotta_needs_subcommand remote" -a show    -d "Show remote"

# --- key subcommands ---
complete -c dotta -n "__dotta_using_command key; and __dotta_needs_subcommand key" -a set    -d "Set encryption passphrase"
complete -c dotta -n "__dotta_using_command key; and __dotta_needs_subcommand key" -a clear  -d "Clear cached passphrase"
complete -c dotta -n "__dotta_using_command key; and __dotta_needs_subcommand key" -a status -d "Show key status"

# =============================================================================
# Flag-Value Completions
#
# The generator emits each flag's name + description; these rules
# augment specific flags with value candidates or file completion.
# Fish merges rules for the same flag, so -d is omitted here to avoid
# duplicate description rendering.
# =============================================================================

# -p/--profile: every command that offers it wants profile-name completion.
complete -c dotta -n "__dotta_using_command add; or __dotta_using_command apply; or __dotta_using_command status; or __dotta_using_command list; or __dotta_using_command diff; or __dotta_using_command show; or __dotta_using_command update; or __dotta_using_command remove; or __dotta_using_command revert; or __dotta_using_command sync; or __dotta_using_command ignore; or __dotta_using_command bootstrap" -s p -l profile -xa "(__dotta_profiles)"

# clone's --profiles wants available (not enabled) profiles.
complete -c dotta -n "__dotta_using_command clone" -s p -l profiles -xa "(__dotta_profiles_all)"

# sync's --diverged takes one of a fixed strategy set.
complete -c dotta -n "__dotta_using_command sync" -l diverged -xa "warn rebase merge ours theirs"

# ignore --test takes a filesystem path, not a profile/file token.
complete -c dotta -n "__dotta_using_command ignore" -l test -F

# =============================================================================
# Positional Arguments
#
# Per-command positional semantics (first arg is a profile, second is
# a managed file, etc.) are classifier-driven and can't be derived
# from the spec's opt table. Keep them aligned with each command's
# post_parse logic.
# =============================================================================

# add: First positional is profile (required), remaining are filesystem paths
complete -c dotta -n "__dotta_using_command add; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles_all)"
complete -c dotta -n "__dotta_using_command add; and not __dotta_is_nth_arg 1" -F

# remove: First positional is profile (required), remaining are managed files
complete -c dotta -n "__dotta_using_command remove; and not __dotta_seen_option --delete-profile; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command remove; and not __dotta_seen_option --delete-profile; and not __dotta_is_nth_arg 1" -xa "(__dotta_files)"

# apply: Can take profile names OR file paths (heuristic determines type)
complete -c dotta -n "__dotta_using_command apply" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command apply" -xa "(__dotta_files)"
complete -c dotta -n "__dotta_using_command apply" -F

# update: Can take profile name OR file paths (heuristic determines type)
complete -c dotta -n "__dotta_using_command update" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command update" -xa "(__dotta_files)"
complete -c dotta -n "__dotta_using_command update" -F

# status: Positional arguments are profiles
complete -c dotta -n "__dotta_using_command status" -xa "(__dotta_profiles)"

# list: 1st arg is profile, 2nd is managed file
complete -c dotta -n "__dotta_using_command list; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command list; and __dotta_is_nth_arg 2" -xa "(__dotta_files)"

# diff: Takes profiles, files, or commits
complete -c dotta -n "__dotta_using_command diff; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_command diff" -xa "(__dotta_files)"
complete -c dotta -n "__dotta_using_command diff" -xa "(__dotta_commits)"
complete -c dotta -n "__dotta_using_command diff" -F

# sync: Positional arguments are profiles
complete -c dotta -n "__dotta_using_command sync" -xa "(__dotta_profiles)"

# ignore: Positional argument is profile
complete -c dotta -n "__dotta_using_command ignore; and __dotta_is_nth_arg 1" -xa "(__dotta_profiles)"

# show: Takes managed files, commits, or file@commit refspecs
complete -c dotta -n "__dotta_using_command show" -xa "(__dotta_files)"
complete -c dotta -n "__dotta_using_command show" -xa "(__dotta_commits)"
complete -c dotta -n "__dotta_using_command show" -xa "(__dotta_refspec_commits)"

# revert: Takes file@commit refspecs, managed files, or commits
complete -c dotta -n "__dotta_using_command revert" -xa "(__dotta_files)"
complete -c dotta -n "__dotta_using_command revert" -xa "(__dotta_commits)"
complete -c dotta -n "__dotta_using_command revert" -xa "(__dotta_refspec_commits)"

# profile subcommand argument values
complete -c dotta -n "__dotta_using_subcommand profile enable"  -xa "(__dotta_profiles_all)"
complete -c dotta -n "__dotta_using_subcommand profile disable" -xa "(__dotta_profiles)"
complete -c dotta -n "__dotta_using_subcommand profile fetch"   -xa "(__dotta_profiles_all)"
complete -c dotta -n "__dotta_using_subcommand profile reorder" -xa "(__dotta_profiles)"

# remote subcommand argument values (subcommand itself is not in .subcommands)
complete -c dotta -n "__dotta_using_subcommand remote remove"  -xa "(__dotta_remotes)"
complete -c dotta -n "__dotta_using_subcommand remote set-url" -xa "(__dotta_remotes)"
complete -c dotta -n "__dotta_using_subcommand remote rename"  -xa "(__dotta_remotes)"
complete -c dotta -n "__dotta_using_subcommand remote show"    -xa "(__dotta_remotes)"

# =============================================================================
# Auto-generated schema
#
# Sourced last so the condition helpers defined above are already in
# scope (fish resolves `-n "..."` expressions at completion time, but
# defining helpers first keeps load-order reasoning local to this file).
# =============================================================================

set -l __dotta_comp_dir (status dirname)
source "$__dotta_comp_dir/dotta-completions.fish"
