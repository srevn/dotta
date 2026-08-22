# Dotta Fish Completions — entry point
#
# Fish looks for completions under ~/.config/fish/completions (and other
# XDG paths) and auto-sources this file by command name. It holds every
# piece of the completion set that cannot be derived from the spec-engine
# registry, then sources the auto-generated schema at the bottom.
#
# What lives here (hand-maintained):
#
#   1. One reading of the command line (__dotta_command, __dotta_scan and
#      the views over it) that mirrors the engine's rules: the command is
#      the second token, `--flag=value` is one token, a value-taking flag
#      consumes the next token, `--` ends the flags. Which flags take a
#      value comes from the generated schema, per command
#      (__dotta_value_flags_<cmd>).
#
#   2. Sources that shell out to `dotta __complete <mode>` for data that
#      depends on the user's repo. Each mode reads one authority: the
#      enabled set (profiles), the view — every enabled profile at HEAD,
#      precedence resolved — (files), or Git (refspecs, commits). A rule
#      picks the authority the command reads: a workspace verb acts on the
#      view, a verb that names a profile acts on that profile's tree.
#
#   3. Positions: which profile the command line has named so far
#      (__dotta_profile_filter for the workspace verbs, __dotta_pinned_profile
#      for the profile-first verbs), the `<prefix>@<commit>` form, and add's
#      --target-aware path completion.
#
#   4. Condition helpers (__dotta_using_command et al.) referenced by both
#      this file and the generated schema.
#
#   5. Subcommand entries for commands whose router parses positionals
#      into an enum (remote, key) instead of declaring a `.subcommands`
#      tree. The generator can only project the spec's declared subcommand
#      table; router-internal routing stays here.
#
#   6. Flag-value and positional completions. The spec engine carries no
#      classifier for "this positional is a profile name" vs "this
#      positional is a managed file" — those rules are command-specific and
#      live here, aligned with each command's post_parse.
#
# What lives in dotta-completions.fish (auto-generated, sourced at the
# bottom of this file): root flags, command list, per-command flag
# tables, declared subcommand trees, and the per-command
# `__dotta_value_flags_<cmd>` lists read by the positional scan below.
# Regenerate with `make completions` after editing any command spec; never
# hand-edit that file.
#
# Installation:
#   make install-completions
#   # or, manually, copy both *.fish files into
#   #   ~/.config/fish/completions/

# =============================================================================
# The command line — one reading, the engine's rules
# =============================================================================

function __dotta_command
    # The command token. The engine reads argv[1] as the command — a bare
    # word, or a root alias such as -i — so no root flag ever precedes it.
    set -l tokens (commandline -opc)
    test (count $tokens) -ge 2; and echo $tokens[2]
end

function __dotta_scan
    # One reading of the tokens after the command, a line per token as the
    # engine sees it: `p<TAB>token` for a positional, `o<TAB>flag<TAB>value`
    # for a flag (the value empty for a bare one). A value-taking flag (the
    # command's generated __dotta_value_flags_<cmd> list) takes the next
    # token whatever it looks like, `--flag=value` carries its own, `-` alone
    # is positional, and after `--` everything is. A tree command's
    # subcommand is its first positional. Only meaningful under a known
    # command — every caller is guarded by __dotta_using_command.
    set -l tokens (commandline -opc)
    test (count $tokens) -ge 3; or return
    set -l values __dotta_value_flags_$tokens[2]
    set -l pending ''
    set -l literal 0
    for t in $tokens[3..]
        if test -n "$pending"
            printf 'o\t%s\t%s\n' $pending $t
            set pending ''
            continue
        end
        if test $literal -eq 1
            printf 'p\t%s\n' $t
            continue
        end
        switch $t
            case -
                printf 'p\t%s\n' $t
            case --
                set literal 1
            case '--*=*'
                set -l kv (string split -m1 = -- $t)
                printf 'o\t%s\t%s\n' $kv[1] $kv[2]
            case '-*'
                if contains -- $t $$values
                    set pending $t
                else
                    printf 'o\t%s\t\n' $t
                end
            case '*'
                printf 'p\t%s\n' $t
        end
    end
end

function __dotta_positionals
    # The positionals after the command, one per line, in order.
    __dotta_scan | string replace -rf '^p\t' ''
end

function __dotta_nth
    # True when the token being completed is the Nth positional.
    test (count (__dotta_positionals)) -eq (math $argv[1] - 1)
end

function __dotta_opt_seen
    # True when one of the given flags appears among the complete tokens.
    for line in (__dotta_scan)
        set -l f (string split \t -- $line)
        test $f[1] = o; and contains -- $f[2] $argv; and return 0
    end
    return 1
end

function __dotta_opt_values
    # The values of the given flags, one per line, in command-line order. A
    # single-valued flag's parser keeps the last occurrence, so callers read
    # [-1].
    for line in (__dotta_scan)
        set -l f (string split \t -- $line)
        test $f[1] = o; and contains -- $f[2] $argv; and echo $f[3]
    end
end

# =============================================================================
# Sources — dotta __complete, one authority per mode
# =============================================================================

function __dotta_profiles
    # The enabled set in precedence order; `--local` every local branch (the
    # enabled ones marked); `--remote` the remote-tracking branches not yet
    # fetched into a local one.
    dotta __complete profiles $argv 2>/dev/null
end

function __dotta_files
    # The view's files, each with the profile that wins it — narrowed to the
    # rows the profiles in $argv win, when any are given.
    set -l args
    for p in $argv
        set -a args -p $p
    end
    dotta __complete files $args 2>/dev/null
end

function __dotta_refspecs
    # Git's files: every local branch's, as profile:path, or — pinned to the
    # branch $argv[1] — that branch's, bare. Reaches a path a higher profile
    # shadows and a profile that is not enabled, which the view cannot.
    if test -n "$argv[1]"
        dotta __complete refspecs -p $argv[1] 2>/dev/null
    else
        dotta __complete refspecs 2>/dev/null
    end
end

function __dotta_commits
    # Reference forms first — valid against any branch. Then hashes from the
    # histories the command would search: the branches in $argv when one of
    # them is a branch, else the enabled set in precedence order (a guess
    # handed in from a positional may be a path; a path names no branch and
    # the enabled histories stand in, which is where show and diff resolve
    # a bare reference).
    printf 'HEAD\tCurrent commit\n'
    printf 'HEAD~1\tPrevious commit\n'
    printf 'HEAD~2\t2 commits ago\n'
    printf 'HEAD~3\t3 commits ago\n'
    if test (count $argv) -gt 0
        set -l args
        for p in $argv
            set -a args -p $p
        end
        set -l scoped (dotta __complete commits $args 2>/dev/null)
        if test (count $scoped) -gt 0
            printf '%s\n' $scoped
            return
        end
    end
    dotta __complete commits 2>/dev/null
end

function __dotta_remotes
    dotta __complete remotes 2>/dev/null
end

# =============================================================================
# Positions — which profile the command line has named
# =============================================================================

function __dotta_profile_filter
    # The profile filter a workspace verb (apply, update, diff) has built so
    # far: the -p values, and the positionals that name an enabled profile —
    # the verb's own classification, since a path is never a profile name.
    # Empty while nothing narrows the view.
    set -l enabled (__dotta_profiles | string replace -r '\t.*' '')
    set -l names (__dotta_opt_values -p --profile)
    for t in (__dotta_positionals)
        contains -- $t $enabled; and set -a names $t
    end
    for n in $names
        echo $n
    end
end

function __dotta_pinned_profile
    # The profile a profile-first verb (remove, list, show, revert, export)
    # has pinned: -p's value, else the first positional — its part before
    # ':' when that is a refspec. Prints nothing while no profile is pinned.
    set -l p (__dotta_opt_values -p --profile)[-1]
    if test -n "$p"
        echo $p
        return
    end
    set -l first (__dotta_positionals)[1]
    test -n "$first"; and echo (string split -m1 : -- $first)[1]
end

function __dotta_profile_slot
    # True while the token being completed is a profile-first verb's profile
    # slot: the first positional, with no -p/--profile given.
    __dotta_nth 1; and not __dotta_opt_seen -p --profile
end

function __dotta_packed_refspec
    # True when the first positional is a colon-packed refspec
    # (profile:path[@commit]) — export's cp-style form, whose next
    # positional is the destination.
    set -l first (__dotta_positionals)[1]
    string match -q '*:*' -- "$first"
end

function __dotta_at_commits
    # When the token being typed carries '@', complete its commit part as
    # <prefix>@<ref>. The history is the prefix's profile — the part before
    # ':' of a refspec, the whole prefix for export's profile@commit — unless
    # -p pins one; a path prefix names no branch and __dotta_commits falls
    # through to the enabled histories (revert discovers the profile itself).
    set -l token (commandline -ct)
    string match -q '*@*' -- $token; or return
    set -l prefix (string replace -r '@[^@]*$' '' -- $token)
    set -l p (__dotta_opt_values -p --profile)[-1]
    test -n "$p"; or set p (string split -m1 : -- $prefix)[1]
    for line in (__dotta_commits $p)
        set -l parts (string split -m1 \t -- $line)
        printf '%s@%s\t%s\n' $prefix $parts[1] $parts[2]
    end
end

function __dotta_add_paths
    # Mirror path_input_normalize (src/infra/path.c): when --target /T is
    # set, positional file paths resolve chroot-style relative to /T. So
    # complete from /T/ instead of CWD, preserving the user's leading-slash
    # style on the way back so the inserted token round-trips unchanged.
    set -l token (commandline -ct)
    set -l target (__dotta_opt_values --target)[-1]

    # No --target → standard filesystem completion (CWD-relative or absolute).
    # Tilde token → bypass target (path_input_normalize special-cases ~).
    if test -z "$target"; or string match -q '~*' -- $token
        __fish_complete_path "$token"
        return
    end

    # Strip trailing slashes from target; pathological "--target /" falls back.
    set target (string replace -r '/+$' '' -- $target)
    if test -z "$target"
        __fish_complete_path "$token"
        return
    end

    # User already typed the target prefix → already-inside branch, complete
    # against the real absolute path (matches path_input_normalize's check).
    if test "$token" = "$target"; or string match -q "$target/*" -- $token
        __fish_complete_path "$token"
        return
    end

    # Preserve leading-slash style: `/etc/foo` stays `/etc/foo`, `etc/foo`
    # stays relative — both chroot to target on the dotta side.
    set -l leading ''
    set -l rel $token
    if string match -q '/*' -- $token
        set leading /
        set rel (string sub -s 2 -- $token)
    end

    set -l prefix_len (math (string length $target) + 2)
    for path in "$target/$rel"*
        test -e $path; or test -L $path; or continue
        set -l visible (string sub -s $prefix_len -- $path)
        if test -d $path
            printf '%s%s/\n' $leading $visible
        else
            printf '%s%s\n' $leading $visible
        end
    end
end

# =============================================================================
# Condition helpers — referenced by the generated schema
# =============================================================================

function __dotta_needs_command
    # True while no command has been typed (only `dotta` so far).
    test (count (commandline -opc)) -eq 1
end

function __dotta_using_command
    # True when the command is one of $argv.
    set -l cmd (__dotta_command)
    test -n "$cmd"; and contains -- $cmd $argv
end

function __dotta_needs_subcommand
    # True while command $argv[1]'s first positional — its subcommand — is
    # absent.
    __dotta_using_command $argv[1]; and test (count (__dotta_positionals)) -eq 0
end

function __dotta_using_subcommand
    # True when the command is $argv[1] and its first positional is $argv[2].
    __dotta_using_command $argv[1]; or return
    set -l pos (__dotta_positionals)
    test "$pos[1]" = "$argv[2]"
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
complete -c dotta -n '__dotta_needs_subcommand remote' -a list -d 'List remotes'
complete -c dotta -n '__dotta_needs_subcommand remote' -a add -d 'Add remote'
complete -c dotta -n '__dotta_needs_subcommand remote' -a remove -d 'Remove remote'
complete -c dotta -n '__dotta_needs_subcommand remote' -a set-url -d 'Set remote URL'
complete -c dotta -n '__dotta_needs_subcommand remote' -a rename -d 'Rename remote'
complete -c dotta -n '__dotta_needs_subcommand remote' -a show -d 'Show remote'

# --- key subcommands ---
complete -c dotta -n '__dotta_needs_subcommand key' -a set -d 'Set encryption passphrase'
complete -c dotta -n '__dotta_needs_subcommand key' -a clear -d 'Clear cached passphrase'
complete -c dotta -n '__dotta_needs_subcommand key' -a status -d 'Show key status'

# =============================================================================
# Flag-Value Completions
#
# The generator emits each flag's name + description; these rules
# augment specific flags with value candidates or file completion.
# Fish merges rules for the same flag, so -d is omitted here to avoid
# duplicate description rendering.
# =============================================================================

# -p/--profile: the workspace verbs filter the enabled set; the verbs that
# read or write one profile's branch name any local profile.
complete -c dotta -n '__dotta_using_command apply update status diff sync' -s p -l profile -xa '(__dotta_profiles)'
complete -c dotta -n '__dotta_using_command add remove list show revert ignore bootstrap' -s p -l profile -xa '(__dotta_profiles --local)'

# sync's --diverged takes one of a fixed strategy set.
complete -c dotta -n '__dotta_using_command sync' -l diverged -xa 'warn rebase merge ours theirs'

# Filesystem paths: ignore --test, export -o/--output.
complete -c dotta -n '__dotta_using_command ignore' -l test -rF
complete -c dotta -n '__dotta_using_command export' -s o -l output -rF

# --target takes a deployment-root directory
complete -c dotta -n '__dotta_using_command add' -l target -xa '(__fish_complete_directories)'
complete -c dotta -n '__dotta_using_subcommand profile enable' -l target -xa '(__fish_complete_directories)'

# =============================================================================
# Positional Arguments
#
# Per-command positional semantics (first arg is a profile, second is
# a managed file, etc.) are classifier-driven and can't be derived
# from the spec's opt table. Keep them aligned with each command's
# post_parse logic.
# =============================================================================

# init: [path] — where the repository goes
complete -c dotta -n '__dotta_using_command init; and __dotta_nth 1' -xa '(__fish_complete_directories)'

# clone: <url> [path]
complete -c dotta -n '__dotta_using_command clone; and __dotta_nth 2' -xa '(__fish_complete_directories)'

# add: a profile (any local one; a new name is typed), then filesystem paths
complete -c dotta -n '__dotta_using_command add; and __dotta_profile_slot' -xa '(__dotta_profiles --local)'
complete -c dotta -n '__dotta_using_command add; and not __dotta_profile_slot' -xa '(__dotta_add_paths)'

# remove: a profile, then paths of that profile's tree — Git, so a path a
# higher profile shadows and a disabled profile's paths are reachable
complete -c dotta -n '__dotta_using_command remove; and __dotta_profile_slot' -xa '(__dotta_profiles --local)'
complete -c dotta -n '__dotta_using_command remove; and not __dotta_profile_slot; and not __dotta_opt_seen --delete-profile' -xa '(__dotta_refspecs (__dotta_pinned_profile))'

# update: the first positional may name an enabled profile; every positional
# may be a file of the view, narrowed by the profiles named so far
complete -c dotta -n '__dotta_using_command update; and __dotta_profile_slot' -xa '(__dotta_profiles)'
complete -c dotta -n '__dotta_using_command update' -xa '(__dotta_files (__dotta_profile_filter))'
complete -c dotta -n '__dotta_using_command update' -F

# apply: enabled profiles or files of the view, in any order
complete -c dotta -n '__dotta_using_command apply' -xa '(__dotta_profiles)'
complete -c dotta -n '__dotta_using_command apply' -xa '(__dotta_files (__dotta_profile_filter))'
complete -c dotta -n '__dotta_using_command apply' -F

# status, sync: enabled profiles
complete -c dotta -n '__dotta_using_command status sync' -xa '(__dotta_profiles)'

# diff: enabled profiles, files of the view, commits — classified by shape
complete -c dotta -n '__dotta_using_command diff' -xa '(__dotta_profiles)'
complete -c dotta -n '__dotta_using_command diff' -xa '(__dotta_files (__dotta_profile_filter))'
complete -c dotta -n '__dotta_using_command diff' -xa '(__dotta_commits (__dotta_profile_filter))'
complete -c dotta -n '__dotta_using_command diff' -F

# list: a profile (any local one) or a file of the view; then, under the
# pinned profile, a file of its tree
complete -c dotta -n '__dotta_using_command list; and __dotta_profile_slot' -xa '(__dotta_profiles --local)'
complete -c dotta -n '__dotta_using_command list; and __dotta_profile_slot' -xa '(__dotta_files)'
complete -c dotta -n '__dotta_using_command list; and not __dotta_profile_slot' -xa '(__dotta_refspecs (__dotta_pinned_profile))'

# show: [profile:]file[@commit] | commit | file commit | profile file[@commit]
# | profile file commit — files of every branch (bare once a profile is
# pinned), commits of the pinned or enabled histories
complete -c dotta -n '__dotta_using_command show; and __dotta_nth 1' -xa '(__dotta_refspecs (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command show; and __dotta_nth 2; and not __dotta_opt_seen -p --profile' -xa '(__dotta_refspecs (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command show' -xa '(__dotta_commits (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command show' -xa '(__dotta_at_commits)'

# revert: [profile:]file@commit | file commit | profile file[@commit]
# | profile file commit — as show, without the bare-commit form
complete -c dotta -n '__dotta_using_command revert; and __dotta_nth 1' -xa '(__dotta_refspecs (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command revert; and __dotta_nth 2; and not __dotta_opt_seen -p --profile' -xa '(__dotta_refspecs (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command revert; and not __dotta_nth 1' -xa '(__dotta_commits (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command revert' -xa '(__dotta_at_commits)'

# export: profile[@commit] [path] [commit] -o dest | profile:path[@commit] dest
complete -c dotta -n '__dotta_using_command export; and __dotta_nth 1' -xa '(__dotta_profiles --local)'
complete -c dotta -n '__dotta_using_command export; and __dotta_nth 1' -xa '(__dotta_refspecs)'
complete -c dotta -n '__dotta_using_command export; and __dotta_nth 2; and not __dotta_packed_refspec' -xa '(__dotta_refspecs (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command export; and __dotta_nth 2; and not __dotta_packed_refspec' -xa '(__dotta_commits (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command export; and __dotta_nth 2; and __dotta_packed_refspec' -F
complete -c dotta -n '__dotta_using_command export; and __dotta_nth 3; and not __dotta_packed_refspec' -xa '(__dotta_commits (__dotta_pinned_profile))'
complete -c dotta -n '__dotta_using_command export' -xa '(__dotta_at_commits)'

# ignore: [profile] — any local profile's .dottaignore
complete -c dotta -n '__dotta_using_command ignore; and __dotta_profile_slot' -xa '(__dotta_profiles --local)'

# bootstrap: [profile]... — any local profile's script
complete -c dotta -n '__dotta_using_command bootstrap' -xa '(__dotta_profiles --local)'

# profile subcommand argument values
complete -c dotta -n '__dotta_using_subcommand profile enable' -xa '(__dotta_profiles --local)'
complete -c dotta -n '__dotta_using_subcommand profile disable' -xa '(__dotta_profiles)'
complete -c dotta -n '__dotta_using_subcommand profile fetch' -xa '(__dotta_profiles --local --remote)'
complete -c dotta -n '__dotta_using_subcommand profile reorder' -xa '(__dotta_profiles)'

# remote subcommand argument values (subcommand itself is not in .subcommands)
complete -c dotta -n '__dotta_using_subcommand remote remove; and __dotta_nth 2' -xa '(__dotta_remotes)'
complete -c dotta -n '__dotta_using_subcommand remote set-url; and __dotta_nth 2' -xa '(__dotta_remotes)'
complete -c dotta -n '__dotta_using_subcommand remote rename; and __dotta_nth 2' -xa '(__dotta_remotes)'
complete -c dotta -n '__dotta_using_subcommand remote show; and __dotta_nth 2' -xa '(__dotta_remotes)'

# =============================================================================
# Auto-generated schema
#
# Sourced last so the condition helpers defined above are already in
# scope (fish resolves `-n "..."` expressions at completion time, but
# defining helpers first keeps load-order reasoning local to this file).
# =============================================================================

set -l __dotta_comp_dir (status dirname)
source "$__dotta_comp_dir/dotta-completions.fish"
