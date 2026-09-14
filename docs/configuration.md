# Configuration

Dotta is configured through `~/.config/dotta/config.toml`. A fully annotated sample is available at [`etc/config.example.toml`](../etc/config.example.toml).

A missing file means the defaults. A file that cannot be read, does not parse, or holds a key or value dotta refuses stops every command, and the error names the file and the reason. Every value is read in its key's type — `strict_mode = "yes"` is refused, not read as the default — and the error names the key as `[section] key`.

## Environment Variables

```bash
DOTTA_REPO_DIR       # Override repository location
DOTTA_CONFIG_FILE    # Use a different config file
DOTTA_EDITOR         # Editor for bootstrap/ignore (fallback: VISUAL → EDITOR → vi/nano)
```

## Config Sections

### [core]

```toml
[core]
repo_dir = "~/.local/share/dotta/repo"   # Repository location
strict_mode = false                      # Block sync on uncommitted changes, vs warn and prompt
strict_ownership = false                 # Abort apply on an unresolvable owner or group, vs warn
auto_detect_new_files = true             # Detect new files in tracked dirs during update
```

### [security]

```toml
[security]
confirm_destructive = true    # Prompt before overwrites/deletes
confirm_new_files = true      # Prompt before adding detected new files
```

### [sync]

```toml
[sync]
auto_pull = true              # Auto-pull when remote is ahead
diverged_strategy = "warn"    # warn, rebase, merge, ours, theirs
```

`dotta sync --diverged <strategy>` overrides the setting for one run. `ours` and `theirs` are destructive, and act on a branch that is only behind or only ahead as well: `ours` force-pushes over the newer remote commits, `theirs` resets the local ones away.

### [encryption]

```toml
[encryption]
enabled = false               # Enable encryption (opt-in)
session_timeout = 3600        # Key cache timeout in seconds (0=always prompt, -1=never expire)
auto_encrypt = [              # Patterns for automatic encryption
    ".ssh/id_*",
    "*.key",
]
```

The list is a *selector*: the last rule that reaches a file decides, where a rule reaches a file when it matches the file itself or any directory above it. A `!` rule stands wherever you put it — nothing here is final, unlike `.dottaignore`.

See [Encryption](encryption.md) for the full encryption guide.

### [ignore]

```toml
[ignore]
patterns = [                  # Personal ignore patterns (not shared)
    ".DS_Store",
    "*.local",
]
respect_gitignore = true      # Honor source .gitignore when adding
```

### [output]

```toml
[output]
verbosity = "normal"   # quiet, normal, verbose
color = "auto"         # auto, always, never
```

### [commit]

Custom commit message templates with variable substitution:

```toml
[commit]
title = "{host}: {action} {profile}"
body = """
Date: {datetime}
User: {user}
Files: {count}

{action_past}:
{files}
"""
```

**Available variables:** `{host}`, `{user}`, `{profile}`, `{action}`, `{action_past}`, `{count}`, `{files}`, `{date}`, `{datetime}`, `{target_commit}`

### [hooks]

```toml
[hooks]
hooks_dir = "~/.config/dotta/hooks"   # Hook script directory
timeout = 30                          # Max execution time (seconds)
pre_apply = true
post_apply = true
pre_add = false
post_add = false
pre_remove = false
post_remove = false
pre_update = false
post_update = false
pre_sync = false
post_sync = false
```

## Hooks

Hook scripts run before/after operations. Place executable scripts in the hooks directory.

**Available hooks:** `pre-apply`, `post-apply`, `pre-add`, `post-add`, `pre-remove`, `post-remove`, `pre-update`, `post-update`, `pre-sync`, `post-sync`

**Behavior:**
- Pre-hooks can abort operations by exiting with a non-zero status
- Post-hooks run after the operation completes; their exit code is logged but does not affect the operation

**Environment variables passed to hooks:**
- `DOTTA_REPO_DIR` -- repository path
- `DOTTA_COMMAND` -- operation name (`apply`, `add`, `remove`, `update`, `sync`)
- `DOTTA_PROFILE` -- the profile for add and remove; the space-separated list of profiles for apply, update and sync
- `DOTTA_REMOTE` -- the remote's name (sync hooks)
- `DOTTA_DRY_RUN` -- `"1"` if dry-run, `"0"` otherwise (a post-hook never runs on a dry run)
- `DOTTA_FILE_COUNT` -- number of files (add/remove/update hooks)
- `DOTTA_FILE_0`, `DOTTA_FILE_1`, ... -- individual file paths

See [`etc/hooks/README.md`](../etc/hooks/README.md) for hook samples and detailed documentation.

## Ignore Patterns

Dotta uses a multi-layered ignore system (in precedence order):

1. **CLI** -- `--exclude` flags (highest priority, per-operation)
2. **Config patterns** -- `[ignore] patterns` in config.toml (user-specific)
3. **Profile `.dottaignore`** -- per-profile overrides, can negate with `!`
4. **Baseline `.dottaignore`** -- repository-wide, machine-local, version-controlled
5. **Source `.gitignore`** -- from the directory being added (lowest priority)

A pattern is matched against the path **as seen from the directory it deploys under** — exactly what a `.gitignore` sitting at `~` (for `home/` files), at `/` (for `root/` files) or at the profile's target (for `custom/` files) would see. So write `.config/Code/Cache/` for `~/.config/Code/Cache` and `etc/ssh/*_key` for `/etc/ssh/ssh_host_*_key`. The leading `home/`, `root/` and `custom/` never appear in a pattern, and nothing above that directory takes part in a match: a `$HOME` that happens to live under `/srv/build` is not caught by `build/`.

`--exclude` on `add`, `apply` and `update` takes the same patterns with the same meaning. Every entry of a pattern list — an `--exclude`, an entry of `[ignore] patterns` or of `auto_encrypt` — is one pattern, read as the line it would be in a `.dottaignore`; an entry that would make no rule there (a comment, a blank, two lines) is refused. Both config lists are compiled when the file is loaded, `auto_encrypt` whether or not encryption is enabled, so a bad entry stops every command and the error names its line and column. `dotta ignore` opens a `.dottaignore` in the configured editor exactly as it stands, so a broken one can be mended.

```bash
# Edit the baseline ignore file
dotta ignore

# Edit a profile's ignore file
dotta ignore darwin

# Add a pattern programmatically
dotta ignore --add '*.tmp'                # to baseline
dotta ignore darwin --add '*.tmp'         # to the darwin profile

# See the compiled safety defaults
dotta ignore --list-defaults

# Test if a path would be ignored (any form add accepts; a trailing / tests it as a directory)
dotta ignore --test ~/.config/nvim/node_modules
dotta ignore --test home/.cache/x/
```

**Pattern syntax** follows `.gitignore` conventions: `*` (wildcard), `?` (single char), `[abc]` (class), `!` (negate), a trailing `/` for directories, a leading `/` to anchor at the top of that directory (`/.cache/` is `~/.cache` alone; `.cache/` is every `.cache` directory).

Profile `.dottaignore` files start empty and inherit all baseline patterns. Use `!pattern` in a profile to override a baseline ignore — a *pattern*, not a directory an earlier layer excluded. As in git, an excluded directory is final: with a baseline `.cache/`, `!.cache/keep.conf` does nothing and `!.cache/` is what re-opens it. The same holds for `--exclude`: `-e 'build/' -e '!build/keep'` keeps nothing, while `-e 'build/*' -e '!build/keep'` keeps the file, because a pattern that matches no directory builds no barrier. `dotta ignore --test` names the rule that excluded a path, which is the one to clear.

## Bootstrap

Per-profile setup scripts that automate system configuration:

```bash
# Run bootstrap for auto-detected profiles
dotta bootstrap

# Run for specific profiles
dotta bootstrap darwin

# Create/edit a bootstrap script
dotta bootstrap darwin --edit

# List all bootstrap scripts
dotta bootstrap --list

# Preview without executing
dotta bootstrap --dry-run
```

Bootstrap scripts are stored as `.bootstrap` in each profile branch and receive:
- `DOTTA_REPO_DIR`, `DOTTA_PROFILE`, `DOTTA_PROFILES`, `HOME`, `DOTTA_DRY_RUN`

They run as the invoker, never as root. `HOME`, `USER` and `LOGNAME` name the user who typed the command, even when the run obtained root through `sudo`, and `HOME` is the same home directory dotta resolved the `home/` paths against.

Scripts execute in the enabled profiles' layering order, bottom layer first (on a fresh clone: global, then the OS, then the host); `--all` runs every profile's script in the layering convention's order, and named profiles run in the order given. After cloning, dotta prompts to run detected bootstrap scripts (override with `--bootstrap` or `--no-bootstrap`).

## Deployment Targets

A profile can be pointed at a directory of its own -- a container, a jail, a chroot -- so that files inside it deploy there on each machine. There is nothing to configure here: a target belongs to the machine, and `dotta profile enable --target` sets it. See [Targets](profiles.md#targets).
