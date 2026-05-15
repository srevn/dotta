# Configuration

Dotta is configured through `~/.config/dotta/config.toml`. A fully annotated sample is available at [`etc/config.toml.sample`](../etc/config.toml.sample).

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
strict_mode = false                      # Fail on validation errors vs warn
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

### [encryption]

```toml
[encryption]
enabled = false               # Enable encryption (opt-in)
strength = "balanced"         # Controls the memory and pass count of the password-based key derivation
session_timeout = 3600        # Key cache timeout in seconds (0=always prompt, -1=never expire)
auto_encrypt = [              # Patterns for automatic encryption
    ".ssh/id_*",
    "*.key",
]
```

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
```

## Hooks

Hook scripts run before/after operations. Place executable scripts in the hooks directory.

**Available hooks:** `pre-apply`, `post-apply`, `pre-add`, `post-add`, `pre-remove`, `post-remove`, `pre-update`, `post-update`

**Behavior:**
- Pre-hooks can abort operations by exiting with a non-zero status
- Post-hooks run after the operation completes; their exit code is logged but does not affect the operation

**Environment variables passed to hooks:**
- `DOTTA_REPO_DIR` -- repository path
- `DOTTA_COMMAND` -- operation name (`apply`, `add`, `remove`, `update`)
- `DOTTA_PROFILE` -- comma-separated profile list
- `DOTTA_DRY_RUN` -- `"1"` if dry-run, `"0"` otherwise
- `DOTTA_FILE_COUNT` -- number of files (add/remove/update hooks)
- `DOTTA_FILE_0`, `DOTTA_FILE_1`, ... -- individual file paths

See [`etc/hooks/README.md`](../etc/hooks/README.md) for hook samples and detailed documentation.

## Ignore Patterns

Dotta uses a multi-layered ignore system (in precedence order):

1. **CLI** -- `--exclude` flags (highest priority, per-operation)
2. **Profile `.dottaignore`** -- per-profile overrides, can negate with `!`
3. **Baseline `.dottaignore`** -- repository-wide, machine-local, version-controlled
4. **Config patterns** -- `[ignore] patterns` in config.toml (user-specific)
5. **Source `.gitignore`** -- from the directory being added (lowest priority)

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

# Test if a path would be ignored
dotta ignore --test ~/.config/nvim/node_modules
```

**Pattern syntax** follows `.gitignore` conventions: `*` (wildcard), `?` (single char), `[abc]` (class), `!` (negate).

Profile `.dottaignore` files start empty and inherit all baseline patterns. Use `!pattern` in a profile to override a baseline ignore.

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

Scripts execute in profile layering order (global, then OS, then host). After cloning, dotta prompts to run detected bootstrap scripts (override with `--bootstrap` or `--no-bootstrap`).

## Custom Deployment Root

Deploy files to arbitrary filesystem locations (containers, jails, chroots):

```bash
# Add files with a custom deployment root
dotta add --profile jail/web --target /mnt/jails/web /mnt/jails/web/etc/nginx.conf

# Enable with the target root
dotta profile enable jail/web --target /mnt/jails/web
```

Files are stored as `custom/<path>` and deployed under the specified target. Custom target requires exactly one profile per operation.
