# Dotta Hook Scripts

Hooks allow you to run custom scripts before and after dotta operations.

## Installation

1. **Create hooks directory:**
   ```bash
   mkdir -p ~/.config/dotta/hooks
   ```

2. **Copy sample hooks:**
   ```bash
   cp etc/hooks/pre-apply.sample ~/.config/dotta/hooks/pre-apply
   cp etc/hooks/post-apply.sample ~/.config/dotta/hooks/post-apply
   cp etc/hooks/pre-add.sample ~/.config/dotta/hooks/pre-add
   cp etc/hooks/post-add.sample ~/.config/dotta/hooks/post-add
   ```

3. **Make them executable:**
   ```bash
   chmod +x ~/.config/dotta/hooks/*
   ```

4. **Customize for your needs:**
   Edit the scripts to match your workflow.

## Available Hooks

### `pre-apply`

**When:** Before applying profiles
**Use For:** Backing up configs, validating environment, checking disk space

**Example Use Cases:**
- Create timestamped backups of current configs
- Verify required environment variables are set
- Check system resources (disk space, memory)
- Pull latest changes from remote repo

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_COMMAND` - Always "apply"
- `DOTTA_PROFILE` - Comma-separated list of profiles being applied
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0: Continue with apply
- Exit non-zero: Abort apply operation

### `post-apply`

**When:** After applying profiles
**Use For:** Reloading services, restarting apps, sending notifications

**Example Use Cases:**
- Reload shell configuration
- Restart tmux/tmuxinator
- Update vim/neovim plugins
- Send desktop notification
- Trigger service restarts

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_COMMAND` - Always "apply"
- `DOTTA_PROFILE` - Comma-separated list of profiles being applied
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0 or non-zero: Apply already completed, exit code logged only

### `pre-add`

**When:** Before adding files to a profile
**Use For:** Validating file contents, checking for secrets, size checks

**Example Use Cases:**
- Scan for secrets (API keys, passwords, tokens)
- Check for private SSH keys
- Validate file sizes (warn on large files)
- Lint/validate file formats
- Check for binary files

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_COMMAND` - Always "add"
- `DOTTA_PROFILE` - Profile name being modified
- `DOTTA_FILE_COUNT` - Number of files
- `DOTTA_FILE_0`, `DOTTA_FILE_1`, ... - Individual file paths (0-indexed)
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0: Continue with add
- Exit non-zero: Abort add operation

### `post-add`

**When:** After adding files to a profile
**Use For:** Auto-committing, CI/CD triggers, team notifications

**Example Use Cases:**
- Auto-commit changes to git
- Push to remote repository
- Trigger CI/CD pipelines
- Send Slack/Discord notifications
- Generate profile documentation
- Update README files

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_COMMAND` - Always "add"
- `DOTTA_PROFILE` - Profile name that was modified
- `DOTTA_FILE_COUNT` - Number of files
- `DOTTA_FILE_0`, `DOTTA_FILE_1`, ... - Individual file paths (0-indexed)
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0 or non-zero: Add already completed, exit code logged only

## Hook Configuration

Control hooks via `~/.config/dotta/config.toml`:

```toml
[hooks]
hooks_dir = "~/.config/dotta/hooks"  # Where to find hooks
pre_apply = true                      # Enable pre-apply
post_apply = true                     # Enable post-apply
pre_add = false                       # Disable pre-add (default)
post_add = false                      # Disable post-add (default)
```

## Writing Hooks

### Best Practices

1. **Always use `set -euo pipefail`** at the top of bash scripts
2. **Check environment variables** before using them
3. **Provide clear error messages** to stderr
4. **Exit with appropriate codes:**
   - 0 for success
   - Non-zero for errors (aborts pre-hooks only)
5. **Be idempotent:** Hooks may run multiple times
6. **Handle missing commands gracefully:** Use `command -v` checks
7. **Log what you're doing:** Help users understand what happened

### Script Template

```bash
#!/usr/bin/env bash
set -euo pipefail

# Validate environment
if [[ -z "${DOTTA_REPO_DIR:-}" ]]; then
    echo "Error: DOTTA_REPO_DIR not set!" >&2
    exit 1
fi

# Your logic here
echo "Running hook: $(basename "$0")"

# Exit appropriately
exit 0
```

### Security Considerations

1. **Never hardcode secrets** in hook scripts
2. **Use environment variables** for sensitive data
3. **Validate inputs:** Always validate file paths from `DOTTA_FILE_N` variables
4. **Use indexed variables:** Iterate via `DOTTA_FILE_COUNT` and `DOTTA_FILE_N` for safe file handling
5. **Be careful with auto-push:** Could expose sensitive data
6. **Limit permissions:** Hooks should only modify what they need

### Debugging Hooks

Run dotta with verbose output to see hook execution:

```bash
dotta add --profile test ~/.bashrc --verbose
```

Test hooks manually:

```bash
# Set up environment
export DOTTA_REPO_DIR=~/.local/share/dotta/repo
export DOTTA_COMMAND=add
export DOTTA_PROFILE=test
export DOTTA_FILE_COUNT=2
export DOTTA_FILE_0="file1.txt"
export DOTTA_FILE_1="file2.txt"
export DOTTA_DRY_RUN=0

# Run hook
~/.config/dotta/hooks/pre-add
```

## Example Workflows

### Workflow 1: Backup Before Apply

```bash
# pre-apply
#!/usr/bin/env bash
set -euo pipefail

backup_dir="$HOME/.dotta-backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"

# Backup all current dotfiles
rsync -a --files-from=<(dotta list --files) ~ "$backup_dir/" || true

echo "Backup created: $backup_dir"
```

### Workflow 2: Auto-Commit on Add

```bash
# post-add
#!/usr/bin/env bash
set -euo pipefail

cd "$DOTTA_REPO_DIR"

if ! git diff --quiet; then
    git add -A
    git commit -m "Add to $DOTTA_PROFILE: $DOTTA_FILE_COUNT files"
    git push origin main
fi
```

### Workflow 3: Secret Detection

```bash
# pre-add
#!/usr/bin/env bash
set -euo pipefail

# Iterate through all files using indexed variables
for ((i=0; i<DOTTA_FILE_COUNT; i++)); do
    var_name="DOTTA_FILE_$i"
    file="${!var_name}"

    if grep -qiE '(api[_-]?key|password|secret|token)' "$file"; then
        echo "ERROR: Potential secret in $file" >&2
        exit 1
    fi
done
```

### Workflow 4: Service Reload

```bash
# post-apply
#!/usr/bin/env bash
set -euo pipefail

# Reload systemd user services
for service in my-app my-other-app; do
    if systemctl --user is-active "$service" &>/dev/null; then
        systemctl --user reload "$service"
    fi
done
```

## Troubleshooting

### Hook Not Running

1. **Check if enabled:**
   ```bash
   grep -A5 "\[hooks\]" ~/.config/dotta/config.toml
   ```

2. **Verify file exists and is executable:**
   ```bash
   ls -la ~/.config/dotta/hooks/
   ```

3. **Test manually:**
   ```bash
   bash -x ~/.config/dotta/hooks/pre-apply
   ```

### Hook Failing

1. **Check exit code:**
   ```bash
   ~/.config/dotta/hooks/pre-apply
   echo $?  # Should be 0 for success
   ```

2. **Add debug output:**
   ```bash
   # At top of script
   set -x  # Print all commands
   ```

3. **Check logs:**
   ```bash
   dotta apply --verbose 2>&1 | tee dotta.log
   ```

## Advanced Topics

### Hook Chains

Run multiple scripts per hook:

```bash
#!/usr/bin/env bash
# post-apply
set -euo pipefail

hook_dir="$(dirname "$0")/post-apply.d"

if [[ -d "$hook_dir" ]]; then
    for script in "$hook_dir"/*.sh; do
        [[ -x "$script" ]] && "$script"
    done
fi
```

### Conditional Hooks

Run different logic based on profile:

```bash
#!/usr/bin/env bash
# post-apply
set -euo pipefail

case "$DOTTA_PROFILE" in
    work)
        # Work-specific post-apply
        ;;
    personal)
        # Personal post-apply
        ;;
esac
```

### Async Hooks

Run time-consuming tasks in background:

```bash
#!/usr/bin/env bash
# post-apply
set -euo pipefail

# Start long-running task in background
{
    sleep 2
    update_vim_plugins
} &

# Continue immediately
echo "Background task started"
exit 0
```

## See Also

- Main configuration: `etc/config.toml.sample`
- Hook samples: `etc/hooks/*.sample`
- Security guide: `docs/security.md`
