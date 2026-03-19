# Workflows

Common day-to-day workflows with dotta.

## The Core Cycle: Add, Apply, Update

### Adding Files

```bash
# Add files to a profile (first arg is profile name)
dotta add global ~/.bashrc
dotta add darwin ~/.config/fish

# Add a directory (recursively)
dotta add global ~/.config/nvim

# Exclude certain files
dotta add global ~/.config/nvim --exclude '*.log' --exclude 'node_modules/*'

# Custom commit message
dotta add global ~/.bashrc -m "Add shell config"
```

### Deploying

```bash
# Deploy all enabled profiles
dotta apply

# Preview without making changes
dotta apply --dry-run

# Deploy only a specific profile's files
dotta apply -p darwin

# Deploy specific files
dotta apply ~/.bashrc ~/.zshrc

# Force overwrite modified files
dotta apply --force

# Keep orphaned files (don't remove files from disabled profiles)
dotta apply --keep-orphans
```

`apply` performs full synchronization: it deploys new and updated files, and removes orphaned files from disabled profiles.

### Updating (Filesystem to Repo)

After editing deployed files in place:

```bash
# Commit all modified files back to their profiles
dotta update

# Update a specific file
dotta update ~/.bashrc

# Preview changes
dotta update --dry-run

# Also pick up new files in tracked directories
dotta update --include-new

# Custom commit message
dotta update -m "Update shell config"
```

## Checking Status

```bash
# Full status (local filesystem + remote sync state)
dotta status

# Only filesystem status
dotta status --local

# Only remote sync state
dotta status --remote

# Specific profile
dotta status -p global

# Verbose output
dotta status -v
```

**Status indicators:**
- `[undeployed]` -- file in manifest but never deployed
- `[clean]` -- deployed file matches expected state
- `[modified]` -- deployed file has been changed on disk
- `[deleted]` -- deployed file was removed from disk
- `[orphaned]` -- file's profile was disabled, pending removal

**Remote indicators:**
- `=` up-to-date
- `↑n` n commits ahead (ready to push)
- `↓n` n commits behind (run `dotta sync`)
- `↕` diverged
- `•` no remote tracking

## Viewing Differences

```bash
# Full workspace diff (what apply would change)
dotta diff

# What apply would deploy (repo → filesystem)
dotta diff --upstream

# What update would commit (filesystem → repo)
dotta diff --downstream

# Both directions
dotta diff --all

# Diff for a specific file
dotta diff home/.bashrc

# Compare two commits
dotta diff b3e1f9a a4f2c8e

# Only show file names
dotta diff --name-only
```

## Listing Files and History

`dotta list` has three levels depending on arguments:

```bash
# Level 1: List profiles
dotta list
dotta list -v                    # With stats (file count, size, last commit)
dotta list --remote              # Include sync status

# Level 2: List files in a profile
dotta list global
dotta list global -v             # With sizes and per-file commits

# Level 3: File commit history
dotta list global home/.bashrc
dotta list global home/.bashrc -v  # Full commit messages
```

## Showing File Content

```bash
# Show file from enabled profiles
dotta show home/.bashrc

# From a specific profile
dotta show -p global home/.bashrc

# At a specific commit
dotta show home/.bashrc@a4f2c8e

# Refspec syntax
dotta show global:home/.bashrc@a4f2c8e

# Show a commit with diff
dotta show a4f2c8e

# Raw content (no formatting)
dotta show --raw home/.bashrc
```

## Reverting Files

```bash
# See file history first
dotta list global home/.bashrc

# Revert to a specific commit
dotta revert home/.bashrc@HEAD~1
dotta revert darwin home/.bashrc a4f2c8e

# Preview the revert
dotta revert --dry-run home/.bashrc@HEAD~3

# Revert modifies the Git repository only
# Run apply to deploy the reverted version
dotta apply
```

## Syncing with Remote

```bash
# Sync all enabled profiles (fetch + push/pull)
dotta sync

# Sync specific profiles
dotta sync global darwin

# Preview what would happen
dotta sync --dry-run

# Push only (no pulling)
dotta sync --no-pull

# Pull only (no pushing)
dotta sync --no-push

# Handle diverged branches with a specific strategy
dotta sync --diverged rebase   # Options: warn, rebase, merge, ours, theirs
```

**Typical workflow:**

```bash
dotta update    # Commit local changes
dotta sync      # Push/pull with remote
```

`sync` requires a clean workspace (no uncommitted changes). Use `dotta update` first, or `--force` to override.

## Removing Files

```bash
# Remove a file from a profile
dotta remove global ~/.bashrc

# Remove a directory
dotta remove global ~/.config/nvim

# Delete an entire profile
dotta remove test --delete-profile

# Preview removal
dotta remove global ~/.bashrc --dry-run
```

Removing modifies the Git repository only. Run `dotta apply` afterward to sync the filesystem (orphaned files are pruned by default).
