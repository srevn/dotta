# Workflows

Common day-to-day workflows with dotta.

## The Core Cycle: Add, Apply, Update

### Adding Files and Directories

```bash
# Add files or directories to a profile (first arg is profile name)
dotta add global ~/.bashrc
dotta add darwin ~/.config/fish

# Add a directory (recursively)
dotta add global ~/.config/nvim

# Exclude certain files
dotta add global ~/.config/nvim --exclude '*.log' --exclude 'node_modules/'

# Custom commit message
dotta add global ~/.bashrc -m "Add shell config"

# Preview: what would be added, and where each path would be stored
dotta add --dry-run -v global ~/.config/nvim

# Point a profile at a directory of its own and capture from inside it
dotta add web --target /mnt/jails/web /mnt/jails/web/etc/nginx.conf
```

Where each path lands inside the profile is covered in [How Files Are Stored](concepts.md#how-files-are-stored) and [Targets](profiles.md#targets).

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

# Keep orphaned files (prune none, a disabled profile's included)
dotta apply --keep-orphans
```

`apply` performs full synchronization: it deploys new and updated files, and prunes dotta's own unchanged copies of orphaned files — those of disabled profiles, and those deleted from their profiles.

### Updating (Filesystem to Repo)

After editing deployed files in place:

```bash
# Commit every modified path back to its profile
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

Deleting a file and running `dotta update` deletes it and every machine's unchanged copy: see [Removing Files](#removing-files).

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

`dotta status` groups paths by what to do about them and tags each one -- `[undeployed]`, `[clean]`, `[modified]`, `[deleted]`, `[orphaned]` and more. A path can carry several tags at once (`[orphaned] [relocated]`), and where a tag needs explaining, status prints a short legend under the group. `dotta status --full` lists every managed path with its state and the profile it comes from.

**Remote indicators** -- `dotta list --remote` prints these compact markers; `dotta status` spells the same states out in words (`↑ 2 commits ahead`). What `dotta sync` does with each is its strategy's (see [Syncing with Remote](#syncing-with-remote)):

- `[=]` up-to-date
- `[↑n]` n commits ahead
- `[↓n]` n commits behind
- `[↕n+m]` diverged (n ahead, m behind)
- `[•]` no remote branch

## Viewing Differences

```bash
# Full workspace diff (what apply would change, or skip)
dotta diff

# What apply would deploy or skip (repo → filesystem)
dotta diff --upstream

# What update would commit or skip (filesystem → repo)
dotta diff --downstream

# Both directions
dotta diff --all

# Diff for a specific path: a file, or a directory and what it holds
dotta diff home/.bashrc

# Compare two commits
dotta diff b3e1f9a a4f2c8e

# Only show the paths
dotta diff --name-only
```

Each listed path opens with a status line: what differs, then what the previewed verb does about it, or why it skips the path -- `modified locally (would be committed by update)`, `changed in Git (would be deployed by apply)`, `changed in Git and on disk (update skips it)`. A directory is listed as a file is, for its mode, its ownership or its kind. Beneath the line, differing bytes draw a hunk, and a differing kind names both kinds. `dotta diff` compares the paths your enabled profiles claim: new files in tracked directories are listed by `dotta update --dry-run`, and the copies apply would remove by `dotta apply --dry-run`.

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

# Byte-faithful content to stdout (scripting; show is a terminal display)
dotta export global:home/.bashrc -
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

# Revert commits the restore to its profile; nothing on disk changes
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

`sync` moves commits and nothing else: it neither reads nor changes the files on this machine, so an edit not yet committed with `dotta update` stays here. A file you edited that a pull also changed then reads as changed in Git and on disk, for you to decide: `dotta apply --force <path>` keeps the pulled version, `dotta add --force <profile> <path>` keeps yours. Committed first, the two edits leave the profile diverged instead, and `dotta sync --diverged merge` (or `rebase`) merges them where they touch different lines.

After a pull, `sync` lists what it did to each profile's files — added, updated, reassigned to another profile, overridden by another profile's file, removed or deleted (see [Removing Files](#removing-files)) — and names `dotta apply` for as long as it has work to do.

## Removing Files

```bash
# Stop tracking a file; it stays on disk
dotta remove global ~/.bashrc

# Stop tracking a directory; its files stay on disk
dotta remove global ~/.config/nvim

# Delete a file and every machine's unchanged copy
rm ~/.bashrc
dotta update

# Delete an entire profile; no file is deleted from disk
dotta remove test --delete-profile

# Preview removal
dotta remove global ~/.bashrc --dry-run
```

`dotta remove` stops tracking a path: it stays on disk, on every machine. To delete a file instead, delete it and run `dotta update`: every machine's next `dotta apply` deletes its unchanged copy, or lands another enabled profile's file where one claims the path. A machine where the file was changed keeps it until `dotta apply --force <path>`.

A file removed from a directory the profile tracks shows up again as a new file; `dotta ignore <profile> --add <pattern>` keeps it out.
