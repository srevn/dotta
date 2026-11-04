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

### A Machine That Already Has Its Own Files

When you clone onto a machine or enable a profile, a file already there that matches the profile is simply taken over, and one holding an older version of the profile's is brought up to date by `dotta apply`. A file whose contents the profile has never had is yours to decide: `dotta status` lists it under Unconfirmed paths, and `dotta apply` leaves it alone until you choose.

```bash
dotta diff ~/.bashrc                     # Compare the two versions
dotta apply --force ~/.bashrc            # Take the profile's version (this machine's is lost)
dotta update --force ~/.bashrc           # Make this machine's version the profile's, for every machine
dotta add hosts/$(hostname) ~/.bashrc    # Keep this machine's version on this machine only
```

The last creates a profile of this machine's own, [layered](profiles.md#layering-and-precedence) above the others, the first time you use it. Only this machine uses it, but `dotta sync` sends it to your remote like any other profile. Name the files you mean: with no path, `dotta update --force` takes every file `dotta status` lists this way — on a machine you have just cloned onto, all of its own — and commits each into the profile `dotta status` shows it from, which every machine using that profile then gets. To stop managing the file instead, `dotta remove <profile> <path>` stops tracking it on every machine and leaves it on disk.

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

# Keep your version of a file status lists under Conflicts or Unconfirmed paths
dotta update --force ~/.bashrc

# Custom commit message
dotta update -m "Update shell config"
```

A plain `update` leaves alone a file that changed both on disk and in its profile -- a pull over an edit you had not committed -- and one dotta has not confirmed, such as a file this machine already had: `dotta status` lists them under Conflicts and Unconfirmed paths. `dotta apply --force <path>` takes the profile's version; `dotta update --force <path>` keeps yours, its permissions and owner with it, in the profile `dotta status` names. It never commits a file only the profile changed -- `dotta apply` brings that one to you -- nor one that became a directory or the other way round.

To delete a file everywhere, delete it and run `dotta update`: see [Removing Files](#removing-files).

### Naming Paths

A path holding `*`, `?` or `[` is also a pattern; a `\` before each `\`, `*`, `?` and `[` names that one path, and a leading `!` leaves out what it names:

```bash
dotta update '~/.config/*' '!~/.config/secret'
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

`dotta status` groups paths by what to do about them and tags each one -- `[undeployed]`, `[clean]`, `[modified]`, `[deleted]`, `[orphaned]` and more. A path can carry several tags at once (`[orphaned] [relocated]`), and where a tag needs explaining, status prints a short legend under the group. `dotta status --full` lists every managed path with its state and the profile it comes from.

`dotta status --raw` prints the same items for a program. Each item is eight fields a TAB apart, and ends in a NUL rather than a newline, since a file name can hold a newline; a field with nothing to say holds `-`. To read it yourself, `dotta status --raw | tr '\0' '\n'`.

| # | Field | What it holds |
|---|-------|---------------|
| 1 | tags | the item's tags as status shows them, without brackets, comma-joined: `orphaned,relocated` |
| 2 | section | the group status lists it under: `conflicts`, `unconfirmed`, `squatted`, `displaced`, `unverifiable`, `uncommitted`, `reassigned`, `undeployed`, `new`, `overridden`, `orphaned`, `released` -- or `-` for an unchanged path, which `--full` lists |
| 3 | `active`, `orphan` or `scan` | `active`: an enabled profile claims the path; `orphan`: dotta remembers it, but no enabled profile claims it any more (a disabled profile's, say); `scan`: the search for new files found it -- a new file in a tracked directory, or a directory it could not read |
| 4 | `file` or `directory` | a symlink is a `file` |
| 5 | profile | the profile the path belongs to |
| 6 | other profile | the second profile status names beside the path: the one it is reassigned from, or the one whose file stands above an overridden copy |
| 7 | reason | the reason status gives beside an orphan: `deleted`, `removed`, `not-in-history`, `no-branch`, `never-deployed` |
| 8 | path | the full path, byte for byte, a directory's without a trailing `/` |

Items come in the order status lists them, group by group, with the unchanged paths last. One path can be listed twice, under two values of field 3 -- a tracked directory you cannot read, for one -- so a script tells items apart by field 3 and the path together. The remote's state is not included, and a program that stops reading early (`head`, `fzf`) is no failure.

A script hands a path back escaped as [Naming Paths](#naming-paths) says:

```bash
# Diff exactly the files status lists under Uncommitted changes
paths=()
while IFS=$'\t' read -r -d '' _ section _ kind _ _ _ path; do
    [[ $section == uncommitted && $kind == file ]] || continue
    if [[ $path == *[*?[]* ]]; then   # a pattern too: escape it to name just this path
        path=${path//\\/\\\\} path=${path//\*/\\*} path=${path//\?/\\?} path=${path//\[/\\[}
        [[ $path == *' ' ]] && path="${path% }\\ "
    fi
    paths+=("$path")
done < <(dotta status --raw)
(( ${#paths[@]} )) && dotta diff "${paths[@]}"
```

**Remote state** -- `dotta status` and `dotta list --remote` say where each profile stands against its remote, a glyph beside the words: `= up-to-date`, `↑ 2 commits ahead`, `↓ 1 commit behind`, `↕ diverged (1 ahead, 2 behind)`, `• no remote branch` (never pushed there), `− deleted on the remote` (another machine deleted the profile; `− deleted on the remote, 2 commits ahead` where commits made here never reached it), `↻ recreated on the remote` (another machine deleted the profile and created it again; `, 2 commits ahead` likewise). `dotta status` asks the remote first. `dotta list --remote` and `dotta status --no-fetch` ask it nothing, and neither does a `dotta status` that cannot reach it: their section is then titled `Remote sync status (origin, as last seen)`, and shows each profile as it stood at the last fetch, so a profile deleted or recreated on the remote since shows there as it last stood. What `dotta sync` does with each is in [Syncing with Remote](#syncing-with-remote).

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

# Only the patch, as git prints it, for a pager or a program
dotta diff --raw --downstream | delta
```

Each listed path opens with a status line: what differs, then what the previewed verb does about it, the `--force` that does it where the verb leaves the choice to you, or why it skips the path -- `modified locally (would be committed by update)`, `changed in Git (would be deployed by apply)`, `changed in Git and on disk (update --force <path> keeps disk's)`, `a different kind stands on disk (update skips it)`. A directory is listed as a file is, for its mode, its ownership or its kind. Beneath the line, differing bytes draw a hunk, and a differing kind names both kinds. `dotta diff` compares the paths your enabled profiles claim: new files in tracked directories are listed by `dotta update --dry-run`, and the copies apply would remove by `dotta apply --dry-run`.

`dotta diff --raw` prints the patch alone; anything else dotta says goes to stderr, a path it has no patch for among it. Compared with the file on disk, a patch shows an encrypted file's plaintext, names each file mode `100644`, and names an encrypted one by its plaintext's hash; between two commits, an encrypted file reads as binary.

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
dotta list global home/.bashrc -v  # Each commit's full id, date and title
```

Through a merge, a file's history — and its last commit at level 2 — follows the side the merge took the file from, as `git log -- <file>` does: the merge is listed only where it composed the file anew, and a side whose version the merge discarded is no part of it.

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

A merge's header names its parents, as `git show` does, and its diff is against the first — what the merge brought into that line, its stat line reading "changed from" that parent.

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

# Preview what would happen, conflicts included
dotta sync --dry-run

# Pull and merge, push nothing
dotta sync --no-push

# Where both machines changed the same thing, keep the remote's side
dotta sync --conflicts theirs
```

**Typical workflow:**

```bash
dotta update    # Commit local changes
dotta sync      # Push/pull with remote
```

`sync` moves commits and nothing else: it neither reads nor changes the files on this machine, so an edit not yet committed with `dotta update` stays here. A file you edited that a pull also changed then reads as changed in Git and on disk, for you to decide: `dotta apply --force <path>` keeps the pulled version, `dotta update --force <path>` keeps yours. Committed first, the two edits are merged by the sync instead.

Where both machines committed to a profile, `dotta sync` merges the two and pushes the merge: it combines what each changed wherever they changed different files, lines or permissions. Where both changed the same thing differently, the profile is not merged: the sync lists each conflict beneath it -- `home/.config/f (mode: 0640 ours, 0600 theirs)`, `home/.config/r (content)`, or `home/.config/r (content: file ours, none theirs)` where the remote deleted a file this machine changed -- and `--conflicts ours` keeps this machine's side of every one, `--conflicts theirs` the remote's: of a file both changed, that side's version, or its deletion. A change only one machine made, a permission or another file, stays either way, and the side not kept stays in the profile's history.

A profile another machine deleted is deleted locally too, and one it recreated replaces the local one — unless this machine holds commits the remote never had: then the profile is kept as it stands, and the sync says how to keep those commits or let them go. An enabled profile with no local branch gets it back from the remote at the next sync; where the remote has none either, the sync says so until `dotta profile disable` drops it.

`dotta remote set-url origin <url>` points the remote at another URL, and the next sync pushes every profile the new URL lacks. Sync before changing it: a profile another machine deleted or recreated since this machine's last sync would otherwise be pushed back, or merged with its old history.

After a pull, `sync` lists what it did to each profile's files — added, updated, reassigned to another profile, overridden by another profile's file, removed or deleted (see [Removing Files](#removing-files)); `dotta apply` lands what it brought.

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

That works when the copy you deleted was the profile's latest version. If the profile has moved on since you last applied, or dotta never saw your copy match it, the deletion doesn't count: `update` leaves the profile as it is, and `dotta apply` brings the file back.

A file removed from a directory the profile tracks shows up again as a new file; `dotta ignore <profile> --add <pattern>` keeps it out.

`dotta remove <profile> --delete-profile` deletes the whole profile, locally and on the remote; no file is deleted from disk. If another machine pushed to the profile since this machine last fetched it, the deletion is refused and nothing changes: run `dotta profile fetch <profile>`, then delete again. If the remote can't be reached, the profile is deleted locally and dotta prints the command that deletes it on the remote once it can.
