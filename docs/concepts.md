# Concepts

This document explains the core ideas behind dotta's design.

## Profile-Based Architecture

A **profile** is a Git orphan branch containing configuration files. Each profile has its own independent commit history and can be enabled or disabled on any machine.

Typical profiles map to OS, role, or host:

```
global              # Base configuration (all systems)
darwin              # macOS base settings
darwin/work         # macOS work-specific settings
darwin/personal     # macOS personal overrides
freebsd/base        # FreeBSD base settings
linux/server        # Linux server-specific settings
hosts/laptop        # Per-machine overrides
hosts/laptop/vpn    # Machine-specific variants
```

Profiles support **hierarchical organization** for both OS-specific and host-specific configurations. Profiles are applied in **layered order**, with later-enabled profiles overriding earlier ones. The order is this machine's: `enable` appends, `reorder` moves, and `clone` seeds it by the layering convention:

1. `global` - Universal base configuration
2. `<os>` - OS base profile (darwin, linux, freebsd)
3. `<os>/<variant>` - OS sub-profiles (sorted alphabetically)
4. `hosts/<hostname>` - Host base profile
5. `hosts/<hostname>/<variant>` - Host sub-profiles (sorted alphabetically)

See [Profiles](profiles.md) for the full profile management guide.

## How Files Are Stored

A profile branch stores every file under a path that begins with `home/`, `root/` or `custom/`. That first part says which directory on this machine the rest of the path hangs from:

```
home/.bashrc                  → deploys to $HOME/.bashrc
home/.config/fish/config.fish → deploys to $HOME/.config/fish/config.fish
root/etc/hosts                → deploys to /etc/hosts
custom/etc/nginx.conf         → deploys to <this profile's target>/etc/nginx.conf
```

These names travel with the profile. Each machine supplies its home directory and each profile's [target](profiles.md#targets); `root/` paths stay absolute. A profile needs a target to deploy its `custom/` paths.

### Where a File Goes

**An added pathname keeps its stored name.** Later captures update that entry; setting a target does not rename it. By default, new files are named relative to the closest root: your home, the profile's target, or `/`.

```bash
dotta add web ~/jail/etc/x                    # no target yet → home/jail/etc/x
dotta add web --target ~/jail ~/jail/etc/y    # sets one, and → custom/etc/y
dotta add web ~/jail/etc/z                    # saved target → custom/etc/z
```

`x` keeps its `home/` name. The saved target gives `y` and `z` their `custom/` names.

**Adding a directory gives its name to new children:**

```bash
dotta add web --force home/jail/etc   # new children use home/jail/etc/...
```

Existing children keep their names. A nested home or target starts fresh, unless you've explicitly named its directory. `update --include-new` uses the same naming rules for files it discovers.

Use `add --force` to update an existing entry. To give the same pathname another stored name, remove its entry first.

Each profile chooses its own names. For example, `web` can store `~/jail/etc/x` as `custom/etc/x` while `global` stores it as `home/jail/etc/x`. Because both deploy to the same pathname, [profile precedence](profiles.md#layering-and-precedence) decides which one wins.

Each profile also maintains a `.dotta/metadata.json` file recording the permissions of every path it manages, and the owner of `root/` and `custom/` paths owned by someone other than you. A path with no owner recorded deploys as whoever runs `dotta`, so your own files need none — except when you run as root, where every one of those paths records its owner instead. Paths under `home/` never record an owner and never report one in `dotta status`: that is your own home directory on every machine. Metadata is captured during `add`/`update` and restored during `apply`.

### Spellings and Symlinks

Dotta treats symlinks as path components. `home/.config/app.conf` keeps that name even if `~/.config` points to `~/dotfiles/config`. File access follows the link; the pathname keeps `.config`. Adding the link itself stores a symlink, while naming your home or target root enters its contents.

Use the home or target spelling dotta knows, or a stored name such as `home/.config/app.conf`. Another spelling of the same file is a different path to dotta, even within one profile. Directory walks keep the pathnames they encounter, and profiles layer only where their destination pathnames match.

Relative paths start at your working directory. `..` removes the preceding path component: `~/link/../x` means `~/x`.

## Directories

Dotta remembers two kinds of directory, and treats them very differently.

**A directory you added** — `dotta add p ~/.config/nvim` — is one the profile manages in its own right. Dotta creates it even when it would be empty, and restores its permissions on `apply` (its owner too, under `root/` and `custom/`). It reports the directory in `dotta status` when it drifts, and looks inside it for new files under `dotta update --include-new`.

**A directory dotta passed through** on its way to a file you added is just a recipe for re-creating it. When dotta has to make that directory to put a file in it, it uses the permissions it saw at the time; a directory that already exists is never touched, never checked and never searched. And if part of the path was a symlink when the file was added, dotta records nothing for that component at all — a symlinked config directory is left alone, and dotta writes straight through it.

Dotta only revisits any of this when asked. Adding or updating a file refreshes the directories above it, and pointing `dotta update` at a directory — `dotta update ~/.config` — refreshes everything beneath it. That is also the fix when things move. Swap a passed-through directory for a symlink and `apply` refuses to write through it (`~/.config/nvim is not a directory`); `dotta update <dir>` drops the stale expectation, and the next `apply` trusts the arrangement on disk.

## Repository Structure

```
<store>/                   # a bare Git repository, declared dotta's own in its config
├── HEAD                   # git's, unborn, never read by dotta
├── refs/heads/
│   ├── global             # Profile branch
│   ├── darwin             # Profile branch
│   └── hosts/laptop       # Profile branch — one branch per profile, nothing else
├── refs/dotta/
│   ├── epoch              # encryption parameters (synced across machines)
│   └── baseline           # the baseline .dottaignore (this machine's)
└── dotta.db               # the record
```

Nothing is ever checked out. Every command reads the branches and writes commits to them, and the store is a bare repository: `git status` has nothing to say in it, and `HEAD` names an unborn branch dotta never reads. To look at a profile with other tools: `dotta git worktree add <dir> <profile>`. What makes a directory dotta's store is a line `init` and `clone` write into its config: `dotta.store = true`. Without it, every command refuses the directory. `dotta init` will take over an empty bare repository, but refuses one with a working tree or a history it did not write.

## The View and the Record

Dotta stores only what it cannot work out for itself.

What *should* be at each path, and from which profile, is **the view**. Dotta rebuilds it on every command from the branches, the enabled profiles, and where this machine keeps the home directory and each profile's target. What dotta *did* at a path — **the record** — is the one thing it cannot recompute, so that is the one thing it keeps, in the store's `dotta.db`.

The architecture mirrors Git's three-tree model:

```
Git Branches (Source of Truth)  ×  enabled profiles  ×  this machine's directories
     ↓  computed at every run, never stored
The View (one entry per managed path, precedence resolved)
     ↓  joined with
The Record (what dotta deployed, confirmed or observed at each path)
     ↓
Workspace (the comparison, made when the command runs)
     ↓
Filesystem (Live System)
```

**The view** -- which paths are managed, and what belongs at each one: the contents, whether it is a file or a directory or a link, the permissions, the owner, whether it is encrypted. Precedence is already settled here, so there is one entry per path and a later profile has won any it shares. The view is never out of date, because nothing stores it — every command builds it fresh from the branches.

**The record** -- for each managed path, what dotta last confirmed was on disk, whether dotta put it there, and when it first saw it. A path dotta deployed or captured is *owned*; one it merely found on disk is *observed*. When a path stops being managed, dotta removes an owned copy and leaves an observed one alone.

**Workspace** -- what dotta finds when it compares the view against the actual filesystem, with the record saying what it last confirmed. This is what `dotta status` reports, and it is worked out when the command runs, so nothing it decides is out of date.

**Apply** -- walks the view and compares each path against disk, deploying only what actually changed: contents, permissions, owner, encryption. It then removes or releases the leftovers according to the record, and writes the record for what it did.

This design gives:

- **Fast status checks** -- dotta looks each path up directly, and skips reading a file's contents when nothing has touched it since dotta last checked
- **Fresh comparisons** -- each command reads the current Git state and filesystem
- **Explicit scope** -- `dotta status --full` shows exactly which paths are managed and by which profile
- **Nothing to keep in sync** -- the view has no writer at all, and the record is written only by the command that deployed, captured or observed the path
