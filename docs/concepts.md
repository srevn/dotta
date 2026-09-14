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

The stored path travels with the repository. The directory it hangs from belongs to the machine: `home/` is the home directory and `root/` is `/`, the same for every profile, while `custom/` is the one directory *this* profile is pointed at on this machine — its **target**, which each machine chooses for itself (see [Targets](profiles.md#targets)). Without a target, a profile has nowhere to put `custom/` files here, and one profile's target means nothing to another profile.

### Where a File Goes

Dotta uses the first of these rules that applies:

1. **A file the profile already has stays where it is.** Giving a profile a target later never moves what it already stores.
2. Otherwise the file goes under **the closest directory you have added to the profile** — after `dotta add web home/jail/etc`, everything new inside it is stored under `home/jail/etc/...`.
3. Otherwise it goes under **the directory it actually sits in** — the profile's target if it is inside one, else the home directory, else `/`.

`dotta update` puts a newly found file exactly where `dotta add` would have put it.

Each profile decides for itself, so two profiles can store one file in two different places:

```bash
dotta add web --target ~/jail ~/jail/etc/x   # web:    custom/etc/x
dotta add global ~/jail/etc/x                # global: home/jail/etc/x
```

Which of them actually deploys the file is a question of precedence, not of storage — see [Layering and Precedence](profiles.md#layering-and-precedence).

A profile stores a given file in **one** place. Ask it to store the same file somewhere else and dotta refuses, shows where the file already lives, and names the two commands that settle it: `dotta add --force` to re-capture it where it is, or `dotta remove` to give that place up first.

By rule 3, a file inside the profile's target is stored under `custom/`, with or without `--target` on the command:

```bash
dotta add web ~/jail/etc/x                    # no target yet → home/jail/etc/x
dotta add web --target ~/jail ~/jail/etc/y    # sets one, and → custom/etc/y
dotta add web ~/jail/etc/z                    # inside it too → custom/etc/z
```

`x` was stored before the target existed, so rule 1 leaves it exactly where it is.

To settle a whole directory one way, add the directory itself:

```bash
dotta add web home/jail/etc     # everything new inside it is home/jail/etc/...
```

Files already stored stay where they are; only new ones follow the directory. (If the directory already holds files the profile has, dotta stops and asks for `--force`.)

Each profile also maintains a `.dotta/metadata.json` file recording the permissions of every path it manages, and the owner of `root/` and `custom/` paths that belong to someone else. A path the invoker owns needs no owner recorded — every machine reads that absence as "whoever is running dotta". Metadata is captured during `add`/`update` and restored during `apply`.

### Spellings and Symlinks

A path is keyed by the spelling it was given: your home as `$HOME` spells it, `/`, and a target as you gave it to `--target`. A symlink in a path is part of the path — dotta never reads through one, and a `..` after a link pops the link's spelling, not the directory it reaches. A working directory your shell did not spell (`sudo`, `cron`) is read back under your home. A path dotta walks is spelled the way it walked there. Two profiles that reach one file through two spellings are two paths, both deployed; dotta never unlinks or re-offers a file it manages under another spelling, and a filesystem that folds case or Unicode normalization is read the same way. A profile's target keeps the spelling you bound it with — `dotta profile enable --target` with another spelling of the same directory says so and keeps the row — and `profile disable` tells you that spelling back.

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
- **No stale decisions** -- always converges to current Git and current filesystem reality
- **Explicit scope** -- `dotta status --full` shows exactly which paths are managed and by which profile
- **Nothing to keep in sync** -- the view has no writer at all, and the record is written only by the command that deployed, captured or observed the path
