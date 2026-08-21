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

Profiles support **hierarchical organization** for both OS-specific and host-specific configurations. Profiles are applied in **layered order**, with later profiles overriding earlier ones:

1. `global` - Universal base configuration
2. `<os>` - OS base profile (darwin, linux, freebsd)
3. `<os>/<variant>` - OS sub-profiles (sorted alphabetically)
4. `hosts/<hostname>` - Host base profile
5. `hosts/<hostname>/<variant>` - Host sub-profiles (sorted alphabetically)

See [Profiles](profiles.md) for the full profile management guide.

## File Storage

Files are stored with **location prefixes** inside profile branches:

```
home/.bashrc                  → deploys to $HOME/.bashrc
home/.config/fish/config.fish → deploys to $HOME/.config/fish/config.fish
root/etc/hosts                → deploys to /etc/hosts
custom/etc/nginx.conf         → deploys to <custom_prefix>/etc/nginx.conf
```

**Prefix rules:**
- Paths under `$HOME` are stored as `home/<relative_path>`
- Absolute paths outside `$HOME` are stored as `root/<relative_path>`
- Paths under a custom prefix are stored as `custom/<relative_path>`

Each profile also maintains a `.dotta/metadata.json` file that tracks file permissions (mode) and ownership (user/group for `root/` files). Metadata is captured during `add`/`update` and restored during `apply`.

## Repository Structure

```
.git/
├── refs/heads/
│   ├── dotta-worktree     # Empty branch (worktree anchor)
│   ├── global             # Profile branch
│   ├── darwin             # Profile branch
│   └── hosts/laptop       # Profile branch
└── dotta.db               # State database (manifest + metadata)
```

The main worktree always points to `dotta-worktree`, an empty branch. This prevents Git status pollution. All profile operations use temporary worktrees internally.

## The view and the record

Dotta stores only what it cannot recompute. What *should* stand at each path, and from which profile, is a pure function of Git, the enabled profiles and the machine's mount table — **the view** — and is computed from Git every time a command runs. What dotta *did* at a path — **the record** — is dotta's own and is the only per-path state it keeps, in `.git/dotta.db`.

The architecture mirrors Git's three-tree model:

```
Git Branches (Source of Truth)  ×  enabled profiles  ×  mount table
     ↓  computed at every run, never stored
The View (one row per managed path, precedence resolved)
     ↓  joined with
The Record (what dotta deployed, confirmed or observed at each path)
     ↓
Workspace (Runtime Analysis)
     ↓
Filesystem (Live System)
```

**The view** -- the single source of truth for which paths are managed and what is expected there (content, file type, mode, ownership, encryption flag), with precedence already resolved: later enabled profiles win, one row per path. It is never stale, because nothing caches it — every command builds it from the current branches.

**The record** -- for each managed path, the content dotta last confirmed on disk, whether dotta put it there (the *ownership* timestamp), and when it first saw it. A path dotta deployed or captured is *owned*; one that was merely found on disk is *observed*. On scope exit an owned copy is pruned and an observed one is left alone.

**Workspace** -- runtime divergence analysis that compares the view against the actual filesystem, with the record as the reference for what dotta last confirmed. This comparison happens at execution time, so decisions are never stale.

**Apply** -- iterates the view's rows, checks workspace divergence for each, deploys only what actually changed (content, mode, ownership, encryption), prunes or releases orphans according to the record, and then writes the record for what it did.

This design gives:
- **Fast status checks** -- O(1) per-file divergence lookups via hashmap, and a stat fast path that skips content comparison for files whose record still matches
- **No stale decisions** -- always converges to current Git and current filesystem reality
- **Explicit scope** -- `dotta status --full` shows exactly which paths are managed and by which profile
- **One writer per fact** -- the view has none; the record is written only by the command that deployed, captured or observed the path
