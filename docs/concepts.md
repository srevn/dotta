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

## Virtual Working Directory

Dotta uses a **Virtual Working Directory** (VWD) to track deployment state. The VWD is a manifest stored in `.git/dotta.db` that represents the composed, layered state of all enabled profiles.

The architecture mirrors Git's three-tree model:

```
Git Branches (Source of Truth)
     ↓
Manifest (Virtual Working Directory)
     ↓
Workspace (Runtime Analysis)
     ↓
Filesystem (Live System)
```

**Manifest** -- the single source of truth for which files are managed. It caches expected state from Git (OIDs, content hashes, file type, mode, ownership, encryption flag) with precedence already resolved. It is updated eagerly: any change to profiles or files updates the manifest immediately, not lazily at apply time.

**Workspace** -- runtime divergence analysis that compares the manifest's expected state against the actual filesystem. This comparison happens at execution time, so decisions are never stale.

**Apply** -- iterates manifest entries, checks workspace divergence for each file, and deploys only files that have actually changed (content, mode, ownership, encryption). After deployment, lifecycle timestamps are updated.

This design gives:
- **Fast status checks** -- O(1) per-file divergence lookups via hashmap
- **No stale decisions** -- always converges to current filesystem reality
- **Explicit scope** -- the manifest shows exactly which files are managed
- **Efficient deploys** -- pre-cached expected state eliminates redundant Git tree walks
