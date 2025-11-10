# dotta

Declarative, Git-based configuration management for heterogeneous Unix estates.

## Overview

Manage a single repository with independent, versioned profiles across laptops, servers, workstations and containers. Deploy actual files with correct ownership and atomic rollbacks, optional transparent encryption, and a bidirectional workflow that lets you edit in place.

## How It Works

### Repository Structure

```
.git/
├── refs/heads/
│   ├── dotta-worktree     # Empty branch (worktree anchor)
│   ├── global             # Base configuration
│   ├── darwin             # macOS-specific
│   ├── linux              # Linux-specific
│   └── hosts/laptop       # Host-specific
└── dotta.db               # State database (manifest + metadata)
```

### Virtual Working Directory with Runtime Convergence

Dotta uses a **Virtual Working Directory** (VWD) that caches expected state derived from Git and relies on **runtime convergence** to determine what needs deployment.

**The Three-Tree Model**: Dotta mirrors Git's layered approach, but replaces Git's index with a virtual manifest representing complete desired state.

```
Git Branches (Source of Truth)
     ↓
Manifest (Virtual Working Directory)
     ↓
Workspace (Runtime Analysis)
     ↓
Filesystem (Live System)
```

**Workflow**:

1. **Profile enable** → Reads Git branches, populates VWD with expected state (scope + git_oid + blob_oid + metadata) and with precedence resolved
2. **Status** → Reads VWD scope, loads workspace to analyze runtime divergence (compares VWD expected state vs filesystem)
3. **Apply** → Iterates VWD entries, checks workspace divergence at runtime, deploys only divergent files, updates lifecycle timestamps

**Manifest Database** (in `.git/dotta.db`):
- **Scope authority**: Defines which files are managed (based on enabled profiles)
- **Expected state cache**: Stores `git_oid`, `blob_oid`, `type`, `mode`, `owner`, `group`, `encrypted` from Git
  - Enables fast comparison without Git tree walks
  - Precedence already resolved (which profile wins for each path)
- **Lifecycle tracking**: `deployed_at` timestamp (0 = never deployed, >0 = known to dotta)
- **Eager Consistency**: Updated immediately when profiles/files change
- **Indexed**: SQLite indexes on profile and storage_path for instant queries

### File Storage Model

Files are stored with **location prefixes** (`home/`, `root/`) in **isolated Git orphan branches** (one per profile), then **deployed** to their filesystem locations on demand. Each profile maintains independent version history.

This provides:

- **Multi-machine flexibility** - Profiles version independently; no forced synchronization
- **System-level configs** - Root-owned files deployed with correct ownership/permissions
- **Security by default** - Pattern-based transparent encryption for secrets
- **Strong safety guarantees** - Atomic deployments with state tracking prevent data loss

```
Profile branch "darwin":
  home/.bashrc                       → deploys to: $HOME/.bashrc
  home/.config/fish/config.fish      → deploys to: $HOME/.config/fish/config.fish
  root/etc/apcupsd/apcupsd.conf      → deploys to: /etc/apcupsd/apcupsd.conf
  .dotta/metadata.json               → metadata for permissions/ownership
```

**Prefix rules:**
- Path starts with `$HOME` → stored as `home/<relative_path>`
- Absolute path → stored as `root/<relative_path>`
- Custom prefix path → stored as `custom/<relative_path>`

### Main Worktree

The repository's main worktree always points to `dotta-worktree` (an empty branch). This prevents Git status pollution and keeps your repository clean. All profile operations use temporary worktrees.

### Profile Resolution & Layering

Profile resolution follows a strict priority order:

1. **Explicit CLI** (`-p/--profile flags`) - Temporary override for testing
2. **State file** (`profiles` array in `.git/dotta.db`) - Persistent management via `dotta profile enable`

Enabled profiles are managed exclusively through `dotta profile enable/disable/reorder` commands. The state file is the single source of truth for which profiles are enabled on each machine.

When profiles are applied, later profiles override earlier ones following this precedence:

1. `global` - Base configuration
2. `<os>` - OS base profile (e.g., `darwin`)
3. `<os>/<variant>` - OS sub-profiles (e.g., `darwin/work`, alphabetically sorted)
4. `hosts/<hostname>` - Host base profile
5. `hosts/<hostname>/<variant>` - Host sub-profiles (e.g., `hosts/laptop/vpn`, alphabetically sorted)

Example layering for a macOS laptop with work and vpn configs:
- `dotta apply` → `global` → `darwin/base` → `darwin/work` → `hosts/laptop/vpn`
- Files from later profiles override files from earlier profiles

## Key Features

### 1. Profile-Based Architecture

Dotta organizes configurations into Git orphan branches (profiles):

```
global              # Base configuration (all systems)
darwin              # macOS base settings
darwin/work         # macOS work-specific settings
darwin/personal     # macOS personal overrides
freebsd             # FreeBSD base settings
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

This enables:

- Shared base configuration across all machines
- OS-specific base settings with contextual variants
- Host-specific overrides with role-based variants
- Predictable layering with alphabetical sub-profile ordering

**Note:** Due to Git ref namespace limitations, you cannot have both a base profile and sub-profiles with the same prefix (e.g., `darwin` and `darwin/work` cannot coexist). Use either the base profile OR sub-profiles, not both. The same limitation applies to host profiles.

### 2. Profile Management with Explicit Staging

Dotta uses **explicit profile management** with **immediate staging** to provide safe, predictable control over which configurations are deployed on each machine:

- **Available Profiles**: Exist as local Git branches - can be inspected, not automatically deployed
- **Enabled Profiles**: Tracked in `.git/dotta.db` with files staged in manifest - participate in all operations (apply, update, sync, status)

```bash
# Enable profiles for this machine (shows preview of what needs deployment)
$ dotta profile enable global darwin
✓ Enabled 'global' (23 files in scope, 12 need deployment)
✓ Enabled 'darwin' (47 files in scope, 35 need deployment)
  5 files override lower precedence (global)

# View enabled vs available profiles
dotta profile list

# Status performs runtime divergence analysis
$ dotta status
Undeployed files (47 items):
  [undeployed] home/.bashrc (darwin)
  [undeployed] home/.vimrc (global)
  ... (45 more)

# Apply analyzes divergence and deploys only changed files
$ dotta apply
Analyzing files for convergence...
  47 files need deployment (divergent from Git)
  23 files already up-to-date (skipped)

Deploying 47 divergent files...
✓ Deployed 47 files

# Operations use enabled profiles
dotta apply   # Deploys: global, darwin
dotta status  # Checks: global, darwin (instant manifest lookup)
dotta sync    # Syncs: global, darwin
```

**Clone automatically enables** detected profiles: `global`, OS base and sub-profiles (`darwin`, `darwin/*`), and host base and sub-profiles (`hosts/<hostname>`, `hosts/<hostname>/*`).

**Virtual Working Directory with Runtime Convergence Benefits**:
- **Manifest caching**: Expected state pre-cached from Git (no redundant tree walks)
- **Runtime analysis**: Apply always uses current filesystem state (no stale cached decisions)
- **Explicit preview**: See exactly what enabling/disabling a profile will do before applying
- **Performance**: O(1) workspace divergence lookups
- **Safety**: Profile changes preview removals and fallbacks

### 3. Metadata Preservation

Dotta automatically preserves file metadata across machines:

- **File permissions** (mode) - captured during `add`, restored during `apply`
- **Ownership tracking** (for `root/` prefix files) - preserves user:group when running as root
- Stored in `.dotta/metadata.json` within each profile branch
- Cross-platform compatibility - permissions mapped appropriately per OS

Example workflow:
```bash
# On source machine (as root for system files)
dotta add --profile linux /etc/systemd/system/myservice.service

# On target machine
dotta apply  # Restores both content and permissions (0644, root:root)
```

### 4. Smart Deployment with VWD and Runtime Convergence

Dotta uses a **Virtual Working Directory** with **runtime convergence** for safe, efficient deployment:

- **VWD (Manifest)** - Caches expected state from Git (scope + git_oid + blob_oid + metadata)
  - Eliminates redundant Git tree walks
  - Precedence already resolved
  - Automatically updated when profiles or files change
- **Runtime convergence** - Apply analyzes current filesystem state at execution time
  - Workspace compares VWD expected state vs filesystem
  - Only deploys files with divergence (content, mode, ownership, encryption)
  - No stale cached decisions - always uses current reality
- **Lifecycle tracking** - `deployed_at` timestamp distinguishes never-deployed vs known files
- **Pre-flight checks** - Detects conflicts before making changes
- **Overlap detection** - Warns when files appear in multiple profiles
- **Efficient skipping** - O(1) workspace divergence lookups
- **Conflict resolution** - Clear error messages with `--force` override option

### 5. Automatic Synchronization

Dotta's `apply` command performs complete synchronization:

```bash
# Deploy new/updated files AND remove orphaned files
dotta apply

# Preview what would change
dotta apply --dry-run

# Advanced: apply without removing orphaned files
dotta apply --keep-orphans
```

### 6. Bidirectional Sync

Unlike many dotfile managers that only deploy *from* repository *to* filesystem, dotta supports the reverse:

```bash
# Update profiles with modified files from filesystem
dotta update

# Two-way sync with remote
dotta sync  # fetch + push/pull with conflict detection
```

### 7. Hook System

Run custom scripts at lifecycle points:

```bash
~/.config/dotta/hooks/
├── pre-apply       # Before deploying files
├── post-apply      # After deployment (reload services, etc.)
├── pre-add         # Before adding files
├── post-add        # After adding files
└── ...
```

### 8. Multi-Layered Ignore System

Fine-grained control over what gets tracked:

1. **CLI patterns** (`--exclude` flags) - Highest priority, operation-specific
2. **Repository `.dottaignore`** - Version-controlled, shared with team
3. **Profile-specific `.dottaignore`** - Extends baseline, can use `!` to override
4. **Config file patterns** - User-specific, not shared
5. **Source `.gitignore`** - Respects existing Git ignore files

```bash
# Edit shared ignore patterns
dotta ignore

# Edit profile-specific overrides
dotta ignore --profile darwin

# Quickly add a specific pattern to profile
dotta ignore --profile darwin --add 'somefile'

# Test if a path would be ignored
dotta ignore --test ~/.config/nvim/node_modules
```

### 9. File Encryption

Encrypt sensitive files at rest in Git using authenticated encryption:

```bash
# Enable encryption in config
[encryption]
enabled = true
auto_encrypt = [".ssh/id_*", ".gnupg/*", "*.key"]

# Explicitly encrypt specific files
dotta add --profile global ~/.ssh/id_rsa --encrypt

# Auto-encrypt based on patterns (config)
dotta add --profile global ~/.ssh/id_ed25519  # Encrypted automatically

# Override auto-encryption
dotta add --profile global ~/.aws/config --no-encrypt

# Manage encryption keys
dotta key set      # Set/cache passphrase for session
dotta key status   # Check encryption status and key cache
dotta key clear    # Clear cached passphrase
```

**Security Features:**
- **Deterministic AEAD** - SIV (Synthetic IV) construction for Git-friendly encryption
- **Path-bound encryption** - Files tied to specific storage paths (authenticated associated data)
- **Per-profile key isolation** - Each profile uses a derived encryption key
- **Passphrase-based key derivation** - No key files to manage (PBKDF2-based)
- **Persistent key caching** - Cache persists across commands (default: 1 hour, machine-bound)
- **Automatic decryption** - Transparent during `apply` and `show` operations

**Encryption Modes:**
1. **Explicit** - Use `--encrypt` flag to force encryption
2. **Auto-encrypt** - Configure patterns in `[encryption] auto_encrypt` (e.g., `"*.key"`, `".ssh/id_*"`)
3. **Override** - Use `--no-encrypt` to skip auto-encryption for specific files

Encrypted files are stored in Git with a magic header (`DOTTA`) and decrypted transparently during deployment. Master keys are cached at `~/.cache/dotta/session` (machine-bound, auto-expires) for seamless multi-command workflows.

### 10. Bootstrap System

Automate system setup with per-profile bootstrap scripts that run during initial configuration:

```bash
# Create/edit bootstrap script for a profile
dotta bootstrap --profile darwin --edit

# List bootstrap scripts across profiles
dotta bootstrap --list

# Run bootstrap scripts (auto-detected profiles)
dotta bootstrap

# Run for specific profiles with auto-confirmation
dotta bootstrap --profile global --profile darwin --yes

# Preview what would execute
dotta bootstrap --dry-run

# Continue even if a script fails
dotta bootstrap --continue-on-error
```

**Bootstrap scripts** are stored in `.bootstrap` within each profile branch and receive environment context:

- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_PROFILE` - Current profile being bootstrapped
- `DOTTA_PROFILES` - Space-separated list of all profiles
- `DOTTA_DRY_RUN` - Set to "1" during dry-run mode
- `HOME` - User home directory

**Integration with clone:**
```bash
# Clone prompts to run bootstrap if scripts detected
dotta clone git@github.com:user/dotfiles.git

# Auto-run bootstrap without prompt
dotta clone <url> --bootstrap

# Skip bootstrap entirely
dotta clone <url> --no-bootstrap

# After clone, apply profiles
dotta apply
```

**Use cases:**
- Install package managers (Homebrew, apt, yum)
- Install system dependencies
- Configure OS preferences (macOS defaults, systemd)
- Clone additional repositories
- Generate SSH keys or certificates
- Set up development environments

## Installation

### Prerequisites

- libgit2 1.5+
- libhydrogen (bundled) - For file encryption
- sqlite3 3.40+
- C11-compliant compiler (clang recommended)
- POSIX system (macOS, Linux, FreeBSD)

### Build from Source

```bash
# Clone repository
git clone https://github.com/srevn/dotta.git
cd dotta

# Check dependencies
make check-deps

# Build
make

# Install (optional)
sudo make install PREFIX=/usr/local

# Or use directly from bin/
./bin/dotta --version
```

### Build Targets

```bash
make              # Release build
make debug        # Debug build with sanitizers
make clean        # Remove build artifacts
make install      # Install to PREFIX (default: /usr/local)
make uninstall    # Remove installed files
```

## Configuration

Configuration file: `~/.config/dotta/config.toml`

### Essential Settings

```toml
[core]
repo_dir = "~/.local/share/dotta/repo"    # Repository location
strict_mode = false                       # Fail on validation errors
auto_detect_new_files = true              # Detect new files in tracked directories

[security]
confirm_destructive = true                # Prompt before overwrites
confirm_new_files = true                  # Prompt for new file detection

[sync]
auto_pull = true                          # Auto-pull when behind
diverged_strategy = "warn"                # warn, rebase, merge, ours, theirs

[ignore]
patterns = [                              # Personal ignore patterns
    ".DS_Store",
    "*.local",
]

[encryption]
enabled = false                           # Enable encryption feature (opt-in)
auto_encrypt = [                          # Patterns for automatic encryption
    ".ssh/id_*",                          # SSH private keys
    ".gnupg/*",                           # GPG keys
    "*.key",                              # Generic key files
    ".aws/credentials",                   # AWS credentials
]
session_timeout = 3600                    # Cache timeout in seconds (0=always prompt, -1=never expire)
opslimit = 10000                          # KDF CPU cost
```

### Environment Variables

```bash
DOTTA_REPO_DIR       # Override repo_dir
DOTTA_CONFIG_FILE    # Use different config file
DOTTA_EDITOR         # Editor for bootstrap/ignore (fallback: VISUAL → EDITOR → vi/nano)
```

## Advanced Features

### Custom Prefix (Containers/Jails/Chroots)

Deploy configuration files to arbitrary filesystem locations beyond `$HOME` and system root using custom prefixes:

```bash
# Use case: Container/jail configuration from host
mkdir -p /mnt/jails/web

# Add files with custom prefix (smart resolution - both forms work)
dotta add --profile jail/web --prefix /mnt/jails/web /mnt/jails/web/etc/nginx.conf
# Automatically resolves to /mnt/jails/web/etc/nginx.conf if exists
dotta add --profile jail/web --prefix /mnt/jails/web /etc/nginx.conf
# Both stored as: custom/etc/nginx.conf

# Enable profile with custom prefix (required for custom/ files)
dotta profile enable jail/web --prefix /mnt/jails/web
# Deploys to: /mnt/jails/web/etc/nginx.conf

# Files deployed to correct location
dotta apply
```

**Use cases:**
- Container/jail rootfs deployment from host
- Chroot environment configuration
- Mounted filesystem management (NFS, SMB)
- Alternative root hierarchies
- Multi-tenancy configuration

**Restrictions:**
- Custom prefix requires exactly one profile (cannot use with `--all` or multiple profiles)
- Profiles with `custom/` files require `--prefix` when enabling (error if omitted)
- Custom prefix must be absolute path to existing directory

### Custom Commit Messages

Configure commit message templates with variable substitution:

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

Variables: `{host}`, `{user}`, `{profile}`, `{action}`, `{count}`, `{files}`, `{datetime}`, `{target_commit}`

### Remote Profile Tracking

Track which profiles exist on remote without downloading:

```bash
dotta profile list --remote      # Show available remote profiles
dotta profile fetch linux        # Download without activating
dotta profile enable linux       # Enable it
dotta status --remote            # Check sync state
```

### Profile-Specific Ignore Patterns

Each profile can extend or override baseline ignore patterns:

```bash
# Baseline .dottaignore (applies to all profiles)
*.log
.cache/

# Profile darwin/.dottaignore (extends baseline)
!debug.log           # Override: keep debug.log in darwin profile
.DS_Store            # Additional: ignore .DS_Store in darwin
```

### Hierarchical Profile Organization

Organize profiles hierarchically for both OS-specific and host-specific configurations:

```
# OS-specific hierarchical profiles
darwin              # macOS base (or use sub-profiles only)
darwin/work         # Work-specific macOS settings
darwin/personal     # Personal macOS overrides

linux               # Linux base (or use sub-profiles only)
linux/desktop       # Desktop environment configs
linux/server        # Server-specific settings

# Host-specific hierarchical profiles
hosts/laptop        # Laptop base (or use sub-profiles only)
hosts/laptop/office # Office network configs
hosts/laptop/vpn    # VPN-specific settings

hosts/desktop        # Desktop base
hosts/desktop/gaming # Gaming-specific configs
```

**Hierarchical rules:**
- Sub-profiles are limited to one level deep (`darwin/work` ✓, `darwin/work/client` ✗)
- Multiple sub-profiles are applied in alphabetical order
- Git limitation: Cannot have both base AND sub-profiles (see note above)

### Bootstrap Scripts

Bootstrap scripts automate system setup when cloning configurations to a new machine. Each profile can have its own bootstrap script in `.bootstrap`:

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "Running darwin bootstrap..."

# Install Homebrew if not present
if ! command -v brew >/dev/null 2>&1; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install essential packages
brew install git fish neovim tmux

# Set macOS preferences
defaults write NSGlobalDomain ApplePressAndHoldEnabled -bool false
defaults write com.apple.dock autohide -bool true

echo "darwin bootstrap complete!"
```

**Environment variables available in scripts:**
- `$DOTTA_REPO_DIR` - Repository location
- `$DOTTA_PROFILE` - Current profile name
- `$DOTTA_PROFILES` - All profiles being bootstrapped
- `$DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Execution order:** Bootstrap scripts run in profile layering order (global → OS → host), allowing base scripts to install dependencies for host-specific scripts.

### File-Level Revert

Revert individual files to previous versions:

```bash
# Show file history
dotta list global <file>

# Revert to specific commit
dotta revert ~/.bashrc@abc123

# Revert with commit
dotta revert --commit -m "Fix config" ~/.bashrc@HEAD~1
```

## Performance

Dotta is designed for efficiency and scalability:

- **Virtual Working Directory** - Pre-caches expected state from Git (eliminates redundant tree walks)
- **Streaming tree walks** - Uses callback-based iteration; never loads entire repository into memory
- **Size-first blob comparison** - Checks file size before content (short-circuits on mismatch, uses mmap when needed)
- **Three-tier deployment optimization** - OID hash comparison → profile version check → content comparison (only if needed)
- **Incremental operations** - `update` processes only diverged files; `apply` skips clean files with O(1) lookups
- **Content caching** - Preflight safety checks populate cache reused during deployment (avoids redundant decryption)
- **O(1) lookups** - Hashmaps throughout for state, metadata, manifest, workspace, and file index operations
- **Load-once, query-many** - State and metadata loaded once per operation, queried via hashmap
- **Indexed manifest queries** - SQLite indexes on profile and storage_path for instant lookups

Operations scale linearly with tracked files, not repository history depth.

## Acknowledgments

Built with libgit2 for robust Git operations. Inspired by YADM's simplicity and Chezmoi's declarative approach, but designed from the ground up for the orphan branch model.
