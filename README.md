# dotta

A declarative, profile-based dotfile manager built on Git that uses orphan branches to manage configurations across multiple machines and operating systems.

### Core Principle

Files are stored with **location prefixes** (`home/`, `root/`) in isolated profile branches, then deployed to their actual filesystem locations on demand. This provides:

- **Clean separation** between different configurations
- **No Git pollution** in your home directory
- **Profile layering** for shared and machine-specific settings
- **Predictable deployment** with strong safety guarantees

## Key Features

### 1. Profile-Based Architecture

Dotta organizes configurations into Git orphan branches (profiles):

```
global              # Base configuration (all systems)
darwin              # macOS base settings
darwin/work         # macOS work-specific settings
darwin/personal     # macOS personal overrides
linux               # Linux base settings
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

### 2. Active Profile Management

Dotta uses **explicit active profile management** to provide safe, predictable control over which configurations are deployed on each machine:

- **Available Profiles**: Exist as local Git branches - can be inspected, not automatically deployed
- **Active Profiles**: Tracked in `.git/dotta.db` - participate in all operations (apply, update, sync, status)

```bash
# Select active profiles for this machine
dotta profile select global darwin

# View active vs available profiles
dotta profile list

# Operations use active profiles
dotta apply   # Deploys: global, darwin
dotta status  # Checks: global, darwin
dotta sync    # Syncs: global, darwin
```

**Clone automatically selects** detected profiles: `global`, OS base and sub-profiles (`darwin`, `darwin/*`), and host base and sub-profiles (`hosts/<hostname>`, `hosts/<hostname>/*`).

### 3. Metadata Preservation

Dotta automatically preserves file metadata across machines:

- **File permissions** (mode) - captured during `add`, restored during `apply`
- **Ownership tracking** (for `root/` prefix files) - preserves user:group when running as root
- Stored in `.dotta/metadata.json` within each profile branch
- Cross-platform compatibility - permissions mapped appropriately per OS

Example workflow:
```bash
# On source machine (as root for system files)
dotta add --profile global /etc/systemd/system/myservice.service

# On target machine
dotta apply  # Restores both content and permissions (0644, root:root)
```

### 4. Smart Deployment

Dotta optimizes the deployment process:

- **Pre-flight checks** - Detects conflicts before making changes
- **Overlap detection** - Warns when files appear in multiple profiles
- **Smart skipping** - Avoids rewriting unchanged files (enabled by default)
- **Conflict resolution** - Clear error messages with `--force` override option
- **State tracking** - Tracks deployed files in `.git/dotta.db`

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

Unlike many dotfile managers that only deploy *from* repository *to* filesystem, Dotta supports the reverse:

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

# Quicky add a specific pattern to profile
dotta ignore --profile darwin --add 'somefile'

# Test if a path would be ignored
dotta ignore --test ~/.config/nvim/node_modules
```

### 9. Bootstrap System

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

**Bootstrap scripts** are stored in `.dotta/bootstrap` within each profile branch and receive environment context:

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
└── dotta.db               # Deployment tracking
```

### File Storage Model

Files are stored with deployment prefixes in profile branches:

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

### Main Worktree

The repository's main worktree always points to `dotta-worktree` (an empty branch). This prevents Git status pollution and keeps your repository clean. All profile operations use temporary worktrees.

### Profile Resolution & Layering

Profile resolution follows a strict priority order:

1. **Explicit CLI** (`-p/--profile flags`) - Temporary override for testing
2. **State file** (`profiles` array in `.git/dotta.db`) - Persistent selection via `dotta profile select`

Active profiles are managed exclusively through `dotta profile select/unselect/reorder` commands. The state file is the single source of truth for which profiles are active on each machine.

When profiles are applied, later profiles override earlier ones following this precedence:

1. `global` - Base configuration
2. `<os>` - OS base profile (e.g., `darwin`)
3. `<os>/<variant>` - OS sub-profiles (e.g., `darwin/work`, alphabetically sorted)
4. `hosts/<hostname>` - Host base profile
5. `hosts/<hostname>/<variant>` - Host sub-profiles (e.g., `hosts/laptop/vpn`, alphabetically sorted)

Example layering for a macOS laptop with work and vpn configs:
- `dotta apply` → `global` → `darwin` → `darwin/work` → `hosts/laptop` → `hosts/laptop/vpn`
- Files from later profiles override files from earlier profiles

## Installation

### Prerequisites

- libgit2 1.5+
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
make format       # Format code with clang-format
make install      # Install to PREFIX (default: /usr/local)
make uninstall    # Remove installed files
```

## Quick Start

### Initialize a New Repository

```bash
# Create and initialize repository
dotta init

# Add files to base profiles
dotta add --profile global ~/.bashrc ~/.vimrc

# Add OS-specific files (hierarchical)
dotta add --profile darwin ~/.config/fish/config.fish
dotta add --profile darwin/work ~/.ssh/work_config

# Add host-specific files
dotta add --profile hosts/$(hostname) ~/.local/machine_specific

# Select active profiles for this machine
dotta profile select global darwin darwin/work hosts/$(hostname)

# View status
dotta status

# Apply configurations (layers: global → darwin → darwin/work → hosts/hostname)
dotta apply
```

### Clone an Existing Repository

```bash
# Clone dotfiles repository (auto-detects and activates profiles)
dotta clone git@github.com:username/dotfiles.git

# Cloning automatically:
# 1. Detects relevant profiles:
#    - global (if exists)
#    - OS base and sub-profiles (darwin, darwin/work, darwin/personal)
#    - Host base and sub-profiles (hosts/<hostname>, hosts/<hostname>/*)
# 2. Fetches detected profiles
# 3. Activates them in state

# Example auto-detection on macOS "laptop" with profiles:
# → Selects: global, darwin, darwin/work, hosts/laptop

# Run bootstrap scripts if present (prompts for confirmation)
dotta bootstrap

# Apply configurations
dotta apply

# Or clone with auto-bootstrap
dotta clone <url> --bootstrap
```

### Daily Workflow

```bash
# Make changes to your configs
vim ~/.bashrc

# Update the profile
dotta update

# Sync with remote
dotta sync

# On another machine
dotta sync     # Pull changes and apply
```

## Core Commands

### Repository Management

```bash
dotta init                          # Initialize new repository
dotta clone <url>                   # Clone existing repository
dotta remote add origin <url>       # Add remote
```

### Profile Management

```bash
dotta profile list                  # Show active vs available profiles
dotta profile list --remote         # Show remote profiles
dotta profile fetch <name>          # Download profile without activating
dotta profile select <name>         # Selects profile for this machine
dotta profile unselect <name>       # Deselects profile
dotta profile validate              # Check state consistency
```

### Profile Operations

```bash
dotta add --profile <name> <file>   # Add files to profile
dotta apply [profile]...            # Deploy active profiles (or specified)
dotta apply                         # Deploy and remove orphaned files
dotta update                        # Update active profiles with modified files
dotta sync                          # Intelligent two-way sync of active profiles
```

### Information & Inspection

```bash
dotta status                        # Show deployment and sync status
dotta list                          # List all profiles
dotta list <profile>                # List files in profile
dotta list --log [profile]          # Show commit history
dotta diff                          # Show differences
dotta show <file>                   # Show file content from profile
```

### File Management

```bash
dotta remove --profile <name> <file>              # Remove from profile
dotta remove --profile <name> --delete-profile    # Delete entire profile
dotta revert <file> <commit>                      # Revert to previous version
```

### Configuration & Setup

```bash
dotta bootstrap [--profile <name>]  # Run bootstrap scripts
dotta bootstrap --edit              # Create/edit bootstrap script
dotta ignore                        # Edit .dottaignore
dotta ignore --test <path>          # Test if path would be ignored
dotta git <command>                 # Run git commands in repository
```

## Configuration

Configuration file: `~/.config/dotta/config.toml`

### Essential Settings

```toml
[core]
repo_dir = "~/.local/share/dotta/repo"    # Repository location
strict_mode = false                       # Fail on validation errors

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
```

### Environment Variables

```bash
DOTTA_REPO_DIR       # Override repo_dir
DOTTA_CONFIG_FILE    # Use different config file
DOTTA_EDITOR         # Editor for bootstrap/ignore (fallback: VISUAL → EDITOR → vi/nano)
```

## Advanced Features

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
dotta profile select linux       # Make it active
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

hosts/desktop       # Desktop base
hosts/desktop/gaming # Gaming-specific configs
```

**Hierarchical rules:**
- Sub-profiles are limited to one level deep (`darwin/work` ✓, `darwin/work/client` ✗)
- Multiple sub-profiles are applied in alphabetical order
- Git limitation: Cannot have both base AND sub-profiles (see note above)

### Bootstrap Scripts

Bootstrap scripts automate system setup when cloning configurations to a new machine. Each profile can have its own bootstrap script in `.dotta/bootstrap`:

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
dotta list --log global

# Revert to specific commit
dotta revert ~/.bashrc abc123

# Revert with commit
dotta revert --commit -m "Fix config" ~/.bashrc HEAD~1
```

## Performance

Dotta is designed for efficiency:

- **O(1) lookups** - Hashmaps for state, metadata, and manifest operations
- **Smart skipping** - Avoids rewriting unchanged files (enabled by default)
- **Streaming tree walks** - Doesn't load all files into memory
- **Efficient blob comparison** - Short-circuit on size mismatch
- **Incremental operations** - Only processes changed files during update

## License

[Specify your license]

## Resources

- **Repository**: https://github.com/srevn/dotta
- **Documentation**: [Link to docs if available]
- **Issues**: https://github.com/srevn/dotta/issues

## Acknowledgments

Built with libgit2 for robust Git operations. Inspired by YADM's simplicity and Chezmoi's declarative approach, but designed from the ground up for the orphan branch model.
