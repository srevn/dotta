# Dotta

A declarative, profile-based dotfile manager built on Git that uses orphan branches to manage configurations across multiple machines and operating systems.

## What is Dotta?

Dotta manages your configuration files (dotfiles) across different machines using Git as the underlying storage mechanism. Unlike traditional dotfile managers that use symlinks or track your home directory directly, Dotta uses **Git orphan branches** as independent configuration profiles, giving you powerful version control without the complexity of managing a monorepo.

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
global           # Base configuration (all systems)
darwin           # macOS-specific settings
linux            # Linux-specific settings
hosts/laptop     # Per-machine overrides
hosts/server     # Server-specific configuration
```

Profiles are applied in **layered order**, with later profiles overriding earlier ones. This enables:

- Shared base configuration across all machines
- OS-specific customizations
- Host-specific overrides
- Custom profile variants for different contexts (work, personal, client projects)

### 2. Three Workflow Modes

Dotta supports three distinct profile resolution modes to fit different use cases:

#### `local` mode (default) - Variant-Friendly Workflow
Operates on all local branches. Perfect for teams or individuals managing multiple configuration variants:

```bash
# Machine A creates a new variant
dotta add --profile experimental ~/.new_config
dotta sync  # Pushes to remote

# Machine B automatically discovers it
dotta sync  # Creates local branch, ready to use
dotta apply -p experimental
```

#### `auto` mode - Minimal Machine Workflow
Only operates on auto-detected profiles (`global` + OS + hostname). Perfect for single-purpose machines:

```bash
# Ignores all variant profiles
# Only manages: global, darwin/linux, hosts/<hostname>
dotta apply  # Only deploys system-relevant configs
```

#### `all` mode - Hub/Backup Workflow
Mirrors the entire remote repository. Perfect for backup servers or multi-machine management hubs:

```bash
# Syncs and maintains local copies of ALL remote profiles
dotta sync  # Complete mirror for disaster recovery
```

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
- **State tracking** - Tracks deployed files in `.git/dotta-state.json`

### 5. Orphan Detection & Cleanup

Dotta tracks what it deploys and can clean up files that are no longer managed:

```bash
# Remove files that were deployed but removed from profiles
dotta clean

# Preview what would be removed
dotta clean --dry-run

# Or clean during apply
dotta apply --prune
```

### 6. Bidirectional Sync

Unlike many dotfile managers that only deploy *from* repository *to* filesystem, Dotta supports the reverse:

```bash
# Update profiles with modified files from filesystem
dotta update

# Two-way sync with remote
dotta sync  # update + fetch + push/pull with conflict detection
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
└── dotta-state.json       # Deployment tracking
```

### File Storage Model

Files are stored with deployment prefixes in profile branches:

```
Profile branch "darwin":
  home/.bashrc                       → deploys to: $HOME/.bashrc
  home/.config/fish/config.fish      → deploys to: $HOME/.config/fish/config.fish
  root/etc/apcupsd/apcupsd.conf     → deploys to: /etc/apcupsd/apcupsd.conf
  .dotta/metadata.json               → metadata for permissions/ownership
```

**Prefix rules:**
- Path starts with `$HOME` → stored as `home/<relative_path>`
- Absolute path → stored as `root/<relative_path>`

### Main Worktree

The repository's main worktree always points to `dotta-worktree` (an empty branch). This prevents Git status pollution and keeps your repository clean. All profile operations use temporary worktrees.

### Profile Layering

When you run `dotta apply`, profiles are applied in order:

1. Auto-detected profiles: `global` → OS-specific → `hosts/<hostname>`
2. Or manually specified: `dotta apply profile-A profile-B` (B overrides A)
3. Files from later profiles override files from earlier profiles

## Installation

### Prerequisites

- libgit2 1.5+
- C11-compliant compiler (clang recommended)
- POSIX system (macOS, Linux, FreeBSD)

### Build from Source

```bash
# Clone repository
git clone https://github.com/yourusername/dotta.git
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

# Add your first files
dotta add --profile global ~/.bashrc ~/.vimrc
dotta add --profile darwin ~/.config/fish/config.fish

# View status
dotta status
```

### Clone an Existing Repository

```bash
# Clone dotfiles repository
dotta clone git@github.com:username/dotfiles.git

# Apply configurations
dotta apply

# Check what was deployed
dotta list global
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

### Profile Operations

```bash
dotta add --profile <name> <file>   # Add files to profile
dotta apply [profile]...            # Deploy profiles to filesystem
dotta apply --prune                 # Deploy and remove orphaned files
dotta update                        # Update profiles with modified files
dotta sync                          # Intelligent two-way sync
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
dotta clean                                       # Remove orphaned files
dotta revert <file> <commit>                      # Revert to previous version
```

### Configuration

```bash
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
mode = "local"                            # local, auto, or all
strict_mode = false                       # Fail on validation errors

[profiles]
order = ["base", "work", "laptop"]        # Manual profile order (optional)

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
```

## Architecture

### Layered Design

Dotta is built in distinct architectural layers (all in C11):

```
┌─────────────────────────────────────┐
│  Commands (cmds/)                   │  ← User-facing commands
│  init, add, apply, status, sync...  │
├─────────────────────────────────────┤
│  Core Logic (core/)                 │  ← Business logic
│  state, profiles, deploy, metadata  │
├─────────────────────────────────────┤
│  Infrastructure (infra/)            │  ← Path & worktree management
│  path, worktree, compare            │
├─────────────────────────────────────┤
│  Base Layer (base/)                 │  ← Git & filesystem operations
│  gitops, filesystem, error          │
├─────────────────────────────────────┤
│  Utilities (utils/)                 │  ← Cross-cutting concerns
│  config, hooks, output, buffer...   │
└─────────────────────────────────────┘
```

### Key Concepts

**Profile Resolution:** Determines which profiles to operate on based on CLI args → config → mode (local/auto/all)

**Manifest:** In-memory representation of files to deploy, built by walking profile trees and applying precedence rules

**State File:** `.git/dotta-state.json` tracks deployed files, enabling orphan detection and smart operations

**Metadata File:** `.dotta/metadata.json` in each profile branch preserves permissions and ownership

**Temporary Worktrees:** Profile operations use ephemeral worktrees to avoid polluting the main working directory

## Use Cases

### Personal Dotfiles Across Multiple Machines

```toml
# ~/.config/dotta/config.toml
[core]
mode = "local"

[profiles]
order = ["global", "darwin", "hosts/macbook"]
```

Manage your personal configurations with OS and host-specific overrides.

### Team Configuration Management

```toml
[core]
mode = "local"

[profiles]
order = ["base", "backend-dev", "docker"]

[ignore]
patterns = [".local/*", "*.work"]  # Personal overrides
```

Share base configurations while allowing personal customizations.

### Single-Purpose Server

```toml
[core]
mode = "auto"  # Only global + OS + hostname
```

Minimal configuration for servers that don't need variant profiles.

### Centralized Backup Hub

```toml
[core]
mode = "all"  # Mirror all remote profiles
```

Maintain complete backups of all configurations for disaster recovery.

### Development Environment Bootstrap

```bash
# Clone and apply in one session
dotta clone git@github.com:team/dev-configs.git
dotta apply

# Hooks auto-install packages, configure services
# ~/.config/dotta/hooks/post-apply handles setup
```

## Safety Features

### Pre-Flight Checks

Before deployment, Dotta checks for:
- File conflicts (local modifications)
- Permission errors (unwritable paths)
- Profile overlaps (same file in multiple profiles)

### Confirmation Prompts

Operations that modify files require confirmation:
- `dotta apply` (overwrites files) - unless `--force`
- `dotta clean` (removes files) - unless `--force`
- `dotta remove --cleanup` (deletes from filesystem)
- New file detection during `update` (configurable)

### Fail-Safe Deployment

Deployment stops on first error:
- Partial deployments are avoided
- Clear error messages with file paths
- State file only updated on success

### Dry-Run Mode

Preview operations without making changes:
```bash
dotta apply --dry-run
dotta clean --dry-run
dotta update --dry-run
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
dotta list --remote              # Show local + remote profiles
dotta status --remote            # Check sync state
dotta sync --mode=all            # Sync all remote profiles
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

### Subprofile Organization

Organize profiles hierarchically:

```
hosts/
├── laptop
├── desktop
└── servers/
    ├── web01
    └── db01
```

### File-Level Revert

Revert individual files to previous versions:

```bash
# Show file history
dotta list --log global

# Revert to specific commit
dotta revert ~/.bashrc abc123

# Revert and deploy
dotta revert --apply ~/.bashrc HEAD~3

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

## Troubleshooting

### Common Issues

**Worktree errors:**
```bash
# Clean up stale worktrees
dotta git worktree prune
```

**State mismatch:**
```bash
# Rebuild state
dotta apply --force
```

**Permission denied:**
```bash
# System files require root
sudo dotta apply

# Or use hooks to handle ownership
```

**Conflicts:**
```bash
# View conflicts
dotta status

# Force overwrite
dotta apply --force

# Or manually resolve
dotta diff
```

### Debug Mode

```bash
# Enable verbose output
dotta -v apply

# Or configure in config.toml
[output]
verbosity = "debug"
```

### Repository Verification

```bash
# Check repository health
dotta git fsck

# View branches
dotta git branch -a

# Inspect state file
cat ~/.local/share/dotta/repo/.git/dotta-state.json
```

## Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/dotta.git
cd dotta

# Build debug version with sanitizers
make debug

# Run tests (when available)
make test

# Format code
make format
```

### Adding Features

When adding new source files, simply place them in the appropriate layer directory:

```
src/
├── base/      # Foundation layer
├── infra/     # Infrastructure
├── core/      # Business logic
├── cmds/      # Commands
└── utils/     # Utilities
```

The Makefile automatically discovers and compiles new `.c` files - no manual updates needed.

### Code Style

- C11 standard
- Layer-respecting dependencies (base ← infra ← core ← cmds)
- Error handling with `error_t` type
- Null checks with `CHECK_NULL` macro
- Memory cleanup with goto-style error handling

## License

[Specify your license]

## Resources

- **Repository**: https://github.com/srevn/dotta
- **Documentation**: [Link to docs if available]
- **Issues**: https://github.com/srevn/dotta/issues

## Acknowledgments

Built with libgit2 for robust Git operations. Inspired by YADM's simplicity and Chezmoi's declarative approach, but designed from the ground up for the orphan branch model.
