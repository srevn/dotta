# Dotta

A declarative profile-based dotfile manager written in C11.

## What is Dotta?

Dotta manages configuration files across multiple machines using Git orphan branches as independent configuration profiles. Each profile is a separate Git branch with no shared history, allowing you to maintain distinct configurations for different systems while keeping everything in a single repository.

## Key Features

**Profile System**
Configuration is organized into profiles that are automatically layered based on your environment:
- `global` - Base configuration for all systems
- `darwin`/`linux`/`freebsd` - OS-specific configurations
- `hosts/<hostname>` - Machine-specific configurations

**Location Prefixes**
Files are stored with location prefixes that determine where they are deployed:
- `home/` - Files relative to `$HOME` (e.g., `home/.bashrc` → `~/.bashrc`)
- `root/` - Absolute paths (e.g., `root/etc/hosts` → `/etc/hosts`)

**Safe Deployment**
The `apply` command includes pre-flight checks for conflicts, permissions, and local modifications before deploying files to the filesystem. Use `--force` to override protection against modified files.

**Bidirectional Sync**
- `apply` - Deploy files from profiles to filesystem (repository → filesystem)
- `update` - Commit modified files back to profiles (filesystem → repository)
- `sync` - Intelligently combines update, fetch, and push operations

**Clean Worktree**
The main worktree always points to an empty `dotta-worktree` branch, preventing Git status pollution from deployed files.

## Dependencies

- libgit2 1.5+
- C11 compiler (clang recommended)
- POSIX-compliant system

## Building

```bash
make              # Build release binary
make install      # Install to /usr/local
```

## Basic Usage

### Initialize a Repository

```bash
dotta init
```

### Add Files to a Profile

```bash
dotta add --profile global ~/.bashrc ~/.vimrc
dotta add --profile darwin ~/.config/fish/config.fish
dotta add --profile hosts/laptop ~/.ssh/config
```

### Deploy Profiles

```bash
dotta apply                    # Apply auto-detected profiles
dotta apply global darwin      # Apply specific profiles
dotta apply --dry-run          # Preview changes
```

### Update Profiles with Changes

```bash
dotta update                   # Update all modified files
dotta update ~/.bashrc         # Update specific file
dotta update --profile global  # Update files in global profile only
```

### Check Status

```bash
dotta status                   # Show all managed files
dotta diff                     # Show differences
dotta diff --downstream        # Show filesystem → repo changes
```

### Remote Synchronization

```bash
dotta clone <url>              # Clone existing repository
dotta sync                     # Smart sync (update + fetch + push)
dotta pull                     # Pull changes from remote
dotta push                     # Push changes to remote
```

### Other Commands

```bash
dotta list                     # List profiles
dotta list --profile global    # List files in profile
dotta branch                   # Show branches
dotta log <profile>            # Show commit history
dotta show <file>              # Show file content
dotta revert <file> <commit>   # Revert file to previous version
dotta clean                    # Remove orphaned files
```

## Configuration

Default repository location: `~/.local/share/dotta/repo`

Override with environment variables:
```bash
export DOTTA_REPO_DIR=/path/to/dotfiles
export DOTTA_CONFIG_FILE=/path/to/config.toml
```

## Technical Details

- **Language**: C11
- **Main Dependency**: libgit2 for Git operations
- **Build System**: Make
- **Architecture**: Layered design (base, infrastructure, core, commands)

## License

[License information to be added]
