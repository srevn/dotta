# dotta

Declarative, Git-based configuration management for heterogeneous Unix estates.

## Overview

Manage a single repository with independent, versioned profiles across laptops, servers, workstations and containers. Deploy actual files with correct ownership and atomic rollbacks, optional transparent encryption, and a bidirectional workflow that lets you edit in place.

Profiles layer by scope (global, OS-specific, host-specific) so shared settings propagate naturally while machine-specific overrides stay isolated. Files are stored with location prefixes (`home/`, `root/`) and deployed to their filesystem targets on demand.

## Commands

```
Usage: dotta <command> [options]

Commands:
  init           Initialize a new dotta repository
  clone          Clone an existing dotta repository
  add            Add files or directories to a profile
  remove         Remove files from a profile or delete profile
  update         Commit filesystem changes back to profiles
  apply          Deploy enabled profiles to the filesystem
  revert         Revert a file to a previous version
  status         Show workspace status and remote sync state
  diff           Show differences between profiles and filesystem
  list           List profiles, files, and commit history
  show           Show file content or commit details
  sync           Synchronize profiles with remote repository
  profile        Profile management and layering
  remote         Manage remote repositories
  ignore         Manage ignore patterns
  bootstrap      Execute profile bootstrap scripts
  key            Manage encryption keys and passphrases
  git            Execute git commands within repository

Options:
  -h, --help     Show help (use <command> --help for details)
  -v, --version  Show version information
  --interactive  TUI for profile management

Run 'dotta <command> --help' for more information on a command.
```

## Quick Start

### New Repository

```bash
dotta init
dotta add global ~/.bashrc ~/.config/fish
dotta profile enable global
dotta apply
```

### Clone Existing

```bash
dotta clone git@github.com:user/dotfiles.git
dotta apply
```

Clone auto-detects profiles matching the current system (`global`, OS, hostname) and enables them.

### Day-to-Day

```bash
# Edit files in place, then commit changes back
dotta update

# Check what needs attention
dotta status

# Sync with remote
dotta sync

# Deploy after pulling changes on another machine
dotta apply
```

## Installation

### Prerequisites

- libgit2 1.5+
- sqlite3 3.40+
- C11 compiler (clang recommended)
- POSIX system (macOS, Linux, FreeBSD)

### Build

```bash
git clone https://github.com/srevn/dotta.git
cd dotta
make check-deps
make
sudo make install  # optional, installs to /usr/local
```

## Configuration

Default config: `~/.config/dotta/config.toml`

See [`etc/config.toml.sample`](etc/config.toml.sample) for all available settings.

Key environment variables:
- `DOTTA_REPO_DIR` -- override repository location
- `DOTTA_CONFIG_FILE` -- use a different config file

## Documentation

Detailed guides are available in [`docs/`](docs/):

- [**Concepts**](docs/concepts.md) -- How dotta works: the profile model, file storage, virtual working directory
- [**Profiles**](docs/profiles.md) -- Profile management, layering, hierarchical organization
- [**Workflows**](docs/workflows.md) -- Common workflows: add/apply/update cycle, sync, diff, revert
- [**Encryption**](docs/encryption.md) -- Transparent file encryption setup and usage
- [**Configuration**](docs/configuration.md) -- Full configuration reference: hooks, ignore patterns, commit templates
- [**Encryption Spec**](docs/encryption-spec.md) -- Cryptographic design and implementation details

## Acknowledgments

Built with libgit2 for robust Git operations. Inspired by YADM's simplicity and Chezmoi's declarative approach, but designed from the ground up for the orphan branch model.
