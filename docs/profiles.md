# Profiles

Profiles are the central organizing unit in dotta. Each profile is a Git orphan branch containing configuration files. This guide covers how to manage them.

## Profile States

- **Available** -- exists as a local Git branch but is not enabled
- **Enabled** -- tracked in the state database, participates in all operations (apply, update, sync, status)
- **Remote** -- exists on a remote but has not been fetched locally

## Enabling and Disabling

```bash
# Enable profiles for this machine
dotta profile enable global darwin
# ✓ Enabled 'global' (23 files in scope, 12 need deployment)
# ✓ Enabled 'darwin' (47 files in scope, 35 need deployment)

# Disable a profile (files will be removed on next apply)
dotta profile disable darwin

# Preview the impact without making changes
dotta profile disable darwin --dry-run

# List all profiles and their state
dotta profile list

# Include remote profiles
dotta profile list --all
```

Enabling a profile populates the manifest with all of the profile's files (with precedence resolved). Disabling removes them, showing a preview of what will happen -- files may fall back to a lower-precedence profile or be marked as orphaned for removal.

## Layering and Precedence

When multiple profiles contain the same file path, the profile with higher precedence wins. The order is:

1. `global`
2. `<os>` (e.g., `darwin`, `linux`)
3. `<os>/<variant>` (e.g., `darwin/work`, sorted alphabetically)
4. `hosts/<hostname>` (e.g., `hosts/laptop`)
5. `hosts/<hostname>/<variant>` (e.g., `hosts/laptop/vpn`, sorted alphabetically)

Example: if both `global` and `darwin` contain `home/.bashrc`, the `darwin` version takes precedence.

To change the order of enabled profiles:

```bash
dotta profile reorder global darwin hosts/laptop
```

## Hierarchical Organization

Profiles can be organized hierarchically for both OS and host dimensions:

```
# OS hierarchy
darwin/work         # Work macOS settings
darwin/personal     # Personal macOS settings

# Host hierarchy
hosts/laptop/office # Office network configs
hosts/laptop/vpn    # VPN settings
```

**Note:** Due to Git ref namespace limitations, you cannot have both a base profile and sub-profiles with the same prefix (e.g., `darwin` and `darwin/work` cannot coexist). Use either the base profile OR sub-profiles, not both. The same limitation applies to host profiles.

## CLI Profile Filter

The `-p`/`--profile` flag on commands like `apply`, `status`, and `update` acts as an **operation filter**, not a scope override:

```bash
# Workspace always loads ALL enabled profiles
# The -p flag filters which files to process
dotta apply -p darwin    # Deploys only darwin's files
dotta status -p global   # Shows only global's status
```

The full set of enabled profiles is always used to compute the manifest. The filter just narrows which files the command acts on.

## Fetching Remote Profiles

If a profile exists on the remote but not locally:

```bash
# See what's available
dotta profile list --all

# Fetch without enabling
dotta profile fetch linux

# Fetch and enable
dotta profile fetch linux
dotta profile enable linux
```

## Auto-Detection During Clone

When cloning, dotta auto-detects profiles that match the current system:

- `global` (if it exists)
- OS base and sub-profiles (e.g., `darwin`, `darwin/*`)
- Host base and sub-profiles (e.g., `hosts/<hostname>`, `hosts/<hostname>/*`)

These are automatically fetched and enabled. Override this with `--all` (fetch everything) or `--profiles` (fetch specific ones).

## Interactive Mode

For visual profile management:

```bash
dotta --interactive
```

Keybindings:
- Arrow keys / `j`/`k` -- navigate
- `Space` -- toggle enable/disable
- `J`/`K` -- reorder (move up/down)
- `w` -- save changes
- `q` / `Esc` -- quit

## Metadata Preservation

Dotta automatically preserves file metadata across machines:

- **Permissions** (mode) -- captured during `add`/`update`, restored during `apply`
- **Ownership** (user:group) -- tracked for `root/` prefix files when running as root
- Stored in `.dotta/metadata.json` within each profile branch

```bash
# On source machine (as root for system files)
dotta add linux /etc/systemd/system/myservice.service

# On target machine
dotta apply  # Restores content, permissions (0644), and ownership (root:root)
```

## Validation

If something gets out of sync, validate and fix the profile state:

```bash
dotta profile validate        # Check for inconsistencies
dotta profile validate --fix  # Auto-fix detected issues
```
