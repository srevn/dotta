# Profiles

Profiles are the central organizing unit in dotta. Each profile is a Git orphan branch containing configuration files. This guide covers how to manage them.

## Profile States

- **Available** -- exists as a local Git branch but is not enabled
- **Enabled** -- switched on for this machine; every command acts on it (apply, update, sync, status)
- **Remote** -- exists on a remote but has not been fetched locally

## Enabling and Disabling

```bash
# Enable profiles for this machine
dotta profile enable global darwin
# ✓ Enabled global
# ✓ Enabled darwin
# Staged 47 entries for deployment

# Disable a profile (files will be removed on next apply)
dotta profile disable darwin

# Preview the impact without making changes
dotta profile disable darwin --dry-run

# List all profiles and their state
dotta profile list

# Include remote profiles
dotta profile list --all
```

Enabling a profile puts its files in play: dotta now expects them on disk, and a higher profile still wins any path they share (see [The View and the Record](concepts.md#the-view-and-the-record)). Disabling takes them back out, showing a preview of what that does -- files may fall back to a lower-precedence profile, or be marked as orphaned for removal.

`enable`, `disable`, `reorder`, `fetch` and `validate` also work without the `profile` in front of them: `dotta enable global` is `dotta profile enable global`.

## Layering and Precedence

When multiple profiles contain the same file path, the profile enabled later wins. Precedence is this machine's enabled order, the one `dotta profile list` prints, and the repository knows nothing of it: the same two profiles can layer one way on one machine and the other way on another.

The order is a list this machine keeps:

- `dotta profile enable <name>...` appends each profile above the ones already enabled, in the order given. Re-enabling a disabled profile puts it on top.
- `dotta profile enable --all` and `dotta clone --all` enable every profile, and `dotta clone` enables the ones it detects. Neither names an order, so dotta uses the layering convention. That is only the starting order -- nothing re-sorts an enabled set afterwards:
  1. `global`
  2. `<os>` (e.g., `darwin`, `linux`)
  3. `<os>/<variant>` (e.g., `darwin/work`, sorted alphabetically)
  4. `hosts/<hostname>` (e.g., `hosts/laptop`)
  5. `hosts/<hostname>/<variant>` (e.g., `hosts/laptop/vpn`, sorted alphabetically)
- `dotta profile disable <name>` deletes the profile's line; the others keep their order.
- `dotta profile reorder <name>...` names every enabled profile in the desired order.

Example: a fresh clone that detected `global`, `darwin` and `hosts/laptop` has them in that order, so if both `global` and `darwin` contain `home/.bashrc`, the `darwin` version deploys. Disable `darwin` and enable it again, and it sits above `hosts/laptop`.

```bash
# Name every enabled profile to set the whole order
dotta profile reorder global darwin hosts/laptop
```

An `<os>/<variant>` profile is detected on every machine of that OS; a per-machine variant is `hosts/<hostname>/<variant>`.

Precedence decides **who deploys a path**, and nothing else. Where each profile *stores* the file is its own business -- decided by its target and what it already holds (see [How Files Are Stored](concepts.md#how-files-are-stored)). So two profiles can keep one file in two different places, and the higher one simply wins the spot on disk.

That is also why an enabled profile can hold files and still read `empty` under `dotta status -v`. The two commands count different things: `status` counts what a profile currently **wins**, while `dotta profile list` counts what it **holds**. When a higher profile takes a path over, `dotta add` says so -- `Note: 1 path taken over from other profiles` -- and `dotta status --full` names the winner beside every managed path.

## Targets

Some profiles manage a tree that is not the home directory and not at the same absolute path everywhere -- a container, a jail, a chroot, a second home. A profile like that can be pointed at one directory per machine: its **target**. Files inside it are stored under `custom/` and deploy wherever the profile is pointed on that machine.

```bash
# Set the target and capture a file from inside it, in one command
dotta add web --target /mnt/jails/web /mnt/jails/web/etc/nginx.conf

# On another machine, point it where that machine keeps the tree
dotta profile enable web --target /srv/web
```

A profile has one target, and it belongs to this machine, not to the branch. It travels nowhere, and disabling the profile forgets it -- `dotta profile disable` prints the command that puts it back. `dotta profile list` shows a profile's target beside its name.

**`--target` sets the target; it is not a per-command mode.** Once a profile has one, every later command reads it, flag or no flag:

```bash
dotta add web --target ~/jail ~/jail/etc/y   # sets it → custom/etc/y
dotta add web ~/jail/etc/z                   # no flag → custom/etc/z
```

**Moving a target** is `dotta profile enable <name> --target <new>` on a profile that is already enabled. Everything moves at once: the next `dotta status` shows the new paths as `[undeployed]` and the old copies as `[orphaned] [relocated]`, and `dotta apply` deploys the first and prunes the second.

**A profile with files under `custom/` is enabled only with a target.** `dotta clone` and `dotta profile enable --all` leave such a profile disabled and name the command; `dotta profile list` marks it `(custom)`. A profile that picks up `custom/` files from a sync *after* it was enabled here stays enabled, and `dotta status` keeps saying so until it has one.

A target is not ownership. Other profiles may keep files inside it in their own way, and dotta walks straight through it: `dotta add global ~` captures a file inside `web`'s target as `home/jail/etc/x`, because `web`'s target means nothing to `global`. A target says where a profile's files land, not who owns the files there.

A path that is the same absolute path on every machine -- `/etc/hosts` -- belongs under `root/` and needs no target.

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

**Note:** A base profile and its sub-profiles cannot coexist -- Git will not let one branch name be a prefix of another, so `darwin` and `darwin/work` cannot both exist. Use the base profile or the sub-profiles, not both. The same applies to host profiles.

## CLI Profile Filter

The `-p`/`--profile` flag on commands like `apply`, `status`, and `update` acts as an **operation filter**, not a scope override:

```bash
# Workspace always loads ALL enabled profiles
# The -p flag filters which files to process
dotta apply -p darwin    # Deploys only darwin's files
dotta status -p global   # Shows only global's status
```

Dotta always looks at every enabled profile to decide what belongs where. The flag only narrows which of those files the command touches.

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

These are automatically fetched and enabled in the layering convention's order. Override this with `--all` (fetch everything, enabled in the same order) or `--profile` (fetch specific ones, enabled in the order given).

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
- **Ownership** (user:group) -- recorded for `root/` and `custom/` paths owned by someone else; no privileges are needed to read it
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
