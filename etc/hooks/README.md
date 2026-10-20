# Dotta Hook Scripts

Hooks allow you to run custom scripts before and after dotta operations.

## Installation

1. **Create hooks directory:**
   ```bash
   mkdir -p ~/.config/dotta/hooks
   ```

2. **Copy sample hooks:**
   ```bash
   cp etc/hooks/pre-apply.sample ~/.config/dotta/hooks/pre-apply
   cp etc/hooks/post-apply.sample ~/.config/dotta/hooks/post-apply
   cp etc/hooks/pre-add.sample ~/.config/dotta/hooks/pre-add
   cp etc/hooks/post-add.sample ~/.config/dotta/hooks/post-add
   cp etc/hooks/pre-sync.sample ~/.config/dotta/hooks/pre-sync
   cp etc/hooks/post-sync.sample ~/.config/dotta/hooks/post-sync
   ```

3. **Make them executable** — the file is the switch: a hook runs where it is
   executable, and `chmod -x` switches it off:
   ```bash
   chmod +x ~/.config/dotta/hooks/*
   ```

4. **Customize for your needs:**
   Edit the scripts to match your workflow.

## Available Hooks

### `pre-apply`

**When:** Before applying profiles: after apply's preview, before its question
**Use For:** Backing up configs, validating environment, checking disk space

**Example Use Cases:**
- Create timestamped backups of current configs
- Verify required environment variables are set
- Check system resources (disk space, memory)

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "apply"
- `DOTTA_PROFILE` - Space-separated list of profiles being applied
- `DOTTA_PATH_COUNT` - Always "0" for apply
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0: Continue with apply
- Exit non-zero: Abort apply operation

### `post-apply`

**When:** After applying profiles, once apply's report is printed
**Use For:** Reloading services, restarting apps, sending notifications

**Example Use Cases:**
- Reload shell configuration
- Restart tmux/tmuxinator
- Update vim/neovim plugins
- Send desktop notification
- Trigger service restarts

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "apply"
- `DOTTA_PROFILE` - Space-separated list of profiles being applied
- `DOTTA_PATH_COUNT` - Always "0" for apply
- `DOTTA_DRY_RUN` - Always "0" — post-apply does not fire on dry-run

**Exit Behavior:**
- Exit 0 or non-zero: a non-zero exit is warned, with the hook's output; the apply has already completed

### `pre-add`

**When:** Before adding files or directories to a profile: once the add has
decided what it takes, after its preview under `-n`
**Use For:** Validating file contents, checking for secrets, size checks

**Example Use Cases:**
- Scan for secrets (API keys, passwords, tokens)
- Check for private SSH keys
- Validate file sizes (warn on large files)
- Lint/validate file formats
- Check for binary files

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "add"
- `DOTTA_PROFILE` - Profile name being modified
- `DOTTA_PATH_COUNT` - Number of paths: the arguments as given (file or dir)
- `DOTTA_PATH_0`, `DOTTA_PATH_1`, ... - Each path, as given (0-indexed)
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0: Continue with add
- Exit non-zero: Abort add operation

### `post-add`

**When:** After adding files or directories to a profile, once add's report is
printed
**Use For:** Publishing the profile, CI/CD triggers, team notifications

**Example Use Cases:**
- Push the profile to its remote with `dotta sync` (dotta committed the add)
- Trigger CI/CD pipelines
- Send Slack/Discord notifications
- Generate profile documentation
- Update README files

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "add"
- `DOTTA_PROFILE` - Profile name that was modified
- `DOTTA_PATH_COUNT` - Number of paths: the arguments as given (file or dir)
- `DOTTA_PATH_0`, `DOTTA_PATH_1`, ... - Each path, as given (0-indexed)
- `DOTTA_DRY_RUN` - Always "0" — post-add does not fire on dry-run

**Exit Behavior:**
- Exit 0 or non-zero: a non-zero exit is warned, with the hook's output; the add has already completed

### `pre-remove`

**When:** Before removing paths from a profile or deleting a profile: once the
removal has decided what it takes — after `-i`'s questions and its preview —
and before its question
**Use For:** Backing up paths, validating removal, preventing accidental deletion

**Example Use Cases:**
- Create backup of the paths about to be removed
- Prevent removal of critical config files
- Notify team about profile deletions

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "remove"
- `DOTTA_PROFILE` - Profile name being modified or deleted
- `DOTTA_PATH_COUNT` - Number of paths: one per path the removal takes a claim
  at, a directory the profile tracks as well as a file — every path the profile
  tracks, when it is deleted — each once, however many claims stand there; a
  directory the profile only passes through is none of them
- `DOTTA_PATH_0`, `DOTTA_PATH_1`, ... - Each path (0-indexed)
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0: Continue with remove
- Exit non-zero: Abort remove operation

### `post-remove`

**When:** After removing paths from a profile or deleting a profile, once
remove's report is printed — a deletion's push to its remote among it
**Use For:** Cleanup, notifications, auditing

**Example Use Cases:**
- Log removal for auditing
- Notify team about profile deletions
- Trigger CI/CD pipelines
- Clean up related resources

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "remove"
- `DOTTA_PROFILE` - Profile name that was modified or deleted
- `DOTTA_PATH_COUNT` - Number of paths: the ones `pre-remove` was handed
- `DOTTA_PATH_0`, `DOTTA_PATH_1`, ... - Each path (0-indexed)
- `DOTTA_DRY_RUN` - Always "0" — post-remove does not fire on dry-run

**Exit Behavior:**
- Exit 0 or non-zero: a non-zero exit is warned, with the hook's output; the remove has already completed

### `pre-update`

**When:** Before committing filesystem changes back to profiles: after update's
preview and its new-files question, before `-i`'s question
**Use For:** Validating changes, checking for conflicts, creating checkpoints

**Example Use Cases:**
- Validate that modified files are syntactically correct
- Check for sensitive data in changes
- Create a snapshot before updating
- Verify no conflicting changes exist

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "update"
- `DOTTA_PROFILE` - Space-separated list of profiles being updated
- `DOTTA_PATH_COUNT` - Number of paths: the arguments as given (file or dir); 0
  on a run given none, which updates every modified path
- `DOTTA_PATH_0`, `DOTTA_PATH_1`, ... - Each path, as given (0-indexed)
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0: Continue with update
- Exit non-zero: Abort update operation

### `post-update`

**When:** After committing filesystem changes back to profiles, once update's
report is printed; a run stopped at a profile fires none
**Use For:** Syncing changes, notifications, triggering deployments

**Example Use Cases:**
- Auto-sync to remote after update
- Send Slack/Discord notifications about changes
- Trigger CI/CD pipelines
- Update documentation or changelogs

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "update"
- `DOTTA_PROFILE` - Space-separated list of profiles that were updated
- `DOTTA_PATH_COUNT` - Number of paths: the arguments as given (file or dir); 0
  on a run given none, which updates every modified path
- `DOTTA_PATH_0`, `DOTTA_PATH_1`, ... - Each path, as given (0-indexed)
- `DOTTA_DRY_RUN` - Always "0" — post-update does not fire on dry-run

**Exit Behavior:**
- Exit 0 or non-zero: a non-zero exit is warned, with the hook's output; the update has already completed

### `pre-sync`

**When:** Before synchronizing with the remote: after sync's workspace check,
before its question and the fetch
**Use For:** Gating sync on network conditions, host policy, or remote reachability

**Example Use Cases:**
- Block sync on a metered network
- Refuse to push from a designated read-only host
- Verify the remote is reachable before paying the fetch cost
- Require VPN connection for private remotes

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "sync"
- `DOTTA_PROFILE` - Space-separated list of profiles being synced
- `DOTTA_REMOTE` - Resolved remote name (e.g., "origin")
- `DOTTA_PATH_COUNT` - Always "0" for sync
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0: Continue with sync
- Exit non-zero: Abort sync operation

**Fire ordering:** Pre-sync fires once sync has checked the workspace — a
`strict_mode` refusal fires none — and before the question it asks over
uncommitted changes, so it can fire over a sync the user then declines, with
no post-sync after it. It fires before the fetch as well, so a run whose force
push or reset is declined after the fetch, or refused there off a terminal, has
fired it with no post-sync after it. Network or push failures may suppress
post-sync too — the same operational asymmetry every hook pair carries.

### `post-sync`

**When:** After synchronizing with the remote, once sync's report is printed — a
profile that failed to push or pull included; a sync that stops before it, a
fetch that failed among them, fires none
**Use For:** Cross-machine signaling, notifications, triggering downstream apply

**Example Use Cases:**
- Desktop notification on sync completion
- Webhook ping to a coordinator service ("this host pushed")
- Auto-trigger `dotta apply` on the same machine after pulling
- Trigger CI/CD when a profile branch advances

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "sync"
- `DOTTA_PROFILE` - Space-separated list of profiles that were synced
- `DOTTA_REMOTE` - Resolved remote name (e.g., "origin")
- `DOTTA_PATH_COUNT` - Always "0" for sync
- `DOTTA_DRY_RUN` - Always "0" — post-sync does not fire on dry-run

**Exit Behavior:**
- Exit 0 or non-zero: a non-zero exit is warned, with the hook's output; the sync has already completed

**Note:** post-sync fires once sync's report is printed, so individual
profiles may still have diverged or failed — run `dotta status` inside the
hook if per-profile detail is needed.

### `pre-revert`

**When:** Before reverting a file to a past commit: after revert's preview,
before its question
**Use For:** Guarding a profile's history, checking the version restored

**Example Use Cases:**
- Refuse a revert of a file other machines rely on
- Check the restored version before it is committed
- Record that a profile's history is being rewound

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "revert"
- `DOTTA_PROFILE` - Profile name being reverted
- `DOTTA_PATH_COUNT` - Always "1"
- `DOTTA_PATH_0` - The file, as given (a path or a storage path)
- `DOTTA_DRY_RUN` - "1" if dry-run, "0" otherwise

**Exit Behavior:**
- Exit 0: Continue with revert
- Exit non-zero: Abort revert operation

### `post-revert`

**When:** After reverting a file to a past commit, once revert's report is
printed
**Use For:** Deploying the restored version, notifications, auditing

**Example Use Cases:**
- Run `dotta apply` to deploy the restored version (revert commits it alone)
- Log the revert for auditing
- Send a desktop notification

**Environment Variables:**
- `DOTTA_REPO_DIR` - Path to dotta repository
- `DOTTA_CONFIG_FILE` - Path to the configuration file the run read
- `DOTTA_COMMAND` - Always "revert"
- `DOTTA_PROFILE` - Profile name that was reverted
- `DOTTA_PATH_COUNT` - Always "1"
- `DOTTA_PATH_0` - The file, as given (a path or a storage path)
- `DOTTA_DRY_RUN` - Always "0" — post-revert does not fire on dry-run

**Exit Behavior:**
- Exit 0 or non-zero: a non-zero exit is warned, with the hook's output; the revert has already completed

## When a hook fires

Every hook-bearing command runs one order: it decides what it will do, shows
it, fires its `pre-` hook, asks its question, acts, says what it did — the act,
then any record it writes of it — and fires its `post-` hook last, once that
report is printed. Under `-n` the `pre-` hook fires told `DOTTA_DRY_RUN=1`, and
no `post-` hook fires. So a `pre-` hook runs over a decided run: a run the
command refused, or one with nothing to do, fires no hook, and a question the
run owes but cannot ask — a destructive one off a terminal, without `--force` —
refuses before the hook.

What a `pre-` hook changes meets what the command decided: add,
`remove <path>` and revert read the profile before the hook, so a commit it
makes refuses theirs and a branch it deletes comes back with their commit;
update reads the profile after it and builds on the hook's commit;
`remove --delete-profile` deletes the branch whatever the hook committed to it.

sync decides twice: it checks the workspace before `pre-sync` and asks its
question after it, and decides what to pull and push after the fetch that
follows the hook — a run that force pushes or resets asks once there, beneath
what it will do and before any profile acts, and off a terminal is refused
there. The enabled-set writers (`profile enable`, `disable`, `reorder`,
`interactive`, `clone`) and dotta's own files (`ignore`, `bootstrap --edit`)
fire none.

## Hook Configuration

`~/.config/dotta/config.toml` says where the hooks are and how long one may run:

```toml
[hooks]
hooks_dir = "~/.config/dotta/hooks"  # Where to find hooks
timeout = 30                         # Seconds a hook may run (0: no limit)
```

It switches none of them: a hook runs where its file is executable, as git's do.
One that is there but cannot run — no execute bit, no regular file — is ignored
with a warning naming why, and a hooks directory dotta cannot search is named
once a run.

A hook that outlives `timeout` is ended — the hook itself, not what it started.
It runs in dotta's own process group, as git's hooks run in git's: Ctrl-C at
the terminal ends dotta and the hook alike, and a hook may write to the
terminal or read an answer from it (`/dev/tty`). A signal sent to dotta alone
(`kill`) does not reach it.

A hook is handed its paths in its environment, one variable a path, as git
hands a hook its push options. A list the system will not carry in an
environment — a removal of a large tracked tree, or of a whole profile —
refuses the hook, and with it the command: `chmod -x` the hook to run the
command without it.

## Writing Hooks

### Output is captured, or live under -v

Dotta sends a hook's stdout and stderr into a temporary file — in
`$TMPDIR`, else `/tmp`, unlinked as soon as it is made — reads it once
the hook exits, and prints it only when the hook reports a failure
(non-zero exit, timeout, signal), up to its first mebibyte. On the
happy path the output is discarded silently, so anything your hook
prints during normal operation is invisible in the terminal running
dotta.

A hook therefore needs a temporary directory where a file can be
created: where none can be, dotta refuses to run it. What a hook prints
stays in that directory until the file is last closed, and a hook that
prints without bound fills it while it runs.

Under `-v` (`--verbose`, or `verbosity = "verbose"` in `[output]`) a
hook's stdout and stderr are dotta's own instead: what it prints
reaches the terminal as it prints it, beneath a line naming the hook
(`Running hook 'post-add'...`), and nothing is kept — a failing hook's
output stands where it wrote it.

This matters for long-running `post-*` scripts (webhook callouts,
desktop notifications, notification daemons). If you want visible
progress while the hook runs, do not rely on plain `echo`. Instead,
direct the output to a destination dotta does not capture:

- `>/dev/tty`  — write straight to the controlling terminal
- `logger -t dotta`  — append to syslog/journald
- `>> "$HOME/.local/state/dotta/hook.log"`  — append to a file
- `notify-send` / `osascript`  — surface a desktop notification

### The run's identity is your environment

A hook runs as the run's invoker — the user who typed the command. A run
that obtained root through `sudo` drops back to that user before the fork,
so your script has exactly the reach the invoker has and nothing more.

`HOME`, `USER` and `LOGNAME` name that same user, on every run and not only
a `sudo`'d one. `HOME` is the directory dotta itself resolved and classified
`home/` paths against — absolute and lexically normalised — so an absolute
path tested against it gets the answer dotta would give:

```bash
case "$path" in
    "$HOME"/*) echo "under home/" ;;
esac
```

`DOTTA_PATH_*` is not guaranteed absolute: add and update pass the paths on to
the hook as they received them. Make a path absolute before comparing it.

Sudo's own variables (`SUDO_USER`, `SUDO_UID`, ...) are left as they were, so
a hook that wants to know how the run was started can still tell.

### A dotta your hook runs is the run's own

`DOTTA_REPO_DIR` and `DOTTA_CONFIG_FILE` name the store and the configuration
file the run read, absolute, so a `dotta` your hook runs acts on the same store
under the same configuration from any directory. Every other `DOTTA_*` variable
the run was started with is left out of the hook's environment, an outer hook's
among them.

### The store's write lock

`dotta add` and `dotta apply` hold the store's database write lock from before
their `pre-` hook fires to the end of their own record write, which is before
the `post-` hook fires — deliberately, so two of them cannot interleave.

So a hook of either command can read the store freely, but must not run a `dotta`
command that itself writes state: from a `pre-add` or `pre-apply` hook such a
command is refused with a database-locked error. `dotta status`, `dotta list`,
`dotta diff`, `dotta show` and `dotta git ...` read only and are always fine; the
same is true of every hook of the other commands, which take the lock only for
the moment they write.

If a hook needs to write state, run it from a `post-` hook — by then the command
has finished its transaction either way, including when its record write failed.

A preview takes no lock at all. `dotta add -n` and `dotta apply -n` open the store
for reading, so a `pre-add` or `pre-apply` hook of one may run a `dotta` command
that writes state. The preview has already read the profiles it names paths under
by the time the hook fires, so what such a command changes is the next command's
answer, not this preview's.

### Best Practices

1. **Always use `set -euo pipefail`** at the top of bash scripts
2. **Check environment variables** before using them
3. **Provide clear error messages** to stderr
4. **Exit with appropriate codes:**
   - 0 for success
   - Non-zero for errors (aborts pre-hooks only)
5. **Be idempotent:** Hooks may run multiple times
6. **Handle missing commands gracefully:** Use `command -v` checks
7. **Log what you're doing:** Help users understand what happened
8. **Name your interpreter** on a `#!` line: a hook without one is run by
   `/bin/sh`, as git runs one

### Script Template

```bash
#!/usr/bin/env bash
set -euo pipefail

# Validate environment
if [[ -z "${DOTTA_REPO_DIR:-}" ]]; then
    echo "Error: DOTTA_REPO_DIR not set!" >&2
    exit 1
fi

# Your logic here
echo "Running hook: $(basename "$0")"

# Exit appropriately
exit 0
```

### Security Considerations

1. **Never hardcode secrets** in hook scripts
2. **Use environment variables** for sensitive data
3. **Validate inputs:** Always validate the paths from `DOTTA_PATH_N` variables — each a file or a directory
4. **Use indexed variables:** Iterate via `DOTTA_PATH_COUNT` and `DOTTA_PATH_N` for safe path handling
5. **Be careful with auto-push:** Could expose sensitive data
6. **Limit permissions:** Hooks should only modify what they need

### Debugging Hooks

Run dotta with `--verbose` to see what a hook prints, live as it runs:

```bash
dotta add --profile test ~/.bashrc --verbose
```

Test hooks manually:

```bash
# Set up environment
export DOTTA_REPO_DIR=~/.local/share/dotta/repo
export DOTTA_CONFIG_FILE=~/.config/dotta/config.toml
export DOTTA_COMMAND=add
export DOTTA_PROFILE=test
export DOTTA_PATH_COUNT=2
export DOTTA_PATH_0="file1.txt"
export DOTTA_PATH_1="dir1"
export DOTTA_DRY_RUN=0

# Run hook
~/.config/dotta/hooks/pre-add
```

## Example Workflows

### Workflow 1: Backup Before Apply

```bash
# pre-apply
#!/usr/bin/env bash
set -euo pipefail

backup_dir="$HOME/.dotta-backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"

# Back up every home/ file the profiles being applied claim, as it stands now:
# Git lists each profile's names, which dotta passes through
for profile in $DOTTA_PROFILE; do
    dotta git ls-tree -r --name-only "$profile" -- home/
done | sed 's|^home/||' | sort -u > "$backup_dir.list"
rsync -a --files-from="$backup_dir.list" ~ "$backup_dir/" || true
```

### Workflow 2: Push on Add

```bash
# post-add
#!/usr/bin/env bash
set -euo pipefail

# dotta committed the add to the profile's branch itself; publish it
dotta sync -p "$DOTTA_PROFILE"
```

### Workflow 3: Secret Detection

```bash
# pre-add
#!/usr/bin/env bash
set -euo pipefail

# Iterate through all paths using indexed variables: each is a file or a
# directory, and grep -r reads a file and every file beneath a directory alike
for ((i=0; i<DOTTA_PATH_COUNT; i++)); do
    var_name="DOTTA_PATH_$i"
    path="${!var_name}"

    if grep -rqiE '(api[_-]?key|password|secret|token)' "$path"; then
        echo "ERROR: Potential secret in $path" >&2
        exit 1
    fi
done
```

### Workflow 4: Service Reload

```bash
# post-apply
#!/usr/bin/env bash
set -euo pipefail

# Reload systemd user services
for service in my-app my-other-app; do
    if systemctl --user is-active "$service" &>/dev/null; then
        systemctl --user reload "$service"
    fi
done
```

## Troubleshooting

### Hook Not Running

1. **Verify file exists and is executable** — dotta warns of a hook it ignored,
   naming why, and of a hooks directory it cannot search:
   ```bash
   ls -la ~/.config/dotta/hooks/
   ```

2. **Test manually:**
   ```bash
   bash -x ~/.config/dotta/hooks/pre-apply
   ```

### Hook Failing

1. **Check exit code:**
   ```bash
   ~/.config/dotta/hooks/pre-apply
   echo $?  # Should be 0 for success
   ```

2. **Add debug output:**
   ```bash
   # At top of script
   set -x  # Print all commands
   ```

3. **Check logs:**
   ```bash
   dotta apply --verbose 2>&1 | tee dotta.log
   ```

## Advanced Topics

### Hook Chains

Run multiple scripts per hook:

```bash
#!/usr/bin/env bash
# post-apply
set -euo pipefail

hook_dir="$(dirname "$0")/post-apply.d"

if [[ -d "$hook_dir" ]]; then
    for script in "$hook_dir"/*.sh; do
        [[ -x "$script" ]] && "$script"
    done
fi
```

### Conditional Hooks

Run different logic based on profile:

```bash
#!/usr/bin/env bash
# post-apply
set -euo pipefail

case "$DOTTA_PROFILE" in
    work)
        # Work-specific post-apply
        ;;
    personal)
        # Personal post-apply
        ;;
esac
```

### Async Hooks

Run time-consuming tasks in background. Dotta waits for the hook
itself, never for what it leaves running: the command goes on once the
hook exits, and the task runs on. What the task prints after the hook
has exited is shown nowhere, so send it to a log of its own:

```bash
#!/usr/bin/env bash
# post-apply
set -euo pipefail

# Start long-running task in background, its output in a log of its own
{
    sleep 2
    update_vim_plugins
} >> "$HOME/.local/state/dotta/hook.log" 2>&1 &

# Continue immediately
echo "Background task started"
exit 0
```

## See Also

- Main configuration: `etc/config.example.toml`
- Hook samples: `etc/hooks/*.sample`
- Hooks in the configuration guide: `docs/configuration.md` (Hooks)
