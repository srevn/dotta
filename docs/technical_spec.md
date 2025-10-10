# Declarative Profile Dotfile Manager  - Technical Specification

# Project name : `dotta`

## Purpose

Manage dotfiles and system configuration files across multiple machines with different operating systems using git orphan branches as independent configuration profiles.

**Core principle**: Files are stored with location prefixes (`home/`, `root/`) in isolated profile branches, then deployed to their actual filesystem locations on demand, with a strong emphasis on safety, predictability, and robustness.

## Architecture

### Repository State

- **Main Worktree:** The main worktree `HEAD` must always point to the `dotta-worktree` branch. This is a core assumption for all operations. The tool will verify this state before executing commands.
- **Profile Branches:** Orphan branches (no shared history) that contain the configuration files.
- **`dotta-worktree` Branch:** An empty branch that serves as a clean anchor for the main worktree, preventing git status pollution from deployed files.

### Profile Layering and Precedence

Profiles are applied in a specific order, with files from later profiles overwriting files from earlier ones.

1.  **Auto-detected profiles**: `global` → OS-specific (`darwin`, `linux`) → host-specific (`hosts/<name>`)
2.  **Manually specified profiles**: The order on the command line determines precedence. In `dotta apply profile-A profile-B`, `profile-B` will override `profile-A`.

### Repository Structure

```
.git/
├── refs/heads/
│   ├── dotta-worktree     # Empty branch - main worktree anchor
│   ├── global             # Base configuration (all systems)
│   ├── darwin             # macOS-specific
│   ├── linux              # Linux-specific
│   ├── freebsd            # FreeBSD-specific
│   └── hosts/<name>       # Per-machine configuration
└── worktrees/
    └── <temp>/            # Temporary worktrees for operations
```

**Profile branches**: Orphan branches (no shared history)
**Main worktree**: Always on `yadm-worktree` (empty) - prevents git status pollution

### File Storage Model

Files stored with deployment prefix:

```
Profile branch "darwin":
  home/.config/fish/config.fish      → deploys to: $HOME/.config/fish/config.fish
  home/.bashrc                       → deploys to: $HOME/.bashrc
  root/usr/local/etc/apcupsd.conf   → deploys to: /usr/local/etc/apcupsd.conf
```

**Prefix rules**:
- Path starts with `$HOME` → store as `home/<relative_path>`
- Absolute path → store as `root/<relative_path>`


## Core Operations

### 1. Add Files to Profile

**Command**: `dotta add <profile> <path>...`

**Algorithm**:
```
1. Verify main worktree is on dotta-worktree branch.
2. Create temporary worktree.
3. If profile branch exists:
     Checkout profile in temp worktree.
   Else:
     Create orphan branch in temp worktree.
4. For each source path:
     If path is a symbolic link, create a git symlink object.
     Determine prefix (home/ or root/).
     Copy source → temp_worktree/<prefix>/<relpath>.
     Stage file (git_index_add_bypath).
5. Commit in temp worktree.
6. Cleanup temp worktree.
```

### 2. Apply Profiles

**Command**: `dotta apply [--force] [--prune] [<profile>...]`

**Algorithm**:
```
1. Verify main worktree is on dotta-worktree branch.
2. Determine profiles to apply and their precedence order.
3. Build a manifest of all files to be deployed from the profiles.

4. Pre-flight Check 1: Detect Profile Overlaps
   If the same file path exists in multiple profiles being applied:
     Issue a warning listing the overlapping files.
     Clearly state the precedence order that will be used.
     (Optional: A strict mode could abort here).

5. Pre-flight Check 2: Detect Local Modifications
   For each file in the manifest:
     Check status against the deployed file on disk.
     If file is locally modified and --force is NOT specified:
       Abort and report all conflicts to the user.

6. Pre-flight Check 3: Check Permissions & Paths
   For each file in the manifest:
     Verify that the destination directory exists and is writable.
     If not, abort and report all permission/path errors.

7. Execution:
   For each file in the manifest (respecting precedence):
     Deploy the file or symlink.
     Preserve executable bit permission.

8. State & Pruning:
   After a successful apply, save the manifest of deployed files to a state file (e.g., .git/dotta-state.json).
   If --prune is specified:
     Compare the new manifest with the previously saved state.
     Remove any files from the filesystem that were in the old state but not in the new one.
```

### 3. Clean Untracked Files

**Command**: `dotta clean [--dry-run]`

**Purpose**: Detects and removes deployed files that are no longer tracked by any of the auto-detected profiles.

**Algorithm**:
```
1. Determine the set of files that SHOULD be present by analyzing the auto-detected profiles (global, os, host).
2. Load the last known deployment state from .git/dotta-state.json.
3. Identify files that are in the state file but not in the set of files that should be present.
4. If --dry-run, print the list of files that would be removed.
5. Otherwise, prompt the user for confirmation and then remove the files.
```

### 4. Diff

**Command**: `dotta diff [--profile <name>] [<path>]`

### 5. Clone

**Command**: `dotta clone <url>`

**Algorithm**:
```
1. Clone repository (git_clone).
2. For each remote branch, create a local tracking branch.
3. Create dotta-worktree branch with an empty tree.
4. Checkout dotta-worktree.
5. Display usage instructions.
```

### 6. Pull

**Command**: `dotta pull`

**Algorithm**:
```
1. Verify main worktree is on dotta-worktree branch.
2. Enumerate local profile branches.
3. For each branch:
     git_remote_fetch().
     Attempt git_merge(FASTFORWARD_ONLY, local, remote).
     If merge fails (diverged history):
       Report descriptive error for that branch and continue.
       Suggest manual resolution (e.g., rebase).
4. Report updates.
```

### 7. Push

**Algorithm**:
```
1. Enumerate local branches (except yadm-worktree)
2. For each branch:
     git_push(refs/heads/<branch>:refs/heads/<branch>)
3. Report which branches pushed
```

## Data Structures

### Profile

```c
typedef struct {
    char *name;              // "global", "darwin", "hosts/laptop"
    git_reference *ref;      // refs/heads/<name>
    git_tree *tree;          // Tree object for this profile
} profile_t;
```

**Command**: `dotta push`

## Filesystem Object Handling

This section details how different types of filesystem objects are managed.

### Regular Files
- **Storage**: Stored as standard git blobs.
- **Permissions**: Only the executable bit is tracked by git and preserved on `apply`. For files requiring other specific permissions (e.g., `0600`), a `post-apply` hook should be used.

### Symbolic Links
- **`add`**: If the source path is a symlink, its target path is stored in a git blob marked as a symlink.
- **`apply`**: If a tree entry is a symlink, `dotta` creates a symlink on the filesystem pointing to the stored target. It will overwrite an existing file or symlink at that path.
- **`status`**: Compares the deployed symlink's target path with the target path stored in the profile.

### Empty Directories
- **Limitation**: Git does not track empty directories.
- **Workaround**: To track an empty directory, place a `.gitkeep` file inside it and `dotta add` that file. The `apply` operation will then ensure the directory is created.

## Path Handling

### Prefix Detection
- `PREFIX_HOME`: Path is within `$HOME`.
- `PREFIX_ROOT`: Path is an absolute path outside `$HOME`.

### Storage Path Construction
- `/home/user/.bashrc` → `home/.bashrc`
- `/etc/hosts` → `root/etc/hosts`

### Deployed Path Extraction
- `home/.bashrc` → `/home/user/.bashrc`
- `root/etc/hosts` → `/etc/hosts`

## Worktree Management

### Temporary Worktree Pattern

```c
typedef struct {
    char *path;              // /tmp/yadm-XXXXXX
    git_worktree *worktree;  // libgit2 worktree handle
    git_repository *repo;    // Repository within worktree
} temp_worktree_t;

// Uses a temporary directory like /tmp/dotta-XXXXXX
temp_worktree_t *create_temp_worktree(git_repository *repo) {
    char path_template[] = "/tmp/yadm-XXXXXX";
    char *path = mkdtemp(path_template);

    git_worktree *wt;
    git_worktree_add(&wt, repo, "temp", path, NULL);

    git_repository *wt_repo;
    git_repository_open_from_worktree(&wt_repo, wt);

    temp_worktree_t *tw = malloc(sizeof(temp_worktree_t));
    tw->path = strdup(path);
    tw->worktree = wt;
    tw->repo = wt_repo;

    return tw;
}

void cleanup_temp_worktree(temp_worktree_t *tw) {
    git_repository_free(tw->repo);
    git_worktree_prune(tw->worktree, GIT_WORKTREE_PRUNE_VALID);
    recursive_rmdir(tw->path);
    free(tw->path);
    free(tw);
}
```

### Orphan Branch Creation in Worktree

```c
void create_orphan_branch(git_repository *wt_repo, const char *branch_name) {
    // Create empty tree
    git_treebuilder *tb;
    git_treebuilder_new(&tb, wt_repo, NULL);
    git_oid tree_id;
    git_treebuilder_write(&tree_id, tb);
    git_treebuilder_free(tb);

    // Create reference
    git_reference *ref;
    git_reference_create(&ref, wt_repo,
                        format("refs/heads/%s", branch_name),
                        &tree_id, 1, NULL);

    // Set HEAD
    git_repository_set_head(wt_repo, format("refs/heads/%s", branch_name));

    // Clear index
    git_index *index;
    git_repository_index(&index, wt_repo);
    git_index_clear(index);
    git_index_write(index);
    git_index_free(index);
}
```

## Profile Detection

### Auto-detect Active Profiles

```c
typedef struct {
    char *global;     // Always "global"
    char *os;         // "darwin", "linux", "freebsd"
    char *hostname;   // "hosts/<hostname>"
} auto_profiles_t;

auto_profiles_t detect_auto_profiles(void) {
    auto_profiles_t profiles;

    // Always include global
    profiles.global = "global";

    // Detect OS
    struct utsname uts;
    uname(&uts);

    char *os_lower = tolower_str(uts.sysname);
    profiles.os = os_lower;  // "Darwin" → "darwin"

    // Detect hostname
    profiles.hostname = format("hosts/%s", uts.nodename);

    return profiles;
}
```

## File Comparison

### Compare Git Blob with Disk File

```c
typedef enum {
    CMP_EQUAL,
    CMP_DIFFERENT,
    CMP_MISSING
} file_cmp_result_t;

file_cmp_result_t compare_blob_to_disk(
    git_repository *repo,
    const git_oid *blob_id,
    const char *disk_path
) {
    // Check if file exists
    if (access(disk_path, F_OK) != 0) {
        return CMP_MISSING;
    }

    // Load git blob
    git_blob *blob;
    git_blob_lookup(&blob, repo, blob_id);
    const void *blob_data = git_blob_rawcontent(blob);
    size_t blob_size = git_blob_rawsize(blob);

    // Load disk file
    FILE *fp = fopen(disk_path, "rb");
    fseek(fp, 0, SEEK_END);
    size_t disk_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (blob_size != disk_size) {
        fclose(fp);
        git_blob_free(blob);
        return CMP_DIFFERENT;
    }

    void *disk_data = malloc(disk_size);
    fread(disk_data, 1, disk_size, fp);
    fclose(fp);

    int result = memcmp(blob_data, disk_data, blob_size);

    free(disk_data);
    git_blob_free(blob);

    return (result == 0) ? CMP_EQUAL : CMP_DIFFERENT;
}
```

## Security Considerations

### Sensitive Files
- Support `.dottaignore` patterns (via standard `.gitignore` mechanism).
- Integration with `git-crypt` can be used for encrypted profiles.

### Path Validation
- Reject path traversal attempts (`../`) in storage paths.
- Validate all deployed paths resolve to locations under `$HOME` or `/`.
- Check for symlink cycles or malicious symlinks during `apply`.

## Command Reference

```
dotta init
dotta add <profile> <path>...
dotta apply [--force] [--prune] [<profile>...]
dotta clean [--dry-run]
dotta status [--profile <profile>]
dotta diff [--profile <profile>] [<path>]
dotta list [--profile <profile>]
dotta clone <url>
dotta pull
dotta push
dotta branch
dotta log <profile>
dotta show <profile>:<path>
```

## Build & Dependencies

### Dependencies
- **libgit2** (>= 1.5.0)
- **libc**

## Testing Strategy

### Unit Tests

Test individual components:
- Path prefix detection and conversion
- File comparison logic
- Profile detection
- Worktree management


### Platform Tests

Run full test suite on:
- macOS (Darwin)
- Linux (Ubuntu, Fedora)
- FreeBSD

## Performance Considerations

### File Enumeration

For large profiles (1000+ files):
- Use `git_tree_walk()` with callbacks (streaming)
- Don't load all files into memory
- Process one file at a time

### Blob Comparison

- Stream comparison for large files (>10MB)
- Use `mmap()` for disk files when possible
- Short-circuit on size mismatch

### Parallel Operations

Potential parallelization:
- Apply multiple profiles (if no overlapping files)
- Status checks across profiles
- Push/pull multiple branches

## Security Considerations

### File Permissions

- Preserve source file permissions in git
- Restore permissions on apply
- Warn if insufficient permissions for system files

### Sensitive Files

- Support `.yadmignore` patterns
- Integration with git-crypt for encrypted profiles
- Never log file contents in debug output

### Path Validation

- Reject path traversal attempts (`../`)
- Validate all paths are under HOME or root
- Check for symlink attacks


### Integration Tests
```bash
# Test add workflow
dotta init
echo "test" > ~/.testfile
dotta add global ~/.testfile
git --git-dir=.git ls-tree -r global | grep "home/.testfile"

# Test apply workflow
rm ~/.testfile
dotta apply global
test -f ~/.testfile
```

## Future Extensions

### Content Merging
For specific file types (e.g., shell configuration), it may be desirable to merge content instead of overwriting. This could be explored using a strategy involving `.gitattributes` and custom merge drivers, allowing users to define how to combine files from different profiles.

### Encrypted Profiles
```bash
dotta add --encrypt secrets ~/.ssh/config
```

### Hooks
```bash
~/.config/dotta/hooks/post-apply
~/.config/dotta/hooks/pre-add
```

Run custom scripts at lifecycle points.

### Partial Apply

```bash
yadm apply global --only ~/.config/fish/
```

Apply only specific paths from a profile.

### Profile Dependencies
```yaml
# .dotta/manifest.yml
darwin:
  extends: global
```