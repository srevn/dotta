# Dotta Configuration

This directory contains sample configuration files for dotta.

## Quick Start

Copy the sample configuration and customize it:

```bash
mkdir -p ~/.config/dotta
cp etc/config.toml.sample ~/.config/dotta/config.toml
```

Edit the file to customize settings (or use the defaults), then:

```bash
dotta init
```

The sample configuration includes all available options with detailed documentation.
You can comment out sections you don't need - the defaults are sensible for most use cases.

## Configuration File Location

Dotta looks for configuration in this order:

1. **`$DOTTA_CONFIG_FILE`** - Environment variable (highest priority)
2. **`~/.config/dotta/config.toml`** - Default location
3. **Built-in defaults** - If no config file exists

### Example: Using a Custom Config Location

```bash
export DOTTA_CONFIG_FILE=/path/to/my/config.toml
dotta init
```

## Configuration Sections

### `[core]` - Core Settings

Controls fundamental dotta behavior:

- **`repo_dir`** - Where dotta stores profiles (default: `~/.local/share/dotta/repo`)
- **`auto_detect`** - Auto-detect which profiles to apply (default: `true`)
- **`strict_mode`** - Fail on validation errors vs. warn (default: `false`)

### `[profiles]` - Profile Management

Defines how profiles are organized and applied:

- **`order`** - Array of profile names defining application order

**Example:**
```toml
[profiles]
order = ["base", "work", "laptop"]
```

### `[hooks]` - Hook Scripts

Configure pre/post operation hooks:

- **`hooks_dir`** - Directory containing hook scripts (default: `~/.config/dotta/hooks`)
- **`pre_apply`** - Enable pre-apply hook (default: `true`)
- **`post_apply`** - Enable post-apply hook (default: `true`)
- **`pre_add`** - Enable pre-add hook (default: `false`)
- **`post_add`** - Enable post-add hook (default: `false`)

**Hook Scripts:**

Create executable scripts in `hooks_dir`:
- `pre-apply` - Runs before `dotta apply`
- `post-apply` - Runs after `dotta apply`
- `pre-add` - Runs before `dotta add`
- `post-add` - Runs after `dotta add`

### `[security]` - Security Settings

Control security-related behavior:

- **`confirm_destructive`** - Prompt before destructive operations (default: `true`)

### `[ignore]` - Ignore Patterns

Multi-layered file ignore system with 4 levels of precedence:

1. **CLI `--exclude` flags** (highest priority) - One-time, operation-specific
2. **`.dottaignore` file** - Repository-wide, version-controlled
3. **Config `ignore.patterns`** - Personal, machine-specific (below)
4. **Source `.gitignore`** - When adding from git repositories

**Settings:**

- **`patterns`** - Array of personal ignore patterns (gitignore syntax)
- **`file`** - Path to shared `.dottaignore` (default: `.dottaignore`)
- **`respect_gitignore`** - Honor source `.gitignore` files (default: `true`)

**Example:**
```toml
[ignore]
patterns = [
    "*.local",           # Local overrides
    ".vscode/*.json",    # Personal IDE settings
    ".env.personal",     # Personal environment
]
file = ".dottaignore"
respect_gitignore = true
```

**When to Use Each Layer:**

| Layer | Use Case | Example |
|-------|----------|---------|
| CLI `--exclude` | One-time exclusions | `dotta add --profile test . --exclude "*.tmp"` |
| `.dottaignore` | Team-wide rules | Build artifacts, OS files, shared patterns |
| Config patterns | Personal rules | Your IDE settings, machine-specific files |
| Source `.gitignore` | Safety net | Prevents adding files already ignored at source |

### `[output]` - Output Formatting

Control how dotta displays information:

- **`verbosity`** - Output level: `quiet`, `normal`, `verbose`, `debug` (default: `normal`)
- **`color`** - Color output: `auto`, `always`, `never` (default: `auto`)
- **`format`** - Output format: `compact`, `detailed`, `json` (default: `compact`)

**Example for CI/CD:**
```toml
[output]
verbosity = "verbose"
color = "never"
format = "json"
```

## Environment Variables

Override configuration via environment variables:

| Variable | Purpose | Example |
|----------|---------|---------|
| `DOTTA_REPO_DIR` | Override `repo_dir` | `export DOTTA_REPO_DIR=/mnt/shared/dotfiles` |
| `DOTTA_CONFIG_FILE` | Use different config file | `export DOTTA_CONFIG_FILE=/etc/dotta.toml` |

**Priority:** Environment variables take precedence over config file settings.

## Common Configuration Patterns

### Personal Dotfiles

Simple setup for personal use:

```toml
[core]
repo_dir = "~/dotfiles"

[ignore]
patterns = ["*.local", "*.backup"]
```

### Team Environment

Shared dotfiles with personal overrides:

```toml
[core]
repo_dir = "~/company-dotfiles"

[profiles]
order = ["base", "backend", "docker"]

[hooks]
post_apply = true

[ignore]
patterns = [
    ".local/*",      # Personal overrides
    "*.work",        # Work-specific temp files
]
```

### Multi-Machine Sync

Same repo, different profiles per machine:

**Laptop config:**
```toml
[profiles]
order = ["base", "laptop", "gui"]
```

**Server config:**
```toml
[profiles]
order = ["base", "server", "headless"]
```

### CI/CD Pipeline

Non-interactive, machine-readable output:

```toml
[security]
confirm_destructive = false

[output]
verbosity = "verbose"
color = "never"
format = "json"

[hooks]
pre_apply = false
post_apply = false
```

## Configuration Best Practices

### 1. **Start Simple, Add as Needed**

The sample configuration includes all available options, but you don't need to configure everything.
Comment out sections you don't need - the defaults are sensible for most use cases.

### 2. **Use Ignore Layers Appropriately**

- **`.dottaignore`**: Team-wide patterns (version controlled)
- **Config `patterns`**: Personal patterns (not version controlled)
- **CLI `--exclude`**: One-off exclusions

Never put personal patterns in `.dottaignore` - use config `patterns` instead!

### 3. **Profile Ordering Matters**

Later profiles can override earlier ones:

```toml
[profiles]
order = ["base", "desktop", "work"]
# work settings can override base and desktop
```

### 4. **Use Hooks for Automation**

Create hook scripts for common tasks:

- **`post-apply`**: Reload services, restart apps
- **`pre-add`**: Validate file contents, check for secrets
- **`post-add`**: Commit to git, trigger CI/CD

### 5. **Security First**

Always review files before adding:

```bash
dotta add --profile secrets ~/.ssh/config --verbose
# Check what's being added!
```

Consider using strict mode for critical profiles:

```toml
[core]
strict_mode = true
```

## Troubleshooting

### Config Not Loading

Check config file location:

```bash
# Should show your config path
ls ~/.config/dotta/config.toml

# Or check where dotta looks
export DOTTA_CONFIG_FILE=/path/to/config.toml
```

### Syntax Errors

Validate TOML syntax:

```bash
# Test parsing
dotta init --verbose
# Errors will show up if config is malformed
```

Common mistakes:
- Missing quotes around strings: `repo_dir = ~/dotfiles` ❌ → `repo_dir = "~/dotfiles"` ✅
- Wrong array syntax: `patterns = "*.log"` ❌ → `patterns = ["*.log"]` ✅

### Ignore Patterns Not Working

Check pattern syntax:

```bash
# Test with verbose output
dotta add --profile test /path/to/file --verbose
# Shows which files are excluded and why
```

Remember:
- Use forward slashes: `foo/bar` not `foo\bar`
- Directories need trailing slash: `node_modules/`
- Negation requires leading `!`: `!important.log`

## Further Reading

- **Main README**: See project root for overall documentation
- **Ignore System**: See `src/utils/ignore.h` for technical details
- **Hooks**: Create scripts in `~/.config/dotta/hooks/`

## Support

If you encounter issues with configuration:

1. Check this README for common patterns
2. Review `config.toml.sample` for all options
3. Run with `--verbose` flag for detailed output
4. Report issues at: https://github.com/anthropics/dotta/issues
