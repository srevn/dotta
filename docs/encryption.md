# Encryption

Dotta supports transparent file encryption for sensitive dotfiles. Files are encrypted at rest in Git and decrypted automatically during deployment.

For the cryptographic design details, see [Encryption Specification](encryption-spec.md).

## Setup

Enable encryption in `~/.config/dotta/config.toml`:

```toml
[encryption]
enabled = true
```

## Adding Encrypted Files

Three modes of encryption:

```bash
# Explicit: force encryption for a file
dotta add global ~/.ssh/id_rsa --encrypt

# Auto-encrypt: based on config patterns (see below)
dotta add global ~/.ssh/id_ed25519  # Encrypted automatically if pattern matches

# Override: skip auto-encryption for a specific file
dotta add global ~/.aws/config --no-encrypt
```

## Auto-Encrypt Patterns

Configure glob patterns to automatically encrypt matching files:

```toml
[encryption]
auto_encrypt = [
    ".ssh/id_*",           # SSH private keys
    ".gnupg/*",            # GPG keys
    "*.key",               # Generic key files
    ".aws/credentials",    # AWS credentials
    ".netrc",              # Network credentials
]
```

**Pattern syntax:**
- Patterns without `/` match the basename at any depth (`*.key` matches `dir/api.key`)
- Patterns with `/` match the full path from the storage root (`.ssh/id_*` matches only `.ssh/id_rsa`)
- Wildcards: `*` (any chars), `?` (single char), `[abc]` (character class)

## Key Management

Dotta uses a single passphrase to derive encryption keys for all profiles.

```bash
# Set passphrase (caches for the session)
dotta key set

# Check status (encryption config, cache expiry, encrypted file count)
dotta key status
dotta key status -v   # Detailed view with auto-encrypt patterns

# Clear cached passphrase
dotta key clear
```

### Session Caching

After entering your passphrase, the derived key is cached both in memory and on disk (`~/.cache/dotta/session`). This avoids repeated prompts across commands.

Configure the cache timeout in `config.toml`:

```toml
[encryption]
session_timeout = 3600   # 1 hour (default)
# session_timeout = 0    # Always prompt (no caching)
# session_timeout = -1   # Never expire
```

The file cache is machine-bound (tied to hostname + username), tamper-evident, and auto-expires.

### Passphrase Sources (priority order)

1. File cache (if valid and not expired)
2. Memory cache (within current process)
3. `DOTTA_ENCRYPTION_PASSPHRASE` environment variable (with security warning)
4. Interactive prompt (stdin, echo disabled)

## Deployment

Encrypted files are decrypted transparently during `apply`:

```bash
dotta key set     # Cache passphrase once
dotta apply       # Encrypted files are decrypted and deployed
dotta show home/.ssh/id_rsa  # Decrypted on display too
```

## Work Factor

A single parameter controls the cost of passphrase-to-key derivation:

```toml
[encryption]
memlimit = 8       # Memory cost in MB (must be a power of two)
```

**`memlimit`** -- Memory hardness via balloon hashing (in MB, power of two):
- `1` -- ~30 ms (CI/test only)
- `8` -- ~600 ms (recommended default)
- `16` -- ~1.2 s (extra margin)
- `32` -- ~2.5 s (uncomfortable interactively)

Memory hardness bounds attacker parallelism by RAM rather than CPU cores, which is what scales against GPU/ASIC brute-force. Higher values raise per-guess cost linearly with memory budget.

**Important:** `memlimit` must be identical across all machines that share the same encrypted profiles. Different values produce different keys from the same passphrase, causing decryption failures. Non-power-of-two values fail validation.

## Security Properties

- **Memory-hard key derivation** -- balloon hashing resists GPU/ASIC brute-force attacks
- **Deterministic AEAD** -- same file + key produces identical ciphertext (Git-friendly)
- **Path-bound** -- files are cryptographically tied to their storage path
- **Per-profile key isolation** -- each profile derives its own encryption key
- **Nonce-misuse resistant** -- no random IVs to manage
- **40 bytes overhead** per encrypted file (8-byte header + 32-byte MAC)
