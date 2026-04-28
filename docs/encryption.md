# Encryption

Dotta supports transparent file encryption for sensitive dotfiles. Files are encrypted at rest in Git and decrypted on demand during deployment.

For the cryptographic design, see [Encryption Specification](encryption-spec.md).

## Setup

Enable encryption in `~/.config/dotta/config.toml`:

```toml
[encryption]
enabled = true
```

## Repository Salt

Each dotta repository has its own 32-byte Argon2id salt, generated automatically at `dotta init`. The salt makes every dotta repository a distinct cracking target: a precomputation table built against one repo's passphrase guesses cannot be reused against any other.

The salt lives at `refs/dotta/salt:salt` and travels with the repository — `dotta clone` fetches it, `dotta sync` pushes it. There is nothing to configure or remember; the salt is public, machine-portable, and managed entirely by dotta.

**Recovery story.** Backing up your repository plus your passphrase is sufficient to recover plaintext on any machine. The repository carries the salt; the passphrase is the only secret. (Hostname binding via Argon2 `extras.ad` would have broken this property and is intentionally not used.)

**Cloning a remote without a salt.** If you `dotta clone` a remote that was never `dotta init`ed (or predates per-repo salts), you'll see a warning at clone time:

```
Warning: Remote does not advertise refs/dotta/salt. Encryption operations
will fail until the ref is fetched or 'dotta init' is run locally.
```

Encryption-disabled use of the clone still works. To use encryption in such a clone, run `dotta init` locally to generate the salt — but understand that any encrypted blobs already on the remote were sealed under a different (or no) salt and will not decrypt.

## Adding Encrypted Files

Three modes:

```bash
# Explicit: force encryption for a file.
dotta add global ~/.ssh/id_rsa --encrypt

# Auto-encrypt: matches a config pattern (see below).
dotta add global ~/.ssh/id_ed25519

# Override: skip auto-encryption for a specific file.
dotta add global ~/.aws/config --no-encrypt
```

## Auto-Encrypt Patterns

Glob patterns automatically encrypt matching files:

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

**Pattern syntax** (gitignore semantics):

- Patterns without `/` match basename at any depth (`*.key` matches `dir/api.key`).
- Patterns with `/` match the full path from the storage root (`.ssh/id_*` matches only `.ssh/id_rsa`, not `backup/.ssh/id_rsa`).
- Wildcards: `*` (any chars), `?` (single char), `[abc]` (character class), `**` (recursive).
- `!` negates a prior match.

The storage prefix (`home/`, `root/`) is stripped before matching, so write `.ssh/id_*` rather than `home/.ssh/id_*`.

## Key Management

A single passphrase derives all encryption keys.

```bash
dotta key set                 # Cache passphrase for the session
dotta key status              # Show cache state, expiry, encrypted file count
dotta key status -v           # Include auto-encrypt patterns
dotta key clear               # Drop cached key (memory + disk)
```

### Session Caching

After the passphrase is entered, the derived master key is cached both in process memory and on disk (`~/.cache/dotta/session`) so subsequent commands do not re-prompt.

```toml
[encryption]
session_timeout = 3600   # 1 hour (default)
# session_timeout = 0    # Always prompt (also disables on-disk cache)
# session_timeout = -1   # Never expire
```

The on-disk cache is **machine-bound** (XOR-obfuscated under a key derived from hostname + username, MAC-authenticated). It defends against casual inspection and cross-machine copy, **not** against a local attacker who reads the file: with the cache plus the host's hostname/username, the master key is recoverable without the passphrase. Run `dotta key clear` before lending or retiring a machine, and exclude `~/.cache/dotta` from cloud-synced backups.

### Passphrase Sources (priority order)

1. In-memory cache (current process).
2. On-disk session cache (when `session_timeout != 0`, MAC-valid, not expired).
3. `DOTTA_ENCRYPTION_PASSPHRASE` environment variable (with stderr advisory — env vars leak via `ps(1)` and child-process inheritance).
4. Interactive TTY prompt (echo disabled).

## Deployment

Encrypted files are decrypted transparently:

```bash
dotta key set       # Cache passphrase once
dotta apply         # Encrypted files decrypted and deployed
dotta show home/.ssh/id_rsa
```

## Work Factor

The Argon2id key derivation is configured by a strength preset. Memory hardness is the only attacker-bounding work — an attacker's parallelism is bounded by RAM bandwidth, not CPU cores.

```toml
[encryption]
strength = "balanced"   # Default
```

| Preset      | Memory  | Passes | Wall-clock     |
|-------------|---------|--------|----------------|
| `fast`      |   64 MiB|   3    | ~250–400 ms    |
| `balanced`  |  256 MiB|   3    | ~1.0 s         |
| `paranoid`  | 1024 MiB|   4    | ~4–6 s         |

Raw overrides (advanced; both must be set together, ignore `strength`):

```toml
argon2_memory_mib = 256   # bounds: 8..4096
argon2_passes     = 3     # bounds: 1..20
```

The chosen params are **recorded inside every encrypted blob's header**, so `dotta apply` can decrypt files sealed under an older preset even after you change the setting. Workflows that interleave files at different presets re-prompt on each transition (single-slot cache). To converge on one preset, re-encrypt old files with `dotta remove` + `dotta add` after the change.

## Passphrase Rotation

There is no automated rotation command. To change the passphrase:

```bash
dotta key clear                          # Drop the old key
dotta apply                              # Decrypt + redeploy under the old passphrase
                                         # (last chance; the prompt uses the OLD passphrase)
# Re-add every encrypted file under the new passphrase:
dotta key set                            # Enter NEW passphrase
dotta remove <file> && dotta add <file>  # Per encrypted file
```

A premature `dotta key set <new>` followed by `dotta apply` leaves files encrypted under the old passphrase **unrecoverable**.

## Security Properties

- **Memory-hard derivation** — Argon2id (RFC 9106).
- **Deterministic AEAD** — same `(passphrase, profile, path, plaintext)` produces byte-identical ciphertext (Git deduplication, meaningful diffs).
- **Path-bound authentication** — files are cryptographically tied to their storage path; renaming requires re-encryption.
- **Per-profile isolation** — domain-separated subkeys per profile.
- **Nonce-misuse resistant** — synthetic IV is plaintext-derived; no random IVs to manage.
- **41 bytes overhead** per encrypted file (9-byte header + 32-byte SIV).

## Limitations

- **Plaintext-equality leakage.** Identical plaintexts at the same path produce identical ciphertext; Git history reveals **whether** an encrypted file changed, not what changed. Files whose change cadence itself is sensitive (e.g. frequently-rotated tokens) are a poor fit for this model.
- **Storage paths are public.** Path strings appear in `.dotta/metadata.json` and as Git tree entries. Encryption hides content, not structure.
- **Non-ASCII paths are not portable across normalization-divergent machines.** Unicode NFC vs. NFD path bytes produce distinct SIVs and therefore distinct ciphertext. If you encrypt on one machine and decrypt on another and receive an authentication failure, the path bytes likely differ; remove the file and re-add on the target machine.
- **Local interactive compromise is out of scope.** A process running as the dotta user (or root) can read the master key from process memory while cached, and from `~/.cache/dotta/session` in obfuscated form.
