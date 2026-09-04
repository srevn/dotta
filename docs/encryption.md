# Encryption

Dotta supports transparent file encryption for sensitive dotfiles. Files are encrypted at rest in Git and decrypted on demand during deployment.

For the detailed cryptographic design and invariants, see the [Encryption Specification](encryption-spec.md).

## Setup

Enable encryption in `~/.config/dotta/config.toml`:

```toml
[encryption]
enabled = true
```

The configuration file controls only local client preferences: whether encryption is enabled, glob patterns for automatic encryption, and how long to cache passphrases. Cryptographic parameters (salt and Argon2id work factor) are owned by the repository itself, not by the configuration file.

## The Repository Epoch

Each dotta repository owns its derivation parameters as an immutable **epoch** stored at `refs/dotta/epoch`. The epoch is created once at `dotta init` and holds two blobs:
- `salt` (32 random bytes from the OS CSPRNG)
- `params` (3 bytes: memory cost in MiB and pass count)

The epoch makes every repository a distinct cracking target: precomputation against one repository's passphrase guesses cannot be reused against any other, and every machine that shares the repository derives the identical master key from the same passphrase.

The epoch ref travels with the repository: `dotta clone` fetches it, and `dotta sync` pushes and reconciles it.

### Work Factor (Strength Presets)

The Argon2id work factor is chosen when initializing the repository with `--strength`:

```bash
dotta init --strength fast        # 64 MiB RAM, 3 passes (~250–400 ms)
dotta init --strength balanced    # 256 MiB RAM, 3 passes (~1.0 s, default)
dotta init --strength paranoid    # 1024 MiB RAM, 4 passes (~4–6 s)
```

Memory hardness is the primary wall bounding an attacker's guessing speed: parallelism is constrained by memory bandwidth rather than CPU cores.

Once minted, the epoch is immutable for as long as encrypted files exist. An existing valid epoch is preserved across re-initialization. `dotta key status -v` displays the repository's epoch parameters and the matching preset name.

**Cloning a remote without an epoch.** The epoch ref doubles as the repository's identity marker. A remote that does not advertise `refs/dotta/epoch` is not recognized as a dotta repository, and `dotta clone` refuses it.

## Adding Encrypted Files

Files can be encrypted explicitly or automatically:

```bash
# Explicit: force encryption for a file
dotta add global ~/.ssh/id_rsa --encrypt

# Auto-encrypt: matches a config pattern (see below)
dotta add global ~/.ssh/id_ed25519

# Override: skip auto-encryption for a specific file
dotta add global ~/.aws/config --no-encrypt
```

Plaintext files whose first bytes happen to match dotta's cipher magic (`DOTTA\x09`) cannot be stored as plaintext; dotta refuses them at the store boundary to prevent ambiguity between encrypted and unencrypted blobs.

## Auto-Encrypt Patterns

Glob patterns automatically encrypt matching files when added or updated:

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
- Patterns with `/` match the full path from the mount root (`.ssh/id_*` matches `~/.ssh/id_rsa`, but not `~/backup/.ssh/id_rsa`).
- Wildcards: `*` (any characters), `?` (single character), `[abc]` (character class), `**` (recursive directories).
- `!` negates a prior match.

Patterns match against the path relative to the mount root (see [Ignore Patterns](configuration.md#ignore-patterns)): write `.ssh/id_*` rather than `home/.ssh/id_*`.

## Key Management

A single passphrase derives all encryption keys.

```bash
dotta key set                 # Cache passphrase for the session
dotta key status              # Show cache state, expiry, encrypted file count
dotta key status -v           # Include epoch parameters and auto-encrypt patterns
dotta key clear               # Drop cached key (memory and session file)
```

### The Unlock Proof

Dotta treats the master key not as an unchecked derivation cache, but as **the repository's unlock proof**. A master key enters neither process memory nor disk cache until it has been proven to open repository data:
- When decrypting, a candidate key must successfully authenticate and decrypt the blob in hand.
- In commands that encrypt or set a key (`dotta add`, `dotta key set`), dotta finds a **witness** ciphertext already in the repository and verifies the candidate key against it.
- In a repository with no ciphertext yet, a typed passphrase is confirmed by typing it twice.
- If a passphrase fails verification, it is wiped immediately. At an interactive terminal, dotta allows three attempts (`Wrong passphrase, try again: `).
- Once an attempt fails or no passphrase source is available, the refusal stands for the rest of the process run; dotta will not prompt repeatedly across a workspace of multiple files.

### Command Reach (`CACHED` vs `OBTAIN`)

Commands declare how far they may reach for a passphrase:
- **Reporting commands** (`dotta status`, `dotta sync`, `dotta key status`, `dotta key clear`) operate in `CACHED` mode. They read only what earlier commands left in the cache. They **never prompt**, never read environment variables, and never create a session file. If the cache is cold, encrypted files are reported as `[locked]`.
- **Content operations** (`dotta apply`, `dotta add`, `dotta update`, `dotta diff`, `dotta show`, `dotta export`, `dotta revert`, `dotta key set`) operate in `OBTAIN` mode. If the cache is cold, they will check `DOTTA_ENCRYPTION_PASSPHRASE` or prompt interactively.

### Session Caching

When a passphrase is verified, the master key is held in process memory and saved to an on-disk session file under the user's home directory:

```
~/.cache/dotta/session-<epoch fingerprint, 16 hex>
```

The file is the **epoch's**, not the repository's. Two repositories that each minted their own epoch never contest a file; two checkouts of one repository share one, deliberately — the master is a function of (passphrase, epoch), so there is only one of it to cache. A checkout that adopts a different epoch during `dotta sync` leaves its old file where it stands, for whichever checkout is still on that epoch.

```toml
[encryption]
session_timeout = 3600   # 1 hour (default)
# session_timeout = 0    # Memory-only: cache for the process run, no disk file
# session_timeout = -1   # Never expire
```

**Security model of the session file:**
- The session file is **obfuscated, not encrypted at rest**: the obfuscation key is derived from the repository's public epoch. It protects against casual exposure in directory listings, but anyone with read access to the file and the repository can recover the master key.
- The file's security rests entirely on POSIX filesystem permissions (mode `0600`) and verification that the file is owned by the invoking user's UID.
- Under `sudo`, dotta resolves the cache directory using the invoker's original user ID and home directory (`identity()->home`), ensuring keys set before invoking `sudo` remain accessible without leaking across users.
- Run `dotta key clear` before lending, transferring, or retiring a machine, and exclude `~/.cache/dotta` from cloud backups.

### Passphrase Sources (priority order)

In `OBTAIN` mode, dotta resolves passphrases in the following order:
1. **In-memory cache**: Process memo from an earlier operation in the same run.
2. **On-disk session file**: When `session_timeout != 0`, matching the repository epoch, unexpired, and authentic.
3. **Environment variable**: `DOTTA_ENCRYPTION_PASSPHRASE`.
4. **Interactive TTY prompt**: Terminal prompt with echo disabled (signal-safe terminal restore).

## Understanding Status Tags

In commands like `dotta status`, `dotta update`, and `dotta apply`, files that cannot be verified are categorized by the remedy that resolves them:

```
$ dotta status
Workspace status
  Invalid - workspace has paths dotta could not verify

Unverifiable paths (1 item) (dotta could not verify these paths)

  [locked] /home/you/.ssh/id_ed25519 (from global)

  [locked] - encrypted, and no key opened it; 'dotta key set' unlocks it
```

| Tag | Meaning | Remedy |
|---|---|---|
| `[locked]` | File is encrypted, but no valid key is currently cached (or encryption is disabled over a sealed file). | Run `dotta key set` to authenticate. |
| `[unreadable]` | Filesystem permissions prevented reading the file. | Run under `sudo` or adjust permissions. |
| `[unverified]` | A held key did not open this blob, or nothing ever could: a tampered file, a foreign epoch, an unsupported version, or an I/O error. | Run the verb that touches it (`dotta show`, `dotta export`) to view the cause. |

A wrong passphrase reads `[locked]`, not `[unverified]`. It leaves the run holding no key at all — one fact for every encrypted row, and one `dotta key set` settles them — where `[unverified]` is a key in hand that this one blob refuses, which is the blob's own problem.

Dotta names no single remedy for `[unverified]` because there is none. The command that actually touches the file prints the reason:

```
$ dotta show global:home/.ssh/id_ed25519
Error: Failed to get file content
  Caused by: Cannot decrypt 'home/.ssh/id_ed25519'
  Caused by: No passphrase: End of input; set DOTTA_ENCRYPTION_PASSPHRASE, or run 'dotta key set' at a terminal
```

`dotta apply` skips locked paths and deploys the rest; `dotta update` skips them; `dotta diff` shows the row with its status line and no hunk.

## Passphrase and Strength Rotation

### Changing the Passphrase

There is no rotation command, and there is no way to keep existing ciphertext: every blob is sealed under the current passphrase, so changing it means re-sealing every one of them.

A new passphrase cannot be installed while old ciphertext stands: `dotta key set` verifies against the repository — inspecting every profile branch and its **full Git history** — and refuses a passphrase that opens nothing. Removing a file from a profile's tip is not enough, because its blob remains reachable through historical commits. Moving to a new passphrase means dropping the branches holding that history:

```bash
dotta apply                                # last chance under the OLD passphrase:
                                           #   the plaintext lands on disk
dotta remove <profile> --delete-profile    # every profile whose history holds ciphertext
dotta key clear
dotta key set                              # the NEW passphrase: with nothing left to
                                           #   verify against, it is confirmed by typing twice
dotta add <profile> <files> --encrypt      # re-sealed
```

A repository must keep at least one profile, so if the only profile is the encrypted one, create another (`dotta add <other> <some file>`) before deleting it.

The epoch does not change here — the salt and work parameters belong to the repository, not to the passphrase. Only the ciphertext has to go.

### Changing Repository Strength (Minting a New Epoch)

Argon2id parameters belong to the repository epoch, and the epoch is immutable while ciphertext sealed under it exists. A new strength is a new epoch:

```bash
dotta apply                                # plaintext on disk under the old epoch
dotta remove <profile> --delete-profile    # every profile whose history holds ciphertext
dotta git update-ref -d refs/dotta/epoch
dotta init --strength paranoid
dotta add <profile> <files> --encrypt
```

The order matters. `dotta init` refuses to mint an epoch while any encrypted file is still reachable through Git history, preventing accidental permanent data loss:

```
$ dotta init --strength paranoid
Error: Repository epoch 'refs/dotta/epoch' is missing and encrypted files depend on it

Minting a new one would seal every encrypted file in this repository away permanently. Restore the ref instead:
  dotta git fetch origin '+refs/dotta/*:refs/dotta/*'
or copy it from a machine that still has this repository.
```

That refusal is the safety net for the accident this procedure resembles — a deleted or lost epoch ref, where the remedy is to restore it, not to mint. The refspec is forced (`+`) because an epoch commit is an orphan: over a ref that is present but damaged, a plain fetch is rejected as non-fast-forward and restores nothing. `dotta remove` needs no key and works either way. Naming a `--strength` that an existing epoch does not match is refused rather than silently ignored, and an existing valid epoch is always preserved.

## Security Properties

- **Memory-hard key derivation** — Argon2id (RFC 9106) with bounded memory and pass counts.
- **Deterministic AEAD** — Identical `(passphrase, profile, path, plaintext)` produces byte-identical ciphertext (v9), enabling Git delta deduplication and clean diffs.
- **Path-bound authentication** — Files are authenticated against their storage path; moving a blob to a different path causes decryption to fail.
- **Per-profile isolation** — Domain-separated subkeys derived via keyed BLAKE2b (`dot-mac\0`, `dot-prf\0`).
- **Epoch binding** — Each cipher blob header embeds an 8-byte BLAKE2b fingerprint of the repository epoch.
- **Nonce-misuse resistance** — Synthetic IV (SIV) derived from MAC over header, path, and plaintext; no random nonces to exhaust.
- **Memory isolation** — Passphrase buffers, Argon2 work areas, and key manager slots reside in dedicated anonymous mappings (`secure_alloc`) that are `mlock`ed, excluded from core dumps (`MADV_DONTDUMP`), and erased via volatile memory wipes (`secure_wipe`). Core dumps are disabled globally (`RLIMIT_CORE = 0`).
- **Fixed overhead** — Exactly 46 bytes overhead per encrypted file (14-byte authenticated header + 32-byte SIV tag).

## Limitations

- **Plaintext-equality leakage.** Identical plaintexts at the same path produce identical ciphertext; Git history reveals *whether* an encrypted file changed, but not what changed.
- **Storage paths are public.** Paths are stored in plaintext in `.dotta/metadata.json` and in Git tree objects. Encryption protects file contents, not repository structure.
- **Non-ASCII path normalization.** Unicode normalization differences (NFC vs. NFD across macOS and Linux) yield different byte sequences for storage paths, resulting in SIV verification failures. If moving between OS platforms, paths should be normalized.
- **Local interactive access.** A process running with the user's UID (or root) can read keys from process memory or read the obfuscated session file from `~/.cache/dotta/`.
