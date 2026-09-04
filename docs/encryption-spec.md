# Encryption Technical Specification

## Overview

Dotta encrypts sensitive dotfiles transparently so they can be stored in a Git repository without exposing their contents. Files are encrypted at rest in Git and decrypted only when deployed to the filesystem.

**Design goals:**

- **Deterministic AEAD** — identical `(passphrase, profile, path, plaintext)` produces byte-identical ciphertext (v9). Git deduplicates, history is meaningful.
- **Path-bound authentication** — ciphertext is cryptographically tied to its storage path; a file moved to a different path cannot be decrypted.
- **Nonce-misuse resistant** — Synthetic-IV (SIV) construction; no random nonces to manage.
- **Single passphrase UX** — one passphrase covers every profile. Per-profile subkeys are derived deterministically.
- **Epoch-anchored derivation** — the repository owns all derivation inputs (salt and work factor parameters) in an immutable epoch ref; derivation is a function of `(passphrase, epoch)` alone.
- **The unlock proof** — master keys enter memory and session caches only after successfully opening repository ciphertext or being confirmed twice.
- **Session caching** — master key cached in memory and in an epoch-dedicated session file for a configurable timeout.

## Threat model

### Mitigated

- **Passive repository compromise.** An attacker who exfiltrates the Git repository (clone, disk image, backup) cannot recover plaintext without the passphrase. Brute-force resistance is bounded by Argon2id memory hardness × passphrase entropy against the repository's unique 256-bit salt.
- **Active tampering of encrypted blobs.** Modifying any byte of the magic, version, epoch fingerprint, SIV, or ciphertext fails SIV verification. The candidate plaintext is wiped before return; the error is a uniform "authentication failed" diagnostic.
- **Path confusion.** A blob encrypted for `home/.ssh/id_rsa` cannot decrypt as `home/.bashrc`. The storage path is absorbed into the SIV scope byte-for-byte.
- **Cross-profile contamination.** Per-profile subkeys are derived deterministically from `(master_key, profile_name)` under domain-separated tags; compromise of one profile's `(mac_key, prf_key)` pair leaks nothing about another's without the master key.
- **Epoch and version confusion.** The 14-byte header (`"DOTTA" || 0x09 || epoch_fp[8]`) is the first input absorbed into the SIV. A blob forged with a different version or relabelled to another epoch fails MAC verification. Foreign-epoch blobs are rejected up front by `keymgr_decrypt` before prompting.
- **Argon2-params tampering.** Parameters are stored in the signed repository epoch ref (`refs/dotta/epoch`), validated at load/fetch, and bound into the epoch fingerprint. Cipher blobs do not carry parameters, preventing remote-controlled DoS or parameter degradation.
- **Memory scraping and core dumps.** Sensitive buffers (passphrases, Argon2 work areas, keymgr slots) live in locked memory (`secure_alloc`) excluded from core dumps via `MADV_DONTDUMP`. Process core dumps are disabled globally (`RLIMIT_CORE = 0`).

### Not mitigated

- **Local interactive compromise.** A process running with the user's UID (or root) can read the master key from process memory while cached, or from `~/.cache/dotta/session-<epoch_fp>` in obfuscated form (see *Session cache*).
- **Weak passphrases.** Argon2id raises the per-guess wall but does not save short or dictionary-based passphrases.
- **Keyloggers, shoulder-surfing, evil-maid attacks** during passphrase entry.
- **Forensic disk imaging on a live host.** The session cache resists casual inspection and directory listing, not a forensic adversary on the host that wrote it.
- **Plaintext-length leakage.** Stream cipher; ciphertext length = plaintext length + 46-byte overhead. Padding to a fixed boundary would defeat Git deduplication and is not adopted.
- **Storage path leakage.** Paths are recorded in plaintext in `.dotta/metadata.json` and as Git tree entries. Encryption hides content, not repository structure.
- **Plaintext-equality leakage across commits.** Encryption is deterministic; identical inputs produce identical ciphertext. An attacker observing multiple commits learns *whether* an encrypted file at a given path changed, not *what* changed.

### Leakage matrix

| What leaks                            | Brute-force cost                                    | Notes                                                                                    |
|---------------------------------------|-----------------------------------------------------|------------------------------------------------------------------------------------------|
| Repo only                             | Passphrase entropy × Argon2id memory cost           | 256-bit per-repo salt in `refs/dotta/epoch` forecloses cross-installation precomputation; memory hardness is the wall against this specific repository. |
| Plaintext sizes (any leaked repo)     | N/A — leaked unconditionally                        | Stream cipher (46-byte fixed overhead); out of scope by design.                          |
| `~/.cache/dotta/session-*` + repo     | Master key recoverable without passphrase           | Session cache is obfuscation under public epoch bytes. Protection is POSIX permissions (0600) and UID checks. |

For "stolen laptop" / machine transfer exposures the response is `dotta key clear` before lending or retiring the machine, plus exclusion of `~/.cache/dotta` from any backup that already contains the repository.

## Cryptographic foundation

### Monocypher

Dotta uses [Monocypher](https://monocypher.org/), a small auditable C library implementing standard primitives:

| Operation             | Monocypher function                          | Standard                              |
|-----------------------|----------------------------------------------|---------------------------------------|
| Memory-hard KDF       | `crypto_argon2`                              | Argon2id, RFC 9106                    |
| Keyed hash / MAC      | `crypto_blake2b_keyed*`                      | BLAKE2b, RFC 7693                     |
| Stream cipher         | `crypto_chacha20_x`                          | XChaCha20 (RFC 8439 + 24-byte nonce)  |
| Constant-time compare | `crypto_verify32`                            | —                                     |
| Memory clearing       | `crypto_wipe`                                | Doubly-volatile loop                  |

Inside `src/crypto/` the canonical wipe primitive is `crypto_wipe`. Other layers use `secure_wipe` from `base/secure.h` (functionally identical; removes the vendor dependency from non-crypto layers).

### `crypto/mac` chokepoint

Every keyed-BLAKE2b call in the codebase routes through `src/crypto/mac.c`, which provides:

1. **Domain separation.** Each call is tagged with an 8-byte ASCII string absorbed into the keyed BLAKE2b state at init. Adding a new tag requires editing one file with a compile-time uniqueness check.
2. **Canonical LE64 length-prefixed framing.** `crypto_mac_absorb` unconditionally prepends `LE64(len)` to every absorbed input. Distinct sequences produce distinct absorbed byte streams even when the bytes coincide; concatenation-collision attacks are foreclosed at the framing layer.
3. **Audit chokepoint.** A CI grep enforces no direct `crypto_blake2b_keyed*` calls outside `mac.c`.

The 8-byte tag is absorbed *unframed* (fixed-length by construction); all subsequent absorptions ARE LE64-prefixed.

| Tag (`crypto_domain_t`)        | 8-byte value | Purpose                                                  |
|--------------------------------|--------------|----------------------------------------------------------|
| `CRYPTO_DOMAIN_SIV_MAC`        | `dot-mac\0`  | kdf: master + profile → mac_key                          |
| `CRYPTO_DOMAIN_SIV_PRF`        | `dot-prf\0`  | kdf: master + profile → prf_key                          |
| `CRYPTO_DOMAIN_CIPHER_SIV`     | `dot-siv\0`  | cipher: SIV over (header, path, plaintext)               |
| `CRYPTO_DOMAIN_CIPHER_KEY`     | `dot-key\0`  | cipher: keystream-seed from SIV under prf_key            |
| `CRYPTO_DOMAIN_SESSION_MAC`    | `dot-ses\0`  | session: cache MAC over the 76-byte prefix               |

## Key hierarchy

```
        User passphrase (1..1024 bytes)
                    │
                    ▼  Argon2id (RFC 9106)
                       memory_mib, passes from repository epoch
                       lanes = 1 (Monocypher is single-threaded)
                       salt = 32-byte per-repo random in `refs/dotta/epoch:salt`
        ┌────────────────────────────────────────────┐
        │              Master key (32 B)             │
        │    Held as unlock proof in keymgr slot     │
        │    and on-disk epoch session cache         │
        └────────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
  crypto_mac_oneshot        crypto_mac_oneshot
  (master, SIV_MAC,         (master, SIV_PRF,
   profile_name)             profile_name)
        │                       │
        ▼                       ▼
   mac_key (32 B)           prf_key (32 B)
        │                       │
        └───────────┬───────────┘
                    ▼  Consumed by cipher_encrypt / cipher_decrypt
                       for one operation, then wiped before return.
```

**Two derivation tiers**:
1. **Passphrase + Epoch → Master Key**: Argon2id executed once per authenticated run (or restored from the session cache). Memory hardness bounds attacker guessing.
2. **Master Key + Profile Name → Subkeys**: Domain-separated keyed-BLAKE2b calls (`dot-mac\0` and `dot-prf\0`). Performed on demand per operation; the cipher module never sees the master key or the profile name.

| Step                                       | Module       | Primitive                         | Cost (warm) |
|--------------------------------------------|--------------|-----------------------------------|-------------|
| passphrase + epoch → master                | `kdf.c`      | `crypto_argon2`                   | 0 (cached)  |
| master + profile → mac_key                 | `kdf.c`      | `crypto_mac_oneshot`              | µs          |
| master + profile → prf_key                 | `kdf.c`      | `crypto_mac_oneshot`              | µs          |
| (mac_key, header, path, plaintext) → SIV   | `cipher.c`   | `crypto_mac_*` (incremental)      | bandwidth   |
| (prf_key, SIV) → keystream seed            | `cipher.c`   | `crypto_mac_oneshot`              | µs          |
| (seed, SIV[0..24], plaintext) → ciphertext | `cipher.c`   | `crypto_chacha20_x`               | bandwidth   |

### Argon2id parameters

| Preset      | memory_mib | passes | Wall-clock target | memory × passes |
|-------------|------------|--------|-------------------|-----------------|
| `fast`      |    64 MiB  |    3   | ~250–400 ms       | 192 MiB·passes  |
| `balanced`  |   256 MiB  |    3   | ~1.0 s            | 768 MiB·passes  |
| `paranoid`  |  1024 MiB  |    4   | ~4–6 s            |   4 GiB·passes  |

`lanes = 1` is forced by Monocypher's single-threaded implementation. With `lanes = 1`, `memory × passes` is the primary memory-hardness metric.

**Parameter bounds** (enforced by `kdf_validate_params` at `epoch_load` and `epoch_fetch`):
- `memory_mib` ∈ [8, 4096]. The 8 MiB floor is dotta's minimum operational security bound; the 4096 MiB ceiling is an allocation limit defending against hostile refs.
- `passes` ∈ [1, 20].

Parameters do not travel in individual blob headers. They are owned strictly by the repository epoch, preventing attackers from forcing parameter degradation on arbitrary files.

### The Repository Epoch

The derivation parameters and salt constitute an immutable **epoch** stored at `refs/dotta/epoch`.

```
refs/dotta/epoch
  └── commit ("Initialize repository epoch")
        └── tree
              ├── salt   (32 bytes — random salt from OS CSPRNG)
              └── params (3 bytes — LE16 memory_mib ‖ passes)
```

The epoch structure guarantees that every input to key derivation except the passphrase itself has a single, immutable owner:
- **`salt`** (32 bytes): Ensures that every repository presents a unique attack surface. Precomputation built against one repository cannot be reused against another.
- **`params`** (3 bytes): Serialized via `kdf_params_store` (LE16 memory in MiB followed by pass count).
- **`fingerprint`** (8 bytes): Computed as BLAKE2b-8 over `salt ‖ params` (35 bytes). The fingerprint is public identity material embedded in every cipher blob header, allowing key-free readers (such as the ciphertext census or `keymgr_decrypt`'s preflight check) to determine whether a blob belongs to the current repository without prompting for a passphrase.

| Operation                       | Where                                          |
|---------------------------------|------------------------------------------------|
| Minted                          | `dotta init --strength <preset>` via `epoch_init` |
| Loaded & Validated              | `main.c::open_crypto_for_mode` via `epoch_load` |
| Fetched & Reconciled            | `dotta clone` and `dotta sync` via `epoch_fetch` / `epoch_resolve` |
| Inspected (raw)                 | `dotta git show refs/dotta/epoch:salt`, `dotta git show refs/dotta/epoch:params` |
| Inspected (CLI)                 | `dotta key status -v` (prints MiB, passes, and preset name) |

### Sync reconcile

`epoch_resolve` is a pure fact-finder: it connects, lists the remote and compares **commit OIDs** (zero object transfer). The epoch only ever propagates by force-fetch, which copies the exact remote commit, so a converged local ref shares the remote's OID byte-for-byte. Two independently minted epochs hold different random bytes in different commits, hence different OIDs.

| Decision | Condition | `cmd_sync` does |
|---|---|---|
| `EQUAL` | same OID | nothing |
| `ESTABLISH` | remote has none, local is valid | push the ref |
| `NO_LOCAL_EPOCH` | remote has none, local missing or malformed | nothing to publish |
| `ADOPT` | divergent, no reachable ciphertext keyed by the local epoch | force-fetch, then `keymgr_rekey` |
| `CONFLICT` | divergent, local epoch keys reachable ciphertext | warn; plaintext profiles still sync |
| `UNREACHABLE` | transport failure | skip, best-effort |

The census behind `ADOPT` walks the **full history** of every local branch, not just the tips — `dotta show` and `dotta revert` open blobs at any `@commit`, so history-reachable ciphertext pins the epoch exactly as tip ciphertext does. Attribution is by fingerprint: only ciphertext the *local* epoch keys argues against adopting; foreign-keyed blobs argue for converging. The census **fails closed** — any uncertainty lands on `CONFLICT`, never on a data-destroying `ADOPT`.

Two ways the walk could report an absence it had not proved are closed at the walk itself. A revwalk that ends on an unreadable object returns that error instead of reading as a finished history. And a branch listing that does not contain `dotta-worktree` — the one branch every repository holding this ref has — is refused outright, because libgit2's filesystem refdb *skips* a ref it cannot open or parse rather than reporting it, so an unlistable `refs/heads` otherwise yields an empty list and a clean `GIT_ITEROVER`. A listing that lost only some of its refs while the anchor still reads stays Git's limit, stated as one at both headers rather than defended.

`epoch_fetch` is the acquisition boundary: after the force-fetch lands the remote commit, both blobs are validated, and a malformed epoch is rolled back to the prior target (or removed) with `ERR_CRYPTO`. A corrupt remote epoch never persists locally to be mistaken for canonical later.

## SIV construction (cipher format v9)

Implemented in `src/crypto/cipher.c`. SIV deterministic AEAD in the spirit of RFC 5297, built from BLAKE2b (MAC) and XChaCha20 (keystream).

### Encryption

Inputs: `(plaintext, mac_key, prf_key, storage_path, epoch_fp)`.

1. **Build the 14-byte authenticated header:**
   ```
   bytes [0..5)   = "DOTTA"
   byte   [5]     = CIPHER_VERSION (0x09)
   bytes [6..14)  = epoch_fp (BLAKE2b-8 over epoch's 35 bytes)
   ```

2. **Compute the synthetic IV** (32 bytes) over `(header, path, plaintext)`:
   ```
   crypto_mac_init(ctx, mac_key, CRYPTO_DOMAIN_CIPHER_SIV);
   crypto_mac_absorb(ctx, header, 14);                     /* LE64-prefixed */
   crypto_mac_absorb(ctx, storage_path, path_len);         /* LE64-prefixed */
   crypto_mac_absorb(ctx, plaintext, plaintext_len);       /* LE64-prefixed */
   crypto_mac_final(ctx, siv);
   ```

3. **Derive the keystream seed** from the SIV under `prf_key`:
   ```
   seed = crypto_mac_oneshot(prf_key, CRYPTO_DOMAIN_CIPHER_KEY, siv, 32);
   ```
   Keying the seed with `prf_key` keeps the keystream secret; the SIV tag alone is public.

4. **Encrypt** with XChaCha20:
   ```
   crypto_chacha20_x(ciphertext, plaintext, plaintext_len,
                     /*key=*/seed, /*nonce=*/siv[0..24], /*ctr=*/0);
   ```
   Monocypher reads exactly 24 bytes from the nonce pointer; the trailing 8 bytes of the 32-byte SIV serve as additional MAC tag width.

5. **Assemble** `[ header(14) | SIV(32) | ciphertext(N) ]`.

### Decryption

1. **Header parse** via `cipher_read_header`: validates length (≥ 14), magic `"DOTTA"`, and version `0x09`; extracts `epoch_fp`.
2. **Epoch check**: `keymgr_decrypt` verifies `epoch_fp` matches the repository's epoch fingerprint. A mismatch returns `ERR_CRYPTO("Encrypted under a different repository epoch...")` immediately, without prompting for a passphrase.
3. **Derive `seed`** from `(prf_key, stored_siv)` under `CIPHER_KEY`.
4. **Decrypt**: `candidate = ciphertext_body XOR XChaCha20(seed, siv[0..24], 0)`.
5. **Recompute SIV** over `(header || storage_path || candidate)` under `mac_key`.
6. **Constant-time compare** via `crypto_verify32`. On match, transfer the candidate to caller. On mismatch, wipe candidate and return `ERR_CRYPTO("Authentication failed (wrong passphrase, tampered ciphertext, or path mismatch)")`. The candidate is never surfaced.

In SIV, the IV authenticates the plaintext; verification cannot happen before recovery. The candidate is held in a wiped buffer just long enough to verify.

### Determinism rationale

Standard AEAD modes (AES-GCM, ChaCha20-Poly1305) require a unique nonce per encryption and produce different ciphertext on every call. Dotta needs deterministic ciphertext for:

- **Git deduplication.** Identical plaintexts share Git storage.
- **Idempotency.** Re-running `dotta add` or `dotta update` on an unchanged file produces no diff.
- **Diffability.** Only files whose plaintexts actually changed appear in Git diffs of the encrypted tree.

SIV provides the same security as a nonce-based AEAD when nonces are unique and stays robust ("nonce-misuse resistant") under repeated plaintexts at the same path. Different plaintexts at the same `(mac_key, path, header)` yield different SIVs and different keystreams; many-time-pad leakage is structurally impossible.

### Why not ChaCha20-Poly1305

- Poly1305's 128-bit tag gives a 64-bit collision boundary, marginal for long-term Git storage.
- Poly1305-based AEAD is **not key-committing**: two distinct keys can decrypt the same ciphertext to different plaintexts without failing the tag (the "invisible salamander" attack). ETM-SIV with BLAKE2b's 256-bit collision resistance provides key commitment unconditionally.

### Cipher input bounds

- **Storage path:** at most 4096 bytes (excluding NUL).
- **Plaintext / ciphertext body:** at most `CIPHER_MAX_CONTENT = 100 MiB`. Defends against runaway allocations.

## File formats

### Encrypted blob (`CIPHER_VERSION = 0x09`)

```
┌─────────┬────────────────────────────────────────┬─────────┬──────────────────┐
│ offset  │ field                                  │ size    │ encoding         │
├─────────┼────────────────────────────────────────┼─────────┼──────────────────┤
│      0  │ magic                                  │   5 B   │ ASCII "DOTTA"    │
│      5  │ version                                │   1 B   │ 0x09             │
│      6  │ epoch_fingerprint                      │   8 B   │ BLAKE2b-8        │
│     14  │ SIV / MAC tag                          │  32 B   │ BLAKE2b keyed    │
│     46  │ ciphertext                             │   N B   │ XChaCha20 ⊕ pt   │
└─────────┴────────────────────────────────────────┴─────────┴──────────────────┘

Total: 46 + N bytes overhead.
```

The 14-byte header is the first input absorbed into the SIV scope. Any tampering with magic, version, or epoch fingerprint fails MAC verification.

### Encryption detection

`content_classify_bytes` (in `infra/content.c`) inspects the 6-byte detection window and returns one of three verdicts:

| First 5 bytes | Version byte         | Verdict                       |
|---------------|----------------------|-------------------------------|
| `"DOTTA"`     | `0x09`               | `CONTENT_ENCRYPTED`           |
| `"DOTTA"`     | other                | `CONTENT_UNSUPPORTED_VERSION` |
| anything else | n/a                  | `CONTENT_PLAINTEXT`           |
| `< 6 bytes`   | n/a                  | `CONTENT_PLAINTEXT`           |

Bytes are the single authoritative source for "is this blob encrypted?":

- `CONTENT_PLAINTEXT` → copy bytes through to the worktree.
- `CONTENT_ENCRYPTED` → decrypt via `keymgr_decrypt`.
- `CONTENT_UNSUPPORTED_VERSION` → `ERR_CRYPTO` with a version-skew diagnostic citing the unrecognized version byte; prevents deploying unrecognized ciphertext verbatim to the filesystem.

### Store refusal and write-time invariant

Plaintext files whose first 6 bytes match `"DOTTA\x09"` cannot be stored as plaintext. `content_store_file_to_worktree` refuses them with `ERR_VALIDATION`:
```
Cannot store '%s' as plaintext: its first bytes are dotta's cipher magic; add it with --encrypt, or change them
```
This write-boundary invariant guarantees that any blob written as plaintext will never be misclassified as ciphertext upon subsequent reads.

The deployment anchor (`anchor.blob_oid` in the state DB) does **not** carry an encryption flag. Anchor staleness checks route through `content_compare_blob_to_disk`, which classifies the anchor blob's bytes directly.

### Session cache (`SESSION_CACHE_VERSION = 0x04`)

The cache file is named by the epoch, and is therefore the epoch's rather than any one checkout's:

```
~/.cache/dotta/session-<epoch fingerprint, 16 hex>
```

```
┌─────────┬────────────────────────────────────────┬─────────┬──────────────────┐
│ offset  │ field                                  │ size    │ encoding         │
├─────────┼────────────────────────────────────────┼─────────┼──────────────────┤
│      0  │ magic                                  │   8 B   │ ASCII "DOTTASES" │
│      8  │ version                                │   1 B   │ 0x04             │
│      9  │ created_at                             │   8 B   │ LE64 Unix sec    │
│     17  │ expires_at                             │   8 B   │ LE64 Unix sec    │
│     25  │ nonce                                  │  24 B   │ entropy_fill     │
│     49  │ obfuscated_key                         │  32 B   │ master ⊕ stream  │
│     81  │ mac                                    │  32 B   │ keyed BLAKE2b    │
└─────────┴────────────────────────────────────────┴─────────┴──────────────────┘

Total: 113 bytes. All multi-byte integers are little-endian.
```

`expires_at = 0` indicates the cache never expires (`session_timeout = -1`).

#### Cache-key derivation

```
cache_key = BLAKE2b(salt || params, out_size = 32)
```

Unkeyed BLAKE2b over the 35 bytes of the repository's epoch. The derivation uses only public epoch bytes.

#### Obfuscation keystream

```
obfuscated_key[i] = master_key[i] XOR XChaCha20(cache_key, nonce, ctr=0)[i]
```

The 24-byte `nonce` is drawn from the OS CSPRNG (`entropy_fill`) per save.

This construction is **obfuscation, not encryption**: anyone with read access to the cache file and the public repository epoch can recompute `cache_key` and recover `master_key`. The file is protected by POSIX filesystem permissions (`0600`) and verification that the file descriptor is owned by the invoking user's UID.

#### MAC

```
mac = crypto_mac_oneshot(cache_key, CRYPTO_DOMAIN_SESSION_MAC,
                         /*data=*/&cache[0..81], /*data_len=*/81);
```

The MAC covers bytes `[0..81)` under domain `CRYPTO_DOMAIN_SESSION_MAC`. It detects file corruption or tampering. Because the file name and MAC key are both bound to the epoch, a file is only ever read under the epoch that named it: repositories with distinct epochs never contest a file, and checkouts sharing an epoch share the one master it caches. `keymgr_rekey` (sync's `ADOPT`) therefore leaves the old epoch's file in place — it belongs to that epoch, not to the checkout that has just stopped holding it. Verification is constant-time via `crypto_verify32`.

## Encryption workflow

### `dotta add ... --encrypt`

```
1. User: dotta add -p myprofile ~/.ssh/id_rsa --encrypt

2. Policy decision (core/policy.c):
   - Protected meta-files (.bootstrap, .dottaignore, .dotta/metadata.json)
     are always plaintext (rejected with an error if --encrypt is requested).
   - Otherwise priority: --encrypt > --no-encrypt > previous metadata state
                         > auto-encrypt patterns > default plaintext.

3. Read plaintext from filesystem.
   - Reject plaintexts starting with "DOTTA\x09" (magic collision).

4. Encrypt (crypto/keymgr → crypto/cipher):
   - keymgr resolves master_key under the repository's epoch.
   - If cold, keymgr verifies the fresh master against a witness in the repository
     (or confirms twice if repository has no ciphertext).
   - kdf_siv_subkeys: master_key + profile → mac_key, prf_key.
   - cipher_encrypt: builds 14-byte header (including epoch_fp), computes SIV,
     derives keystream seed, XChaCha20 → ciphertext.
   - mac_key and prf_key are wiped from the stack immediately.

5. Store in Git:
   - Create blob from ciphertext, update tree in profile branch.

6. Metadata (core/metadata.c):
   - Record encrypted=true and mode in .dotta/metadata.json.
   - Commit metadata.json to profile branch.
```

### `dotta apply`

```
1. User: dotta apply

2. Load workspace (manifest + per-profile metadata).

3. For each managed file (infra/content.c):
   - Read blob from Git tree.
   - Classify via content_classify_bytes.

   IF CONTENT_ENCRYPTED:
     - cipher_read_header validates header and extracts epoch_fp.
     - keymgr_decrypt verifies epoch_fp matches repository epoch.
     - keymgr resolves master_key with this blob as the witness in hand.
     - kdf_siv_subkeys → mac_key, prf_key.
     - cipher_decrypt: derives seed, XChaCha20, recomputes SIV,
                       constant-time compare; returns plaintext on match,
                       wipes candidate on mismatch.
     - Subkeys wiped on every exit path.

   IF CONTENT_PLAINTEXT:
     - Use blob content directly.

   IF CONTENT_UNSUPPORTED_VERSION:
     - Surface ERR_CRYPTO with a version diagnostic. Ciphertext is never
       written verbatim to the filesystem.

4. Deploy:
   - Copy plaintext to target path.
   - Restore mode (and ownership for root/ files) from metadata.
   - Update the record.
```

## Auto-encryption policy

Implemented in `src/core/policy.c`. Evaluates booleans from `config_t` and `metadata_t` without calling cryptographic primitives.

### Configuration

```toml
[encryption]
enabled = true
auto_encrypt = [
    ".ssh/id_*",
    "*.key",
    ".gnupg/*",
]
```

Patterns compile once into a `gitignore_ruleset_t` at `config_load` and live on the config handle (`config->auto_encrypt.rules`). Per-file matching runs in `encryption_policy_matches_auto_patterns`, which strips the storage prefix (`home/`, `root/`, `custom/`) before evaluation so users can write `.ssh/id_*` rather than `home/.ssh/id_*`.

Full gitignore semantics include `!` negation, directory-only patterns, anchoring, and `**` recursive globs (via `base/gitignore`).

### Decision priority

`encryption_policy_should_encrypt`:

1. **Protected meta-files** (`.bootstrap`, `.dottaignore`, `.dotta/metadata.json`) — always plaintext. Explicit `--encrypt` on these files is rejected with a clear error.
2. **Explicit `--encrypt`** on the command line.
3. **Explicit `--no-encrypt`** on the command line.
4. **Previous state in metadata.** A file previously encrypted stays encrypted on subsequent `update` so workflows like *add → modify → update* don't accidentally drop encryption.
5. **Auto-encrypt patterns**.
6. **Default plaintext.**

Priorities 1 and 4 are **not** gated on `config.encryption_enabled`. If the user explicitly requested encryption or a file's prior state says "encrypted", the policy says so; the content layer surfaces a friendly "enable encryption" error rather than silently coercing a previously-encrypted file to plaintext.

## Key management

Implemented in `src/crypto/keymgr.c`.

### The Unlock Proof

The key manager is structured as **the repository's unlock proof**, not a passive derivation cache.

```c
struct keymgr {
    kdf_epoch_t    epoch;
    uint8_t        epoch_fp[KDF_EPOCH_FP_SIZE];
    int32_t        session_timeout;
    keymgr_reach_t reach;

    /* The slot: process memo of one verified master, and the binding of the
     * witness it opened (both strings NULL when the master came from a cache
     * or was taken as given). */
    bool           has_key;
    uint8_t        master_key[KDF_KEY_SIZE];
    time_t         expires_at;
    char          *witness_profile;
    char          *witness_path;

    /* The standing refusal: the code and the top line of the ladder's first
     * refusal, re-issued by every resolve after. A NULL line means none
     * stands. */
    struct { error_code_t code; char *line; } refusal;

    /* The witness source, and the repository token handed back to it. */
    keymgr_witness_source_fn source;
    struct git_repository   *repo;
};
```

The key manager struct lives in its own `secure_alloc` mapping (anonymous `mmap`, `mlock`ed, dump-excluded).

Every master this module holds lives in exactly one of two carriers, each with one verb that fills it and one that empties it: the slot above (`install_slot` / `evict_slot`), and a `keymgr_proof_t` — a fresh master with the binding of whatever it opened — filled by `kdf_master_key` or `session_load` plus `bind_proof`, emptied by `wipe_proof`, or consumed by `install_slot`. There is no third buffer: subkeys are derived from the slot in place, and a witness trial's two subkeys are per-call intermediates wiped where they stand.

### The Witness

A fresh master (derived from a passphrase just obtained) is kept only after it has opened a **witness**: one ciphertext with the binding it was sealed under:

```c
typedef struct keymgr_witness {
    const uint8_t *ciphertext;   /* the blob, whole */
    size_t         len;
    const char    *profile;      /* the branch it is sealed under */
    const char    *storage_path; /* the tree path bound into its SIV */
} keymgr_witness_t;
```

Two sources, in order:
1. **The blob in hand**: For a decrypt, the very blob the caller requested. A cold decrypt verifies on its own row.
2. **The witness source**: `infra/epoch::epoch_find_ciphertext` presents every ciphertext of this epoch the repository holds — walking every local branch and its full Git history, **tips first** — to a predicate of the keymgr until one opens. One object at two paths or under two branches is presented under each candidate binding. Blobs belonging to other epochs or unsupported cipher versions are skipped.

A master that opens nothing is wiped and never kept. Tampered or relocated blobs cost nothing but their own row — the witness walk moves on.

### Core Invariants

1. **Verified before kept**: A fresh master key is never stored in the in-memory slot or session file until it has opened a witness (or, in an empty repository with no ciphertext, confirmed twice or supplied via `DOTTA_ENCRYPTION_PASSPHRASE`).
2. **Failure does not evict**: A cached master that fails to decrypt a blob stays cached. Tampered or corrupted blobs do not cost the user a verified key; the row is reported as `[unverified]`.
3. **Refusal stands for the process**: If passphrase acquisition fails (no passphrase in reach, prompt aborted, a passphrase that opens nothing, or 3 wrong attempts at a TTY), the code and the top line of that refusal are recorded on `km->refusal`. The asker that met it receives the error itself, causes and all — the chain describes an event that happened once — while every later resolve re-issues the recorded line, which is the one sentence true of the whole run. The refusal therefore names no row: `infra/content` wraps it with the path of the row that asked, and what varies in its wording is only how much there was to open, since against a single ciphertext a miss is undecidable. `dotta key set` and `keymgr_rekey` clear a standing refusal; `dotta key clear` does not.

### Command Reach (`keymgr_reach_t`)

Commands declare how far keymgr may reach:
- `KEYMGR_REACH_CACHED`: Used by reporting commands (`status`, `sync`, `key status`, `key clear`). Reads only the in-memory slot and on-disk session file. Returns `ERR_LOCKED` immediately on a cold cache without prompting or reading environment variables.
- `KEYMGR_REACH_OBTAIN`: Used by content commands (`apply`, `add`, `update`, `diff`, `show`, `export`, `revert`, `key set`). Permitted to read `DOTTA_ENCRYPTION_PASSPHRASE` and prompt interactively.

### Fault Classification (`core/workspace.h`)

Failed looks in divergence analysis are classified into three fault classes based on the root error code:

| Fault | Root code | CLI Tag | Remedy |
|---|---|---|---|
| `WORKSPACE_FAULT_LOCKED` | `ERR_LOCKED` | `[locked]` | Run `dotta key set` |
| `WORKSPACE_FAULT_UNREADABLE` | `ERR_PERMISSION` | `[unreadable]` | Run under `sudo` or fix permissions |
| `WORKSPACE_FAULT_UNVERIFIED` | anything else | `[unverified]` | Inspect with `dotta show <path>` |

The workspace item holds only the enum (`item->fault`). Display printers generate concise, consistent status lines and legends without borrowing error strings across architectural layers.

### Master-key resolution ladder

`resolve_master(km, in_hand)`, in cost order — `in_hand` is the blob a decrypt was asked for, or NULL for an encrypt and for `key set`:

1. **The slot**: if `km->has_key`, return (O(1)). The slot is read first, so a master that arrived *after* the ladder refused — one another process wrote and `keymgr_cached`'s probe installed — wins over an answer that is no longer true.
2. **The standing refusal**: if one stands, re-issue its line and stop. It sits above the file because it can only stand once the file tier has already been asked and missed, so N encrypted rows under a cold run cost one probe and one prompt, not N.
3. **The file tier** (`warm_from_file`): when `session_timeout != 0`, `session_load` under this epoch. Every miss is silent — absent, expired, MAC mismatch (the loader unlinks it), a transient I/O failure (it does not) — and a hit installs the slot with the file's recorded `expires_at`.
4. **`obtain`** — the ladder's user half, and the only step that can record a refusal:
   - **Reach gate**: `KEYMGR_REACH_CACHED` stops here with `ERR_LOCKED` ("No passphrase is cached, and this command does not ask for one").
   - **Environment**: `DOTTA_ENCRYPTION_PASSPHRASE`, derived and checked against the witnesses. One attempt, no retry — an explicit variable is the automation's own assertion.
   - **Prompt**: the shape is the repository's. A witness in reach means verify (`prompt_and_verify`); none means confirm by typing twice (`prompt_and_confirm`). Up to `KEYMGR_ATTEMPTS` rounds at a terminal, one over a pipe, and a miss of any kind spends a round.
5. **`keep`**: the verified proof enters the slot, and the session file when the tier is on. A save that fails unlinks the file so it never lies; it is silent inside an operation and returned by `keymgr_set`, whose job the file is.

Verification of a fresh master is `derive_and_check`: Argon2 under the epoch, then the witnesses in order — `in_hand` first, then whatever the source presents — until one opens. Nothing shown to it at all means nothing can refuse it, and it is taken as given.

### Session-cache load validation

`session_load` validates in this order:

1. `open(O_NOFOLLOW)` followed by `fstat` against the opened fd (closes TOCTOU windows).
2. Regular file, mode exactly `0600`, owned by invoker UID (`identity()->uid`).
3. File size exactly 113 bytes.
4. Magic `"DOTTASES"` and version `0x04`.
5. Recompute `cache_key = BLAKE2b(salt || params)`.
6. Verify MAC over bytes `[0..81)` via `crypto_verify32` constant-time compare.
7. Expiry against wall-clock (if `expires_at != 0`).
8. Deobfuscate `master_key` into caller's buffer.

On file corruption or expiry, the file is unlinked.

### Content cache

`infra/content.c` caches decrypted plaintexts for the lifetime of one command:
- Keyed by the binding refspec: `profile:storage_path@blob_oid_hex`.
- Prevents redundant decryptions of the same file while preserving path-binding guarantees.
- Plaintext buffers are zeroed with `crypto_wipe` before deallocation.

## Memory protection

Memory protection for secret-bearing data is implemented across `base/secure.c` and `sys/identity.c`:

- **Dedicated locked mappings (`secure_alloc` / `secure_free`)**: Every secret that outlives a function call resides in its own anonymous, page-aligned `mmap` mapping:
  - The `keymgr` struct and its internal master key slot.
  - Passphrase buffers allocated during prompt or environment acquisition (`sys/passphrase.c`).
  - The Argon2id work area (`memory_mib << 20` bytes) allocated during derivation.
- **Locking against paging**: Mappings are locked into RAM via `mlock(2)`. If memory locking fails (e.g. due to restrictive `RLIMIT_MEMLOCK`), dotta logs a single advisory and proceeds.
- **Dump exclusion**: Where supported by the OS (Linux), mappings are tagged with `madvise(MADV_DONTDUMP)` to prevent inclusion in core dumps.
- **Core dump disablement**: `identity_init` sets `RLIMIT_CORE` to 0 via `setrlimit(2)` at process startup. `PR_SET_DUMPABLE` was explicitly declined to preserve user debugging (`ptrace`, `gdb`, `lldb`).
- **Memory scrubbing**: Mappings are wiped via volatile loops (`secure_wipe`) before `munlock` and `munmap`. Stack copies of ephemeral subkeys (`mac_key`, `prf_key`, keystream seed, candidate plaintext) are scrubbed via `crypto_wipe` immediately upon completion.

## Configuration reference

```toml
[encryption]

# Enable encryption support. Default: false (opt-in).
enabled = false

# Master-key session cache lifetime (seconds).
#   0    : process memory only (never written to disk; next process prompts again)
#   -1   : never expire
#   N>0  : seconds before expiry
# Default: 3600 (1 hour).
session_timeout = 3600

# Auto-encrypt patterns (gitignore-style).
auto_encrypt = [
    ".ssh/id_*",
    ".ssh/*.pem",
    ".gnupg/*",
    "*.key",
    ".aws/credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".config/gh/hosts.yml",
]
```

Cryptographic derivation parameters (`memory_mib` and `passes`) are **not** configured here; they belong to the repository epoch and are minted once via `dotta init --strength <fast|balanced|paranoid>`.

### Validation

Validation is performed at the boundary where parameters enter the system:

| Field | Location | Rule | Error |
|---|---|---|---|
| `session_timeout` | Config load | `-1`, `0`, or `1..INT32_MAX` | `ERR_INVALID_CONFIG` |
| `auto_encrypt[i]` | Config load | Valid gitignore pattern | `ERR_INVALID_CONFIG` |
| `epoch.memory_mib` | `epoch_load` / `epoch_fetch` | `8..4096` | `ERR_CRYPTO` |
| `epoch.passes` | `epoch_load` / `epoch_fetch` | `1..20` | `ERR_CRYPTO` |

### Hardcoded constants

| Constant | Value | Rationale |
|---|---|---|
| KDF Algorithm | Argon2id | RFC 9106; memory-hard primitive in Monocypher |
| Epoch salt size | 32 bytes (256 bits) | Matches codebase key buffer width (`KDF_KEY_SIZE`) |
| Epoch params size | 3 bytes | LE16 memory_mib ‖ passes |
| Epoch fingerprint | 8 bytes (64 bits) | BLAKE2b-8 over 35 bytes of salt ‖ params |
| Cipher version | `0x09` | Authenticated in header |
| Cipher header size | 14 bytes | `"DOTTA"` (5) + version (1) + epoch_fp (8) |
| Cipher MAC tag size | 32 bytes | BLAKE2b keyed output; 256-bit collision boundary |
| Cipher overhead | 46 bytes | 14-byte header + 32-byte SIV tag |
| Session file version | `0x04` | Dedicated per-epoch cache file |
| Session file size | 113 bytes | Includes created_at, expires_at, nonce, obfuscated key, MAC |

## Security analysis

### Cryptographic primitives

- **Argon2id** — RFC 9106, memory-hard password-based key derivation.
- **BLAKE2b** — RFC 7693, used keyed for MAC/subkeys and unkeyed for epoch fingerprints and session cache keys.
- **XChaCha20** — RFC 8439 ChaCha20 with 24-byte extended nonce; stream cipher for blob encryption and cache obfuscation.
- **SIV pattern** — Synthetic Initialization Vector construction providing deterministic AEAD and nonce-misuse resistance.

### Key invariants

- **Determinism**: Identical `(passphrase, profile, path, plaintext)` produces byte-identical ciphertext under a given repository epoch.
- **Unlock proof**: Keys enter cache structures only after verifying against repository ciphertext or being confirmed twice.
- **Isolated subkeys**: The cipher module never handles the master key; operations use ephemeral `(mac_key, prf_key)` pairs derived per call and wiped immediately.
- **Header binding**: The 14-byte header is bound into the SIV scope; tampering with version, magic, or epoch fingerprint fails authentication.
- **Epoch ownership**: The repository owns its salt and work factor; blobs do not carry parameters and cannot dictate derivation cost.
- **Constant-time verification**: All authentication tags are verified via `crypto_verify32`.

## Implementation map

| Concern | Module | Public surface |
|---|---|---|
| Memory-hard derivation & Epoch | `src/crypto/kdf` | `kdf_epoch_t`, `kdf_epoch_fingerprint`, `kdf_master_key`, `kdf_siv_subkeys`, `kdf_validate_params`, `kdf_params_store/load`, `kdf_presets` |
| Keyed-BLAKE2b chokepoint | `src/crypto/mac` | `crypto_mac_init/absorb/final/oneshot`, `crypto_domain_t` |
| SIV encrypt/decrypt + format | `src/crypto/cipher` | `cipher_encrypt`, `cipher_decrypt`, `cipher_read_header` |
| Unlock proof & key manager | `src/crypto/keymgr` | `keymgr_create`, `keymgr_encrypt`, `keymgr_decrypt`, `keymgr_set`, `keymgr_clear`, `keymgr_cached`, `keymgr_epoch`, `keymgr_rekey`, `keymgr_witness`, `keymgr_free` |
| On-disk epoch session cache | `src/crypto/session` | `session_save`, `session_load`, `session_clear` |
| Repository epoch lifecycle & census | `src/infra/epoch` | `epoch_init`, `epoch_load`, `epoch_push`, `epoch_fetch`, `epoch_resolve`, `epoch_find_ciphertext`, `walk_ciphertext` |
| Content abstraction & cache | `src/infra/content` | `content_cache_*`, `content_classify*`, `content_store_file_to_worktree` |
| Memory protection | `src/base/secure` | `secure_alloc`, `secure_free`, `secure_wipe` |
| Passphrase acquisition | `src/sys/passphrase` | `passphrase_prompt`, `passphrase_from_env` |
| CSPRNG entropy | `src/sys/entropy` | `entropy_fill` |
| Encryption policy | `src/core/policy` | `encryption_policy_should_encrypt`, `encryption_policy_matches_auto_patterns` |

## References

- Argon2 — RFC 9106. <https://datatracker.ietf.org/doc/html/rfc9106>
- BLAKE2 — RFC 7693. <https://datatracker.ietf.org/doc/html/rfc7693>
- ChaCha20 / XChaCha20 — RFC 8439. <https://datatracker.ietf.org/doc/html/rfc8439>
- SIV — RFC 5297. <https://datatracker.ietf.org/doc/html/rfc5297>
- Monocypher — <https://monocypher.org/>
