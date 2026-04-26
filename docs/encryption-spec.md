# Encryption Technical Specification

## Overview

Dotta encrypts sensitive dotfiles transparently so they can be stored in a Git repository without exposing their contents. Files are encrypted at rest in Git and decrypted only when deployed to the filesystem.

**Design goals:**

- **Deterministic AEAD** — identical `(passphrase, profile, path, plaintext)` produces byte-identical ciphertext. Git deduplicates, history is meaningful.
- **Path-bound authentication** — ciphertext is cryptographically tied to its storage path; a file moved to a different path cannot be decrypted.
- **Nonce-misuse resistant** — Synthetic-IV (SIV) construction; no random nonces to manage.
- **Single passphrase UX** — one passphrase covers every profile. Per-profile subkeys are derived deterministically.
- **Session caching** — master key cached in memory and on disk for a configurable timeout.

## Threat model

### Mitigated

- **Passive repository compromise.** An attacker who exfiltrates the Git repository (clone, stolen disk image, leaked backup) cannot recover plaintext without the passphrase. Brute force is bounded by Argon2id memory hardness × passphrase entropy.
- **Active tampering of encrypted blobs.** Modifying any byte of the magic, version, Argon2 params, SIV, or ciphertext fails SIV verification. The candidate plaintext is wiped before any return; the error is a uniform "authentication failed" diagnostic.
- **Path confusion.** A blob encrypted for `home/.ssh/id_rsa` cannot decrypt as `home/.bashrc`. The storage path is bound into the SIV byte-for-byte.
- **Cross-profile contamination.** Per-profile subkeys are derived deterministically from `(master_key, profile_name)` under domain-separated tags; compromise of one profile's `(mac_key, prf_key)` pair leaks nothing about another's without the master key.
- **Version-confusion attacks on the file format.** The 9-byte cipher-blob header is bound into the SIV. A forged "v7-on-v6" blob fails MAC, not parse; every error path is uniform.
- **Argon2-params tampering.** Params live in the authenticated header. A config edit cannot silently invalidate old files — decrypt re-runs Argon2 with whatever params each blob carries — and a bit-flipped header field fails MAC.

### Not mitigated

- **Local interactive compromise.** A process running as the dotta user (or root) can read the master key from process memory while cached, and from `~/.cache/dotta/session` in obfuscated form (see *Session cache*).
- **Weak passphrases.** Argon2id raises the per-guess wall but does not save a 6-character dictionary word.
- **Keyloggers, shoulder-surfing, evil-maid attacks** during passphrase entry.
- **Forensic disk imaging on a live host.** The session cache resists casual inspection and cross-machine copy, not a forensic adversary on the host that wrote it.
- **Plaintext-length leakage.** Stream cipher; ciphertext length = plaintext length + 41-byte header. Padding to a fixed boundary would defeat Git deduplication and is not adopted. File sizes are visible in Git regardless.
- **Storage path leakage.** Paths are recorded in plaintext in `.dotta/metadata.json` and as Git tree entries. Encryption hides content, not structure.
- **Plaintext-equality leakage across commits.** Encryption is deterministic; identical inputs produce identical ciphertext. An attacker observing multiple commits learns *whether* a file at a given path changed, not *what* changed. Intrinsic to deterministic SIV; the cost of Git friendliness.

### Leakage matrix

| What leaks                            | Brute-force cost                                    | Notes                                                                                    |
|---------------------------------------|-----------------------------------------------------|------------------------------------------------------------------------------------------|
| Repo only                             | Passphrase entropy × Argon2id memory cost           | Salt is hardcoded; attacker has it from source. Memory-hardness is the only wall.        |
| Plaintext sizes (any leaked repo)     | N/A — leaked unconditionally                        | Stream cipher; out-of-scope by design.                                                   |
| `~/.cache/dotta/session` + repo       | Master key recoverable without passphrase           | Cache is machine-bound obfuscation, not crypto. Possession of both reduces decryption to a hostname/username lookup. |

For the "stolen laptop" / cloud-sync exposures the response is `dotta key clear` before lending or retiring the machine, plus exclusion of `~/.cache/dotta` from any backup that already contains the encrypted repo.

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
                       memory_mib, passes from blob header / current config
                       lanes = 1 (Monocypher is single-threaded)
                       salt = 16-byte hardcoded constant in kdf.c
        ┌────────────────────────────────────────────┐
        │              Master key (32 B)             │
        │      Cached by keymgr (memory + disk)      │
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

**Three derivation steps** (down from a prior 4-level design that included a `profile_key` intermediate; the indirection bought no security and one extra BLAKE2b call per file). The cipher module never sees the master key or the profile name — only the `(mac_key, prf_key)` pair.

| Step                                       | Module       | Primitive                         | Cost (warm) |
|--------------------------------------------|--------------|-----------------------------------|-------------|
| passphrase → master                        | `kdf.c`      | `crypto_argon2`                   | 0 (cached)  |
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

`lanes = 1` is forced by Monocypher's single-threaded implementation. With `lanes = 1`, `memory × passes` is the right memory-hardness metric; RFC 9106's recommendations assume `lanes = 4`. Re-bench on real hardware.

**Bounds** (validated at config-load AND at the crypto boundary):

- `argon2_memory_mib` ∈ [8, 4096]. The 8 MiB minimum is dotta's chosen security floor. The 4 GiB ceiling is a **DoS bound**: `cipher_decrypt` reads `memory_mib` from the blob header and would otherwise allocate attacker-controlled tens of GiB before SIV verification fires. 4 GiB is 4× the `paranoid` preset and well above any defensible setting.
- `argon2_passes` ∈ [1, 20]. Same DoS rationale.

`cipher_peek_params` revalidates the header-recorded params via `kdf_validate_params` BEFORE any allocation, so a tampered or attacker- planted blob is rejected at the parse step.

### Salt

The Argon2id salt is a 16-byte constant compiled into `kdf.c`. A salt's job is to prevent attackers from amortising cracking work across multiple targets. Dotta is single-user / single-target; with one target there is nothing to amortise, so per-install random salt and constant salt produce identical per-guess attacker cost.

The constant satisfies the API; it contributes no security claims to the threat model. Changing the bytes invalidates every encrypted blob in every user's repo — treat it as a format-defining value alongside `CIPHER_VERSION`.

`extras.key` (pepper) and `extras.ad` (binding to host/install-id) are not used (`crypto_argon2_no_extras`):

- **Pepper** narrows to a scenario (repo exfiltrated, pepper not exfiltrated) that rarely applies for a single-user manager and adds a second loss-of-data failure mode.
- **`ad`** would break "back up your repo + passphrase = recover anywhere".

## SIV construction (cipher format v6)

Implemented in `src/crypto/cipher.c`. SIV deterministic AEAD in the spirit of RFC 5297, built from BLAKE2b (MAC) and XChaCha20 (keystream).

### Encryption

Inputs: `(plaintext, mac_key, prf_key, storage_path, memory_mib, passes)`.

1. **Build the 9-byte authenticated header:**
   ```
   bytes [0..5)  = "DOTTA"
   byte   [5]    = CIPHER_VERSION (0x06)
   bytes [6..8)  = LE16(argon2_memory_mib)
   byte   [8]    = argon2_passes
   ```

2. **Compute the synthetic IV** (32 bytes) over `(header, path, plaintext)`:
   ```
   crypto_mac_init(ctx, mac_key, CRYPTO_DOMAIN_CIPHER_SIV);
   crypto_mac_absorb(ctx, header, 9);                      /* LE64-prefixed */
   crypto_mac_absorb(ctx, storage_path, path_len);         /* LE64-prefixed */
   crypto_mac_absorb(ctx, plaintext, plaintext_len);       /* LE64-prefixed */
   crypto_mac_final(ctx, siv);
   ```

3. **Derive the keystream seed** from the (public) SIV under `prf_key`:
   ```
   seed = crypto_mac_oneshot(prf_key, CRYPTO_DOMAIN_CIPHER_KEY, siv, 32);
   ```
   Keying the seed with `prf_key` keeps the keystream behind a secret. The SIV alone is public.

4. **Encrypt** with XChaCha20:
   ```
   crypto_chacha20_x(ciphertext, plaintext, plaintext_len,
                     /*key=*/seed, /*nonce=*/siv[0..24], /*ctr=*/0);
   ```
   Monocypher reads exactly 24 bytes from the nonce pointer; the trailing 8 bytes of the 32-byte SIV serve only as the MAC tag.

5. **Assemble** `[ header(9) | SIV(32) | ciphertext(N) ]`.

### Decryption

1. Validate length, magic, version, and header-recorded Argon2 params via `kdf_validate_params`. Defense-in-depth — `keymgr_decrypt` already routed the call by `cipher_peek_params`.
2. Derive `seed` from `(prf_key, stored_siv)` under `CIPHER_KEY` exactly as in encryption step 3.
3. Decrypt: `candidate = ciphertext_body XOR XChaCha20(seed, siv[0..24], 0)`.
4. Recompute SIV over `(header || storage_path || candidate)` under `mac_key`.
5. Constant-time compare via `crypto_verify32`. On match, transfer the candidate to the caller. On mismatch, wipe the candidate and return `ERR_CRYPTO("authentication failed")`. The candidate is never surfaced.

In SIV, the IV authenticates the plaintext; verification cannot happen before recovery. The candidate is held just long enough to verify; cleanup zeroes the buffer on every error path.

### Determinism rationale

Standard AEAD modes (AES-GCM, ChaCha20-Poly1305) require a unique nonce per encryption and produce different ciphertext on every call. Dotta needs deterministic ciphertext for:

- **Git deduplication.** Identical plaintexts share Git storage.
- **Idempotency.** Re-running `dotta add` on an unchanged file produces no diff.
- **Diffability.** Only files whose plaintexts actually changed appear in Git diffs of the encrypted tree.

SIV gives the same security as a nonce-based AEAD when nonces are unique and stays robust ("nonce-misuse resistant") under repeated plaintexts at the same path. Different plaintexts at the same `(mac_key, path, header)` yield different SIVs and different keystreams; the many-time-pad leakage that a random-nonce stream cipher would suffer is structurally impossible.

### Why not ChaCha20-Poly1305

- Poly1305's 128-bit tag gives a 64-bit collision boundary, marginal for long-term Git storage.
- Poly1305-based AEAD is **not key-committing**: two distinct keys can decrypt the same ciphertext to different plaintexts without failing the tag (the "invisible salamander" attack), especially relevant for password-derived keys. ETM-SIV with BLAKE2b's collision resistance gives key commitment for free.

### Cipher input bounds

- **Storage path:** at most 4096 bytes (excluding NUL). `strnlen` keeps the scan bounded even on non-NUL-terminated input.
- **Plaintext / ciphertext body:** at most `CIPHER_MAX_CONTENT = 100 MiB`. Dotfiles are small; the cap defends the crypto layer from runaway input.

## File formats

### Encrypted blob (`CIPHER_VERSION = 0x06`)

```
┌─────────┬────────────────────────────────────────┬─────────┬──────────────────┐
│ offset  │ field                                  │ size    │ encoding         │
├─────────┼────────────────────────────────────────┼─────────┼──────────────────┤
│      0  │ magic                                  │   5 B   │ ASCII "DOTTA"    │
│      5  │ version                                │   1 B   │ 0x06             │
│      6  │ argon2_memory_mib                      │   2 B   │ LE16, 8..4096    │
│      8  │ argon2_passes                          │   1 B   │ uint8, 1..20     │
│      9  │ SIV / MAC tag                          │  32 B   │ BLAKE2b keyed    │
│     41  │ ciphertext                             │   N B   │ XChaCha20 ⊕ pt   │
└─────────┴────────────────────────────────────────┴─────────┴──────────────────┘

Total: 41 + N bytes.  Lanes = 1 (not stored).
```

The full 9-byte header is bound into the SIV computation as the first absorbed input. Tampering any byte (magic, version, or params) fails MAC, not parse — the version-confusion / params-rollback attack class is closed.

### Encryption detection

`cipher_is_encrypted` tests the 6-byte detection window (magic + current build's version). A blob whose first 5 bytes are `"DOTTA"` but whose version byte is not `CIPHER_VERSION` reports as **not encrypted** — coincidental plaintext starting with `"DOTTA"` is not misrouted into the decrypt path.

The deploy decision in `infra/content.c` is a 4-case truth table joining `metadata.encrypted` (declared at add-time) with the magic-byte sniff:

| metadata.encrypted | sniff                | Action                                                          |
|--------------------|----------------------|-----------------------------------------------------------------|
| true               | true                 | Decrypt via `keymgr_decrypt`.                                   |
| false              | false                | Plaintext deploy.                                               |
| true               | false                | `ERR_CRYPTO`: "metadata says encrypted but blob magic missing." |
| false              | true                 | `ERR_CRYPTO`: "metadata says plaintext but blob has magic."     |

A v7 blob encountered by a v6 build sniffs as not-encrypted; row 3 of the truth table fires before any decrypt attempt.

### Session cache (`SESSION_CACHE_VERSION = 0x02`)

```
┌─────────┬────────────────────────────────────────┬─────────┬──────────────────┐
│ offset  │ field                                  │ size    │ encoding         │
├─────────┼────────────────────────────────────────┼─────────┼──────────────────┤
│      0  │ magic                                  │   8 B   │ ASCII "DOTTASES" │
│      8  │ version                                │   1 B   │ 0x02             │
│      9  │ argon2_memory_mib                      │   2 B   │ LE16             │
│     11  │ argon2_passes                          │   1 B   │ uint8            │
│     12  │ created_at                             │   8 B   │ LE64 Unix sec    │
│     20  │ expires_at                             │   8 B   │ LE64 Unix sec    │
│     28  │ machine_salt                           │  16 B   │ entropy_fill     │
│     44  │ obfuscated_key                         │  32 B   │ master ⊕ stream  │
│     76  │ mac                                    │  32 B   │ keyed BLAKE2b    │
└─────────┴────────────────────────────────────────┴─────────┴──────────────────┘

Total: 108 bytes.  All multi-byte fields are little-endian on disk.
```

`expires_at = 0` means "never expire" (configured `session_timeout = -1`).

#### Cache-key derivation

```
cache_key = BLAKE2b(LE64(host_len) || hostname
                 || LE64(user_len) || username
                 || machine_salt[16],
                    out_size = 32)             /* unkeyed BLAKE2b */
```

Variable-length inputs are LE64-prefixed; the fixed-width 16-byte salt is absorbed verbatim. Hostname comes from `gethostname(2)`; username from `getpwuid(getuid())` (kernel-anchored, unlike `getlogin(3)` or `getenv("USER")`).

This is the one keyed-BLAKE2b carve-out in the codebase: `cache_key` is the *output* of derivation, not a key into a keyed primitive, so the "no `crypto_blake2b_keyed*` outside `mac.c`" rule does not apply here. The keyed primitive is reserved for the MAC step that follows.

#### Obfuscation keystream

```
zero_nonce[24]    = { 0 }
obfuscated_key[i] = master_key[i] XOR XChaCha20(cache_key, zero_nonce, ctr=0)[i]
```

The `(cache_key, zero_nonce)` pair is unique per cache file because `cache_key` incorporates the per-file `machine_salt`.

This is **obfuscation, not encryption**: an attacker with read access to the cache file plus the host's hostname and username (recoverable trivially from `/etc/hostname` and `/etc/passwd`) can re-derive `cache_key`, regenerate the keystream, and recover `master_key`. Naming the field `obfuscated_key` keeps the threat model and the construction in agreement — this layer provides **integrity** (the MAC over the 76-byte prefix) and **resistance to casual cross-machine copy** (machine-binding fails on a different host); it does **not** provide local-file confidentiality.

#### MAC

```
mac = crypto_mac_oneshot(cache_key, CRYPTO_DOMAIN_SESSION_MAC,
                         /*data=*/&cache[0..76], /*data_len=*/76);
```

Verification is constant-time via `crypto_verify32`. Domain-separated under `CRYPTO_DOMAIN_SESSION_MAC` so a forged cache cannot pass as a SIV-style MAC under another module's key.

## Encryption workflow

### `dotta add ... --encrypt`

```
1. User: dotta add -p myprofile ~/.ssh/id_rsa --encrypt

2. Policy decision (core/policy.c):
   - Protected meta-files (.bootstrap, .dottaignore, .dotta/metadata.json)
     are always plaintext (rejected with a clear error if --encrypt is
     requested explicitly).
   - Otherwise priority: --encrypt > --no-encrypt > previous metadata state
                         > auto-encrypt patterns > default plaintext.

3. Read plaintext from filesystem.

4. Encrypt (crypto/keymgr → crypto/cipher):
   - keymgr resolves master_key for current-config (memory_mib, passes).
   - kdf_siv_subkeys: master_key + profile → mac_key, prf_key.
   - cipher_encrypt: builds header, computes SIV, derives keystream seed,
                     XChaCha20 → ciphertext.
   - mac_key, prf_key wiped on every exit path.

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
   - Detect dotta magic + version with cipher_is_encrypted; cross-check
     against metadata.encrypted via the 4-case truth table.

   IF ENCRYPTED:
     - cipher_peek_params reads (memory_mib, passes) from blob header.
     - keymgr resolves master_key for the BLOB's params (not current config).
     - kdf_siv_subkeys → mac_key, prf_key.
     - cipher_decrypt: derives seed, XChaCha20, recomputes SIV,
                       constant-time compare; returns plaintext on match,
                       wipes candidate on mismatch.
     - keys wiped on every exit path.

   ELSE:
     - Use blob content directly.

4. Deploy:
   - Copy plaintext to target path.
   - Restore mode (and ownership for root/ files) from metadata.
   - Update deployment state.
```

## Auto-encryption policy

Implemented in `src/core/policy.c`. (Moved from `src/crypto/` in the v6 rewrite — the module evaluates a boolean from `config_t` and `metadata_t` and never calls a cryptographic primitive, so it does not belong in the crypto layer.)

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

Full gitignore semantics including `!` negation, directory-only patterns, anchoring, and `**` recursive globs (via `base/gitignore`).

### Decision priority

`encryption_policy_should_encrypt`:

1. **Protected meta-files** (`.bootstrap`, `.dottaignore`, `.dotta/metadata.json`) — always plaintext. Explicit `--encrypt` on these files is rejected with a clear error.
2. **Explicit `--encrypt`** on the command line.
3. **Explicit `--no-encrypt`** on the command line.
4. **Previous state in metadata.** A file previously encrypted stays encrypted on subsequent `update` so workflows like *add → modify → update* don't accidentally drop encryption.
5. **Auto-encrypt patterns**.
6. **Default plaintext.**

Priorities 1 and 4 are **not** gated on `config.encryption_enabled`. If the user explicitly requested encryption or a file's prior state says "encrypted", the policy says so; the content layer surfaces a friendly "enable encryption" error rather than silently coercing a previously- encrypted file to plaintext (which would leak its content).

## Key management

### Two-tier cache

```c
struct keymgr {
    /* Configuration snapshot — set at create time, never mutated. */
    uint16_t current_memory_mib;
    uint8_t  current_passes;
    int32_t  session_timeout;     /* seconds; 0 = always prompt, -1 = never expire */

    /* In-memory cache slot (single slot; routes by params). */
    bool     has_key;
    uint16_t cached_memory_mib;
    uint8_t  cached_passes;
    uint8_t  master_key[KDF_KEY_SIZE];
    time_t   cached_at;           /* CLOCK_MONOTONIC seconds */

    bool     mlocked;
};
```

The struct is best-effort `mlock`'d at create time so the cached master key cannot be paged. The much larger Argon2 work area is `mlock`'d separately inside `kdf_master_key` for the duration of one derivation.

In-memory cache expiry uses `CLOCK_MONOTONIC` so a wall-clock skew cannot extend the session. The on-disk session uses wall-clock seconds (a monotonic clock resets on reboot, which would defeat the persistence).

### Single-slot rationale

Argon2 params live in the blob header, so `cipher_decrypt` runs Argon2 under whatever params the blob carries. The on-disk session cache only ever holds **one** entry — the master key under the **current-config** params — so a fresh process always re-prompts for old-params blobs regardless of any in-memory multi-slot scheme.

A multi-slot in-memory cache would optimise *only* the within-process case where one command touches blobs at multiple param settings. The narrow benefit doesn't justify slot-management machinery; single-slot keeps the invariants tractable. Cross-params transitions cost one re-prompt per transition — the operational remediation is to re-encrypt old files under one consistent params set.

### Param routing

| Function                  | Params source                                 |
|---------------------------|-----------------------------------------------|
| `keymgr_encrypt`          | Current-config snapshot (latest strength)     |
| `keymgr_decrypt`          | Blob-header params via `cipher_peek_params`   |
| `keymgr_set_passphrase`   | Current-config snapshot                       |
| `keymgr_probe_key`        | Current-config snapshot                       |

### Master-key resolution chain

`keymgr_resolve(target_memory_mib, target_passes, out)`:

1. **In-memory slot match** for the target params + not expired → return.
2. **Slot mismatch** (any has_key) → evict (single-slot eviction).
3. **Always-prompt mode** (`session_timeout == 0`) → skip disk.
4. **`session_load`:**
   - Match → install slot, return.
   - Mismatch params → discard the loaded key, **leave the file in place**
     (it is the canonical current-config slot).
   - `ERR_NOT_FOUND` / `ERR_CRYPTO` → fall through; `session_load` already
     unlinked anything unrecoverable.
   - `ERR_FS` → warn, fall through.
5. **`passphrase_from_env`** with stderr advisory (env var leaks via `ps(1)` and child-process inheritance).
6. **`passphrase_prompt`** otherwise.
7. Derive under target params, install in slot, wipe passphrase.
8. **Save to disk** only if `target_(mib, passes) == current_(mib, passes)` AND `session_timeout != 0`. Old-params masters never persist.

### Passphrase rotation

There is no automated rotation command. `keymgr_set_passphrase` derives the master under current-config params and replaces the cached slot, but every file encrypted under the old passphrase becomes unrecoverable on next decrypt. The CLI command `cmd_key_set` is responsible for surfacing the rotation warning before invoking the function.

The user-facing procedure (`docs/encryption.md`):

```
dotta key clear
dotta apply              # decrypt + redeploy under the OLD passphrase
dotta key set            # NEW passphrase
dotta remove <file> && dotta add <file>   # per encrypted file
```

A premature `dotta key set <new>` followed by `dotta apply` leaves old-passphrase blobs unrecoverable.

### Session cache lifecycle

1. **First key request.** Memory miss → disk miss (when timeout != 0) → passphrase (env or prompt) → Argon2id derivation → cache in memory → write to disk.
2. **Subsequent requests in the same process.** Memory hit (O(1) until expiry).
3. **Subsequent requests across processes.** Disk hit; promoted to memory.
4. **Expiration.** Default `session_timeout = 3600` seconds. `-1` = never expire. `0` = never cache (always prompt; disk cache disabled).
5. **Cleanup.** `dotta key clear` zeroes the in-memory slot and unlinks the on-disk file. `keymgr_free` zeroes and `munlock`s on process exit.

### Session-cache load validation

`session_load` validates in this order:

1. `open(O_NOFOLLOW)` followed by `fstat` against the opened fd (closes the TOCTOU window).
2. Regular file, mode exactly `0600`, owned by current uid.
3. File size exactly 108 bytes.
4. Magic + version.
5. `derive_cache_key` over the (still-unauthenticated) salt.
6. MAC verify (constant-time `crypto_verify32`) — runs **before** expiry so the trusted bytes drive the comparison.
7. Expiry against wall-clock.
8. Recorded params within `KDF_ARGON2_*_MIN/MAX`.
9. Deobfuscate `master_key` directly into the caller's output buffer.

On any failure caused by the file itself (corruption, mismatch, expiry, wrong perms) the file is unlinked. On transient I/O failure the file is left in place.

`session_clear` overwrites the file with zeros, fsyncs, then unlinks. Best-effort: copy-on-write filesystems (btrfs, zfs, APFS) may retain the freed inode contents.

## Memory protection

- **Master key** (in `keymgr` struct): best-effort `mlock`'d, `crypto_wipe`'d on `keymgr_free`, `keymgr_clear`, and signal-handled exit.
- **Argon2 work area** (`memory_mib * 1024 * 1024` bytes): best-effort `mlock`'d for the duration of one derivation; `crypto_wipe`'d before free on every exit path. Defense-in-depth alongside Monocypher's internal zeroization.
- **Passphrase buffers** (allocated by `sys/passphrase`): right-sized and `mlock`'d; released via `buffer_secure_free(p, len + 1)` (the `+1` covers the NUL terminator that is also `mlock`'d).
- **Subkeys** (`mac_key`, `prf_key`, keystream seed, candidate plaintext): live on the stack for one cipher call; `crypto_wipe`'d before return on both success and failure paths.

`mlock` failures are non-fatal — `kdf_master_key` and `keymgr_create` each emit a one-time-per-process advisory pointing at `RLIMIT_MEMLOCK` (`ulimit -l`). The default macOS limit (64 KiB) is too small to lock any non-trivial Argon2 work area.

## Performance

### Master-key derivation (cold session)

Re-bench on real hardware before tuning. Approximate values on commodity 2024-era hardware:

| Preset      | memory_mib | passes | Wall-clock     |
|-------------|------------|--------|----------------|
| `fast`      |    64      |   3    | ~250–400 ms    |
| `balanced`  |   256      |   3    | ~1.0 s         |
| `paranoid`  |  1024      |   4    | ~4–6 s         |

The defender pays this once per cold cache. The attacker pays it for every passphrase guess, multiplied by `attacker_RAM / memory_mib` parallel guesses.

### Per-file overhead (warm cache)

Once master_key is cached:

- 2 keyed BLAKE2b for SIV subkeys (`kdf_siv_subkeys`), µs.
- 1 keyed BLAKE2b absorption pass over `(header, path, plaintext)` for the SIV — bandwidth-bound.
- 1 keyed BLAKE2b for the keystream seed, µs.
- 1 XChaCha20 over `plaintext_len` bytes, bandwidth-bound.

For typical dotfiles (well under 100 KiB), per-file overhead is in the millisecond range — dominated by file I/O, not crypto.

### Content cache

`infra/content.c` deduplicates decryption when the same blob OID is read multiple times within a single command. Hashmap keyed by blob OID; the cache lives for one command and zeroes plaintext buffers before free.

## Configuration reference

```toml
[encryption]

# Enable encryption support. Default: false (opt-in).
enabled = false

# Strength preset. Default: "balanced".
strength = "balanced"

# Raw Argon2id overrides (advanced; both must be set together — setting one
# is a config error). When set, `strength` is ignored. Bounds:
#   argon2_memory_mib in [8, 4096]
#   argon2_passes     in [1, 20]
# argon2_memory_mib = 256
# argon2_passes     = 3

# Master-key cache lifetime (seconds).
#   0    : always prompt (also disables on-disk session cache)
#   -1   : never expire
#   N>0  : seconds before expiry
# Default: 3600.
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

### Validation

Run at config-load AND at the crypto boundary:

| Field                                    | Rule                                                       | Error                |
|------------------------------------------|------------------------------------------------------------|----------------------|
| `strength`                               | `"fast"`, `"balanced"`, or `"paranoid"`                    | `ERR_INVALID_CONFIG` |
| `argon2_memory_mib`                      | 8..4096 if set                                             | `ERR_INVALID_CONFIG` |
| `argon2_passes`                          | 1..20 if set                                               | `ERR_INVALID_CONFIG` |
| `argon2_memory_mib` and `argon2_passes`  | Both set together or neither                               | `ERR_INVALID_CONFIG` |
| Raw overrides + `strength`               | Raw overrides win; `strength` ignored (warning to stderr)  | warning              |
| `session_timeout`                        | -1, 0, or 1..INT32_MAX                                     | `ERR_INVALID_CONFIG` |
| `auto_encrypt[i]`                        | Valid gitignore pattern                                    | `ERR_INVALID_CONFIG` |

Crypto-boundary checks (`kdf_master_key`, `cipher_peek_params`, `cipher_encrypt`):

- `memory_mib ∈ [8, 4096]` else `ERR_CRYPTO`
- `passes ∈ [1, 20]` else `ERR_CRYPTO`

### Hardcoded constants

| Constant                  | Value                          | Rationale                                                   |
|---------------------------|--------------------------------|-------------------------------------------------------------|
| Algorithm                 | Argon2id                       | RFC 9106; only memory-hard primitive in Monocypher          |
| Argon2id salt             | 16-byte constant in `kdf.c`    | Single user, no cross-target benefit                        |
| Argon2 lanes              | 1                              | Forced by Monocypher's single-threaded implementation       |
| Cipher MAC tag size       | 32 bytes (BLAKE2b output)      | Long-term Git storage; 256-bit collision boundary           |
| Cipher nonce size         | 24 bytes (XChaCha20 nonce)     | First 24 bytes of the 32-byte SIV                           |
| Key sizes                 | 32 bytes                       | BLAKE2b output; ChaCha20 key                                |
| Argon2 `extras.key`       | Not used                       | Pepper (rejected; see *Salt* §)                             |
| Argon2 `extras.ad`        | Not used                       | Hostname / install-id binding breaks cross-machine recovery |

## Security analysis

### Cryptographic primitives

- **Argon2id** — RFC 9106, memory-hard password-based KDF.
- **BLAKE2b** — RFC 7693, used keyed for MAC and unkeyed for cache_key derivation.
- **XChaCha20** — RFC 8439 ChaCha20 with the Bernstein 24-byte-nonce extension; used by libsodium and Monocypher.
- **SIV pattern** — RFC 5297 in spirit; concrete construction is bespoke ETM-SIV with BLAKE2b.

### Key invariants

- **Determinism.** Identical `(passphrase, profile, path, plaintext, params)` produces byte-identical ciphertext. No randomness in the encryption path.
- **Cipher isolation.** `cipher.c` never sees the master key or the profile name; it operates only on `(mac_key, prf_key)`.
- **Framing.** Every variable-length input to keyed BLAKE2b is LE64-prefixed by `crypto_mac_absorb`. Domain tags are unique (compile-time check).
- **Header binding.** The 9-byte cipher header is bound into the SIV scope. Any tamper fails MAC, not parse.
- **Constant-time compare.** Tag bytes compared via `crypto_verify32`, never `memcmp`.
- **Output zeroization.** Every error path wipes partial outputs via `crypto_wipe` before return.
- **DoS bounds.** Header-recorded Argon2 params validated against `KDF_ARGON2_*_MAX` BEFORE allocation.
- **Path canonicalization.** `cipher.c` does NO path normalization; the producer's canonical bytes are bound verbatim. Cross-platform Unicode drift falls on the caller (see *Limitations*).

### Defense in depth

- Argon2 work area wiped twice on every exit path (Monocypher's internal zero plus an explicit `crypto_wipe`).
- Header validation runs at every boundary that sees the bytes (`cipher_peek_params`, `cipher_encrypt`, `cipher_decrypt`).
- Session cache load: MAC verify before expiry check (trusted bytes drive the comparison).
- Magic + version mismatch routes through the metadata-vs-sniff truth table before any decrypt attempt.

### Limitations

1. **Deterministic encryption leaks change patterns.** Identical files under the same key produce identical ciphertext; Git history reveals **whether** an encrypted file changed at a given path. Intrinsic to deterministic SIV.
2. **Storage path is part of the SIV input.** Renaming an encrypted file requires re-encrypting under the new path. The path itself appears in plaintext in `.dotta/metadata.json`.
3. **Profile names are public.** They appear as Git branch names. Per-profile keys provide cryptographic isolation; profile *existence* is not hidden.
4. **Session cache is obfuscation, not encryption.** Re-stated from the threat model: an attacker with the cache file plus hostname and username can recover the master key without cracking the passphrase. `dotta key clear` is the response when this matters.
5. **Non-ASCII paths are not portable across normalization-divergent machines.** Unicode NFC vs. NFD path bytes produce distinct SIVs. NFC normalization is deferred until needed; remediation is `dotta remove` + `dotta add` on the target machine.

## Implementation map

| Concern                       | Module                | Public surface                                                 |
|-------------------------------|-----------------------|----------------------------------------------------------------|
| Memory-hard derivation        | `src/crypto/kdf`      | `kdf_master_key`, `kdf_siv_subkeys`, `kdf_validate_params`     |
| Keyed-BLAKE2b chokepoint      | `src/crypto/mac`      | `crypto_mac_init/absorb/final/oneshot`, `crypto_domain_t`      |
| SIV encrypt/decrypt + format  | `src/crypto/cipher`   | `cipher_encrypt`, `cipher_decrypt`, `cipher_is_encrypted`, `cipher_peek_params` |
| Master-key lifecycle          | `src/crypto/keymgr`   | `keymgr_create/encrypt/decrypt/set_passphrase/clear/probe_key/time_until_expiry/free` |
| On-disk session cache         | `src/crypto/session`  | `session_save`, `session_load`, `session_clear`                |
| Passphrase prompt + env       | `src/sys/passphrase`  | `passphrase_prompt`, `passphrase_from_env`                     |
| Cryptographic random bytes    | `src/sys/entropy`     | `entropy_fill`                                                 |
| Encryption policy             | `src/core/policy`     | `encryption_policy_should_encrypt`, `encryption_policy_matches_auto_patterns`, `encryption_policy_is_active` |
| Content cache (decrypt cache) | `src/infra/content`   | `content_cache_*`                                              |

`policy` and `passphrase` moved out of `src/crypto/` in this rewrite. Neither calls a cryptographic primitive — `policy` resolves a boolean from `config_t` and `metadata_t`; `passphrase` is TTY UX with `mlock`-backed buffer ownership — so they did not belong in the crypto layer.

## References

- Argon2 — RFC 9106. <https://datatracker.ietf.org/doc/html/rfc9106>
- BLAKE2 — RFC 7693. <https://datatracker.ietf.org/doc/html/rfc7693>
- ChaCha20 / XChaCha20 — RFC 8439. <https://datatracker.ietf.org/doc/html/rfc8439>
- SIV — RFC 5297. <https://datatracker.ietf.org/doc/html/rfc5297>
- Monocypher — <https://monocypher.org/>
- Source: `src/crypto/{kdf,mac,cipher,keymgr,session}.{c,h}`, `src/sys/{passphrase,entropy}.{c,h}`, `src/core/policy.{c,h}`, `src/infra/content.{c,h}`.
