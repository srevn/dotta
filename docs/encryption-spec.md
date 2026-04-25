# Encryption Technical Specification

## Overview

Dotta implements transparent file encryption for sensitive dotfiles, allowing encrypted storage in Git repositories while maintaining usability. Files are encrypted at rest in Git and decrypted during deployment to the filesystem.

**Design Goals:**
- **Deterministic encryption** - Same file + key produces identical ciphertext (Git-friendly, enables deduplication)
- **Path-bound security** - Files cryptographically bound to their storage location
- **Nonce-misuse resistance** - No random nonces or IV management required
- **Single passphrase UX** - One passphrase for all profiles with automatic key derivation
- **Session-based caching** - Balance security and usability

## Cryptographic Foundation

### libhydrogen

The implementation uses [libhydrogen](https://github.com/jedisct1/libhydrogen), a minimal cryptographic library built on two primitives:

- **Curve25519** - Elliptic curve for key exchange and signatures
- **Gimli** - Cryptographic permutation for hashing and encryption

**Rationale:**
- Small, auditable codebase (~3000 LOC)
- Zero dynamic memory allocation
- Hard-to-misuse high-level API
- Portable C99 implementation
- ISC license (liberal)

### Primitive Usage

| Operation | libhydrogen Function | Algorithm |
|-----------|---------------------|-----------|
| Password hashing | `hydro_pwhash_deterministic` | Gimli-based KDF with configurable work factor |
| Balloon hashing | `hydro_hash_hash` + `hydro_random_buf_deterministic` | Memory-hard KDF (Boneh et al., 2016) |
| Key derivation | `hydro_kdf_derive_from_key` | KMAC-like construction over Gimli |
| Keyed hashing | `hydro_hash_hash` | KMAC variant (similar to NIST SP 800-185) |
| Deterministic RNG | `hydro_random_buf_deterministic` | Gimli-based PRNG |
| Memory clearing | `hydro_memzero` | Secure memory zeroing |
| Constant-time comparison | `hydro_equal` | Timing-safe equality check |

## Key Hierarchy

```
User Passphrase
    ↓ [hydro_pwhash_deterministic with high work factor]
CPU Key (32 bytes, intermediate)
    ↓ [balloon_harden with memory-hard buffer, when memlimit > 0]
Master Key (32 bytes)
    ↓ [hydro_hash_hash with profile name as input]
Profile Key (32 bytes, one per profile)
    ↓ [hydro_kdf_derive_from_key]
    ├─→ MAC Key (32 bytes, subkey_id=1)   — used to compute the SIV over (path, plaintext)
    └─→ PRF Key (32 bytes, subkey_id=2)   — used to derive the keystream seed from the SIV
         ↓ [hydro_hash_hash with the SIV as input]
         Keystream Seed (32 bytes, plaintext-dependent)
```

### Key Derivation Details

**Master Key Derivation (two phases):**

Phase 1 — CPU-hard (Gimli permutation iterations):
```c
hydro_pwhash_deterministic(
    cpu_key,              // Output: 32 bytes (intermediate)
    passphrase,           // Input: user passphrase
    "dotta/v1",           // Context: version tag
    zero_master,          // Master: zeros (direct derivation mode)
    opslimit=10000,       // CPU cost (configurable)
    memlimit=0,           // Memory (unused by libhydrogen)
    threads=1             // Single-threaded (fixed)
)
```

Phase 2 — Memory-hard (balloon hashing, when memlimit > 0):
```c
balloon_harden(
    cpu_key,              // Input: 32-byte CPU-hard key
    memlimit=67108864,    // Memory: 64 MB (configurable)
    master_key            // Output: 32 bytes
)
```

When `memlimit = 0`, balloon hashing is skipped and `cpu_key` becomes the master key directly (CPU-hard only).

**Profile Key Derivation:**
```c
hydro_hash_hash(
    profile_key,          // Output: 32 bytes
    profile_name,         // Input: profile name string
    "profile ",           // Context: 8 bytes
    master_key            // Key: master key
)
```

**MAC/PRF Subkey Derivation:**
```c
hydro_kdf_derive_from_key(mac_key, 32, 1, "dottasiv", profile_key)
hydro_kdf_derive_from_key(prf_key, 32, 2, "dottasiv", profile_key)
```

**Keystream Seed Derivation:**
```c
hydro_hash_hash(
    keystream_seed,       // Output: 32 bytes
    siv,                  // Input: the 32-byte synthetic IV (a function of plaintext)
    "dottactr",           // Context: 8 bytes
    prf_key               // Key: PRF subkey
)
```

The keystream seed is derived from the *secret* PRF key applied to the (public)
SIV. If the seed were a function of the SIV alone, anyone with the ciphertext
could reproduce the keystream and recover the plaintext.

## Balloon Hashing (Memory-Hard Layer)

### Motivation

libhydrogen's `hydro_pwhash_deterministic` provides CPU hardness via Gimli permutation iterations, but has **zero memory hardness** — the `memlimit` parameter is silently ignored (`(void) memlimit;` in the implementation). This makes the KDF trivially parallelizable on GPUs/ASICs, where thousands of cores can each run the derivation using negligible memory.

Balloon hashing (Boneh, Corrigan-Gibbs, Schechter, 2016) adds a memory-hard layer on top of the CPU-hard derivation, forcing each derivation attempt to allocate and randomly access a large buffer (default: 64 MB). This makes parallel attacks proportionally expensive in both compute and memory.

### Algorithm

The balloon hashing layer wraps the CPU-hard key (`cpu_key`) and produces the final master key through three phases:

**Phase 1 — Expansion:** Fill a buffer of `n_blocks = memlimit / 1024` blocks, each 1024 bytes. Each block gets a unique seed derived from `cpu_key` and the block index, then expanded via `hydro_random_buf_deterministic`:
```
for i in 0..n_blocks:
    seed = hash(i, context="dottamem", key=cpu_key)
    block[i] = PRNG(seed, 1024 bytes)
```

**Phase 2 — Mixing (3 rounds):** Data-dependent random access that provides memory hardness. For each block, derive a pseudo-random index from the block's content, then mix the current block with the previous and randomly-indexed blocks:
```
for round in 0..3:
    for i in 0..n_blocks:
        prev = block[(i-1) % n_blocks]
        idx = hash(round||i, context="dottaidx", key=block[i]) % n_blocks
        mix = streaming_hash(block[idx] || block[i], context="dottamix", key=prev)
        block[i] = PRNG(mix, 1024 bytes)
```

**Phase 3 — Finalization:** Hash the last block to produce the master key:
```
master_key = hash(block[n_blocks-1], context="dottafin", key=cpu_key)
```

### Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Block size | 1024 bytes | Balance between hash calls and memory bandwidth |
| Mixing rounds | 3 | Standard recommendation from the paper |
| Default memlimit | 64 MB (67,108,864 bytes) | 65,536 blocks |
| Minimum memlimit | 1 MB (1,048,576 bytes) | 1,024 blocks |
| memlimit = 0 | Disabled | CPU-hard only (pre-balloon behavior) |

### Security Properties

- **Provable memory hardness:** Computing the output requires O(memlimit) memory (proven lower bound)
- **Time-memory trade-off resistance:** 3 mixing rounds provide strong resistance
- **Sequential within rounds:** Block `i` depends on block `i-1`, preventing intra-round parallelism
- **Data-dependent access:** Random index depends on block content, preventing precomputation
- **Deterministic:** Same inputs always produce the same output

### Secure Memory Handling

- Buffer is `mlock()`'d to prevent swapping to disk (best-effort, non-fatal if fails)
- Buffer is `hydro_memzero()`'d before freeing
- Buffer is `munlock()`'d after zeroing
- All intermediate seeds and hashes are zeroed after use
- CPU key (intermediate between pwhash and balloon) is zeroed after balloon completes

### Performance

For 64 MB (default):
- Expansion: 65,536 hash + PRNG calls
- Mixing: 3 × 65,536 = 196,608 hash + PRNG calls
- Total: ~262K cryptographic operations
- Expected time: ~200-400ms on modern hardware (happens once per session)

## SIV Construction

Dotta implements a custom **SIV (Synthetic IV)** construction for deterministic authenticated encryption. This is a well-established pattern that provides both confidentiality and authenticity without requiring nonces.

### Construction Steps

**Encryption:**

1. **Derive subkeys** from profile key:
   - `mac_key = KDF(profile_key, subkey_id=1, context="dottasiv")`
   - `prf_key = KDF(profile_key, subkey_id=2, context="dottasiv")`

2. **Compute the synthetic IV** over (path, plaintext) — the defining
   property of SIV. The IV doubles as the authentication tag:
   - `siv = HMAC(mac_key, len(storage_path) || storage_path || plaintext, context="dottamac")`
   - Path length is encoded as 8-byte little-endian for domain separation
     between path and plaintext bytes; BLAKE2 is not length-extension
     vulnerable, so no trailing length is required.

3. **Derive the keystream seed** from the SIV under the PRF key (the SIV
   itself is public; passing it through a keyed hash keeps the keystream
   behind the profile key):
   - `keystream_seed = HMAC(prf_key, siv, context="dottactr")`

4. **Generate keystream** deterministically:
   - `keystream = DeterministicPRNG(keystream_seed, length=plaintext_len)`

5. **Encrypt plaintext** via XOR:
   - `ciphertext = plaintext ⊕ keystream`

6. **Assemble output**:
   - `[Magic Header 8B][SIV 32B][Ciphertext N B]`

Because the SIV depends on the plaintext, two different plaintexts at the
same `(profile_key, path)` yield different SIVs — and therefore different
keystreams — giving nonce-misuse resistance.

**Decryption:**

1. Parse header and extract the stored `siv` and the ciphertext body.
2. Derive `mac_key` and `prf_key` (same as encryption).
3. Derive `keystream_seed = HMAC(prf_key, stored_siv, context="dottactr")`.
4. Generate the keystream and recover a candidate plaintext:
   - `candidate_plaintext = ciphertext ⊕ keystream`
5. Re-compute the SIV over the candidate plaintext:
   - `siv' = HMAC(mac_key, len(storage_path) || storage_path || candidate_plaintext, context="dottamac")`
6. Constant-time compare `siv'` against the stored `siv`.
   - On mismatch: securely zero the candidate plaintext and return
     `ERR_CRYPTO`. The candidate is never returned to the caller.
   - On match: return the candidate plaintext.

### Security Properties

- **Deterministic:** Same (path, content, key) → same ciphertext
- **Authenticated:** SIV provides integrity verification (32-byte MAC)
- **Path-bound:** Storage path is cryptographically bound via AAD
- **Nonce-misuse resistant:** No nonce management required
- **Key isolation:** Independent MAC and PRF keys prevent cryptographic cross-contamination

### Why SIV?

Traditional AEAD modes (AES-GCM, ChaCha20-Poly1305) require unique nonces. In version control systems, deterministic output is essential for:
- **Git deduplication** - Identical files share storage
- **Idempotency** - Re-running `add` doesn't create churn
- **Diff-ability** - Only modified files show changes

SIV constructions trade randomness for determinism while maintaining strong security properties.

## File Format

### Encrypted File Structure

```
┌──────────────────────┬──────┬────────────────────┐
│ Magic Header         │ SIV  │ Ciphertext         │
├──────────────────────┼──────┼────────────────────┤
│ 8 bytes              │ 32 B │ N bytes            │
└──────────────────────┴──────┴────────────────────┘

Magic Header (8 bytes):
  [0-4]   "DOTTA" (magic string)
  [5]     0x04 (version byte)
  [6-7]   0x00 0x00 (reserved/padding)

SIV (32 bytes):
  MAC tag authenticating len(storage_path) || storage_path || plaintext.
  The SIV is a function of the plaintext (the defining SIV property)
  and also doubles as the keystream-seed input via prf_key.

Ciphertext (N bytes):
  plaintext ⊕ keystream, where keystream = PRNG(HMAC(prf_key, siv))
```

**Total overhead:** 40 bytes per file

## Encryption Workflow

### Adding Files

```
1. User: dotta add -p myprofile ~/.ssh/id_rsa --encrypt

2. Policy Decision (crypto/policy.c):
   - Check --encrypt flag → YES
   - Result: should_encrypt = true

3. Read File:
   - Load plaintext from filesystem

4. Encryption (crypto/encryption.c):
   - Get profile key from keymgr (may prompt for passphrase)
   - Derive MAC/PRF subkeys from profile key
   - Compute SIV over (path, plaintext) — the synthetic IV
   - Derive keystream seed from the SIV under prf_key
   - Generate keystream
   - Encrypt: ciphertext = plaintext ⊕ keystream
   - Assemble: [Magic][SIV][Ciphertext]

5. Store in Git:
   - Create blob from encrypted data
   - Update tree in profile branch

6. Metadata (core/metadata.c):
   - Record: "home/.ssh/id_rsa: encrypted=true, mode=0600"
   - Commit metadata.json to profile branch
```

### Deploying Files

```
1. User: dotta apply -p myprofile

2. Load Profile:
   - Read metadata.json
   - Enumerate tracked files

3. For Each File (infra/content.c):
   - Load blob from Git tree
   - Check magic header

   IF ENCRYPTED:
     - Get profile key from keymgr (may prompt once)
     - Derive MAC/PRF subkeys
     - Derive keystream seed from the stored SIV under prf_key
     - Generate keystream
     - Decrypt candidate: candidate_plaintext = ciphertext ⊕ keystream
     - Re-compute SIV over (path, candidate_plaintext)
     - Constant-time compare against the stored SIV
     - On mismatch: securely zero the candidate and fail
     - On match: return the candidate plaintext

   ELSE:
     - Use blob content directly

4. Deploy:
   - Copy plaintext to target location
   - Restore permissions from metadata
   - Update deployment state
```

### Auto-Encryption

Files can be automatically encrypted based on glob patterns:

**Configuration (config.toml):**
```toml
[encryption]
enabled = true
auto_encrypt = [
    ".ssh/id_*",        # SSH private keys
    "*.key",            # Any .key files
    ".gnupg/secring*"   # GPG secret keyrings
]
```

**Pattern Matching (crypto/policy.c, evaluated via base/gitignore.c):**
- Auto-encrypt patterns are compiled once into a `gitignore_ruleset_t` at
  `config_load` and stored on the config handle (`config->auto_encrypt.rules`).
- Per-file matching runs in `encryption_policy_matches_auto_patterns`, which
  strips the storage prefix (`home/`, `root/`, `custom/`) before evaluating
  patterns so users can write `.ssh/id_*` instead of `home/.ssh/id_*`.
- Full gitignore semantics: last-match-wins with `!` negation support
  (`*.key` + `!public.key` correctly excludes `public.key`).
- Patterns without `/` match basename at any depth.
- Patterns with `/` match full path from root (anchored).
- Example: `*.key` matches `home/api.key` and `home/dir/secret.key`.
- Example: `.ssh/id_*` matches `home/.ssh/id_rsa` (anchored to profile root).

## Key Management

### Session-Based Caching

**Design (crypto/keymgr.c):**

```c
struct keymgr {
    /* Configuration */
    uint64_t opslimit;        // CPU cost for password hashing
    size_t memlimit;          // Memory cost for balloon hashing (0 = disabled)
    int32_t session_timeout;  // Timeout in seconds (0 = always prompt, -1 = never expire)

    /* Cached master key */
    uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
    bool has_key;             // Is master key cached?
    time_t cached_at;         // When was key cached (monotonic time)
    bool mlocked;             // Is memory locked with mlock()?
};
```

In-memory cache expiry uses `CLOCK_MONOTONIC` (immune to wall-clock
manipulation). The persistent disk cache below uses Unix wall-clock
timestamps because `CLOCK_MONOTONIC` resets across reboots.

**Cache Lifecycle:**

1. **First Request:**
   - Check file cache at `~/.cache/dotta/session` (if session_timeout ≠ 0)
   - If cache hit: Load and verify cached master key
   - If cache miss: Prompt for passphrase (stdin with echo disabled)
   - Derive master key (expensive: ~10,000 iterations)
   - Cache master key in memory
   - Save master key to file cache (persistent)
   - Attempt `mlock()` to prevent swapping
   - Start session timer

2. **Subsequent Requests (within same invocation):**
   - Return cached master key from memory (O(1))
   - Derive profile key (fast: single hash)
   - Cache profile key for reuse

3. **Cross-Invocation Requests (separate process):**
   - Load cached master key from file (no passphrase prompt)
   - Verify MAC and expiry
   - Cache in memory for duration of command
   - Derive profile keys as needed

4. **Expiration:**
   - Default timeout: 3600 seconds (1 hour)
   - Configurable via `session_timeout` in config
   - `-1` = never expire (persist until manual clear)
   - `0` = always prompt (no caching, file cache disabled)

5. **Cleanup:**
   - `dotta key clear` - Manual clear (both memory and file)
   - Session timeout - Automatic expiry (file cache self-validates)
   - Process exit - Memory cleared via `hydro_memzero` (file persists)

### Passphrase Sources (priority order)

1. **File cache** (if session_timeout ≠ 0, verified and not expired)
2. **Memory cache** (if not expired within current process)
3. **Environment variable:** `DOTTA_ENCRYPTION_PASSPHRASE` (with security warning)
4. **Interactive prompt** (stdin with `tcsetattr` to disable echo)

### File-Based Session Cache

**Purpose:** Persist master key across command invocations to eliminate repeated passphrase prompts during multi-command workflows.

**Location:** `~/.cache/dotta/session` (XDG Base Directory compatible)

**File Format (108 bytes total):**

```
┌────────────┬─────────┬──────────┬──────────────┬──────────────┬──────────────┬───────────────┬──────────┐
│ Magic      │ Version │ Reserved │ Created At   │ Expires At   │ Machine Salt │ Encrypted Key │ MAC      │
├────────────┼─────────┼──────────┼──────────────┼──────────────┼──────────────┼───────────────┼──────────┤
│ "DOTTASES" │ 0x01    │ 0x00×3   │ uint64_t     │ uint64_t     │ 16 bytes     │ 32 bytes      │ 32 bytes │
│ 8 bytes    │ 1 byte  │ 3 bytes  │ 8 bytes      │ 8 bytes      │              │               │          │
└────────────┴─────────┴──────────┴──────────────┴──────────────┴──────────────┴───────────────┴──────────┘

Magic Header (8 bytes):
  "DOTTASES" - Cache file identifier

Metadata (12 bytes):
  version:    Format version (1)
  reserved:   Future use (must be 0)
  created_at: Unix timestamp when cache was created
  expires_at: Unix timestamp when cache expires (0 = never)

Security Fields (80 bytes):
  machine_salt:    Random salt for machine binding (16 bytes)
  encrypted_key:   Obfuscated master key (32 bytes)
  mac:            HMAC for integrity and authenticity (32 bytes)
```

**Cryptographic Design:**

```
1. Machine Identity Derivation:
   machine_id = hostname || '\0' || username

2. Cache Key Derivation (machine-bound):
   cache_key = HASH(machine_id || machine_salt, context="dottacch", key=NULL)

3. Master Key Obfuscation (XOR with deterministic stream):
   stream = DeterministicPRNG(cache_key, length=32)
   encrypted_key = master_key ⊕ stream

4. MAC Computation (authenticated data):
   mac = HMAC(created_at || expires_at || machine_salt || encrypted_key,
              context="dottamac", key=cache_key)
```

**Security Properties:**

- **Obfuscation:** Master key XORed with deterministic keystream (not plaintext in file)
- **Machine-binding:** Cache only valid on same hostname + username combination
- **Time-bound:** Automatic expiry based on `session_timeout` configuration
- **Tamper-evident:** MAC verification detects any modification
- **Appropriate security:** Lightweight protection suitable for local filesystem threat model

**Cache Operations:**

```c
// Save (after passphrase entry)
session_cache_save(master_key, session_timeout)
  → Create ~/.cache/dotta/ directory with 0700 permissions
  → Generate random machine_salt
  → Derive cache_key from machine identity + salt
  → Encrypt master_key using deterministic stream cipher
  → Compute MAC over all authenticated fields
  → Write to file with atomic permissions (open() with 0600 mode)
  → fsync() for durability

// Load (on key request)
session_cache_load(out_master_key)
  → Read cache file
  → Verify permissions are 0600 (delete if wrong)
  → Validate magic header and version
  → Check expiry timestamp
  → Derive cache_key from current machine identity + stored salt
  → Recompute MAC and verify (constant-time)
  → If valid: decrypt master_key via XOR with keystream
  → If invalid: delete cache file and return error

// Clear (manual or automatic)
session_cache_clear()
  → Secure zero: overwrite file with zeros before unlink()
  → Remove file from filesystem
```

**File Permissions:**

- **Directory:** `~/.cache/dotta/` created with mode 0700 (owner-only access)
- **Cache file:** Created atomically with mode 0600 via `open(O_CREAT, 0600)`
- **Defense-in-depth:** Explicit `fchmod(0600)` verification after creation
- **Validation:** Cache load fails if permissions are not exactly 0600

**Error Handling:**

| Failure Scenario | Behavior | Rationale |
|-----------------|----------|-----------|
| Cache doesn't exist | Fallback to passphrase prompt | Expected on first use |
| Cache expired | Delete cache, prompt for passphrase | Normal timeout behavior |
| MAC verification failed | Delete cache, prompt for passphrase | Tampered or wrong machine |
| Wrong permissions | Delete cache, prompt for passphrase | Security violation |
| Machine identity changed | MAC fails → delete cache | Hostname or user change |
| Corrupted file | Delete cache, prompt for passphrase | Bit rot or incomplete write |
| Save failure | Warn but continue (memory cache works) | Non-fatal, degraded UX |

**Threat Model:**

**Protected Against:**
- Casual inspection: Cache content not plaintext
- File tampering: MAC detects modifications
- Cross-machine copying: Machine binding prevents use on different systems
- Stale credentials: Automatic expiry enforcement

**Not Protected Against:**
- Local root access: Root can read any user file
- Memory dumps: Master key in process memory during use
- Malicious code execution: No sandboxing
- Physical disk forensics: Obfuscation is not encryption

**Rationale:** The cache protects Git repositories from passive compromise while accepting that the local filesystem is trusted. This aligns with the overall dotta threat model where encryption protects remote/offline repositories, not the actively-used system.

### Security Considerations

**Memory Protection:**
- Master key stored in process memory (vulnerable to dumps)
- `mlock()` prevents swapping to disk (best-effort, may fail without privileges)
- Graceful degradation: warns if `mlock()` fails, continues operation
- Secure clearing: `hydro_memzero()` on timeout/clear/exit
- Profile key cache cleared when master key changes

**Environment Variable Risk:**
```bash
# INSECURE - visible in process listings
DOTTA_ENCRYPTION_PASSPHRASE="secret" dotta apply

# Better: use interactive prompt or key caching
dotta key set     # Prompts once, caches for session
dotta apply       # Uses cached key
```

## Performance Optimization

### Profile Key Caching

**Problem:** Deriving profile keys is fast (~microseconds) but becomes bottleneck during batch operations (e.g., `status` with 1000 files).

**Solution (crypto/keymgr.c, `keymgr_get_profile_key`):**
```c
error_t *keymgr_get_profile_key(
    keymgr *km,
    const char *profile,
    uint8_t out_profile_key[ENCRYPTION_PROFILE_KEY_SIZE]
) {
    // 1. Check cache, but only if master key is still valid.
    //    If the master key has expired (session timeout), cached profile keys
    //    must not be served — that would bypass re-authentication. Clear and
    //    fall through to a fresh derivation, which prompts as needed.
    if (km->profile_keys) {
        if (!is_key_valid(km)) {
            hashmap_clear(km->profile_keys, secure_free_profile_key);
        } else {
            uint8_t *cached_key = hashmap_get(km->profile_keys, profile);
            if (cached_key) {
                memcpy(out_profile_key, cached_key, ENCRYPTION_PROFILE_KEY_SIZE);
                return NULL;  // Cache hit
            }
        }
    }

    // 2. Cache miss or expired: get master key (may prompt), derive and cache.
    //    ... keymgr_get_key + encryption_derive_profile_key + hashmap_set ...
    return NULL;
}
```

**Benefits:**
- **First access:** Full derivation (master key + profile key)
- **Subsequent:** O(1) cache lookup (30,000x faster)
- **Lifetime:** Tied to master key cache (invalidated on session timeout)
- **Memory:** ~32 bytes per profile (negligible)

### Content Caching

**Problem:** Commands like `status` need to read and decrypt the same files repeatedly.

**Solution (infra/content.c):**
```c
content_cache_t *cache = content_cache_create(repo, keymgr);

for (each_file) {
    const buffer_t *content;  // Borrowed reference
    content_cache_get_from_blob_oid(
        cache, &blob_oid, storage_path, profile,
        expected_encrypted, &content
    );
    // ... use content (cache owns buffer, don't free) ...
}

content_cache_free(cache);  // Frees all cached buffers (zeros plaintext first)
```

**Benefits:**
- **Deduplication:** Same blob OID → single decryption
- **O(1) lookup:** Hashmap keyed by blob OID
- **Memory-efficient:** Cache cleared after operation
- **Type-safe:** `const` pointers prevent misuse

## Configuration

### Encryption Settings (config.toml)

```toml
[encryption]
# Enable encryption subsystem
enabled = true

# Password hashing work factor (higher = slower, more secure)
# Recommended: 10000+ for interactive use
opslimit = 10000

# Memory hardness for key derivation via balloon hashing (in MB)
# 0 = disabled, minimum 1 MB when enabled
memlimit = 64  # 64 MB (default)

# Session timeout in seconds (-1 = never, 0 = always prompt, N = expire after N seconds)
session_timeout = 3600  # 1 hour

# Auto-encrypt patterns (gitignore-style globs)
auto_encrypt = [
    ".ssh/id_*",
    "*.key",
    ".gnupg/secring*"
]
```

### Work Factor Tuning

**Opslimit Recommendations (CPU hardness):**
- **Development:** 1000 (faster iteration)
- **Production:** 10000+ (recommended)
- **High security:** 100000+ (very slow, paranoid)

**Memlimit Recommendations (memory hardness):**
- **Disabled:** 0 (CPU hardness only, not recommended for production)
- **Low memory:** 1 MB (1,048,576) — minimal protection
- **Moderate:** 16 MB (16,777,216) — constrained environments
- **Recommended:** 64 MB (67,108,864) — good balance (default)
- **High security:** 256 MB (268,435,456) — for systems with ample RAM

**Benchmark (approximate, combined opslimit + memlimit):**
```
opslimit=10000, memlimit=0       → ~100ms  (CPU only, GPU-vulnerable)
opslimit=10000, memlimit=64MB    → ~300ms  (recommended)
opslimit=10000, memlimit=256MB   → ~800ms  (high security)
```

Trade-off: Higher values protect against brute-force but slow down legitimate use and increase memory requirements.

## Security Analysis

### Threat Model

**Protected Against:**
- **Passive repository compromise:** Encrypted files unreadable without passphrase
- **Tampering:** SIV detects modifications (authentication failure)
- **Path confusion:** Files bound to specific paths via AAD
- **Key reuse across profiles:** Independent profile keys
- **Timing attacks:** Constant-time MAC verification

**Not Protected Against:**
- **Memory dumps:** Master key in process memory
- **Malicious code execution:** No sandboxing
- **Weak passphrases:** User-chosen entropy
- **Keyloggers:** Passphrase entry observable
- **Rubber hose cryptanalysis:** Physical coercion

### Cryptographic Assumptions

**Relies on:**
- Gimli permutation security (peer-reviewed, NIST lightweight crypto finalist)
- KMAC construction soundness (NIST SP 800-185 standard)
- `hydro_pwhash` work factor adequacy (CPU hardness)
- Balloon hashing memory-hardness proofs (Boneh et al., 2016)
- Proper implementation (code audit recommended)

**Does Not Rely On:**
- Random number generation quality (deterministic construction)
- Nonce uniqueness (nonce-misuse resistant)

### Known Limitations

1. **Deterministic encryption leaks patterns:**
   - Identical files → identical ciphertext
   - Git history shows when files change (but not what changed)
   - Mitigation: This is a design trade-off for Git compatibility

2. **Storage path part of AAD:**
   - Renaming file requires re-encryption
   - Path recorded in metadata.json (visible)
   - Mitigation: Intentional (prevents unauthorized path changes)

3. **Profile isolation not perfect:**
   - Profile names visible in metadata
   - Different profiles with same passphrase derive different keys (via profile name)
   - Compromise of one profile doesn't compromise others (cryptographic isolation)

## Implementation Notes

### Context Strings

libhydrogen requires 8-byte context strings for domain separation:

| Context | Value | Purpose |
|---------|-------|---------|
| `ENCRYPTION_CTX_PWHASH` | `"dotta/v1"` | CPU-hard key derivation (pwhash) |
| `ENCRYPTION_CTX_BALLOON_EXPAND` | `"dottamem"` | Balloon expansion: per-block seed derivation |
| `ENCRYPTION_CTX_BALLOON_INDEX` | `"dottaidx"` | Balloon mixing: pseudo-random index derivation |
| `ENCRYPTION_CTX_BALLOON_MIX` | `"dottamix"` | Balloon mixing: block combination |
| `ENCRYPTION_CTX_BALLOON_FINAL` | `"dottafin"` | Balloon finalization: master key extraction |
| `ENCRYPTION_CTX_KDF` | `"profile "` | Profile key derivation |
| `ENCRYPTION_CTX_SIV_KDF` | `"dottasiv"` | MAC/PRF subkey derivation |
| `ENCRYPTION_CTX_SIV_MAC` | `"dottamac"` | SIV computation over (path, plaintext) |
| `ENCRYPTION_CTX_SIV_CTR` | `"dottactr"` | Keystream seed derivation from the SIV under prf_key |
| (Session cache) | `"dottacch"` | Cache key derivation |
| (Session cache) | `"dottamac"` | Cache MAC computation (reuses SIV MAC context) |

**Rationale:** Prevent cross-protocol attacks, ensure cryptographic domain separation.

**Note:** The session cache reuses the `"dottamac"` context (shared with SIV MAC computation) since both perform keyed HMAC operations with different key material, ensuring no cryptographic interference.

### Zero Master Key in pwhash

```c
static const uint8_t zero_master[hydro_pwhash_MASTERKEYBYTES] = {0};

hydro_pwhash_deterministic(
    cpu_key, 32, passphrase, passphrase_len,
    "dotta/v1", zero_master, opslimit, 0, 1
);
// cpu_key is then passed through balloon_harden() when memlimit > 0
```

**Why zero master?** libhydrogen's `hydro_pwhash_deterministic` supports two modes:
1. **Password storage:** Master key encrypts password hash representatives
2. **Direct key derivation:** Zero master key performs direct KDF (our use case)

We use direct derivation mode (no password storage), so zero master is correct.

## References

- [libhydrogen documentation](https://github.com/jedisct1/libhydrogen/wiki)
- [Balloon Hashing](https://eprint.iacr.org/2016/027) - Boneh, Corrigan-Gibbs, Schechter (2016)
- [SIV (RFC 5297)](https://tools.ietf.org/html/rfc5297) - Synthetic Initialization Vector
- [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final) - KMAC construction
- [Gimli permutation](https://gimli.cr.yp.to/) - Cryptographic primitive
- Dotta source code: `src/crypto/`, `src/infra/content.c`

