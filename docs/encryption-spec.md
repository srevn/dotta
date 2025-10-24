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
- Small, auditable codebase (~4000 LOC)
- Zero dynamic memory allocation
- Hard-to-misuse high-level API
- Portable C99 implementation
- ISC license (liberal)

### Primitive Usage

| Operation | libhydrogen Function | Algorithm |
|-----------|---------------------|-----------|
| Password hashing | `hydro_pwhash_deterministic` | Gimli-based KDF with configurable work factor |
| Key derivation | `hydro_kdf_derive_from_key` | KMAC-like construction over Gimli |
| Keyed hashing | `hydro_hash_hash` | KMAC variant (similar to NIST SP 800-185) |
| Deterministic RNG | `hydro_random_buf_deterministic` | Gimli-based PRNG |
| Memory clearing | `hydro_memzero` | Secure memory zeroing |
| Constant-time comparison | `hydro_equal` | Timing-safe equality check |

## Key Hierarchy

```
User Passphrase
    ↓ [hydro_pwhash_deterministic with high work factor]
Master Key (32 bytes)
    ↓ [hydro_hash_hash with profile name as input]
Profile Key (32 bytes, one per profile)
    ↓ [hydro_kdf_derive_from_key]
    ├─→ MAC Key (32 bytes, subkey_id=1)
    └─→ CTR Key (32 bytes, subkey_id=2)
         ↓ [hydro_hash_hash with storage path]
         Stream Seed (32 bytes, path-specific)
```

### Key Derivation Details

**Master Key Derivation:**
```c
hydro_pwhash_deterministic(
    master_key,           // Output: 32 bytes
    passphrase,           // Input: user passphrase
    "dotta/v1",          // Context: version tag
    zero_master,          // Master: zeros (direct derivation mode)
    opslimit=10000,       // CPU cost (configurable)
    memlimit=0,           // Memory (fixed)
    threads=1             // Single-threaded
)
```

**Profile Key Derivation:**
```c
hydro_hash_hash(
    profile_key,          // Output: 32 bytes
    profile_name,         // Input: profile name string
    "profile ",           // Context: 8 bytes
    master_key            // Key: master key
)
```

**MAC/CTR Subkey Derivation:**
```c
hydro_kdf_derive_from_key(mac_key, 32, 1, "dottasiv", profile_key)
hydro_kdf_derive_from_key(ctr_key, 32, 2, "dottasiv", profile_key)
```

**Stream Seed Derivation:**
```c
hydro_hash_hash(
    stream_seed,          // Output: 32 bytes
    storage_path,         // Input: path in profile
    "dottactr",           // Context: 8 bytes
    ctr_key               // Key: CTR subkey
)
```

## SIV Construction (Version 2)

Dotta implements a custom **SIV (Synthetic IV)** construction for deterministic authenticated encryption. This is a well-established pattern that provides both confidentiality and authenticity without requiring nonces.

### Construction Steps

**Encryption:**

1. **Derive subkeys** from profile key:
   - `mac_key = KDF(profile_key, subkey_id=1, context="dottasiv")`
   - `ctr_key = KDF(profile_key, subkey_id=2, context="dottasiv")`

2. **Derive deterministic stream seed** from path:
   - `stream_seed = HMAC(ctr_key, storage_path, context="dottactr")`

3. **Generate keystream** deterministically:
   - `keystream = DeterministicPRNG(stream_seed, length=plaintext_len)`

4. **Encrypt plaintext** via XOR:
   - `ciphertext = plaintext ⊕ keystream`

5. **Compute SIV** (MAC over AAD + ciphertext):
   - `siv = HMAC(mac_key, storage_path || ciphertext, context="dottamac")`

6. **Assemble output**:
   - `[Magic Header 8B][SIV 32B][Ciphertext N B]`

**Decryption:**

1. Parse header and extract SIV
2. Derive `mac_key` and `ctr_key` (same as encryption)
3. Re-compute SIV over `storage_path || ciphertext`
4. Verify SIV matches (constant-time comparison)
5. If valid: derive `stream_seed`, generate keystream, decrypt

### Security Properties

- **Deterministic:** Same (path, content, key) → same ciphertext
- **Authenticated:** SIV provides integrity verification (32-byte MAC)
- **Path-bound:** Storage path is cryptographically bound via AAD
- **Nonce-misuse resistant:** No nonce management required
- **Key isolation:** Independent MAC and CTR keys prevent cryptographic cross-contamination

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
  [5]     0x02 (version byte)
  [6-7]   0x00 0x00 (reserved/padding)

SIV (32 bytes):
  MAC tag authenticating storage_path || ciphertext

Ciphertext (N bytes):
  plaintext ⊕ keystream
```

**Total overhead:** 40 bytes per file

### Version History

- **Version 1:** (deprecated) - Nonce-based encryption
- **Version 2:** (current) - SIV-based deterministic encryption

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
   - Get profile key from keymanager (may prompt for passphrase)
   - Derive MAC/CTR subkeys from profile key
   - Derive stream seed from path
   - Generate keystream
   - Encrypt: ciphertext = plaintext ⊕ keystream
   - Compute SIV
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
     - Get profile key from keymanager (may prompt once)
     - Derive MAC/CTR subkeys
     - Recompute SIV and verify (constant-time)
     - Derive stream seed from path
     - Generate keystream
     - Decrypt: plaintext = ciphertext ⊕ keystream

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

**Pattern Matching (crypto/pattern.c):**
- Uses gitignore-style glob syntax
- Patterns without `/` match basename at any depth
- Patterns with `/` match full path from root
- Example: `*.key` matches `api.key` and `dir/api.key`
- Example: `.ssh/id_*` matches only `.ssh/id_rsa` (anchored)

## Key Management

### Session-Based Caching

**Design (crypto/keymanager.c):**

```c
struct keymanager {
    uint8_t master_key[32];    // Cached master key
    bool has_key;              // Cache valid?
    time_t cached_at;          // Cache timestamp
    int32_t session_timeout;   // Timeout in seconds
    hashmap_t *profile_keys;   // Profile key cache
    bool mlocked;              // Memory locked with mlock()?
};
```

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
┌────────────┬─────────┬──────────┬──────────────┬──────────────┬──────────────┬──────────────┬─────────┐
│ Magic      │ Version │ Reserved │ Created At   │ Expires At   │ Machine Salt │ Encrypted Key│ MAC     │
├────────────┼─────────┼──────────┼──────────────┼──────────────┼──────────────┼──────────────┼─────────┤
│ "DOTTASES" │ 0x01    │ 0x00×3   │ uint64_t     │ uint64_t     │ 16 bytes     │ 32 bytes     │ 32 bytes│
│ 8 bytes    │ 1 byte  │ 3 bytes  │ 8 bytes      │ 8 bytes      │              │              │         │
└────────────┴─────────┴──────────┴──────────────┴──────────────┴──────────────┴──────────────┴─────────┘

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

**Solution (crypto/keymanager.c:466):**
```c
error_t *keymanager_get_profile_key(
    keymanager_t *mgr,
    const char *profile_name,
    uint8_t out_profile_key[32]
) {
    // 1. Check cache (O(1) hashmap lookup)
    if (mgr->profile_keys) {
        uint8_t *cached_key = hashmap_get(mgr->profile_keys, profile_name);
        if (cached_key) {
            memcpy(out_profile_key, cached_key, 32);
            return NULL;  // Cache hit
        }
    }

    // 2. Cache miss: derive and cache
    // ...derive profile_key from master_key...
    hashmap_set(mgr->profile_keys, profile_name, profile_key);

    return NULL;
}
```

**Benefits:**
- **First access:** Full derivation (master key + profile key)
- **Subsequent:** O(1) cache lookup (30,000x faster)
- **Lifetime:** Tied to master key cache
- **Memory:** ~32 bytes per profile (negligible)

### Content Caching

**Problem:** Commands like `status` need to read and decrypt the same files repeatedly.

**Solution (infra/content.c):**
```c
content_cache_t *cache = content_cache_create(repo, keymanager);

for (each_file) {
    const buffer_t *content;  // Borrowed reference
    content_cache_get_from_tree_entry(cache, entry, path, profile, meta, &content);
    // ... use content (cache owns buffer, don't free) ...
}

content_cache_free(cache);  // Frees all cached buffers
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

# Memory limit (currently unused by libhydrogen)
memlimit = 0

# Thread count (currently unused by libhydrogen)
threads = 1

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

**Opslimit Recommendations:**
- **Development:** 1000 (faster iteration)
- **Production:** 10000+ (recommended)
- **High security:** 100000+ (very slow, paranoid)

**Benchmark (approximate):**
```
opslimit=1000   → ~10ms  (weak)
opslimit=10000  → ~100ms (recommended)
opslimit=100000 → ~1s    (strong)
```

Trade-off: Higher values protect against brute-force but slow down legitimate use.

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
- `hydro_pwhash` work factor adequacy
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
| `ENCRYPTION_CTX_PWHASH` | `"dotta/v1"` | Master key derivation |
| `ENCRYPTION_CTX_KDF` | `"profile "` | Profile key derivation |
| `ENCRYPTION_CTX_SIV_KDF` | `"dottasiv"` | MAC/CTR subkey derivation |
| `ENCRYPTION_CTX_SIV_MAC` | `"dottamac"` | SIV computation |
| `ENCRYPTION_CTX_SIV_CTR` | `"dottactr"` | Stream seed derivation |
| (Session cache) | `"dottacch"` | Cache key derivation |
| (Session cache) | `"dottamac"` | Cache MAC computation (reuses SIV MAC context) |

**Rationale:** Prevent cross-protocol attacks, ensure cryptographic domain separation.

**Note:** The session cache reuses the `"dottamac"` context (shared with SIV MAC computation) since both perform keyed HMAC operations with different key material, ensuring no cryptographic interference.

### Zero Master Key in pwhash

```c
static const uint8_t zero_master[hydro_pwhash_MASTERKEYBYTES] = {0};

hydro_pwhash_deterministic(
    out_master_key, 32, passphrase, passphrase_len,
    "dotta/v1", zero_master, opslimit, memlimit, threads
);
```

**Why zero master?** libhydrogen's `hydro_pwhash_deterministic` supports two modes:
1. **Password storage:** Master key encrypts password hash representatives
2. **Direct key derivation:** Zero master key performs direct KDF (our use case)

We use direct derivation mode (no password storage), so zero master is correct.

## References

- [libhydrogen documentation](https://github.com/jedisct1/libhydrogen/wiki)
- [SIV (RFC 5297)](https://tools.ietf.org/html/rfc5297) - Synthetic Initialization Vector
- [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final) - KMAC construction
- [Gimli permutation](https://gimli.cr.yp.to/) - Cryptographic primitive
- Dotta source code: `src/crypto/`, `src/infra/content.c`

## Change Log

**Version 2 (Current):**
- SIV-based deterministic encryption
- Path-bound via AAD
- Profile key caching for performance
- Session-based key management
- File-based session cache for cross-invocation persistence

**Version 1 (Deprecated):**
- Nonce-based encryption (non-deterministic)
- Not suitable for Git versioning
