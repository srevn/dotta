# Encryption Technical Specification

## Overview

Dotta encrypts sensitive dotfiles transparently so they can be stored in a Git
repository without exposing their contents. Files are encrypted at rest in
Git and decrypted only when deployed to the filesystem.

**Design goals:**
- **Deterministic encryption** — same plaintext under the same key produces
  the same ciphertext (Git deduplicates, history is meaningful).
- **Path-bound authentication** — ciphertext is cryptographically tied to its
  storage path; a file moved to a different path cannot be decrypted.
- **Nonce-misuse resistant** — different plaintexts at the same path produce
  different synthetic IVs (and therefore different keystreams) without any
  per-encryption nonce or randomness.
- **Single passphrase UX** — one passphrase covers every profile and every
  encrypted file; profile- and file-level keys are derived deterministically.
- **Session-based caching** — the master key is cached in process memory and
  on disk for a configurable timeout, so users do not retype their passphrase
  on every command.

## Cryptographic foundation

### libhydrogen

Dotta uses [libhydrogen](https://github.com/jedisct1/libhydrogen), a minimal
cryptographic library built on the Gimli permutation:

- Small auditable codebase (~3000 LOC).
- Hard-to-misuse high-level API, suitable for this project's scale.
- Portable C99, ISC license.
- No dynamic allocation in libhydrogen itself.

The Curve25519 surface of libhydrogen is unused; only the symmetric primitives
matter here.

### Primitive usage

| Operation             | libhydrogen function             | Algorithm                                |
|-----------------------|----------------------------------|------------------------------------------|
| Keyed hashing (HMAC)  | `hydro_hash_hash`, `hydro_hash_*`| KMAC-style construction over Gimli       |
| Subkey derivation     | `hydro_kdf_derive_from_key`      | KMAC-like KDF over Gimli                 |
| Deterministic PRNG    | `hydro_random_buf_deterministic` | Gimli-based DRBG (32-byte seed)          |
| Memory clearing       | `hydro_memzero`                  | Compiler-fence-protected secure zero     |
| Constant-time compare | `hydro_equal`                    | Timing-safe equality check               |

`hydro_hash_*` accepts an 8-byte domain-separation context plus an optional
32-byte key, and supports both 32-byte digest output (used for keys, MACs,
and the SIV) and long-output / XOF mode up to 65 535 bytes (used by
balloon hashing to squeeze full 1024-byte blocks directly from the keyed
sponge). `hydro_random_buf_deterministic` absorbs a 32-byte seed in two
16-byte halves before squeezing output; dotta uses it only as a stream
keystream generator (cipher, session cache), never to fill data an
attacker would benefit from compressing.

> **Note on libhydrogen's `hydro_pwhash_deterministic`.** Dotta does **not**
> use this function. It iterates the Gimli permutation `opslimit` times over
> a 48-byte state, which is CPU-hard but not memory-hard: the permutation
> needs no working memory, so an attacker with `n` cores runs `n` guesses in
> parallel for the same time the defender pays for one. The `memlimit`
> parameter is mixed into the seed (parameter binding) but does not drive
> any memory-hard work — the only loop is over `opslimit`. Memory hardness
> is the only thing that bounds the attacker's parallelism in this threat
> model, so dotta builds it directly via balloon hashing (below) rather than
> spending wall-clock time on a CPU-hard pre-stage that contributes nothing
> against a parallel attacker.

## Threat model

**Mitigated** by the constructions in this document:
- **Passive repository compromise.** An attacker who exfiltrates a Git
  repository (clone of remote, stolen disk image, leaked backup) cannot
  recover the plaintext of encrypted files without the passphrase. Brute
  force is bounded by balloon-hashing's memory hardness — see the section
  below for what that means in practice.
- **Tampering of encrypted files.** Modifying any byte of the SIV or the
  ciphertext causes the SIV-recompute step to fail. The candidate plaintext
  is wiped and never returned.
- **Path confusion.** A ciphertext encrypted for `home/.ssh/id_rsa` cannot
  be decrypted as if it were `home/.bashrc` — the path is part of the
  authenticated input to the SIV.
- **Per-profile cross-contamination.** Different profile names derive
  different per-profile keys; compromise of the keys for one profile does
  not let an attacker forge or read another profile's files.

**Not mitigated:**
- **Local interactive compromise.** A process running as the dotta user
  (or root) can read the master key from process memory while it is cached,
  and from `~/.cache/dotta/session` in obfuscated form (see *Session cache*
  below — the on-disk cache is XOR-obfuscated, not encrypted).
- **Weak passphrases.** Memory hardness raises the per-guess cost but does
  not save a 6-character dictionary word.
- **Keyloggers and shoulder-surfing** during passphrase entry.
- **Offline disk forensics on the live host.** The session cache is
  designed to resist casual inspection and cross-machine copy, not a
  forensic adversary on the host that wrote it.

## Key hierarchy

```
User Passphrase
    ↓ [crypto/balloon — memory-hard, params-bound]
Master Key (32 bytes)
    ↓ [crypto/kdf — keyed BLAKE2 with profile name]
Profile Key (32 bytes, one per profile)
    ↓ [crypto/kdf — hydro_kdf_derive_from_key, subkey_id 1 and 2]
    ├─→ MAC Key (32 bytes) — keys the SIV computation over (path, plaintext)
    └─→ PRF Key (32 bytes) — keys the keystream-seed derivation from the SIV
         ↓ [crypto/cipher — keyed BLAKE2 over the SIV]
         Keystream Seed (32 bytes, plaintext-dependent via the SIV)
```

The hierarchy is implemented across three crypto modules:

- **`crypto/balloon`** owns the memory-hard derivation. It is the only
  module that touches the balloon buffer. Its public surface is one
  function (`balloon_derive`), one parameter struct, and a few constants.
  All context strings, block size, mix structure, and `mlock` handling
  are file-static.
- **`crypto/kdf`** owns the rest of the derivation chain — passphrase →
  master, master → profile, profile → SIV subkeys. It calls `balloon_derive`
  internally; callers do not see balloon parameters except by passing them
  through `kdf_master_key`.
- **`crypto/cipher`** owns SIV encryption/decryption and the on-disk file
  format. It receives the (mac_key, prf_key) pair directly and never sees
  the master key or profile key.

`crypto/keymgr` is the only module that holds the master key in memory; it
calls `kdf_*` to derive profile and SIV subkeys for each cipher invocation,
then zeroes them on the way out.

### Master key derivation (single phase, memory-hard)

```c
balloon_params_t params = {
    .memlimit_bytes = config->encryption_memlimit, // 8 MiB default; power of two
    .rounds = BALLOON_DEFAULT_ROUNDS,              // 3
    .delta  = BALLOON_DEFAULT_DELTA,               // 3
};
kdf_master_key(passphrase, passphrase_len, params, master_key);
// ↳ thin wrapper over balloon_derive
```

There is no separate CPU-hard pre-stage. The entire derivation is the
balloon — see *Balloon hashing* below for the algorithm and rationale.

### Profile key derivation

```c
hydro_hash_hash(
    profile_key, KDF_KEY_SIZE,         // out, 32 bytes
    profile, strlen(profile),          // in, the profile name
    "profile ",                        // 8-byte context (trailing space)
    master_key                         // 32-byte key
);
```

A keyed BLAKE2 over the profile name. Different profile names yield
independent profile keys; the same name always yields the same key under
a given master.

### MAC and PRF subkey derivation

```c
hydro_kdf_derive_from_key(mac_key, KDF_KEY_SIZE, /*subkey_id=*/1, "dottasiv", profile_key);
hydro_kdf_derive_from_key(prf_key, KDF_KEY_SIZE, /*subkey_id=*/2, "dottasiv", profile_key);
```

Two independent subkeys are required by the SIV construction:
- `mac_key` keys the SIV (which authenticates path + plaintext).
- `prf_key` keys the derivation of the keystream seed from the public SIV.

Cryptographic independence between the two is essential — otherwise the
keystream would be derivable from the SIV alone, and the SIV is public.

### Keystream seed derivation

```c
hydro_hash_hash(
    keystream_seed, 32,                // out
    siv, CIPHER_SIV_SIZE,              // in (the 32-byte SIV)
    "dottactr",                        // 8-byte context
    prf_key                            // 32-byte key
);
```

The seed is a keyed hash of the (public) SIV under the (secret) `prf_key`.
If the seed were a function of the SIV alone, anyone holding the ciphertext
could reproduce the keystream and recover the plaintext.

## Balloon hashing — single-phase memory-hard derivation

### Why balloon, why one phase

Memory hardness is the only attacker-bounding work in this derivation.
A passphrase guess on a 16-MiB balloon needs 16 MiB of working memory; a
6 GiB attacker GPU can therefore run at most ~384 guesses in parallel —
**bounded by RAM, not cores**. CPU-hard pre-stages do not help: their
parallelism is bounded by cores, of which any modern attacker has many,
each paying the same cost the defender does.

Dotta therefore implements a single-phase balloon (Boneh, Corrigan-Gibbs,
Schechter, 2016) directly over libhydrogen's keyed BLAKE2-via-Gimli sponge
in long-output mode (1024-byte block fills squeezed from the same primitive
that produces 32-byte digests). The whole interactive time budget goes into
memory-hard work.

### Algorithm

The implementation lives in `src/crypto/balloon.c`. The header `balloon.h`
exposes only `balloon_derive`, the parameter struct, and a handful of
constants; everything else (block size, context strings, stage helpers,
`mlock` handling) is file-static.

#### Stage 0 — absorb passphrase + params into a 32-byte state

```
state = H(LE64(passphrase_len) || passphrase || LE64(memlimit) || LE64(rounds) || LE64(delta),
          ctx="dottabl0", key=NULL)
```

A single keyed-BLAKE2 hash. The passphrase is length-prefixed so a shorter
passphrase that happens to be a prefix of another cannot collide with it.
The parameters are domain-mixed in so the same passphrase under different
(memlimit, rounds, delta) yields unrelated keys.

#### Stage 1 — sequential expansion with full-block dependencies

```
buf[0] = H(LE64(0),
           ctx="dottabl1", key=state, out_len=BLOCK_SIZE)
for i = 1 .. n_blocks - 1:
    buf[i] = H(LE64(i) || buf[i-1],   # full previous block, 1024 bytes
               ctx="dottabl1", key=state, out_len=BLOCK_SIZE)
```

The block content **is** the keyed-BLAKE2 long-output (BLAKE2 is sponge-
based, and `hydro_hash_final` accepts output sizes up to 65 535 bytes;
squeezing 1024 bytes costs the same number of Gimli permutations as
filling the same buffer with the deterministic PRNG would). There is no
32-byte intermediate seed sitting between the hash and the block, so a
storage-tradeoff attacker has no compressed per-block label they could
stash to obtain a free memory savings on top of the standard balloon TS
tradeoff.

Each block depends on the **full** previous block (1024 bytes), not a
32-byte prefix. A parallel attacker cannot fill blocks out of order, and a
storage-tradeoff attacker who keeps `k` bytes per block must recompute
back through the dependency chain to a stashed neighbour, which is the
standard balloon-hashing TS bound.

#### Stage 2 — `rounds` mixing passes with full-block dependencies

For each round `r ∈ [0, rounds)` and each block index `i ∈ [0, n_blocks)`,
let `prev_idx = (i - 1) mod n_blocks`.

**Index seed (data-dependent):**

```
idx_seed = H(LE64(r) || LE64(i) || buf[i],   # full current block, 1024 bytes
             ctx="dottabli", key=state, out_len=8 * delta)
```

A single keyed hash absorbs `(r, i, full_current_block)` and produces
`8 * delta` output bytes. Reading the **full current block** here keeps
index derivation honest: the index is a function of the actual block
contents, not a stashable prefix.

**Mix step (data-dependent, full-block):**

```
for d = 0 .. delta - 1:
    idx[d] = LE64(idx_seed[8*d : 8*(d+1)]) mod n_blocks    # bias-free; n_blocks is power of two

buf[i] = H(LE64(r) || LE64(i) ||
           buf[prev_idx] ||                                # full prev block
           buf[i] ||                                       # full current block
           buf[idx[0]] || buf[idx[1]] || ... || buf[idx[delta-1]],
           ctx="dottablm", key=state, out_len=BLOCK_SIZE)
securely_zero(idx_seed)
```

The hash absorbs every input completely before squeezing any output
byte, so writing the squeezed output back into `buf[i]` (the same memory
that was just absorbed as `current_block`) is safe — there is no
absorb/squeeze aliasing.

As in expansion, the new block content **is** the keyed-BLAKE2 long-output;
no 32-byte intermediate seed exists between the hash and the block. Every
block referenced in the mix is read in full (`BLOCK_SIZE` bytes), not as a
32-byte prefix. The mix is keyed by `state` (the absorbed passphrase +
params), binding every step back to the input.

`n_blocks = memlimit_bytes / BLOCK_SIZE` is a power of two (because
`memlimit_bytes` is validated as a power of two and `BLOCK_SIZE = 1024`),
so `(uint64 % n_blocks)` is bias-free without rejection sampling.

#### Stage 3 — finalize

```
master_key = H(buf[n_blocks - 1],    # full last block, 1024 bytes
               ctx="dottablf", key=state, out_len=32)
```

The output is a keyed hash of the full final block under the absorbed-state
key. The buffer is wiped and freed before return.

### Parameters and bounds

| Parameter        | Default           | Bounds       | Notes                                              |
|------------------|-------------------|--------------|----------------------------------------------------|
| `memlimit_bytes` | 8 MiB             | 1 MiB .. ∞   | Must be a power of two; multiple of `BLOCK_SIZE`.  |
| `rounds`         | 3                 | 1 .. 16      | Mixing passes over the buffer.                     |
| `delta`          | 3                 | 2 .. 8       | Random-block references absorbed per mix step.     |

Validation runs both at config-parse time (`utils/config.c`) and at the
crypto boundary (`balloon.c::validate_params`). Invalid parameters fail
with a clear error before any allocation.

`delta`'s lower bound is 2 because the index extraction asks
`hydro_hash_final` for `8 * delta` bytes and libhydrogen rejects output
shorter than `hydro_hash_BYTES_MIN = 16`. `delta`'s upper bound keeps the
on-stack `idx_seed` array fixed-size (`8 * BALLOON_DELTA_MAX = 64` bytes).
`rounds`'s upper bound prevents a misconfigured caller from locking the
process up with a runaway value.

### Block size choice

`BLOCK_SIZE = 1024`. Block size is a tuning parameter, not a security
parameter — total memory hardness is bounded by `memlimit_bytes`, not by
block size. 1024 is large enough to amortize the per-mix hash setup
(init + finalize cost is constant; absorbing 1024 bytes through `gimli_RATE = 16`
takes 64 permutations, dwarfing the framing) and small enough that the
buffer holds many blocks at any defensible memory budget.

### Memory hygiene

- The balloon buffer is best-effort `mlock`'d. On failure, `balloon_derive`
  emits a single warning to stderr pointing at `RLIMIT_MEMLOCK` (`ulimit -l`)
  and continues; the buffer is wiped before free regardless. The default
  macOS `RLIMIT_MEMLOCK` is 64 KiB, so unprivileged processes will see
  this warning unless the limit is raised.
- The buffer is zeroed via `buffer_secure_free` on every exit path
  (success, validation error, hash error).
- The 32-byte `state` is zeroed at function exit.
- Per-iteration secrets (mix hash state, index seed) are zeroed at the
  end of each iteration as defense in depth — this bounds the window in
  which transient key material sits on the stack on both normal-
  completion and early-return paths inside the mix loops.
- The output `out_key` is zeroed on any error before return so a partial
  derivation cannot leak.

### Performance notes

The implementation is dominated by Stage 2 (mix), which runs
`rounds × n_blocks` keyed long-output hashes; each absorbs `delta + 2`
full predecessor blocks (prev, current, and `delta` random blocks) plus
the index hash that absorbs the current block. Squeezing the new block
out of the sponge costs the same number of Gimli permutations as
absorbing one block. For the default
`memlimit = 8 MiB, rounds = 3, delta = 3`, that is ~98 K full-block
absorptions and ~24 K block-sized squeezes per derivation — measured at
~600 ms on commodity 2026-era hardware. Derivation runs at most once
per session (the master key is cached across commands; see *Session
cache*).

The defender pays this once per cache miss. The attacker pays it for
every passphrase guess, multiplied by guesses-per-second per parallel
guesser, which is itself bounded by `attacker_RAM / memlimit_bytes`.

## SIV construction (cipher)

Implemented in `crypto/cipher` as a Synthetic IV (SIV) deterministic AEAD
in the spirit of RFC 5297. The synthetic IV is a function of the path and
plaintext, and doubles as the authentication tag.

### Encryption

Inputs: `(plaintext, mac_key, prf_key, storage_path)`.

1. **Compute the synthetic IV** over (path, plaintext):
   ```
   siv = H(LE64(path_len) || storage_path || plaintext,
           ctx="dottamac", key=mac_key, out_len=32)
   ```
   The 8-byte path length prefix domain-separates the path from the
   plaintext so an adversary cannot shift the boundary to forge a valid
   SIV for a different (path, plaintext) pair. BLAKE2 is not vulnerable
   to length extension, so no trailing length is required.
2. **Derive the keystream seed** from the (public) SIV under `prf_key`:
   ```
   keystream_seed = H(siv, ctx="dottactr", key=prf_key, out_len=32)
   ```
3. **Encrypt** by XOR with a deterministic keystream:
   ```
   keystream  = PRNG(keystream_seed, plaintext_len)
   ciphertext = plaintext ⊕ keystream
   ```
4. **Assemble** the output:
   ```
   [Magic 8B][SIV 32B][Ciphertext N B]
   ```

Because the SIV depends on the plaintext, two distinct plaintexts at the
same `(profile_key, path)` yield distinct SIVs and distinct keystreams.
That gives nonce-misuse resistance without any nonce management: there is
no per-encryption randomness to track.

### Decryption

Inputs: `(ciphertext, mac_key, prf_key, storage_path)`.

1. Parse the header. Magic must equal `"DOTTA"`; version byte must equal
   `CIPHER_VERSION = 4`. Mismatches return `ERR_CRYPTO`.
2. Extract the stored `siv` and the ciphertext body.
3. Derive `keystream_seed` from `(prf_key, siv)` exactly as in step 2 of
   encryption.
4. Compute the candidate plaintext:
   ```
   candidate = ciphertext ⊕ PRNG(keystream_seed, body_len)
   ```
5. Recompute `siv'` over `(LE64(path_len), storage_path, candidate)` under
   `mac_key`.
6. Constant-time compare `siv' == siv`. On match, return the candidate.
   On mismatch, wipe the candidate via the cleanup path and return
   `ERR_CRYPTO`. **The candidate is never returned on mismatch.**

In SIV, the IV authenticates the plaintext — it cannot be checked without
first recovering the plaintext. The candidate is held in memory only long
enough to verify; the cleanup path zeroes the output buffer on every
error path before freeing.

### Why SIV (not AES-GCM / ChaCha20-Poly1305)

Standard AEAD modes require a unique nonce per encryption. Dotta wants
deterministic ciphertexts because:

- **Git deduplication.** Identical plaintexts under the same key share Git
  storage.
- **Idempotency.** Re-running `dotta add` on an unchanged file produces no
  Git diff.
- **Diff-ability.** Only files whose plaintexts actually changed appear in
  Git diffs of the encrypted tree.

A nonce-based AEAD with a random nonce per encryption breaks all three.
SIV gives the same security as a nonce-based AEAD when nonces are unique,
and stays robust ("nonce-misuse resistant") in the face of repeated
plaintexts at the same path.

### Cipher input bounds

`crypto/cipher` enforces two limits at its entry points to avoid the
crypto layer allocating huge buffers on behalf of pathological input:

- **Storage path:** at most `CIPHER_STORAGE_PATH_MAX = 4096` bytes
  (excluding NUL). `strnlen` keeps the scan bounded even on
  non-NUL-terminated input.
- **Plaintext / inner ciphertext:** at most
  `CIPHER_MAX_CONTENT_SIZE = 100 MiB`. Dotfiles are small; this cap
  defends the crypto layer from runaway input regardless of how the
  bytes reached us.

## File format

```
┌──────────────────────┬──────┬────────────────────┐
│ Magic Header         │ SIV  │ Ciphertext         │
├──────────────────────┼──────┼────────────────────┤
│ 8 bytes              │ 32 B │ N bytes            │
└──────────────────────┴──────┴────────────────────┘

Magic Header (8 bytes):
  [0..4]  "DOTTA" (magic string)
  [5]     0x04 (CIPHER_VERSION)
  [6..7]  0x00 0x00 (reserved)

SIV (32 bytes):
  MAC tag over LE64(path_len) || storage_path || plaintext, keyed by mac_key.
  Public; doubles as the input to keystream-seed derivation under prf_key.

Ciphertext (N bytes):
  plaintext ⊕ keystream, where keystream = PRNG(H(siv, key=prf_key)).
```

`CIPHER_OVERHEAD = 40` bytes per file.

`cipher_is_encrypted` recognises a blob as a dotta-encrypted file iff its
first 6 bytes match magic + the build's version byte. A blob whose first
bytes are `"DOTTA"` followed by a different version is reported as **not**
encrypted, so callers never try to decrypt something they cannot parse;
any explicit decrypt call surfaces a precise "unsupported version" error
instead.

## Encryption workflow

### `dotta add ... --encrypt`

```
1. User: dotta add -p myprofile ~/.ssh/id_rsa --encrypt

2. Policy decision (crypto/policy.c):
     - Protected meta-files (.bootstrap, .dottaignore, .dotta/metadata.json)
       are always plaintext (rejected with a clear error if --encrypt is
       requested explicitly).
     - Otherwise: --encrypt > --no-encrypt > previous state in metadata
       > auto-encrypt patterns.

3. Read plaintext from filesystem.

4. Encrypt (crypto/cipher via crypto/keymgr):
     - keymgr resolves the master key (memory cache → disk session → prompt).
     - kdf_profile_key:    master_key   + profile  → profile_key
     - kdf_siv_subkeys:    profile_key  → mac_key, prf_key
     - cipher_encrypt:     SIV over (path, plaintext) → keystream → ciphertext
     - profile_key, mac_key, prf_key zeroed on the way out.

5. Store in Git:
     - Create blob from ciphertext, update tree in profile branch.

6. Metadata (core/metadata.c):
     - Record encrypted=true, mode=0600 in .dotta/metadata.json.
     - Commit metadata.json to profile branch.
```

### `dotta apply`

```
1. User: dotta apply

2. Load workspace (manifest + per-profile metadata).

3. For each managed file (infra/content.c):
     - Read blob from Git tree.
     - Detect dotta magic + version with cipher_is_encrypted.

   IF ENCRYPTED:
     - keymgr resolves master_key (cache or prompt, once per command).
     - kdf_profile_key + kdf_siv_subkeys → mac_key, prf_key.
     - cipher_decrypt: candidate = ciphertext ⊕ keystream;
                       recompute SIV; constant-time compare; return on match,
                       wipe on mismatch.
     - keys zeroed on the way out.

   ELSE:
     - Use blob content directly.

4. Deploy:
     - Copy plaintext to target path.
     - Restore mode (and ownership for root/ files) from metadata.
     - Update deployment state.
```

## Auto-encryption policy

Files can be auto-encrypted by glob pattern.

**Configuration (`config.toml`):**

```toml
[encryption]
enabled = true
auto_encrypt = [
    ".ssh/id_*",        # SSH private keys
    "*.key",            # Generic key files
    ".gnupg/secring*",  # GPG secret keyrings
]
```

**Pattern matching (`crypto/policy.c`, evaluated via `base/gitignore.c`):**

- Patterns compile once into a `gitignore_ruleset_t` at `config_load` and
  are stored on the config handle (`config->auto_encrypt.rules`).
- Per-file matching runs in `encryption_policy_matches_auto_patterns`,
  which strips the storage prefix (`home/`, `root/`, `custom/`) before
  evaluation so users write `.ssh/id_*` rather than `home/.ssh/id_*`.
- Full gitignore semantics, including `!` negation
  (`*.key` + `!public.key` correctly excludes `public.key`).
- Patterns without `/` match basename at any depth; patterns with `/` are
  anchored to the storage root.

**Decision priority (`encryption_policy_should_encrypt`):**

1. **Protected meta-files** (`.bootstrap`, `.dottaignore`,
   `.dotta/metadata.json`) — always plaintext. Explicit `--encrypt` on
   these files is rejected with a clear error.
2. **Explicit `--encrypt`** on the command line.
3. **Explicit `--no-encrypt`** on the command line.
4. **Previous state in metadata.json.** A file previously encrypted stays
   encrypted on subsequent `update` (so workflows like
   *add → modify → update* don't accidentally drop encryption).
5. **Auto-encrypt patterns** as the final fallback.

The default is "no encryption" if no rule matches.

## Key management

### `crypto/keymgr` lifecycle

```c
struct keymgr {
    balloon_params_t params;        // snapshot from config at create time
    int32_t          session_timeout; // seconds; 0 = always prompt, -1 = never expire
    uint8_t          master_key[KDF_KEY_SIZE];
    bool             has_key;
    time_t           cached_at;     // monotonic time, 0 if not cached
    bool             mlocked;
};
```

The keymgr struct is best-effort `mlock`'d so the cached master key cannot
be paged to disk. The (much larger) balloon buffer is `mlock`'d separately
inside `balloon_derive` for the duration of one derivation call.

In-memory cache expiry is computed against `CLOCK_MONOTONIC`, which is
immune to wall-clock manipulation. The on-disk session cache uses
wall-clock timestamps because monotonic time resets on reboot, which would
make the on-disk cache un-loadable across a reboot.

Profile keys are **not** cached. They are derived on demand (one keyed
hash, microseconds), used for one cipher call, then zeroed on the stack.
Caching profile keys was tried and removed (see commit `0dff2a5b`); the
performance gain did not justify the additional in-memory key surface.

### Cache lifecycle

1. **First key request.** Try the in-memory cache. On miss, try the
   on-disk session cache (skipped when `session_timeout == 0`). On miss,
   read the passphrase (env var or interactive prompt), derive the master
   key via `kdf_master_key` (the expensive step), cache it in memory,
   write the on-disk cache.
2. **Subsequent requests in the same process.** Memory cache hit, O(1).
3. **Subsequent requests across processes.** On-disk cache hit, validated
   against the machine identity and timestamps before accepting; promoted
   to memory cache.
4. **Expiration.** Default `session_timeout = 3600` seconds. `-1` means
   never expire (cache until manual clear). `0` disables caching entirely
   (always prompt; on-disk cache also disabled).
5. **Cleanup.** `dotta key clear` zeroes the in-memory key and unlinks
   the on-disk file. `keymgr_free` zeroes and `munlock`s on process exit.

### Passphrase sources (priority order)

1. **In-memory cache** (this process, not expired).
2. **On-disk session cache** (`session_timeout != 0`, MAC-valid, not expired).
3. **`DOTTA_ENCRYPTION_PASSPHRASE`** environment variable (with a stderr
   warning that env vars leak in process listings and inherited environs).
4. **Interactive prompt** on stdin with echo disabled via `tcsetattr`.

### On-disk session cache (`~/.cache/dotta/session`)

**Purpose.** Persist the master key across command invocations so users
don't retype their passphrase every time.

**File format (108 bytes total, packed):**

```
┌────────────┬─────────┬──────────┬──────────────┬──────────────┬──────────────┬───────────────┬──────────┐
│ Magic      │ Version │ Reserved │ Created at   │ Expires at   │ Machine salt │ Encrypted key │ MAC      │
├────────────┼─────────┼──────────┼──────────────┼──────────────┼──────────────┼───────────────┼──────────┤
│ "DOTTASES" │ 0x01    │ 0x00 × 3 │ uint64       │ uint64       │ 16 bytes     │ 32 bytes      │ 32 bytes │
│ 8 bytes    │ 1 byte  │ 3 bytes  │ 8 bytes      │ 8 bytes      │              │               │          │
└────────────┴─────────┴──────────┴──────────────┴──────────────┴──────────────┴───────────────┴──────────┘
```

Timestamps are stored in native byte order (the cache is machine-bound
and never migrates between hosts). The MAC computation canonicalizes
both timestamps to little-endian so it is reproducible from the field
values alone and does not silently depend on host byte order.

**Cryptographic design:**

```
machine_id  = hostname || '\0' || username || '\0'   # two NUL-terminated fields
cache_key   = H(machine_id || machine_salt, ctx="dottacch", key=NULL, out_len=32)
keystream   = PRNG(cache_key, 32)
encrypted_k = master_key ⊕ keystream                       # XOR obfuscation
mac         = H(LE(created_at) || LE(expires_at) || machine_salt || encrypted_k,
                ctx="dottamac", key=cache_key, out_len=32) # tamper-evident
```

> **Threat-model caveat — read this.** The on-disk cache is **obfuscated
> with a host-bound XOR keystream and authenticated with a MAC**, but it
> is **not encrypted by anything the attacker doesn't already have**. An
> attacker who reads the cache file, knows the hostname, and knows the
> username can reconstruct `machine_id`, recompute `cache_key`, regenerate
> the keystream, and recover the master key — without ever cracking the
> passphrase.
>
> This is a deliberate UX trade-off: an actually-passphrase-encrypted
> cache would require typing the passphrase to load it, defeating the
> cache's reason to exist. It means **balloon hardness is not the only
> wall** an attacker has to climb; on a host the attacker controls, the
> cache is a shorter wall. Threat scenarios where this matters: backup
> theft, malware running as the user, access to a stale disk image,
> shared filesystems with bad permissions.

**Cache load validation.** `session_load`:
- Read the file. Verify mode is exactly `0600` (delete and refuse
  otherwise).
- Validate magic and version.
- Check `expires_at` against wall-clock `time()`.
- Recompute `cache_key` from the current host's `machine_id` plus the
  stored `machine_salt`, recompute the MAC, constant-time compare.
- On any failure, delete the file and report cache miss.
- On success, XOR-decode the master key and return it.

**File permissions.** The cache directory `~/.cache/dotta/` is created
with mode `0700`; the cache file with mode `0600`. Both are checked on
every load.

**What this protects against:**
- Casual inspection (cache content is not plaintext).
- Cross-machine copying (machine binding fails the MAC).
- Stale credentials (auto-expiry).
- Tampering (MAC detects modification).

**What it does not protect against:**
- Local root, malicious code running as the user, memory dumps, or
  forensic disk imaging on the host that wrote the cache.

### Memory protection

- Master key in `keymgr` struct: best-effort `mlock`'d, `hydro_memzero`'d
  on `keymgr_free`, on `keymgr_clear`, and on signal-handled exit.
- Balloon buffer: best-effort `mlock`'d, `hydro_memzero`'d before free
  on every exit path of `balloon_derive`.
- Passphrase buffers: allocated by `crypto/passphrase` with
  `buffer_secure_free` semantics (mlock on alloc, zero on free).
- Subkeys (`profile_key`, `mac_key`, `prf_key`, `keystream_seed`): live
  on the stack for one cipher call; zeroed before the function returns
  on both success and failure paths.

`mlock` failures are non-fatal but warn loudly to stderr — the warning
text points the user at `RLIMIT_MEMLOCK` (`ulimit -l`). The default macOS
limit (64 KiB) is too small to lock the balloon buffer, so unprivileged
users will see the warning unless they raise the limit.

### Environment variable risk

```bash
# Insecure — passphrase visible in process listings and child environs.
DOTTA_ENCRYPTION_PASSPHRASE="secret" dotta apply

# Better — interactive prompt, cached for the session.
dotta key set
dotta apply
```

`keymgr` warns to stderr on every command that uses
`DOTTA_ENCRYPTION_PASSPHRASE`.

## Performance

### Master key derivation (cold start)

| `memlimit` | Approx. wall-clock on commodity hardware |
|------------|------------------------------------------|
|  1 MiB     | ~30 ms (CI / test only — minimum allowed) |
|  8 MiB     | ~600 ms (default)                         |
| 16 MiB     | ~1.2 s                                    |
| 32 MiB     | ~2.5 s (uncomfortable interactively)      |

These numbers come from the user-visible config sample
(`etc/config.toml.sample`). Re-bench on your hardware before tuning.

Note: pushing memory hardness much harder than the on-disk cache's
strength does not help in the realistic threat model (see *Session cache*
threat-model caveat above). 8 MiB is the chosen default because it
saturates the cache's strength while staying interactive.

### Per-file overhead (warm session)

Once the master key is cached, every file encrypt or decrypt costs:

- 1 keyed BLAKE2 (`kdf_profile_key`), microseconds.
- 2 KDF subkey derivations (`kdf_siv_subkeys`), microseconds.
- 1 SIV computation (one BLAKE2 over `LE(path_len) + path + plaintext`),
  bounded by file size; megabytes per second on commodity hardware.
- 1 keystream-seed derivation (one BLAKE2), microseconds.
- 1 PRNG fill of `plaintext_len` bytes plus an in-place XOR, both
  bandwidth-bound.

For typical dotfiles (well under 100 KiB), per-file overhead is in the
millisecond range — dominated by file I/O, not crypto.

### Content cache

`infra/content.c` adds a content-cache that deduplicates decryption when
the same blob OID is read multiple times within a single command:

```c
content_cache_t *cache = content_cache_create(repo, keymgr);
for (each file) {
    const buffer_t *content;            // borrowed reference
    content_cache_get_from_blob_oid(cache, &blob_oid, storage_path,
                                    profile, expected_encrypted, &content);
    // use content; cache owns the buffer.
}
content_cache_free(cache);              // zeroes plaintext before free
```

Hashmap keyed by blob OID. Cache lives for one command; freed buffers
are zeroed first.

## Configuration

### `[encryption]` section

```toml
[encryption]
enabled = true                  # opt-in; default false
memlimit = 8                    # MiB; power of two, >= 1; default 8
session_timeout = 3600          # seconds; -1 = never, 0 = always prompt
auto_encrypt = [
    ".ssh/id_*",
    "*.key",
    ".gnupg/secring*",
]
```

The `memlimit` field is parsed in mebibytes for user friendliness and
converted to bytes at config-load. The validator enforces:

- `memlimit_bytes >= 1 MiB`,
- `memlimit_bytes` is a power of two (so the modular index reduction is
  bias-free).

`rounds` and `delta` are not exposed in `config.toml` — the defaults (3
and 3) match the Boneh paper's parameters and align with the algorithm's
provable memory-hardness bound. They are still validated at the crypto
boundary (`balloon.c::validate_params`) for defense in depth.

`session_timeout` accepts:
- `-1` — never expire (until manual clear via `dotta key clear`).
- `0` — never cache (always prompt; on-disk cache disabled).
- positive integer — seconds before expiry.

### Tuning notes

- **Choose `memlimit` against your hardware**, not against an absolute
  byte count. The defender pays the derivation cost on a cold session;
  the attacker pays it per guess. Aim for ~500 ms – 1 s of wall-clock on
  the slowest machine you intend to use. Memory hardness scales
  proportionally to `memlimit_bytes`.
- **`memlimit` must match across machines** that share the same
  encrypted profiles. Different `memlimit` produces a different master
  key for the same passphrase (params are domain-mixed into the absorbed
  state), so files encrypted on one machine will fail SIV verification
  on another with a different `memlimit`.

## Security analysis

### Cryptographic assumptions

- **Gimli permutation security.** Peer-reviewed; NIST lightweight crypto
  finalist; underlying primitive of every libhydrogen operation here.
- **KMAC-style construction soundness.** libhydrogen's keyed hash and
  KDF use a KMAC-like framing over Gimli (similar in spirit to NIST
  SP 800-185).
- **Balloon hashing memory-hardness** (Boneh, Corrigan-Gibbs, Schechter,
  2016). The implementation follows the paper's primary data-dependent
  scheme with `delta = 3` and full-block dependencies in expansion and
  mixing.

### Known limitations

1. **Deterministic encryption leaks change patterns.** Identical files
   under the same key produce identical ciphertext; Git history reveals
   *when* an encrypted file changed, not what changed to. This is the
   intentional trade for Git friendliness.
2. **Storage path is part of the AAD.** Renaming an encrypted file
   requires re-encrypting it under the new path. The path itself is
   recorded in plaintext in `.dotta/metadata.json` (visible to anyone
   with the repo).
3. **Profile names are public.** They appear as Git branch names and in
   metadata. Per-profile keys provide cryptographic isolation between
   profiles, but the existence of profiles is not hidden.
4. **Session cache is obfuscation, not encryption.** Re-stated here from
   the threat-model section: an attacker with the cache file plus the
   hostname and username can recover the master key without cracking
   the passphrase. `dotta key clear` is the response when this matters
   (e.g., before lending or returning a machine).

### Defense in depth

- Magic + version mismatch produces a precise error, not a silent
  "wrong-passphrase".
- SIV verification is constant-time (`hydro_equal`).
- Decrypt's candidate plaintext is wiped on mismatch and never returned.
- `mlock` failure warns rather than failing silently.
- Balloon parameters are validated at both the config and crypto layers.
- Cipher input bounds are enforced at the crypto entry points regardless
  of upstream caller.

## Implementation map

| Concern                    | Module                | Public surface                                                        |
|----------------------------|-----------------------|-----------------------------------------------------------------------|
| Memory-hard derivation     | `src/crypto/balloon`  | `balloon_derive`, `balloon_params_t`, BALLOON_* defaults              |
| Keyed-BLAKE2 / KDF chain   | `src/crypto/kdf`      | `kdf_master_key`, `kdf_profile_key`, `kdf_siv_subkeys`                |
| SIV encrypt/decrypt + format| `src/crypto/cipher`  | `cipher_encrypt`, `cipher_decrypt`, `cipher_is_encrypted`             |
| Master-key cache, lifecycle| `src/crypto/keymgr`   | `keymgr_create`, `keymgr_encrypt`, `keymgr_decrypt`, …                |
| On-disk session cache      | `src/crypto/session`  | `session_load`, `session_save`, `session_clear`                       |
| Passphrase prompt + env    | `src/crypto/passphrase` | `passphrase_prompt`, `passphrase_from_env`                          |
| Auto-encrypt policy        | `src/crypto/policy`   | `encryption_policy_should_encrypt`, …                                 |
| Content cache              | `src/infra/content`   | `content_cache_*`                                                     |

### Context strings

| Context     | Module           | Purpose                                                  |
|-------------|------------------|----------------------------------------------------------|
| `dottabl0`  | crypto/balloon   | Stage 0 absorb (passphrase + params → state)             |
| `dottabl1`  | crypto/balloon   | Stage 1 expansion (full-block squeeze per index)         |
| `dottabli`  | crypto/balloon   | Stage 2 index-seed derivation                            |
| `dottablm`  | crypto/balloon   | Stage 2 mix (full-block squeeze per (round, index))      |
| `dottablf`  | crypto/balloon   | Stage 3 finalization                                     |
| `profile `  | crypto/kdf       | `master_key, profile_name → profile_key`                 |
| `dottasiv`  | crypto/kdf       | `profile_key → mac_key, prf_key`                         |
| `dottamac`  | crypto/cipher    | SIV computation over `(path, plaintext)`                 |
| `dottactr`  | crypto/cipher    | Keystream-seed derivation from the SIV under `prf_key`   |
| `dottacch`  | crypto/session   | Cache key derivation from machine identity               |
| `dottamac`  | crypto/session   | Cache MAC (key material disjoint from the SIV's `dottamac`) |

The `"dottamac"` context is intentionally shared between the SIV MAC and
the session-cache MAC — both are keyed BLAKE2s, but the *keys* come from
disjoint key material (profile-derived `mac_key` vs. machine-derived
`cache_key`), so cross-protocol confusion is not possible.

## References

- [libhydrogen documentation](https://github.com/jedisct1/libhydrogen/wiki)
- Balloon Hashing — Boneh, Corrigan-Gibbs, Schechter (2016).
  [eprint.iacr.org/2016/027](https://eprint.iacr.org/2016/027)
- SIV — RFC 5297. [tools.ietf.org/html/rfc5297](https://tools.ietf.org/html/rfc5297)
- KMAC — NIST SP 800-185. [csrc.nist.gov/publications/detail/sp/800-185/final](https://csrc.nist.gov/publications/detail/sp/800-185/final)
- Gimli permutation. [gimli.cr.yp.to](https://gimli.cr.yp.to/)
- Source: `src/crypto/{balloon,kdf,cipher,keymgr,session,passphrase,policy}.{c,h}`,
  `src/infra/content.{c,h}`.
