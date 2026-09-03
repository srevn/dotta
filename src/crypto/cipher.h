/**
 * cipher.h - Deterministic authenticated encryption (SIV)
 *
 * Deterministic AEAD for sensitive dotfiles. Identical (mac_key, prf_key, header,
 * storage_path, plaintext) yields byte-identical ciphertext, preserving Git
 * deduplication.
 *
 * SIV pipeline:
 *   1. siv  = MAC(mac_key, CIPHER_SIV, header(17), storage_path, plaintext)
 *   2. seed = MAC(prf_key, CIPHER_KEY, siv)
 *   3. ciphertext = XChaCha20(key=seed, nonce=siv[0..24], ctr=0, plaintext)
 *
 * The 32-byte SIV doubles as MAC tag and as the source of XChaCha20's 24-byte
 * nonce; `crypto_mac_absorb` LE64-prefixes each variable input so distinct tuples
 * produce distinct absorbed streams.
 *
 * On-disk blob layout:
 *
 *     ┌────────┬────────────────────────────────────┬────────┐
 *     │ offset │ field                              │ size   │
 *     ├────────┼────────────────────────────────────┼────────┤
 *     │   0    │ magic "DOTTA"                      │  5 B   │
 *     │   5    │ version = 0x08                     │  1 B   │
 *     │   6    │ argon2_memory_mib (LE16)           │  2 B   │
 *     │   8    │ argon2_passes                      │  1 B   │
 *     │   9    │ salt fingerprint (BLAKE2b-8)       │  8 B   │
 *     │  17    │ SIV / MAC tag                      │ 32 B   │
 *     │  49    │ ciphertext (XChaCha20 keystream)   │  N B   │
 *     └────────┴────────────────────────────────────┴────────┘
 *
 * The 17-byte header is the FIRST input absorbed into the SIV. Tampering any of
 * magic, version, Argon2 params, or the salt fingerprint fails MAC verification,
 * not parse validation, keeping error paths uniform.
 *
 * The salt fingerprint (`kdf_salt_fingerprint` of the repo salt the producer
 * derived under) makes every ciphertext name the salt that keyed it. Two key-free
 * consumers read it: the salt census in `infra/salt` attributes reachable
 * ciphertext to a specific salt before deciding a divergent-salt reconcile, and
 * `keymgr_decrypt` refuses a foreign-salt blob up front with a precise diagnostic
 * instead of prompting for a passphrase that can never verify.
 *
 * Security properties:
 *   - Determinism. Same inputs → same ciphertext (Git-friendly).
 *   - Authentication. 32-byte keyed-BLAKE2b tag over (header || path || plaintext);
 *     constant-time verify on decrypt.
 *   - Path binding. `storage_path` bytes are absorbed verbatim; no normalization.
 *     A blob encrypted under one path cannot decrypt under another.
 *   - Params binding. Argon2 (memory_mib, passes) live in the bound header, so
 *     config edits cannot invalidate old blobs and a tampered params field fails
 *     MAC.
 *   - Nonce-misuse resistance. Distinct plaintexts under the same (mac_key, path,
 *     header) yield distinct SIVs and keystreams.
 *   - Key isolation. Operates only on the per-operation (mac_key, prf_key) pair;
 *     never sees master key or profile name.
 *
 * Format-version policy: `CIPHER_VERSION` bumps on any incompatible change. A
 * bump invalidates every blob keyed under the prior version — no migration path
 * (alpha policy in CLAUDE.md).
 *
 * Caller contract: `cipher_encrypt` / `cipher_decrypt` accept a raw `(mac_key,
 * prf_key)` pair so this module stays free of master-key and profile-name
 * knowledge. The canonical caller is `crypto/keymgr`, which derives the pair
 * via `kdf_siv_subkeys` and wipes both buffers after the single per-operation
 * use. Any other production call site needs explicit justification —
 * `kdf_siv_subkeys` is what makes the two subkeys cryptographically independent,
 * and per-operation derive + wipe is what bounds subkey lifetime on the stack.
 * tests/test-cipher.c calls both with a fixed pair to pin the format at its own
 * boundary.
 */

#ifndef DOTTA_CRYPTO_CIPHER_H
#define DOTTA_CRYPTO_CIPHER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <types.h>

#include "crypto/kdf.h"
#include "crypto/mac.h"

/** Magic prefix on every encrypted blob (5 ASCII bytes). */
#define CIPHER_MAGIC          "DOTTA"
#define CIPHER_MAGIC_SIZE     5

/** Cipher format version. See file-level "Format-version policy". */
#define CIPHER_VERSION        0x08

/**
 * Detection-prefix length (magic + version).
 *
 * Callers sample the first `CIPHER_DETECT_BYTES` to discriminate a current-build
 * cipher blob (`"DOTTA" || CIPHER_VERSION`) from arbitrary plaintext.
 * Classification lives at the infra layer (see `content_classify` in
 * `infra/content.h`); cipher exports only the format constants.
 */
#define CIPHER_DETECT_BYTES   6

/**
 * Authenticated header size (magic + version + Argon2 params + salt fingerprint).
 *
 *   bytes [0..5)   = "DOTTA"
 *   byte   [5]     = CIPHER_VERSION
 *   bytes [6..8)   = LE16 argon2_memory_mib
 *   byte   [8]     = argon2_passes
 *   bytes [9..17)  = salt fingerprint (kdf_salt_fingerprint)
 *
 * Bound into the SIV as the first absorbed input — tampering fails MAC, not parse,
 * closing version-confusion / params-rollback / salt-relabel attacks.
 */
#define CIPHER_HEADER_SIZE    17

/** SIV / MAC tag size. Must equal `CRYPTO_MAC_SIZE`. */
#define CIPHER_SIV_SIZE       32

/** Total fixed overhead per ciphertext (header + SIV). */
#define CIPHER_OVERHEAD       (CIPHER_HEADER_SIZE + CIPHER_SIV_SIZE)

/**
 * Defensive plaintext / ciphertext-body cap (100 MiB).
 *
 * Policy bound, not a primitive limit: dotfiles are small. Prevents runaway input
 * from forcing huge keystream / ciphertext allocations.
 */
#define CIPHER_MAX_CONTENT    ((size_t) 100 * 1024 * 1024)

_Static_assert(
    CIPHER_SIV_SIZE == CRYPTO_MAC_SIZE,
    "SIV is a BLAKE2b-keyed tag"
);
_Static_assert(
    CIPHER_HEADER_SIZE == CIPHER_MAGIC_SIZE + 1 + 2 + 1 + KDF_SALT_FP_SIZE,
    "header layout drift: must be magic(5) + version(1) + mib(2) + passes(1) "
    "+ salt_fp(8)"
);
_Static_assert(
    CIPHER_OVERHEAD == CIPHER_HEADER_SIZE + CIPHER_SIV_SIZE,
    "OVERHEAD must equal HEADER + SIV"
);

/**
 * The fields a cipher-blob header carries, as `cipher_read_header` hands them
 * out: the Argon2 params the producer derived under and the fingerprint of the
 * salt it derived from. The magic and the version are not fields — a header whose
 * version is not this build's is refused at the read, so a reader never holds one.
 */
typedef struct cipher_header {
    uint16_t memory_mib;                /* argon2_memory_mib, in range */
    uint8_t passes;                     /* argon2_passes, in range */
    uint8_t salt_fp[KDF_SALT_FP_SIZE];  /* kdf_salt_fingerprint of the producer's salt */
} cipher_header_t;

/**
 * Read a cipher-blob header without touching the SIV or attempting decryption.
 *
 * The one reader of a header's fields, key-free. Length → magic → version →
 * `kdf_validate_params` on the recorded (memory_mib, passes), so an out-of-range
 * header is refused before any caller allocates an Argon2 work area for it — an
 * attacker-planted blob cannot force a tens-of-GiB allocation. The fingerprint
 * needs no validation: any 8 bytes are a well-formed fingerprint, and whether
 * it names *this* repository's salt is the caller's question.
 *
 * Readers: `keymgr_decrypt` (the salt gate, then the params to derive under)
 * and `content_classify` (the fingerprint the salt census attributes by);
 * tests/test-cipher.c pins the fields and the refusals. `cipher_decrypt` runs
 * the same validation as its own gate and reads no field — every one is bound
 * into the SIV.
 *
 * Failure modes (all ERR_CRYPTO): too short, magic mismatch, unsupported version,
 * params out of [KDF_ARGON2_*_MIN..MAX]. `*out` is untouched on failure.
 *
 * @param data     Blob bytes (must point to at least data_len bytes)
 * @param data_len Blob length
 * @param out      The header's fields on success
 * @return Error or NULL on success
 */
error_t *cipher_read_header(
    const uint8_t *data,
    size_t data_len,
    cipher_header_t *out
);

/**
 * Encrypt a plaintext buffer under (mac_key, prf_key) bound to `storage_path`,
 * recording the Argon2 params in the header.
 *
 * Output ownership: on success `*out_ciphertext` becomes the caller's (release
 * with `buffer_free`); on any error the in-progress buffer is wiped and freed
 * before return.
 *
 * Subkey wiping: `mac_key` / `prf_key` are NOT wiped here. The caller (typically
 * `keymgr_encrypt`) owns the per-operation lifetime.
 *
 * @param plaintext         Input bytes (non-NULL)
 * @param plaintext_len     Input length (≤ CIPHER_MAX_CONTENT)
 * @param mac_key           SIV MAC subkey (32 bytes)
 * @param prf_key           SIV PRF subkey (32 bytes)
 * @param storage_path      Profile-relative path bound into SIV
 *                          (non-NULL, NUL-terminated)
 * @param argon2_memory_mib Memory parameter (validated against
 *                          KDF_ARGON2_*_MIN/MAX)
 * @param argon2_passes     Pass parameter (validated)
 * @param salt_fp           Fingerprint of the repo salt the subkeys derive
 *                          from (8 bytes; stamped into the authenticated header)
 * @param out_ciphertext    Output buffer (caller frees with buffer_free)
 * @return Error or NULL on success
 */
error_t *cipher_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    uint16_t argon2_memory_mib,
    uint8_t argon2_passes,
    const uint8_t salt_fp[KDF_SALT_FP_SIZE],
    buffer_t *out_ciphertext
);

/**
 * Decrypt a dotta-encrypted blob bound to `storage_path`.
 *
 * Validates the header, derives the keystream seed from (prf_key, stored SIV),
 * produces a candidate plaintext, recomputes the SIV over (header || path ||
 * candidate), and constant-time compares against the stored SIV. On mismatch
 * the candidate is wiped before return and never surfaces.
 *
 * Output ownership: on success `*out_plaintext` becomes the caller's (release
 * with `buffer_free`); on any error the candidate is wiped and freed before return.
 *
 * SIV mismatch surfaces as a single generic "authentication failed" regardless
 * of which bound input was tampered. Parse-level errors carry specific messages
 * but no key-derivable information.
 *
 * @param ciphertext     Encrypted input (≥ CIPHER_OVERHEAD bytes)
 * @param ciphertext_len Input length
 * @param mac_key        SIV MAC subkey (32 bytes)
 * @param prf_key        SIV PRF subkey (32 bytes)
 * @param storage_path   Profile-relative path used at encryption
 * @param out_plaintext  Output buffer (caller frees with buffer_free)
 * @return Error or NULL on success (ERR_CRYPTO on auth/parse failure)
 */
error_t *cipher_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    buffer_t *out_plaintext
);

#endif /* DOTTA_CRYPTO_CIPHER_H */
