/**
 * cipher.h - Deterministic authenticated encryption (SIV)
 *
 * Deterministic AEAD for sensitive dotfiles. Identical
 * (mac_key, prf_key, header, storage_path, plaintext) yields
 * byte-identical ciphertext, preserving Git deduplication.
 *
 * SIV pipeline:
 *   1. siv  = MAC(mac_key, CIPHER_SIV, header(9), storage_path, plaintext)
 *   2. seed = MAC(prf_key, CIPHER_KEY, siv)
 *   3. ciphertext = XChaCha20(key=seed, nonce=siv[0..24], ctr=0, plaintext)
 *
 * The 32-byte SIV doubles as MAC tag and as the source of XChaCha20's
 * 24-byte nonce; `crypto_mac_absorb` LE64-prefixes each variable input
 * so distinct tuples produce distinct absorbed streams.
 *
 * On-disk blob layout:
 *
 *     ┌────────┬────────────────────────────────────┬────────┐
 *     │ offset │ field                              │ size   │
 *     ├────────┼────────────────────────────────────┼────────┤
 *     │   0    │ magic "DOTTA"                      │  5 B   │
 *     │   5    │ version = 0x06                     │  1 B   │
 *     │   6    │ argon2_memory_mib (LE16)           │  2 B   │
 *     │   8    │ argon2_passes                      │  1 B   │
 *     │   9    │ SIV / MAC tag                      │ 32 B   │
 *     │  41    │ ciphertext (XChaCha20 keystream)   │  N B   │
 *     └────────┴────────────────────────────────────┴────────┘
 *
 * The 9-byte header is the FIRST input absorbed into the SIV.
 * Tampering any of magic, version, or Argon2 params fails MAC
 * verification, not parse validation, keeping error paths uniform.
 *
 * Security properties:
 *   - Determinism. Same inputs → same ciphertext (Git-friendly).
 *   - Authentication. 32-byte keyed-BLAKE2b tag over
 *     (header || path || plaintext); constant-time verify on decrypt.
 *   - Path binding. `storage_path` bytes are absorbed verbatim; no
 *     normalization. A blob encrypted under one path cannot decrypt
 *     under another.
 *   - Params binding. Argon2 (memory_mib, passes) live in the bound
 *     header, so config edits cannot invalidate old blobs and a
 *     tampered params field fails MAC.
 *   - Nonce-misuse resistance. Distinct plaintexts under the same
 *     (mac_key, path, header) yield distinct SIVs and keystreams.
 *   - Key isolation. Operates only on the per-operation
 *     (mac_key, prf_key) pair; never sees master key or profile name.
 *
 * Format-version policy: `CIPHER_VERSION` bumps on any incompatible
 * change. A bump invalidates every blob keyed under the prior version
 * — no migration path (alpha policy in CLAUDE.md).
 *
 * Caller contract: `cipher_encrypt` / `cipher_decrypt` accept a raw
 * `(mac_key, prf_key)` pair so this module stays free of master-key
 * and profile-name knowledge. The canonical caller is `crypto/keymgr`,
 * which derives the pair via `kdf_siv_subkeys` and wipes both buffers
 * after the single per-operation use. Any other call site needs
 * explicit justification — `kdf_siv_subkeys` is what makes the two
 * subkeys cryptographically independent, and per-operation derive +
 * wipe is what bounds subkey lifetime on the stack.
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
#define CIPHER_VERSION        0x06

/**
 * Detection-prefix length (magic + version).
 *
 * `cipher_is_encrypted` matches the first 6 bytes against
 * `"DOTTA" || CIPHER_VERSION`; a different version byte reports as
 * not-encrypted so the metadata cross-check in infra/content.c can
 * route the mismatch before any decrypt attempt.
 */
#define CIPHER_DETECT_BYTES   6

/**
 * Authenticated header size (magic + version + Argon2 params).
 *
 *   bytes [0..5)  = "DOTTA"
 *   byte   [5]    = CIPHER_VERSION
 *   bytes [6..8)  = LE16 argon2_memory_mib
 *   byte   [8]    = argon2_passes
 *
 * Bound into the SIV as the first absorbed input — tampering fails
 * MAC, not parse, closing version-confusion / params-rollback attacks.
 */
#define CIPHER_HEADER_SIZE    9

/** SIV / MAC tag size. Must equal `CRYPTO_MAC_SIZE`. */
#define CIPHER_SIV_SIZE       32

/** Total fixed overhead per ciphertext (header + SIV). */
#define CIPHER_OVERHEAD       (CIPHER_HEADER_SIZE + CIPHER_SIV_SIZE)

/**
 * Defensive plaintext / ciphertext-body cap (100 MiB).
 *
 * Policy bound, not a primitive limit: dotfiles are small. Prevents
 * runaway input from forcing huge keystream / ciphertext allocations.
 */
#define CIPHER_MAX_CONTENT    ((size_t) 100 * 1024 * 1024)

_Static_assert(
    CIPHER_SIV_SIZE == CRYPTO_MAC_SIZE,
    "SIV is a BLAKE2b-keyed tag"
);
_Static_assert(
    CIPHER_HEADER_SIZE == 9,
    "header layout drift: must be magic(5) + version(1) + mib(2) + passes(1)"
);
_Static_assert(
    CIPHER_OVERHEAD == CIPHER_HEADER_SIZE + CIPHER_SIV_SIZE,
    "OVERHEAD must equal HEADER + SIV"
);

/**
 * Test whether a byte buffer is a dotta-encrypted blob this build
 * can decrypt.
 *
 * Sniffs the 6-byte detection window (magic + version). A blob with
 * a non-current version byte reports false; the metadata cross-check
 * in infra/content.c routes that case before any decrypt attempt.
 *
 * @param data     File content (may be NULL when len == 0)
 * @param data_len Content length
 * @return true iff data begins with magic + current-build version
 */
bool cipher_is_encrypted(const uint8_t *data, size_t data_len);

/**
 * Read the Argon2 params from a cipher-blob header without
 * touching the SIV or attempting decryption.
 *
 * Used by `keymgr_decrypt` to derive the master key under the params
 * the producer used. Applies `kdf_validate_params` so an out-of-range
 * header rejects before any Argon2 work area is allocated — closes
 * the DoS surface where an attacker-planted blob would otherwise
 * force tens-of-GiB allocations.
 *
 * Failure modes (all ERR_CRYPTO): too short, magic mismatch,
 * unsupported version, params out of [KDF_ARGON2_*_MIN..MAX].
 *
 * @param data            Blob bytes (must include at least HEADER_SIZE)
 * @param data_len        Blob length
 * @param out_memory_mib  Set to header's argon2_memory_mib on success
 * @param out_passes      Set to header's argon2_passes on success
 * @return Error or NULL on success
 */
error_t *cipher_peek_params(
    const uint8_t *data,
    size_t data_len,
    uint16_t *out_memory_mib,
    uint8_t *out_passes
);

/**
 * Encrypt a plaintext buffer under (mac_key, prf_key) bound to
 * `storage_path`, recording the Argon2 params in the header.
 *
 * Output ownership: on success `*out_ciphertext` becomes the caller's
 * (release with `buffer_free`); on any error the in-progress buffer
 * is wiped and freed before return.
 *
 * Subkey wiping: `mac_key` / `prf_key` are NOT wiped here. The
 * caller (typically `keymgr_encrypt`) owns the per-operation lifetime.
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
    buffer_t *out_ciphertext
);

/**
 * Decrypt a dotta-encrypted blob bound to `storage_path`.
 *
 * Validates the header, derives the keystream seed from
 * (prf_key, stored SIV), produces a candidate plaintext, recomputes
 * the SIV over (header || path || candidate), and constant-time
 * compares against the stored SIV. On mismatch the candidate is
 * wiped before return and never surfaces.
 *
 * Output ownership: on success `*out_plaintext` becomes the caller's
 * (release with `buffer_free`); on any error the candidate is wiped
 * and freed before return.
 *
 * SIV mismatch surfaces as a single generic "authentication failed"
 * regardless of which bound input was tampered. Parse-level errors
 * carry specific messages but no key-derivable information.
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
