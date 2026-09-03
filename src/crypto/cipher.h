/**
 * cipher.h - Deterministic authenticated encryption (SIV)
 *
 * Deterministic AEAD for sensitive dotfiles. Identical (mac_key, prf_key, header,
 * storage_path, plaintext) yields byte-identical ciphertext, preserving Git
 * deduplication.
 *
 * SIV pipeline:
 *   1. siv  = MAC(mac_key, CIPHER_SIV, header(14), storage_path, plaintext)
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
 *     │   5    │ version = 0x09                     │  1 B   │
 *     │   6    │ epoch fingerprint (BLAKE2b-8)      │  8 B   │
 *     │  14    │ SIV / MAC tag                      │ 32 B   │
 *     │  46    │ ciphertext (XChaCha20 keystream)   │  N B   │
 *     └────────┴────────────────────────────────────┴────────┘
 *
 * The 14-byte header is the FIRST input absorbed into the SIV. Tampering any of
 * magic, version, or the epoch fingerprint fails MAC verification, not parse
 * validation, keeping error paths uniform.
 *
 * The epoch fingerprint (`kdf_epoch_fingerprint` of the epoch the producer derived
 * under) makes every ciphertext name the epoch that keyed it. Two key-free
 * consumers read it: the ciphertext census in `infra/epoch` attributes reachable
 * ciphertext to an epoch before deciding a divergent-epoch reconcile, and
 * `keymgr_decrypt` refuses a foreign-epoch blob up front with a precise diagnostic
 * instead of prompting for a passphrase that can never verify. The Argon2
 * parameters are the epoch's and travel with the repository, never with a blob.
 *
 * Security properties:
 *   - Determinism. Same inputs → same ciphertext (Git-friendly).
 *   - Authentication. 32-byte keyed-BLAKE2b tag over (header || path || plaintext);
 *     constant-time verify on decrypt.
 *   - Path binding. `storage_path` bytes are absorbed verbatim; no normalization.
 *     A blob encrypted under one path cannot decrypt under another.
 *   - Epoch binding. The fingerprint lives in the bound header, so a blob
 *     relabelled to another epoch fails MAC.
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
#define CIPHER_VERSION        0x09

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
 * Authenticated header size (magic + version + epoch fingerprint).
 *
 *   bytes [0..5)   = "DOTTA"
 *   byte   [5]     = CIPHER_VERSION
 *   bytes [6..14)  = epoch fingerprint (kdf_epoch_fingerprint)
 *
 * Bound into the SIV as the first absorbed input — tampering fails MAC, not parse,
 * closing version-confusion / epoch-relabel attacks.
 */
#define CIPHER_HEADER_SIZE    14

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
    CIPHER_HEADER_SIZE == CIPHER_MAGIC_SIZE + 1 + KDF_EPOCH_FP_SIZE,
    "header layout drift: must be magic(5) + version(1) + epoch_fp(8)"
);
_Static_assert(
    CIPHER_OVERHEAD == CIPHER_HEADER_SIZE + CIPHER_SIV_SIZE,
    "OVERHEAD must equal HEADER + SIV"
);

/**
 * Read a cipher-blob header without touching the SIV or attempting decryption.
 *
 * The one reader of a header's field, key-free: length → magic → version, then
 * the epoch fingerprint out. The fingerprint needs no validation: any 8 bytes
 * are a well-formed fingerprint, and whether it names *this* repository's epoch
 * is the caller's question. The magic and the version are not handed out — a
 * header whose version is not this build's is refused here, so a reader never
 * holds one.
 *
 * Readers: `keymgr_decrypt` (the epoch gate) and `content_classify` (the
 * fingerprint the census attributes by); tests/test-cipher.c pins the field and
 * the refusals. `cipher_decrypt` runs the same validation as its own gate and
 * reads no field — every one is bound into the SIV.
 *
 * Failure modes (all ERR_CRYPTO): too short, magic mismatch, unsupported version.
 * `out_epoch_fp` is untouched on failure.
 *
 * @param data         Blob bytes (must point to at least data_len bytes)
 * @param data_len     Blob length
 * @param out_epoch_fp The header's epoch fingerprint on success (8 bytes)
 * @return Error or NULL on success
 */
error_t *cipher_read_header(
    const uint8_t *data,
    size_t data_len,
    uint8_t out_epoch_fp[KDF_EPOCH_FP_SIZE]
);

/**
 * Encrypt a plaintext buffer under (mac_key, prf_key) bound to `storage_path`,
 * naming the epoch in the header.
 *
 * Output ownership: on success `*out_ciphertext` becomes the caller's (release
 * with `buffer_free`); on any error the in-progress buffer is wiped and freed
 * before return.
 *
 * Subkey wiping: `mac_key` / `prf_key` are NOT wiped here. The caller (typically
 * `keymgr_encrypt`) owns the per-operation lifetime.
 *
 * @param plaintext      Input bytes (non-NULL)
 * @param plaintext_len  Input length (≤ CIPHER_MAX_CONTENT)
 * @param mac_key        SIV MAC subkey (32 bytes)
 * @param prf_key        SIV PRF subkey (32 bytes)
 * @param storage_path   Profile-relative path bound into SIV
 *                       (non-NULL, NUL-terminated)
 * @param epoch_fp       Fingerprint of the epoch the subkeys derive under
 *                       (8 bytes; stamped into the authenticated header)
 * @param out_ciphertext Output buffer (caller frees with buffer_free)
 * @return Error or NULL on success
 */
error_t *cipher_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    const uint8_t epoch_fp[KDF_EPOCH_FP_SIZE],
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
