/**
 * cipher.c - SIV encryption/decryption implementation
 *
 * Pipeline (4 steps; decrypt mirrors steps 2–4):
 *   1. Build the 9-byte authenticated header (magic, version,
 *      Argon2 params).
 *   2. SIV = MAC(mac_key, CIPHER_SIV, header, path, plaintext)
 *      — all variable inputs LE64-prefixed by `crypto_mac_absorb`,
 *      foreclosing concatenation-collision attacks.
 *   3. seed = MAC(prf_key, CIPHER_KEY, SIV) — keying with `prf_key`
 *      keeps the keystream behind a secret (SIV is public).
 *   4. crypto_chacha20_x(seed, nonce=SIV[0..24], ctr=0) XORs
 *      plaintext with keystream in one pass.
 *
 * Wiping discipline:
 *   - `keystream_seed` and (decrypt) `siv_recomputed` are stack-local
 *     and wiped on every exit path.
 *   - The output `buffer_t` is wiped and freed on any error; on
 *     success ownership transfers and the local slot is zeroed.
 *   - Subkeys are caller-owned; never wiped here.
 *
 * Wipe primitive: this layer uses monocypher's `crypto_wipe`
 * directly (already in scope via `<monocypher.h>`); non-crypto
 * layers use `secure_wipe` from `base/secure.h`. Functionally
 * identical doubly-volatile loops.
 */

#include "crypto/cipher.h"

#include <monocypher.h>
#include <string.h>

#include "base/buffer.h"
#include "base/encoding.h"
#include "base/error.h"
#include "crypto/mac.h"

/* Defensive upper bound on storage_path bytes (excluding NUL).
 * Profile-relative paths stay well under 1 KiB; this cap defends
 * the boundary independent of platform PATH_MAX (1024 on macOS,
 * 4096 on Linux). */
#define CIPHER_STORAGE_PATH_MAX 4096

/* Header byte offsets within the 9-byte authenticated header.
 * Bound into the SIV verbatim; changing any offset is a format-
 * version bump (see CIPHER_VERSION in cipher.h). */
#define CIPHER_OFFSET_MAGIC   0      /* "DOTTA" — 5 bytes */
#define CIPHER_OFFSET_VERSION 5      /* CIPHER_VERSION byte */
#define CIPHER_OFFSET_MIB     6      /* LE16 argon2_memory_mib */
#define CIPHER_OFFSET_PASSES  8      /* uint8 argon2_passes */

_Static_assert(
    CIPHER_OFFSET_VERSION == CIPHER_MAGIC_SIZE,
    "version byte must come immediately after magic"
);
_Static_assert(
    CIPHER_OFFSET_PASSES + 1 == CIPHER_HEADER_SIZE,
    "passes byte must close out the header"
);

/**
 * Bound and measure storage_path in one pass.
 *
 * `strnlen` caps the scan even if the caller hands us a
 * non-NUL-terminated buffer — the crypto module defends its own
 * boundary against caller memory-safety bugs.
 *
 * @param storage_path Path to validate (non-NULL, NUL-terminated)
 * @param out_len      Set to the path's length on success
 * @return Error or NULL on success
 */
static error_t *validate_path(const char *storage_path, size_t *out_len) {
    size_t len = strnlen(storage_path, CIPHER_STORAGE_PATH_MAX + 1);
    if (len > CIPHER_STORAGE_PATH_MAX) {
        return ERROR(
            ERR_INVALID_ARG, "Storage path too long (maximum %d bytes)",
            CIPHER_STORAGE_PATH_MAX
        );
    }
    *out_len = len;

    return NULL;
}

/**
 * Validate the 9-byte cipher-blob header.
 *
 * Length → magic → version → `kdf_validate_params` on the recorded
 * (memory_mib, passes). Used by both `cipher_peek_params` and
 * `cipher_decrypt`; centralising "what does a well-formed header
 * look like" keeps the version-bump policy tractable.
 *
 * @param data     Blob bytes (must point to at least data_len bytes)
 * @param data_len Blob length
 * @return Error or NULL if the header is well-formed and in-range
 */
static error_t *validate_header(const uint8_t *data, size_t data_len) {
    if (data_len < CIPHER_HEADER_SIZE) {
        return ERROR(
            ERR_CRYPTO,
            "Encrypted blob too short to carry a header (got %zu, need %d)",
            data_len, CIPHER_HEADER_SIZE
        );
    }
    if (memcmp(data + CIPHER_OFFSET_MAGIC, CIPHER_MAGIC, CIPHER_MAGIC_SIZE) != 0) {
        return ERROR(
            ERR_CRYPTO,
            "Invalid magic header (not a dotta encrypted file)"
        );
    }
    if (data[CIPHER_OFFSET_VERSION] != CIPHER_VERSION) {
        return ERROR(
            ERR_CRYPTO,
            "Unsupported encryption version: %u (build with version %u)",
            (unsigned) data[CIPHER_OFFSET_VERSION], (unsigned) CIPHER_VERSION
        );
    }
    return kdf_validate_params(
        load_le16(&data[CIPHER_OFFSET_MIB]),
        data[CIPHER_OFFSET_PASSES]
    );
}

/**
 * Compute the SIV over (header, path, plaintext) under `mac_key`.
 *
 *   SIV = MAC(mac_key, CIPHER_SIV, header, path, plaintext)
 *
 * Each input is LE64-prefixed by `crypto_mac_absorb`. Used identically
 * by encrypt (plaintext is user input) and decrypt (plaintext is the
 * candidate just XORed from the keystream). Wipes its context before
 * return.
 */
static void compute_siv(
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t header[CIPHER_HEADER_SIZE],
    const char *path, size_t path_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t out_siv[CIPHER_SIV_SIZE]
) {
    crypto_mac_ctx ctx;
    crypto_mac_init(&ctx, mac_key, CRYPTO_DOMAIN_CIPHER_SIV);
    crypto_mac_absorb(&ctx, header, CIPHER_HEADER_SIZE);
    crypto_mac_absorb(&ctx, (const uint8_t *) path, path_len);
    crypto_mac_absorb(&ctx, plaintext, plaintext_len);
    crypto_mac_final(&ctx, out_siv);
    crypto_wipe(&ctx, sizeof(ctx));
}

error_t *cipher_peek_params(
    const uint8_t *data,
    size_t data_len,
    uint16_t *out_memory_mib,
    uint8_t *out_passes
) {
    CHECK_NULL(data);
    CHECK_NULL(out_memory_mib);
    CHECK_NULL(out_passes);

    /* validate_header runs the same length / magic / version /
     * params-range checks that decrypt will run; we re-extract the
     * (mib, passes) pair here for the caller. The redundant LE16 load
     * is a couple of bytes — well below the noise floor of any caller
     * (Argon2 derivations are seconds-scale). */
    error_t *err = validate_header(data, data_len);
    if (err) {
        return err;
    }

    *out_memory_mib = load_le16(&data[CIPHER_OFFSET_MIB]);
    *out_passes = data[CIPHER_OFFSET_PASSES];

    return NULL;
}

error_t *cipher_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    uint16_t argon2_memory_mib,
    uint8_t argon2_passes,
    buffer_t *out_ciphertext
) {
    CHECK_NULL(plaintext);
    CHECK_NULL(mac_key);
    CHECK_NULL(prf_key);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_ciphertext);

    error_t *err = NULL;
    uint8_t header[CIPHER_HEADER_SIZE];
    uint8_t keystream_seed[CIPHER_SIV_SIZE] = { 0 };
    buffer_t output = BUFFER_INIT;
    size_t path_len = 0;

    *out_ciphertext = (buffer_t){ 0 };

    /* Every error exit funnels through `cleanup` so the wipe-and-free
     * discipline is uniform: future code that writes secrets into
     * `keystream_seed` or `output` between validation and the existing
     * `goto cleanup` sites cannot silently leak by introducing a new
     * `return err` above the wipes. The cleanup is idempotent on the
     * zero-initialised stack (keystream_seed is `{0}`, output is
     * BUFFER_INIT), so the early-validation paths pay nothing. */

    err = validate_path(storage_path, &path_len);
    if (err) {
        goto cleanup;
    }

    /* Defense-in-depth params validation. Symmetrical with
     * cipher_decrypt's header re-validation: keymgr already snapshots
     * config-validated params, but the cost of re-checking is a
     * handful of comparisons and the failure mode is a clean error
     * rather than a corrupt header on disk. */
    err = kdf_validate_params(argon2_memory_mib, argon2_passes);
    if (err) {
        goto cleanup;
    }

    /* Policy cap: dotta manages small configuration files. A single
     * cap on the crypto entry point enforces the rule for every
     * caller. */
    if (plaintext_len > CIPHER_MAX_CONTENT) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Content too large: %zu bytes (max %zu bytes).\n\n"
            "Rationale: dotfiles should be small configuration files.\n"
            "If you need to manage files larger than 100MB, consider whether\n"
            "they belong in a dotfile manager or should use a different tool.",
            plaintext_len, CIPHER_MAX_CONTENT
        );
        goto cleanup;
    }

    /* Belt-and-braces overflow guard; unreachable today
     * (CIPHER_MAX_CONTENT ≪ SIZE_MAX on 64-bit hosts), survives
     * future bumps to the content cap. */
    if (plaintext_len > SIZE_MAX - CIPHER_OVERHEAD) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Plaintext too large (size_t overflow): %zu bytes",
            plaintext_len
        );
        goto cleanup;
    }
    const size_t total_len = CIPHER_OVERHEAD + plaintext_len;

    /* Build the header on the stack so its type stays strictly
     * `uint8_t[9]` for the SIV-input contract; the same bytes feed
     * both `memcpy` into output and `compute_siv`'s first absorb. */
    memcpy(&header[CIPHER_OFFSET_MAGIC], CIPHER_MAGIC, CIPHER_MAGIC_SIZE);
    header[CIPHER_OFFSET_VERSION] = CIPHER_VERSION;
    store_le16(&header[CIPHER_OFFSET_MIB], argon2_memory_mib);
    header[CIPHER_OFFSET_PASSES] = argon2_passes;

    /* Allocate at final size; SIV and ciphertext write into their
     * slots in-place so peak memory stays at `total_len`. buffer_grow
     * over-allocates by 1 for the NUL invariant. */
    err = buffer_grow(&output, total_len);
    if (err) goto cleanup;

    output.size = total_len;
    output.data[output.size] = '\0';

    /* Layout: [header(9) | siv(32) | ciphertext(N)] */
    memcpy(output.data, header, CIPHER_HEADER_SIZE);
    uint8_t *siv_slot = (uint8_t *) output.data + CIPHER_HEADER_SIZE;
    uint8_t *ct_slot = siv_slot + CIPHER_SIV_SIZE;

    /* Step 2: SIV over (header, path, plaintext) keyed by mac_key.
     * The plaintext is read here and again at step 4 — SIV is
     * fundamentally two-pass. */
    compute_siv(
        mac_key, header, storage_path, path_len,
        plaintext, plaintext_len, siv_slot
    );

    /* Step 3: keystream seed = MAC(prf_key, CIPHER_KEY, SIV). Keying
     * with prf_key keeps the keystream secret even though the SIV is
     * public (it sits in the output we are about to hand out). */
    crypto_mac_oneshot(
        keystream_seed, prf_key, CRYPTO_DOMAIN_CIPHER_KEY,
        siv_slot, CIPHER_SIV_SIZE, NULL, 0
    );

    /* Step 4: XChaCha20(seed, nonce=siv[0..24], ctr=0) XOR plaintext.
     * monocypher reads exactly 24 bytes from the nonce pointer; the
     * SIV's tail 8 bytes serve only as the MAC tag. plaintext_len == 0
     * is a no-op inside the primitive. */
    crypto_chacha20_x(
        ct_slot, plaintext, plaintext_len,
        keystream_seed, siv_slot, /*ctr=*/ 0
    );

    /* Transfer ownership; cleanup becomes a no-op on the zeroed slot. */
    *out_ciphertext = output;
    output = (buffer_t){ 0 };

cleanup:
    crypto_wipe(keystream_seed, sizeof(keystream_seed));
    /* On error, wipe whatever was written into the output buffer
     * before freeing. The bytes might include a freshly-written
     * keystream which, paired with knowledge of the plaintext, would
     * leak the keystream to a memory-disclosure attacker. */
    if (output.data) {
        crypto_wipe(output.data, output.size);
        buffer_free(&output);
    }

    return err;
}

error_t *cipher_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t mac_key[KDF_KEY_SIZE],
    const uint8_t prf_key[KDF_KEY_SIZE],
    const char *storage_path,
    buffer_t *out_plaintext
) {
    CHECK_NULL(ciphertext);
    CHECK_NULL(mac_key);
    CHECK_NULL(prf_key);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_plaintext);

    error_t *err = NULL;
    uint8_t keystream_seed[CIPHER_SIV_SIZE] = { 0 };
    uint8_t siv_recomputed[CIPHER_SIV_SIZE] = { 0 };
    buffer_t output = BUFFER_INIT;
    size_t path_len = 0;

    *out_plaintext = (buffer_t){ 0 };

    /* Same uniform-exit pattern as cipher_encrypt: validation early-
     * returns route through `cleanup` so a future partial-secret
     * write cannot silently bypass the wipe. */

    err = validate_path(storage_path, &path_len);
    if (err) goto cleanup;

    /* Mirror the encrypt-side cap, accounting for OVERHEAD. The
     * compile-time constant `CIPHER_MAX_CONTENT + CIPHER_OVERHEAD`
     * is well under SIZE_MAX so the addition cannot wrap. */
    if (ciphertext_len > CIPHER_MAX_CONTENT + (size_t) CIPHER_OVERHEAD) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Ciphertext too large: %zu bytes (max %zu bytes).\n\n"
            "Rationale: dotfiles should be small configuration files.\n"
            "If you need to manage files larger than 100MB, consider whether\n"
            "they belong in a dotfile manager or should use a different tool.",
            ciphertext_len, CIPHER_MAX_CONTENT + (size_t) CIPHER_OVERHEAD
        );
        goto cleanup;
    }

    if (ciphertext_len < CIPHER_OVERHEAD) {
        err = ERROR(
            ERR_CRYPTO,
            "Invalid ciphertext: too short (expected >= %d, got %zu)",
            CIPHER_OVERHEAD, ciphertext_len
        );
        goto cleanup;
    }

    /* Defense-in-depth header validation at the cipher boundary.
     * The recorded params themselves are not used here — their bytes
     * are bound into the SIV via the header, so any tamper fails the
     * constant-time MAC verify below. */
    err = validate_header(ciphertext, ciphertext_len);
    if (err) goto cleanup;

    const uint8_t *header = ciphertext;
    const uint8_t *siv_received = ciphertext + CIPHER_HEADER_SIZE;
    const uint8_t *ct_body = ciphertext + CIPHER_OVERHEAD;
    const size_t plaintext_len = ciphertext_len - CIPHER_OVERHEAD;

    /* Allocate the candidate plaintext buffer at its final size; the
     * keystream XOR writes into it in-place, after which we recompute
     * SIV over the candidate. */
    err = buffer_grow(&output, plaintext_len);
    if (err) goto cleanup;

    output.size = plaintext_len;
    output.data[output.size] = '\0';

    /* Step 3: keystream seed from received SIV under prf_key. In SIV
     * the IV authenticates the plaintext — we must decrypt the
     * candidate before we can verify, then either return or wipe it. */
    crypto_mac_oneshot(
        keystream_seed, prf_key, CRYPTO_DOMAIN_CIPHER_KEY,
        siv_received, CIPHER_SIV_SIZE,
        NULL, 0
    );

    /* Step 4: XChaCha20 ciphertext_body → candidate plaintext. Same
     * (seed, nonce, ctr) as encrypt; XOR is its own inverse. */
    crypto_chacha20_x(
        (uint8_t *) output.data, ct_body, plaintext_len,
        keystream_seed, siv_received, /*ctr=*/ 0
    );

    /* Step 2 (recomputed): SIV over (header, path, candidate). If
     * authentication holds, candidate == original plaintext, so the
     * recomputed SIV matches the stored SIV byte-for-byte. */
    compute_siv(
        mac_key, header, storage_path, path_len,
        (const uint8_t *) output.data, plaintext_len,
        siv_recomputed
    );

    /* Constant-time compare. crypto_verify32 returns 0 iff the two
     * 32-byte buffers are byte-equal; non-zero indicates ANY
     * difference, with no early-exit timing leak. */
    if (crypto_verify32(siv_recomputed, siv_received) != 0) {
        err = ERROR(
            ERR_CRYPTO,
            "Authentication failed "
            "(wrong passphrase, tampered ciphertext, or path mismatch)"
        );
        goto cleanup;
    }

    /* Transfer ownership to caller. The cleanup path becomes a no-op
     * because `output` is now zeroed. */
    *out_plaintext = output;
    output = (buffer_t){ 0 };

cleanup:
    crypto_wipe(keystream_seed, sizeof(keystream_seed));
    crypto_wipe(siv_recomputed, sizeof(siv_recomputed));
    /* On error, wipe before free: after a MAC mismatch the candidate
     * is would-be plaintext from an attacker-supplied SIV/ciphertext
     * pair and must not survive to the caller. */
    if (output.data) {
        crypto_wipe(output.data, output.size);
        buffer_free(&output);
    }

    return err;
}
