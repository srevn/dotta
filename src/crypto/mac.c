/**
 * mac.c - Keyed-BLAKE2b chokepoint with canonical framing
 *
 * Hosts the domain-tag registry in two parallel forms derived from
 * the same `TAG_BYTES_*` macros:
 *   - Byte form (`domain_tags[][8]`) for runtime absorption.
 *   - U64-packed form for compile-time uniqueness assertions.
 *
 * Two forms exist because a C11 `_Static_assert` needs an
 * integer-constant expression, which a `static const uint8_t[]` is
 * not. `PACK_U64` packs eight char literals into a `uint64_t` ICE
 * that the assertion can compare. The byte form remains the runtime
 * feed; the U64 form exists only for the assertion chain. Single
 * source of truth: each tag has one `TAG_BYTES_*` definition both
 * forms reference.
 */

#include "crypto/mac.h"

#include <assert.h>
#include <monocypher.h>
#include <stddef.h>
#include <stdint.h>

#include "base/encoding.h"

/* Each tag is exactly 8 bytes; the fixed width is what lets us absorb
 * unframed at MAC init. The trailing `\0` is a regular byte, not a
 * string terminator (these are never treated as C strings). The "dot-"
 * prefix is a readability marker; the cryptographic effect comes from
 * byte-level distinctness. */
#define TAG_BYTES_SIV_MAC      'd', 'o', 't', '-', 'm', 'a', 'c', '\0'
#define TAG_BYTES_SIV_PRF      'd', 'o', 't', '-', 'p', 'r', 'f', '\0'
#define TAG_BYTES_CIPHER_SIV   'd', 'o', 't', '-', 's', 'i', 'v', '\0'
#define TAG_BYTES_CIPHER_KEY   'd', 'o', 't', '-', 'k', 'e', 'y', '\0'
#define TAG_BYTES_SESSION_MAC  'd', 'o', 't', '-', 's', 'e', 's', '\0'

/* Pack eight byte values into a uint64_t ICE so a `_Static_assert`
 * can compare tags for inequality. The cast through `unsigned char`
 * preserves the bit pattern when `char` is signed.
 *
 * The PACK_U64 / PACK_U64_IMPL split is the deferred-expansion idiom
 * (C11 §6.10.3.1): macro arguments are identified BEFORE expansion,
 * so calling PACK_U64_IMPL directly with `TAG_BYTES_SIV_MAC` (which
 * expands to 8 comma-separated bytes) would see one argument, not
 * eight. The variadic outer `PACK_U64(...)` forces the inner
 * expansion during the post-substitution rescan. */
#define PACK_U64(...)       PACK_U64_IMPL(__VA_ARGS__)
#define PACK_U64_IMPL(b0, b1, b2, b3, b4, b5, b6, b7) \
    ((uint64_t) (unsigned char) (b0) \
     | ((uint64_t) (unsigned char) (b1) << 8) \
     | ((uint64_t) (unsigned char) (b2) << 16) \
     | ((uint64_t) (unsigned char) (b3) << 24) \
     | ((uint64_t) (unsigned char) (b4) << 32) \
     | ((uint64_t) (unsigned char) (b5) << 40) \
     | ((uint64_t) (unsigned char) (b6) << 48) \
     | ((uint64_t) (unsigned char) (b7) << 56))

#define DOM_U64_SIV_MAC      PACK_U64(TAG_BYTES_SIV_MAC)
#define DOM_U64_SIV_PRF      PACK_U64(TAG_BYTES_SIV_PRF)
#define DOM_U64_CIPHER_SIV   PACK_U64(TAG_BYTES_CIPHER_SIV)
#define DOM_U64_CIPHER_KEY   PACK_U64(TAG_BYTES_CIPHER_KEY)
#define DOM_U64_SESSION_MAC  PACK_U64(TAG_BYTES_SESSION_MAC)

#define DOMAIN_NEQ(a, b) \
    _Static_assert((a) != (b), "domain tag collision: " #a " == " #b)

/* Pairwise inequality across all CRYPTO_DOMAIN_* tags. With N tags
 * there are N*(N-1)/2 = 10 pairs for N=5; every additional tag adds
 * one new chain of N comparisons. */
DOMAIN_NEQ(DOM_U64_SIV_MAC, DOM_U64_SIV_PRF);
DOMAIN_NEQ(DOM_U64_SIV_MAC, DOM_U64_CIPHER_SIV);
DOMAIN_NEQ(DOM_U64_SIV_MAC, DOM_U64_CIPHER_KEY);
DOMAIN_NEQ(DOM_U64_SIV_MAC, DOM_U64_SESSION_MAC);
DOMAIN_NEQ(DOM_U64_SIV_PRF, DOM_U64_CIPHER_SIV);
DOMAIN_NEQ(DOM_U64_SIV_PRF, DOM_U64_CIPHER_KEY);
DOMAIN_NEQ(DOM_U64_SIV_PRF, DOM_U64_SESSION_MAC);
DOMAIN_NEQ(DOM_U64_CIPHER_SIV, DOM_U64_CIPHER_KEY);
DOMAIN_NEQ(DOM_U64_CIPHER_SIV, DOM_U64_SESSION_MAC);
DOMAIN_NEQ(DOM_U64_CIPHER_KEY, DOM_U64_SESSION_MAC);

/* Indexed by `crypto_domain_t`; designated initializers tie row order
 * to the enum even if entries are reordered. */
static const uint8_t domain_tags[CRYPTO_DOMAIN_COUNT][8] = {
    [CRYPTO_DOMAIN_SIV_MAC] =     { TAG_BYTES_SIV_MAC     },
    [CRYPTO_DOMAIN_SIV_PRF] =     { TAG_BYTES_SIV_PRF     },
    [CRYPTO_DOMAIN_CIPHER_SIV] =  { TAG_BYTES_CIPHER_SIV  },
    [CRYPTO_DOMAIN_CIPHER_KEY] =  { TAG_BYTES_CIPHER_KEY  },
    [CRYPTO_DOMAIN_SESSION_MAC] = { TAG_BYTES_SESSION_MAC },
};

_Static_assert(
    CRYPTO_KEY_SIZE == 32,
    "BLAKE2b keyed-input convention is 32 bytes"
);
_Static_assert(
    CRYPTO_MAC_SIZE == 32,
    "BLAKE2b output convention is 32 bytes"
);
_Static_assert(
    sizeof(crypto_mac_ctx) == sizeof(crypto_blake2b_ctx),
    "crypto_mac_ctx must be a thin wrapper — no extra fields"
);

void crypto_mac_init(
    crypto_mac_ctx *ctx,
    const uint8_t key[CRYPTO_KEY_SIZE],
    crypto_domain_t domain
) {
    /* Defensive bound on the domain index. Compile-time uniqueness
     * is enforced by DOMAIN_NEQ above, but a caller passing an
     * out-of-range int cast (e.g. a deserialized field that bypassed
     * validation) would read past the end of `domain_tags[]`. The
     * `unsigned` cast makes negatives compare as huge unsigned and
     * sidesteps -Wtype-limits on unsigned-enum platforms. */
    assert((unsigned int) domain < (unsigned int) CRYPTO_DOMAIN_COUNT);

    /* Output size is the BLAKE2b-256 default; key size is 32 (the
     * keyed-BLAKE2b standard for 32-byte tags). Both are constants
     * cross-asserted against monocypher's input size assumptions. */
    crypto_blake2b_keyed_init(
        &ctx->blake, CRYPTO_MAC_SIZE, key, CRYPTO_KEY_SIZE
    );

    /* Absorb the 8-byte domain tag UNFRAMED. Fixed length by
     * construction; LE64(8) would add no security and would force a
     * canonicalisation rule on a tag that has none. The same pattern
     * is used by `derive_cache_key` in session.c for its 16-byte
     * machine_salt. */
    crypto_blake2b_update(&ctx->blake, domain_tags[domain], 8);
}

void crypto_mac_absorb(
    crypto_mac_ctx *ctx,
    const uint8_t *data,
    size_t len
) {
    /* Always emit LE64(len) first — even for len == 0 — so
     * ("ab"+"c") and ("a"+"bc") absorb distinct byte streams. */
    uint8_t len_le[8];
    store_le64(len_le, (uint64_t) len);
    crypto_blake2b_update(&ctx->blake, len_le, sizeof(len_le));

    /* `crypto_blake2b_update` accepts (NULL, 0) per monocypher's
     * contract, so len == 0 is safe even when the caller passed NULL. */
    if (len > 0) {
        crypto_blake2b_update(&ctx->blake, data, len);
    }
}

void crypto_mac_final(
    crypto_mac_ctx *ctx,
    uint8_t out[CRYPTO_MAC_SIZE]
) {
    crypto_blake2b_final(&ctx->blake, out);
    /* Caller is responsible for `crypto_wipe(ctx, sizeof(*ctx))`.
     * `crypto_blake2b_final` zeroes its internal accumulator, but the
     * wrapper struct still occupies stack space. See header. */
}

void crypto_mac_oneshot(
    uint8_t out[CRYPTO_MAC_SIZE],
    const uint8_t key[CRYPTO_KEY_SIZE],
    crypto_domain_t domain,
    const uint8_t *input1, size_t len1,
    const uint8_t *input2, size_t len2
) {
    crypto_mac_ctx ctx;
    crypto_mac_init(&ctx, key, domain);
    crypto_mac_absorb(&ctx, input1, len1);

    /* NULL = "input not provided", not "absorb LE64(0)" — a
     * single-input call's absorbed bytes must be identical regardless
     * of whether the caller knew about the two-input form. */
    if (input2 != NULL) {
        crypto_mac_absorb(&ctx, input2, len2);
    }

    crypto_mac_final(&ctx, out);
    crypto_wipe(&ctx, sizeof(ctx));
}
