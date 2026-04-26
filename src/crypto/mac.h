/**
 * mac.h - Keyed-BLAKE2b chokepoint with canonical framing
 *
 * The single point of access to keyed BLAKE2b for the codebase. Other
 * crypto modules absorb variable-length inputs through this layer,
 * which prepends a canonical LE64 length prefix on every absorbed
 * input so MAC inputs cannot be left ambiguously framed.
 *
 * Purpose:
 *   1. Domain separation. The 8-byte tag absorbed at init binds every
 *      keyed BLAKE2b call to a single, named purpose. Same key under
 *      different tags yields cryptographically independent outputs.
 *      The tag registry lives in mac.c with a compile-time uniqueness
 *      check.
 *   2. Canonical framing. `crypto_mac_absorb` always emits LE64(len)
 *      before data bytes, foreclosing length-extension and
 *      concatenation-collision attacks: ("ab"+"c") and ("a"+"bc")
 *      would otherwise absorb identical bytes.
 *   3. Audit chokepoint. Every keyed BLAKE2b call goes through one
 *      module with one framing rule.
 *
 * Used by cipher.c (SIV computation), kdf.c (subkey derivation), and
 * session.c (cache authentication).
 *
 * Adding a new domain tag:
 *   1. Insert a new enum value in `crypto_domain_t` before _COUNT.
 *   2. Add an entry to the static `domain_tags[]` table in mac.c
 *      with a unique 8-byte ASCII string.
 *   3. Add `DOMAIN_NEQ(NEW_TAG, ALL_PRIOR_TAGS)` lines pairing the
 *      new tag against every prior entry.
 *   The build fails if any pair collides; no runtime test required.
 *
 * Output zeroization:
 *   - After `crypto_mac_final` the caller MUST `crypto_wipe(&ctx,
 *     sizeof(ctx))` if the context held secret-keyed state. The
 *     wrapper struct on the caller's stack still carries derived
 *     material even after `crypto_blake2b_final` clears its internal
 *     accumulator.
 *   - `crypto_mac_oneshot` wipes its internal context on every exit
 *     path; callers need no further scrub.
 *
 * Wipe primitive: this layer uses monocypher's `crypto_wipe`
 * directly; non-crypto layers use `secure_wipe` from base/secure.h.
 * Functionally identical doubly-volatile loops.
 */

#ifndef DOTTA_CRYPTO_MAC_H
#define DOTTA_CRYPTO_MAC_H

#include <monocypher.h>
#include <stddef.h>
#include <stdint.h>

#define CRYPTO_KEY_SIZE 32      /* Keyed-BLAKE2b key size (bytes). */
#define CRYPTO_MAC_SIZE 32      /* Keyed-BLAKE2b output size (bytes). */

/**
 * Domain-separation tags.
 *
 * Each enum value names a distinct keyed-BLAKE2b call site. Values
 * are 8-byte ASCII strings stored in `domain_tags[]` in mac.c,
 * asserted unique at compile time. Insert new tags before `_COUNT`.
 */
typedef enum {
    CRYPTO_DOMAIN_SIV_MAC,      /* kdf: master + profile -> mac_key   ("dot-mac\0") */
    CRYPTO_DOMAIN_SIV_PRF,      /* kdf: master + profile -> prf_key   ("dot-prf\0") */
    CRYPTO_DOMAIN_CIPHER_SIV,   /* cipher: SIV over (header,path,pt)  ("dot-siv\0") */
    CRYPTO_DOMAIN_CIPHER_KEY,   /* cipher: keystream-seed from SIV    ("dot-key\0") */
    CRYPTO_DOMAIN_SESSION_MAC,  /* session: cache MAC                 ("dot-ses\0") */
    CRYPTO_DOMAIN_COUNT
} crypto_domain_t;

/**
 * Incremental MAC context.
 *
 * Thin wrapper around `crypto_blake2b_ctx` so callers cannot bypass
 * this module's LE64 framing by calling monocypher's incremental API
 * directly. `sizeof(crypto_mac_ctx) == sizeof(crypto_blake2b_ctx)` —
 * the type's cost is purely compile-time discipline.
 *
 * Caller-provided storage. After `_final`, the caller must
 * `crypto_wipe(&ctx, sizeof(ctx))`.
 */
typedef struct crypto_mac_ctx {
    crypto_blake2b_ctx blake;
} crypto_mac_ctx;

/**
 * Initialize an incremental keyed MAC.
 *
 * `crypto_blake2b_keyed_init` with the supplied key, then absorbs the
 * 8-byte domain tag UNFRAMED (fixed-length by construction; subsequent
 * `crypto_mac_absorb` calls are LE64-prefixed).
 *
 * @param ctx    Caller-provided context (any uninitialized storage)
 * @param key    32-byte key
 * @param domain Valid `crypto_domain_t` value (out-of-range caught by
 *               assertion in mac.c)
 */
void crypto_mac_init(
    crypto_mac_ctx *ctx,
    const uint8_t key[CRYPTO_KEY_SIZE],
    crypto_domain_t domain
);

/**
 * Absorb a variable-length input into the MAC.
 *
 * Unconditionally prepends `LE64(len)` before `data[0..len]`; callers
 * cannot opt out — that is the whole point of this layer. Safe for
 * `len == 0` (absorbs only `LE64(0)`; `data` may be NULL).
 *
 * @param ctx  Initialized context
 * @param data Bytes to absorb (may be NULL iff len == 0)
 * @param len  Length in bytes
 */
void crypto_mac_absorb(
    crypto_mac_ctx *ctx,
    const uint8_t *data,
    size_t len
);

/**
 * Finalize the MAC and write 32 bytes of output.
 *
 * The caller MUST `crypto_wipe(ctx, sizeof(*ctx))` after this if the
 * context held key-derived state — `crypto_blake2b_final` clears its
 * internal accumulator, but the wrapper struct on the caller's stack
 * is the caller's responsibility.
 *
 * @param ctx Initialized context (consumed; do not reuse without re-init)
 * @param out 32-byte output buffer
 */
void crypto_mac_final(
    crypto_mac_ctx *ctx,
    uint8_t out[CRYPTO_MAC_SIZE]
);

/**
 * One-shot keyed MAC over up to two variable-length inputs.
 *
 * Equivalent to:
 *   crypto_mac_init(&ctx, key, domain);
 *   crypto_mac_absorb(&ctx, input1, len1);
 *   if (input2 != NULL) crypto_mac_absorb(&ctx, input2, len2);
 *   crypto_mac_final(&ctx, out);
 *   crypto_wipe(&ctx, sizeof(ctx));
 *
 * `input2 == NULL` skips the second absorb entirely (rather than
 * absorbing `LE64(0)` as a sentinel) so a single-input call's
 * absorbed byte stream is identical regardless of whether the caller
 * knew the API supported a second input. The internal context is
 * wiped on every exit path.
 *
 * @param out    32-byte output buffer
 * @param key    32-byte key
 * @param domain Domain-separation tag
 * @param input1 First input bytes (non-NULL or len1 == 0)
 * @param len1   Length of first input in bytes
 * @param input2 Second input bytes (may be NULL to skip)
 * @param len2   Length of second input (ignored if input2 == NULL)
 */
void crypto_mac_oneshot(
    uint8_t out[CRYPTO_MAC_SIZE],
    const uint8_t key[CRYPTO_KEY_SIZE],
    crypto_domain_t domain,
    const uint8_t *input1, size_t len1,
    const uint8_t *input2, size_t len2
);

#endif /* DOTTA_CRYPTO_MAC_H */
