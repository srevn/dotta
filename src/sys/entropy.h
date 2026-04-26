/**
 * entropy.h - Cryptographic randomness from the OS CSPRNG
 *
 * Single chokepoint for "give me N random bytes that an attacker
 * cannot predict." Backed by `getentropy(3)` on every supported
 * platform (macOS >=10.12, Linux >=3.17 via glibc shim, FreeBSD >=12).
 *
 * A platform without `getentropy` is a build-time error — there is no
 * silent fallback to `/dev/urandom`. Falling back would be both
 * weaker (depends on /dev being mounted; surprises in restricted
 * chroots) and an opportunity for a port to use less-vetted entropy
 * without anyone noticing.
 *
 * Why getentropy is the right primitive:
 *   - One syscall, no file lifecycle to manage.
 *   - Blocks until the kernel CSPRNG is seeded; never returns
 *     pre-init weak randomness — the historical mistake that
 *     /dev/urandom can make. (`getentropy` was added to fix it.)
 *   - Async-signal-safe per POSIX 2024.
 *   - Works in chroots and minimal containers without /dev mounted.
 *
 * Why not /dev/random:
 *   `/dev/random` blocks on a kernel entropy estimate that does not
 *   correspond to real predictability on a continuously-reseeded
 *   modern CSPRNG. `getentropy` and `/dev/urandom` use the same
 *   kernel CSPRNG output once initialized.
 *
 * Output contract on error:
 *   On any syscall failure mid-loop, the function scrubs `out[0..len]`
 *   with `secure_wipe` before returning `ERR_FS`. Result: `out` is
 *   either fully populated with random bytes (on success) or fully
 *   zeroed (on error). Never partial-with-garbage.
 *
 * Used once per `dotta key set` to seed the session-cache machine
 * salt. Encryption itself is deterministic by design (SIV) and uses
 * no randomness — see `docs/encryption-spec.md`.
 */

#ifndef DOTTA_SYS_ENTROPY_H
#define DOTTA_SYS_ENTROPY_H

#include <stddef.h>
#include <stdint.h>
#include <types.h>

/**
 * Fill `out` with `len` cryptographically-strong random bytes.
 *
 * Returns NULL on success. Returns ERR_FS on syscall failure, with
 * `out[0..len]` scrubbed before return.
 *
 * NULL-safe for `len == 0` (no-op success). `out` MUST be non-NULL
 * when `len > 0`.
 *
 * @param out Output buffer (must accommodate `len` bytes; non-NULL when len > 0)
 * @param len Number of bytes to write
 * @return Error or NULL on success
 */
error_t *entropy_fill(uint8_t *out, size_t len);

#endif /* DOTTA_SYS_ENTROPY_H */
