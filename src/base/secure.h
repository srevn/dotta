/**
 * secure.h - Secure-memory utilities
 *
 * Two unrelated helpers grouped here because both serve the
 * "this buffer is about to hold (or just held) a secret" lifecycle:
 *
 *   - `secure_wipe`           - compiler-resistant zeroization.
 *   - `secure_mlock_warn` - one-time-per-process advisory when
 *                                an mlock attempt fails.
 *
 * `secure_wipe` is the chokepoint for scrubbing secret-bearing memory
 * across non-crypto layers (base/, sys/, infra/, core/, cmds/). The
 * crypto layer (src/crypto/) calls monocypher's `crypto_wipe` directly
 * — its primitives are already in scope. Each layer cluster uses its
 * native wipe; both implementations are functionally identical
 * doubly-volatile loops. Keeping `secure_wipe` vendor-free is what
 * lets non-crypto modules wipe secrets without dragging a crypto
 * dependency into layers below the crypto layer.
 *
 * `secure_mlock_warn` is shared by every layer (including the
 * crypto layer) because the advisory is purely a stderr message — no
 * crypto primitive is involved, and a single one-time-per-process
 * gate is the right UX regardless of which subsystem hit the limit
 * first. Centralising the gate prevents the user from seeing two,
 * three, or four near-identical warnings in a single command run.
 *
 * Implementation guarantee for `secure_wipe`: writes are not elided
 * by dead-store elimination or whole-program optimization. Implemented
 * via a doubly-volatile-pointer loop (`volatile unsigned char
 * *volatile`) that hardens against both per-write elision (the writes
 * are volatile) and pointer-variable elision (the pointer is
 * volatile). `unsigned char` is the strict-aliasing-safe access type
 * per C11 §6.5p7, so this works for any buffer regardless of its
 * declared type.
 *
 * Out-of-line by design: the call appears in disassembly and lives
 * at a single machine-code address, which keeps the audit chokepoint
 * legible. Cost is one indirect call per scrub — negligible against
 * the allocator and syscall work that surrounds every secret-bearing
 * lifecycle in this codebase.
 *
 * Use `secure_wipe` whenever a buffer that has held a secret
 * (passphrase bytes, derived keys, decrypted plaintext, credential
 * helper output) is about to be released to the allocator, reused,
 * or otherwise stop being controlled. A plain memset is forbidden
 * for these buffers because the optimizer is permitted to eliminate
 * stores to memory that is freed or never read again.
 */

#ifndef DOTTA_SECURE_H
#define DOTTA_SECURE_H

#include <stddef.h>

/**
 * Securely zero `len` bytes at `ptr`.
 *
 * Writes are guaranteed to land in memory; the optimizer cannot drop
 * them as dead stores. Behavior matches a hand-rolled loop with
 * `volatile` byte writes.
 *
 * NULL-safe: `ptr == NULL` is a no-op.
 * Zero-length: `len == 0` is a no-op.
 *
 * Does not unlock or free; pair with `munlock`/`free` (or use
 * `buffer_secure_free` for the full secret-allocation lifecycle) when
 * the bytes lived in a heap allocation that needs to be released.
 *
 * @param ptr Memory to wipe (may be NULL)
 * @param len Number of bytes to wipe (may be 0)
 */
void secure_wipe(void *ptr, size_t len);

/**
 * Emit a one-time-per-process advisory to stderr about an mlock failure.
 *
 * Several call sites attempt `mlock` on secret-bearing buffers (Argon2
 * work area, master-key cache slot, passphrase buffers). On macOS the
 * default `RLIMIT_MEMLOCK` is 64 KiB — every non-trivial Argon2 setting
 * exceeds that, so failures are the common case for default-configured
 * systems. Without coordination, the user would see one warning per
 * site per command (4+ near-identical messages); this helper gates
 * output on a process-wide flag so the user sees exactly one advisory
 * regardless of which site hit the limit first.
 *
 * The format string and varargs describe what failed to lock; the
 * helper appends the standard "may be paged to disk / raise
 * RLIMIT_MEMLOCK" remediation boilerplate so every advisory has the
 * same actionable tail.
 *
 * Subsequent calls within the same process are no-ops.
 *
 * Not thread-safe (the gate is a plain `static bool`). Dotta is
 * single-threaded; revisit if that ever changes.
 *
 * @param saved_errno errno value from the failed mlock call
 * @param fmt         printf-style description of the buffer that
 *                    failed to lock (e.g., "%u MiB Argon2 work area")
 */
void secure_mlock_warn(int saved_errno, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

#endif /* DOTTA_SECURE_H */
