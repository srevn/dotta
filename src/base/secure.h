/**
 * secure.h - Secure-memory utilities
 *
 * Three helpers for one lifecycle — "this memory is about to hold (or just held)
 * a secret":
 *
 *   - `secure_wipe`  - compiler-resistant zeroization of any buffer.
 *   - `secure_alloc` - a mapping of its own for a secret that outlives a call.
 *   - `secure_free`  - the end of that mapping: wiped, unlocked, unmapped.
 *
 * `secure_wipe` is the chokepoint for scrubbing secret-bearing memory across
 * non-crypto layers (base/, sys/, infra/, core/, cmds/). The crypto layer
 * (src/crypto/) calls monocypher's `crypto_wipe` directly — its primitives are
 * already in scope. Each layer cluster uses its native wipe; both implementations
 * are functionally identical doubly-volatile loops. Keeping `secure_wipe`
 * vendor-free is what lets non-crypto modules wipe secrets without dragging a
 * crypto dependency into layers below the crypto layer.
 *
 * `secure_alloc` / `secure_free` are the one home of every secret that lives
 * longer than the function that made it: the key manager's slot, a passphrase
 * between its read and its derivation, the Argon2 work area. Each secret gets
 * an anonymous private mapping of its own — page-aligned, zero-filled by the
 * kernel — locked against swap where the process may lock memory, and excluded
 * from core dumps where the platform can say so. One mapping per secret is what
 * makes the unlock exact: `munlock` is page-granular and does not stack, so two
 * secrets on one heap page would unlock each other when the first was freed.
 * Stack copies (a master between resolve and subkey derivation, a subkey pair,
 * a candidate plaintext) stay where they are and are wiped, not locked; the
 * plaintext the content cache holds is about to be a file on disk and is wiped,
 * not locked.
 *
 * The lock is best-effort, and the run has already asked for as much of it as
 * it may: sys/identity raises RLIMIT_MEMLOCK's soft limit to the hard one at
 * the prologue, and the hard one to infinity where the run holds root. What is
 * left is the platform's answer. Linux's default is the tight one — 8 MiB under
 * a modern systemd, 64 KiB on older kernels, and every Argon2 setting exceeds
 * both; macOS leaves the rlimit unlimited and wires against vm.user_wire_limit
 * instead. Where the process may not lock, the mapping still serves, unlocked,
 * and the process prints one advisory the first time a lock fails — one per
 * process, whichever secret hit the limit first, so the user never sees the same
 * line three times in one command.
 *
 * Implementation guarantee for `secure_wipe`: writes are not elided by dead-store
 * elimination or whole-program optimization. Implemented via a
 * doubly-volatile-pointer loop (`volatile unsigned char *volatile`) that hardens
 * against both per-write elision (the writes are volatile) and pointer-variable
 * elision (the pointer is volatile). `unsigned char` is the strict-aliasing-safe
 * access type per C11 §6.5p7, so this works for any buffer regardless of its
 * declared type.
 *
 * Out-of-line by design: the call appears in disassembly and lives at a single
 * machine-code address, which keeps the audit chokepoint legible. Cost is one
 * indirect call per scrub — negligible against the allocator and syscall work
 * that surrounds every secret-bearing lifecycle in this codebase.
 *
 * Use `secure_wipe` whenever a buffer that has held a secret (passphrase bytes,
 * derived keys, decrypted plaintext, credential helper output) is about to be
 * released to the allocator, reused, or otherwise stop being controlled. A plain
 * memset is forbidden for these buffers because the optimizer is permitted to
 * eliminate stores to memory that is freed or never read again.
 */

#ifndef DOTTA_SECURE_H
#define DOTTA_SECURE_H

#include <stddef.h>

/**
 * Securely zero `len` bytes at `ptr`.
 *
 * Writes are guaranteed to land in memory; the optimizer cannot drop them as
 * dead stores. Behavior matches a hand-rolled loop with `volatile` byte writes.
 *
 * NULL-safe: `ptr == NULL` is a no-op. Zero-length: `len == 0` is a no-op.
 *
 * Does not unlock or free; a secret in its own mapping ends with `secure_free`,
 * and a heap string that held a credential with `buffer_secure_free`.
 *
 * @param ptr Memory to wipe (may be NULL)
 * @param len Number of bytes to wipe (may be 0)
 */
void secure_wipe(void *ptr, size_t len);

/**
 * Map `len` bytes for a secret that outlives a call.
 *
 * An anonymous private mapping of its own: page-aligned (so it serves Argon2's
 * u64-aligned blocks as well as a 33-byte passphrase), zero-filled, locked against
 * swap best-effort (the one-time advisory on failure), and excluded from core
 * dumps where the platform has MADV_DONTDUMP. Released with `secure_free` and
 * nothing else — the pointer is not the allocator's.
 *
 * @param len Bytes to map (> 0)
 * @return The mapping, or NULL when the mapping fails (the caller reports
 *         ERR_MEMORY)
 */
void *secure_alloc(size_t len);

/**
 * End a `secure_alloc` mapping: wipe, unlock, unmap.
 *
 * `len` is the length the mapping was made with — the caller's cleanup length,
 * as `buffer_secure_free` takes it. NULL-safe.
 *
 * @param ptr The mapping (may be NULL)
 * @param len Its length
 */
void secure_free(void *ptr, size_t len);

#endif /* DOTTA_SECURE_H */
