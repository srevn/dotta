/**
 * secure.c - Secure-memory utilities
 *
 * `secure_wipe` — the doubly-volatile-pointer loop is the canonical portable
 * idiom for defeating dead-store elimination. Two layers of `volatile` carry
 * distinct guarantees:
 *
 *   1. `volatile unsigned char *` qualifies the bytes being written. Per C11
 *      §6.7.3p7, accesses through volatile-qualified lvalues are observable side
 *      effects that the compiler cannot elide, so the zeroing stores are guaranteed
 *      to reach memory even when the buffer is free()'d immediately afterwards.
 *
 *   2. `* volatile p` qualifies the pointer variable itself. This prevents an
 *      aggressive interprocedural pass from caching the pointer in a register
 *      and reasoning that the loop's effects are unobservable in the caller's
 *      frame, removing the call wholesale. Belt-and-suspenders relative to (1).
 *
 * The access type is `unsigned char *`, not `uint8_t *`: C11 §6.5p7 (the
 * strict-aliasing exception) names `unsigned char` — and the other character
 * types — as the access types that can legitimately read or write any object's
 * bytes regardless of its declared type. `uint8_t` is typically a typedef for
 * `unsigned char` on POSIX targets but the standard does not guarantee it; for
 * a primitive whose only job is to defeat the optimizer we use the type the
 * standard explicitly authorizes.
 *
 * The same pattern (with minor variations) is used by:
 *   - monocypher's crypto_wipe
 *   - libsodium's sodium_memzero fallback path
 *   - OpenBSD's explicit_bzero portable fallback
 *
 * No `#ifdef HAVE_EXPLICIT_BZERO` cascade is used: macOS does not provide
 * `explicit_bzero`, so the conditional adds noise while giving up the
 * single-implementation auditability for one of the
 * three target platforms.  The volatile loop is already as strong
 * as `explicit_bzero`'s portable backstop.
 *
 * No GCC/Clang asm memory barrier is used: the C11 volatile
 * semantics are sufficient on every conforming compiler.  If a real
 * compiler ever elides volatile writes, that is a bug to file upstream, not a
 * workaround to bake into every wipe call.
 *
 * `secure_alloc` / `secure_free` — one anonymous mapping per secret. The wipe
 * before the unmap is the one the spec can state; the kernel zeroes an anonymous
 * page before it is handed out again regardless, so for a mapping the wipe costs
 * one pass over the bytes and buys the sentence. The lock is where the pages
 * are protected from swap, and the advisory below is the one place the process
 * says it could not lock: the first failure prints, every later one is silent.
 */

#include "base/secure.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

void secure_wipe(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    volatile unsigned char *volatile p =
        (volatile unsigned char *volatile) ptr;
    while (len--) {
        *p++ = 0;
    }
}

/**
 * One-time-per-process advisory that a lock failed.
 *
 * What failed and what it costs, and no remedy. The prologue already raised
 * RLIMIT_MEMLOCK as far as this run may (sys/identity), so the knob that is left
 * is the system's hard limit — limits.conf, a systemd unit, launchd, or nothing
 * at all on a platform that wires against something else — and which one it is
 * cannot be told from here. On Linux every non-trivial Argon2 setting exceeds
 * the default, which makes failure the common case on a default-configured system.
 * The process-wide gate keeps it to one line. Not thread-safe (a plain `static
 * bool`); dotta is single-threaded.
 */
static void mlock_warn(int saved_errno, size_t len) {
    static bool warned = false;
    if (warned) {
        return;
    }
    warned = true;

    fprintf(
        stderr,
        "Warning: Failed to lock %zu bytes of secret-bearing memory: %s\n"
        "         Sensitive material may be paged to disk.\n",
        len, strerror(saved_errno)
    );
}

void *secure_alloc(size_t len) {
    void *ptr = mmap(
        NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    );
    if (ptr == MAP_FAILED) {
        return NULL;
    }

    if (mlock(ptr, len) != 0) {
        mlock_warn(errno, len);
    }

    #ifdef MADV_DONTDUMP
    /* Belt to the core limit's braces (sys/identity zeroes RLIMIT_CORE): where
     * the kernel can be told, the pages never enter a dump at all. Advisory; a
     * refusal changes nothing. */
    (void) madvise(ptr, len, MADV_DONTDUMP);
    #endif

    return ptr;
}

void secure_free(void *ptr, size_t len) {
    if (!ptr) {
        return;
    }

    secure_wipe(ptr, len);

    /* Unlock before unmap, and best-effort: a range the lock refused is not locked,
     * and munlock on it is a no-op the kernel answers with success or a code
     * nothing here can act on. */
    (void) munlock(ptr, len);
    (void) munmap(ptr, len);
}
