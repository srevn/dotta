/**
 * secure.c - Secure-memory utilities
 *
 * `secure_wipe` — the doubly-volatile-pointer loop is the canonical
 * portable idiom for defeating dead-store elimination. Two layers of
 * `volatile` carry distinct guarantees:
 *
 *   1. `volatile unsigned char *` qualifies the bytes being written.
 *      Per C11 §6.7.3p7, accesses through volatile-qualified lvalues
 *      are observable side effects that the compiler cannot elide,
 *      so the zeroing stores are guaranteed to reach memory even
 *      when the buffer is free()'d immediately afterwards.
 *
 *   2. `* volatile p` qualifies the pointer variable itself. This
 *      prevents an aggressive interprocedural pass from caching the
 *      pointer in a register and reasoning that the loop's effects
 *      are unobservable in the caller's frame, removing the call
 *      wholesale. Belt-and-suspenders relative to (1).
 *
 * The access type is `unsigned char *`, not `uint8_t *`: C11 §6.5p7
 * (the strict-aliasing exception) names `unsigned char` — and the
 * other character types — as the access types that can legitimately
 * read or write any object's bytes regardless of its declared type.
 * `uint8_t` is typically a typedef for `unsigned char` on POSIX
 * targets but the standard does not guarantee it; for a primitive
 * whose only job is to defeat the optimizer we use the type the
 * standard explicitly authorizes.
 *
 * The same pattern (with minor variations) is used by:
 *   - monocypher's crypto_wipe
 *   - libsodium's sodium_memzero fallback path
 *   - OpenBSD's explicit_bzero portable fallback
 *
 * No `#ifdef HAVE_EXPLICIT_BZERO` cascade is used: macOS does not
 * provide `explicit_bzero`, so the conditional adds noise while
 * giving up the single-implementation auditability for one of the
 * three target platforms.  The volatile loop is already as strong
 * as `explicit_bzero`'s portable backstop.
 *
 * No GCC/Clang asm memory barrier is used: the C11 volatile
 * semantics are sufficient on every conforming compiler.  If a real
 * compiler ever elides volatile writes, that is a bug to file
 * upstream, not a workaround to bake into every wipe call.
 *
 * `secure_mlock_warn` — single chokepoint for the "we tried to
 * pin secret-bearing pages and the kernel said no" advisory. Three
 * subsystems (kdf, keymgr, sys/passphrase) hit `mlock` and may fail
 * on macOS's default 64 KiB RLIMIT_MEMLOCK. The first failure prints;
 * subsequent failures within the same process are silent. The format
 * is uniform across call sites so the remediation tail is identical
 * regardless of which subsystem fired first.
 */

#include "base/secure.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

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

void secure_mlock_warn(int saved_errno, const char *fmt, ...) {
    /* Process-wide gate. Single-threaded, so plain `bool` suffices —
     * no atomic load/store needed. The first call fires; all later
     * calls return early. */
    static bool warned = false;
    if (warned) {
        return;
    }
    warned = true;

    /* Two-step format so the description (caller-supplied) is bracketed
     * by the canonical "Warning: Failed to lock " prefix and the
     * standard remediation tail. Every advisory in dotta therefore
     * shares the same shape — only the middle clause varies. */
    fputs("Warning: Failed to lock ", stderr);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(
        stderr,
        ": %s\n"
        "         Sensitive material may be paged to disk.\n"
        "         Raise RLIMIT_MEMLOCK (ulimit -l) or run with elevated\n"
        "         privileges to enable this protection.\n",
        strerror(saved_errno)
    );
}
