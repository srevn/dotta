/**
 * secure.c - Secure-memory utilities
 *
 * `secure_wipe` — volatile bytes through a plain pointer, the canonical portable
 * idiom for defeating dead-store elimination. Each zero is stored through an
 * lvalue of volatile-qualified type, which is a volatile access: a side effect
 * evaluated strictly according to the abstract machine's rules, which no
 * implementation may drop because the buffer is freed or never read again (C23
 * §5.1.2.3 p2 and p6, DR 476's resolution of what C11 §6.7.3p7 left to the
 * implementation). The stores reach memory even when the buffer is free()'d
 * immediately afterwards. A volatile pointer as well would guarantee nothing
 * more, at a load and a store of the pointer for every byte.
 *
 * The access type is `unsigned char *`, not `uint8_t *`: C11 §6.5p7 (the
 * strict-aliasing exception) names `unsigned char` — and the other character
 * types — as the access types that can legitimately read or write any object's
 * bytes regardless of its declared type. `uint8_t` is typically a typedef for
 * `unsigned char` on POSIX targets but the standard does not guarantee it; for
 * a primitive whose only job is to defeat the optimizer we use the type the
 * standard explicitly authorizes.
 *
 * The same loop, exactly, is monocypher's crypto_wipe, so the tree's two wipes
 * are one; variations of it are libsodium's sodium_memzero fallback path and
 * OpenBSD's explicit_bzero portable fallback.
 *
 * No `#ifdef HAVE_EXPLICIT_BZERO` cascade is used: macOS does not provide
 * `explicit_bzero`, so the conditional adds noise while giving up the
 * single-implementation auditability for one of the
 * three target platforms.  The volatile loop is already as strong
 * as `explicit_bzero`'s portable backstop.
 *
 * No GCC/Clang asm memory barrier is used: the volatile access is the guarantee,
 * on every conforming compiler. If a real compiler ever elides volatile writes,
 * that is a bug to file upstream, not a workaround to bake into every wipe call.
 *
 * `secure_alloc` / `secure_free` — one anonymous mapping per secret. The wipe
 * before the unmap is the one the spec can state; the kernel zeroes an anonymous
 * page before it is handed out again regardless, so for a mapping the wipe costs
 * one pass over the bytes and buys the sentence. The lock is where the pages
 * are protected from swap, and the advisory below is the one place the process
 * says it could not lock: the first failure prints, every later one is silent.
 *
 * `secure_free_string` — the heap's end for a string that held a secret: every
 * lock is a mapping's, so there is none to release, and the wipe and the free
 * are the whole of it.
 */

#include "base/secure.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void secure_wipe(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *) ptr;
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
 * bool`): one thread maps secrets, and the key derivation's threads compute into
 * a mapping their caller made (crypto/kdf.c).
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

void secure_free_string(char *str) {
    if (!str) {
        return;
    }

    secure_wipe(str, strlen(str) + 1);
    free(str);
}
