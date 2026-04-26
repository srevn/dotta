/**
 * entropy.c - getentropy(3)-backed CSPRNG wrapper
 *
 * One backend on every supported platform. Larger requests loop
 * within the POSIX 2024 256-byte cap; EINTR is retried.
 */

#include "sys/entropy.h"

#include <errno.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "base/error.h"
#include "base/secure.h"

/* POSIX 2024 caps a single getentropy() call at 256 bytes; larger
 * requests loop. The one in-tree caller asks for 16 bytes — the loop
 * is kept so the function honestly serves any future caller without
 * a hidden size ceiling. */
#define ENTROPY_CHUNK_MAX 256

error_t *entropy_fill(uint8_t *out, size_t len) {
    if (len == 0) {
        return NULL;
    }
    if (out == NULL) {
        return ERROR(
            ERR_INVALID_ARG,
            "entropy_fill: output buffer cannot be NULL"
        );
    }

    size_t off = 0;
    while (off < len) {
        size_t chunk = (len - off > ENTROPY_CHUNK_MAX)
                       ? ENTROPY_CHUNK_MAX : (len - off);

        /* EINTR retry: getentropy is documented as not interruptible
         * by signals on macOS/FreeBSD; on Linux the underlying
         * getrandom(2) can return EINTR while the kernel CSPRNG is
         * still seeding. Either way, retry is the right response. */
        int rc;
        do {
            rc = getentropy(out + off, chunk);
        } while (rc != 0 && errno == EINTR);

        if (rc != 0) {
            int saved_errno = errno;
            /* Scrub partial output so callers get the "all valid or
             * all zero" contract documented in entropy.h. */
            secure_wipe(out, len);
            return ERROR(
                ERR_FS, "entropy_fill: failed after %zu of %zu bytes: %s",
                off, len, strerror(saved_errno)
            );
        }
        off += chunk;
    }

    return NULL;
}
