/**
 * buffer.c - Dynamic byte buffer implementation
 *
 * Stack-allocable, always null-terminated when non-empty.
 */

#include "base/buffer.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "base/error.h"
#include "base/secure.h"

#define MIN_CAPACITY 64

/**
 * Make room for at least alloc content bytes, geometrically.
 *
 * The append path's allocator, and only that: an append does not know the final
 * size, so each growth has to buy headroom or N appends cost N reallocations. A
 * caller who does know the size wants buffer_reserve — no null check here because
 * both callers are append paths that have already made it.
 */
static error_t *buffer_grow(buffer_t *buf, size_t alloc) {
    /* Account for null terminator */
    size_t needed = alloc + 1;
    if (needed == 0) {
        return ERROR(
            ERR_MEMORY,
            "Buffer capacity overflow"
        );
    }

    if (needed <= buf->capacity) {
        return NULL;
    }

    /* Growth strategy: double from current or MIN_CAPACITY, whichever is larger.
     * A reserve leaves behind an exact capacity that is no power of anything;
     * doubling from there is still amortised, so the append path never has to
     * ask which policy sized the buffer it was handed. */
    size_t cap = buf->capacity ? buf->capacity : MIN_CAPACITY;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2) {
            return ERROR(
                ERR_MEMORY,
                "Buffer capacity overflow"
            );
        }
        cap *= 2;
    }

    char *new_data = realloc(buf->data, cap);
    if (!new_data) {
        return ERROR(
            ERR_MEMORY,
            "Failed to grow buffer to %zu bytes", cap
        );
    }

    buf->data = new_data;
    buf->capacity = cap;
    buf->data[buf->size] = '\0';

    return NULL;
}

error_t *buffer_reserve(buffer_t *buf, size_t alloc) {
    CHECK_NULL(buf);

    /* Account for null terminator. This byte is the whole cost of the invariant
     * when the allocation is exact; rounded up to the next power of two it is
     * the cost of a second buffer. */
    size_t needed = alloc + 1;
    if (needed == 0) {
        return ERROR(
            ERR_MEMORY,
            "Buffer capacity overflow"
        );
    }

    if (needed <= buf->capacity) {
        return NULL;
    }

    char *new_data = realloc(buf->data, needed);
    if (!new_data) {
        return ERROR(
            ERR_MEMORY,
            "Failed to reserve %zu bytes for buffer", needed
        );
    }

    buf->data = new_data;
    buf->capacity = needed;

    /* Restore the invariant at the new address. In bounds either way: a buffer
     * that held nothing has size 0 and at least one byte now, and one that held
     * something had size < old capacity < needed. */
    buf->data[buf->size] = '\0';

    return NULL;
}

error_t *buffer_resize(buffer_t *buf, size_t size) {
    CHECK_NULL(buf);

    /* Reserve first: a refusal must leave the buffer holding exactly what it
     * held, not a size pointing past its allocation. */
    error_t *err = buffer_reserve(buf, size);
    if (err) {
        return err;
    }

    buf->size = size;
    buf->data[size] = '\0';

    return NULL;
}

void buffer_free(buffer_t *buf) {
    if (!buf) {
        return;
    }
    free(buf->data);
    *buf = (buffer_t){ 0 };
}

buffer_t *buffer_new(size_t capacity) {
    buffer_t *buf = calloc(1, sizeof(*buf));
    if (!buf) {
        return NULL;
    }

    if (capacity > 0) {
        error_t *err = buffer_reserve(buf, capacity);
        if (err) {
            error_free(err);
            free(buf);
            return NULL;
        }
    }

    return buf;
}

void buffer_destroy(void *ptr) {
    buffer_t *buf = ptr;
    if (!buf) {
        return;
    }
    free(buf->data);
    free(buf);
}

error_t *buffer_append(buffer_t *buf, const void *data, size_t len) {
    CHECK_NULL(buf);

    if (len == 0) {
        return NULL;
    }
    CHECK_NULL(data);

    /* Overflow check */
    size_t new_size = buf->size + len;
    if (new_size < buf->size) {
        return ERROR(
            ERR_MEMORY,
            "Buffer size overflow"
        );
    }

    /* Save offset if data points into this buffer */
    const char *src = data;
    size_t src_offset = 0;
    bool self_ref = buf->data && src >= buf->data
        && src < buf->data + buf->capacity;
    if (self_ref) {
        src_offset = (size_t) (src - buf->data);
    }

    error_t *err = buffer_grow(buf, new_size);
    if (err) {
        return err;
    }

    if (self_ref) {
        src = buf->data + src_offset;
    }

    memmove(buf->data + buf->size, src, len);
    buf->size = new_size;
    buf->data[buf->size] = '\0';

    return NULL;
}

error_t *buffer_append_string(buffer_t *buf, const char *str) {
    CHECK_NULL(str);

    return buffer_append(buf, str, strlen(str));
}

error_t *buffer_appendf(buffer_t *buf, const char *fmt, ...) {
    CHECK_NULL(buf);
    CHECK_NULL(fmt);

    va_list args;
    va_start(args, fmt);

    /* Measure required size */
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    if (len < 0) {
        va_end(args);
        return ERROR(
            ERR_INVALID_ARG,
            "Invalid format string"
        );
    }

    /* Overflow check */
    size_t new_size = buf->size + (size_t) len;
    if (new_size < buf->size) {
        va_end(args);
        return ERROR(
            ERR_MEMORY,
            "Buffer size overflow"
        );
    }

    error_t *err = buffer_grow(buf, new_size);
    if (err) {
        va_end(args);
        return err;
    }

    /* Format directly into buffer */
    vsnprintf(
        buf->data + buf->size,
        (size_t) len + 1, fmt, args
    );
    buf->size = new_size;

    va_end(args);
    return NULL;
}

void buffer_clear(buffer_t *buf) {
    if (!buf) {
        return;
    }
    buf->size = 0;
    if (buf->data) {
        buf->data[0] = '\0';
    }
}

char *buffer_detach(buffer_t *buf) {
    if (!buf || !buf->data) {
        if (buf) {
            *buf = (buffer_t){ 0 };
        }
        char *empty = malloc(1);
        if (empty) {
            empty[0] = '\0';
        }
        return empty;
    }

    /* data is already null-terminated by invariant */
    char *data = buf->data;
    *buf = (buffer_t){ 0 };

    return data;
}

void buffer_secure_free(void *ptr, size_t len) {
    if (!ptr) {
        return;
    }

    /* Zero before unlock: the wipe must land in physical memory before the page
     * becomes swap-eligible. secure_wipe resists dead-store elimination
     * (free-immediately-after would otherwise let the optimizer delete the
     * zeroization). */
    secure_wipe(ptr, len);

    /* Unlock is best-effort. Calling munlock on memory that was never mlock'd
     * (mlock may have failed at allocation time for want of RLIMIT_MEMLOCK) returns
     * an error we explicitly ignore — there is no recovery and no remaining
     * user-visible behavior at this point in the cleanup. */
    (void) munlock(ptr, len);

    free(ptr);
}
