/**
 * buffer.c - Dynamic byte buffer implementation
 *
 * Stack-allocable, always null-terminated when non-empty. The bytes are the heap's,
 * which dies rather than answer NULL (base/heap.h).
 */

#include "base/buffer.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "base/error.h"
#include "base/heap.h"
#include "base/secure.h"

#define MIN_CAPACITY 64

/**
 * Make room for `len` more content bytes, geometrically.
 *
 * The append path's allocator, and only that: an append does not know the final
 * size, so each growth has to buy headroom or N appends cost N reallocations. A
 * caller who does know the size wants buffer_reserve — no null check here because
 * both callers are append paths that have already made it.
 */
static void buffer_grow(buffer_t *buf, size_t len) {
    /* The content, the bytes after it and the terminator are one count, and one
     * no memory could hold is exhaustion. */
    if (len >= SIZE_MAX - buf->size) {
        heap_die(SIZE_MAX);
    }

    size_t needed = buf->size + len + 1;
    if (needed <= buf->capacity) {
        return;
    }

    /* Growth strategy: double from current or MIN_CAPACITY, whichever is larger.
     * A reserve leaves behind an exact capacity that is no power of anything;
     * doubling from there is still amortised, so the append path never has to
     * ask which policy sized the buffer it was handed. A doubling past SIZE_MAX
     * asks for what was needed, and the heap judges that. */
    size_t cap = buf->capacity ? buf->capacity : MIN_CAPACITY;
    while (cap < needed) {
        cap = cap > SIZE_MAX / 2 ? needed : cap * 2;
    }

    buf->data = heap_realloc(buf->data, cap);
    buf->capacity = cap;
    buf->data[buf->size] = '\0';
}

void buffer_reserve(buffer_t *buf, size_t alloc) {
    CHECK_NULL(buf);

    /* Account for null terminator. This byte is the whole cost of the invariant
     * when the allocation is exact; rounded up to the next power of two it is
     * the cost of a second buffer. A size the terminator would wrap is one no
     * memory could hold: exhaustion. */
    if (alloc == SIZE_MAX) {
        heap_die(SIZE_MAX);
    }

    size_t needed = alloc + 1;
    if (needed <= buf->capacity) {
        return;
    }

    buf->data = heap_realloc(buf->data, needed);
    buf->capacity = needed;

    /* Restore the invariant at the new address. In bounds either way: a buffer
     * that held nothing has size 0 and at least one byte now, and one that held
     * something had size < old capacity < needed. */
    buf->data[buf->size] = '\0';
}

void buffer_resize(buffer_t *buf, size_t size) {
    CHECK_NULL(buf);

    buffer_reserve(buf, size);
    buf->size = size;
    buf->data[size] = '\0';
}

void buffer_deinit(buffer_t *buf) {
    if (!buf) {
        return;
    }
    free(buf->data);
    *buf = (buffer_t){ 0 };
}

buffer_t *buffer_create(size_t capacity) {
    buffer_t *buf = heap_calloc(1, sizeof(*buf));

    if (capacity > 0) {
        buffer_reserve(buf, capacity);
    }

    return buf;
}

void buffer_free(void *ptr) {
    buffer_t *buf = ptr;
    if (!buf) {
        return;
    }
    free(buf->data);
    free(buf);
}

void buffer_append(buffer_t *buf, const void *data, size_t len) {
    CHECK_NULL(buf);

    if (len == 0) {
        return;
    }
    CHECK_NULL(data);

    /* Save offset if data points into this buffer */
    const char *src = data;
    size_t src_offset = 0;
    bool self_ref = buf->data && src >= buf->data
        && src < buf->data + buf->capacity;
    if (self_ref) {
        src_offset = (size_t) (src - buf->data);
    }

    buffer_grow(buf, len);

    if (self_ref) {
        src = buf->data + src_offset;
    }

    memmove(buf->data + buf->size, src, len);
    buf->size += len;
    buf->data[buf->size] = '\0';
}

void buffer_append_string(buffer_t *buf, const char *str) {
    CHECK_NULL(str);

    buffer_append(buf, str, strlen(str));
}

void buffer_appendf(buffer_t *buf, const char *fmt, ...) {
    CHECK_NULL(buf);
    CHECK_NULL(fmt);

    va_list args;
    va_start(args, fmt);

    /* Measure required size. The format is its writer's: one that cannot be
     * formatted is a caller's bug. */
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);
    CHECK_ARG(len >= 0, "fmt cannot be formatted");

    buffer_grow(buf, (size_t) len);

    /* Format directly into buffer */
    vsnprintf(
        buf->data + buf->size,
        (size_t) len + 1, fmt, args
    );
    buf->size += (size_t) len;

    va_end(args);
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
        return heap_strdup("");
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
