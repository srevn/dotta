/**
 * buffer.h - Dynamic byte buffer (stack-allocable, null-terminated)
 *
 * Invariants:
 *   - When data is non-NULL: data[size] == '\0' (always a valid C string)
 *   - When data is NULL: size == 0 && capacity == 0 (zero-initialized state)
 *   - buffer_deinit() resets to zero state; safe to call multiple times
 *
 * A buffer's bytes are the heap's, so room cannot fail: every append, reserve
 * and resize succeeds or the run dies of exhaustion (base/heap.h), and none of
 * them answers anything. A size no memory could hold — a length that wraps the
 * content it would follow — is exhaustion too.
 *
 * Sizing — a buffer is made room for in one of two ways, and they are not the
 * same operation:
 *   append / appendf          the size is discovered as you go, so room is found
 *                             geometrically; N appends cost O(N)
 *   buffer_reserve(&buf, n)   the size is known, so room for n bytes is
 *                             allocated exactly
 *   buffer_resize(&buf, n)    the size is known and the bytes are the caller's
 *                             to write: n bytes of content, uninitialised
 *
 * Reserving is not a growth step and does not round up: doubling a number the
 * caller already knows is waste, and for a payload that is itself a power of
 * two — a 4 KiB, 1 MiB or 64 MiB file — it is a doubling of the whole allocation.
 *
 * Out parameters — a buffer_t a function fills on its caller's behalf is written,
 * never read. The callee clears the struct once the arguments are accepted, so
 * what the caller passed in is neither read nor freed by it: callers pass
 * BUFFER_INIT or a buffer they have already freed, since one still holding bytes
 * has them dropped rather than released.
 *
 * On success the caller owns the bytes. On failure it owns whatever the callee
 * left there — usually nothing, but a callee may fail after writing, and what
 * it wrote reaches the caller's free: a secret written before a failure must
 * reach the caller's wiping free rather than a plain one. So freeing an out buffer
 * is correct and sufficient either way; reading one after a failure is neither.
 *
 * Stack usage (common):
 *   buffer_t buf = BUFFER_INIT;
 *   buffer_append_string(&buf, "hello");
 *   printf("%s\n", buf.data);   // direct access, always null-terminated
 *   buffer_deinit(&buf);
 *
 * Heap usage (for caches/collections):
 *   buffer_t *buf = buffer_create(0);
 *   buffer_append_string(buf, "hello");
 *   buffer_free(buf);           // frees data + struct
 */

#ifndef DOTTA_BUFFER_H
#define DOTTA_BUFFER_H

#include <types.h>

/** Zero-initializer for stack-allocated buffers */
#define BUFFER_INIT {0}

/**
 * Free buffer data and reset to zero state
 *
 * After this call, buf is equivalent to BUFFER_INIT. Safe to call on
 * zero-initialized or already-released buffers.
 *
 * @param buf Buffer (can be NULL)
 */
void buffer_deinit(buffer_t *buf);

/**
 * Heap-allocate a buffer (for caches and collections)
 *
 * @param capacity Content bytes to reserve, read as buffer_reserve reads it (0
 *                 allocates nothing)
 * @return Heap-allocated buffer; never NULL
 */
buffer_t *buffer_create(size_t capacity);

/**
 * Free buffer data and the struct itself
 *
 * @param buf Buffer to free (can be NULL)
 */
void buffer_free(buffer_t *buf);

/**
 * Reserve room for alloc content bytes, allocated exactly
 *
 * For a caller that already knows the final size. Allocates exactly alloc+1 bytes
 * — the content plus the terminator the invariant costs — and no more: the
 * geometric growth the append path needs exists to amortise a size nobody knew,
 * and applying it to a size somebody did know only doubles the bill.
 *
 * A no-op when the capacity already suffices, so it never shrinks a buffer. The
 * content is untouched: size stays where it was and the terminator moves with
 * the allocation.
 *
 * A buffer left at an exact capacity still appends correctly — the append path
 * grows geometrically from wherever it finds itself, so the two policies compose.
 *
 * @param buf Buffer (must not be NULL)
 * @param alloc Content bytes the buffer must accommodate
 */
void buffer_reserve(buffer_t *buf, size_t alloc);

/**
 * Claim size content bytes for the caller to write
 *
 * Reserves exactly that much, declares it the buffer's content, and restores
 * the terminator at the new end. For a caller that computes its output's layout
 * up front and writes into the slots directly — the alternative is setting `size`
 * by hand and re-terminating at the call site, which is this type's invariant
 * maintained outside the only file that owns it.
 *
 * The claimed bytes are UNINITIALISED. Everything from the old size to the new
 * one holds whatever the allocator last left there, and the caller is expected
 * to write all of it.
 *
 * Shrinking is truncation: the content past the new size is dropped but not
 * cleared, exactly as buffer_clear drops all of it without clearing. A buffer
 * that held secrets is wiped by its owner (base/secure.h secure_wipe), never by
 * this call.
 *
 * @param buf Buffer (must not be NULL)
 * @param size Content bytes the buffer is to hold
 */
void buffer_resize(buffer_t *buf, size_t size);

/**
 * Append raw bytes to buffer
 *
 * @param buf  Buffer (must not be NULL)
 * @param data Data to append (must not be NULL when len > 0)
 * @param len  Number of bytes to append
 */
void buffer_append(buffer_t *buf, const void *data, size_t len);

/**
 * Append a null-terminated string (excluding its terminator)
 *
 * @param buf Buffer (must not be NULL)
 * @param str String to append (must not be NULL)
 */
void buffer_append_string(buffer_t *buf, const char *str);

/**
 * Append a formatted string
 *
 * The format is its writer's, so one that cannot be formatted is a caller's bug.
 *
 * @param buf Buffer (must not be NULL)
 * @param fmt Format string
 */
void buffer_appendf(buffer_t *buf, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Reset size to 0 without freeing memory
 *
 * @param buf Buffer (can be NULL)
 */
void buffer_clear(buffer_t *buf);

/**
 * Transfer ownership of buffer data to caller
 *
 * Returns the internal data pointer (already null-terminated) and resets the
 * buffer to zero state. Caller must free() the returned pointer. Returns a fresh
 * "" for empty/uninitialized buffers.
 *
 * @param buf Buffer (reset to BUFFER_INIT after call)
 * @return Null-terminated string (caller must free); never NULL
 */
char *buffer_detach(buffer_t *buf);

/** Cleanup function for __attribute__((cleanup)) on stack-allocated buffers */
static inline void buffer_cleanup_fn(buffer_t *buf) {
    buffer_deinit(buf);
}

/** RAII attribute: automatically frees buffer data when variable goes out of scope */
#define BUFFER_CLEANUP __attribute__((cleanup(buffer_cleanup_fn)))

#endif /* DOTTA_BUFFER_H */
