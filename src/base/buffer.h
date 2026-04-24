/**
 * buffer.h - Dynamic byte buffer (stack-allocable, null-terminated)
 *
 * Invariants:
 *   - When data is non-NULL: data[size] == '\0' (always a valid C string)
 *   - When data is NULL: size == 0 && capacity == 0 (zero-initialized state)
 *   - buffer_free() resets to zero state; safe to call multiple times
 *
 * Stack usage (common):
 *   buffer_t buf = BUFFER_INIT;
 *   buffer_append_string(&buf, "hello");
 *   printf("%s\n", buf.data);   // direct access, always null-terminated
 *   buffer_free(&buf);
 *
 * Heap usage (for caches/collections):
 *   buffer_t *buf = buffer_new(0);
 *   buffer_append_string(buf, "hello");
 *   buffer_destroy(buf);        // frees data + struct
 */

#ifndef DOTTA_BUFFER_H
#define DOTTA_BUFFER_H

#include <types.h>

/** Zero-initializer for stack-allocated buffers */
#define BUFFER_INIT {0}

/**
 * Free buffer data and reset to zero state
 *
 * After this call, buf is equivalent to BUFFER_INIT.
 * Safe to call on zero-initialized or already-freed buffers.
 *
 * @param buf Buffer (can be NULL)
 */
void buffer_free(buffer_t *buf);

/**
 * Heap-allocate a buffer (for caches and collections)
 *
 * @param capacity Initial capacity in content bytes (0 for empty)
 * @return Heap-allocated buffer, or NULL on failure
 */
buffer_t *buffer_new(size_t capacity);

/**
 * Free buffer data and the struct itself
 *
 * Accepts void* for hashmap_free() compatibility.
 *
 * @param buf Buffer to destroy (can be NULL)
 */
void buffer_destroy(void *ptr);

/**
 * Ensure buffer can hold at least alloc content bytes
 *
 * Allocates alloc+1 bytes internally (for null terminator).
 * No-op if capacity is already sufficient.
 *
 * @param buf Buffer (must not be NULL)
 * @param alloc Minimum content bytes the buffer must accommodate
 * @return Error or NULL on success
 */
error_t *buffer_grow(buffer_t *buf, size_t alloc);

/**
 * Append raw bytes to buffer
 *
 * @param buf  Buffer (must not be NULL)
 * @param data Data to append (must not be NULL when len > 0)
 * @param len  Number of bytes to append
 * @return Error or NULL on success
 */
error_t *buffer_append(buffer_t *buf, const void *data, size_t len);

/**
 * Append a null-terminated string (excluding its terminator)
 *
 * @param buf Buffer (must not be NULL)
 * @param str String to append (must not be NULL)
 * @return Error or NULL on success
 */
error_t *buffer_append_string(buffer_t *buf, const char *str);

/**
 * Append a formatted string
 *
 * @param buf Buffer (must not be NULL)
 * @param fmt Format string
 * @return Error or NULL on success
 */
error_t *buffer_appendf(buffer_t *buf, const char *fmt, ...)
__attribute__((format(printf, 2, 3)));

/**
 * Reset size to 0 without freeing memory
 *
 * @param buf Buffer (can be NULL)
 */
void buffer_clear(buffer_t *buf);

/**
 * Securely free a secret-bearing heap allocation
 *
 * Runs the mandatory cleanup sequence for buffers that hold passphrases,
 * encryption keys, or other sensitive bytes:
 *
 *   1. hydro_memzero(ptr, len)   — wipe while still mlock'd, resistant
 *                                  to dead-store elimination
 *   2. munlock(ptr, len)         — release any best-effort mlock
 *                                  (safe to call on never-locked
 *                                  memory; the error is ignored)
 *   3. free(ptr)                 — release the allocation
 *
 * Zeroing before munlock ensures the clearing is committed to physical
 * memory before the page becomes swap-eligible; inverting the order
 * widens the (small) window where the kernel could page out pre-zero
 * bytes. Callers MUST NOT inline this sequence themselves — the single
 * form prevents mis-ordering and mis-sized zeroization from spreading
 * through hand-copied three-liners.
 *
 * Does not take a `buffer_t*`: secret allocations in this codebase are
 * right-sized `char*` passphrases and `uint8_t*` key buffers; pairing
 * pointer and length keeps the interface concern-free of buffer_t
 * internals.
 *
 * Preconditions:
 *   - `ptr` was obtained from a malloc-family allocator (or is NULL)
 *   - `len` is the exact allocated byte count that was also the mlock
 *     extent. A length mismatch either leaks tail bytes (short zero)
 *     or munlocks pages outside this allocation.
 *
 * NULL-safe: `ptr == NULL` is a no-op.
 * Zero-length: `len == 0` is legal; zero and munlock become no-ops,
 * `free` still runs.
 */
void buffer_secure_free(void *ptr, size_t len);

/**
 * Transfer ownership of buffer data to caller
 *
 * Returns the internal data pointer (already null-terminated) and resets
 * the buffer to zero state. Caller must free() the returned pointer.
 * Returns strdup("") for empty/uninitialized buffers.
 *
 * @param buf Buffer (reset to BUFFER_INIT after call)
 * @return Null-terminated string (caller must free), or NULL on allocation failure
 */
char *buffer_detach(buffer_t *buf);

/** Cleanup function for __attribute__((cleanup)) on stack-allocated buffers */
static inline void buffer_cleanup_fn(buffer_t *buf) {
    buffer_free(buf);
}

/** RAII attribute: automatically frees buffer data when variable goes out of scope */
#define BUFFER_CLEANUP __attribute__((cleanup(buffer_cleanup_fn)))

#endif /* DOTTA_BUFFER_H */
