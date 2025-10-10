/**
 * buffer.h - Dynamic byte buffer utilities
 *
 * Provides a dynamic byte buffer for handling file contents.
 */

#ifndef DOTTA_BUFFER_H
#define DOTTA_BUFFER_H

#include "dotta/types.h"

/**
 * Create a new buffer
 *
 * @return Newly allocated buffer (must be freed with buffer_free)
 */
buffer_t *buffer_create(void);

/**
 * Create buffer with initial capacity
 *
 * @param capacity Initial capacity in bytes
 * @return Newly allocated buffer
 */
buffer_t *buffer_create_with_capacity(size_t capacity);

/**
 * Create buffer from existing data (copies data)
 *
 * @param data Data to copy
 * @param size Size of data in bytes
 * @return Newly allocated buffer
 */
buffer_t *buffer_create_from_data(const unsigned char *data, size_t size);

/**
 * Free buffer
 *
 * @param buf Buffer to free (can be NULL)
 */
void buffer_free(buffer_t *buf);

/**
 * Append data to buffer
 *
 * @param buf Buffer
 * @param data Data to append
 * @param size Size of data in bytes
 * @return Error or NULL on success
 */
dotta_error_t *buffer_append(buffer_t *buf, const unsigned char *data, size_t size);

/**
 * Append string to buffer (including null terminator)
 *
 * @param buf Buffer
 * @param str String to append
 * @return Error or NULL on success
 */
dotta_error_t *buffer_append_string(buffer_t *buf, const char *str);

/**
 * Clear buffer (reset size to 0, keep capacity)
 *
 * @param buf Buffer
 */
void buffer_clear(buffer_t *buf);

/**
 * Get buffer data
 *
 * @param buf Buffer
 * @return Pointer to data (valid until buffer is modified or freed)
 */
const unsigned char *buffer_data(const buffer_t *buf);

/**
 * Get buffer size
 *
 * @param buf Buffer
 * @return Size in bytes
 */
size_t buffer_size(const buffer_t *buf);

/**
 * Get buffer capacity
 *
 * @param buf Buffer
 * @return Capacity in bytes
 */
size_t buffer_capacity(const buffer_t *buf);

/**
 * Reserve buffer capacity
 *
 * Ensures buffer has at least the specified capacity.
 *
 * @param buf Buffer
 * @param capacity Desired capacity
 * @return Error or NULL on success
 */
dotta_error_t *buffer_reserve(buffer_t *buf, size_t capacity);

/**
 * RAII cleanup attribute helper
 */
static inline void cleanup_buffer(buffer_t **buf) {
    if (buf && *buf) {
        buffer_free(*buf);
        *buf = NULL;
    }
}

#define BUFFER_CLEANUP __attribute__((cleanup(cleanup_buffer)))

#endif /* DOTTA_BUFFER_H */
