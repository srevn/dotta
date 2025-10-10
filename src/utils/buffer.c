/**
 * buffer.c - Dynamic byte buffer implementation
 */

#include "buffer.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"

#define INITIAL_CAPACITY 4096

buffer_t *buffer_create(void) {
    return buffer_create_with_capacity(INITIAL_CAPACITY);
}

buffer_t *buffer_create_with_capacity(size_t capacity) {
    buffer_t *buf = calloc(1, sizeof(buffer_t));
    if (!buf) {
        return NULL;
    }

    if (capacity > 0) {
        buf->data = malloc(capacity);
        if (!buf->data) {
            free(buf);
            return NULL;
        }
        buf->capacity = capacity;
    }

    buf->size = 0;
    return buf;
}

buffer_t *buffer_create_from_data(const unsigned char *data, size_t size) {
    if (!data || size == 0) {
        return buffer_create();
    }

    buffer_t *buf = buffer_create_with_capacity(size);
    if (!buf) {
        return NULL;
    }

    memcpy(buf->data, data, size);
    buf->size = size;

    return buf;
}

void buffer_free(buffer_t *buf) {
    if (!buf) {
        return;
    }

    free(buf->data);
    free(buf);
}

dotta_error_t *buffer_reserve(buffer_t *buf, size_t capacity) {
    CHECK_NULL(buf);

    if (capacity <= buf->capacity) {
        return NULL;  /* Already have enough capacity */
    }

    unsigned char *new_data = realloc(buf->data, capacity);
    if (!new_data) {
        return error_create(DOTTA_ERR_MEMORY, "Failed to grow buffer");
    }

    buf->data = new_data;
    buf->capacity = capacity;

    return NULL;
}

dotta_error_t *buffer_append(buffer_t *buf, const unsigned char *data, size_t size) {
    CHECK_NULL(buf);
    CHECK_NULL(data);

    if (size == 0) {
        return NULL;
    }

    /* Ensure capacity */
    size_t required = buf->size + size;
    if (required > buf->capacity) {
        size_t new_capacity = buf->capacity == 0 ? INITIAL_CAPACITY : buf->capacity;
        while (new_capacity < required) {
            new_capacity *= 2;
        }

        dotta_error_t *err = buffer_reserve(buf, new_capacity);
        if (err) {
            return err;
        }
    }

    memcpy(buf->data + buf->size, data, size);
    buf->size += size;

    return NULL;
}

dotta_error_t *buffer_append_string(buffer_t *buf, const char *str) {
    CHECK_NULL(buf);
    CHECK_NULL(str);

    size_t len = strlen(str);  /* Don't include null terminator in buffer */
    return buffer_append(buf, (const unsigned char *)str, len);
}

void buffer_clear(buffer_t *buf) {
    if (!buf) {
        return;
    }
    buf->size = 0;
}

const unsigned char *buffer_data(const buffer_t *buf) {
    if (!buf) {
        return NULL;
    }
    return buf->data;
}

size_t buffer_size(const buffer_t *buf) {
    if (!buf) {
        return 0;
    }
    return buf->size;
}

size_t buffer_capacity(const buffer_t *buf) {
    if (!buf) {
        return 0;
    }
    return buf->capacity;
}
