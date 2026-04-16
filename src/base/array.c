/**
 * array.c - Dynamic string array implementation
 */

#include "base/array.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"

#define DEFAULT_CAP 8

/* === string_array_t — owned-string dynamic array === */

/* --- Lifecycle (stack / embedded) --- */

void string_array_init(string_array_t *arr) {
    *arr = (string_array_t){ 0 };
}

error_t *string_array_init_cap(string_array_t *arr, size_t cap) {
    CHECK_NULL(arr);

    *arr = (string_array_t){ 0 };

    if (cap == 0) {
        return NULL;
    }

    if (cap > SIZE_MAX / sizeof(char *)) {
        return ERROR(
            ERR_MEMORY,
            "Array capacity overflow"
        );
    }

    arr->items = malloc(cap * sizeof(char *));
    if (!arr->items) {
        return ERROR(
            ERR_MEMORY,
            "Failed to allocate array"
        );
    }
    arr->capacity = cap;

    return NULL;
}

void string_array_deinit(string_array_t *arr) {
    if (!arr) {
        return;
    }

    for (size_t i = 0; i < arr->count; i++) {
        free(arr->items[i]);
    }
    free(arr->items);

    *arr = (string_array_t){ 0 };
}

/* --- Lifecycle (heap) --- */

string_array_t *string_array_new(size_t cap) {
    string_array_t *arr = calloc(1, sizeof(*arr));
    if (!arr) {
        return NULL;
    }

    if (cap > 0) {
        error_t *err = string_array_init_cap(arr, cap);
        if (err) {
            error_free(err);
            free(arr);
            return NULL;
        }
    }

    return arr;
}

void string_array_free(string_array_t *arr) {
    if (!arr) {
        return;
    }
    string_array_deinit(arr);
    free(arr);
}

void string_array_free_cb(void *ptr) {
    string_array_free(ptr);
}

/* --- Internal --- */

static error_t *string_array_ensure_capacity(string_array_t *arr) {
    if (arr->count < arr->capacity) {
        return NULL;
    }

    size_t new_cap = arr->capacity ? arr->capacity * 2 : DEFAULT_CAP;

    if (new_cap < arr->capacity || new_cap > SIZE_MAX / sizeof(char *)) {
        return ERROR(
            ERR_MEMORY,
            "Array too large to grow"
        );
    }

    char **new_items = realloc(arr->items, new_cap * sizeof(char *));
    if (!new_items) {
        return ERROR(
            ERR_MEMORY,
            "Failed to grow array"
        );
    }

    arr->items = new_items;
    arr->capacity = new_cap;

    return NULL;
}

/* --- Mutation --- */

error_t *string_array_push(string_array_t *arr, const char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    char *dup = strdup(str);
    if (!dup) {
        return ERROR(
            ERR_MEMORY,
            "Failed to duplicate string"
        );
    }

    error_t *err = string_array_push_owned(arr, dup);
    if (err) {
        free(dup);
        return err;
    }

    return NULL;
}

error_t *string_array_push_owned(string_array_t *arr, char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    RETURN_IF_ERROR(string_array_ensure_capacity(arr));
    arr->items[arr->count++] = str;

    return NULL;
}

error_t *string_array_reserve(string_array_t *arr, size_t cap) {
    CHECK_NULL(arr);

    if (cap <= arr->capacity) {
        return NULL;
    }

    if (cap > SIZE_MAX / sizeof(char *)) {
        return ERROR(
            ERR_MEMORY,
            "Array capacity overflow"
        );
    }

    char **new_items = realloc(arr->items, cap * sizeof(char *));
    if (!new_items) {
        return ERROR(
            ERR_MEMORY,
            "Failed to reserve array capacity"
        );
    }

    arr->items = new_items;
    arr->capacity = cap;

    return NULL;
}

void string_array_remove(string_array_t *arr, size_t index) {
    if (!arr || index >= arr->count) {
        return;
    }

    free(arr->items[index]);
    arr->count--;

    if (index < arr->count) {
        memmove(
            &arr->items[index], &arr->items[index + 1],
            (arr->count - index) * sizeof(char *)
        );
    }
}

void string_array_swap_remove(string_array_t *arr, size_t index) {
    if (!arr || index >= arr->count) {
        return;
    }

    free(arr->items[index]);
    arr->count--;

    if (index < arr->count) {
        arr->items[index] = arr->items[arr->count];
    }
}

bool string_array_remove_value(string_array_t *arr, const char *str) {
    if (!arr || !str) {
        return false;
    }

    for (size_t i = 0; i < arr->count; i++) {
        if (strcmp(arr->items[i], str) == 0) {
            string_array_remove(arr, i);
            return true;
        }
    }

    return false;
}

void string_array_clear(string_array_t *arr) {
    if (!arr) {
        return;
    }

    for (size_t i = 0; i < arr->count; i++) {
        free(arr->items[i]);
    }
    arr->count = 0;
}

/* --- Query --- */

bool string_array_contains(const string_array_t *arr, const char *str) {
    if (!arr || !str) {
        return false;
    }

    for (size_t i = 0; i < arr->count; i++) {
        if (strcmp(arr->items[i], str) == 0) {
            return true;
        }
    }

    return false;
}

/* --- Ordering --- */

static int cmp_strings(const void *a, const void *b) {
    return strcmp(*(const char *const *) a, *(const char *const *) b);
}

void string_array_sort(string_array_t *arr) {
    if (!arr || arr->count < 2) {
        return;
    }
    qsort(arr->items, arr->count, sizeof(char *), cmp_strings);
}

/* --- Copy --- */

error_t *string_array_clone(const string_array_t *src, string_array_t *dst) {
    CHECK_NULL(src);
    CHECK_NULL(dst);

    *dst = (string_array_t){ 0 };

    if (src->count == 0) {
        return NULL;
    }

    dst->items = malloc(src->count * sizeof(char *));
    if (!dst->items) {
        return ERROR(
            ERR_MEMORY,
            "Failed to allocate clone"
        );
    }
    dst->capacity = src->count;

    for (size_t i = 0; i < src->count; i++) {
        dst->items[i] = strdup(src->items[i]);
        if (!dst->items[i]) {
            dst->count = i;
            string_array_deinit(dst);
            return ERROR(
                ERR_MEMORY,
                "Failed to clone string"
            );
        }
    }
    dst->count = src->count;

    return NULL;
}

char *string_array_join(const string_array_t *arr, const char *delimiter) {
    if (!arr || arr->count == 0) {
        return strdup("");
    }

    size_t delim_len = delimiter ? strlen(delimiter) : 0;

    /* Measure total length, caching individual lengths to avoid double strlen.
     * Small arrays use stack; larger arrays fall back to heap. */
    size_t stack_lengths[64];
    size_t *heap_lengths = NULL;
    size_t *lengths;
    if (arr->count <= 64) {
        lengths = stack_lengths;
    } else {
        heap_lengths = calloc(arr->count, sizeof(size_t));
        if (!heap_lengths) {
            return NULL;
        }
        lengths = heap_lengths;
    }

    char *result = NULL;
    size_t total = 0;
    for (size_t i = 0; i < arr->count; i++) {
        lengths[i] = strlen(arr->items[i]);
        if (total + lengths[i] < total) {
            goto cleanup;
        }
        total += lengths[i];
    }
    if (delim_len > 0 && arr->count > 1) {
        size_t delim_total = delim_len * (arr->count - 1);
        if (delim_total / delim_len != (arr->count - 1) ||
            total + delim_total < total) {
            goto cleanup;
        }
        total += delim_total;
    }

    /* Allocate result */
    result = malloc(total + 1);
    if (!result) {
        goto cleanup;
    }

    /* Build result */
    char *p = result;
    for (size_t i = 0; i < arr->count; i++) {
        if (i > 0 && delim_len > 0) {
            memcpy(p, delimiter, delim_len);
            p += delim_len;
        }
        memcpy(p, arr->items[i], lengths[i]);
        p += lengths[i];
    }
    *p = '\0';

cleanup:
    free(heap_lengths);
    return result;
}

/* === ptr_array_t — borrowed-pointer dynamic array === */

/* --- Lifecycle (stack / embedded) --- */

void ptr_array_init(ptr_array_t *arr) {
    *arr = (ptr_array_t){ 0 };
}

error_t *ptr_array_init_cap(ptr_array_t *arr, size_t cap) {
    CHECK_NULL(arr);

    *arr = (ptr_array_t){ 0 };

    if (cap == 0) {
        return NULL;
    }

    if (cap > SIZE_MAX / sizeof(void *)) {
        return ERROR(
            ERR_MEMORY,
            "Array capacity overflow"
        );
    }

    arr->items = malloc(cap * sizeof(void *));
    if (!arr->items) {
        return ERROR(
            ERR_MEMORY,
            "Failed to allocate array"
        );
    }
    arr->capacity = cap;

    return NULL;
}

void ptr_array_deinit(ptr_array_t *arr) {
    if (!arr) {
        return;
    }

    free(arr->items);
    *arr = (ptr_array_t){ 0 };
}

/* --- Lifecycle (heap) --- */

ptr_array_t *ptr_array_new(size_t cap) {
    ptr_array_t *arr = calloc(1, sizeof(*arr));
    if (!arr) {
        return NULL;
    }

    if (cap > 0) {
        error_t *err = ptr_array_init_cap(arr, cap);
        if (err) {
            error_free(err);
            free(arr);
            return NULL;
        }
    }

    return arr;
}

void ptr_array_free(ptr_array_t *arr) {
    if (!arr) {
        return;
    }
    ptr_array_deinit(arr);
    free(arr);
}

void ptr_array_free_cb(void *ptr) {
    ptr_array_free(ptr);
}

/* --- Internal --- */

static error_t *ptr_array_ensure_capacity(ptr_array_t *arr) {
    if (arr->count < arr->capacity) {
        return NULL;
    }

    size_t new_cap = arr->capacity ? arr->capacity * 2 : DEFAULT_CAP;

    if (new_cap < arr->capacity || new_cap > SIZE_MAX / sizeof(void *)) {
        return ERROR(
            ERR_MEMORY,
            "Array too large to grow"
        );
    }

    void **new_items = realloc(arr->items, new_cap * sizeof(void *));
    if (!new_items) {
        return ERROR(
            ERR_MEMORY,
            "Failed to grow array"
        );
    }

    arr->items = new_items;
    arr->capacity = new_cap;

    return NULL;
}

/* --- Mutation --- */

error_t *ptr_array_push(ptr_array_t *arr, const void *p) {
    CHECK_NULL(arr);

    RETURN_IF_ERROR(ptr_array_ensure_capacity(arr));
    /* Storage is type-erased void *; the caller's const intent (if any) is
     * re-applied at retrieval through their cast back to T ** / const T **. */
    arr->items[arr->count++] = (void *) p;

    return NULL;
}

error_t *ptr_array_reserve(ptr_array_t *arr, size_t cap) {
    CHECK_NULL(arr);

    if (cap <= arr->capacity) {
        return NULL;
    }

    if (cap > SIZE_MAX / sizeof(void *)) {
        return ERROR(
            ERR_MEMORY,
            "Array capacity overflow"
        );
    }

    void **new_items = realloc(arr->items, cap * sizeof(void *));
    if (!new_items) {
        return ERROR(
            ERR_MEMORY,
            "Failed to reserve array capacity"
        );
    }

    arr->items = new_items;
    arr->capacity = cap;

    return NULL;
}

void ptr_array_clear(ptr_array_t *arr) {
    if (!arr) {
        return;
    }
    arr->count = 0;
}

/* --- Transfer --- */

const void **ptr_array_steal(ptr_array_t *arr, size_t *out_count) {
    if (!arr || !out_count) {
        if (out_count) {
            *out_count = 0;
        }
        return NULL;
    }

    if (arr->count == 0) {
        /* Collapse empty-but-reserved state to the NULL/0 contract.
         * Callers passing the result through output parameters rely on
         * "NULL means no results" — a zero-length non-NULL buffer would
         * complicate that. */
        free(arr->items);
        *arr = (ptr_array_t){ 0 };
        *out_count = 0;
        return NULL;
    }

    /* Centralized cast: storage is type-erased void ** to remain universal
     * across const and mutable callers; the return type advertises that
     * callers should treat the stolen buffer as read-only references. */
    const void **buf = (const void **) arr->items;
    *out_count = arr->count;
    *arr = (ptr_array_t){ 0 };
    return buf;
}
