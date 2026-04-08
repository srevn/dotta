/**
 * array.c - Dynamic string array implementation
 */

#include "base/array.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"

#define DEFAULT_CAP 8

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

static error_t *ensure_capacity(string_array_t *arr) {
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

    RETURN_IF_ERROR(ensure_capacity(arr));
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
    return strcmp(*(const char **) a, *(const char **) b);
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
