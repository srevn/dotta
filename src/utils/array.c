/**
 * array.c - Dynamic string array implementation
 */

#include "array.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"

#define INITIAL_CAPACITY 8

string_array_t *string_array_create(void) {
    return string_array_create_with_capacity(INITIAL_CAPACITY);
}

string_array_t *string_array_create_with_capacity(size_t capacity) {
    string_array_t *arr = calloc(1, sizeof(string_array_t));
    if (!arr) {
        return NULL;
    }

    if (capacity > 0) {
        arr->items = calloc(capacity, sizeof(char *));
        if (!arr->items) {
            free(arr);
            return NULL;
        }
        arr->capacity = capacity;
    }

    arr->count = 0;
    return arr;
}

void string_array_free(string_array_t *arr) {
    if (!arr) {
        return;
    }

    for (size_t i = 0; i < arr->count; i++) {
        free(arr->items[i]);
    }

    free(arr->items);
    free(arr);
}

/**
 * Grow array capacity
 */
static dotta_error_t *string_array_grow(string_array_t *arr) {
    size_t new_capacity = arr->capacity == 0 ? INITIAL_CAPACITY : arr->capacity * 2;
    char **new_items = realloc(arr->items, new_capacity * sizeof(char *));

    if (!new_items) {
        return error_create(DOTTA_ERR_MEMORY, "Failed to grow string array");
    }

    arr->items = new_items;
    arr->capacity = new_capacity;

    /* Zero new slots */
    for (size_t i = arr->count; i < new_capacity; i++) {
        arr->items[i] = NULL;
    }

    return NULL;
}

dotta_error_t *string_array_push(string_array_t *arr, const char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    char *dup = strdup(str);
    if (!dup) {
        return error_create(DOTTA_ERR_MEMORY, "Failed to duplicate string");
    }

    return string_array_push_take(arr, dup);
}

dotta_error_t *string_array_push_take(string_array_t *arr, char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    if (arr->count >= arr->capacity) {
        dotta_error_t *err = string_array_grow(arr);
        if (err) {
            return err;
        }
    }

    arr->items[arr->count++] = str;
    return NULL;
}

const char *string_array_get(const string_array_t *arr, size_t index) {
    if (!arr || index >= arr->count) {
        return NULL;
    }
    return arr->items[index];
}

dotta_error_t *string_array_remove(string_array_t *arr, size_t index) {
    CHECK_NULL(arr);

    if (index >= arr->count) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Index out of bounds");
    }

    free(arr->items[index]);

    /* Shift remaining items */
    for (size_t i = index; i < arr->count - 1; i++) {
        arr->items[i] = arr->items[i + 1];
    }

    arr->count--;
    arr->items[arr->count] = NULL;

    return NULL;
}

dotta_error_t *string_array_remove_value(string_array_t *arr, const char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    for (size_t i = 0; i < arr->count; i++) {
        if (strcmp(arr->items[i], str) == 0) {
            return string_array_remove(arr, i);
        }
    }

    return NULL;  /* Not found - not an error */
}

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

void string_array_clear(string_array_t *arr) {
    if (!arr) {
        return;
    }

    for (size_t i = 0; i < arr->count; i++) {
        free(arr->items[i]);
        arr->items[i] = NULL;
    }

    arr->count = 0;
}

size_t string_array_size(const string_array_t *arr) {
    if (!arr) {
        return 0;
    }
    return arr->count;
}

/**
 * Comparison function for qsort
 */
static int compare_strings(const void *a, const void *b) {
    const char *str_a = *(const char **)a;
    const char *str_b = *(const char **)b;
    return strcmp(str_a, str_b);
}

void string_array_sort(string_array_t *arr) {
    if (!arr || arr->count == 0) {
        return;
    }

    qsort(arr->items, arr->count, sizeof(char *), compare_strings);
}
