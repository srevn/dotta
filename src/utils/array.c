/**
 * array.c - Dynamic string array implementation
 */

#include "array.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "hashmap.h"

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

void string_array_free(void *ptr) {
    string_array_t *arr = ptr;
    if (!arr) {
        return;
    }

    for (size_t i = 0; i < arr->count; i++) {
        free(arr->items[i]);
    }

    free(arr->items);
    free(arr);
}

string_array_t *string_array_clone(const string_array_t *src) {
    if (!src) {
        return NULL;
    }

    /* Create new array with same capacity for efficiency */
    string_array_t *clone = string_array_create_with_capacity(src->count);
    if (!clone) {
        return NULL;
    }

    /* Deep copy all strings */
    for (size_t i = 0; i < src->count; i++) {
        char *dup = strdup(src->items[i]);
        if (!dup) {
            /* Cleanup on failure */
            string_array_free(clone);
            return NULL;
        }
        /* Direct assignment is safe - we pre-allocated capacity */
        clone->items[clone->count++] = dup;
    }

    return clone;
}

/**
 * Grow array capacity
 */
static error_t *string_array_grow(string_array_t *arr) {
    size_t new_capacity;

    if (arr->capacity == 0) {
        new_capacity = INITIAL_CAPACITY;
    } else {
        /* Check for overflow before doubling */
        if (arr->capacity > SIZE_MAX / 2) {
            return error_create(ERR_MEMORY, "String array too large to grow");
        }
        new_capacity = arr->capacity * 2;
    }

    char **new_items = realloc(arr->items, new_capacity * sizeof(char *));
    if (!new_items) {
        return error_create(ERR_MEMORY, "Failed to grow string array");
    }

    arr->items = new_items;
    arr->capacity = new_capacity;

    return NULL;
}

error_t *string_array_push(string_array_t *arr, const char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    char *dup = strdup(str);
    if (!dup) {
        return error_create(ERR_MEMORY, "Failed to duplicate string");
    }

    return string_array_push_take(arr, dup);
}

error_t *string_array_push_take(string_array_t *arr, char *str) {
    CHECK_NULL(arr);
    CHECK_NULL(str);

    if (arr->count >= arr->capacity) {
        error_t *err = string_array_grow(arr);
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

error_t *string_array_remove(string_array_t *arr, size_t index) {
    CHECK_NULL(arr);

    if (index >= arr->count) {
        return ERROR(ERR_INVALID_ARG, "Index out of bounds");
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

error_t *string_array_remove_value(string_array_t *arr, const char *str) {
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

error_t *string_array_reserve(string_array_t *arr, size_t capacity) {
    CHECK_NULL(arr);

    /* Already have enough capacity */
    if (capacity <= arr->capacity) {
        return NULL;
    }

    /* Allocate new capacity */
    char **new_items = realloc(arr->items, capacity * sizeof(char *));
    if (!new_items) {
        return error_create(ERR_MEMORY, "Failed to reserve array capacity");
    }

    arr->items = new_items;
    arr->capacity = capacity;

    return NULL;
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

error_t *string_array_difference(
    const string_array_t *set_a,
    const string_array_t *set_b,
    string_array_t **out_difference
) {
    CHECK_NULL(set_a);
    CHECK_NULL(set_b);
    CHECK_NULL(out_difference);

    /* Resource tracking for cleanup */
    hashmap_t *exclude_set = NULL;
    string_array_t *result = NULL;
    error_t *err = NULL;

    /* Create result array with capacity hint based on set_a size */
    result = string_array_create_with_capacity(string_array_size(set_a));
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to create result array");
    }

    /* Edge case: if set_b is empty, all of set_a is in the difference */
    if (string_array_size(set_b) == 0) {
        for (size_t i = 0; i < string_array_size(set_a); i++) {
            err = string_array_push(result, string_array_get(set_a, i));
            if (err) {
                string_array_free(result);
                return error_wrap(err, "Failed to copy element to result");
            }
        }
        *out_difference = result;
        return NULL;
    }

    /* Build exclusion set from set_b using hashmap for O(1) lookups */
    exclude_set = hashmap_create(string_array_size(set_b));
    if (!exclude_set) {
        string_array_free(result);
        return ERROR(ERR_MEMORY, "Failed to create exclusion index");
    }

    /* Populate exclusion set - map values are just (void*)1 as existence markers */
    for (size_t i = 0; i < string_array_size(set_b); i++) {
        const char *item = string_array_get(set_b, i);
        err = hashmap_set(exclude_set, item, (void*)1);
        if (err) {
            err = error_wrap(err, "Failed to build exclusion index");
            goto cleanup;
        }
    }

    /* Filter set_a: add items not in exclusion set to result */
    for (size_t i = 0; i < string_array_size(set_a); i++) {
        const char *item = string_array_get(set_a, i);

        /* O(1) lookup in hashmap */
        if (!hashmap_has(exclude_set, item)) {
            err = string_array_push(result, item);
            if (err) {
                err = error_wrap(err, "Failed to add element to result");
                goto cleanup;
            }
        }
    }

    /* Success - cleanup and return */
    hashmap_free(exclude_set, NULL);
    *out_difference = result;
    return NULL;

cleanup:
    /* Error path cleanup */
    hashmap_free(exclude_set, NULL);
    string_array_free(result);
    return err;
}
