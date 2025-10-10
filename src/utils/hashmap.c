/**
 * hashmap.c - Hash table implementation
 *
 * Uses FNV-1a hash function with separate chaining for collisions.
 * Automatically resizes when load factor exceeds 0.75.
 */

#include "hashmap.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"

/* Default initial capacity (must be power of 2 for fast modulo) */
#define DEFAULT_CAPACITY 16

/* Resize when load factor exceeds this threshold */
#define LOAD_FACTOR_THRESHOLD 0.75

/**
 * Hash map entry (linked list node)
 */
typedef struct hashmap_entry {
    char *key;                      /* Owned by entry */
    void *value;                    /* Not owned, just pointer */
    struct hashmap_entry *next;     /* Next in chain */
} hashmap_entry_t;

/**
 * Hash map structure
 */
struct hashmap {
    hashmap_entry_t **buckets;      /* Array of bucket chains */
    size_t bucket_count;            /* Number of buckets */
    size_t entry_count;             /* Number of entries */
    size_t resize_threshold;        /* When to resize */
};

/**
 * FNV-1a hash function for strings
 *
 * Fast, simple, good distribution for string keys
 */
static uint64_t hashmap_hash(const char *key) {
    /* FNV-1a parameters */
    const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;

    uint64_t hash = FNV_OFFSET_BASIS;
    for (const unsigned char *p = (const unsigned char *)key; *p; p++) {
        hash ^= *p;
        hash *= FNV_PRIME;
    }
    return hash;
}

/**
 * Get bucket index for key
 */
static size_t hashmap_bucket_index(const hashmap_t *map, const char *key) {
    uint64_t hash = hashmap_hash(key);
    /* Fast modulo using bitwise AND (works because bucket_count is power of 2) */
    return (size_t)(hash & (map->bucket_count - 1));
}

/**
 * Find entry in bucket chain
 *
 * @param bucket Head of bucket chain
 * @param key Key to find
 * @param prev Output: previous entry in chain (NULL if first)
 * @return Entry if found, NULL otherwise
 */
static hashmap_entry_t *hashmap_find_entry(
    hashmap_entry_t *bucket,
    const char *key,
    hashmap_entry_t **prev
) {
    hashmap_entry_t *entry = bucket;
    hashmap_entry_t *previous = NULL;

    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            if (prev) *prev = previous;
            return entry;
        }
        previous = entry;
        entry = entry->next;
    }

    if (prev) *prev = NULL;
    return NULL;
}

/**
 * Create new entry
 */
static hashmap_entry_t *hashmap_entry_create(const char *key, void *value) {
    hashmap_entry_t *entry = calloc(1, sizeof(hashmap_entry_t));
    if (!entry) {
        return NULL;
    }

    entry->key = strdup(key);
    if (!entry->key) {
        free(entry);
        return NULL;
    }

    entry->value = value;
    entry->next = NULL;
    return entry;
}

/**
 * Free entry (does not free value)
 */
static void hashmap_entry_free(hashmap_entry_t *entry) {
    if (!entry) return;
    free(entry->key);
    free(entry);
}

/**
 * Resize hash map to new capacity
 */
static dotta_error_t *hashmap_resize(hashmap_t *map, size_t new_capacity) {
    /* Allocate new bucket array */
    hashmap_entry_t **new_buckets = calloc(new_capacity, sizeof(hashmap_entry_t *));
    if (!new_buckets) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate buckets for resize");
    }

    /* Save old buckets */
    hashmap_entry_t **old_buckets = map->buckets;
    size_t old_capacity = map->bucket_count;

    /* Update map to use new buckets */
    map->buckets = new_buckets;
    map->bucket_count = new_capacity;
    map->resize_threshold = (size_t)(new_capacity * LOAD_FACTOR_THRESHOLD);

    /* Rehash all entries from old buckets to new buckets */
    for (size_t i = 0; i < old_capacity; i++) {
        hashmap_entry_t *entry = old_buckets[i];
        while (entry) {
            hashmap_entry_t *next = entry->next;

            /* Compute new bucket index */
            size_t new_idx = hashmap_bucket_index(map, entry->key);

            /* Insert at head of new bucket chain */
            entry->next = map->buckets[new_idx];
            map->buckets[new_idx] = entry;

            entry = next;
        }
    }

    /* Free old bucket array (entries have been moved) */
    free(old_buckets);

    return NULL;
}

/**
 * Create new hash map
 */
hashmap_t *hashmap_create(size_t initial_capacity) {
    /* Use default if not specified */
    if (initial_capacity == 0) {
        initial_capacity = DEFAULT_CAPACITY;
    }

    /* Round up to next power of 2 for fast modulo */
    size_t capacity = 1;
    while (capacity < initial_capacity) {
        capacity *= 2;
    }

    /* Allocate map structure */
    hashmap_t *map = calloc(1, sizeof(hashmap_t));
    if (!map) {
        return NULL;
    }

    /* Allocate bucket array */
    map->buckets = calloc(capacity, sizeof(hashmap_entry_t *));
    if (!map->buckets) {
        free(map);
        return NULL;
    }

    map->bucket_count = capacity;
    map->entry_count = 0;
    map->resize_threshold = (size_t)(capacity * LOAD_FACTOR_THRESHOLD);

    return map;
}

/**
 * Insert or update key-value pair
 */
dotta_error_t *hashmap_set(hashmap_t *map, const char *key, void *value) {
    if (!map) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Hash map is NULL");
    }
    if (!key) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Key is NULL");
    }

    /* Find bucket */
    size_t idx = hashmap_bucket_index(map, key);
    hashmap_entry_t *existing = hashmap_find_entry(map->buckets[idx], key, NULL);

    if (existing) {
        /* Update existing entry */
        existing->value = value;
        return NULL;
    }

    /* Create new entry */
    hashmap_entry_t *new_entry = hashmap_entry_create(key, value);
    if (!new_entry) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate hash map entry");
    }

    /* Insert at head of bucket chain */
    new_entry->next = map->buckets[idx];
    map->buckets[idx] = new_entry;
    map->entry_count++;

    /* Check if resize needed */
    if (map->entry_count > map->resize_threshold) {
        dotta_error_t *err = hashmap_resize(map, map->bucket_count * 2);
        if (err) {
            /* Resize failed, but insertion succeeded.
             * Continue with current size, but warn about performance degradation.
             * As more items are added without resizing, collision chains grow
             * longer, degrading lookup performance from O(1) to O(n).
             */
            fprintf(stderr, "Warning: Hash map resize failed (%s)\n", error_message(err));
            fprintf(stderr, "         Performance may degrade. Current size: %zu entries, %zu buckets\n",
                    map->entry_count, map->bucket_count);
            error_free(err);
        }
    }

    return NULL;
}

/**
 * Get value for key
 */
void *hashmap_get(const hashmap_t *map, const char *key) {
    if (!map || !key) {
        return NULL;
    }

    size_t idx = hashmap_bucket_index(map, key);
    hashmap_entry_t *entry = hashmap_find_entry(map->buckets[idx], key, NULL);
    return entry ? entry->value : NULL;
}

/**
 * Check if key exists
 */
bool hashmap_has(const hashmap_t *map, const char *key) {
    if (!map || !key) {
        return false;
    }

    size_t idx = hashmap_bucket_index(map, key);
    return hashmap_find_entry(map->buckets[idx], key, NULL) != NULL;
}

/**
 * Remove key-value pair
 */
dotta_error_t *hashmap_remove(hashmap_t *map, const char *key, void **old_value) {
    if (!map) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Hash map is NULL");
    }
    if (!key) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Key is NULL");
    }

    size_t idx = hashmap_bucket_index(map, key);
    hashmap_entry_t *prev = NULL;
    hashmap_entry_t *entry = hashmap_find_entry(map->buckets[idx], key, &prev);

    if (!entry) {
        return ERROR(DOTTA_ERR_NOT_FOUND, "Key not found in hash map: %s", key);
    }

    /* Save old value if requested */
    if (old_value) {
        *old_value = entry->value;
    }

    /* Remove from chain */
    if (prev) {
        prev->next = entry->next;
    } else {
        map->buckets[idx] = entry->next;
    }

    /* Free entry */
    hashmap_entry_free(entry);
    map->entry_count--;

    return NULL;
}

/**
 * Iterate over all entries
 */
void hashmap_foreach(const hashmap_t *map, hashmap_iter_fn fn, void *user_data) {
    if (!map || !fn) {
        return;
    }

    for (size_t i = 0; i < map->bucket_count; i++) {
        hashmap_entry_t *entry = map->buckets[i];
        while (entry) {
            /* Save next pointer before callback (in case entry is modified) */
            hashmap_entry_t *next = entry->next;

            /* Call iterator */
            bool continue_iter = fn(entry->key, entry->value, user_data);
            if (!continue_iter) {
                return;
            }

            entry = next;
        }
    }
}

/**
 * Get number of entries
 */
size_t hashmap_size(const hashmap_t *map) {
    return map ? map->entry_count : 0;
}

/**
 * Check if empty
 */
bool hashmap_is_empty(const hashmap_t *map) {
    return !map || map->entry_count == 0;
}

/**
 * Remove all entries
 */
void hashmap_clear(hashmap_t *map, hashmap_value_free_fn free_value) {
    if (!map) {
        return;
    }

    for (size_t i = 0; i < map->bucket_count; i++) {
        hashmap_entry_t *entry = map->buckets[i];
        while (entry) {
            hashmap_entry_t *next = entry->next;

            /* Free value if callback provided */
            if (free_value && entry->value) {
                free_value(entry->value);
            }

            /* Free entry */
            hashmap_entry_free(entry);

            entry = next;
        }
        map->buckets[i] = NULL;
    }

    map->entry_count = 0;
}

/**
 * Free hash map
 */
void hashmap_free(hashmap_t *map, hashmap_value_free_fn free_value) {
    if (!map) {
        return;
    }

    /* Clear all entries */
    hashmap_clear(map, free_value);

    /* Free bucket array */
    free(map->buckets);

    /* Free map structure */
    free(map);
}
