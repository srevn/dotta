/**
 * hashmap.h - Hash table for string keys
 *
 * Simple, efficient hash map implementation using separate chaining.
 * Keys are strings (duplicated internally), values are void pointers.
 *
 * Memory ownership:
 * - Map owns keys (duplicates on insert, frees on remove/destroy)
 * - Caller owns values (map only stores pointers)
 * - Optional free_value callback for cleanup
 *
 * Performance characteristics:
 * - Average case: O(1) insert, lookup, delete
 * - Worst case: O(n) if all keys hash to same bucket
 * - Automatic resizing when load factor exceeds 0.75
 */

#ifndef DOTTA_UTILS_HASHMAP_H
#define DOTTA_UTILS_HASHMAP_H

#include <stdbool.h>
#include <stddef.h>

/* Forward declarations */
typedef struct hashmap hashmap_t;
typedef struct error error_t;

/**
 * Iterator callback function
 *
 * @param key Entry key (read-only)
 * @param value Entry value (can be modified)
 * @param user_data User-provided context
 * @return true to continue iteration, false to stop
 */
typedef bool (*hashmap_iter_fn)(const char *key, void *value, void *user_data);

/**
 * Value destructor callback
 *
 * Called when removing entries or destroying the map.
 *
 * @param value The value to free
 */
typedef void (*hashmap_value_free_fn)(void *value);

/**
 * Create new hash map
 *
 * @param initial_capacity Initial number of buckets (0 = default)
 * @return New hash map, or NULL on allocation failure
 */
hashmap_t *hashmap_create(size_t initial_capacity);

/**
 * Insert or update key-value pair
 *
 * If key already exists, old value is replaced. The caller is responsible
 * for freeing the old value if needed (use hashmap_get first to retrieve it).
 *
 * @param map Hash map
 * @param key Key string (will be duplicated)
 * @param value Value pointer (map does not take ownership)
 * @return NULL on success, error otherwise
 */
error_t *hashmap_set(hashmap_t *map, const char *key, void *value);

/**
 * Get value for key
 *
 * @param map Hash map
 * @param key Key string
 * @return Value pointer, or NULL if not found
 */
void *hashmap_get(const hashmap_t *map, const char *key);

/**
 * Check if key exists
 *
 * @param map Hash map
 * @param key Key string
 * @return true if key exists, false otherwise
 */
bool hashmap_has(const hashmap_t *map, const char *key);

/**
 * Remove key-value pair
 *
 * @param map Hash map
 * @param key Key to remove
 * @param old_value Optional output for removed value (can be NULL)
 * @return NULL on success, error if key not found
 */
error_t *hashmap_remove(hashmap_t *map, const char *key, void **old_value);

/**
 * Iterate over all entries
 *
 * Iteration order is undefined. Do not modify the map during iteration.
 *
 * @param map Hash map
 * @param fn Iterator callback
 * @param user_data User context passed to callback
 */
void hashmap_foreach(const hashmap_t *map, hashmap_iter_fn fn, void *user_data);

/**
 * Get number of entries
 *
 * @param map Hash map
 * @return Number of key-value pairs
 */
size_t hashmap_size(const hashmap_t *map);

/**
 * Check if map is empty
 *
 * @param map Hash map
 * @return true if empty
 */
bool hashmap_is_empty(const hashmap_t *map);

/**
 * Remove all entries
 *
 * @param map Hash map
 * @param free_value Optional callback to free values
 */
void hashmap_clear(hashmap_t *map, hashmap_value_free_fn free_value);

/**
 * Free hash map
 *
 * @param map Hash map (can be NULL)
 * @param free_value Optional callback to free values
 */
void hashmap_free(hashmap_t *map, hashmap_value_free_fn free_value);

#endif /* DOTTA_UTILS_HASHMAP_H */
