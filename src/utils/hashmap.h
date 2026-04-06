/**
 * hashmap.h - Open-addressed hash table with Robin Hood probing
 *
 * String-keyed hash map using Robin Hood hashing with backward-shift
 * deletion. Keys are strings (duplicated internally), values are void
 * pointers.
 *
 * Robin Hood probing bounds probe-sequence variance: entries that hashed
 * far from their ideal slot "steal" from entries closer to theirs,
 * keeping all chains short. Backward-shift deletion avoids tombstones
 * entirely, so the table never degrades over insert/remove cycles.
 *
 * Memory ownership:
 * - Map owns keys (duplicates on insert, frees on remove/destroy)
 * - Caller owns values (map only stores pointers)
 * - Optional free_value callback for cleanup on clear/free
 *
 * Performance:
 * - Average O(1) insert, lookup, delete with excellent cache locality
 * - Automatic growth when load factor exceeds 75%
 * - No tombstones — backward-shift keeps the table clean
 */

#ifndef DOTTA_HASHMAP_H
#define DOTTA_HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Forward declarations */
typedef struct hashmap hashmap_t;
typedef struct error error_t;

/**
 * Value destructor callback
 *
 * Called when removing entries or destroying the map.
 *
 * @param value The value to free
 */
typedef void (*hashmap_free_fn)(void *value);

/**
 * Hash map iterator
 *
 * Stack-allocated. Initialize with hashmap_iter_init(), advance with
 * hashmap_iter_next(). Iteration order is undefined but deterministic
 * for a given map state.
 *
 * SAFETY: If the map is modified after init, hashmap_iter_next()
 * detects this and returns false.
 */
typedef struct hashmap_iter {
    const hashmap_t *map;
    size_t index;                      /* Next slot to examine */
    uint64_t snapshot_mod_count;
} hashmap_iter_t;

/**
 * Create new hash map
 *
 * @param initial_capacity Hint for expected entry count (0 = default 16).
 *                         Rounded up to next power of two internally.
 * @return New hash map, or NULL on allocation failure
 */
hashmap_t *hashmap_create(size_t initial_capacity);

/**
 * Remove all entries without freeing the map itself
 *
 * @param map Hash map (NULL is a no-op)
 * @param free_fn Optional callback to free each value, or NULL
 */
void hashmap_clear(hashmap_t *map, hashmap_free_fn free_fn);

/**
 * Free hash map and all entries
 *
 * @param map Hash map (NULL is a no-op)
 * @param free_fn Optional callback to free each value, or NULL
 */
void hashmap_free(hashmap_t *map, hashmap_free_fn free_fn);

/**
 * Insert or update a key-value pair
 *
 * If the key already exists, its value is replaced. The caller is
 * responsible for the old value's lifetime (retrieve it first with
 * hashmap_get if needed, or use hashmap_put for old-value retrieval).
 *
 * @param map Hash map (must not be NULL)
 * @param key Key string (will be duplicated; must not be NULL)
 * @param value Value pointer (map does not take ownership)
 * @return NULL on success, error on allocation failure
 */
error_t *hashmap_set(hashmap_t *map, const char *key, void *value);

/**
 * Insert or update, returning the previous value
 *
 * Like hashmap_set but writes the displaced value (if any) to *out_prev.
 * When the key is new, *out_prev is set to NULL.
 *
 * @param map Hash map (must not be NULL)
 * @param key Key string (will be duplicated; must not be NULL)
 * @param value New value pointer
 * @param out_prev Receives the previous value, or NULL if key was new
 * @return NULL on success, error on allocation failure
 */
error_t *hashmap_put(hashmap_t *map, const char *key, void *value, void **out_prev);

/**
 * Get value for key
 *
 * Returns NULL both when the key is absent and when its value is NULL.
 * Use hashmap_has() to distinguish the two cases.
 *
 * @param map Hash map (NULL returns NULL)
 * @param key Key string (NULL returns NULL)
 * @return Value pointer, or NULL if not found
 */
void *hashmap_get(const hashmap_t *map, const char *key);

/**
 * Check if key exists
 *
 * @param map Hash map (NULL returns false)
 * @param key Key string (NULL returns false)
 * @return true if key exists
 */
bool hashmap_has(const hashmap_t *map, const char *key);

/**
 * Remove a key-value pair
 *
 * Uses backward-shift deletion (no tombstones).
 *
 * @param map Hash map (NULL returns false)
 * @param key Key to remove (NULL returns false)
 * @param out_old If non-NULL and key existed, receives the removed value
 * @return true if key was found and removed, false if absent
 */
bool hashmap_remove(hashmap_t *map, const char *key, void **out_old);

/**
 * @return Number of key-value pairs (0 if map is NULL)
 */
size_t hashmap_size(const hashmap_t *map);

/**
 * @return true if map is NULL or contains no entries
 */
bool hashmap_is_empty(const hashmap_t *map);

/**
 * Initialize an iterator
 *
 * Takes a snapshot of the map's modification counter. If the map is
 * modified after this call, hashmap_iter_next() will return false.
 *
 * @param iter Iterator to initialize (must not be NULL)
 * @param map  Map to iterate (NULL produces an empty iteration)
 */
void hashmap_iter_init(hashmap_iter_t *iter, const hashmap_t *map);

/**
 * Advance iterator to next entry
 *
 * @param iter Iterator (must not be NULL)
 * @param out_key Receives key pointer (can be NULL to skip)
 * @param out_value Receives value pointer (can be NULL to skip)
 * @return true if an entry was retrieved, false at end or on stale iterator
 */
bool hashmap_iter_next(hashmap_iter_t *iter, const char **out_key, void **out_value);

#endif /* DOTTA_HASHMAP_H */
