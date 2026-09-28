/**
 * hashmap.h - Open-addressed hash table with Robin Hood probing
 *
 * String-keyed hash map using Robin Hood hashing with backward-shift deletion.
 * Keys are strings, values are void pointers.
 *
 * Robin Hood probing bounds probe-sequence variance: entries that hashed far
 * from their ideal slot "steal" from entries closer to theirs, keeping all chains
 * short. Backward-shift deletion avoids tombstones entirely, so the table never
 * degrades over insert/remove cycles.
 *
 * Memory ownership:
 * - A map lives in the arena it was made in — the struct, its slots and every
 *   key it copies — and goes with it: nothing frees a map. A rehash carves new
 *   slots and abandons the old to the arena (base/arena.h arena_abandon).
 * - Owning mode (hashmap_create): a key is copied into the map's arena once,
 *   when an insert takes a slot for it — never on an update or a probe.
 * - Borrowing mode (hashmap_borrow): the map stores the caller's key pointer.
 * - Caller owns values (map only stores pointers); a value that holds something
 *   to release is torn down by hashmap_clear's callback
 *
 * Performance:
 * - Average O(1) insert, lookup, delete with excellent cache locality
 * - Automatic growth when load factor exceeds 75%
 * - No tombstones — backward-shift keeps the table clean
 *
 * Growth cannot fail: a create, a set or a put succeeds or the run dies of
 * exhaustion (base/arena.h), and none of them answers anything — a table no memory
 * could hold is exhaustion too.
 */

#ifndef DOTTA_HASHMAP_H
#define DOTTA_HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <types.h>

/* Forward declarations */
typedef struct hashmap hashmap_t;

/**
 * Value destructor callback
 *
 * Called by hashmap_clear on every value it empties out of the map.
 *
 * @param value The value to free
 */
typedef void (*hashmap_free_fn)(void *value);

/**
 * Hash map iterator
 *
 * Stack-allocated. Initialize with hashmap_iter_init(), advance with
 * hashmap_iter_next(). Iteration order is undefined but deterministic for a given
 * map state. A map modified between the init and a next is a caller's bug.
 */
typedef struct hashmap_iter {
    const hashmap_t *map;
    size_t index;                      /* Next slot to examine */
    uint64_t snapshot_mod_count;
} hashmap_iter_t;

/**
 * Create a hash map in `arena`, owning its keys
 *
 * A key is copied into the arena when an insert takes a slot for it, so the
 * caller's key may change or go once the insert returns.
 *
 * @param arena Arena the map, its slots and its keys live in (must not be NULL)
 * @param expected Number of entries the caller expects to hold (0 = no expectation,
 *                 giving 16 slots). The map allocates the slots those entries
 *                 need in order to fit without a resize — more slots than entries,
 *                 since the table grows at its load factor rather than when full,
 *                 and rounded up to a power of two.
 * @return New hash map; never NULL
 */
hashmap_t *hashmap_create(arena_t *arena, size_t expected);

/**
 * Create a hash map in `arena`, borrowing its keys — stored by reference, not
 * copied
 *
 * The caller MUST guarantee:
 * - All key strings outlive the hashmap
 * - Keys are not modified after insertion
 *
 * @param arena Arena the map and its slots live in (must not be NULL)
 * @param expected Entries the caller expects to hold, read exactly as
 *                 hashmap_create reads it.
 * @return New hash map; never NULL
 */
hashmap_t *hashmap_borrow(arena_t *arena, size_t expected);

/**
 * Remove all entries; the map's room stays
 *
 * The way to release what the values hold: `free_fn` is handed each non-NULL
 * value as it leaves. The keys and the slots are the arena's.
 *
 * @param map Hash map (NULL is a no-op)
 * @param free_fn Optional callback to free each value, or NULL
 */
void hashmap_clear(hashmap_t *map, hashmap_free_fn free_fn);

/**
 * Insert or update a key-value pair
 *
 * If the key already exists, its value is replaced. The caller is responsible
 * for the old value's lifetime (retrieve it first with hashmap_get if needed,
 * or use hashmap_put for old-value retrieval).
 *
 * @param map Hash map (must not be NULL)
 * @param key Key string (copied into the map's arena in owning mode, stored
 *            directly in borrowing mode; must not be NULL)
 * @param value Value pointer (map does not take ownership)
 */
void hashmap_set(hashmap_t *map, const char *key, void *value);

/**
 * Insert or update, returning the previous value
 *
 * Like hashmap_set but writes the displaced value (if any) to *out_prev. When
 * the key is new, *out_prev is set to NULL.
 *
 * @param map Hash map (must not be NULL)
 * @param key Key string (copied into the map's arena in owning mode, stored
 *            directly in borrowing mode; must not be NULL)
 * @param value New value pointer
 * @param out_prev Receives the previous value, or NULL if key was new
 */
void hashmap_put(hashmap_t *map, const char *key, void *value, void **out_prev);

/**
 * Get value for key
 *
 * Returns NULL both when the key is absent and when its value is NULL. Use
 * hashmap_has() to distinguish the two cases.
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
 * Uses backward-shift deletion (no tombstones). An owned key stays the arena's.
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
 * Slots allocated, always a power of two (0 if map is NULL)
 *
 * The sibling of hashmap_size, and the answer this container owes for the same
 * reason the transparent ones give it away as a field: string_array_t and buffer_t
 * both carry a public `capacity`, and an opaque table should not be the one
 * collection that cannot say how much room it took.
 *
 * What it is good for is checking that a sizing hint held — a capacity that stands
 * unchanged across the inserts it was sized for is a map that never rehashed.
 */
size_t hashmap_capacity(const hashmap_t *map);

/**
 * @return true if map is NULL or contains no entries
 */
bool hashmap_is_empty(const hashmap_t *map);

/**
 * Initialize an iterator
 *
 * Takes a snapshot of the map's modification counter: a map modified after this
 * call dies at the next hashmap_iter_next, naming the mistake.
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
 * @return true if an entry was retrieved, false at the end
 */
bool hashmap_iter_next(hashmap_iter_t *iter, const char **out_key, void **out_value);

#endif /* DOTTA_HASHMAP_H */
