/**
 * hashmap.c - Robin Hood hash table implementation
 *
 * Open addressing with linear probing and Robin Hood displacement.
 * Backward-shift deletion keeps the table tombstone-free.
 *
 * Slot layout:
 *   key != NULL  →  occupied (key is owned or borrowed per borrow_keys flag)
 *   key == NULL  →  empty
 *
 * Hash: FNV-1a (64-bit compute, XOR-folded to 32-bit for compact slots).
 * Capacity: always a power of two for fast masking.
 */

#include "hashmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"

/* Default initial capacity (must be power of 2 for fast modulo) */
#define HASHMAP_DEFAULT_CAPACITY    16
#define HASHMAP_MIN_CAPACITY        4      /* Floor to avoid degenerate grow_at */
#define HASHMAP_LOAD_PERCENT        75     /* Resize at 75% occupancy */

/* FNV-1a 64-bit parameters */
#define FNV_OFFSET  14695981039346656037ULL
#define FNV_PRIME   1099511628211ULL

/* Slot */
typedef struct {
    char *key;          /* NULL = empty slot; owned or borrowed per map->borrow_keys */
    void *value;
    uint32_t hash;      /* Cached XOR-folded 32 bits of FNV-1a */
} hashmap_slot_t;

/* Map */
struct hashmap {
    hashmap_slot_t *slots;
    size_t capacity;            /* Always power of 2 */
    size_t count;               /* Number of occupied slots */
    size_t grow_at;             /* count threshold triggering resize */
    uint64_t mod_count;         /* Mutation counter for iterator safety */
    bool borrow_keys;           /* If true: keys stored by reference, not strdup'd */
};

/* FNV-1a hash function for strings */
static uint32_t hash_key(const char *key) {
    uint64_t hash = FNV_OFFSET;
    for (const unsigned char *p = (const unsigned char *) key; *p; p++) {
        hash ^= *p;
        hash *= FNV_PRIME;
    }
    /* XOR-fold: mix upper bits into lower 32 for better distribution */
    return (uint32_t) (hash ^ (hash >> 32));
}

/* Ideal slot for a given hash */
static inline size_t ideal_slot(uint32_t hash, size_t mask) {
    return (size_t) hash & mask;
}

/* Distance from ideal slot (probe sequence length) */
static inline size_t probe_dist(size_t slot, uint32_t hash, size_t mask) {
    return (slot - ideal_slot(hash, mask)) & mask;
}

/* Resize-only insert (no key dup, no update check) */
static void insert_for_resize(
    hashmap_t *map,
    char *key,
    void *value,
    uint32_t hash
) {
    size_t mask = map->capacity - 1;
    size_t pos = ideal_slot(hash, mask);
    size_t dist = 0;

    for (;;) {
        hashmap_slot_t *slot = &map->slots[pos];

        if (!slot->key) {
            slot->key = key;
            slot->value = value;
            slot->hash = hash;
            map->count++;
            return;
        }

        size_t existing = probe_dist(pos, slot->hash, mask);
        if (dist > existing) {
            /* Robin Hood swap: displace the richer entry */
            char *tk = slot->key;
            void *tv = slot->value;
            uint32_t th = slot->hash;

            slot->key = key;
            slot->value = value;
            slot->hash = hash;

            key = tk;
            value = tv;
            hash = th;
            dist = existing;
        }

        pos = (pos + 1) & mask;
        dist++;
    }
}

/* Internal: grow */
static error_t *hashmap_grow(hashmap_t *map) {
    size_t new_cap = map->capacity * 2;
    if (new_cap <= map->capacity) {
        return ERROR(
            ERR_MEMORY,
            "Hash map capacity overflow"
        );
    }

    hashmap_slot_t *new_slots = calloc(new_cap, sizeof(hashmap_slot_t));
    if (!new_slots) {
        return ERROR(
            ERR_MEMORY,
            "Failed to allocate hash map slots for resize"
        );
    }

    hashmap_slot_t *old_slots = map->slots;
    size_t old_cap = map->capacity;

    map->slots = new_slots;
    map->capacity = new_cap;
    map->grow_at = new_cap * HASHMAP_LOAD_PERCENT / 100;
    map->count = 0;

    for (size_t i = 0; i < old_cap; i++) {
        if (old_slots[i].key) {
            insert_for_resize(
                map,
                old_slots[i].key,
                old_slots[i].value,
                old_slots[i].hash
            );
        }
    }

    free(old_slots);
    map->mod_count++;

    return NULL;
}

/**
 * Shared insert/update implementation.
 *
 * @param map       Target map
 * @param key       Caller's key (const — will be strdup'd if needed)
 * @param value     Value to store
 * @param out_prev  If non-NULL, receives the previous value when updating
 *                  an existing key (set to NULL when inserting a new key).
 * @return NULL on success, error on OOM
 */
static error_t *hashmap_insert(
    hashmap_t *map,
    const char *key,
    void *value,
    void **out_prev
) {
    if (out_prev) *out_prev = NULL;

    /* Grow before insert so there is always at least one empty slot */
    if (map->count >= map->grow_at) {
        error_t *err = hashmap_grow(map);
        if (err) {
            if (map->count >= map->capacity) {
                /* Table completely full — probe loop would never terminate */
                return error_wrap(
                    err, "Hash map at capacity, cannot insert"
                );
            }
            /*
             * Non-fatal: current load < 100%.  At 75% threshold with
             * power-of-2 capacity we still have ≥25% empty slots.
             */
            fprintf(
                stderr, "warning: hash map resize failed (%s)\n",
                error_message(err)
            );
            fprintf(
                stderr, "         %zu entries in %zu slots\n",
                map->count, map->capacity
            );
            error_free(err);
        }
    }

    uint32_t h = hash_key(key);
    size_t mask = map->capacity - 1;
    size_t pos = ideal_slot(h, mask);
    size_t dist = 0;

    /* Key we are carrying (NULL until we need to allocate) */
    char *carry_key = NULL;
    void *carry_val = value;
    uint32_t carry_h = h;

    for (;;) {
        hashmap_slot_t *slot = &map->slots[pos];

        /* Empty slot — insert */
        if (!slot->key) {
            if (!carry_key) {
                if (map->borrow_keys) {
                    carry_key = (char *) key;
                } else {
                    carry_key = strdup(key);
                    if (!carry_key) {
                        return ERROR(
                            ERR_MEMORY,
                            "Failed to allocate hash map key"
                        );
                    }
                }
            }
            slot->key = carry_key;
            slot->value = carry_val;
            slot->hash = carry_h;
            map->count++;
            map->mod_count++;
            return NULL;
        }

        /* Exact match — update value */
        if (slot->hash == h && strcmp(slot->key, key) == 0) {
            if (out_prev) *out_prev = slot->value;
            slot->value = value;
            /* No mod_count bump: value-only update is not structural */
            return NULL;
        }

        /* Robin Hood: displace richer entries */
        size_t existing = probe_dist(pos, slot->hash, mask);
        if (dist > existing) {
            if (!carry_key) {
                if (map->borrow_keys) {
                    carry_key = (char *) key;
                } else {
                    carry_key = strdup(key);
                    if (!carry_key) {
                        return ERROR(
                            ERR_MEMORY,
                            "Failed to allocate hash map key"
                        );
                    }
                }
            }

            /* Swap our entry into this slot, carry the displaced one */
            char *tk = slot->key;
            void *tv = slot->value;
            uint32_t th = slot->hash;

            slot->key = carry_key;
            slot->value = carry_val;
            slot->hash = carry_h;

            carry_key = tk;
            carry_val = tv;
            carry_h = th;
            dist = existing;
        }

        pos = (pos + 1) & mask;
        dist++;
    }
}

/**
 * Find a slot by key.
 *
 * Returns pointer to the occupied slot, or NULL if absent. Uses Robin
 * Hood early termination: if our probe distance exceeds the slot's,
 * the key cannot be present.
 */
static const hashmap_slot_t *hashmap_find(
    const hashmap_t *map,
    const char *key,
    uint32_t h
) {
    size_t mask = map->capacity - 1;
    size_t pos = ideal_slot(h, mask);
    size_t dist = 0;

    for (;;) {
        const hashmap_slot_t *slot = &map->slots[pos];

        if (!slot->key)
            return NULL;

        if (slot->hash == h && strcmp(slot->key, key) == 0)
            return slot;

        if (dist > probe_dist(pos, slot->hash, mask))
            return NULL;     /* Robin Hood guarantee: key would be here */

        pos = (pos + 1) & mask;
        dist++;
    }
}

/* Capacity helper */
static size_t next_power_of_two(size_t n) {
    size_t p = 1;
    while (p < n) {
        if (p > SIZE_MAX / 2) return 0;   /* Overflow */
        p *= 2;
    }

    return p;
}

/* Create new hash map */
hashmap_t *hashmap_create(size_t initial_capacity) {
    if (initial_capacity == 0)
        initial_capacity = HASHMAP_DEFAULT_CAPACITY;
    else if (initial_capacity < HASHMAP_MIN_CAPACITY)
        initial_capacity = HASHMAP_MIN_CAPACITY;

    size_t cap = next_power_of_two(initial_capacity);
    if (cap == 0) return NULL;

    hashmap_t *map = calloc(1, sizeof(hashmap_t));
    if (!map) return NULL;

    map->slots = calloc(cap, sizeof(hashmap_slot_t));
    if (!map->slots) {
        free(map);
        return NULL;
    }

    map->capacity = cap;
    map->grow_at = cap * HASHMAP_LOAD_PERCENT / 100;

    return map;
}

/* Create hash map with borrowed keys (caller must ensure key lifetimes) */
hashmap_t *hashmap_borrow(size_t initial_capacity) {
    hashmap_t *map = hashmap_create(initial_capacity);
    if (map) map->borrow_keys = true;

    return map;
}

/* Remove all entries without freeing the map itself */
void hashmap_clear(hashmap_t *map, hashmap_free_fn free_fn) {
    if (!map) return;

    for (size_t i = 0; i < map->capacity; i++) {
        hashmap_slot_t *slot = &map->slots[i];
        if (slot->key) {
            if (free_fn && slot->value)
                free_fn(slot->value);
            if (!map->borrow_keys) free(slot->key);
            *slot = (hashmap_slot_t){ 0 };
        }
    }

    map->count = 0;
    map->mod_count++;
}

/* Free hash map and all entries */
void hashmap_free(hashmap_t *map, hashmap_free_fn free_fn) {
    if (!map) return;

    hashmap_clear(map, free_fn);
    free(map->slots);
    free(map);
}

/* Insert or update a key-value pair */
error_t *hashmap_set(hashmap_t *map, const char *key, void *value) {
    if (!map) return ERROR(ERR_INVALID_ARG, "Hash map is NULL");
    if (!key) return ERROR(ERR_INVALID_ARG, "Key is NULL");

    return hashmap_insert(map, key, value, NULL);
}

/* Insert or update, returning the previous value */
error_t *hashmap_put(hashmap_t *map, const char *key, void *value, void **out_prev) {
    if (!map) return ERROR(ERR_INVALID_ARG, "Hash map is NULL");
    if (!key) return ERROR(ERR_INVALID_ARG, "Key is NULL");
    if (!out_prev) return ERROR(ERR_INVALID_ARG, "out_prev is NULL");

    return hashmap_insert(map, key, value, out_prev);
}

/** Get value for key */
void *hashmap_get(const hashmap_t *map, const char *key) {
    if (!map || !key || map->count == 0) return NULL;
    const hashmap_slot_t *slot = hashmap_find(map, key, hash_key(key));

    return slot ? slot->value : NULL;
}

/* Check if key exists */
bool hashmap_has(const hashmap_t *map, const char *key) {
    if (!map || !key || map->count == 0) return false;

    return hashmap_find(map, key, hash_key(key)) != NULL;
}

/* Remove key-value pair */
bool hashmap_remove(hashmap_t *map, const char *key, void **out_old) {
    if (!map || !key || map->count == 0) return false;

    uint32_t h = hash_key(key);
    size_t mask = map->capacity - 1;
    size_t pos = ideal_slot(h, mask);
    size_t dist = 0;

    /* Locate the entry */
    for (;;) {
        hashmap_slot_t *slot = &map->slots[pos];

        if (!slot->key)
            return false;

        if (slot->hash == h && strcmp(slot->key, key) == 0)
            break;   /* Found at pos */

        if (dist > probe_dist(pos, slot->hash, mask))
            return false;

        pos = (pos + 1) & mask;
        dist++;
    }

    /* Harvest value and free key */
    if (out_old) *out_old = map->slots[pos].value;
    if (!map->borrow_keys) free(map->slots[pos].key);

    /*
     * Backward-shift deletion: pull subsequent displaced entries back
     * one slot until we hit an empty slot or one at its ideal position.
     */
    for (;;) {
        size_t next = (pos + 1) & mask;
        hashmap_slot_t *next_slot = &map->slots[next];

        if (!next_slot->key || probe_dist(next, next_slot->hash, mask) == 0)
            break;

        map->slots[pos] = *next_slot;
        pos = next;
    }

    map->slots[pos] = (hashmap_slot_t){ 0 };
    map->count--;
    map->mod_count++;

    return true;
}

/* Get number of entries */
size_t hashmap_size(const hashmap_t *map) {
    return map ? map->count : 0;
}

/* Check if empty */
bool hashmap_is_empty(const hashmap_t *map) {
    return !map || map->count == 0;
}

/* Initialize iterator for hashmap */
void hashmap_iter_init(hashmap_iter_t *iter, const hashmap_t *map) {
    if (!iter) return;

    iter->map = map;
    iter->index = 0;
    iter->snapshot_mod_count = map ? map->mod_count : 0;
}

/* Advance iterator to next entry */
bool hashmap_iter_next(
    hashmap_iter_t *iter,
    const char **out_key,
    void **out_value
) {
    if (!iter || !iter->map) return false;

    const hashmap_t *map = iter->map;

    if (map->mod_count != iter->snapshot_mod_count) {
        fprintf(stderr, "warning: hashmap modified during iteration\n");
        return false;
    }

    while (iter->index < map->capacity) {
        const hashmap_slot_t *slot = &map->slots[iter->index++];
        if (slot->key) {
            if (out_key)   *out_key = slot->key;
            if (out_value) *out_value = slot->value;
            return true;
        }
    }

    return false;
}
