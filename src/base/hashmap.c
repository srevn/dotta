/**
 * hashmap.c - Robin Hood hash table implementation
 *
 * Open addressing with linear probing and Robin Hood displacement. Backward-shift
 * deletion keeps the table tombstone-free.
 *
 * Slot layout:
 *   key != NULL  →  occupied (key is owned or borrowed per borrow_keys flag)
 *   key == NULL  →  empty
 *
 * Hash: FNV-1a (64-bit compute, XOR-folded to 32-bit for compact slots). Capacity:
 * always a power of two for fast masking. The map, its slots and every owned
 * key are its arena's, which dies rather than answer NULL (base/arena.h).
 */

#include "base/hashmap.h"

#include <stdint.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/heap.h"

/* Default initial capacity (must be power of 2 for fast modulo) */
#define HASHMAP_DEFAULT_CAPACITY    16
#define HASHMAP_MIN_CAPACITY        4      /* Floor to avoid degenerate grow_at */
#define HASHMAP_LOAD_PERCENT        75     /* Resize at 75% occupancy */

/* FNV-1a 64-bit parameters */
#define FNV_OFFSET  14695981039346656037ULL
#define FNV_PRIME   1099511628211ULL

/* Slot */
typedef struct {
    char *key;          /* NULL = empty slot; the arena's or borrowed per map->borrow_keys */
    void *value;
    uint32_t hash;      /* Cached XOR-folded 32 bits of FNV-1a */
} hashmap_slot_t;

/* Map */
struct hashmap {
    arena_t *arena;             /* Where the map, its slots and its owned keys live */
    hashmap_slot_t *slots;
    size_t capacity;            /* Always power of 2 */
    size_t count;               /* Number of occupied slots */
    size_t grow_at;             /* count threshold triggering resize */
    uint64_t mod_count;         /* Mutation counter for iterator safety */
    bool borrow_keys;           /* If true: keys stored by reference, not copied */
};

/* FNV-1a over a key's `len` bytes: a whole key hashes its strlen, a span its own */
static uint32_t hash_key(const char *key, size_t len) {
    uint64_t hash = FNV_OFFSET;
    const unsigned char *bytes = (const unsigned char *) key;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
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

/* Internal: grow. The capacity's slots stand in memory, so its double cannot
 * wrap; the double's bytes can, and the arena judges them. The old slots are
 * abandoned to the arena once every entry has moved. */
static void hashmap_grow(hashmap_t *map) {
    size_t new_cap = map->capacity * 2;
    hashmap_slot_t *new_slots = arena_calloc(map->arena, new_cap, sizeof(hashmap_slot_t));

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

    arena_abandon(map->arena, old_slots, old_cap * sizeof(hashmap_slot_t));
    map->mod_count++;
}

/**
 * The slot `key` already holds, or NULL once `key` → `value` took one
 *
 * The one probe every writer makes: set and put replace the value of the slot
 * it answers, add leaves it — so a key is found or placed in a single walk,
 * whichever the writer then does with it.
 *
 * @param map   Target map
 * @param key   Caller's key (const — copied into the arena if a slot is taken)
 * @param value Value a new slot is given; a held slot's is untouched here
 */
static hashmap_slot_t *hashmap_insert(hashmap_t *map, const char *key, void *value) {
    /* Grow before insert so there is always at least one empty slot */
    if (map->count >= map->grow_at) {
        hashmap_grow(map);
    }

    uint32_t h = hash_key(key, strlen(key));
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
                carry_key = map->borrow_keys ? (char *) key : arena_strdup(map->arena, key);
            }
            slot->key = carry_key;
            slot->value = carry_val;
            slot->hash = carry_h;
            map->count++;
            map->mod_count++;
            return NULL;
        }

        /* Exact match — the writer decides the value. Never after a swap: the
         * Robin Hood order puts a held key before any slot richer than it, so a
         * walk that has displaced an entry already knows the key is not here. */
        if (slot->hash == h && strcmp(slot->key, key) == 0) {
            return slot;
        }

        /* Robin Hood: displace richer entries */
        size_t existing = probe_dist(pos, slot->hash, mask);
        if (dist > existing) {
            if (!carry_key) {
                carry_key = map->borrow_keys ? (char *) key : arena_strdup(map->arena, key);
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
 * Find a slot by the key spelled by `key`'s first `len` bytes.
 *
 * Returns pointer to the occupied slot, or NULL if absent. Uses Robin Hood early
 * termination: if our probe distance exceeds the slot's, the key cannot be present.
 * A slot matches only a key exactly `len` bytes long, so a span that is a prefix
 * of a held key finds nothing: strncmp stops at the held key's end, and the byte
 * after the span must be that end.
 */
static const hashmap_slot_t *hashmap_slot(
    const hashmap_t *map,
    const char *key,
    size_t len
) {
    const uint32_t h = hash_key(key, len);
    size_t mask = map->capacity - 1;
    size_t pos = ideal_slot(h, mask);
    size_t dist = 0;

    for (;;) {
        const hashmap_slot_t *slot = &map->slots[pos];

        if (!slot->key)
            return NULL;

        if (slot->hash == h && strncmp(slot->key, key, len) == 0 && slot->key[len] == '\0')
            return slot;

        if (dist > probe_dist(pos, slot->hash, mask))
            return NULL;     /* Robin Hood guarantee: key would be here */

        pos = (pos + 1) & mask;
        dist++;
    }
}

/* Capacity helper: a power of two no size can hold is a table no memory could */
static size_t next_power_of_two(size_t n) {
    size_t p = 1;
    while (p < n) {
        if (p > SIZE_MAX / 2) heap_die(SIZE_MAX);
        p *= 2;
    }

    return p;
}

/* Slots needed to hold `expected` entries without a resize.
 *
 * The caller counts entries; only this file knows what an entry costs in slots.
 * hashmap_insert grows once count reaches grow_at, so a table sized at the caller's
 * number outright would rehash on the way to filling it — the hint asked for
 * room and bought a resize. Dividing by the load factor first is what makes the
 * number mean what the header says it means, and it lands on the same capacity
 * the map would have reached by growing into those entries, so an honest hint
 * costs no memory and saves the rehash. */
static size_t slots_for(size_t expected) {
    if (expected == 0) {
        return HASHMAP_DEFAULT_CAPACITY;
    }

    /* Guard the multiply and its rounding term. A count that wraps them is a
     * table no memory could hold — exhaustion, never a small capacity: a mask
     * that does not cover the slots loses entries in silence. */
    if (expected > (SIZE_MAX - (HASHMAP_LOAD_PERCENT - 1)) / 100) {
        heap_die(SIZE_MAX);
    }

    size_t needed = (expected * 100 + HASHMAP_LOAD_PERCENT - 1)
        / HASHMAP_LOAD_PERCENT;

    size_t cap = next_power_of_two(needed);
    if (cap < HASHMAP_MIN_CAPACITY) {
        cap = HASHMAP_MIN_CAPACITY;
    }

    return cap;
}

/* Create new hash map */
hashmap_t *hashmap_create(arena_t *arena, size_t expected) {
    CHECK_NULL(arena);

    size_t cap = slots_for(expected);

    hashmap_t *map = arena_calloc(arena, 1, sizeof(hashmap_t));
    map->arena = arena;
    map->slots = arena_calloc(arena, cap, sizeof(hashmap_slot_t));
    map->capacity = cap;
    map->grow_at = cap * HASHMAP_LOAD_PERCENT / 100;

    return map;
}

/* Create hash map with borrowed keys (caller must ensure key lifetimes) */
hashmap_t *hashmap_borrow(arena_t *arena, size_t expected) {
    hashmap_t *map = hashmap_create(arena, expected);
    map->borrow_keys = true;

    return map;
}

/* Remove all entries; the keys and the slots are the arena's */
void hashmap_clear(hashmap_t *map, hashmap_free_fn free_fn) {
    if (!map) return;

    for (size_t i = 0; i < map->capacity; i++) {
        hashmap_slot_t *slot = &map->slots[i];
        if (slot->key) {
            if (free_fn && slot->value)
                free_fn(slot->value);
            *slot = (hashmap_slot_t){ 0 };
        }
    }

    map->count = 0;
    map->mod_count++;
}

/* Insert or update a key-value pair */
void hashmap_set(hashmap_t *map, const char *key, void *value) {
    CHECK_NULL(map);
    CHECK_NULL(key);

    /* No mod_count bump on an update: a value-only write is not structural */
    hashmap_slot_t *held = hashmap_insert(map, key, value);
    if (held) held->value = value;
}

/* Insert or update, returning the previous value */
void hashmap_put(hashmap_t *map, const char *key, void *value, void **out_prev) {
    CHECK_NULL(map);
    CHECK_NULL(key);
    CHECK_NULL(out_prev);

    hashmap_slot_t *held = hashmap_insert(map, key, value);
    *out_prev = held ? held->value : NULL;
    if (held) held->value = value;
}

/* Insert a key that is not there yet */
bool hashmap_add(hashmap_t *map, const char *key, void *value) {
    CHECK_NULL(map);
    CHECK_NULL(key);

    return hashmap_insert(map, key, value) == NULL;
}

/** Get value for key */
void *hashmap_get(const hashmap_t *map, const char *key) {
    if (!map || !key) return NULL;

    return hashmap_get_n(map, key, strlen(key));
}

/* Get value for the key the span spells */
void *hashmap_get_n(const hashmap_t *map, const char *key, size_t len) {
    if (!map || !key || map->count == 0) return NULL;
    const hashmap_slot_t *slot = hashmap_slot(map, key, len);

    return slot ? slot->value : NULL;
}

/* Look up a key, telling absence from a NULL value */
bool hashmap_find(const hashmap_t *map, const char *key, void **out) {
    CHECK_NULL(out);
    if (!map || !key || map->count == 0) return false;

    const hashmap_slot_t *slot = hashmap_slot(map, key, strlen(key));
    if (!slot) return false;

    *out = slot->value;
    return true;
}

/* Check if key exists */
bool hashmap_has(const hashmap_t *map, const char *key) {
    if (!map || !key || map->count == 0) return false;

    return hashmap_slot(map, key, strlen(key)) != NULL;
}

/* Remove key-value pair */
bool hashmap_remove(hashmap_t *map, const char *key, void **out_old) {
    if (!map || !key || map->count == 0) return false;

    uint32_t h = hash_key(key, strlen(key));
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

    /* Harvest value; an owned key stays the arena's */
    if (out_old) *out_old = map->slots[pos].value;

    /*
     * Backward-shift deletion: pull subsequent displaced entries back one slot
     * until we hit an empty slot or one at its ideal position.
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

/* Get number of slots */
size_t hashmap_capacity(const hashmap_t *map) {
    return map ? map->capacity : 0;
}

/* Check if empty */
bool hashmap_is_empty(const hashmap_t *map) {
    return !map || map->count == 0;
}

/* Initialize iterator for hashmap */
void hashmap_iter_init(hashmap_iter_t *iter, const hashmap_t *map) {
    CHECK_NULL(iter);

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
    CHECK_NULL(iter);
    if (!iter->map) return false;

    const hashmap_t *map = iter->map;
    CHECK_ARG(
        map->mod_count == iter->snapshot_mod_count, "a map was modified while it was iterated"
    );

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
