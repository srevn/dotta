/**
 * keymgr.c — Master-key lifecycle and per-operation subkey acquisition
 *
 * Implements the two-tier cache (in-memory slot + on-disk session) and the
 * resolution chain documented in keymgr.h.
 *
 * Internal layout:
 *   - `is_slot_valid` — slot freshness predicate (expiry).
 *   - `evict_slot` / `install_slot` — single chokepoints for slot mutations;
 *     every write to (master_key, has_key, cached_at) goes through one of these.
 *   - `try_memory_hit` / `try_disk_hit` / `prompt_passphrase` /
 *     `derive_and_install` — the four tiers of the resolution decision tree.
 *     Each owns one storage location, one decision.
 *   - `keymgr_resolve` — orchestrator composing the four tiers in memory → disk
 *     → env → prompt order.
 *   - `keymgr_acquire_subkeys` — atomic resolve + derive + wipe-master used by
 *     both encrypt and decrypt so the operation paths only own the (mac, prf) pair.
 *
 * Wipe discipline: every slot eviction, every per-call key intermediate, every
 * error return path scrubs the relevant buffer via `crypto_wipe` (monocypher's
 * primitive, used directly inside the crypto layer; non-crypto layers use
 * `secure_wipe` from `base/secure.h`). Public API symmetry: every entry point
 * either returns `error_t *` with the cleanup-on-error contract, or runs
 * idempotently with no error surface (free, clear).
 */

#include "crypto/keymgr.h"

#include <errno.h>
#include <monocypher.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "base/secure.h"
#include "crypto/cipher.h"
#include "crypto/kdf.h"
#include "crypto/session.h"
#include "sys/passphrase.h"

/**
 * Key manager structure.
 *
 * The epoch, the timeout, and the single in-memory cache slot. Best-effort mlock'd;
 * the much larger Argon2 work area is mlock'd separately by `kdf_master_key`.
 */
struct keymgr {
    /* The repository's epoch and its public fingerprint — set together at create
     * time and by `keymgr_rekey`, never otherwise. The fingerprint is stamped
     * into every blob this keymgr encrypts and checked against every blob it is
     * asked to decrypt. */
    kdf_epoch_t epoch;
    uint8_t epoch_fp[KDF_EPOCH_FP_SIZE];

    int32_t session_timeout;        /* seconds; 0 = always prompt, -1 = never expire */

    /* Cache slot. */
    bool has_key;
    uint8_t master_key[KDF_KEY_SIZE];
    time_t cached_at;               /* CLOCK_MONOTONIC seconds; 0 if !has_key */

    bool mlocked;
};

/**
 * Monotonic timestamp in seconds — used for in-memory cache expiry so the user
 * cannot stretch cache lifetime by skewing the wall clock. The on-disk cache
 * uses wall-clock instead (must survive reboots, which reset CLOCK_MONOTONIC).
 */
static time_t get_monotonic_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        /* Falls back to wall-clock so a malfunctioning monotonic clock degrades
         * gracefully rather than crashing. Should not happen on any modern POSIX
         * system. */
        return time(NULL);
    }
    return ts.tv_sec;
}

/**
 * Is the in-memory slot a valid hit?
 *
 * `session_timeout == 0` (always-prompt) treats the slot as already-expired;
 * `session_timeout < 0` (never-expire) skips the elapsed-time check.
 */
static bool is_slot_valid(const keymgr *km) {
    if (!km->has_key) {
        return false;
    }
    if (km->session_timeout == 0) {
        return false;
    }
    if (km->session_timeout < 0) {
        return true;
    }
    const time_t now = get_monotonic_time();
    const time_t elapsed = now - km->cached_at;
    return elapsed < km->session_timeout;
}

/**
 * Evict the in-memory slot. Scrubs the master key and resets every cache field
 * to its post-`calloc` state. Idempotent.
 */
static void evict_slot(keymgr *km) {
    crypto_wipe(km->master_key, sizeof(km->master_key));
    km->has_key = false;
    km->cached_at = 0;
}

/**
 * Install a freshly resolved master key into the slot.
 *
 * Caller must evict any prior occupant first — calling over a non-empty slot
 * leaks the old key.
 */
static void install_slot(
    keymgr *km,
    const uint8_t master_key[KDF_KEY_SIZE]
) {
    memcpy(km->master_key, master_key, KDF_KEY_SIZE);
    km->cached_at = get_monotonic_time();
    km->has_key = true;
}

/**
 * Bind the keymgr to an epoch: the copy, and the fingerprint every blob is stamped
 * with and checked against. The one writer of both fields.
 */
static void bind_epoch(keymgr *km, const kdf_epoch_t *epoch) {
    km->epoch = *epoch;
    kdf_epoch_fingerprint(&km->epoch, km->epoch_fp);
}

error_t *keymgr_create(
    int32_t session_timeout,
    const kdf_epoch_t *epoch,
    keymgr **out
) {
    CHECK_NULL(epoch);
    CHECK_NULL(out);

    keymgr *km = calloc(1, sizeof(*km));
    if (!km) {
        return ERROR(ERR_MEMORY, "Failed to allocate key manager");
    }

    /* calloc zeroed every field; only the binding needs assignment. */
    km->session_timeout = session_timeout;
    bind_epoch(km, epoch);

    /* Best-effort mlock to keep the cached master off swap. Failure is non-fatal;
     * the advisory is process-wide so the user sees one warning regardless of
     * which subsystem hit RLIMIT_MEMLOCK. */
    if (mlock(km, sizeof(*km)) == 0) {
        km->mlocked = true;
    } else {
        secure_mlock_warn(
            errno, "%zu-byte master-key cache slot", sizeof(*km)
        );
    }

    *out = km;
    return NULL;
}

void keymgr_free(keymgr *km) {
    if (!km) {
        return;
    }
    evict_slot(km);
    if (km->mlocked) {
        munlock(km, sizeof(*km));
        km->mlocked = false;
    }
    free(km);
}

/*
 * Resolution decision tree. Four tiers, each owning one storage location and
 * one decision:
 *
 *   try_memory_hit     — in-memory slot   (fast path)
 *   try_disk_hit       — on-disk session  (process-fresh warm path)
 *   prompt_passphrase  — env or TTY       (cold path)
 *   derive_and_install — Argon2id + slot + disk save
 *
 * `keymgr_resolve` is the orchestrator that composes them in order.
 */

/**
 * Tier 1: in-memory cache hit.
 *
 * Hit copies the master key to `out_master_key`. On miss, an expired occupant
 * is evicted so the caller can install fresh material. Never writes to
 * `out_master_key` on miss.
 */
static bool try_memory_hit(
    keymgr *km,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    if (is_slot_valid(km)) {
        memcpy(out_master_key, km->master_key, KDF_KEY_SIZE);
        return true;
    }
    if (km->has_key) {
        evict_slot(km);
    }
    return false;
}

/**
 * Tier 2: on-disk session cache hit.
 *
 * Hit copies the master to `out_master_key` AND installs it into the in-memory
 * slot. Miss covers cache-disabled, file missing, expired, MAC failure, wrong
 * perms, or a file recording a pair that is not the epoch's — one written by a
 * build before the epoch owned the pair. Transient I/O failure surfaces a stderr
 * advisory and counts as a miss. On miss `out_master_key` is scrubbed.
 */
static bool try_disk_hit(
    keymgr *km,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    if (km->session_timeout == 0) {
        /* Always-prompt mode: file never exists (gated in derive_and_install);
         * skipping the load avoids a syscall. */
        return false;
    }

    uint16_t loaded_memory_mib = 0;
    uint8_t loaded_passes = 0;
    error_t *err = session_load(
        out_master_key, &loaded_memory_mib, &loaded_passes, km->epoch.salt
    );

    if (err == NULL) {
        if (loaded_memory_mib == km->epoch.memory_mib
            && loaded_passes == km->epoch.passes) {
            install_slot(km, out_master_key);
            return true;
        }
        crypto_wipe(out_master_key, KDF_KEY_SIZE);
        return false;
    }

    if (err->code == ERR_NOT_FOUND || err->code == ERR_CRYPTO) {
        /* Expected misses: missing, expired, tampered, wrong perms. session_load
         * already unlinked unrecoverable files and scrubbed `out_master_key`
         * per its own contract. */
        error_free(err);
        return false;
    }

    /* Unexpected I/O failure. Warn but keep the file — a flaky disk should not
     * destroy the cache. session_load already wiped `out_master_key`. */
    fprintf(
        stderr, "Warning: Failed to load session cache: %s\n",
        error_message(err)
    );
    error_free(err);

    return false;
}

/**
 * Tier 3: acquire passphrase via env var or interactive prompt.
 *
 * On success `*out_passphrase` is a heap-allocated, mlock'd buffer the caller
 * releases via `buffer_secure_free(passphrase, *out_passphrase_len + 1)` (the
 * `+1` accounts for the NUL both backends append).
 *
 * A successful env-var read prints a stderr advisory; the interactive prompt
 * runs only when the env var is unset and disables echo around the read. All
 * errors are wrapped under "Failed to get passphrase".
 */
static error_t *prompt_passphrase(
    char **out_passphrase,
    size_t *out_passphrase_len
) {
    error_t *err = passphrase_from_env(out_passphrase, out_passphrase_len);

    if (err == NULL) {
        /* Env-var advisory: env-var passphrases are a legitimate but weaker
         * automation contract; warn rather than error. */
        fprintf(
            stderr,
            "Warning: Using passphrase from DOTTA_ENCRYPTION_PASSPHRASE environment variable\n"
            "         This is insecure - environment variables can leak in process listings\n"
            "         and are inherited by child processes. Use interactive prompt instead.\n"
        );
        return NULL;
    }

    if (err->code != ERR_NOT_FOUND) {
        /* Env-read failed for some reason other than "not set" — surface it;
         * falling back to the prompt would mask a real underlying problem. */
        return error_wrap(err, "Failed to get passphrase");
    }

    /* Env var unset — fall back to the interactive TTY prompt. */
    error_free(err);
    err = passphrase_prompt(
        "Enter encryption passphrase: ", out_passphrase, out_passphrase_len
    );
    if (err) {
        return error_wrap(err, "Failed to get passphrase");
    }

    return NULL;
}

/**
 * Tier 4: derive the master under the epoch; install in the slot and persist to
 * the on-disk session cache — except under always-prompt mode, where the master
 * must not outlive one operation.
 *
 * Slot must already be empty (caller evicts). On success `out_master_key` holds
 * the derived master. Slot/disk state branches on session_timeout:
 *   - `session_timeout != 0`: slot mirrors `out_master_key`; the on-disk cache
 *     is written. `session_save` failures are non-fatal — the in-memory slot is
 *     authoritative for this process.
 *   - `session_timeout == 0` (always-prompt): slot stays empty; disk is not
 *     touched. The caller's wipe path bounds the master's lifetime to a single
 *     operation, honoring the user's opt-out.
 *
 * On failure the buffer is wiped (`kdf_master_key`'s contract) and the slot is
 * unchanged.
 */
static error_t *derive_and_install(
    keymgr *km,
    const uint8_t *passphrase,
    size_t passphrase_len,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    error_t *err = kdf_master_key(
        passphrase, passphrase_len, &km->epoch, out_master_key
    );
    if (err) {
        return error_wrap(err, "Failed to derive encryption key");
    }

    /* Always-prompt mode: hand the master back via out_master_key for one-shot
     * use, but skip the slot install AND the disk cache. The caller's wipe
     * (keymgr_acquire_subkeys → wipe master after subkey derivation) is the
     * master's full lifetime in this mode. */
    if (km->session_timeout == 0) {
        return NULL;
    }

    install_slot(km, out_master_key);

    error_t *save_err = session_save(
        out_master_key, km->epoch.memory_mib, km->epoch.passes,
        km->epoch.salt, km->session_timeout
    );
    if (save_err) {
        /* Non-fatal. The in-memory slot is authoritative for this process; failing
         * to persist the cache only costs a re-prompt in the next process. */
        fprintf(
            stderr, "Warning: Failed to save session cache: %s\n",
            error_message(save_err)
        );
        error_free(save_err);
    }

    return NULL;
}

/**
 * Resolve the master key.
 *
 * Composition of the four tier helpers in memory → disk → env/TTY → derive order.
 * On error `out_master_key` holds nothing derived: the tiers that write it scrub
 * it on their own failure, and the prompt never writes it.
 */
static error_t *keymgr_resolve(
    keymgr *km,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(km);
    CHECK_NULL(out_master_key);

    if (try_memory_hit(km, out_master_key)) {
        return NULL;
    }
    if (try_disk_hit(km, out_master_key)) {
        return NULL;
    }

    char *passphrase = NULL;
    size_t passphrase_len = 0;
    error_t *err = prompt_passphrase(&passphrase, &passphrase_len);
    if (err) {
        return err;
    }

    err = derive_and_install(
        km, (const uint8_t *) passphrase, passphrase_len, out_master_key
    );

    /* Wipe and free the passphrase regardless of derivation outcome. Both backends
     * return a buffer of `passphrase_len + 1` bytes (NUL-terminated, mlock'd). */
    buffer_secure_free(passphrase, passphrase_len + 1);

    return err;
}

/**
 * Resolve the master key, derive (mac_key, prf_key) for a profile, and scrub
 * the master copy before return.
 *
 * Both encrypt and decrypt go through this single entry point so the master-key
 * lifetime is owned in one place. The caller wipes (mac_key, prf_key) after
 * per-operation use; this helper guarantees only that the master never leaks
 * past its boundary.
 */
static error_t *keymgr_acquire_subkeys(
    keymgr *km,
    const char *profile,
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
) {
    uint8_t master_key[KDF_KEY_SIZE];
    error_t *err = keymgr_resolve(km, master_key);
    if (err) {
        return err;
    }

    kdf_siv_subkeys(master_key, profile, out_mac_key, out_prf_key);
    crypto_wipe(master_key, sizeof(master_key));

    return NULL;
}

error_t *keymgr_set_passphrase(
    keymgr *km,
    const uint8_t *passphrase,
    size_t passphrase_len
) {
    CHECK_NULL(km);
    CHECK_NULL(passphrase);
    if (passphrase_len == 0) {
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    /* Stage the new master locally so a derivation failure cannot leave a half-key
     * in the slot — evict and install only on success. */
    uint8_t new_master[KDF_KEY_SIZE];
    error_t *err = kdf_master_key(
        passphrase, passphrase_len, &km->epoch, new_master
    );
    if (err) {
        return error_wrap(err, "Failed to derive encryption key");
    }

    /* Always-prompt mode: derivation succeeded, which validates the passphrase,
     * but the master must not survive past return — neither in the slot nor on
     * disk. */
    if (km->session_timeout == 0) {
        evict_slot(km);
        crypto_wipe(new_master, sizeof(new_master));
        return NULL;
    }

    evict_slot(km);
    install_slot(km, new_master);

    /* Persist to disk so the next process inherits the cached key. */
    error_t *save_err = session_save(
        new_master, km->epoch.memory_mib, km->epoch.passes,
        km->epoch.salt, km->session_timeout
    );
    if (save_err) {
        fprintf(
            stderr, "Warning: Failed to save session cache: %s\n",
            error_message(save_err)
        );
        error_free(save_err);
    }

    crypto_wipe(new_master, sizeof(new_master));

    return NULL;
}

void keymgr_clear(keymgr *km) {
    if (!km) {
        return;
    }

    evict_slot(km);
    session_clear();
}

void keymgr_rekey(keymgr *km, const kdf_epoch_t *epoch) {
    if (!km || !epoch) {
        return;
    }

    /* The cached master derives from the old epoch — evict before re-binding.
     * The on-disk cache is unlinked eagerly; its MAC absorbs the salt, so a stale
     * file would fail-and-unlink lazily anyway (crypto/session.h). */
    evict_slot(km);
    bind_epoch(km, epoch);
    session_clear();
}

const kdf_epoch_t *keymgr_epoch(const keymgr *km) {
    return &km->epoch;
}

bool keymgr_probe_key(keymgr *km) {
    if (!km) {
        return false;
    }

    if (is_slot_valid(km)) {
        return true;
    }

    /* Skip disk in always-prompt mode (the file never exists either;
     * the double-gate is cheap). */
    if (km->session_timeout == 0) {
        return false;
    }

    uint8_t loaded[KDF_KEY_SIZE];
    uint16_t loaded_memory_mib = 0;
    uint8_t loaded_passes = 0;
    error_t *err = session_load(
        loaded, &loaded_memory_mib, &loaded_passes, km->epoch.salt
    );
    if (err) {
        /* ERR_NOT_FOUND, ERR_CRYPTO, ERR_FS — all "no key available without
         * prompting". Forget the error; probe is a boolean question. */
        error_free(err);
        return false;
    }

    if (loaded_memory_mib != km->epoch.memory_mib
        || loaded_passes != km->epoch.passes) {
        /* A file from before the epoch owned the pair: not this epoch's master. */
        crypto_wipe(loaded, sizeof(loaded));
        return false;
    }

    /* Disk hit. Promote into the in-memory slot, evicting any expired occupant
     * first (install_slot's precondition). */
    if (km->has_key) {
        evict_slot(km);
    }
    install_slot(km, loaded);
    crypto_wipe(loaded, sizeof(loaded));

    return true;
}

int64_t keymgr_time_until_expiry(
    const keymgr *km,
    time_t *out_expires_at
) {
    if (!km || !km->has_key) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return 0;
    }

    if (km->session_timeout < 0) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return -1;
    }

    if (km->session_timeout == 0) {
        /* Always-prompt mode: surface "0 seconds remaining" so the UI renders
         * "expired" rather than "indefinite". */
        if (out_expires_at) {
            *out_expires_at = time(NULL);
        }
        return 0;
    }

    const time_t now_monotonic = get_monotonic_time();
    const time_t elapsed = now_monotonic - km->cached_at;
    int64_t remaining = (int64_t) (km->session_timeout - elapsed);
    if (remaining < 0) {
        remaining = 0;
    }

    if (out_expires_at) {
        /* Convert to wall-clock for display: monotonic and wall-clock have
         * different epochs, so add `remaining` to time(NULL) rather than mixing
         * `cached_at` directly. */
        *out_expires_at = time(NULL) + remaining;
    }

    return remaining;
}

error_t *keymgr_encrypt(
    keymgr *km,
    const char *profile,
    const char *storage_path,
    const uint8_t *plaintext,
    size_t plaintext_len,
    buffer_t *out_ciphertext
) {
    CHECK_NULL(km);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_ciphertext);

    /* cipher_encrypt clears this too, but the resolve stands in front of it and
     * can refuse. */
    *out_ciphertext = (buffer_t){ 0 };

    uint8_t mac_key[KDF_KEY_SIZE];
    uint8_t prf_key[KDF_KEY_SIZE];

    error_t *err = keymgr_acquire_subkeys(km, profile, mac_key, prf_key);
    if (err) {
        return err;
    }

    err = cipher_encrypt(
        plaintext, plaintext_len,
        mac_key, prf_key,
        storage_path,
        km->epoch_fp,
        out_ciphertext
    );

    /* Wipe on every path; otherwise 64 bytes of subkey material survive on the
     * stack until the frame is overwritten. */
    crypto_wipe(mac_key, sizeof(mac_key));
    crypto_wipe(prf_key, sizeof(prf_key));

    return err;
}

error_t *keymgr_decrypt(
    keymgr *km,
    const char *profile,
    const char *storage_path,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    buffer_t *out_plaintext
) {
    CHECK_NULL(km);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(ciphertext);
    CHECK_NULL(out_plaintext);

    /* cipher_decrypt clears this too, but the epoch gate below stands in front
     * of it and can refuse. */
    *out_plaintext = (buffer_t){ 0 };

    /* Epoch gate: a foreign fingerprint means no passphrase can ever verify here
     * — the master would derive under a different epoch — so refuse up front
     * with the precise fact instead of prompting and then reporting a misleading
     * SIV authentication failure. Parse-level refusals (bad magic, a version
     * this build does not read) pass through with their own words. Public identity,
     * plain memcmp. */
    uint8_t blob_fp[KDF_EPOCH_FP_SIZE];
    error_t *err = cipher_read_header(ciphertext, ciphertext_len, blob_fp);
    if (err) {
        return err;
    }
    if (memcmp(blob_fp, km->epoch_fp, KDF_EPOCH_FP_SIZE) != 0) {
        return ERROR(
            ERR_CRYPTO,
            "Encrypted under a different repository epoch; this repository's "
            "keys can never decrypt it"
        );
    }

    uint8_t mac_key[KDF_KEY_SIZE];
    uint8_t prf_key[KDF_KEY_SIZE];

    err = keymgr_acquire_subkeys(km, profile, mac_key, prf_key);
    if (err) {
        return err;
    }

    err = cipher_decrypt(
        ciphertext, ciphertext_len,
        mac_key, prf_key,
        storage_path,
        out_plaintext
    );

    crypto_wipe(mac_key, sizeof(mac_key));
    crypto_wipe(prf_key, sizeof(prf_key));

    return err;
}
