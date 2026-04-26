/**
 * keymgr.c - Encryption key management implementation
 */

#include "crypto/keymgr.h"

#include <config.h>
#include <errno.h>
#include <hydrogen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "crypto/balloon.h"
#include "crypto/cipher.h"
#include "crypto/kdf.h"
#include "crypto/passphrase.h"
#include "crypto/session.h"

/**
 * Key manager structure
 *
 * Holds derivation parameters (a balloon_params_t snapshot taken from
 * config at create time) plus the cached master key and its lifecycle
 * metadata. The struct is mlock'd best-effort so the master key cannot
 * be paged out of this process; the much larger balloon buffer used
 * during derivation is mlock'd separately by balloon_derive itself.
 */
struct keymgr {
    /* Configuration snapshot. */
    balloon_params_t params;
    int32_t session_timeout;  /* seconds; 0 = always prompt, -1 = never expire */

    /* Cached master key. */
    uint8_t master_key[KDF_KEY_SIZE];
    bool has_key;
    time_t cached_at;         /* monotonic time, 0 if not cached */
    bool mlocked;
};

/**
 * Get monotonic timestamp in seconds.
 *
 * Returns seconds since an arbitrary epoch (typically system boot).
 * Unlike time(NULL), this is not affected by system clock changes, NTP
 * adjustments, or timezone modifications. Used for in-memory cache
 * expiry so the user can't bend cache lifetime by skewing the clock.
 *
 * The file-based cache still uses wall-clock time (monotonic time
 * resets on reboot, which would make the on-disk cache unreadable
 * after a reboot — which is not what users expect).
 */
static time_t get_monotonic_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        /* Should never happen on modern POSIX. Falls back to wall-clock so
         * a malfunctioning monotonic clock degrades gracefully. */
        return time(NULL);
    }
    return ts.tv_sec;
}

error_t *keymgr_create(
    const config_t *config,
    keymgr **out
) {
    CHECK_NULL(config);
    CHECK_NULL(out);

    keymgr *keymgr = calloc(1, sizeof(*keymgr));
    if (!keymgr) {
        return ERROR(ERR_MEMORY, "Failed to allocate key manager");
    }

    /* calloc zeroed the struct, so master_key, has_key, cached_at, and
     * mlocked are already in their initial state — only the configuration
     * snapshot needs explicit assignment. */
    keymgr->params = (balloon_params_t){
        .memlimit_bytes = config->encryption_memlimit,
        .rounds = BALLOON_DEFAULT_ROUNDS,
        .delta = BALLOON_DEFAULT_DELTA,
    };
    keymgr->session_timeout = config->session_timeout;

    /* Best-effort mlock the keymgr struct so the cached master key cannot
     * be paged out of this process. Failure is non-fatal — the much larger
     * balloon buffer in derivation has its own warning, so this one fires
     * separately for the same RLIMIT_MEMLOCK reason. */
    if (mlock(keymgr, sizeof(*keymgr)) == 0) {
        keymgr->mlocked = true;
    } else {
        fprintf(
            stderr,
            "Warning: Failed to lock keymgr memory: %s\n"
            "         Master key may be paged to disk.\n"
            "         Raise RLIMIT_MEMLOCK (ulimit -l) or run with\n"
            "         elevated privileges to enable this protection.\n",
            strerror(errno)
        );
    }

    *out = keymgr;
    return NULL;
}

void keymgr_free(keymgr *keymgr) {
    if (!keymgr) {
        return;
    }

    /* Securely zero master key before freeing. */
    hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
    keymgr->has_key = false;
    keymgr->cached_at = 0;

    if (keymgr->mlocked) {
        munlock(keymgr, sizeof(*keymgr));
        keymgr->mlocked = false;
    }

    free(keymgr);
}

/**
 * Check if cached key is expired.
 *
 * Uses monotonic clock so cache lifetime can't be manipulated via
 * system clock changes.
 */
static bool is_key_valid(const keymgr *keymgr) {
    if (!keymgr->has_key) {
        return false;
    }
    if (keymgr->session_timeout == 0) {
        /* Always-prompt mode: in-memory cache is treated as already expired. */
        return false;
    }
    if (keymgr->session_timeout < 0) {
        /* Never-expire mode. */
        return true;
    }
    time_t now = get_monotonic_time();
    time_t elapsed = now - keymgr->cached_at;
    return elapsed < keymgr->session_timeout;
}

bool keymgr_probe_key(keymgr *keymgr) {
    if (!keymgr) {
        return false;
    }

    /* In-memory cache. */
    if (is_key_valid(keymgr)) {
        return true;
    }

    /* Disk session cache (skip in always-prompt mode). */
    if (keymgr->session_timeout == 0) {
        return false;
    }

    error_t *err = session_load(keymgr->master_key);
    if (err) {
        error_free(err);
        return false;
    }

    keymgr->has_key = true;
    keymgr->cached_at = get_monotonic_time();
    return true;
}

int64_t keymgr_time_until_expiry(
    const keymgr *keymgr,
    time_t *out_expires_at
) {
    if (!keymgr || !keymgr->has_key) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return 0;
    }

    if (keymgr->session_timeout < 0) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return -1;
    }

    if (keymgr->session_timeout == 0) {
        if (out_expires_at) {
            *out_expires_at = time(NULL);  /* Already expired. */
        }
        return 0;
    }

    /* Positive timeout — use monotonic delta. */
    time_t now_monotonic = get_monotonic_time();
    time_t elapsed = now_monotonic - keymgr->cached_at;
    int64_t remaining = (int64_t) (keymgr->session_timeout - elapsed);
    if (remaining < 0) {
        remaining = 0;
    }

    if (out_expires_at) {
        /* Render expiry in wall-clock terms for display. Computing
         * `time(NULL) + remaining` is more accurate than mixing
         * monotonic cached_at into a wall-clock display field. */
        *out_expires_at = time(NULL) + remaining;
    }
    return remaining;
}

void keymgr_clear(keymgr *keymgr) {
    if (!keymgr) {
        return;
    }
    hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
    keymgr->has_key = false;
    keymgr->cached_at = 0;
    session_clear();
}

error_t *keymgr_set_passphrase(
    keymgr *keymgr,
    const char *passphrase,
    size_t passphrase_len
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(passphrase);
    if (passphrase_len == 0) {
        return ERROR(ERR_INVALID_ARG, "Passphrase cannot be empty");
    }

    error_t *err = kdf_master_key(
        passphrase, passphrase_len, keymgr->params, keymgr->master_key
    );
    if (err) {
        hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
        keymgr->has_key = false;
        return error_wrap(err, "Failed to derive encryption key");
    }

    keymgr->has_key = true;
    keymgr->cached_at = get_monotonic_time();

    /* Save to file cache (non-fatal if it fails — in-memory still works). */
    if (keymgr->session_timeout != 0) {
        error_t *save_err = session_save(keymgr->master_key, keymgr->session_timeout);
        if (save_err) {
            fprintf(
                stderr, "Warning: Failed to save session cache: %s\n",
                error_message(save_err)
            );
            error_free(save_err);
        }
    }

    return NULL;
}

/**
 * Resolve the master key (memory cache → disk session → prompt).
 *
 * Order: in-memory cache, on-disk session file, then interactive prompt
 * (or DOTTA_ENCRYPTION_PASSPHRASE fallback). Caller owns the output
 * buffer and is responsible for zeroing it after use.
 */
static error_t *keymgr_get_key(
    keymgr *keymgr,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(out_master_key);

    /* Step 1: Check in-memory cache. */
    if (is_key_valid(keymgr)) {
        memcpy(out_master_key, keymgr->master_key, KDF_KEY_SIZE);
        return NULL;
    }

    /* Step 2: Try file cache (skip if session_timeout == 0). */
    if (keymgr->session_timeout != 0) {
        error_t *err = session_load(keymgr->master_key);
        if (!err) {
            keymgr->has_key = true;
            keymgr->cached_at = get_monotonic_time();
            memcpy(out_master_key, keymgr->master_key, KDF_KEY_SIZE);
            return NULL;
        }
        if (err->code == ERR_NOT_FOUND || err->code == ERR_CRYPTO) {
            /* Expected: cache absent / expired / corrupted. */
            error_free(err);
        } else {
            /* Unexpected I/O error — warn but continue to prompt. */
            fprintf(
                stderr, "Warning: Failed to load session cache: %s\n",
                error_message(err)
            );
            error_free(err);
        }
    }

    /* Step 3: Prompt for passphrase (env var first, then interactive). */
    char *passphrase = NULL;
    size_t passphrase_len = 0;
    error_t *err = passphrase_from_env(&passphrase, &passphrase_len);

    if (err && err->code == ERR_NOT_FOUND) {
        error_free(err);
        err = passphrase_prompt(
            "Enter encryption passphrase: ", &passphrase, &passphrase_len
        );
    } else if (err == NULL) {
        fprintf(
            stderr,
            "Warning: Using passphrase from DOTTA_ENCRYPTION_PASSPHRASE environment variable\n"
            "         This is insecure - environment variables can leak in process listings\n"
            "         and are inherited by child processes. Use interactive prompt instead.\n"
        );
    }

    if (err) {
        return error_wrap(err, "Failed to get passphrase");
    }

    err = keymgr_set_passphrase(keymgr, passphrase, passphrase_len);

    /* Both passphrase_prompt and passphrase_from_env return a buffer of
     * exactly passphrase_len + 1 bytes (NUL-terminated, mlock'd). */
    buffer_secure_free(passphrase, passphrase_len + 1);

    if (err) {
        return error_wrap(err, "Failed to derive encryption key");
    }

    memcpy(out_master_key, keymgr->master_key, KDF_KEY_SIZE);
    return NULL;
}

/**
 * Derive a profile key from the cached master key.
 *
 * The master key is fetched via keymgr_get_key (in-memory cache, then
 * disk session, then prompt); the derivation itself is a keyed-BLAKE2
 * hash in the microsecond range. The local master-key copy is zeroed
 * before return, so the only remaining key material is the caller's
 * stack buffer — which keymgr_encrypt / keymgr_decrypt zero after their
 * single use.
 */
static error_t *keymgr_get_profile_key(
    keymgr *keymgr,
    const char *profile,
    uint8_t out_profile_key[KDF_KEY_SIZE]
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(profile);
    CHECK_NULL(out_profile_key);

    uint8_t master_key[KDF_KEY_SIZE];
    error_t *err = keymgr_get_key(keymgr, master_key);
    if (err) {
        return error_wrap(err, "Failed to get master key");
    }

    err = kdf_profile_key(master_key, profile, out_profile_key);
    hydro_memzero(master_key, sizeof(master_key));

    if (err) {
        return error_wrap(err, "Failed to derive profile key for '%s'", profile);
    }
    return NULL;
}

/**
 * Resolve (mac_key, prf_key) for a profile in one place.
 *
 * Pulls the master key, derives the profile key, derives the SIV
 * subkeys, then zeroes the intermediate profile key. Both `keymgr_encrypt`
 * and `keymgr_decrypt` go through this so the zeroization sequence is
 * defined once and they only need to wipe the (mac_key, prf_key) pair on
 * exit themselves.
 */
static error_t *keymgr_get_siv_subkeys(
    keymgr *keymgr,
    const char *profile,
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
) {
    uint8_t profile_key[KDF_KEY_SIZE];
    error_t *err = keymgr_get_profile_key(keymgr, profile, profile_key);
    if (err) {
        return err;
    }
    err = kdf_siv_subkeys(profile_key, out_mac_key, out_prf_key);
    hydro_memzero(profile_key, sizeof(profile_key));
    return err;
}

error_t *keymgr_encrypt(
    keymgr *keymgr,
    const char *profile,
    const char *storage_path,
    const unsigned char *plaintext,
    size_t plaintext_len,
    buffer_t *out_ciphertext
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(out_ciphertext);

    uint8_t mac_key[KDF_KEY_SIZE];
    uint8_t prf_key[KDF_KEY_SIZE];

    error_t *err = keymgr_get_siv_subkeys(keymgr, profile, mac_key, prf_key);
    if (err) {
        return error_wrap(err, "Failed to derive SIV subkeys for '%s'", profile);
    }

    err = cipher_encrypt(
        plaintext, plaintext_len, mac_key, prf_key, storage_path, out_ciphertext
    );

    /* Wipe on success and failure: missing the failure-path zeroization
     * would leave 64 bytes of subkey material on the stack until the
     * frame is overwritten. */
    hydro_memzero(mac_key, sizeof(mac_key));
    hydro_memzero(prf_key, sizeof(prf_key));
    return err;
}

error_t *keymgr_decrypt(
    keymgr *keymgr,
    const char *profile,
    const char *storage_path,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    buffer_t *out_plaintext
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(profile);
    CHECK_NULL(storage_path);
    CHECK_NULL(ciphertext);
    CHECK_NULL(out_plaintext);

    uint8_t mac_key[KDF_KEY_SIZE];
    uint8_t prf_key[KDF_KEY_SIZE];

    error_t *err = keymgr_get_siv_subkeys(keymgr, profile, mac_key, prf_key);
    if (err) {
        return error_wrap(err, "Failed to derive SIV subkeys for '%s'", profile);
    }

    err = cipher_decrypt(
        ciphertext, ciphertext_len, mac_key, prf_key, storage_path, out_plaintext
    );

    hydro_memzero(mac_key, sizeof(mac_key));
    hydro_memzero(prf_key, sizeof(prf_key));
    return err;
}
