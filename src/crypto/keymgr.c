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
#include "crypto/encryption.h"
#include "crypto/passphrase.h"
#include "crypto/session.h"

/**
 * Key manager structure
 */
struct keymgr {
    /* Configuration */
    uint64_t opslimit;        /* CPU cost for password hashing */
    size_t memlimit;          /* Memory cost for balloon hashing (0 = disabled) */
    int32_t session_timeout;  /* Timeout in seconds (0 = always prompt, -1 = never expire) */

    /* Cached master key */
    uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
    bool has_key;             /* Is master key cached? */
    time_t cached_at;         /* When was key cached (monotonic time, 0 if not cached) */
    bool mlocked;             /* Is memory locked with mlock()? */
};

/**
 * Get monotonic timestamp in seconds
 *
 * Returns seconds since an arbitrary epoch (typically system boot time).
 * Unlike time(NULL), this is not affected by system clock changes, NTP
 * adjustments, or timezone modifications.
 *
 * This is used for in-memory cache expiry calculations to prevent cache
 * lifetime manipulation via clock changes. The file-based cache still uses
 * wall-clock time (as monotonic time resets on reboot).
 *
 * @return Monotonic timestamp in seconds, or wall-clock time if unavailable
 */
static time_t get_monotonic_time(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        /* Fallback to wall-clock time if CLOCK_MONOTONIC unavailable
         * This should never happen on modern POSIX systems, but provides
         * graceful degradation if it does. */
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

    /* Copy configuration (memlimit: convert MB from config to bytes for crypto) */
    keymgr->opslimit = config->encryption_opslimit;
    keymgr->memlimit = config->encryption_memlimit * 1024 * 1024;
    keymgr->session_timeout = config->session_timeout;

    /* Initialize key state */
    keymgr->has_key = false;
    keymgr->cached_at = 0;
    keymgr->mlocked = false;
    hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));

    /* Attempt to lock memory to prevent swapping to disk
     * This is a best-effort operation - if it fails, we log a warning
     * but continue operation (security enhancement, not requirement) */
    if (mlock(keymgr, sizeof(*keymgr)) == 0) {
        keymgr->mlocked = true;
    } else {
        /* mlock failed - log warning but don't fail initialization
         * Common reasons: insufficient permissions, RLIMIT_MEMLOCK exceeded */
        fprintf(stderr, "Warning: Failed to lock keymgr memory: %s\n", strerror(errno));
        fprintf(stderr, "         Master key may be swapped to disk.\n");
        fprintf(stderr, "         Consider running with elevated privileges\n");
        fprintf(stderr, "         or increasing RLIMIT_MEMLOCK for enhanced security.\n");
    }

    *out = keymgr;
    return NULL;
}

void keymgr_free(keymgr *keymgr) {
    if (!keymgr) {
        return;
    }

    /* Securely zero master key before freeing */
    hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
    keymgr->has_key = false;
    keymgr->cached_at = 0;

    /* Unlock memory if it was locked */
    if (keymgr->mlocked) {
        munlock(keymgr, sizeof(*keymgr));
        keymgr->mlocked = false;
    }

    free(keymgr);
}

/**
 * Check if cached key is expired
 *
 * Uses monotonic clock to prevent cache lifetime manipulation via
 * system clock changes.
 *
 * @param keymgr Key manager (must not be NULL)
 * @return true if key is cached and not expired
 */
static bool is_key_valid(const keymgr *keymgr) {
    if (!keymgr->has_key) {
        return false;
    }

    /* If timeout is 0, always prompt (no caching) */
    if (keymgr->session_timeout == 0) {
        return false;
    }

    /* If timeout is negative, key never expires */
    if (keymgr->session_timeout < 0) {
        return true;
    }

    /* Check if expired (positive timeout) using monotonic clock */
    time_t now = get_monotonic_time();
    time_t elapsed = now - keymgr->cached_at;

    return elapsed < keymgr->session_timeout;
}

bool keymgr_probe_key(keymgr *keymgr) {
    if (!keymgr) {
        return false;
    }

    /* Check in-memory cache first */
    if (is_key_valid(keymgr)) {
        return true;
    }

    /* Try disk session cache (skip if always-prompt mode) */
    if (keymgr->session_timeout == 0) {
        return false;
    }

    error_t *err = session_load(keymgr->master_key);
    if (err) {
        error_free(err);
        return false;
    }

    /* Disk cache loaded successfully - promote to in-memory */
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

    /* Negative timeout = never expires */
    if (keymgr->session_timeout < 0) {
        if (out_expires_at) {
            *out_expires_at = 0;
        }
        return -1;
    }

    /* Timeout of 0 = always prompt (key never valid, always expired) */
    if (keymgr->session_timeout == 0) {
        if (out_expires_at) {
            *out_expires_at = time(NULL);  /* Already expired */
        }
        return 0;
    }

    /* Positive timeout = calculate remaining time using monotonic clock
     * This prevents cache lifetime manipulation via clock changes */
    time_t now_monotonic = get_monotonic_time();
    time_t elapsed = now_monotonic - keymgr->cached_at;
    int64_t remaining = (int64_t) (keymgr->session_timeout - elapsed);

    if (remaining < 0) {
        remaining = 0;
    }

    if (out_expires_at) {
        /* For display purposes, compute wall-clock expiry as current_time + remaining.
         * This is more accurate than using the original cached_at (which is monotonic)
         * and handles clock drift gracefully. */
        *out_expires_at = time(NULL) + remaining;
    }

    return remaining;
}

void keymgr_clear(keymgr *keymgr) {
    if (!keymgr) {
        return;
    }

    /* Securely zero master key */
    hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
    keymgr->has_key = false;
    keymgr->cached_at = 0;

    /* Clear file cache */
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
        return ERROR(
            ERR_INVALID_ARG, "Passphrase cannot be empty"
        );
    }

    /* Derive master key from passphrase */
    error_t *err = encryption_derive_master_key(
        passphrase,
        passphrase_len,
        keymgr->opslimit,
        keymgr->memlimit,
        keymgr->master_key
    );

    if (err) {
        /* Clear key on error */
        hydro_memzero(keymgr->master_key, sizeof(keymgr->master_key));
        keymgr->has_key = false;
        return error_wrap(err, "Failed to derive encryption key");
    }

    /* Mark key as cached (using monotonic time for expiry checks) */
    keymgr->has_key = true;
    keymgr->cached_at = get_monotonic_time();

    /* Save to file cache (non-fatal if fails) */
    if (keymgr->session_timeout != 0) {
        error_t *save_err = session_save(keymgr->master_key, keymgr->session_timeout);
        if (save_err) {
            /* Log warning but don't fail - in-memory cache still works */
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
    uint8_t out_master_key[ENCRYPTION_MASTER_KEY_SIZE]
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(out_master_key);

    /* Step 1: Check in-memory cache */
    if (is_key_valid(keymgr)) {
        memcpy(out_master_key, keymgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);
        return NULL;
    }

    /* Step 2: Try file cache (skip if session_timeout == 0) */
    if (keymgr->session_timeout != 0) {
        error_t *err = session_load(keymgr->master_key);
        if (!err) {
            /* Cache hit! Update in-memory state with current monotonic time.
             * File cache has its own wall-clock expiry check - once loaded,
             * we switch to monotonic time for in-memory expiry. */
            keymgr->has_key = true;
            keymgr->cached_at = get_monotonic_time();
            memcpy(out_master_key, keymgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);
            return NULL;
        }

        /* Cache miss/expired/corrupted - non-fatal, continue to prompt */
        if (err->code == ERR_NOT_FOUND || err->code == ERR_CRYPTO) {
            /* Expected failures (cache doesn't exist, expired, or corrupted) */
            error_free(err);
        } else {
            /* Unexpected error (file I/O) - warn but don't fail */
            fprintf(
                stderr, "Warning: Failed to load session cache: %s\n",
                error_message(err)
            );
            error_free(err);
        }
    }

    /* Step 3: Prompt for passphrase */
    char *passphrase = NULL;
    size_t passphrase_len = 0;
    error_t *err = NULL;

    /* Try environment variable first */
    err = passphrase_from_env(&passphrase, &passphrase_len);

    if (err && err->code == ERR_NOT_FOUND) {
        /* Env var not set - prompt interactively */
        error_free(err);
        err = NULL;

        err = passphrase_prompt(
            "Enter encryption passphrase: ",
            &passphrase,
            &passphrase_len
        );
    } else if (err == NULL) {
        /* Warn user that env var is being used (security risk) */
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

    /* Derive master key */
    err = keymgr_set_passphrase(keymgr, passphrase, passphrase_len);

    /* Securely zero and free passphrase. Both passphrase_prompt and
     * passphrase_from_env return a buffer of exactly
     * passphrase_len + 1 bytes (NUL-terminated, mlock'd). */
    buffer_secure_free(passphrase, passphrase_len + 1);

    if (err) {
        return error_wrap(err, "Failed to derive encryption key");
    }

    /* Copy to output */
    memcpy(out_master_key, keymgr->master_key, ENCRYPTION_MASTER_KEY_SIZE);

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
    uint8_t out_profile_key[ENCRYPTION_PROFILE_KEY_SIZE]
) {
    CHECK_NULL(keymgr);
    CHECK_NULL(profile);
    CHECK_NULL(out_profile_key);

    /* Get master key (may prompt for passphrase) */
    uint8_t master_key[ENCRYPTION_MASTER_KEY_SIZE];
    error_t *err = keymgr_get_key(keymgr, master_key);
    if (err) {
        return error_wrap(err, "Failed to get master key");
    }

    /* Derive profile key from master key */
    err = encryption_derive_profile_key(master_key, profile, out_profile_key);

    /* Clear master key immediately */
    hydro_memzero(master_key, sizeof(master_key));

    if (err) {
        return error_wrap(err, "Failed to derive profile key for '%s'", profile);
    }

    return NULL;
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

    /* Derive profile key into a local buffer — never escapes this frame. */
    uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
    error_t *err = keymgr_get_profile_key(keymgr, profile, profile_key);
    if (err) {
        return error_wrap(err, "Failed to get profile key for '%s'", profile);
    }

    err = encryption_encrypt(
        plaintext, plaintext_len, profile_key, storage_path, out_ciphertext
    );

    /* Clear on both success and failure. Missing this zeroization on the
     * error path would leave 32 bytes of key material on the stack until
     * the frame is overwritten. */
    hydro_memzero(profile_key, sizeof(profile_key));

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

    uint8_t profile_key[ENCRYPTION_PROFILE_KEY_SIZE];
    error_t *err = keymgr_get_profile_key(keymgr, profile, profile_key);
    if (err) {
        return error_wrap(err, "Failed to get profile key for '%s'", profile);
    }

    err = encryption_decrypt(
        ciphertext, ciphertext_len, profile_key, storage_path, out_plaintext
    );

    hydro_memzero(profile_key, sizeof(profile_key));

    return err;
}
