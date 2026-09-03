/**
 * keymgr.c — Master-key lifecycle and per-operation subkey acquisition
 *
 * Implements the slot, the session file and the resolution chain documented in
 * keymgr.h.
 *
 * Internal layout:
 *   - `evict_slot` / `install_slot` — single chokepoints for slot mutations;
 *     every write to (master_key, has_key, expires_at) goes through one of these.
 *   - `try_memory_hit` / `try_disk_hit` / `prompt_passphrase` / `keep` — the
 *     four tiers of the resolution decision tree. Each owns one storage location,
 *     one decision.
 *   - `keymgr_resolve` — orchestrator composing the four tiers in memory → disk
 *     → env → prompt order.
 *   - `keymgr_acquire_subkeys` — atomic resolve + derive + wipe-master used by
 *     both encrypt and decrypt so the operation paths only own the (mac, prf) pair.
 *
 * Wipe discipline: every slot eviction, every per-call key intermediate, every
 * error return path scrubs the relevant buffer via `crypto_wipe` (monocypher's
 * primitive, used directly inside the crypto layer; non-crypto layers use
 * `secure_wipe` from `base/secure.h`). The struct itself — the slot is the secret
 * — is a `secure_alloc` mapping, wiped and unmapped by `keymgr_free`. Public
 * API symmetry: every entry point either returns `error_t *` with the
 * cleanup-on-error contract, or runs idempotently with no error surface (free,
 * clear).
 */

#include "crypto/keymgr.h"

#include <monocypher.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base/error.h"
#include "base/secure.h"
#include "crypto/cipher.h"
#include "crypto/kdf.h"
#include "crypto/session.h"
#include "sys/passphrase.h"

/**
 * Key manager structure.
 *
 * The epoch, the timeout, and the single in-memory slot. A `secure_alloc` mapping
 * of its own (base/secure.h): the slot is the secret, and everything beside it
 * is public and rides along.
 */
struct keymgr {
    /* The repository's epoch and its public fingerprint — set together at create
     * time and by `keymgr_rekey`, never otherwise. The fingerprint is stamped
     * into every blob this keymgr encrypts and checked against every blob it is
     * asked to decrypt. */
    kdf_epoch_t epoch;
    uint8_t epoch_fp[KDF_EPOCH_FP_SIZE];

    int32_t session_timeout;        /* seconds the file lives; 0 = no file, -1 = never expires */
    keymgr_reach_t reach;           /* the caches alone, or the user beyond them */

    /* The slot: the process memo of the master. */
    bool has_key;
    uint8_t master_key[KDF_KEY_SIZE];
    time_t expires_at;              /* the file's; 0 = never, or no file */
};

/**
 * Evict the in-memory slot. Scrubs the master key and resets every slot field
 * to its post-`calloc` state. Idempotent.
 */
static void evict_slot(keymgr *km) {
    crypto_wipe(km->master_key, sizeof(km->master_key));
    km->has_key = false;
    km->expires_at = 0;
}

/**
 * Install a master key into the slot, with the expiry of the file it came from
 * or was written to (0 = never, or no file). Replaces any occupant.
 */
static void install_slot(
    keymgr *km,
    const uint8_t master_key[KDF_KEY_SIZE],
    time_t expires_at
) {
    memcpy(km->master_key, master_key, KDF_KEY_SIZE);
    km->expires_at = expires_at;
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
    keymgr_reach_t reach,
    keymgr **out
) {
    CHECK_NULL(epoch);
    CHECK_NULL(out);

    keymgr *km = secure_alloc(sizeof(*km));
    if (!km) {
        return ERROR(ERR_MEMORY, "Failed to map key manager");
    }

    /* The mapping is zero-filled; only the binding needs assignment. */
    km->session_timeout = session_timeout;
    km->reach = reach;
    bind_epoch(km, epoch);

    *out = km;
    return NULL;
}

void keymgr_free(keymgr *km) {
    if (!km) {
        return;
    }
    evict_slot(km);
    secure_free(km, sizeof(*km));
}

/*
 * Resolution decision tree. Four tiers, each owning one storage location and
 * one decision:
 *
 *   try_memory_hit     — in-memory slot   (fast path)
 *   try_disk_hit       — on-disk session  (process-fresh warm path)
 *   prompt_passphrase  — env or TTY       (cold path)
 *   keep               — the slot, and the file when the tier is on
 *
 * `keymgr_resolve` is the orchestrator that composes them in order.
 */

/**
 * Tier 1: in-memory slot hit. Copies the master to `out_master_key`; never writes
 * it on a miss.
 */
static bool try_memory_hit(
    const keymgr *km,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    if (!km->has_key) {
        return false;
    }
    memcpy(out_master_key, km->master_key, KDF_KEY_SIZE);
    return true;
}

/**
 * Tier 2: on-disk session file hit.
 *
 * Hit copies the master to `out_master_key` AND installs it into the slot with
 * the file's expiry. Miss covers the tier being off, no file, expired, MAC failure,
 * wrong mode or owner. Transient I/O failure surfaces a stderr advisory and counts
 * as a miss. On miss `out_master_key` is scrubbed.
 */
static bool try_disk_hit(
    keymgr *km,
    uint8_t out_master_key[KDF_KEY_SIZE]
) {
    if (km->session_timeout == 0) {
        return false;
    }

    time_t expires_at = 0;
    error_t *err = session_load(out_master_key, &km->epoch, &expires_at);
    if (err == NULL) {
        install_slot(km, out_master_key, expires_at);
        return true;
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
 * On success `*out_passphrase` is the passphrase's own mapping, which the caller
 * releases via `secure_free(passphrase, *out_passphrase_len + 1)` (the `+1`
 * accounts for the NUL both backends append).
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
 * Tier 4: keep a freshly derived master — the slot always, the file when the
 * tier is on.
 *
 * The slot is the process memo under every timeout: an operation that follows
 * in this run reads it rather than deriving again. The file's expiry is computed
 * here (`now + timeout`, or 0 for never) and is what the slot then carries.
 * `session_save` failures are non-fatal — the slot is authoritative for this
 * process; failing to persist only costs a re-prompt in the next one.
 */
static void keep(keymgr *km, const uint8_t master_key[KDF_KEY_SIZE]) {
    time_t expires_at = 0;

    if (km->session_timeout != 0) {
        expires_at = km->session_timeout < 0
            ? 0
            : time(NULL) + km->session_timeout;
        error_t *save_err = session_save(master_key, &km->epoch, expires_at);
        if (save_err) {
            fprintf(
                stderr, "Warning: Failed to save session cache: %s\n",
                error_message(save_err)
            );
            error_free(save_err);
            expires_at = 0;
        }
    }

    install_slot(km, master_key, expires_at);
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

    /* The caches are as far as a reporting command may reach: below them the
     * user would be asked, and a report never asks. */
    if (km->reach != KEYMGR_REACH_OBTAIN) {
        return ERROR(
            ERR_LOCKED,
            "No passphrase is cached, and this command does not ask for one; "
            "run 'dotta key set'"
        );
    }

    char *passphrase = NULL;
    size_t passphrase_len = 0;
    error_t *err = prompt_passphrase(&passphrase, &passphrase_len);
    if (err) {
        return err;
    }

    err = kdf_master_key(
        (const uint8_t *) passphrase, passphrase_len, &km->epoch,
        out_master_key
    );

    /* Wipe and unmap the passphrase regardless of derivation outcome. Both backends
     * return a mapping of `passphrase_len + 1` bytes (NUL-terminated). */
    secure_free(passphrase, passphrase_len + 1);

    if (err) {
        return error_wrap(err, "Failed to derive encryption key");
    }

    keep(km, out_master_key);
    return NULL;
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
     * in the slot — the slot is replaced only on success. */
    uint8_t new_master[KDF_KEY_SIZE];
    error_t *err = kdf_master_key(
        passphrase, passphrase_len, &km->epoch, new_master
    );
    if (err) {
        return error_wrap(err, "Failed to derive encryption key");
    }

    keep(km, new_master);
    crypto_wipe(new_master, sizeof(new_master));

    return NULL;
}

bool keymgr_clear(keymgr *km) {
    if (!km) {
        return false;
    }

    evict_slot(km);
    return session_clear(&km->epoch);
}

void keymgr_rekey(keymgr *km, const kdf_epoch_t *epoch) {
    if (!km || !epoch) {
        return;
    }

    /* The cached master derives from the old epoch — evict before re-binding,
     * and take the old epoch's file with it: the file is the epoch's by name,
     * and nothing would read it again. */
    evict_slot(km);
    (void) session_clear(&km->epoch);
    bind_epoch(km, epoch);
}

const kdf_epoch_t *keymgr_epoch(const keymgr *km) {
    return &km->epoch;
}

bool keymgr_cached(keymgr *km, time_t *out_expires_at) {
    if (out_expires_at) {
        *out_expires_at = 0;
    }
    if (!km) {
        return false;
    }

    uint8_t master_key[KDF_KEY_SIZE];
    const bool cached = try_memory_hit(km, master_key)
        || try_disk_hit(km, master_key);
    crypto_wipe(master_key, sizeof(master_key));

    if (cached && out_expires_at) {
        *out_expires_at = km->expires_at;
    }
    return cached;
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
