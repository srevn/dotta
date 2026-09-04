/**
 * keymgr.c - The repository's unlock proof, and per-operation subkey acquisition
 *
 * Implements the slot, the session file, the ladder and the proof documented in
 * keymgr.h.
 *
 * Internal layout:
 *   - `evict_slot` / `install_slot` — the two writers of the slot; every write
 *     to (master_key, has_key, expires_at, the witness) goes through one of them.
 *   - `refuse` / `clear_refusal` — the standing refusal: the code and the line
 *     of the ladder's first refusal, held for the run and re-issued by every
 *     resolve after.
 *   - `keymgr_proof_t` — what the ladder yields: a fresh master and the binding
 *     of the witness it opened; consumed by `keep`.
 *   - `open_witness` / `trial_opens` / `witness_exists` / `derive_and_check` —
 *     the proof: Argon2 under the epoch, then the witnesses in order — the blob
 *     in hand, then whatever the witness source presents — until one opens.
 *   - `prompt_and_verify` / `prompt_and_confirm` / `obtain` — the ladder's user
 *     half: the environment, then the prompt, with retries at a terminal; two
 *     loops for two questions (is it the right passphrase / is it the passphrase
 *     the user meant), one refusal policy.
 *   - `warm_slot` / `keep` / `resolve_master` — the caches in front of `obtain`,
 *     and the keep behind it; `keymgr_set` walks `obtain` and `keep` without
 *     the caches.
 *   - `acquire_subkeys` — resolve, then derive the pair from the slot in place,
 *     used by both encrypt and decrypt so the operation paths only own (mac,
 *     prf) and the master never reaches a stack.
 *
 * Wipe discipline: every slot eviction, every per-call key intermediate, every
 * fresh master that opened nothing, every witness's decrypt and every error return
 * path scrubs the relevant buffer via `crypto_wipe` (monocypher's primitive,
 * used directly inside the crypto layer; non-crypto layers use `secure_wipe`
 * from `base/secure.h`). The struct itself — the slot is the secret — is a
 * `secure_alloc` mapping, wiped and unmapped by `keymgr_free`. Public API symmetry:
 * every entry point either returns `error_t *` with the cleanup-on-error contract,
 * runs idempotently with no error surface (free, clear), or is a getter reporting
 * what the slot holds (witness, cached, epoch) — the getters are NULL-safe except
 * `keymgr_epoch`, which returns a borrowed pointer and so has nowhere to put a
 * refusal.
 */

#include "crypto/keymgr.h"

#include <monocypher.h>
#include <stdlib.h>
#include <string.h>
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
 * The epoch, the timeout, the reach, the single in-memory slot, the standing
 * refusal and the witness source. A `secure_alloc` mapping of its own
 * (base/secure.h): the slot is the secret, and everything beside it is public
 * and rides along.
 */
struct keymgr {
    /* The repository's epoch and its public fingerprint — set together at create
     * time and by `keymgr_rekey`, never otherwise. The fingerprint is stamped
     * into every blob this keymgr encrypts and checked against every blob it is
     * asked to decrypt. */
    kdf_epoch_t epoch;
    uint8_t epoch_fp[KDF_EPOCH_FP_SIZE];

    int32_t session_timeout;   /* the file's life; 0 = no file, -1 = forever */
    keymgr_reach_t reach;      /* the caches alone, or the user beyond them */

    /* The slot: the process memo of one verified master, and the witness it opened
     * — both witness fields NULL when the master came from a cache or was taken
     * as given. */
    bool has_key;                       /* the slot is occupied */
    uint8_t master_key[KDF_KEY_SIZE];   /* the verified master */
    time_t expires_at;                  /* the file's; 0 = never, or no file */
    char *witness_profile;              /* the branch it opened */
    char *witness_path;                 /* the tree path it opened */

    /* The ladder ran and refused: the code and the top line of what it refused
     * with, re-issued by every resolve after. A NULL line means none stands.
     * The asker that met it got the error itself, causes and all — the chain
     * describes an event that happened once, at the row that met it — and what
     * stands for the run is the one sentence that is true of the run. An allocation
     * failure leaves no refusal standing rather than a wrong one: the next row
     * walks the ladder again (bind_proof's fallback, same idiom). */
    struct {
        error_code_t code;
        char *line;
    } refusal;

    /* Where a fresh master finds witnesses; NULL for none, which is the unit
     * suites' shape. `repo` is the source's own argument, carried untouched. */
    keymgr_witness_source_fn source;
    struct git_repository *repo;
};

/**
 * Evict the in-memory slot. Scrubs the master key, drops the witness and resets
 * every slot field to its post-`calloc` state. Idempotent.
 */
static void evict_slot(keymgr *km) {
    crypto_wipe(km->master_key, sizeof(km->master_key));
    km->has_key = false;
    km->expires_at = 0;
    free(km->witness_profile);
    free(km->witness_path);
    km->witness_profile = NULL;
    km->witness_path = NULL;
}

/**
 * Install a master key into the slot, with the expiry of the file it came from
 * or was written to (0 = never, or no file) and the binding of the witness it
 * opened (both NULL when none: a cache hit, or a master taken as given). Takes
 * ownership of the two strings. Replaces any occupant.
 */
static void install_slot(
    keymgr *km,
    const uint8_t master_key[KDF_KEY_SIZE],
    time_t expires_at,
    char *witness_profile,
    char *witness_path
) {
    free(km->witness_profile);
    free(km->witness_path);
    memcpy(km->master_key, master_key, KDF_KEY_SIZE);
    km->expires_at = expires_at;
    km->witness_profile = witness_profile;
    km->witness_path = witness_path;
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

/**
 * Record the ladder's refusal for the run — the first one stands; a later one
 * replaces it only through `keymgr_set`, which clears it before asking again —
 * and hand `err` back to the asker that met it, whole. The record is the code
 * and the message's top line, which is what a later resolve re-issues; `err`
 * itself, causes and all, stays the caller's to free.
 */
static error_t *refuse(keymgr *km, error_t *err) {
    free(km->refusal.line);
    km->refusal.line = strdup(error_message(err));
    km->refusal.code = err->code;

    return err;
}

static void clear_refusal(keymgr *km) {
    free(km->refusal.line);
    km->refusal.line = NULL;
}

error_t *keymgr_create(
    int32_t session_timeout,
    const kdf_epoch_t *epoch,
    keymgr_reach_t reach,
    keymgr_witness_source_fn source,
    struct git_repository *repo,
    keymgr **out
) {
    CHECK_NULL(epoch);
    CHECK_NULL(out);

    keymgr *km = secure_alloc(sizeof(*km));
    if (!km) {
        return ERROR(ERR_MEMORY, "Failed to map key manager");
    }

    /* The mapping is zero-filled; only the bindings need assignment. */
    km->session_timeout = session_timeout;
    km->reach = reach;
    km->source = source;
    km->repo = repo;
    bind_epoch(km, epoch);

    *out = km;
    return NULL;
}

void keymgr_free(keymgr *km) {
    if (!km) {
        return;
    }
    evict_slot(km);
    clear_refusal(km);
    secure_free(km, sizeof(*km));
}

/*
 * The proof: a fresh master, and what it opened.
 */

/**
 * What the ladder yields and `keep` consumes: a fresh master with the binding
 * of the witness it opened. The strings are owned; both NULL when there was nothing
 * to open and the master was confirmed or taken as given.
 */
typedef struct {
    uint8_t master[KDF_KEY_SIZE];
    char *witness_profile;
    char *witness_path;
} keymgr_proof_t;

static void wipe_proof(keymgr_proof_t *proof) {
    crypto_wipe(proof->master, sizeof(proof->master));
    free(proof->witness_profile);
    free(proof->witness_path);
    proof->witness_profile = NULL;
    proof->witness_path = NULL;
}

/**
 * The proof takes the witness's binding. An allocation failure leaves the proof
 * unnamed rather than failing it: the binding is the receipt's line, not the
 * verification.
 */
static void bind_proof(keymgr_proof_t *proof, const keymgr_witness_t *witness) {
    proof->witness_profile = strdup(witness->profile);
    proof->witness_path = strdup(witness->storage_path);
    if (!proof->witness_profile || !proof->witness_path) {
        free(proof->witness_profile);
        free(proof->witness_path);
        proof->witness_profile = NULL;
        proof->witness_path = NULL;
    }
}

/**
 * Does `master` open `witness`? The pair for the witness's profile, one
 * `cipher_decrypt`, the plaintext wiped and freed here: the ladder carries no
 * plaintext, and the decrypt that asked runs its own once the master is kept.
 * ERR_CRYPTO is "no"; any other error is the decrypt's own failure.
 */
static error_t *open_witness(
    const uint8_t master[KDF_KEY_SIZE],
    const keymgr_witness_t *witness
) {
    uint8_t mac_key[KDF_KEY_SIZE];
    uint8_t prf_key[KDF_KEY_SIZE];
    kdf_siv_subkeys(master, witness->profile, mac_key, prf_key);

    buffer_t plaintext = BUFFER_INIT;
    error_t *err = cipher_decrypt(
        witness->ciphertext, witness->len,
        mac_key, prf_key,
        witness->storage_path,
        &plaintext
    );

    crypto_wipe(mac_key, sizeof(mac_key));
    crypto_wipe(prf_key, sizeof(prf_key));
    if (plaintext.data) {
        crypto_wipe(plaintext.data, plaintext.size);
    }
    buffer_free(&plaintext);

    return err;
}

/* The same witness: the same bytes under the same binding. One object at two
 * paths, or at one path under two branches, is two witnesses — only one of them
 * the one it was sealed under. */
static bool witness_same(const keymgr_witness_t *a, const keymgr_witness_t *b) {
    return strcmp(a->profile, b->profile) == 0
           && strcmp(a->storage_path, b->storage_path) == 0
           && a->len == b->len
           && memcmp(a->ciphertext, b->ciphertext, a->len) == 0;
}

/**
 * A fresh master on trial before the witness source: the blob in hand it was
 * already tried against, how many witnesses it has been shown, and the proof
 * that carries it and takes the opener's binding.
 */
typedef struct {
    const keymgr_witness_t *in_hand;  /* tried first; skipped if presented */
    size_t tried;                     /* witnesses decrypted, the in-hand too;
                                       * the count the refusal is worded by */
    keymgr_proof_t *proof;            /* the master under trial */
} keymgr_trial_t;

/**
 * keymgr_opens_fn: the trial's answer to a presented witness. One the master
 * opens is accepted with its binding on the proof. The cipher's "no" is that
 * witness's refusal and not the master's, so the walk goes on. A decrypt that
 * failed on its own is neither answer, and its error ends the walk.
 */
static error_t *trial_opens(
    void *self, const keymgr_witness_t *witness, bool *out_accepted
) {
    keymgr_trial_t *trial = self;

    *out_accepted = false;
    if (trial->in_hand && witness_same(trial->in_hand, witness)) {
        return NULL;
    }
    trial->tried++;

    error_t *err = open_witness(trial->proof->master, witness);
    if (!err) {
        bind_proof(trial->proof, witness);
        *out_accepted = true;
        return NULL;
    }
    if (err->code != ERR_CRYPTO) {
        return err;
    }
    error_free(err);

    return NULL;
}

/**
 * keymgr_opens_fn: the prompt's question — is there any ciphertext to verify
 * against? — answered by the first witness presented.
 */
static error_t *witness_exists(
    void *self, const keymgr_witness_t *witness, bool *out_accepted
) {
    (void) self;
    (void) witness;
    *out_accepted = true;

    return NULL;
}

/**
 * Argon2 under the epoch, then the witnesses in order: the blob in hand, then
 * whatever the source presents. One that opens fills the proof; none wipes it
 * and refuses the run, worded by how much there was to open — against a lone
 * ciphertext a miss decides nothing, against several it is the passphrase's.
 * With nothing to open at all the master is taken as given: the caller confirmed
 * it, or the environment asserted it. `subject` is what the refusal is about:
 * "The passphrase" or "DOTTA_ENCRYPTION_PASSPHRASE".
 *
 * Three returns and one refusal: each success is taken where its condition is
 * decided, and every failure — the derivation's own included — leaves through
 * the one exit that scrubs the proof. So a caller may return a refusal without
 * a wipe, which is what `obtain`'s contract promises its own.
 */
static error_t *derive_and_check(
    keymgr *km, const char *subject, const char *passphrase,
    size_t passphrase_len, const keymgr_witness_t *in_hand,
    keymgr_proof_t *out
) {
    keymgr_trial_t trial = { .in_hand = in_hand, .proof = out };

    error_t *err = kdf_master_key(
        (const uint8_t *) passphrase, passphrase_len,
        &km->epoch, out->master
    );
    if (err) {
        goto fail;
    }

    if (in_hand) {
        trial.tried++;
        err = open_witness(out->master, in_hand);
        if (!err) {
            bind_proof(out, in_hand);
            return NULL;
        }
        if (err->code != ERR_CRYPTO) {
            goto fail;
        }
        error_free(err);
    }

    if (km->source) {
        bool accepted = false;
        err = km->source(km->repo, &km->epoch, trial_opens, &trial, &accepted);
        if (err) {
            goto fail;
        }
        if (accepted) {
            return NULL;
        }
    }

    /* Nothing was shown to the master, so nothing can refuse it: an operation
     * with no blob in hand against a repository whose ciphertext the source found
     * none of, or a keymgr with no source at all (the unit suites' shape). The
     * caller confirmed it, or the environment asserted it. */
    if (trial.tried == 0) {
        return NULL;
    }

    /* ERR_LOCKED, not the cipher's ERR_CRYPTO: the run is left with no master —
     * every row after this one re-issues the same refusal — and a key is what
     * settles it. The cipher's code is for a held master that one blob refuses;
     * that is the blob's fault, and the reader that tells the two apart (the
     * workspace's fault) reads the code.
     *
     * The refusal names no binding. It stands for the run — the source showed
     * the master every ciphertext of this epoch the repository holds, so what
     * one row met is what all of them meet — and a fact about the run cannot
     * name one of its rows; the caller's own wrap names the row that asked
     * (infra/content). What does vary is how much there was to open, and against
     * a single ciphertext a miss is undecidable: a wrong passphrase and a damaged
     * file are the same "no". */
    if (trial.tried == 1) {
        err = ERROR(
            ERR_LOCKED,
            "%s does not open the one encrypted file it was tried against, "
            "which may itself be damaged", subject
        );
    } else {
        err = ERROR(
            ERR_LOCKED, "%s opens none of this repository's encrypted files",
            subject
        );
    }

fail:
    wipe_proof(out);
    return err;
}

/*
 * The ladder's user half.
 */

/**
 * A prompt that yielded nothing: no terminal, end of input, an empty line, a
 * line too long, a terminal that would not be set. The LOCKED root folds the
 * primitive's line and names the ways out — true at a terminal too, which is
 * where the last empty line lands. An allocation failure passes through as itself.
 * Takes ownership of `read_err`.
 */
static error_t *nothing_read(error_t *read_err) {
    if (read_err->code == ERR_MEMORY) {
        return read_err;
    }
    error_t *locked = ERROR(
        ERR_LOCKED,
        "No passphrase: %s; set DOTTA_ENCRYPTION_PASSPHRASE, or run "
        "'dotta key set' at a terminal", error_message(read_err)
    );
    error_free(read_err);
    return locked;
}

/**
 * A witness is in reach: derive and check, up to KEYMGR_ATTEMPTS times at a
 * terminal. A miss of any kind — a wrong passphrase, an empty line — is an attempt,
 * and the last one's error is the refusal; over a pipe the first miss is.
 */
static error_t *prompt_and_verify(
    keymgr *km,
    const keymgr_witness_t *in_hand,
    keymgr_proof_t *out
) {
    const bool tty = isatty(STDIN_FILENO);
    const char *prompt = "Enter encryption passphrase: ";

    for (int attempt = 1;; attempt++) {
        char *passphrase = NULL;
        size_t passphrase_len = 0;
        error_t *err = passphrase_prompt(prompt, &passphrase, &passphrase_len);
        if (err) {
            if (tty && err->code == ERR_INVALID_ARG
                && attempt < KEYMGR_ATTEMPTS) {
                error_free(err);
                continue;
            }
            return refuse(km, nothing_read(err));
        }

        err = derive_and_check(
            km, "The passphrase", passphrase, passphrase_len, in_hand, out
        );
        secure_free(passphrase, passphrase_len + 1);
        if (!err) {
            return NULL;
        }
        /* A wrong passphrase — derive_and_check's ERR_LOCKED — is re-asked at a
         * terminal; a derivation or a walk that failed on its own is refused at
         * once. */
        if (!tty || err->code != ERR_LOCKED || attempt == KEYMGR_ATTEMPTS) {
            return refuse(km, err);
        }
        error_free(err);
        prompt = "Wrong passphrase, try again: ";
    }
}

/**
 * Nothing to open: the passphrase is confirmed by typing it twice, then derived
 * and taken as given — up to KEYMGR_ATTEMPTS rounds at a terminal. `len` equal
 * and memcmp: the two strings are the user's own, typed into the user's own
 * process; constant time defends nothing here. A confirm the primitive refuses
 * (an empty line) is a mismatch; one it cannot read at all ends the ladder.
 */
static error_t *prompt_and_confirm(keymgr *km, keymgr_proof_t *out) {
    const bool tty = isatty(STDIN_FILENO);
    const char *prompt = "Enter encryption passphrase: ";

    for (int attempt = 1;; attempt++) {
        char *passphrase = NULL;
        size_t passphrase_len = 0;
        error_t *err = passphrase_prompt(prompt, &passphrase, &passphrase_len);
        if (err) {
            if (tty && err->code == ERR_INVALID_ARG
                && attempt < KEYMGR_ATTEMPTS) {
                error_free(err);
                continue;
            }
            return refuse(km, nothing_read(err));
        }

        char *again = NULL;
        size_t again_len = 0;
        err = passphrase_prompt(
            "Confirm encryption passphrase: ", &again, &again_len
        );
        /* Nothing readable at all ends the ladder; a line the primitive refuses
         * is a mismatch, and falls through to be one. */
        if (err && err->code != ERR_INVALID_ARG) {
            secure_free(passphrase, passphrase_len + 1);
            return refuse(km, nothing_read(err));
        }

        const bool same = !err && again_len == passphrase_len
            && memcmp(again, passphrase, passphrase_len) == 0;
        error_free(err);
        secure_free(again, again_len + 1);

        if (same) {
            err = kdf_master_key(
                (const uint8_t *) passphrase, passphrase_len, &km->epoch,
                out->master
            );
            secure_free(passphrase, passphrase_len + 1);
            return err ? refuse(km, err) : NULL;
        }
        secure_free(passphrase, passphrase_len + 1);

        if (!tty || attempt == KEYMGR_ATTEMPTS) {
            return refuse(km, ERROR(ERR_LOCKED, "Passphrases do not match"));
        }
        prompt = "Passphrases do not match, try again: ";
    }
}

/**
 * The ladder's user half: the environment, then the prompt — OBTAIN only. The
 * fresh master it yields is verified before it is returned, and every refusal
 * is recorded for the run. The run is left without a master either way, and the
 * code says so: no passphrase in reach, nothing read, a confirm that never matched,
 * a passphrase that opened nothing — ERR_LOCKED, a key would settle it; a
 * derivation or a witness walk that failed on its own keeps the failure's code.
 * Nothing here installs or persists — the callers keep what verified.
 *
 * A refusal leaves the proof as it found it: nothing written, or already scrubbed
 * by the derivation that failed. Callers return it without a wipe.
 */
static error_t *obtain(
    keymgr *km,
    const keymgr_witness_t *in_hand,
    keymgr_proof_t *out
) {
    /* The caches are as far as a reporting command may reach: below them the
     * user would be asked, and a report never asks. */
    if (km->reach != KEYMGR_REACH_OBTAIN) {
        error_t *err = ERROR(
            ERR_LOCKED,
            "No passphrase is cached, and this command does not ask for one; "
            "run 'dotta key set'"
        );
        return refuse(km, err);
    }

    char *passphrase = NULL;
    size_t passphrase_len = 0;
    error_t *err = passphrase_from_env(&passphrase, &passphrase_len);
    if (!err) {
        err = derive_and_check(
            km, "DOTTA_ENCRYPTION_PASSPHRASE", passphrase, passphrase_len,
            in_hand, out
        );
        secure_free(passphrase, passphrase_len + 1);
        return err ? refuse(km, err) : NULL;
    }
    if (err->code != ERR_NOT_FOUND) {
        return refuse(km, err);
    }
    error_free(err);

    /* The prompt's shape is the repository's to decide: a witness in reach means
     * the passphrase is verified, none means it is confirmed. */
    bool any = in_hand != NULL;
    if (!any && km->source) {
        err = km->source(km->repo, &km->epoch, witness_exists, NULL, &any);
        if (err) {
            return refuse(km, err);
        }
    }
    return any ? prompt_and_verify(km, in_hand, out)
               : prompt_and_confirm(km, out);
}

/*
 * The caches in front of the ladder, and the keep behind it.
 */

/**
 * The CACHED half of the ladder: the slot, else — unless a refusal stands or
 * the file tier is off — the epoch's file, installed. Every miss is silent: not
 * found, expired, tampered (the loader unlinked it), an I/O failure (the loader
 * kept it). The refusal gates the probe, so N rows under a cold run cost one.
 */
static bool warm_slot(keymgr *km) {
    if (km->has_key) {
        return true;
    }
    if (km->refusal.line || km->session_timeout == 0) {
        return false;
    }

    uint8_t master_key[KDF_KEY_SIZE];
    time_t expires_at = 0;
    error_t *err = session_load(master_key, &km->epoch, &expires_at);
    if (err) {
        error_free(err);
        return false;
    }

    install_slot(km, master_key, expires_at, NULL, NULL);
    crypto_wipe(master_key, sizeof(master_key));
    return true;
}

/**
 * A proof enters the slot, and the file unless the tier is off.
 *
 * The slot is the process memo under every timeout. The file's expiry is computed
 * here (`now + timeout`, or 0 for never) and is what the slot then carries. Returns
 * the save's error for the caller whose job the file is (`keymgr_set`);
 * `resolve_master` drops it — the slot is installed either way. A save that fails
 * unlinks the file, so the next process never loads a master this one meant to
 * replace. The proof is consumed: its master wiped, its binding moved into the
 * slot.
 */
static error_t *keep(keymgr *km, keymgr_proof_t *proof) {
    time_t expires_at = 0;
    error_t *err = NULL;

    if (km->session_timeout != 0) {
        expires_at = km->session_timeout < 0
            ? 0
            : time(NULL) + km->session_timeout;
        err = session_save(proof->master, &km->epoch, expires_at);
        if (err) {
            (void) session_clear(&km->epoch);
            expires_at = 0;
        }
    }

    install_slot(
        km, proof->master, expires_at,
        proof->witness_profile, proof->witness_path
    );
    proof->witness_profile = NULL;
    proof->witness_path = NULL;
    crypto_wipe(proof->master, sizeof(proof->master));

    return err;
}

/**
 * The whole ladder: the caches, the standing refusal, then obtain and keep. On
 * success the slot holds a verified master; a refusal leaves it empty and writes
 * nothing.
 */
static error_t *resolve_master(keymgr *km, const keymgr_witness_t *in_hand) {
    if (warm_slot(km)) {
        return NULL;
    }
    if (km->refusal.line) {
        return ERROR(km->refusal.code, "%s", km->refusal.line);
    }

    keymgr_proof_t proof = { 0 };
    RETURN_IF_ERROR(obtain(km, in_hand, &proof));
    error_free(keep(km, &proof));
    return NULL;
}

/**
 * Resolve the master key and derive (mac_key, prf_key) for a profile.
 *
 * Both encrypt and decrypt go through this single entry point so the master-key
 * lifetime is owned in one place. Nothing copies the master out of the slot:
 * the derivation reads it where it lives, inside the keymgr's own locked mapping,
 * so there is no per-call copy on the stack to scrub. The caller wipes (mac_key,
 * prf_key) after per-operation use.
 */
static error_t *acquire_subkeys(
    keymgr *km,
    const char *profile,
    const keymgr_witness_t *in_hand,
    uint8_t out_mac_key[KDF_KEY_SIZE],
    uint8_t out_prf_key[KDF_KEY_SIZE]
) {
    RETURN_IF_ERROR(resolve_master(km, in_hand));
    kdf_siv_subkeys(km->master_key, profile, out_mac_key, out_prf_key);

    return NULL;
}

error_t *keymgr_set(keymgr *km) {
    CHECK_NULL(km);

    /* The verb verifies against the repository, not against what an earlier run
     * left: the slot goes, and so does the refusal — this is the one ask that
     * may follow one. */
    evict_slot(km);
    clear_refusal(km);

    keymgr_proof_t proof = { 0 };
    RETURN_IF_ERROR(obtain(km, NULL, &proof));
    return keep(km, &proof);
}

bool keymgr_witness(
    const keymgr *km, const char **out_profile,
    const char **out_storage_path
) {
    if (!km || !km->has_key || !km->witness_profile) {
        return false;
    }
    *out_profile = km->witness_profile;
    *out_storage_path = km->witness_path;

    return true;
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
     * and nothing would read it again. A refusal was about the old epoch's
     * ciphertext; the new one is asked afresh. */
    evict_slot(km);
    clear_refusal(km);
    (void) session_clear(&km->epoch);
    bind_epoch(km, epoch);
}

const kdf_epoch_t *keymgr_epoch(const keymgr *km) {
    return &km->epoch;
}

bool keymgr_cached(keymgr *km, time_t *out_expires_at) {
    const bool warm = km && warm_slot(km);

    if (out_expires_at) {
        *out_expires_at = warm ? km->expires_at : 0;
    }

    return warm;
}

error_t *keymgr_encrypt(
    keymgr *km, const char *profile, const char *storage_path,
    const uint8_t *plaintext, size_t plaintext_len,
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

    /* No blob in hand: a fresh master is verified against what the repository
     * holds, or confirmed when it holds nothing. */
    error_t *err = acquire_subkeys(km, profile, NULL, mac_key, prf_key);
    if (err) {
        return err;
    }

    err = cipher_encrypt(
        plaintext, plaintext_len, mac_key, prf_key, storage_path,
        km->epoch_fp, out_ciphertext
    );

    /* Wipe on every path; otherwise 64 bytes of subkey material survive on the
     * stack until the frame is overwritten. */
    crypto_wipe(mac_key, sizeof(mac_key));
    crypto_wipe(prf_key, sizeof(prf_key));

    return err;
}

error_t *keymgr_decrypt(
    keymgr *km, const char *profile, const char *storage_path,
    const uint8_t *ciphertext, size_t ciphertext_len,
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

    /* The blob in hand is the witness a fresh master must open first: a cold
     * decrypt verifies on the very blob it was asked for, and the repository's
     * other ciphertext is consulted only when this one refuses. A cached master
     * is not re-verified here — a blob it does not open is that blob's fault,
     * and the slot stays. */
    const keymgr_witness_t in_hand = {
        .ciphertext   = ciphertext,
        .len          = ciphertext_len,
        .profile      = profile,
        .storage_path = storage_path,
    };
    err = acquire_subkeys(km, profile, &in_hand, mac_key, prf_key);
    if (err) {
        return err;
    }

    err = cipher_decrypt(
        ciphertext, ciphertext_len, mac_key, prf_key, storage_path,
        out_plaintext
    );

    crypto_wipe(mac_key, sizeof(mac_key));
    crypto_wipe(prf_key, sizeof(prf_key));

    return err;
}
