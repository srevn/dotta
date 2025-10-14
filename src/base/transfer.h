/**
 * transfer.h - Unified transfer context for network operations
 *
 * Provides a unified context for Git network operations (clone, fetch, push)
 * that encapsulates both credential handling and progress reporting.
 *
 * Design principles:
 * - Single context per operation (matches libgit2 design)
 * - Encapsulates credentials (callers don't manage them directly)
 * - Type-safe (no void* payloads)
 * - Delegates to existing credential and output systems
 * - Extensible for future enhancements (sideband, pack progress)
 */

#ifndef DOTTA_TRANSFER_H
#define DOTTA_TRANSFER_H

#include <git2.h>
#include <stdbool.h>

#include "credentials.h"
#include "utils/output.h"

/**
 * Transfer context for network operations
 *
 * Unified context that manages both credentials and progress reporting
 * for Git network operations (clone, fetch, push).
 */
typedef struct transfer_context_s {
    credential_context_t *cred;    /* Credential context (owned) */
    output_ctx_t *output;          /* Output context (borrowed) */

    /* Progress tracking state */
    bool progress_active;          /* Whether progress is currently being displayed */
    const char *operation;         /* Current operation ("Receiving", "Sending", etc.) */

    /* Transfer statistics */
    size_t total_objects;          /* Total objects to transfer */
    size_t indexed_objects;        /* Objects indexed so far */
    size_t received_objects;       /* Objects received so far */
    size_t received_bytes;         /* Bytes received so far */
} transfer_context_t;

/**
 * Create transfer context
 *
 * Creates a transfer context for a network operation. The context owns
 * the credential context and will free it on destruction. The output
 * context is borrowed and must remain valid for the lifetime of the
 * transfer context.
 *
 * @param output Output context for progress reporting (may be NULL for silent)
 * @param url Remote URL for credential handling (may be NULL)
 * @return Transfer context or NULL on allocation failure
 */
transfer_context_t *transfer_context_create(output_ctx_t *output, const char *url);

/**
 * Free transfer context
 *
 * Frees the transfer context and its owned credential context.
 * Safe to call with NULL.
 *
 * @param ctx Transfer context (may be NULL)
 */
void transfer_context_free(transfer_context_t *ctx);

/**
 * Credential callback for libgit2
 *
 * This callback is used for clone, fetch, and push operations.
 * Delegates to the credential system (credentials_callback).
 *
 * @param out Output credential object
 * @param url Remote URL being accessed
 * @param username_from_url Username from URL (may be NULL)
 * @param allowed_types Allowed credential types (bitfield)
 * @param payload Transfer context (transfer_context_t*)
 * @return 0 on success, negative error code on failure
 */
int transfer_credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
);

/**
 * Transfer progress callback for fetch operations
 *
 * Called by libgit2 during fetch to report download progress.
 * Uses output_progress() to display progress to the user.
 *
 * @param stats Transfer statistics
 * @param payload Transfer context (transfer_context_t*)
 * @return 0 to continue, negative to abort
 */
int transfer_progress_callback(
    const git_indexer_progress *stats,
    void *payload
);

/**
 * Push transfer progress callback for push operations
 *
 * Called by libgit2 during push to report upload progress.
 * Uses output_progress() to display progress to the user.
 *
 * @param current Number of objects transferred
 * @param total Total number of objects
 * @param bytes Bytes transferred
 * @param payload Transfer context (transfer_context_t*)
 * @return 0 to continue, negative to abort
 */
int transfer_push_progress_callback(
    unsigned int current,
    unsigned int total,
    size_t bytes,
    void *payload
);

#endif /* DOTTA_TRANSFER_H */
