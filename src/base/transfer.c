/**
 * transfer.c - Unified transfer context for network operations
 */

#include "transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "credentials.h"
#include "utils/output.h"

/**
 * Format bytes in human-readable format
 */
static void format_bytes(size_t bytes, char *buffer, size_t buffer_size) {
    const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    size_t unit_index = 0;
    double size = (double)bytes;

    while (size >= 1024.0 && unit_index < 4) {
        size /= 1024.0;
        unit_index++;
    }

    if (unit_index == 0) {
        snprintf(buffer, buffer_size, "%zu %s", bytes, units[unit_index]);
    } else {
        snprintf(buffer, buffer_size, "%.1f %s", size, units[unit_index]);
    }
}

/**
 * Create transfer context
 */
transfer_context_t *transfer_context_create(output_ctx_t *output, const char *url) {
    transfer_context_t *ctx = calloc(1, sizeof(transfer_context_t));
    if (!ctx) {
        return NULL;
    }

    /* Create credential context (owned by transfer context) */
    ctx->cred = credential_context_create(url);
    if (!ctx->cred && url) {
        /* If URL was provided but credential creation failed, treat as error */
        free(ctx);
        return NULL;
    }

    /* Borrow output context (not owned) */
    ctx->output = output;

    /* Initialize progress state */
    ctx->progress_active = false;
    ctx->operation = NULL;
    ctx->total_objects = 0;
    ctx->indexed_objects = 0;
    ctx->received_objects = 0;
    ctx->received_bytes = 0;

    return ctx;
}

/**
 * Free transfer context
 */
void transfer_context_free(transfer_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Free owned credential context */
    credential_context_free(ctx->cred);

    /* Clear progress if active */
    if (ctx->progress_active && ctx->output) {
        /* Print newline to finish progress line */
        output_newline(ctx->output);
    }

    /* Free the context itself */
    free(ctx);
}

/**
 * Credential callback for libgit2
 */
int transfer_credentials_callback(
    git_credential **out,
    const char *url,
    const char *username_from_url,
    unsigned int allowed_types,
    void *payload
) {
    /* Payload is transfer_context_t* */
    transfer_context_t *ctx = (transfer_context_t *)payload;

    /* Delegate to the credential system */
    return credentials_callback(
        out,
        url,
        username_from_url,
        allowed_types,
        ctx ? ctx->cred : NULL
    );
}

/**
 * Transfer progress callback for fetch operations
 */
int transfer_progress_callback(
    const git_indexer_progress *stats,
    void *payload
) {
    if (!stats || !payload) {
        return 0;
    }

    transfer_context_t *ctx = (transfer_context_t *)payload;

    /* Skip progress if no output context or below NORMAL verbosity */
    if (!ctx->output || ctx->output->verbosity < OUTPUT_NORMAL) {
        return 0;
    }

    /* Update statistics */
    ctx->total_objects = stats->total_objects;
    ctx->indexed_objects = stats->indexed_objects;
    ctx->received_objects = stats->received_objects;
    ctx->received_bytes = stats->received_bytes;

    unsigned int total = stats->total_objects;
    unsigned int received = stats->received_objects;
    unsigned int indexed = stats->indexed_objects;

    /* Determine what to display based on state */
    if (total > 0) {
        /* Show receiving progress with percentage and bytes */
        int percent = (received * 100) / total;
        char bytes_str[32];
        format_bytes(stats->received_bytes, bytes_str, sizeof(bytes_str));

        /* Display: "Receiving objects: XX% (current/total), X.X MiB" */
        fprintf(ctx->output->stream, "\rReceiving objects: %3d%% (%u/%u), %s",
                percent, received, total, bytes_str);
        fflush(ctx->output->stream);
        ctx->progress_active = true;

        /* Check if indexing is complete */
        if (indexed == total && received == total) {
            fprintf(ctx->output->stream, ", done.\n");
            fflush(ctx->output->stream);
            ctx->progress_active = false;
        }
    } else if (received > 0) {
        /* Don't know total yet, just show count */
        char bytes_str[32];
        format_bytes(stats->received_bytes, bytes_str, sizeof(bytes_str));

        fprintf(ctx->output->stream, "\rReceiving objects: %u, %s",
                received, bytes_str);
        fflush(ctx->output->stream);
        ctx->progress_active = true;
    }

    return 0;
}

/**
 * Push transfer progress callback for push operations
 */
int transfer_push_progress_callback(
    unsigned int current,
    unsigned int total,
    size_t bytes,
    void *payload
) {
    if (!payload) {
        return 0;
    }

    transfer_context_t *ctx = (transfer_context_t *)payload;

    /* Skip progress if no output context or below NORMAL verbosity */
    if (!ctx->output || ctx->output->verbosity < OUTPUT_NORMAL) {
        return 0;
    }

    /* Update statistics */
    ctx->total_objects = total;
    ctx->received_objects = current;
    ctx->received_bytes = bytes;

    /* Calculate progress percentage */
    if (total > 0) {
        int percent = (current * 100) / total;

        /* Display: "Sending objects: XX% (current/total)" */
        fprintf(ctx->output->stream, "\rSending objects: %3d%% (%u/%u)",
                percent, current, total);
        fflush(ctx->output->stream);
        ctx->progress_active = true;

        /* Check if complete */
        if (current == total) {
            fprintf(ctx->output->stream, ", done.\n");
            fflush(ctx->output->stream);
            ctx->progress_active = false;
        }
    } else {
        /* No total known - just show current */
        fprintf(ctx->output->stream, "\rSending objects: %u", current);
        fflush(ctx->output->stream);
        ctx->progress_active = true;
    }

    return 0;
}
