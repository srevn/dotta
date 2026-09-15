/**
 * commit.c - Commit message template builder implementation
 */

#include "utils/commit.h"

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "sys/identity.h"

/* Maximum length for hostname */
#define MAX_HOSTNAME 256

/* Maximum paths to show in detail before truncating */
#define MAX_PATHS_DETAIL 5

/**
 * One template variable, and what it renders to
 *
 * The values a message is made of are resolved once and read by both substitutions,
 * so a title and a body cannot disagree about one of them, and the header's list
 * of variables is one row each (utils/commit.h) — a row being where the name
 * and the value are written beside each other, which is what makes a transposition
 * among ten same-typed strings a thing that cannot be written rather than a thing
 * that compiles.
 *
 * A value is never NULL: NULL is the reader's word for "no such variable", and
 * what it does with one is leave the template's own bytes standing. A variable
 * that is legitimately absent — a target commit outside a revert — renders empty,
 * which is the row's business and not the reader's.
 */
typedef struct {
    const char *name;    /* As a template spells it, without the braces */
    const char *value;   /* Never NULL */
} template_t;

/**
 * Get current hostname Returns allocated string or NULL on error
 */
static char *get_hostname(void) {
    char hostname[MAX_HOSTNAME];

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        /* Fallback to "unknown" if gethostname fails */
        return strdup("unknown");
    }

    /* Ensure null termination */
    hostname[MAX_HOSTNAME - 1] = '\0';

    return strdup(hostname);
}

/**
 * Get current username Returns allocated string or NULL on error
 *
 * The invoker's (sys/identity): under sudo the user who typed the command, not
 * the root that $USER names there. "unknown" for a uid with no passwd entry.
 */
static char *get_username(void) {
    const char *name = identity()->name;
    return strdup(name ? name : "unknown");
}

/**
 * Get current datetime in local timezone as ISO 8601 format Returns allocated
 * string or NULL on error
 */
static char *get_datetime_local(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    if (!tm_info) {
        /* Fallback if localtime fails */
        return strdup("unknown");
    }

    /* Format: 2025-01-09 14:23:45 +0300 (uses %z for timezone offset) */
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S %z", tm_info);

    return strdup(buffer);
}

/**
 * Get current date in ISO 8601 format (YYYY-MM-DD) Returns allocated string or
 * NULL on error
 */
static char *get_date_local(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    if (!tm_info) {
        return strdup("unknown");
    }

    char buffer[16];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d", tm_info);

    return strdup(buffer);
}

/**
 * Get action name in present tense
 *
 * Every action, and no default arm: -Wswitch names this function and its past
 * tense the day a sixth action lands, where a default would have rendered the
 * new one "Unknown" into a commit nobody re-reads. The return past the switch
 * is for a value no enumerator names, which only a cast can produce.
 */
const char *commit_action_name(commit_action_t action) {
    switch (action) {
        case COMMIT_ACTION_ADD:    return "Add";
        case COMMIT_ACTION_UPDATE: return "Update";
        case COMMIT_ACTION_REMOVE: return "Remove";
        case COMMIT_ACTION_SYNC:   return "Sync";
        case COMMIT_ACTION_REVERT: return "Revert";
    }
    return "Unknown";
}

/**
 * Get action name in past tense
 */
const char *commit_action_name_past(commit_action_t action) {
    switch (action) {
        case COMMIT_ACTION_ADD:    return "Added";
        case COMMIT_ACTION_UPDATE: return "Updated";
        case COMMIT_ACTION_REMOVE: return "Removed";
        case COMMIT_ACTION_SYNC:   return "Synced";
        case COMMIT_ACTION_REVERT: return "Reverted";
    }
    return "Unknown";
}

/**
 * Format path list as bullet points with truncation Returns allocated string or
 * NULL on error
 *
 * Both kinds, as the caller handed them over (utils/commit.h): the list says
 * "paths" of what it truncates and of what it has none of, because a commit that
 * claimed a directory and no file has a path to name and no file.
 */
static char *format_path_list(const char *const *paths, size_t count) {
    if (count == 0 || !paths) {
        return strdup("  (no paths)");
    }

    buffer_t buf = BUFFER_INIT;

    /* Show up to MAX_PATHS_DETAIL paths */
    size_t show_count = count < MAX_PATHS_DETAIL ? count : MAX_PATHS_DETAIL;
    error_t *err = NULL;

    for (size_t i = 0; i < show_count; i++) {
        err = buffer_append_string(&buf, "  - ");
        if (!err) err = buffer_append_string(&buf, paths[i]);
        if (!err && (i < show_count - 1 || count > MAX_PATHS_DETAIL)) {
            err = buffer_append_string(&buf, "\n");
        }
        if (err) goto cleanup;
    }

    /* Add truncation notice if needed */
    if (count > MAX_PATHS_DETAIL) {
        char truncate_msg[64];
        snprintf(
            truncate_msg, sizeof(truncate_msg),
            "  ... and %zu more path%s",
            count - MAX_PATHS_DETAIL, (count - MAX_PATHS_DETAIL) == 1 ? "" : "s"
        );
        err = buffer_append_string(&buf, truncate_msg);
        if (err) goto cleanup;
    }

    /* Transfer ownership from buffer to avoid copy */
    return buffer_detach(&buf);

cleanup:
    error_free(err);
    buffer_free(&buf);
    return NULL;
}

/**
 * Substitute template variables in a string
 *
 * Replaces {variable} placeholders with the table's values. A name the table
 * has no row for is left as the template spelled it, braces and all, so a typo
 * empties no line and prose survives a stray brace.
 *
 * @param template Template string with {variable} placeholders
 * @param vars The variables and their values, resolved once by the caller
 * @param var_count How many
 * @return Allocated string with substitutions, or NULL on error
 */
static char *substitute_template(
    const char *template, const template_t *vars, size_t var_count
) {
    if (!template) {
        return NULL;
    }

    buffer_t buf = BUFFER_INIT;
    error_t *err = NULL;

    /* Process template character by character. Three cases, each leaving the
     * loop at its own line: what is not a variable, what is shaped like one and
     * cannot be read, and the name the table answers for. */
    const char *p = template;
    while (*p) {
        /* Where this variable would end. A brace nothing closes opens nothing:
         * it is a character of the template like any other, as is every character
         * that is not a brace at all. */
        const char *end = *p == '{' ? strchr(p, '}') : NULL;
        if (!end) {
            err = buffer_append(&buf, p, 1);
            if (err) goto cleanup;
            p++;
            continue;
        }

        /* A name too long for the scratch is no name: the braced run stands as
         * the template spelled it, and the reader resumes past it. */
        size_t var_len = (size_t) (end - p - 1);
        char var_name[64];

        if (var_len >= sizeof(var_name)) {
            err = buffer_append(&buf, p, (size_t) (end - p) + 1);
            if (err) goto cleanup;
            p = end + 1;
            continue;
        }

        memcpy(var_name, p + 1, var_len);
        var_name[var_len] = '\0';

        /* Substitute variable: the table's row, or no row at all */
        const char *value = NULL;
        for (size_t i = 0; i < var_count; i++) {
            if (strcmp(var_name, vars[i].name) == 0) {
                value = vars[i].value;
                break;
            }
        }

        if (value) {
            err = buffer_append_string(&buf, value);
        } else {
            /* Unknown variable - keep as-is */
            err = buffer_append(&buf, "{", 1);
            if (!err) err = buffer_append_string(&buf, var_name);
            if (!err) err = buffer_append(&buf, "}", 1);
        }
        if (err) goto cleanup;

        p = end + 1;
    }

    /* Transfer ownership from buffer to avoid copy */
    return buffer_detach(&buf);

cleanup:
    error_free(err);
    buffer_free(&buf);

    return NULL;
}

/**
 * Build full commit message (title + body)
 */
static char *build_full_message(const char *title, const char *body) {
    /* Skip body if empty */
    if (body[0] == '\0') {
        return strdup(title);
    }

    /* Calculate size: title + "\n\n" + body + "\0" */
    size_t size = strlen(title) + 2 + strlen(body) + 1;
    char *message = malloc(size);

    if (!message) {
        return NULL;
    }

    snprintf(message, size, "%s\n\n%s", title, body);

    return message;
}

/**
 * Build commit message from context
 */
char *build_commit_message(
    const config_t *config, const commit_message_context_t *ctx
) {
    /* Validate input */
    if (!ctx || !ctx->profile) {
        return NULL;
    }

    /* If custom message provided, use it directly */
    if (ctx->custom_msg) {
        return strdup(ctx->custom_msg);
    }

    /* Get components. Everything allocated here is freed at the one exit below,
     * message and all: each step's failure is the same failure — there is no
     * allocation this function can fail and carry on — so it is spelled once. */
    char *hostname = get_hostname();
    char *username = get_username();
    char *date = get_date_local();
    char *datetime = get_datetime_local();
    char *path_list = format_path_list(ctx->paths, ctx->path_count);
    char *title = NULL, *body = NULL, *message = NULL;

    /* Check allocations */
    if (!hostname || !username || !date || !datetime || !path_list) {
        goto cleanup;
    }

    /* The values this message is made of, resolved once for both templates. The
     * count is rendered here and not in the reader, which is what keeps it the
     * length of the list beside it under any template that names either. */
    char count[32];
    snprintf(count, sizeof(count), "%zu", ctx->path_count);

    const template_t vars[] = {
        { "host",          hostname                                     },
        { "user",          username                                     },
        { "profile",       ctx->profile                                 },
        { "action",        commit_action_name(ctx->action)              },
        { "action_past",   commit_action_name_past(ctx->action)         },
        { "count",         count                                        },
        { "date",          date                                         },
        { "datetime",      datetime                                     },
        { "paths",         path_list                                    },
        { "target_commit", ctx->target_commit ? ctx->target_commit : "" },
    };
    const size_t var_count = sizeof(vars) / sizeof(vars[0]);

    /* Build title and body from their templates */
    title = substitute_template(config->commit_title, vars, var_count);
    if (!title) goto cleanup;

    body = substitute_template(config->commit_body, vars, var_count);
    if (!body) goto cleanup;

    /* Build full message */
    message = build_full_message(title, body);

cleanup:
    free(hostname);
    free(username);
    free(date);
    free(datetime);
    free(path_list);
    free(title);
    free(body);

    return message;
}
