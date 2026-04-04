/**
 * commit.c - Commit message template builder implementation
 */

#include "commit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base/error.h"
#include "buffer.h"
#include "config.h"

/* Maximum length for hostname and username */
#define MAX_HOSTNAME 256
#define MAX_USERNAME 256

/* Maximum files to show in detail before truncating */
#define MAX_FILES_DETAIL 5

/**
 * Get current hostname
 * Returns allocated string or NULL on error
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
 * Get current username
 * Returns allocated string or NULL on error
 */
static char *get_username(void) {
    /* Prefer USER env var (reliable in non-TTY contexts) */
    const char *user = getenv("USER");
    if (user && user[0] != '\0') {
        return strdup(user);
    }

    /* Fallback to getlogin (TTY-dependent) */
    char *login = getlogin();
    if (login && login[0] != '\0') {
        return strdup(login);
    }

    return strdup("unknown");
}

/**
 * Get current datetime in local timezone as ISO 8601 format
 * Returns allocated string or NULL on error
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
 * Get current date in ISO 8601 format (YYYY-MM-DD)
 * Returns allocated string or NULL on error
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
 */
const char *commit_action_name(commit_action_t action) {
    switch (action) {
        case COMMIT_ACTION_ADD:    return "Add";
        case COMMIT_ACTION_UPDATE: return "Update";
        case COMMIT_ACTION_REMOVE: return "Remove";
        case COMMIT_ACTION_SYNC:   return "Sync";
        case COMMIT_ACTION_REVERT: return "Revert";
        default:                   return "Unknown";
    }
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
        default:                   return "Unknown";
    }
}

/**
 * Format file list as bullet points with truncation
 * Returns allocated string or NULL on error
 */
static char *format_file_list(char **files, size_t count) {
    if (count == 0 || !files) {
        return strdup("  (no files)");
    }

    buffer_t *buf = buffer_create();
    if (!buf) {
        return NULL;
    }

    /* Show up to MAX_FILES_DETAIL files */
    size_t show_count = count < MAX_FILES_DETAIL ? count : MAX_FILES_DETAIL;
    error_t *err = NULL;

    for (size_t i = 0; i < show_count; i++) {
        err = buffer_append_string(buf, "  - ");
        if (!err) err = buffer_append_string(buf, files[i]);
        if (!err && (i < show_count - 1 || count > MAX_FILES_DETAIL)) {
            err = buffer_append_string(buf, "\n");
        }
        if (err) goto cleanup;
    }

    /* Add truncation notice if needed */
    if (count > MAX_FILES_DETAIL) {
        char truncate_msg[64];
        snprintf(
            truncate_msg, sizeof(truncate_msg),
            "  ... and %zu more file%s",
            count - MAX_FILES_DETAIL, (count - MAX_FILES_DETAIL) == 1 ? "" : "s"
        );
        err = buffer_append_string(buf, truncate_msg);
        if (err) goto cleanup;
    }

    /* Transfer ownership from buffer to avoid copy */
    char *result = NULL;
    err = buffer_release_data(buf, &result);
    if (err) {
        error_free(err);
        return NULL;
    }

    return result;

cleanup:
    error_free(err);
    buffer_free(buf);
    return NULL;
}

/**
 * Substitute template variables in a string
 *
 * Replaces {variable} placeholders with actual values.
 * Variables: host, user, profile, action, action_past,
 * count, date, datetime, files, target_commit
 *
 * @param template Template string with {variable} placeholders
 * @param hostname Hostname value
 * @param username Username value
 * @param profile Profile name
 * @param action Action name (present tense)
 * @param action_past Action name (past tense)
 * @param file_count Number of files
 * @param date Date string (YYYY-MM-DD)
 * @param datetime Datetime string
 * @param file_list Formatted file list
 * @param target_commit Target commit SHA (can be NULL)
 * @return Allocated string with substitutions, or NULL on error
 */
static char *substitute_template(
    const char *template,
    const char *hostname,
    const char *username,
    const char *profile,
    const char *action,
    const char *action_past,
    size_t file_count,
    const char *date,
    const char *datetime,
    const char *file_list,
    const char *target_commit
) {
    if (!template) {
        return NULL;
    }

    buffer_t *buf = buffer_create();
    if (!buf) {
        return NULL;
    }

    /* File count as string */
    char count_str[32];
    snprintf(count_str, sizeof(count_str), "%zu", file_count);

    error_t *err = NULL;

    /* Process template character by character */
    const char *p = template;
    while (*p) {
        if (*p == '{') {
            /* Found potential variable start */
            const char *end = strchr(p, '}');
            if (end) {
                /* Extract variable name */
                size_t var_len = (size_t) (end - p - 1);
                char var_name[64];

                if (var_len < sizeof(var_name)) {
                    memcpy(var_name, p + 1, var_len);
                    var_name[var_len] = '\0';

                    /* Substitute variable */
                    const char *value = NULL;
                    if (strcmp(var_name, "host") == 0) {
                        value = hostname;
                    } else if (strcmp(var_name, "user") == 0) {
                        value = username;
                    } else if (strcmp(var_name, "profile") == 0) {
                        value = profile;
                    } else if (strcmp(var_name, "action") == 0) {
                        value = action;
                    } else if (strcmp(var_name, "action_past") == 0) {
                        value = action_past;
                    } else if (strcmp(var_name, "count") == 0) {
                        value = count_str;
                    } else if (strcmp(var_name, "date") == 0) {
                        value = date;
                    } else if (strcmp(var_name, "datetime") == 0) {
                        value = datetime;
                    } else if (strcmp(var_name, "files") == 0) {
                        value = file_list;
                    } else if (strcmp(var_name, "target_commit") == 0) {
                        value = target_commit ? target_commit : "";
                    }

                    if (value) {
                        err = buffer_append_string(buf, value);
                    } else {
                        /* Unknown variable - keep as-is */
                        err = buffer_append(buf, (const unsigned char *) "{", 1);
                        if (!err) err = buffer_append_string(buf, var_name);
                        if (!err) err = buffer_append(buf, (const unsigned char *) "}", 1);
                    }

                    if (err) goto cleanup;
                    p = end + 1;
                    continue;
                }

                /* Variable name too long - preserve as literal text */
                size_t literal_len = (size_t) (end - p) + 1;
                err = buffer_append(buf, (const unsigned char *) p, literal_len);
                if (err) goto cleanup;
                p = end + 1;
                continue;
            }
        }

        /* Regular character */
        err = buffer_append(buf, (const unsigned char *) p, 1);
        if (err) goto cleanup;
        p++;
    }

    /* Transfer ownership from buffer to avoid copy */
    char *result = NULL;
    err = buffer_release_data(buf, &result);
    if (err) {
        error_free(err);
        return NULL;
    }

    return result;

cleanup:
    error_free(err);
    buffer_free(buf);
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
    const dotta_config_t *config,
    const commit_message_context_t *ctx
) {
    /* Validate input */
    if (!ctx || !ctx->profile) {
        return NULL;
    }

    /* If custom message provided, use it directly */
    if (ctx->custom_msg) {
        return strdup(ctx->custom_msg);
    }

    /* Load config if not provided */
    dotta_config_t *temp_config = NULL;
    if (!config) {
        temp_config = config_create_default();
        if (!temp_config) {
            return NULL;
        }
        config = temp_config;
    }

    /* Get components */
    char *hostname = get_hostname();
    char *username = get_username();
    char *date = get_date_local();
    char *datetime = get_datetime_local();
    const char *action = commit_action_name(ctx->action);
    const char *action_past = commit_action_name_past(ctx->action);
    char *file_list = format_file_list(ctx->files, ctx->file_count);

    /* Check allocations */
    if (!hostname || !username || !date || !datetime || !file_list) {
        free(hostname);
        free(username);
        free(date);
        free(datetime);
        free(file_list);
        config_free(temp_config);
        return NULL;
    }

    /* Build title from template */
    char *title = substitute_template(
        config->commit_title,
        hostname,
        username,
        ctx->profile,
        action,
        action_past,
        ctx->file_count,
        date,
        datetime,
        file_list,
        ctx->target_commit
    );

    if (!title) {
        free(hostname);
        free(username);
        free(date);
        free(datetime);
        free(file_list);
        config_free(temp_config);
        return NULL;
    }

    /* Build body from template */
    char *body = substitute_template(
        config->commit_body,
        hostname,
        username,
        ctx->profile,
        action,
        action_past,
        ctx->file_count,
        date,
        datetime,
        file_list,
        ctx->target_commit
    );

    /* Free intermediate allocations */
    free(hostname);
    free(username);
    free(date);
    free(datetime);
    free(file_list);
    config_free(temp_config);

    if (!body) {
        free(title);
        return NULL;
    }

    /* Build full message */
    char *message = build_full_message(title, body);

    free(title);
    free(body);

    return message;
}
