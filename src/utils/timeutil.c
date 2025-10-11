/**
 * timeutil.c - Time formatting utilities
 */

#include "timeutil.h"

#include <stdio.h>

/**
 * Format timestamp as relative time string
 */
void format_relative_time(time_t timestamp, char *buf, size_t buf_size) {
    time_t now = time(NULL);
    double seconds = difftime(now, timestamp);

    if (seconds < 0) {
        snprintf(buf, buf_size, "in the future");
    } else if (seconds < 60) {
        snprintf(buf, buf_size, "%.0f seconds ago", seconds);
    } else if (seconds < 3600) {
        snprintf(buf, buf_size, "%.0f minutes ago", seconds / 60);
    } else if (seconds < 86400) {
        int hours = (int)(seconds / 3600);
        snprintf(buf, buf_size, "%d hour%s ago", hours, hours == 1 ? "" : "s");
    } else if (seconds < 604800) {
        int days = (int)(seconds / 86400);
        snprintf(buf, buf_size, "%d day%s ago", days, days == 1 ? "" : "s");
    } else if (seconds < 2592000) {
        int weeks = (int)(seconds / 604800);
        snprintf(buf, buf_size, "%d week%s ago", weeks, weeks == 1 ? "" : "s");
    } else if (seconds < 31536000) {
        int months = (int)(seconds / 2592000);
        snprintf(buf, buf_size, "%d month%s ago", months, months == 1 ? "" : "s");
    } else {
        int years = (int)(seconds / 31536000);
        snprintf(buf, buf_size, "%d year%s ago", years, years == 1 ? "" : "s");
    }
}
