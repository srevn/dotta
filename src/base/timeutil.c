/**
 * timeutil.c - Time formatting utilities
 */

#include "base/timeutil.h"

#include <stdio.h>

/**
 * Format timestamp as relative time string
 */
void timeutil_relative(
    time_t timestamp,
    char *buf,
    size_t buf_size
) {
    time_t now = time(NULL);
    double elapsed = difftime(now, timestamp);

    /* Each unit counts the whole units elapsed and names them in the number they
     * agree with: 90 s is one minute, never two, and 3,599 s is 59 minutes, never
     * the 60 the next unit starts at. */
    if (elapsed < 0) {
        snprintf(
            buf, buf_size, "in the future"
        );
    } else if (elapsed < 60) {
        int seconds = (int) elapsed;
        snprintf(
            buf, buf_size, "%d second%s ago",
            seconds, seconds == 1 ? "" : "s"
        );
    } else if (elapsed < 3600) {
        int minutes = (int) (elapsed / 60);
        snprintf(
            buf, buf_size, "%d minute%s ago",
            minutes, minutes == 1 ? "" : "s"
        );
    } else if (elapsed < 86400) {
        int hours = (int) (elapsed / 3600);
        snprintf(
            buf, buf_size, "%d hour%s ago",
            hours, hours == 1 ? "" : "s"
        );
    } else if (elapsed < 604800) {
        int days = (int) (elapsed / 86400);
        snprintf(
            buf, buf_size, "%d day%s ago",
            days, days == 1 ? "" : "s"
        );
    } else if (elapsed < 2592000) {
        int weeks = (int) (elapsed / 604800);
        snprintf(
            buf, buf_size, "%d week%s ago",
            weeks, weeks == 1 ? "" : "s"
        );
    } else if (elapsed < 31536000) {
        int months = (int) (elapsed / 2592000);
        snprintf(
            buf, buf_size, "%d month%s ago",
            months, months == 1 ? "" : "s"
        );
    } else {
        int years = (int) (elapsed / 31536000);
        snprintf(
            buf, buf_size, "%d year%s ago",
            years, years == 1 ? "" : "s"
        );
    }
}
