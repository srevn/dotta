/**
 * timeutil.c - Time formatting utilities
 */

#include "timeutil.h"

#include <stdbool.h>
#include <stdio.h>

/**
 * Check if year is a leap year
 */
static bool is_leap_year(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

/**
 * Portable, thread-safe replacement for timegm()
 *
 * Converts a struct tm in UTC to time_t using pure calculation without
 * manipulating environment variables (TZ), making it fully thread-safe.
 */
time_t portable_timegm(struct tm *tm) {
    if (!tm) {
        return (time_t)-1;
    }

    /* Validate input ranges */
    if (tm->tm_mon < 0 || tm->tm_mon > 11 ||
        tm->tm_mday < 1 || tm->tm_mday > 31 ||
        tm->tm_hour < 0 || tm->tm_hour > 23 ||
        tm->tm_min < 0 || tm->tm_min > 59 ||
        tm->tm_sec < 0 || tm->tm_sec > 60) {  /* 60 for leap seconds */
        return (time_t)-1;
    }

    /* Normalize year (tm_year is years since 1900) */
    int year = 1900 + tm->tm_year;
    int month = tm->tm_mon;  /* 0-11 */

    /* Calculate days since epoch (1970-01-01)
     * Formula: total_days = (year-1970)*365 + leap_days + month_days + day */

    /* Days from complete years since 1970 (not including leap days yet) */
    long long days = (long long)(year - 1970) * 365;

    /* Add leap days: count leap years from 1970 to (year-1)
     * A year is a leap year if divisible by 4, except century years
     * which must be divisible by 400 */
    for (int y = 1970; y < year; y++) {
        if (is_leap_year(y)) {
            days++;
        }
    }

    /* Days in each month (for non-leap year) */
    static const int days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    /* Add days from complete months in the current year */
    for (int m = 0; m < month; m++) {
        days += days_in_month[m];
        /* Add leap day for February if this is a leap year and we're past February */
        if (m == 1 && is_leap_year(year)) {
            days++;
        }
    }

    /* Add days in current month (tm_mday is 1-based) */
    days += tm->tm_mday - 1;

    /* Convert to seconds and add time components */
    time_t result = days * 86400LL +            /* days to seconds */
                    tm->tm_hour * 3600 +        /* hours to seconds */
                    tm->tm_min * 60 +           /* minutes to seconds */
                    tm->tm_sec;                 /* seconds */

    return result;
}

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
