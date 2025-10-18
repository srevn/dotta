/**
 * timeutil.h - Time formatting utilities
 *
 * Common utilities for formatting timestamps in human-readable ways.
 */

#ifndef DOTTA_TIMEUTIL_H
#define DOTTA_TIMEUTIL_H

#include <time.h>
#include <stddef.h>

/**
 * Format timestamp as relative time string
 *
 * Converts a timestamp to a human-readable relative time like:
 * - "5 seconds ago"
 * - "2 hours ago"
 * - "3 days ago"
 * - "2 weeks ago"
 * - "6 months ago"
 * - "1 year ago"
 *
 * @param timestamp Unix timestamp to format
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 */
void format_relative_time(time_t timestamp, char *buf, size_t buf_size);

/**
 * Portable, thread-safe replacement for timegm() (which is not POSIX standard)
 *
 * Converts a struct tm in UTC to time_t using pure calculation without
 * manipulating environment variables (TZ), making it fully thread-safe.
 * It does not normalize out-of-range `tm` values (e.g. a month greater than 11).
 *
 * This implementation calculates seconds since Unix epoch (1970-01-01 00:00:00 UTC)
 * using a formula based on the proleptic Gregorian calendar.
 *
 * @param tm Time structure in UTC. Must not be NULL and its members must be within
 *           their valid ranges.
 * @return time_t value, or (time_t)-1 on error
 */
time_t portable_timegm(struct tm *tm);

#endif /* DOTTA_TIMEUTIL_H */
