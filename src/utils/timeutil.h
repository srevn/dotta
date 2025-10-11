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

#endif /* DOTTA_TIMEUTIL_H */
