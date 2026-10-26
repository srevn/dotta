/**
 * timeutil.h - Time formatting utilities
 *
 * Common utilities for formatting timestamps in human-readable ways.
 */

#ifndef DOTTA_TIMEUTIL_H
#define DOTTA_TIMEUTIL_H

#include <stdbool.h>
#include <time.h>

/**
 * Format timestamp as relative time string
 *
 * The time elapsed since `timestamp`, in the largest unit it has reached — seconds,
 * minutes, hours, days, weeks, months of 30 days, years of 365 — counted in whole
 * units and named in the number it agrees with: "1 second ago", "59 minutes ago",
 * "2 weeks ago", "1 year ago". A timestamp past now reads "in the future".
 *
 * @param timestamp Unix timestamp to format
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 */
void timeutil_relative(time_t timestamp, char *buf, size_t buf_size);

/**
 * Format timestamp as absolute time string
 *
 * The local time `timestamp` names, as Git prints a commit's date: "Sun Oct 26
 * 18:40:00 2025". A timestamp no local time places — a year past what a broken-down
 * time holds (localtime_r), which only a forged commit carries — has no such
 * string, and neither has a buffer too short for it: either is false, and `buf`
 * then holds nothing to read. 64 bytes hold every date there is.
 *
 * @param timestamp Unix timestamp to format
 * @param buf Output buffer
 * @param buf_size Size of output buffer
 * @return true where `buf` holds the date
 */
bool timeutil_absolute(time_t timestamp, char *buf, size_t buf_size);

#endif /* DOTTA_TIMEUTIL_H */
