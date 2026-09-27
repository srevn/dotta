/**
 * timeutil.h - Time formatting utilities
 *
 * Common utilities for formatting timestamps in human-readable ways.
 */

#ifndef DOTTA_TIMEUTIL_H
#define DOTTA_TIMEUTIL_H

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

#endif /* DOTTA_TIMEUTIL_H */
