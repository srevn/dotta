/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with a Linking
 * Exception. For full terms see the included COPYING file.
 */

#ifndef DOTTA_WILDMATCH_H
#define DOTTA_WILDMATCH_H

#include <stddef.h>

#define WM_CASEFOLD 1
#define WM_PATHNAME 2

#define WM_NOMATCH 1
#define WM_MATCH 0
#define WM_ABORT_ALL -1
#define WM_ABORT_TO_STARSTAR -2

int wildmatch(const char *pattern, const char *text, unsigned int flags);

/**
 * How many leading bytes of `pattern` this matcher reads as themselves.
 *
 * The offset of the first byte it reads as more than itself — `*`, `?`, `[` or
 * the `\` that escapes one. The alphabet is the matcher's own, which is why the
 * question is answered here and not restated by a caller: a caller holding its
 * own copy of it would keep answering after the matcher's changed.
 *
 * `wildmatch_literal_length(p) == strlen(p)` says the whole pattern is a literal,
 * and a caller may answer it with a length check and a memcmp instead of a match.
 * A shorter answer bounds the head that can be compared that way. git's
 * simple_length (dir.c:680); `no_wildcard(p)` is `p[literal_length(p)] == '\0'`.
 *
 * @param pattern NUL-terminated pattern (must not be NULL)
 * @return Byte count, 0 when the first byte can glob
 */
size_t wildmatch_literal_length(const char *pattern);

#endif /* DOTTA_WILDMATCH_H */
