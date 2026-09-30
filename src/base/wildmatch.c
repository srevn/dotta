/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with a Linking
 * Exception. For full terms see the included COPYING file.
 *
 * Do shell-style pattern matching for ?, \, [], and * characters. It is 8bit clean.
 *
 * Written by Rich $alz, mirror!rs, Wed Nov 26 19:03:17 EST 1986. Rich $alz is
 * now <rsalz@bbn.com>.
 *
 * Modified by Wayne Davison to special-case '/' matching, to make '**' work
 * differently than '*', and to fix the character-class code.
 *
 * Imported from git.git, its classes and case read from git's own table (below)
 * as git's are. It departs from git's in cost alone, in one branch, and its answers
 * are git's: a <star star slash> link returns the abort its recursion met, where
 * git's drops it and so searches the text twice over a link — a line of links
 * costs time doubling with each, in git as well — and a chain of links is stepped
 * over as its one link, where git's recurses a frame a link and runs a long chain
 * out of stack.
 */

#include "base/wildmatch.h"

#include <string.h>

#define GIT_SPACE 0x01
#define GIT_DIGIT 0x02
#define GIT_ALPHA 0x04
#define GIT_GLOB_SPECIAL 0x08
#define GIT_REGEX_SPECIAL 0x10
#define GIT_PATHSPEC_MAGIC 0x20
#define GIT_CNTRL 0x40
#define GIT_PUNCT 0x80

enum {
    S = GIT_SPACE,
    A = GIT_ALPHA,
    D = GIT_DIGIT,
    G = GIT_GLOB_SPECIAL,   /* *, ?, [, \\ */
    R = GIT_REGEX_SPECIAL,  /* $, (, ), +, ., ^, {, | */
    P = GIT_PATHSPEC_MAGIC, /* other non-alnum, except for ] and } */
    X = GIT_CNTRL,
    U = GIT_PUNCT,
    Z = GIT_CNTRL | GIT_SPACE
};

static const unsigned char sane_ctype[256] = {
    X, X, X, X, X, X, X, X, X, Z, Z, X, X, Z, X, X,     /*   0.. 15 */
    X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,     /*  16.. 31 */
    S, P, P, P, R, P, P, P, R, R, G, R, P, P, R, P,     /*  32.. 47 */
    D, D, D, D, D, D, D, D, D, D, P, P, P, P, P, G,     /*  48.. 63 */
    P, A, A, A, A, A, A, A, A, A, A, A, A, A, A, A,     /*  64.. 79 */
    A, A, A, A, A, A, A, A, A, A, A, G, G, U, R, P,     /*  80.. 95 */
    P, A, A, A, A, A, A, A, A, A, A, A, A, A, A, A,     /*  96..111 */
    A, A, A, A, A, A, A, A, A, A, A, R, R, U, P, X,     /* 112..127 */
    /* Nothing in the 128.. range */
};

#define sane_istest(x, mask) ((sane_ctype[(unsigned char)(x)] & (mask)) != 0)
#define is_glob_special(x) sane_istest(x,GIT_GLOB_SPECIAL)

typedef unsigned char uchar;

/* What character marks an inverted character class? */
#define NEGATE_CLASS    '!'
#define NEGATE_CLASS2   '^'

#define CC_EQ(class, len, litmatch) ((len) == sizeof (litmatch)-1 \
                    && *(class) == *(litmatch) \
                    && strncmp((char*)class, litmatch, len) == 0)

/* Classes and case as git's own matcher reads them — its sane-ctype.h over the
 * table above: ASCII alone, and no locale. The C library's would read `\v` and
 * `\f` as space, and a set LC_CTYPE would give bytes past 0x7F classes and case,
 * which git's never has. */
#define ISSPACE(c)  sane_istest(c, GIT_SPACE)
#define ISDIGIT(c)  sane_istest(c, GIT_DIGIT)
#define ISALPHA(c)  sane_istest(c, GIT_ALPHA)
#define ISALNUM(c)  sane_istest(c, GIT_ALPHA | GIT_DIGIT)
#define ISCNTRL(c)  sane_istest(c, GIT_CNTRL)
#define ISPUNCT(c) \
        sane_istest(c, GIT_PUNCT | GIT_REGEX_SPECIAL | GIT_GLOB_SPECIAL | GIT_PATHSPEC_MAGIC)
#define ISPRINT(c)  ((c) >= 0x20 && (c) <= 0x7e)
#define ISGRAPH(c)  (ISPRINT(c) && !ISSPACE(c))
#define ISBLANK(c)  ((c) == ' ' || (c) == '\t')
#define ISXDIGIT(c) (ISDIGIT(c) || (ISALPHA(c) && ((c) | 0x20) <= 'f'))
#define ISLOWER(c)  (ISALPHA(c) && ((c) & 0x20))
#define ISUPPER(c)  (ISALPHA(c) && !((c) & 0x20))
#define TOLOWER(c)  (ISALPHA(c) ? ((c) | 0x20) : (c))
#define TOUPPER(c)  (ISALPHA(c) ? ((c) & ~0x20) : (c))

/* Match pattern "p" against "text" */
static int dowild(const uchar *p, const uchar *text, unsigned int flags) {
    uchar p_ch;
    const uchar *pattern = p;

    for ( ; (p_ch = *p) != '\0'; text++, p++) {
        int matched, match_slash, negated;
        uchar t_ch, prev_ch;
        if ((t_ch = *text) == '\0' && p_ch != '*')
            return WM_ABORT_ALL;
        if ((flags & WM_CASEFOLD) && ISUPPER(t_ch))
            t_ch = TOLOWER(t_ch);
        if ((flags & WM_CASEFOLD) && ISUPPER(p_ch))
            p_ch = TOLOWER(p_ch);
        switch (p_ch) {
            case '\\':
                /* Literal match with following character.  Note that the test
                 * in "default" handles the p[1] == '\0' failure case. */
                p_ch = *++p;
            /* FALLTHROUGH */
            default:
                if (t_ch != p_ch)
                    return WM_NOMATCH;
                continue;
            case '?':
                /* Match anything but '/'. */
                if ((flags & WM_PATHNAME) && t_ch == '/')
                    return WM_NOMATCH;
                continue;
            case '*':
                if (*++p == '*') {
                    const uchar *prev_p = p;
                    while (*++p == '*') {}
                    if (!(flags & WM_PATHNAME))
                        /* without WM_PATHNAME, '*' == '**' */
                        match_slash = 1;
                    else if ((prev_p - pattern < 2 || *(prev_p - 2) == '/') &&
                        (*p == '\0' || *p == '/' ||
                        (p[0] == '\\' && p[1] == '/'))) {
                        /*
                         * Assuming we already match 'foo/' and are at <star star
                         * slash>, just assume it matches nothing and go ahead
                         * match the rest of the pattern with the remaining string.
                         * This helps make foo/<*><*>/bar (<> because otherwise
                         * it breaks C comment syntax) match both foo/bar and
                         * foo/a/bar.
                         *
                         * A chain of such links matches what its first one does
                         * — no directories or any, twice over, is no directories
                         * or any — so the rest is taken from past the last link:
                         * one frame for the chain, where a frame a link would
                         * run a long chain out of stack.
                         */
                        while (p[0] == '/' && p[1] == '*' && p[2] == '*') {
                            const uchar *next = p + 3;
                            while (*next == '*') next++;
                            if (*next != '/' && *next != '\0')
                                break;
                            p = next;
                        }
                        /*
                         * The rest with no directory consumed is its earliest
                         * start, so an abort there is final for every later one,
                         * as the loop below reads each recursion's abort. Dropped,
                         * it would send each link to search the text twice over:
                         * time doubling with every link of a line.
                         */
                        if (p[0] == '/' &&
                            ((matched = dowild(p + 1, text, flags)) == WM_MATCH ||
                            matched == WM_ABORT_ALL))
                            return matched;
                        match_slash = 1;
                    } else /* WM_PATHNAME is set */
                        match_slash = 0;
                } else
                    /* without WM_PATHNAME, '*' == '**' */
                    match_slash = flags & WM_PATHNAME ? 0 : 1;
                if (*p == '\0') {
                    /* Trailing "**" matches everything.  Trailing "*" matches
                     * only if there are no more slash characters. */
                    if (!match_slash) {
                        if (strchr((char *) text, '/') != NULL)
                            return WM_ABORT_TO_STARSTAR;
                    }
                    return WM_MATCH;
                } else if (!match_slash && *p == '/') {
                    /*
                     * _one_ asterisk followed by a slash with WM_PATHNAME matches
                     * the next directory
                     */
                    const char *slash = strchr((char *) text, '/');
                    if (!slash)
                        return WM_ABORT_ALL;
                    text = (const uchar *) slash;
                    /* the slash is consumed by the top-level for loop */
                    break;
                }
                while (1) {
                    if (t_ch == '\0')
                        break;
                    /*
                     * Try to advance faster when an asterisk is followed by a
                     * literal. We know in this case that the string before the
                     * literal must belong to "*". If match_slash is false, do
                     * not look past the first slash as it cannot belong to '*'.
                     */
                    if (!is_glob_special(*p)) {
                        p_ch = *p;
                        if ((flags & WM_CASEFOLD) && ISUPPER(p_ch))
                            p_ch = TOLOWER(p_ch);
                        while ((t_ch = *text) != '\0' &&
                            (match_slash || t_ch != '/')) {
                            if ((flags & WM_CASEFOLD) && ISUPPER(t_ch))
                                t_ch = TOLOWER(t_ch);
                            if (t_ch == p_ch)
                                break;
                            text++;
                        }
                        if (t_ch != p_ch) {
                            if (match_slash)
                                return WM_ABORT_ALL;
                            else
                                return WM_ABORT_TO_STARSTAR;
                        }
                    }
                    if ((matched = dowild(p, text, flags)) != WM_NOMATCH) {
                        if (!match_slash || matched != WM_ABORT_TO_STARSTAR)
                            return matched;
                    } else if (!match_slash && t_ch == '/')
                        return WM_ABORT_TO_STARSTAR;
                    t_ch = *++text;
                }
                return WM_ABORT_ALL;
            case '[':
                p_ch = *++p;
                #ifdef NEGATE_CLASS2
                if (p_ch == NEGATE_CLASS2)
                    p_ch = NEGATE_CLASS;
                #endif
                /* Assign literal 1/0 because of "matched" comparison. */
                negated = p_ch == NEGATE_CLASS ? 1 : 0;
                if (negated) {
                    /* Inverted character class. */
                    p_ch = *++p;
                }
                prev_ch = 0;
                matched = 0;
                do {
                    if (!p_ch)
                        return WM_ABORT_ALL;
                    if (p_ch == '\\') {
                        p_ch = *++p;
                        if (!p_ch)
                            return WM_ABORT_ALL;
                        if (t_ch == p_ch)
                            matched = 1;
                    } else if (p_ch == '-' && prev_ch && p[1] && p[1] != ']') {
                        p_ch = *++p;
                        if (p_ch == '\\') {
                            p_ch = *++p;
                            if (!p_ch)
                                return WM_ABORT_ALL;
                        }
                        if (t_ch <= p_ch && t_ch >= prev_ch)
                            matched = 1;
                        else if ((flags & WM_CASEFOLD) && ISLOWER(t_ch)) {
                            uchar t_ch_upper = TOUPPER(t_ch);
                            if (t_ch_upper <= p_ch && t_ch_upper >= prev_ch)
                                matched = 1;
                        }
                        p_ch = 0; /* This makes "prev_ch" get set to 0. */
                    } else if (p_ch == '[' && p[1] == ':') {
                        const uchar *s;
                        int i;
                        for (s = p += 2; (p_ch = *p) && p_ch != ']'; p++) {} /*SHARED ITERATOR*/
                        if (!p_ch)
                            return WM_ABORT_ALL;
                        i = (int) (p - s - 1);
                        if (i < 0 || p[-1] != ':') {
                            /* Didn't find ":]", so treat like a normal set. */
                            p = s - 2;
                            p_ch = '[';
                            if (t_ch == p_ch)
                                matched = 1;
                            continue;
                        }
                        if (CC_EQ(s, i, "alnum")) {
                            if (ISALNUM(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "alpha")) {
                            if (ISALPHA(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "blank")) {
                            if (ISBLANK(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "cntrl")) {
                            if (ISCNTRL(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "digit")) {
                            if (ISDIGIT(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "graph")) {
                            if (ISGRAPH(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "lower")) {
                            if (ISLOWER(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "print")) {
                            if (ISPRINT(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "punct")) {
                            if (ISPUNCT(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "space")) {
                            if (ISSPACE(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "upper")) {
                            if (ISUPPER(t_ch))
                                matched = 1;
                            else if ((flags & WM_CASEFOLD) && ISLOWER(t_ch))
                                matched = 1;
                        } else if (CC_EQ(s, i, "xdigit")) {
                            if (ISXDIGIT(t_ch))
                                matched = 1;
                        } else /* malformed [:class:] string */
                            return WM_ABORT_ALL;
                        p_ch = 0; /* This makes "prev_ch" get set to 0. */
                    } else if (t_ch == p_ch)
                        matched = 1;
                } while (prev_ch = p_ch, (p_ch = *++p) != ']');
                if (matched == negated ||
                    ((flags & WM_PATHNAME) && t_ch == '/'))
                    return WM_NOMATCH;
                continue;
        }
    }

    return *text ? WM_NOMATCH : WM_MATCH;
}

/* Match the "pattern" against the "text" string. */
int wildmatch(const char *pattern, const char *text, unsigned int flags) {
    int res = dowild((const uchar *) pattern, (const uchar *) text, flags);
    return res == WM_MATCH ? WM_MATCH : WM_NOMATCH;
}

/* git's simple_length (dir.c:680), reading the same table dowild reads. */
size_t wildmatch_literal_length(const char *pattern) {
    size_t n = 0;
    while (pattern[n] && !is_glob_special(pattern[n]))
        n++;

    return n;
}
