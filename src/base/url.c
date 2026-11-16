/**
 * url.c - A remote's URL, as git reads one
 *
 * Every rule here is git's, read in lib/git and cited where it is taken, and
 * the reading is swept against git itself (tests/test-url-parity.c): where the
 * two part, the bug is here. A byte is classed as git classes it, ASCII alone
 * and in no locale (git-compat-util.h's sane-ctype.h), and a split is cut in
 * one copy of the URL, in place, as git cuts its own.
 */

#include "base/url.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/string.h"

/* A letter or a digit, which opens a scheme; '+', '-' and '.' may follow one
 * (lib/git/url.c is_urlschemechar) */
#define URL_ALNUM "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

/* The protocol each scheme names, compared whole in the case written: git's own
 * transports' (url.c url_get_scheme), then the two its curl helper carries */
static const struct {
    const char *scheme;
    const char *protocol;
} url_schemes[] = {
    { "ssh",     "ssh"   },
    { "git+ssh", "ssh"   },
    { "ssh+git", "ssh"   },
    { "file",    "file"  },
    { "git",     "git"   },
    { "http",    "http"  },
    { "https",   "https" },
};

/* The scheme characters a URL opens with, counted; what follows them is each
 * reader's question — "::" after a helper's name, "://" after a scheme */
static size_t url_scheme_span(const char *url) {
    if (url[0] == '\0' || !strchr(URL_ALNUM, url[0])) return 0;

    return 1 + strspn(url + 1, URL_ALNUM "+-.");
}

const char *url_protocol(const char *url) {
    CHECK_NULL(url);

    /* git's transport, before it parses anything (transport.c transport_get): a
     * name then "::" is a remote helper's, an empty name too, and "rsync:" is
     * refused */
    size_t span = url_scheme_span(url);
    if (str_starts_with(url + span, "::") || str_starts_with(url, "rsync:")) {
        return NULL;
    }

    /* A scheme names one of these transports in its exact spelling, and any other
     * a helper of its own (url.c is_url) */
    if (span > 0 && str_starts_with(url + span, "://")) {
        for (size_t i = 0; i < sizeof(url_schemes) / sizeof(url_schemes[0]); i++) {
            const char *scheme = url_schemes[i].scheme;
            if (strncmp(url, scheme, span) == 0 && scheme[span] == '\0') {
                return url_schemes[i].protocol;
            }
        }

        return NULL;
    }

    /* git's connect (connect.c parse_connect_url): with no scheme, a "://" names
     * a protocol git knows none by; a string holding no ':', or a '/' before
     * its first, is a path (url.c url_is_local_not_ssh), and any other is ssh's */
    if (strstr(url, "://")) return NULL;

    const char *colon = strchr(url, ':');
    const char *slash = strchr(url, '/');
    return !colon || (slash && slash < colon) ? "file" : "ssh";
}

/* A hex digit's value; -1 for any other byte (lib/git/hex-ll.h hexval) */
static int url_hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* The byte the escape at `at` spells — a '%' and the two hex digits after it,
 * within the `left` bytes that stand from it — %00's 0 among them; -1 where none
 * stands (lib/git/hex-ll.h hex2chr) */
static int url_escaped(const char *at, size_t left) {
    if (left < 3 || at[0] != '%') return -1;

    int high = url_hex(at[1]);
    int low = high < 0 ? -1 : url_hex(at[2]);
    return low < 0 ? -1 : high << 4 | low;
}

size_t url_decode(char *to, const char *from, size_t len) {
    CHECK_NULL(to);
    CHECK_NULL(from);

    /* The span, to a NUL standing inside it (url.c url_decode_internal) */
    const char *end = from + strnlen(from, len);
    const char *start = to;

    /* What stands before its first ':' is copied as written: git steps over a
     * URL's scheme so, and asks it of every span it decodes (url_decode_mem) */
    const char *colon = memchr(from, ':', (size_t) (end - from));
    if (colon) {
        memmove(to, from, (size_t) (colon - from));
        to += colon - from;
        from = colon;
    }

    /* Then each escape is the byte it spells, but %00, which spells none and
     * stays as written; every other byte as written */
    while (from < end) {
        int byte = url_escaped(from, (size_t) (end - from));
        *to++ = byte > 0 ? (char) byte : *from;
        from += byte > 0 ? 3 : 1;
    }
    *to = '\0';

    return (size_t) (to - start);
}

/* The '[' of a host's brackets, as git finds them (connect.c host_end): the one
 * of its first "@[" where that stands, else its first byte — a bracket only where
 * a ']' closes it past that; NULL where none stands */
static char *url_bracket(char *host) {
    char *at = strstr(host, "@[");
    char *open = at ? at + 1 : host;

    return open[0] == '[' && strchr(open + 1, ']') ? open : NULL;
}

/* A host's brackets taken off in place: the place past them, or the host itself
 * where none stands (connect.c host_end, removing them) */
static char *url_unbracket(char *host) {
    char *open = url_bracket(host);
    if (!open) return host;

    char *close = strchr(open, ']');
    memmove(open, open + 1, (size_t) (close - open - 1));
    close[-1] = '\0';
    return close + 1;
}

/* The port at a host's ':', strtol's whole reading from 0 to 65535, cut off the
 * host where git takes one (connect.c get_host_and_port, get_port); NULL, the
 * host as it was, where no ':' stands or git takes none */
static char *url_port(char *colon) {
    if (!colon) return NULL;

    char *end;
    long port = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end != '\0' || port < 0 || port > 65535) return NULL;

    *colon = '\0';
    return colon + 1;
}

error_t url_ssh(const char *url, arena_t *arena, url_ssh_t *out) {
    CHECK_NULL(url);
    CHECK_NULL(arena);
    CHECK_NULL(out);
    CHECK_ARG(str_equal(url_protocol(url), "ssh"), "url is no SSH URL");

    /* One copy, cut in place (connect.c parse_connect_url). A URL SSH reaches
     * opens with its scheme or holds no "://": the URL form is decoded whole,
     * as git decodes it, the decoder stepping over the scheme before its ':' —
     * never past the "://", where it would step over a host's escapes before
     * its port — then its host is read from past the "://" and its path at the
     * first '/'; the scp form is never decoded, its path past the first ':'. */
    char *host = arena_strdup(arena, url);
    char separator = ':';
    size_t span = url_scheme_span(host);
    if (str_starts_with(host + span, "://")) {
        url_decode(host, host, strlen(host));
        host += span + 3;
        separator = '/';
    }

    /* The path: at the first separator past a bracketed host, the brackets found
     * in all that follows the host's start; and from a second byte '~' on, git's
     * way to a home, asked of every path */
    char *open = url_bracket(host);
    char *cut = strchr(open ? strchr(open, ']') : host, separator);
    if (!cut) return error_create(ERR_INVALID_ARG, "The URL names no path");

    const char *path = separator == ':' ? cut + 1 : cut;
    if (path[0] != '\0' && path[1] == '~') path++;
    out->path = arena_strdup(arena, path);
    *cut = '\0';

    /* The host, its brackets asked again of it alone and taken off: a port git
     * takes past them is cut off it, an empty one dropped (get_host_and_port);
     * else a port at its first ':', the scp form's "[host:22]:path" (get_port) */
    char *colon = strchr(url_unbracket(host), ':');
    char *port = url_port(colon);
    if (!port && colon && colon[1] == '\0') *colon = '\0';
    out->port = port ? port : url_port(strchr(host, ':'));
    out->host = host;

    return NULL;
}
