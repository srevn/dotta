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

/* A letter, which opens a scheme git normalizes (urlmatch.c url_normalize_1) */
#define URL_ALPHA "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/* A letter or a digit, which opens a scheme; '+', '-' and '.' may follow one
 * (lib/git/url.c is_urlschemechar) */
#define URL_ALNUM URL_ALPHA "0123456789"

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

/* What a URL's escapes are normalized against (urlmatch.c URL_UNSAFE_CHARS,
 * URL_RESERVED): a byte always written escaped, beside every control byte and
 * every byte past ASCII; and a delimiter, left escaped or not as it was written */
#define URL_UNSAFE " <>\"%{}|\\^`"
#define URL_RESERVED ":/?#[]@!$&'()*+,;="

/* An ASCII letter's lower case, any other byte itself */
static char url_lower(char c) {
    return c >= 'A' && c <= 'Z' ? (char) (c - 'A' + 'a') : c;
}

/**
 * `len` bytes of `from` written at `to`, their escapes normalized as git normalizes
 * them (urlmatch.c append_normalized_escapes): an escape that need not stand,
 * its byte; a byte that must stand escaped, its escape, in upper-case hex; a
 * delimiter as it was written. The place past what was written — at most three
 * bytes for each read — or NULL where a '%' is no escape.
 */
static char *url_normalize_escapes(char *to, const char *from, size_t len) {
    static const char hex[] = "0123456789ABCDEF";

    for (const char *end = from + len; from < end;) {
        bool escaped = *from == '%';
        int byte = escaped ? url_escaped(from, (size_t) (end - from)) : (unsigned char) *from;
        if (byte < 0) return NULL;
        from += escaped ? 3 : 1;

        if (byte <= 0x1F || byte >= 0x7F || strchr(URL_UNSAFE, byte) ||
            (escaped && strchr(URL_RESERVED, byte))) {
            *to++ = '%';
            *to++ = hex[byte >> 4];
            *to++ = hex[byte & 0xF];
        } else {
            *to++ = (char) byte;
        }
    }

    return to;
}

bool url_normalize(const char *url, arena_t *arena, url_normal_t *out) {
    CHECK_NULL(url);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* The scheme: letters, digits and "+.-", opening with a letter, then "://" */
    size_t span = strspn(url, URL_ALNUM "+.-");
    if (span == 0 || !strchr(URL_ALPHA, url[0]) || !str_starts_with(url + span, "://")) {
        return false;
    }

    /* Every part in one block, each ended where the next begins: no byte is written
     * as more than three, and the path gains a '/' */
    char *to = arena_alloc(arena, 3 * strlen(url) + 8);
    url_normal_t normal = { .scheme = to };
    for (size_t i = 0; i < span; i++) *to++ = url_lower(url[i]);
    *to++ = '\0';
    url += span + 3;

    /* The userinfo, where an '@' stands before the path: its escapes normalized,
     * and the user its bytes to their first ':', where an escaped one is none.
     * An '@' with nothing before it names the empty user, which is one. */
    const char *path = url + strcspn(url, "/?#");
    const char *at = memchr(url, '@', (size_t) (path - url));
    if (at) {
        char *user = to;
        to = url_normalize_escapes(to, url, (size_t) (at - url));
        if (!to) return false;

        *to++ = '\0';
        user[strcspn(user, ":")] = '\0';
        normal.user = user;
        url = at + 1;
    }

    /* The host, to its port: past the last ':' outside brackets, else none */
    const char *colon = path - 1;
    while (colon > url && *colon != ':' && *colon != ']') colon--;
    if (*colon != ':') colon = path;

    /* None names no host but a file: URL, and one naming none names no port.
     * Its bytes are letters, digits, ".-_", an IPv6 address's "[:]", and a
     * section's wildcard '*'. */
    if (colon == url && (!str_equal(normal.scheme, "file") || colon + 1 < path)) {
        return false;
    }
    if (strspn(url, URL_ALNUM ".-_[:]*") < (size_t) (colon - url)) return false;

    normal.host = to;
    while (url < colon) *to++ = url_lower(*url++);
    *to++ = '\0';

    /* The port, its leading zeros off: none where it is empty or its scheme's
     * own, else a number from 1 to 65535 */
    if (colon < path) {
        const char *digits = colon + 1 + strspn(colon + 1, "0");
        if (digits == path && digits[-1] == '0') digits--;
        size_t len = (size_t) (path - digits);

        bool own =
            (str_equal(normal.scheme, "http") && len == 2 && strncmp(digits, "80", 2) == 0) ||
            (str_equal(normal.scheme, "https") && len == 3 && strncmp(digits, "443", 3) == 0);
        if (len > 0 && !own) {
            unsigned long number = len <= 5 ? strtoul(digits, NULL, 10) : 0;
            if (strspn(digits, "0123456789") < len || number == 0 || number > 65535) {
                return false;
            }

            normal.port = to;
            memcpy(to, digits, len);
            to += len;
            *to++ = '\0';
        }
    }

    /* The path from its '/', a segment at a time, each written behind a '/' with
     * its escapes normalized: a "." taken out with its '/', and a ".." with the
     * segment before it — none before it is no URL. A path they leave empty is
     * its '/' alone. */
    char *root = to;
    url = path + (*path == '/');
    for (;;) {
        *to++ = '/';
        char *segment = to;
        const char *next = url + strcspn(url, "/?#");
        to = url_normalize_escapes(to, url, (size_t) (next - url));
        if (!to) return false;

        *to = '\0';
        if (str_equal(segment, ".")) {
            to = segment - 1;
        } else if (str_equal(segment, "..")) {
            if (segment - 1 == root) return false;

            to = segment - 1;
            while (*--to != '/') { }
        }

        url = next;
        if (*url != '/') break;
        url++;
    }
    if (to == root) *to++ = '/';

    /* Then what follows it — a query, a fragment — its escapes normalized: the
     * path's own to a match (url_match) */
    to = url_normalize_escapes(to, url, strlen(url));
    if (!to) return false;

    *to = '\0';
    normal.path = root;
    *out = normal;
    return true;
}

bool url_match(const url_normal_t *url, const url_normal_t *section) {
    CHECK_NULL(url);
    CHECK_NULL(section);

    /* The same scheme and the same port, and the section's user, where it names
     * one, the URL's own */
    if (!str_equal(url->scheme, section->scheme) ||
        !str_equal(url->port, section->port)) {
        return false;
    }
    if (section->user && !str_equal(url->user, section->user)) return false;

    /* The host, component by component: a section's "*" is any one, and neither
     * names one the other lacks (urlmatch.c match_host) */
    const char *host = url->host;
    const char *wild = section->host;
    while (*host != '\0' && *wild != '\0') {
        size_t host_len = strcspn(host, ".");
        size_t wild_len = strcspn(wild, ".");
        if (!(wild_len == 1 && wild[0] == '*') &&
            (host_len != wild_len || memcmp(host, wild, host_len) != 0)) {
            return false;
        }

        host += host_len + (host[host_len] == '.');
        wild += wild_len + (wild[wild_len] == '.');
    }
    if (*host != '\0' || *wild != '\0') return false;

    /* The path: the section's, less a '/' it ends on, the URL's own or a prefix
     * of it that ends where a segment does (url_match_prefix) */
    size_t len = strlen(section->path);
    if (section->path[len - 1] == '/') len--;

    return strncmp(url->path, section->path, len) == 0 &&
           (url->path[len] == '\0' || url->path[len] == '/');
}
