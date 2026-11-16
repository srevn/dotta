/**
 * url.h - A remote's URL, as git reads one
 *
 * How a remote is reached is read off its URL alone, with no store in hand, by
 * git's two deciders in git's order: its transport's (lib/git/transport.c
 * transport_get), then its connect's (connect.c parse_connect_url; url.c is_url,
 * url_is_local_not_ssh). Two questions are asked of a URL, so two functions answer:
 * which protocol reaches it, asked at every contact and costing nothing
 * (url_protocol); and what ssh is handed for one SSH reaches — the host, the
 * port and the path, split and decoded as git splits and decodes them (url_ssh;
 * connect.c host_end, get_host_and_port, get_port). A third is asked of a
 * configuration section a URL names — whether it applies to another, the reading
 * git makes of credential.<url>.* and http.<url>.* (url_normalize, url_match;
 * urlmatch.c). Every reading decodes a URL's escapes one way, git's (url_decode;
 * url.c url_decode_mem).
 *
 * The protocol is git's name for it: the key of git's policy
 * (protocol.<name>.allow, transport.c is_transport_allowed) and the word its
 * own diagnosis prints (`git fetch-pack --diag-url`). Strings in, strings out:
 * nothing here opens a store, a file or a connection, so a bundle file, which
 * git's transport tells by its bytes, is a path here like any other.
 */

#ifndef DOTTA_URL_H
#define DOTTA_URL_H

#include <types.h>

/**
 * git's name for the protocol that reaches a URL, or NULL
 *
 * "file" for a path and for file://; "ssh" for host:path and for ssh://, git+ssh://
 * and ssh+git://; "git" for git://; and "http" and "https", which git hands its
 * curl helper (git-remote-http) and libgit2 carries itself, under one name in
 * git's policy either way (transport-helper.c transport_helper_init). NULL where
 * git reaches the URL by none of these: a remote helper's — named before a "::",
 * an empty name too, or by any other scheme, SSH:// among them, since git compares
 * a scheme whole in the case written — and a URL git refuses, rsync: before it
 * reads one and a "://" no scheme stands before. Each holds a ':', and a helper
 * is named by what stands before its first (transport.c
 * external_specification_len).
 *
 * The order is git's: a name then "::", then "rsync:", then a scheme then "://";
 * with none of them, a "://" anywhere refuses, a string holding no ':', or a
 * '/' before its first, is a path, and any other is ssh's. Nothing is allocated
 * and nothing refused: a URL no transport here reaches is its reader's to refuse.
 *
 * Reader: sys/transfer.c transfer_transport_callback, which transport a connection
 * takes.
 *
 * @param url The URL (must not be NULL)
 * @return The name, static; NULL where git hands the URL to a helper or refuses it
 */
const char *url_protocol(const char *url);

/**
 * Decode a span of a URL as git decodes one (lib/git/url.c url_decode_mem)
 *
 * The `len` bytes at `from`, ended early by a NUL among them. What stands before
 * their first ':' is copied as written — git steps over a URL's scheme so, and
 * asks it of every span it decodes, a part of a URL among them, where it keeps
 * a host's escapes before its port as written — then each '%' and the two hex
 * digits after it inside the span is the byte they spell, but %00, which spells
 * none and stays as written; every other byte as written.
 *
 * Written at `to`, the caller's — a secret decoded lands where its caller wipes
 * it, never in an arena — which has room for `len` + 1 bytes and may be `from`
 * itself, no byte being written past the one it was read from; and terminated.
 *
 * Reader: url_ssh, over a whole URL, as git's connect decodes one (connect.c
 * parse_connect_url).
 *
 * @param to Where the decoded bytes go (must not be NULL; room for `len` + 1)
 * @param from The span (must not be NULL)
 * @param len Its length
 * @return The length written at `to`, its NUL not counted
 */
size_t url_decode(char *to, const char *from, size_t len);

/**
 * What ssh is handed for a URL SSH reaches, as git splits it; every part the
 * arena's
 */
typedef struct {
    const char *host;    /* [user@]host, its brackets off */
    const char *port;    /* As the URL spells it; NULL where it names none git takes */
    const char *path;    /* As the far side's command is handed it */
} url_ssh_t;

/**
 * Split a URL SSH reaches, as git splits it
 *
 * The URL form — ssh://, git+ssh://, ssh+git:// — is decoded whole first, its
 * scheme stepped over, as git's connect decodes it (url_decode): "ssh://h%41:22/r"
 * is the host "hA"; the scp form, host:path, never is. The host runs from past
 * the "://", or from the start, to the path: the URL form's first '/', or the
 * scp form's first ':', past a bracketed host — "[::1]", "u@[::1]", "[host:22]":
 * the '[' of the first "@[" past the host's start, or else one opening the host,
 * closed by the first ']' past it (connect.c host_end). That "@[" may stand in
 * the path, which then starts past its ']': "ssh://h/a@[b]/c" is the host "h/a@b"
 * and the path "/c", git's own reading. A path whose second byte is '~' begins
 * there — "/~u/r" is "~u/r", and "a~b/r" is "~b/r", git's too (parse_connect_url).
 *
 * The host's brackets are asked again of the host alone, cut at its path, and
 * taken off it. A port after a ':' past them — strtol's whole reading, 0 to 65535,
 * kept as the URL spells it, "+22" and "022" among them — is cut off the host,
 * an empty one is dropped, and any other is left in the host for ssh to refuse,
 * "host:99999" as git leaves it (get_host_and_port). Where no port stood there,
 * the same is asked at the host's first ':', the scp form's "[host:22]:path"
 * (get_port). A user stays in the host, a password with it: "ssh://u:pw@host/r"
 * hands ssh "u:pw@host".
 *
 * Refused, ERR_INVALID_ARG, where the URL names no path — "ssh://host", "[::1]";
 * "host:" names the empty one — in words that name no URL, which may carry a
 * password. A URL url_protocol does not read as "ssh" is a caller's bug and dies
 * (CHECK_ARG): the shape of a string, checked as a contract where C cannot declare
 * it, as infra/label.h's projections check a storage name's.
 *
 * Reader: sys/ssh.c ssh_start, the line ssh is started with.
 *
 * @param url The URL (must not be NULL; one url_protocol reads as "ssh")
 * @param arena Arena the parts live in (must not be NULL)
 * @param out The parts (must not be NULL)
 * @return Error or NULL on success
 */
error_t url_ssh(const char *url, arena_t *arena, url_ssh_t *out);

/**
 * A URL as git normalizes one to match a configuration section against it
 * (lib/git/urlmatch.c url_normalize_1); every part the arena's
 */
typedef struct {
    const char *scheme;    /* Lowercased */
    const char *user;      /* The userinfo to its first ':'; NULL where it names none, "" the empty one */
    const char *host;      /* Lowercased; "" where a file: URL names none */
    const char *port;      /* Its leading zeros off; NULL where it names none, or its scheme's own */
    const char *path;      /* From its '/', its dot segments resolved, then all that follows it */
} url_normal_t;

/**
 * Normalize a URL as git normalizes one to match a configuration section against
 * it (lib/git/urlmatch.c url_normalize_1)
 *
 * The scheme: letters, digits and "+.-", opening with a letter, then "://";
 * lowercased. The userinfo, where an '@' stands before the path, and the user
 * its bytes to their first ':', a ':' escaped being none. The host, which a file:
 * URL alone may leave unnamed: letters, digits, ".-_", an IPv6 address's "[:]"
 * and a section's wildcard '*'; lowercased. The port, past the last ':' outside
 * the brackets: its leading zeros off, none where it is empty or its scheme's
 * own (http's 80, https's 443), else a number from 1 to 65535 — and none at all
 * on a file: URL that names no host. The path from its '/', which it gains where
 * it has none: a "." taken out, and a ".." with the segment before it; then all
 * that follows it, a query and a fragment.
 *
 * The userinfo's, the path's and the rest's escapes are normalized: one that
 * need not stand, written as its byte; a byte that must stand escaped, as its
 * escape, in upper-case hex; a delimiter, as it was written, escaped or not.
 *
 * Not a URL git normalizes, false, and *out untouched: a scheme not so spelled,
 * no host where the scheme is not file, a byte no host holds, a port that is no
 * number from 1 to 65535 or that a file: URL naming no host names, a '%' that
 * is no escape, a ".." with no segment before it. Its reader reads such a section
 * otherwise, or not at all.
 *
 * '*' is a host's byte here for a section's sake (url_match), where git refuses
 * one in the URL a section is matched against (urlmatch.c url_normalize, beside
 * url_normalize_pattern): a URL formatted with every such byte escaped holds
 * none bare, and a reader whose URL is a person's spelling re-reads this.
 *
 * @param url The URL (must not be NULL)
 * @param arena Arena the parts live in (must not be NULL)
 * @param out The parts (must not be NULL)
 * @return Whether git normalizes it
 */
bool url_normalize(const char *url, arena_t *arena, url_normal_t *out);

/**
 * Whether a configuration section's URL applies to a URL, both normalized
 * (lib/git/urlmatch.c match_urls)
 *
 * The same scheme and the same port; the section's user, where it names one,
 * the URL's own; the host component by component between its dots, a section's
 * "*" any one, neither naming one the other lacks — a trailing dot names none;
 * and the section's path, less a '/' it ends on, the URL's own or a prefix of
 * it ending where a segment does. Whether it applies, never how closely: the
 * closest section for a key of one value is git's question of its http.<url>.*
 * (urlmatch.c cmp_matches), which no reader here asks.
 *
 * @param url The URL (must not be NULL)
 * @param section The section's URL (must not be NULL)
 * @return Whether the section applies to the URL
 */
bool url_match(const url_normal_t *url, const url_normal_t *section);

#endif /* DOTTA_URL_H */
