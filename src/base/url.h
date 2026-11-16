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
 * connect.c host_end, get_host_and_port, get_port; url.c url_decode_mem).
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
 * @param url The URL (must not be NULL)
 * @return The name, static; NULL where git hands the URL to a helper or refuses it
 */
const char *url_protocol(const char *url);

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
 * The URL form — ssh://, git+ssh://, ssh+git:// — is percent-decoded past its
 * scheme first, each '%' and two hex digits the byte they spell but %00, which
 * spells none and stays as written (url.c url_decode_mem); the scp form, host:path,
 * never is. The host runs from past the "://", or from the start, to the path:
 * the URL form's first '/', or the scp form's first ':', past a bracketed host
 * — "[::1]", "u@[::1]", "[host:22]": the '[' of the first "@[" past the host's
 * start, or else one opening the host, closed by the first ']' past it (connect.c
 * host_end). That "@[" may stand in the path, which then starts past its ']':
 * "ssh://h/a@[b]/c" is the host "h/a@b" and the path "/c", git's own reading. A
 * path whose second byte is '~' begins there — "/~u/r" is "~u/r", and "a~b/r"
 * is "~b/r", git's too (parse_connect_url).
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
 * @param url The URL (must not be NULL; one url_protocol reads as "ssh")
 * @param arena Arena the parts live in (must not be NULL)
 * @param out The parts (must not be NULL)
 * @return Error or NULL on success
 */
error_t url_ssh(const char *url, arena_t *arena, url_ssh_t *out);

#endif /* DOTTA_URL_H */
