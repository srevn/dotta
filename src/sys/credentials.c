/**
 * credentials.c - A credential, filled as git fills one: implementation
 *
 * Every rule here is git's, read in lib/git and cited where it is taken, and
 * the flow is run beside git itself (tests/test-credentials-parity.c): the same
 * configuration beneath both, the same helpers asked in the same order with the
 * same request, the same file left behind. In the order it is read: the value;
 * a URL's parts, as git reads them into a credential and spells one back; libgit2's
 * call, and the configuration; the helpers' protocol; git's file; a helper; the
 * person; the three operations.
 */

#include "sys/credentials.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/secure.h"
#include "base/string.h"
#include "base/terminal.h"
#include "base/url.h"
#include "sys/filesystem.h"
#include "sys/identity.h"
#include "sys/process.h"

/* How long a rewrite of git's file asks for its lock, and how long it waits between
 * two tries, in milliseconds: git's own second, the default of its
 * credentialStore.lockTimeoutMS (lib/git/builtin/credential-store.c
 * rewrite_credential_file) */
#define CREDENTIAL_LOCK_WAIT_MS 1000
#define CREDENTIAL_LOCK_STEP_MS 10

/* The links followed from git's file to the file a rewrite replaces, git's own
 * bound (lib/git/lockfile.c resolve_symlink) */
#define CREDENTIAL_LINK_DEPTH 5

/* The bytes git writes as they are where it spells a credential's part, every
 * other escaped: a letter or a digit, and with them the rest of a URL's unreserved
 * bytes (lib/git/url.c is_rfc3986_unreserved) */
#define CREDENTIAL_ALNUM "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define CREDENTIAL_PLAIN CREDENTIAL_ALNUM "-._~"

/* ═══════════════════════════════════════════════════════════════════
 * The value
 * ═══════════════════════════════════════════════════════════════════ */

/* A part given its value, the heap's; what it held wiped */
static void credential_set(char **part, char *value) {
    secure_free_string(*part);
    *part = value;
}

void credential_deinit(credential_t *c) {
    CHECK_NULL(c);

    credential_set(&c->protocol, NULL);
    credential_set(&c->host, NULL);
    credential_set(&c->path, NULL);
    credential_set(&c->username, NULL);
    credential_set(&c->password, NULL);
    credential_set(&c->oauth_refresh_token, NULL);
    arena_free(c->arena);

    *c = (credential_t){ 0 };
}

bool credential_match(const credential_t *want, const credential_t *have) {
    CHECK_NULL(want);
    CHECK_NULL(have);

    return (!want->protocol || str_equal(want->protocol, have->protocol)) &&
           (!want->host || str_equal(want->host, have->host)) &&
           (!want->path || str_equal(want->path, have->path)) &&
           (!want->username || str_equal(want->username, have->username));
}

/* Whether the credential's password has ended, by its helper's word
 * (lib/git/credential.c credential_fill, credential_approve) */
static bool credential_expired(const credential_t *c) {
    return c->password_expiry_utc != 0 && c->password_expiry_utc < (uint64_t) time(NULL);
}

/* The first of the credential's parts that holds a newline, by git's name for
 * it, or NULL: no line of a helper's protocol could carry one (lib/git/credential.c
 * check_url_component) */
static const char *credential_newline(const credential_t *c) {
    const struct {
        const char *name;
        const char *part;
    } parts[] = {
        { "username", c->username },
        { "password", c->password },
        { "protocol", c->protocol },
        { "host",     c->host     },
        { "path",     c->path     },
    };

    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        if (parts[i].part && strchr(parts[i].part, '\n')) {
            return parts[i].name;
        }
    }

    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * A URL's parts
 * ═══════════════════════════════════════════════════════════════════ */

/* A span of a URL decoded as git decodes a credential's part (base/url.h
 * url_decode), the heap's: a password is among what passes here, and ends wiped
 * with the part it becomes */
static char *credential_decode(const char *from, size_t len) {
    char *part = heap_alloc(len + 1);
    url_decode(part, from, len);

    return part;
}

/* A URL's path as git reads one into a credential, the heap's: the '/' before
 * it off, decoded, the '/' it ends on off; NULL where the URL names none
 * (lib/git/credential.c credential_from_url_1) */
static char *credential_path(const char *path) {
    path += strspn(path, "/");
    if (*path == '\0') return NULL;

    char *decoded = credential_decode(path, strlen(path));
    size_t len = strlen(decoded);
    while (len > 1 && decoded[len - 1] == '/') decoded[--len] = '\0';

    return decoded;
}

/**
 * A URL's parts read into a credential, each one it names, as git reads them
 * (lib/git/credential.c credential_from_url_1): a protocol before "://"; a user
 * before an '@' that stands before the path, and a password past a ':' between
 * them; a host; and a path — each decoded, what it replaces wiped. A part the
 * URL leaves out stands as it stood, so one reading serves a configuration section
 * that names a host alone, a line of git's file and a helper's url=, each reader
 * asking of the credential what it needs there. False where a part holds a newline.
 */
static bool credential_read_url(credential_t *c, const char *url) {
    const char *scheme_end = strstr(url, "://");
    const char *from = scheme_end ? scheme_end + 3 : url;
    const char *at = strchr(from, '@');
    const char *colon = strchr(from, ':');
    const char *path = from + strcspn(from, "/?#");

    if (scheme_end && scheme_end > url) {
        credential_set(&c->protocol, heap_strndup(url, (size_t) (scheme_end - url)));
    }

    /* A user, and a password past the ':' that stands before the '@' */
    const char *host = from;
    if (at && at < path) {
        const char *user_end = colon && colon < at ? colon : at;
        credential_set(&c->username, credential_decode(from, (size_t) (user_end - from)));
        if (user_end < at) {
            credential_set(
                &c->password, credential_decode(user_end + 1, (size_t) (at - user_end - 1))
            );
        }
        host = at + 1;
    }
    if (host < path) {
        credential_set(&c->host, credential_decode(host, (size_t) (path - host)));
    }

    char *named = credential_path(path);
    if (named) credential_set(&c->path, named);

    return credential_newline(c) == NULL;
}

/* `text` written at `to` with every byte outside `plain` escaped, in the digits
 * `hex`: git's two escapers differ in which bytes stand plain and in the case
 * of their digits alone (lib/git/strbuf.c strbuf_add_percentencode,
 * strbuf_addstr_urlencode). The place past what was written, at most three bytes
 * for each read. */
static char *credential_escape(char *to, const char *text, const char *plain, const char *hex) {
    for (; *text != '\0'; text++) {
        unsigned char byte = (unsigned char) *text;
        if (strchr(plain, byte)) {
            *to++ = (char) byte;
        } else {
            *to++ = '%';
            *to++ = hex[byte >> 4];
            *to++ = hex[byte & 0xF];
        }
    }

    return to;
}

/**
 * The credential as a URL, the arena's: its protocol, its user where it names
 * one, its host, and its path where it holds one, each part escaped — the URL
 * git matches the configuration's sections against, and the one its questions
 * show (lib/git/credential.c credential_format)
 */
static const char *credential_url(arena_t *arena, const credential_t *c) {
    static const char hex[] = "0123456789ABCDEF";

    /* At most three bytes for each of a part's, and the "://", an '@', a '/'
     * and the NUL */
    size_t room = strlen(c->protocol) + 3 * strlen(c->host) + 6;
    if (c->username) room += 3 * strlen(c->username);
    if (c->path) room += 3 * strlen(c->path);
    char *url = arena_alloc(arena, room);
    char *at = url + snprintf(url, room, "%s://", c->protocol);

    /* Of a user, a '/' is escaped too; of a host, every byte but a letter, a
     * digit and "-.:[]" */
    if (c->username && c->username[0] != '\0') {
        at = credential_escape(at, c->username, CREDENTIAL_PLAIN, hex);
        *at++ = '@';
    }
    at = credential_escape(at, c->host, CREDENTIAL_ALNUM "-.:[]", hex);
    if (c->path) {
        *at++ = '/';
        at = credential_escape(at, c->path, CREDENTIAL_PLAIN "/", hex);
    }
    *at = '\0';

    return url;
}

/* ═══════════════════════════════════════════════════════════════════
 * libgit2's call, and the configuration
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * The request read off libgit2's call: `url` as libgit2 writes one — a scheme,
 * "://", the username and an '@' where it read one, a ':' and a password between
 * them where the URL carries one, the host with a port that is not its scheme's
 * own, then the path from its '/' and a query (lib/libgit2/src/util/net.c
 * git_net_url_fmt)
 */
static error_t credential_read_request(credential_t *c, const char *url, const char *username) {
    const char *host = strstr(url, "://");
    if (!host || host == url) {
        return error_create(ERR_INVALID_ARG, "The URL names no scheme");
    }
    c->protocol = heap_strndup(url, (size_t) (host - url));
    host += 3;

    /* The username is libgit2's own reading, written back as it was read: stepped
     * over by its length, so an '@' it holds — an address, escaped in the URL a
     * person wrote — is none of the host's. A ':' past it opens a password, the
     * URL's own, which libgit2 offered the remote before it called
     * (transports/http.c handle_auth): the remote refused it, and git, which
     * asks nobody past a credential its URL carries, stops there in these words
     * (lib/git/remote-curl.c), its URL beside them. */
    if (username) {
        size_t len = strlen(username);
        if (strncmp(host, username, len) != 0 || (host[len] != '@' && host[len] != ':')) {
            return error_create(ERR_INVALID_ARG, "The URL does not open with its user");
        }
        if (host[len] == ':') {
            return error_create(ERR_INVALID_ARG, "Authentication failed");
        }

        c->username = heap_strdup(username);
        host += len + 1;
    }

    /* The host to the path's '/', as libgit2 names it — decoded, a port its
     * scheme's own gone, an IPv6 address's brackets too — then the path, read
     * as git reads one, its query with it */
    const char *path = host + strcspn(host, "/");
    c->host = heap_strndup(host, (size_t) (path - host));
    c->path = credential_path(path);

    /* A part holding a newline would end a line of a helper's request: refused
     * where git refuses it, by the part's name and no datum — a user is the
     * person's own, and may stand beside a secret */
    const char *part = credential_newline(c);
    if (part) {
        return error_create(
            ERR_INVALID_ARG, "url contains a newline in its %s component", part
        );
    }

    return NULL;
}

/**
 * The configuration's credential.* applied, once a credential: each entry whose
 * section applies, in the configuration's order — the order libgit2's iterator
 * gives a snapshot's levels in, git's own: the system's, the user's two, the
 * store's (lib/libgit2/src/libgit2/config.c all_iter_next; lib/git/credential.c
 * credential_apply_config, credential_config_callback)
 */
static error_t credential_configure(credential_t *c, git_repository *repo) {
    arena_t *frame = arena_create(0);
    git_config *config = NULL;
    git_config_iterator *entries = NULL;
    git_config_entry *entry = NULL;
    error_t err = NULL;

    int rc = git_repository_config_snapshot(&config, repo);
    if (rc == 0) rc = git_config_iterator_new(&entries, config);
    if (rc < 0) {
        err = error_git(rc, "Cannot read the store's configuration");
        goto done;
    }

    /* The credential's own URL, normalized before any entry is read: a section
     * that is a URL is matched against the credential as it stood then, one that
     * is none against the credential as the entries before it left it. The URL's
     * own user outranks the configuration's, and the path is the request's until
     * every section has been matched. */
    url_normal_t own;
    const bool normal = url_normalize(credential_url(frame, c), frame, &own);
    const bool named = c->username != NULL;
    int use_http_path = 0;

    while ((rc = git_config_next(&entry, entries)) == 0) {
        /* "credential.<key>", or "credential.<section>.<key>", the section cut
         * at the name's last '.' (lib/git/urlmatch.c urlmatch_config_entry) */
        if (!str_starts_with(entry->name, "credential.")) continue;

        const char *key = entry->name + strlen("credential.");
        const char *dot = strrchr(key, '.');
        if (dot) {
            /* A section naming a URL git normalizes applies as under git
             * (base/url.h url_match); any other is read by its parts, each one
             * it names the credential's own — "example.com", "https://",
             * "/me/dots.git" (credential.c match_partial_url) */
            const char *section = arena_strndup(frame, key, (size_t) (dot - key));
            url_normal_t pattern;
            credential_t want = { 0 };
            bool applies = url_normalize(section, frame, &pattern)
                ? normal && url_match(&own, &pattern)
                : credential_read_url(&want, section) && credential_match(&want, c);
            credential_deinit(&want);
            if (!applies) continue;

            key = dot + 1;
        }

        /* A key given no value is refused, as git refuses it for every key of a
         * section that applies, under the name git reads it by */
        if (!entry->value) {
            err = error_create(
                ERR_INVALID_ARG, "missing value for 'credential.%s'", key
            );
            goto done;
        }

        if (str_equal(key, "helper")) {
            /* An empty one empties the list before it */
            if (entry->value[0] == '\0') {
                string_array_clear(&c->helpers);
            } else {
                string_array_push(&c->helpers, entry->value);
            }
        } else if (str_equal(key, "username")) {
            if (!named) credential_set(&c->username, heap_strdup(entry->value));
        } else if (str_equal(key, "usehttppath")) {
            if (git_config_parse_bool(&use_http_path, entry->value) < 0) {
                err = error_create(
                    ERR_INVALID_ARG, "bad boolean config value '%s' for 'credential.%s'",
                    entry->value, key
                );
                goto done;
            }
        }
    }
    if (rc != GIT_ITEROVER) {
        err = error_git(rc, "Cannot read the store's configuration");
        goto done;
    }

    /* The path is the request's only where the configuration keeps one */
    if (!use_http_path) credential_set(&c->path, NULL);

done:
    git_config_iterator_free(entries);
    git_config_free(config);
    arena_free(frame);

    return err;
}

error_t credential_init(
    git_repository *repo, const char *url, const char *username, credential_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(url);
    CHECK_NULL(out);

    *out = (credential_t){ .arena = arena_create(0) };
    string_array_init(&out->helpers, out->arena, 0);

    error_t err = credential_read_request(out, url, username);
    if (!err) err = credential_configure(out, repo);
    if (err) credential_deinit(out);

    return err;
}

/* ═══════════════════════════════════════════════════════════════════
 * The helpers' protocol
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * The credential written as a helper reads one, a part a line, in git's order
 * (lib/git/credential.c credential_write). Sized before it is written, so no
 * byte of it is left behind by a buffer that grew. A value holding a line break
 * would end its line and open another: refused in git's words, naming the part
 * (credential_write_item).
 */
static error_t credential_write(const credential_t *c, buffer_t *out) {
    char expiry[24] = "";
    if (c->password_expiry_utc != 0) {
        snprintf(expiry, sizeof(expiry), "%llu", (unsigned long long) c->password_expiry_utc);
    }

    const struct {
        const char *key;
        const char *value;
    } parts[] = {
        { "protocol",            c->protocol                       },
        { "host",                c->host                           },
        { "path",                c->path                           },
        { "username",            c->username                       },
        { "password",            c->password                       },
        { "oauth_refresh_token", c->oauth_refresh_token            },
        { "password_expiry_utc", expiry[0] != '\0' ? expiry : NULL },
    };
    const size_t count = sizeof(parts) / sizeof(parts[0]);

    size_t room = 0;
    for (size_t i = 0; i < count; i++) {
        const char *value = parts[i].value;
        if (!value) continue;

        if (strchr(value, '\n')) {
            return error_create(
                ERR_INVALID_ARG, "credential value for %s contains newline", parts[i].key
            );
        }
        if (strchr(value, '\r')) {
            return error_create(
                ERR_INVALID_ARG, "credential value for %s contains carriage return",
                parts[i].key
            );
        }
        room += strlen(parts[i].key) + strlen(value) + 2;
    }

    buffer_reserve(out, room);
    for (size_t i = 0; i < count; i++) {
        if (parts[i].value) buffer_appendf(out, "%s=%s\n", parts[i].key, parts[i].value);
    }

    return NULL;
}

/**
 * A helper's answer read into the credential, each line a part it names
 * (lib/git/credential.c credential_read): cut in place, to its end or its first
 * empty line. A key git reads and dotta cannot carry is passed over with those
 * neither knows, and a line that is no key=value ends the reading with a warning,
 * the lines before it taken.
 *
 * Then the answer's own words, judged on the credential it left, in git's order
 * (credential.c credential_fill): a password already expired is none; and a helper
 * that said to quit ends the fill — unless its answer made the credential whole,
 * which fills it.
 */
static error_t credential_read(credential_t *c, output_t *out, const char *helper, char *answer) {
    int quit = 0;

    for (char *line = answer, *next; *line != '\0'; line = next) {
        size_t len = strcspn(line, "\n");
        next = line + len + (line[len] == '\n');
        if (len > 0 && line[len - 1] == '\r') len--;
        line[len] = '\0';
        if (len == 0) break;

        char *value = strchr(line, '=');
        if (!value) {
            output_warning(out, OUTPUT_NORMAL, "invalid credential line: %s", line);
            break;
        }
        *value++ = '\0';

        if (str_equal(line, "username")) {
            credential_set(&c->username, heap_strdup(value));
        } else if (str_equal(line, "password")) {
            credential_set(&c->password, heap_strdup(value));
        } else if (str_equal(line, "protocol")) {
            credential_set(&c->protocol, heap_strdup(value));
        } else if (str_equal(line, "host")) {
            credential_set(&c->host, heap_strdup(value));
        } else if (str_equal(line, "path")) {
            credential_set(&c->path, heap_strdup(value));
        } else if (str_equal(line, "oauth_refresh_token")) {
            credential_set(&c->oauth_refresh_token, heap_strdup(value));
        } else if (str_equal(line, "password_expiry_utc")) {
            /* Seconds since the epoch; none where it reads as 0 or past any time */
            errno = 0;
            unsigned long long expiry = strtoull(value, NULL, 10);
            c->password_expiry_utc = errno == ERANGE ? 0 : expiry;
        } else if (str_equal(line, "url")) {
            /* Its parts, as if each had been named: a protocol must stand, and
             * no part hold a newline. git reads the credential anew from it,
             * the helper list it is walking among what it clears, so no later
             * helper is asked; here the helpers stand. Its refusal is git's,
             * less the URL, which may carry a password. */
            const char *scheme_end = strstr(value, "://");
            if (!scheme_end || scheme_end == value || !credential_read_url(c, value)) {
                return error_create(ERR_INVALID_ARG, "credential url cannot be parsed");
            }
        } else if (str_equal(line, "quit")) {
            if (git_config_parse_bool(&quit, value) < 0) {
                return error_create(
                    ERR_INVALID_ARG, "bad boolean config value '%s' for 'quit'", value
                );
            }
        }
    }

    if (credential_expired(c)) {
        credential_set(&c->password, NULL);
        c->password_expiry_utc = 0;
    }

    if (quit && !(c->username && c->password)) {
        return error_create(
            ERR_INVALID_ARG, "credential helper '%s' told us to quit", helper
        );
    }

    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * git's file
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * git's file read whole into *content, as the invoker — asked of the kernel raw,
 * never through the reach (sys/filesystem.h): left empty where no file stands
 * or the invoker may not read it, each of which git reads as no file
 * (lib/git/builtin/credential-store.c parse_credential_file). The open waits on
 * nothing, so a FIFO standing there is refused, never waited for.
 */
static error_t credential_file_read(const char *path, buffer_t *content) {
    *content = (buffer_t){ 0 };

    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 && (errno == ENOENT || errno == EACCES)) {
        buffer_resize(content, 0);
        return NULL;
    }
    if (fd < 0) return error_errno(errno, "Cannot read '%s'", path);

    /* The descriptor's own look, and the read of what it says, which carries no
     * name (sys/filesystem.h fs_read_fd) */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int refused = errno;
        close(fd);
        return error_errno(refused, "Cannot read '%s'", path);
    }

    error_t err = fs_read_fd(fd, &st, content);
    close(fd);

    return error_wrap(err, "Cannot read '%s'", path);
}

/**
 * The next line of git's file from *at, read into `entry` where it is a
 * credential's: a URL naming a protocol, a user and a password
 * (builtin/credential-store.c parse_credential_file). Any other leaves `entry`
 * empty, which answers no request. Ended at its newline for the reading alone,
 * so the file's bytes stand as they were read. NULL at the file's end; *at moved
 * past the line, its newline with it.
 */
static char *credential_file_next(char **at, char *end, credential_t *entry) {
    char *line = *at;
    if (line == end) return NULL;

    /* The last line may end at the buffer's own terminator */
    char *newline = memchr(line, '\n', (size_t) (end - line));
    *at = newline ? newline + 1 : end;
    if (newline) *newline = '\0';

    credential_deinit(entry);
    if (!credential_read_url(entry, line) ||
        !entry->protocol || !entry->username || !entry->password) {
        credential_deinit(entry);
    }
    if (newline) *newline = '\n';

    return line;
}

/**
 * The first line of git's file that answers the credential: its user and its
 * password taken (builtin/credential-store.c lookup_credential)
 */
static error_t credential_file_find(const char *path, credential_t *c) {
    buffer_t content;
    error_t err = credential_file_read(path, &content);
    if (err) return err;

    credential_t entry = { 0 };
    char *at = content.data;
    while (credential_file_next(&at, content.data + content.size, &entry)) {
        if (credential_match(c, &entry)) {
            credential_set(&c->username, heap_strdup(entry.username));
            credential_set(&c->password, heap_strdup(entry.password));
            break;
        }
    }

    credential_deinit(&entry);
    secure_wipe(content.data, content.size);
    buffer_deinit(&content);

    return NULL;
}

/**
 * The file a rewrite of `path` replaces, the arena's: the path itself, or what
 * a link standing there names, followed as git's lock follows one — so a link
 * to the file is kept and its target rewritten, where a rename over the link
 * would leave the target stale (lib/git/lockfile.c resolve_symlink)
 */
static const char *credential_file_target(arena_t *arena, const char *path) {
    for (int depth = 0; depth < CREDENTIAL_LINK_DEPTH; depth++) {
        char link[PATH_MAX];
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len < 0) break;
        link[len] = '\0';

        /* An absolute link is the path; a relative one stands in its place, read
         * from the directory it stands in */
        const char *slash = strrchr(path, '/');
        path = link[0] == '/' || !slash
            ? arena_strdup(arena, link)
            : arena_str_format(arena, "%.*s/%s", (int) (slash - path), path, link);
    }

    return path;
}

/**
 * git's file rewritten under its lock: `line` first, where one is handed — the
 * credential's own — then every line that stood, less those the credential answers:
 * by their request alone where it brings a line (a store), by their password
 * too where it brings none (an erase), so another password's line stays
 * (lib/git/builtin/credential-store.c rewrite_credential_file).
 *
 * The lock is git's — the file's name and ".lock", created for the invoker alone,
 * the new file itself — so a git that writes beside dotta waits its turn, and
 * dotta its. Written only where the file's bytes or its mode would move: git
 * rewrites the same bytes under a new inode, which a copy dotta manages would
 * read as moved after every contact.
 */
static error_t credential_file_rewrite(const char *path, const credential_t *c, const char *line) {
    arena_t *frame = arena_create(0);
    const char *target = credential_file_target(frame, path);
    const char *lock = arena_str_format(frame, "%s.lock", target);
    buffer_t content = BUFFER_INIT;
    buffer_t rewritten = BUFFER_INIT;
    error_t err = NULL;

    /* The lock, asked for until git's own wait has passed */
    int fd = -1;
    for (int waited = 0; fd < 0; waited += CREDENTIAL_LOCK_STEP_MS) {
        fd = open(lock, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST || waited >= CREDENTIAL_LOCK_WAIT_MS) {
            err = error_errno(
                errno, "Cannot lock '%s' within %d ms", target, CREDENTIAL_LOCK_WAIT_MS
            );
            goto done;
        }

        (void) nanosleep(
            &(struct timespec){ .tv_nsec = CREDENTIAL_LOCK_STEP_MS * 1000000L }, NULL
        );
    }

    /* The file as it stands under the lock, and what it becomes: sized before
     * it is written, so no line is left behind by a buffer that grew */
    err = credential_file_read(target, &content);
    if (err) goto unlock;

    buffer_reserve(&rewritten, content.size + (line ? strlen(line) : 0) + 2);
    if (line) buffer_appendf(&rewritten, "%s\n", line);

    credential_t entry = { 0 };
    char *at = content.data;
    char *kept;
    while ((kept = credential_file_next(&at, content.data + content.size, &entry))) {
        if (credential_match(c, &entry) &&
            (line || !c->password || str_equal(c->password, entry.password))) {
            continue;
        }

        /* Kept as it stood, a last line gaining the newline it lacked */
        buffer_append(&rewritten, kept, (size_t) (at - kept));
        if (at[-1] != '\n') buffer_append(&rewritten, "\n", 1);
    }
    credential_deinit(&entry);

    /* Nothing would move: the file holds these bytes, for its owner alone */
    struct stat st;
    if (rewritten.size == content.size &&
        memcmp(rewritten.data, content.data, content.size) == 0 &&
        stat(target, &st) == 0 && (st.st_mode & 07777) == 0600) {
        goto unlock;
    }

    /* Written, and published by its rename: the lock is the file from there */
    err = fs_write_fd(fd, lock, rewritten.data, rewritten.size);
    if (!err && rename(lock, target) != 0) {
        err = error_errno(errno, "Cannot write '%s'", target);
    }
    if (!err) {
        close(fd);
        goto done;
    }

unlock:
    close(fd);
    (void) unlink(lock);

done:
    secure_wipe(rewritten.data, rewritten.size);
    buffer_deinit(&rewritten);
    secure_wipe(content.data, content.size);
    buffer_deinit(&content);
    arena_free(frame);

    return err;
}

/**
 * The credential as git's file spells one, the heap's, a password in it:
 * protocol://user:password@host[/path], each part escaped in lower-case digits,
 * a path's reserved bytes left as they are (lib/git/builtin/credential-store.c
 * store_credential_file)
 */
static char *credential_file_line(const credential_t *c) {
    static const char hex[] = "0123456789abcdef";

    /* At most three bytes for each of a part's, and the "://", a ':', an '@', a
     * '/' and the NUL */
    size_t room = strlen(c->protocol) + 7 +
        3 * (strlen(c->username) + strlen(c->password) + strlen(c->host));
    if (c->path) room += 3 * strlen(c->path);
    char *line = heap_alloc(room);
    char *at = line + snprintf(line, room, "%s://", c->protocol);

    at = credential_escape(at, c->username, CREDENTIAL_PLAIN, hex);
    *at++ = ':';
    at = credential_escape(at, c->password, CREDENTIAL_PLAIN, hex);
    *at++ = '@';
    at = credential_escape(at, c->host, CREDENTIAL_PLAIN, hex);
    if (c->path) {
        *at++ = '/';
        at = credential_escape(at, c->path, CREDENTIAL_PLAIN "!*'();:@&=+$,/?#[]", hex);
    }
    *at = '\0';

    return line;
}

/**
 * git's own helper, `store`, answered by dotta: git's file of credentials read
 * and written as git's helper reads and writes it
 * (lib/git/builtin/credential-store.c). The file is the invoker's:
 * ~/.git-credentials, then the one beneath $XDG_CONFIG_HOME, or ~/.config where
 * that is unset.
 *
 *   get     the first line that answers, of the first file that holds one
 *   store   the credential's line first, in the first file that stands — in
 *           ~/.git-credentials, created, where neither does
 *   erase   the credential's lines out of every file that stands
 *
 * What it could not do is a warning, as a helper's failure is.
 */
static void credential_file(credential_t *c, output_t *out, const char *op) {
    arena_t *frame = arena_create(0);
    const char *home = identity()->home;
    const char *xdg = getenv("XDG_CONFIG_HOME");
    const char *const paths[] = {
        arena_str_format(frame,       "%s/.git-credentials",        home),
        xdg && xdg[0] != '\0'
            ? arena_str_format(frame, "%s/git/credentials",         xdg)
            : arena_str_format(frame, "%s/.config/git/credentials", home),
    };
    struct stat st;
    error_t err = NULL;

    if (str_equal(op, "get")) {
        /* Asked of a credential that lacks a part: the line that answers it makes
         * it whole */
        for (size_t i = 0; i < 2 && !err && !(c->username && c->password); i++) {
            err = credential_file_find(paths[i], c);
        }
    } else if (str_equal(op, "store")) {
        char *line = credential_file_line(c);
        err = credential_file_rewrite(
            stat(paths[0], &st) != 0 && stat(paths[1], &st) == 0 ? paths[1] : paths[0], c, line
        );
        secure_free_string(line);
    } else {
        for (size_t i = 0; i < 2 && !err; i++) {
            if (stat(paths[i], &st) == 0) err = credential_file_rewrite(paths[i], c, NULL);
        }
    }

    if (err) output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
    arena_free(frame);
}

/* ═══════════════════════════════════════════════════════════════════
 * A helper
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * One of a helper's three operations — "get", "store", "erase" — run as git runs
 * it (lib/git/credential.c credential_do, run_credential_helper): git's file
 * where the helper is named `store`; else a line the shell runs — the helper's
 * own past a '!', an absolute path as given, any other name git's
 * `credential-<name>` — the operation its last word, the credential written to
 * it, and for "get" its answer read back. A store and an erase read nothing:
 * their stdout is nobody's, as git leaves it, so a task one leaves running holds
 * nothing of dotta's.
 *
 * The line is the person's configuration, and the shell's; no part of a credential
 * is ever on it. Its environment is dotta's own, as git hands a helper its own,
 * and its exit is unread, as git reads none.
 *
 * What the helper could not do is a warning, and the helper passed over, as git
 * passes over one. The refusal is the operation's own: a credential that cannot
 * be written to a helper, and for a "get" a helper that says to quit or answers
 * what git refuses to read.
 */
static error_t credential_helper(
    credential_t *c, output_t *out, const char *helper, const char *op
) {
    if (str_equal(helper, "store")) {
        credential_file(c, out, op);
        return NULL;
    }

    buffer_t request = BUFFER_INIT;
    error_t err = credential_write(c, &request);
    if (err) return err;

    char *line;
    if (helper[0] == '!') {
        line = heap_str_format("%s %s", helper + 1, op);
    } else if (helper[0] == '/') {
        line = heap_str_format("%s %s", helper, op);
    } else {
        line = heap_str_format("git credential-%s %s", helper, op);
    }
    char **argv = process_shell((char *[]){ line, NULL });

    /* Its words are the terminal's, past the output layer, which sees none of
     * them: the progress line that stands steps aside for its run, and is drawn
     * again once it has ended, beneath what it said and what is said of it here
     * (base/output.h output_suspend_line) */
    process_result_t result = { 0 };
    process_result_t *answer = str_equal(op, "get") ? &result : NULL;
    output_suspend_line(out);

    error_t refused = process_exchange(argv, request.data, request.size, answer);
    if (refused) {
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(refused));
    } else if (answer && result.output_dropped > 0) {
        /* An answer read in part is none, whatever its first lines say */
        output_warning(
            out, OUTPUT_NORMAL, "credential helper '%s' answered more than %zu bytes",
            helper, PROCESS_CAPTURE_MAX
        );
    } else if (answer) {
        err = credential_read(c, out, helper, result.output);
    }
    output_resume_line(out);

    process_result_deinit(&result);
    free(argv);
    free(line);
    secure_wipe(request.data, request.size);
    buffer_deinit(&request);

    return err;
}

/* ═══════════════════════════════════════════════════════════════════
 * The person
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * One question put to the person, as git puts one (lib/git/prompt.c git_prompt):
 * an askpass program handed the question, its first line the answer; else, and
 * where it failed, the terminal, unless GIT_TERMINAL_PROMPT says no. *answer is
 * the heap's, an empty line an answer.
 *
 * An askpass is a program run as named, the question its one argument, never a
 * line the shell reads (prompt.c do_askpass). The refusal is git's sentence,
 * the question's own words in it: "could not read Username for '<url>': ", then
 * why.
 */
static error_t credential_ask_one(
    output_t *out, const char *askpass, const char *question, bool echo, char **answer
) {
    if (askpass && askpass[0] != '\0') {
        process_result_t result;
        error_t refused = process_exchange(
            (char *[]){ (char *) askpass, (char *) question, NULL }, NULL, 0, &result
        );
        if (!refused && result.exit_code == 0) {
            result.output[strcspn(result.output, "\r\n")] = '\0';
            *answer = heap_strdup(result.output);
            process_result_deinit(&result);
            return NULL;
        }

        /* One that failed is said — a program that could not be run in the
         * exchange's own words — and the terminal asked in its place */
        if (refused) {
            output_warning(out, OUTPUT_NORMAL, "%s", error_line(refused));
        } else {
            output_warning(
                out, OUTPUT_NORMAL, "unable to read askpass response from '%s'", askpass
            );
        }
        process_result_deinit(&result);
    }

    /* The terminal, unless GIT_TERMINAL_PROMPT forbids it: a boolean, and refused
     * where it is none, as git refuses it */
    const char *value = getenv("GIT_TERMINAL_PROMPT");
    int allowed = 1;
    if (value && git_config_parse_bool(&allowed, value) < 0) {
        return error_create(
            ERR_INVALID_ARG, "bad boolean environment value '%s' for 'GIT_TERMINAL_PROMPT'",
            value
        );
    }
    error_t err = allowed ? terminal_ask(question, echo, answer)
                          : error_create(ERR_INVALID_ARG, "terminal prompts disabled");

    /* The question's words, less the ": " they end on, which the cause's own
     * joins them by */
    return error_wrap(err, "could not read %.*s", (int) strlen(question) - 2, question);
}

/**
 * Ask the person for what the credential lacks — a username, shown as it is typed,
 * then a password, unseen — where the configuration lets anyone be asked
 * (lib/git/credential.c credential_getpass)
 *
 * Who asks, and whether anyone may, is read here, where git reads it: the askpass
 * is GIT_ASKPASS, else core.askPass, else SSH_ASKPASS — the first that is set,
 * and none where that one is empty — and credential.interactive, false or "never",
 * forbids the asking.
 */
static error_t credential_ask(credential_t *c, git_repository *repo, output_t *out) {
    git_config *config = NULL;
    int rc = git_repository_config_snapshot(&config, repo);
    if (rc < 0) return error_git(rc, "Cannot read the store's configuration");

    const char *value = NULL;
    int interactive = 1;
    if (git_config_get_string(&value, config, "credential.interactive") == 0 &&
        (str_equal(value, "never") ||
        (git_config_parse_bool(&interactive, value) == 0 && !interactive))) {
        git_config_free(config);
        return error_create(ERR_INVALID_ARG, "unable to get password from user");
    }

    const char *askpass = getenv("GIT_ASKPASS");
    if (!askpass) (void) git_config_get_string(&askpass, config, "core.askpass");
    if (!askpass) askpass = getenv("SSH_ASKPASS");

    /* An askpass and the terminal write past the output layer: the progress line
     * that stands steps aside for both questions as one — drawn again between
     * them, it would be drawn over by the second — and comes back beneath the
     * answers (base/output.h output_suspend_line). Each question names the
     * credential as it stands when it is put: the password's, the user just
     * answered. */
    arena_t *frame = arena_create(0);
    error_t err = NULL;
    output_suspend_line(out);

    if (!c->username) {
        const char *url = credential_url(frame, c);
        const char *question = arena_str_format(frame, "Username for '%s': ", url);
        err = credential_ask_one(out, askpass, question, true, &c->username);
    }
    if (!err && !c->password) {
        const char *url = credential_url(frame, c);
        const char *question = arena_str_format(frame, "Password for '%s': ", url);
        err = credential_ask_one(out, askpass, question, false, &c->password);
    }
    output_resume_line(out);

    arena_free(frame);
    git_config_free(config);

    return err;
}

/* ═══════════════════════════════════════════════════════════════════
 * The three operations
 * ═══════════════════════════════════════════════════════════════════ */

error_t credential_fill(credential_t *c, git_repository *repo, output_t *out) {
    CHECK_NULL(c);
    CHECK_NULL(repo);
    CHECK_NULL(out);

    /* Each helper in turn, until one makes the credential whole: what one answers
     * the next is asked with (lib/git/credential.c credential_fill) */
    for (size_t i = 0; i < c->helpers.count && !(c->username && c->password); i++) {
        error_t err = credential_helper(c, out, c->helpers.entries[i], "get");
        if (err) return err;
    }
    if (c->username && c->password) return NULL;

    return credential_ask(c, repo, out);
}

void credential_approve(credential_t *c, output_t *out) {
    CHECK_NULL(c);
    CHECK_NULL(out);

    if (!c->username || !c->password || credential_expired(c)) return;

    for (size_t i = 0; i < c->helpers.count; i++) {
        error_t err = credential_helper(c, out, c->helpers.entries[i], "store");
        if (err) output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
    }
}

void credential_reject(credential_t *c, output_t *out) {
    CHECK_NULL(c);
    CHECK_NULL(out);

    for (size_t i = 0; i < c->helpers.count; i++) {
        error_t err = credential_helper(c, out, c->helpers.entries[i], "erase");
        if (err) output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
    }

    /* What the remote refused is wiped; whose it was stands */
    credential_set(&c->password, NULL);
    credential_set(&c->oauth_refresh_token, NULL);
    c->password_expiry_utc = 0;
}
