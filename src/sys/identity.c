/**
 * identity.c - The identity of the run
 *
 * The shell around the two rules: read what the kernel and the environment hand
 * the process, apply the invoker rule, copy the passwd entry before any other
 * lookup can overwrite it, apply the HOME rule, normalise, read the groups. Written
 * once into file scope, read for the life of the process.
 */

#include "sys/identity.h"

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/buffer.h"
#include "base/error.h"
#include "sys/filesystem.h"

static identity_t id;

/**
 * The user a privilege tool names, when its variable names one this host knows.
 *
 * SUDO_UID as sudo writes it: decimal, whole, within uid_t, with a passwd entry
 * — a hand-set variable beyond any of those names nobody, and so does one that
 * sudo wrote for a user this host cannot name. Else DOAS_USER as doas writes
 * it: a name with an entry. A present SUDO_UID is sudo's answer whatever it says;
 * doas is asked only where sudo said nothing.
 */
static bool tool_invoker(uid_t *out) {
    const char *s = getenv("SUDO_UID");
    if (s && *s) {
        char *end;
        errno = 0;
        long long v = strtoll(s, &end, 10);
        if (isdigit((unsigned char) *s) && errno == 0 && *end == '\0'
            && v <= (long long) (uid_t) -1 && getpwuid((uid_t) v)) {
            *out = (uid_t) v;
            return true;
        }
        return false;
    }

    const char *name = getenv("DOAS_USER");
    if (name && *name) {
        struct passwd *pw = getpwnam(name);
        if (pw) {
            *out = pw->pw_uid;
            return true;
        }
    }

    return false;
}

/* Root's own home by the passwd database — /var/root on macOS, /root elsewhere;
 * never the literal. */
static bool is_roots_home(const char *home) {
    struct passwd *root = getpwuid(0);
    return root && root->pw_dir && strcmp(home, root->pw_dir) == 0;
}

uid_t identity_invoker(uid_t ruid, uid_t euid) {
    uid_t named;
    if (euid == 0 && tool_invoker(&named)) return named;
    return ruid;
}

const char *identity_home(const char *env_home, bool sudoed, const char *pw_dir) {
    if (env_home && *env_home && !(sudoed && is_roots_home(env_home))) {
        return env_home;
    }
    return (pw_dir && *pw_dir) ? pw_dir : NULL;
}

error_t *identity_init(void) {
    uid_t ruid = getuid();
    uid_t euid = geteuid();

    id.privileged = (euid == 0);
    id.uid = identity_invoker(ruid, euid);
    bool sudoed = id.privileged && id.uid != 0;

    /* The passwd entry, copied before any other lookup: getpwuid answers from
     * static storage the next lookup overwrites, and the HOME rule makes one.
     * No entry is a container's bare uid — the group is the kernel's and the
     * name stays NULL. */
    struct passwd *pw = getpwuid(id.uid);
    char *name = NULL;
    char *pw_dir = NULL;
    if (pw) {
        id.gid = pw->pw_gid;
        if (pw->pw_name && *pw->pw_name) {
            name = strdup(pw->pw_name);
            if (!name) return ERROR(ERR_MEMORY, "Failed to copy the user name");
        }
        if (pw->pw_dir && *pw->pw_dir) {
            pw_dir = strdup(pw->pw_dir);
            if (!pw_dir) {
                free(name);
                return ERROR(ERR_MEMORY, "Failed to copy the home directory");
            }
        }
    } else {
        id.gid = getgid();
    }
    id.name = name;

    const char *home = identity_home(getenv("HOME"), sudoed, pw_dir);
    error_t *err = NULL;
    if (!home) {
        err = ERROR(
            ERR_FS, "Unable to determine the home directory of uid %u",
            (unsigned) id.uid
        );
    } else if (home[0] != '/') {
        err = ERROR(ERR_INVALID_ARG, "HOME is not an absolute path: '%s'", home);
    } else {
        char *normalized = NULL;
        err = fs_normalize_path(home, &normalized);
        id.home = normalized;
    }
    free(pw_dir);
    if (err) return err;

    /* The kernel's supplementary list for this process. Sized by asking, never
     * by NGROUPS_MAX; a list that cannot be read is an empty one, and
     * identity_may_chown then answers no where the kernel might say yes. */
    int n = getgroups(0, NULL);
    gid_t *groups = n > 0 ? calloc((size_t) n, sizeof(*groups)) : NULL;
    id.ngroups = groups ? getgroups(n, groups) : 0;
    if (id.ngroups < 0) id.ngroups = 0;
    id.groups = groups;

    return NULL;
}

const identity_t *identity(void) {
    return &id;
}

bool identity_may_chown(const identity_t *idn, uid_t uid, gid_t gid) {
    if (idn->privileged) return true;
    if (uid != (uid_t) -1 && uid != idn->uid) return false;
    if (gid == (gid_t) -1 || gid == idn->gid) return true;
    for (int i = 0; i < idn->ngroups; i++) {
        if (idn->groups[i] == gid) return true;
    }

    return false;
}

/* An argument the shell would split, expand or misread stands single-quoted,
 * the quote itself spelled '\'' — the one POSIX quoting that needs no other escape.
 * The safe set is what a path, a flag or a profile name is made of. */
static bool shell_safe(const char *arg) {
    if (*arg == '\0') return false;
    for (const char *p = arg; *p; p++) {
        if (!isalnum((unsigned char) *p) && !strchr("_-./:@%+=,", *p)) {
            return false;
        }
    }

    return true;
}

static error_t *append_argument(buffer_t *buf, const char *arg) {
    if (shell_safe(arg)) return buffer_append_string(buf, arg);

    RETURN_IF_ERROR(buffer_append(buf, "'", 1));
    for (const char *p = arg; *p; p++) {
        if (*p == '\'') {
            RETURN_IF_ERROR(buffer_append_string(buf, "'\\''"));
        } else {
            RETURN_IF_ERROR(buffer_append(buf, p, 1));
        }
    }

    return buffer_append(buf, "'", 1);
}

char *identity_sudo_hint(const char *prog, int argc, char **argv) {
    extern char **environ;
    bool keep = false;
    for (char **e = environ; *e && !keep; e++) {
        keep = strncmp(*e, "DOTTA_", 6) == 0;
    }

    buffer_t buf = BUFFER_INIT;
    error_t *err = buffer_append_string(&buf, keep ? "sudo -E " : "sudo ");
    if (!err) err = buffer_append_string(&buf, prog);
    for (int i = 1; i < argc && !err; i++) {
        err = buffer_append(&buf, " ", 1);
        if (!err) err = append_argument(&buf, argv[i]);
    }

    if (err) {
        error_free(err);
        buffer_free(&buf);
        return NULL;
    }

    return buffer_detach(&buf);
}
