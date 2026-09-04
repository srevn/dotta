/**
 * identity.c - The identity of the run
 *
 * The process's prologue, in five stanzas: the privilege state every stanza below
 * reads; the limits a secret-bearing process wants, while root — where this run
 * holds any — has not been given away; who the invoker is, by the invoker rule,
 * the passwd entry copied before any other lookup can overwrite it, and the HOME
 * rule, normalised; the drop to that invoker where root was obtained for one,
 * and then the group list it left; and the environment the identity implies.
 * Every stanza runs on every run — only the transition is conditional. Written
 * once into file scope, read for the life of the process.
 */

#include "sys/identity.h"

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

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
    /* The sentinel is refused here and not inside either arm above: one rule
     * about the answer, and both variables can reach it — a decimal SUDO_UID
     * within uid_t, or a DOAS_USER whose passwd entry names it. */
    if (euid == 0 && tool_invoker(&named) && named != (uid_t) -1) return named;
    return ruid;
}

const char *identity_home(const char *env_home, bool sudoed, const char *pw_dir) {
    if (env_home && *env_home && !(sudoed && is_roots_home(env_home))) {
        return env_home;
    }
    return (pw_dir && *pw_dir) ? pw_dir : NULL;
}

/**
 * The drop: the run becomes the invoker, root kept in the saved set.
 *
 * In the order each step needs the one before it: the supplementary groups and
 * the gids while the effective user is still root, the uids last. The real ids
 * move with the effective ones, and setting the real id alone leaves the saved
 * one where it was, so the process ends as (uid, uid, 0) — a setuid tool run by
 * the user — and seteuid(0) stays permitted for the raise.
 *
 * The privilege transition and nothing else. What the run needed root to raise
 * and what its children need to read are the process's own, established for every
 * run whether or not this is called (identity_init).
 */
static error_t *drop_to_invoker(void) {
    if (!id.name) {
        return ERROR(
            ERR_PERMISSION, "Cannot run as uid %u: the user has no name",
            (unsigned) id.uid
        );
    }

    if (initgroups(id.name, id.gid) != 0
        || setregid(id.gid, (gid_t) -1) != 0 || setegid(id.gid) != 0
        || setreuid(id.uid, (uid_t) -1) != 0 || seteuid(id.uid) != 0) {
        /* Coded by subsystem and not by errno, which is why error_from_errno is
         * not the producer here — base/error.h names this site: initgroups can
         * fail EAGAIN or EINVAL on Linux, and error_code_from_errno would call
         * a group-list failure ERR_FS. */
        return ERROR(
            ERR_PERMISSION, "Failed to run as %s (uid %u): %s",
            id.name, (unsigned) id.uid, strerror(errno)
        );
    }

    return NULL;
}

error_t *identity_init(void) {
    uid_t ruid = getuid();
    uid_t euid = geteuid();
    id.privileged = (euid == 0);

    /* No core dump holds a key: the process writes none, from before anything
     * secret-bearing runs. The soft limit alone — a child of the run (a hook,
     * the editor) inherits it and may raise it back for its own crashes; the
     * secrets are this process's, never a child's: the master never leaves this
     * address space, and the passphrase variable is unset by the read, or stripped
     * from the environment a hook or a bootstrap script is built
     * (sys/passphrase.h). Best effort. */
    struct rlimit core;
    if (getrlimit(RLIMIT_CORE, &core) == 0) {
        core.rlim_cur = 0;
        (void) setrlimit(RLIMIT_CORE, &core);
    }

    /* Every lock this run may ask for: secure_alloc pins each secret that outlives
     * a call against swap, and the Argon2 work area alone is 256 MiB at the default
     * strength. Only root may raise a hard limit and this is the last moment
     * root is held — the drop below gives it away — so the hard one goes to
     * infinity where the run holds root at all, and the soft one to whatever
     * the hard one ends up being, which anyone may do. That second half is the
     * case that matters: an unprivileged run is where the lock is refused and
     * the advisory fires (base/secure.h). Best effort — a refusal costs the pinning
     * and nothing else. The raise outlives the drop and every child inherits
     * it, which is the invoker's own hook holding a limit the root it just spent
     * could have handed it anyway. */
    struct rlimit memlock;
    if (getrlimit(RLIMIT_MEMLOCK, &memlock) == 0) {
        if (id.privileged) memlock.rlim_max = RLIM_INFINITY;
        memlock.rlim_cur = memlock.rlim_max;
        (void) setrlimit(RLIMIT_MEMLOCK, &memlock);
    }

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

    /* The drop, before the groups are read: the list below is what the kernel
     * checks the invoker's chown against, and it is the invoker's only after
     * initgroups. */
    if (sudoed) RETURN_IF_ERROR(drop_to_invoker());

    /* The kernel's supplementary list for this process. Sized by asking, never
     * by NGROUPS_MAX; a list that cannot be read is an empty one, and
     * identity_may_chown then answers no where the kernel might say yes. */
    int n = getgroups(0, NULL);
    gid_t *groups = n > 0 ? calloc((size_t) n, sizeof(*groups)) : NULL;
    id.ngroups = groups ? getgroups(n, groups) : 0;
    if (id.ngroups < 0) id.ngroups = 0;
    id.groups = groups;

    /* The environment the identity implies, for libgit2 — which reads $HOME at
     * its init to find the global config — and for every child: a hook and a
     * bootstrap script are built over environ, `dotta git` and the editor exec
     * into it. $HOME is the ruled, normalised answer every layer of this process
     * computes against, so a child asking whether a path dotta handed it starts
     * with $HOME asks the question the mount table already answered; the shell's
     * own spelling, a doubled slash or a trailing dot, answers another. USER
     * and LOGNAME name that same identity — sudo's are root's until this rewrites
     * them, an `env -i` run has none — and a run whose invoker the passwd database
     * cannot name leaves them alone rather than writing a name it does not have.
     * The rules are a fixed point over their own publication: a nested dotta
     * reads back what this one wrote and answers with it. */
    if (setenv("HOME", id.home, 1) != 0) {
        return ERROR(ERR_MEMORY, "Failed to set HOME to '%s'", id.home);
    }
    if (id.name) {
        if (setenv("USER", id.name, 1) != 0
            || setenv("LOGNAME", id.name, 1) != 0) {
            return ERROR(
                ERR_MEMORY, "Failed to set USER and LOGNAME to '%s'", id.name
            );
        }
    }

    return NULL;
}

const identity_t *identity(void) {
    return &id;
}

bool identity_raise_on_refusal(void) {
    if ((errno != EACCES && errno != EPERM) || !id.privileged || id.uid == 0) {
        return false;
    }

    int refused = errno;
    if (seteuid(0) != 0) {
        errno = refused;
        return false;
    }
    (void) setegid(0);

    return true;
}

void identity_lower(void) {
    int saved = errno;
    (void) setegid(id.gid);
    (void) seteuid(id.uid);
    errno = saved;
}

int identity_drop_child(void) {
    if (!id.privileged || id.uid == 0) return 0;

    /* seteuid(0) first: from an unprivileged effective user, setuid changes the
     * effective id alone and leaves the saved root standing; privileged, setgid
     * and setuid set all three. The read-back is the one check a privilege boundary
     * keeps — a kernel that did not drop must not exec. */
    if (seteuid(0) != 0 || setgid(id.gid) != 0 || setuid(id.uid) != 0) return -1;
    if (getuid() != id.uid || geteuid() != id.uid) {
        errno = EPERM;
        return -1;
    }

    return 0;
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
