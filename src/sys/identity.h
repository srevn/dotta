/**
 * identity.h - The identity of the run: the invoker, and root held in reserve
 *
 * Who typed the command, and whether the run may act as root. One process fact,
 * established first in main() — before libgit2 reads $HOME at its init, before
 * the config path is resolved — and read by every layer through identity(): the
 * mount table's HOME, tilde expansion, the session cache's path, owner and key,
 * the commit's user, the ownership a deploy applies where a claim is silent,
 * the bootstrap script's working directory.
 *
 * A process fact, not a run member: it is read beneath the run (the mount table,
 * the session cache, the signature) and it is one for every run of the process,
 * so it lives at file scope in the layer that asks the kernel, the way sys/process
 * publishes the child's process group, and never on the context.
 *
 * The invoker
 * -----------
 * The real user — or, when the effective user is root and a privilege tool names
 * who asked for it, that user: root obtained through sudo is a human's, and a
 * `sudo -i` shell inherits SUDO_UID, so dotta in such a shell is the human's
 * too (real root's own dotfiles: `env -u SUDO_UID dotta …`). The tool's word is
 * SUDO_UID as sudo writes it (decimal, whole, a user this host can name), else
 * DOAS_USER as doas writes it (a name — OpenBSD's tool, common on FreeBSD, sets
 * no uid variable). Anything else names nobody — a shim's 99999, a hand-set
 * variable — and the run is real root's own. A tool's variable beside an effective
 * user that is not root (`sudo -u alice`, a shim that did not elevate) is not
 * consulted: the run is its effective user, and nothing warns.
 *
 * The group is the passwd entry's primary group — the durable fact — and the
 * supplementary list is the kernel's for this process, sized by asking (16 on
 * macOS, up to 65536 on Linux, so never an NGROUPS_MAX array). A name is the
 * passwd entry's, and NULL when the database has none (a container's bare uid):
 * the readers cope, each in its own words.
 *
 * HOME
 * ----
 * $HOME — the test isolation pattern, and every explicit intent — unless it is
 * unset, empty, or, under root obtained for a user, root's own home (`-H`, `-i`
 * and always_set_home rewrite it to root's; that is sudo's doing, not the user's),
 * in which case the invoker's passwd entry answers. Absolute, and lexically
 * normalised: a doubled slash inside HOME matched no surface form of the mount
 * table (195 §8), so `home/` classifies under any spelling. Whether the directory
 * exists is not asked here.
 *
 * Privileged
 * ----------
 * The effective user started as uid 0. A real root run (no tool names a user)
 * is root's own: its invoker is root, its files are root's, its HOME is root's
 * unless $HOME says otherwise — consistent, and stated.
 *
 * Readers
 * -------
 * identity() is borrowed and immutable for the life of the process. Every HOME,
 * every user name and every "is this run root's" answer in the process is
 * identity()'s; a second getenv("HOME"), getuid() or SUDO_UID reader is a bug.
 * The two rules identity_init applies are public beneath it, so a suite can pin
 * them without root (tests/test-identity.c); identity_init is their only production
 * caller.
 */

#ifndef DOTTA_SYS_IDENTITY_H
#define DOTTA_SYS_IDENTITY_H

#include <stdbool.h>
#include <sys/types.h>
#include <types.h>

/**
 * The identity of the run
 *
 * Written once by identity_init, borrowed for the life of the process. The strings
 * and the group list are heap allocations that live as long as the process does:
 * nothing frees them, and nothing needs to.
 */
typedef struct identity {
    uid_t uid;               /* The invoker */
    gid_t gid;               /* The invoker's primary group (the passwd entry's) */
    const gid_t *groups;     /* The kernel's supplementary list for this process */
    int ngroups;             /* Its length; 0 when there is none to read */
    const char *name;        /* The passwd entry's name; NULL when it has no entry */
    const char *home;        /* The HOME rule above; absolute, normalised, never NULL */
    bool privileged;         /* Root is held: the effective user started as uid 0 */
} identity_t;

/**
 * Establish the identity of the run
 *
 * Reads the kernel's ids, the privilege tool's variables, the passwd database
 * and $HOME, and applies the two rules below. Called once, first in main();
 * every other entry point of this module reads what it wrote.
 *
 * @return Error when no home directory can be named for the invoker (no $HOME,
 *         no passwd entry) or the one named is not absolute; NULL on success
 */
error_t *identity_init(void);

/**
 * The identity of the run — borrowed, immutable
 *
 * Valid after identity_init returned NULL.
 *
 * @return The identity (never NULL)
 */
const identity_t *identity(void);

/**
 * The invoker rule: who typed the command
 *
 * The real user, unless the effective user is root and a privilege tool names
 * who asked for it — SUDO_UID, else DOAS_USER, read from the environment and
 * checked against the passwd database. A variable that names nobody leaves the
 * real user, which under sudo is root: the run is real root's own.
 *
 * @param ruid The real user (getuid)
 * @param euid The effective user (geteuid)
 * @return The invoker's uid
 */
uid_t identity_invoker(uid_t ruid, uid_t euid);

/**
 * The HOME rule: which directory is the invoker's home
 *
 * $HOME as given, unless it is unset or empty, or `sudoed` and it is root's own
 * home by the passwd database — then the invoker's passwd directory. Returns
 * one of its inputs, or NULL when neither names a directory; the caller normalises.
 *
 * @param env_home $HOME (may be NULL)
 * @param sudoed Root is held and a user is behind it (privileged, uid != 0)
 * @param pw_dir The invoker's passwd directory (may be NULL)
 * @return env_home, pw_dir, or NULL
 */
const char *identity_home(const char *env_home, bool sudoed, const char *pw_dir);

/**
 * May this identity set the pair without root?
 *
 * The kernel's rule for an unprivileged chown: the owner may not be given away
 * (uid is -1 or its own), and the group must be one it holds (-1, the primary,
 * or a supplementary one). A privileged identity may set anything. On macOS the
 * kernel's list is capped at 16 groups where the directory service knows more,
 * so a "no" here can be a "yes" from the kernel — the refusal's remedy (sudo)
 * holds either way.
 *
 * @param id The identity (must not be NULL)
 * @param uid The owner to set, or (uid_t) -1 for no change
 * @param gid The group to set, or (gid_t) -1 for no change
 * @return true iff the pair is the identity's to set
 */
bool identity_may_chown(const identity_t *id, uid_t uid, gid_t gid);

/**
 * The command line that re-runs this invocation as root
 *
 * "sudo [-E] <prog> <args…>", pasteable: an argument sudo's shell would split
 * or expand is single-quoted. `-E` exactly when a DOTTA_* variable is set in
 * the environment — plain sudo's env_reset would drop it, and everything else
 * dotta reads (HOME, the config path, the repository path) resolves from the
 * invoker and needs nothing preserved.
 *
 * @param prog The program's name as the usage lines render it (must not be NULL)
 * @param argc The process's argc
 * @param argv The process's argv; argv[0] is not rendered, prog stands for it
 * @return The line (caller frees), or NULL on allocation failure
 */
char *identity_sudo_hint(const char *prog, int argc, char **argv);

#endif /* DOTTA_SYS_IDENTITY_H */
