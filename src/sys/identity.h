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
 * Privileged, and the drop
 * ------------------------
 * The effective user started as uid 0. When a tool names the user behind it,
 * the run becomes that user at identity_init — its supplementary groups, then
 * its real and effective gid and uid — and keeps root in the saved set: the shape
 * of a setuid tool run by the user, the one shape every syscall's rule and every
 * library are written for (getuid, access(2), libgit2's owner check all answer
 * for the invoker). Everything of dotta's own — the repository, the state, the
 * session cache, a temp worktree — is then made as the invoker, and root is taken
 * back for one syscall at a time where the invoker is refused
 * (identity_raise_on_refusal / identity_lower: sys/filesystem's second try).
 * HOME, USER and LOGNAME are rewritten in the environment for libgit2 and the
 * children; sudo's own variables stay, so a hook may tell. A child of the run
 * drops for good before its exec (identity_drop_child): hooks, scripts, `dotta
 * git` and the editor run as the invoker.
 *
 * A real root run (no tool names a user) drops nothing and raises nothing: its
 * invoker is root, its files are root's, its HOME is root's unless $HOME says
 * otherwise — consistent, and stated.
 *
 * A run that holds no root says so where a refusal root would lift is reported
 * (cmds/add, cmds/update, apply's two preview blocks): the remedy is named —
 * sudo — and never rendered. The invocation is the user's own and needs no spelling
 * back to them, and what sudo does to their environment on the way is sudo's to
 * document, not dotta's. privileged is the whole of what a reader needs there.
 *
 * Readers
 * -------
 * identity() is borrowed and immutable for the life of the process. Every HOME,
 * every user name and every "is this run root's" answer in the process is
 * identity()'s; a second getenv("HOME"), getuid() or SUDO_UID reader is a bug.
 * The raise pair is sys/filesystem's syscall tier's alone; the child drop is
 * every fork's (sys/process, cmds/git, sys/editor). The two rules identity_init
 * applies are public beneath it, so a suite can pin them without root
 * (tests/test-identity.c); identity_init is their only production caller.
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
 * every other entry point of this module reads what it wrote. Sets the process's
 * limits on the way: core dumps off (no core dump holds a key — the soft limit,
 * so a child may still write its own) and, under sudo, the memlock limit raised
 * while root can raise it.
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
 * Take root back for one syscall the invoker was refused
 *
 * Reads errno first: true iff it is EACCES or EPERM and the run holds root for
 * a user, in which case the effective user is now 0 — and the effective group,
 * so what the call creates is root's, as sudo would have made it. The caller
 * repeats its call and lowers at once (identity_lower), so the window is one
 * syscall wide and never spans a call into libgit2, SQLite, the keymgr or a fork.
 * On false nothing changed and errno is still the refused call's.
 *
 * @return true iff the effective identity is root until identity_lower
 */
bool identity_raise_on_refusal(void);

/**
 * The invoker's effective identity again, after a raise
 *
 * errno is preserved: it is the second call's, which the caller reports.
 */
void identity_lower(void);

/**
 * In a forked child, before its exec: the drop made permanent
 *
 * Real, effective and saved ids all the invoker's, so nothing the child execs
 * can raise. Async-signal-safe (the setuid family and nothing else). A run that
 * holds no root, or root's own, changes nothing. Every fork site calls it and
 * reports a failure in its own words.
 *
 * @return 0, or -1 with errno
 */
int identity_drop_child(void);

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

#endif /* DOTTA_SYS_IDENTITY_H */
