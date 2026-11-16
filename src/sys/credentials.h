/**
 * credentials.h - A credential, filled as git fills one
 *
 * One credential: what a remote asks for — the protocol and the host that asked,
 * the path where the configuration keeps one, the user the URL or the configuration
 * names — and what answered it, kept whole: the username, the password, and what
 * a helper sent beside them (password_expiry_utc, oauth_refresh_token), handed
 * back as they came.
 *
 * Made for one call of libgit2's (credential_init): the request read off the
 * URL libgit2 called with, as libgit2 writes one, and the configuration's
 * credential.* applied — every section whose URL matches, in the configuration's
 * order (lib/git/credential.c credential_apply_config; base/url.h url_match).
 * The configuration is the store's as libgit2 composes it, so a helper named in
 * a file that is a git build's own — its system file, Homebrew's and Apple's on
 * a Mac — or carried in the environment (GIT_CONFIG_COUNT, GIT_CONFIG_GLOBAL)
 * is unread: `git config --global credential.helper <name>` names it where libgit2
 * reads.
 *
 * Filled as git fills one (credential_fill; credential.c credential_fill): each
 * helper asked in turn, "get", until the credential holds a username and a
 * password, a helper that says to quit ending the fill only where its answer
 * left one out; then the person — an askpass program (GIT_ASKPASS, core.askPass,
 * SSH_ASKPASS), else the terminal in git's words (base/terminal.h terminal_ask),
 * unless GIT_TERMINAL_PROMPT or credential.interactive forbids it (prompt.c
 * git_prompt).
 *
 * A helper is run as git runs one (credential.c credential_do,
 * run_credential_helper): `!line` by the shell, an absolute path as given, any
 * other name as `git credential-<name>`, the operation its last word — save git's
 * own file of credentials, the helper named `store`, exactly, which dotta reads
 * and writes itself, as the invoker (builtin/credential-store.c), so it answers
 * on a machine that holds no git. A helper is written the credential; its answer
 * is read back for "get" alone (sys/process.h process_exchange); its words are
 * the terminal's; nothing limits it, as nothing limits it under git. What libgit2
 * cannot carry is not passed: the capabilities git announces (authtype, state)
 * and a 401's own header (wwwauth[]), so a credential that is no username and
 * password does not arrive. credential.sanitizePrompt, credential.protectProtocol
 * and credentialStore.lockTimeoutMS are each read as git's default.
 *
 * Approved, every helper is told "store"; rejected, "erase". Holds no session
 * state: which credential a session keeps, and its verdict, are sys/transfer's.
 *
 * Readers: sys/transfer.c transfer_credentials_callback (the request, the fill)
 * and transfer_op_end (the verdicts).
 */

#ifndef DOTTA_CREDENTIALS_H
#define DOTTA_CREDENTIALS_H

#include <git2.h>
#include <stdbool.h>
#include <stdint.h>
#include <types.h>

#include "base/output.h"

/**
 * A credential: its request, its answer, and the helpers the configuration names
 * for it — a value its holder ends with credential_deinit
 */
typedef struct {
    char *protocol;                 /* What the remote asked by: "https", "http" */
    char *host;                     /* The host that asked and its port, as libgit2 names them */
    char *path;                     /* The repository's, where the configuration keeps one */
    char *username;                 /* The URL's, the configuration's or the answer's */
    char *password;                 /* The answer; NULL until one is given */
    char *oauth_refresh_token;      /* A helper's, handed back as it came */
    uint64_t password_expiry_utc;   /* When the password ends, a helper's word; 0: it names none */
    arena_t *arena;                 /* The helpers' lines, the credential's own */
    string_array_t helpers;         /* Each helper's line, in the configuration's order */
} credential_t;

/**
 * The credential a call of libgit2's is for: its request, the configuration applied
 *
 * `url` is the URL libgit2 called with (git_credential_acquire_cb), which libgit2
 * formats itself (lib/libgit2/src/util/net.c git_net_url_fmt) — the remote that
 * answered 401, a redirect's target where one led there; its userinfo decoded
 * and written raw, a port that is its scheme's own left out, an IPv6 address's
 * brackets too — so it is read as libgit2 writes one, never as a URL a person
 * spelled: the username is `username`, libgit2's own reading, stepped over in
 * the URL by its length, an '@' it holds among it; the host runs from past it
 * to the path's '/'; and the path is read as git reads one (credential.c
 * credential_from_url_1), and kept only where credential.useHttpPath says so.
 * What libgit2's formatting loses is lost: a credential for a remote at an IPv6
 * address or at a spelled default port is kept and found under libgit2's spelling,
 * never git's.
 *
 * Refused, each in words that name no URL, since the one libgit2 called with
 * may carry a password: a URL that carries one — libgit2 offered it before it
 * called, the remote refused it, and git, which asks nobody past a credential
 * its URL carries, stops there, "Authentication failed"; a part holding a newline;
 * a credential.* key given no value, or a credential.useHttpPath that is no
 * boolean, as git refuses each; a configuration that cannot be read; and a URL
 * that is not as libgit2 writes one.
 *
 * @param repo The store, whose configuration applies (must not be NULL)
 * @param url The URL libgit2 called with (must not be NULL)
 * @param username The user libgit2 read off it, or NULL
 * @param out The credential (must not be NULL); zeroed on a refusal
 * @return Error or NULL on success
 */
error_t credential_init(
    git_repository *repo, const char *url, const char *username, credential_t *out
);

/**
 * Whether a credential answers a request: each of the protocol, the host, the
 * path and the username the request names is the credential's own, a part it
 * leaves unset matching any (lib/git/credential.c credential_match)
 *
 * Readers: sys/transfer.c transfer_credential_find, the credential a session
 * keeps for a call; this module's own, over a line of git's file and a
 * configuration section that is no URL.
 *
 * @param want The request (must not be NULL)
 * @param have The credential (must not be NULL)
 * @return Whether it answers
 */
bool credential_match(const credential_t *want, const credential_t *have);

/**
 * Fill a credential as git fills one: each helper asked, then the person
 *
 * On success the credential holds a username and a password. What a helper or
 * an askpass could not do is said as a warning and passed over, as git passes
 * over it. A helper's words, an askpass and the terminal's questions are written
 * past the output layer: the progress line that stands steps aside around each
 * helper that is a program and around the person's questions, and is drawn again
 * beneath what was said (base/output.h output_suspend_line); a fill git's file
 * answers moves no line.
 *
 * The failure is the fill's own, in git's words: a helper that said to quit; a
 * value a helper cannot be written, one holding a line break; nobody to ask —
 * "could not read Username for '<url>': " and the terminal's refusal, or "terminal
 * prompts disabled"; a configuration that forbids asking.
 *
 * @param c The credential (must not be NULL; credential_init's)
 * @param repo The store, whose configuration says who asks the person (must not
 *             be NULL)
 * @param out The run's output, for a warning (must not be NULL)
 * @return Error or NULL on success
 */
error_t credential_fill(credential_t *c, git_repository *repo, output_t *out);

/**
 * Tell every helper the credential served: "store". One with no password, or
 * one already expired, is told to none (lib/git/credential.c credential_approve).
 * What a helper could not do is said as a warning.
 *
 * git's file is written only where its bytes or its mode would move: git's own
 * helper rewrites it at every store — the same bytes under a new inode — which
 * a copy dotta manages would read as moved after every contact. A kill between
 * the lock's creation and its rename leaves `<file>.lock` standing, where git
 * takes its own away: every later store then says so until it is removed.
 *
 * @param c The credential (must not be NULL)
 * @param out The run's output, for a warning (must not be NULL)
 */
void credential_approve(credential_t *c, output_t *out);

/**
 * Tell every helper the remote refused the credential: "erase". Its password
 * and what came beside it are wiped; its request and its username stand, for
 * its holder to refuse the same user's later calls — where git lets the username
 * go too, readying the credential for another fill (lib/git/credential.c
 * credential_reject).
 *
 * @param c The credential (must not be NULL)
 * @param out The run's output, for a warning (must not be NULL)
 */
void credential_reject(credential_t *c, output_t *out);

/**
 * End a credential: every string wiped as a secret is, the helpers' lines let
 * go. Idempotent; safe on a zeroed one.
 *
 * @param c The credential (must not be NULL)
 */
void credential_deinit(credential_t *c);

#endif /* DOTTA_CREDENTIALS_H */
