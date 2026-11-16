/**
 * ssh.h - An SSH remote, reached as git reaches one
 *
 * One connection is one child: the machine's ssh, or the command the person
 * configured, started as git starts it at protocol version 0 (lib/git/connect.c
 * git_connect, fill_ssh_args) — its questions and its words the terminal's, as
 * git leaves them — carrying libgit2's smart protocol on its stdin and stdout
 * (sys/process.h process_start). Handed to libgit2 as the transport of a handle
 * whose URL git reads as SSH's (sys/transfer.h transfer_transport_callback;
 * base/url.h url_protocol).
 *
 * The line is git's: the command — GIT_SSH_COMMAND, else core.sshCommand, each
 * a line the shell runs by git's rule (sys/process.h process_shell); else GIT_SSH,
 * else ssh, a program run as named — then the URL's port behind -p and its host,
 * as git splits them (base/url.h url_ssh), and the far side's command: the remote's
 * own program for the service where its configuration names one
 * (remote.<name>.uploadpack, receivepack), else git's, and the URL's path quoted
 * for the shell ssh starts there. A setting that is set and empty is the command,
 * a name no PATH entry holds, as git takes it. Every command is handed its port
 * as OpenSSH reads one: git's variants — ssh.variant, GIT_SSH_VARIANT, a command
 * named plink or tortoiseplink, and the `-G` start that tells one — are unread,
 * so a PuTTY command is handed -p where git hands -P, and tortoiseplink never
 * git's -batch. The child's environment is dotta's own, less the names git takes
 * out of what it starts for a remote (lib/git/environment.c local_repo_env).
 *
 * A path or a host opening with '-' would be an option — to the far side's program,
 * or to ssh — and is refused before any child, as git refuses it, the path's
 * first (connect.c git_connect, fill_ssh_args); git's protocol policy, which
 * git asks between the two, is asked before either (sys/transfer.h).
 *
 * How the child ended is the connection's to know, and is read where its stream
 * ends — at a read's end of output and at a write's refusal — before libgit2
 * words the end: a child that failed is the op's cause, how it ended, and one
 * that exited 0 leaves the end to libgit2's words. libgit2 tells a connection
 * nothing when a service completes (lib/libgit2/src/libgit2/transports/smart.c
 * git_smart__close), so a child still standing then is finished at the close,
 * its status unread, where git reads it after every fetch and push
 * (lib/git/transport.c fetch_refs_via_pack): a child that fails once its pack
 * or its report is whole reads as success.
 *
 * Reader: sys/transfer.c transfer_transport_callback.
 */

#ifndef DOTTA_SSH_H
#define DOTTA_SSH_H

#include <git2.h>

/**
 * A transport that reaches `owner`'s remote through ssh
 *
 * libgit2's smart transport over a connection of this module's, stateful: one
 * stream a connection, its child started by the connection's listing. A failure
 * is libgit2's code, its sentence in libgit2's slot.
 *
 * @param out The transport, `owner`'s to free (must not be NULL)
 * @param owner The handle (must not be NULL; borrowed for the transport's life)
 * @return 0, or libgit2's error code
 */
int ssh_transport(git_transport **out, git_remote *owner);

#endif /* DOTTA_SSH_H */
