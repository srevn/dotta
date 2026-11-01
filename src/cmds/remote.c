/**
 * remote.c - Manage remote repositories
 */

#include "cmds/remote.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/args.h"
#include "base/error.h"
#include "base/heap.h"
#include "base/output.h"
#include "cmds/completion.h"
#include "sys/remote.h"

/**
 * List remotes: each one's name, and at -v its URLs, a row for where a fetch
 * reaches it and one for where a push does, as git's remote -v lists them
 *
 * The push row is the push URL configured, else the fetch URL — remote_show's
 * reading — and a URL the configuration holds none of, a remote written by hand,
 * is none.
 */
static error_t remote_list(
    git_repository *repo,
    output_t *out
) {
    CHECK_NULL(repo);

    git_strarray remotes = { 0 };
    int rc = git_remote_list(&remotes, repo);
    if (rc < 0) return error_git(rc, "Cannot list the remotes");

    if (remotes.count == 0) {
        output_summary(out, OUTPUT_NORMAL, "No remotes configured");
        git_strarray_dispose(&remotes);
        return NULL;
    }

    /* List each remote */
    for (size_t i = 0; i < remotes.count; i++) {
        const char *remote_name = remotes.strings[i];

        if (output_is_verbose(out)) {
            /* Show URLs for fetch and push */
            git_remote *remote = NULL;
            rc = git_remote_lookup(&remote, repo, remote_name);
            if (rc < 0) {
                /* The name is the listing's, so the error is made before it goes */
                error_t err = error_git(rc, "Cannot read remote '%s'", remote_name);
                git_strarray_dispose(&remotes);
                return err;
            }

            const char *fetch_url = git_remote_url(remote);
            const char *push_url = git_remote_pushurl(remote);
            if (!push_url) push_url = fetch_url;

            output_print(
                out, OUTPUT_NORMAL, "{cyan}%-15s{reset} %s (fetch)\n",
                remote_name, fetch_url ? fetch_url : "none"
            );
            output_print(
                out, OUTPUT_NORMAL, "{cyan}%-15s{reset} %s (push)\n",
                remote_name, push_url ? push_url : "none"
            );

            git_remote_free(remote);
        } else {
            /* Just show names */
            output_print(
                out, OUTPUT_NORMAL, "{cyan}%s{reset}\n",
                remote_name
            );
        }
    }

    git_strarray_dispose(&remotes);

    return NULL;
}

/**
 * Add remote
 *
 * Whether the name can be a remote's is Git's rule, applied by libgit2 where
 * the name first reaches it — every lookup, create, rename and set-url checks
 * it (lib/libgit2/src/libgit2/remote.c ensure_remote_name_is_valid) — and a URL
 * is any string but the empty one, what it reaches being the transport's to say
 * at the first fetch. dotta spells neither rule, as it spells no branch rule
 * (sys/gitops.h gitops_branch_refname), and clone takes the same URLs.
 */
static error_t remote_add(
    git_repository *repo,
    output_t *out,
    const char *name,
    const char *url
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(url);

    /* Check if remote already exists */
    git_remote *existing = NULL;
    int rc = git_remote_lookup(&existing, repo, name);
    if (rc == 0) {
        /* Remote exists */
        git_remote_free(existing);
        return error_create(ERR_EXISTS, "Remote '%s' already exists", name);
    } else if (rc != GIT_ENOTFOUND) {
        /* Unexpected error */
        return error_git(rc, "Cannot add remote '%s'", name);
    }

    /* Create remote */
    git_remote *remote = NULL;
    rc = git_remote_create(&remote, repo, name, url);
    if (rc < 0) return error_git(rc, "Cannot add remote '%s'", name);

    git_remote_free(remote);

    /* Success message */
    output_success(out, OUTPUT_NORMAL, "Added remote '{cyan}%s{reset}'", name);

    return NULL;
}

/**
 * Remove remote
 *
 * libgit2 deletes the remote's tracking refs with it, every ref its fetch refspec
 * names, from no read (lib/libgit2/src/libgit2/remote.c git_remote_delete,
 * remove_remote_tracking): the namespace goes with the remote, and a write landing
 * in it meanwhile goes with it, so no writer's read is owed one.
 */
static error_t remote_remove(
    git_repository *repo,
    output_t *out,
    const char *name
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    /* Check if remote exists */
    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, name);
    if (rc == GIT_ENOTFOUND) {
        return error_create(ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (rc < 0) {
        return error_git(rc, "Cannot remove remote '%s'", name);
    }
    git_remote_free(remote);

    /* Delete remote */
    rc = git_remote_delete(repo, name);
    if (rc < 0) return error_git(rc, "Cannot remove remote '%s'", name);

    /* Success message */
    output_success(
        out, OUTPUT_NORMAL, "Removed remote '{cyan}%s{reset}'",
        name
    );

    return NULL;
}

/*
 * A remote's URL as its configuration holds it — the string its lookup reads
 * before insteadOf rewrites it (lib/libgit2/src/libgit2/remote.c git_remote_lookup,
 * get_optional_config) — into `out` (GIT_BUF_INIT), left empty where the
 * configuration holds none for it, a push URL alone
 */
static error_t remote_configured_url(git_repository *repo, const char *name, git_buf *out) {
    git_config *config = NULL;
    int rc = git_repository_config_snapshot(&config, repo);
    if (rc < 0) return error_git(rc, "Cannot read the repository's configuration");

    char *key = heap_str_format("remote.%s.url", name);
    rc = git_config_get_string_buf(out, config, key);
    error_t err = rc < 0 && rc != GIT_ENOTFOUND ? error_git(rc, "Cannot read %s", key) : NULL;

    free(key);
    git_config_free(config);
    return err;
}

/**
 * Set remote URL — the name and the URL Git's to judge, as remote_add's are
 *
 * The URL the configuration holds already changes nothing. One that reaches another
 * repository forgets what this store took of the old one before it is written
 * (sys/remote.h remote_forget); one that reaches the same repository under another
 * spelling is written, nothing forgotten.
 */
static error_t remote_set_url(
    git_repository *repo,
    output_t *out,
    const char *name,
    const char *new_url
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(new_url);

    /* Check if remote exists */
    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, name);
    if (rc == GIT_ENOTFOUND) {
        return error_create(ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (rc < 0) {
        return error_git(rc, "Cannot set the URL of remote '%s'", name);
    }

    /* The new URL judged as the write will judge it, and read as the lookup read
     * the configured one, insteadOf applied, nothing written (remote.c
     * git_remote_create_with_opts): a URL refused forgets nothing */
    git_remote *reached = NULL;
    git_buf configured = GIT_BUF_INIT;
    size_t forgotten = 0;
    error_t err = NULL;
    rc = git_remote_create_anonymous(&reached, repo, new_url);
    if (rc < 0) {
        err = error_git(rc, "Cannot set the URL of remote '%s'", name);
        goto done;
    }

    err = remote_configured_url(repo, name, &configured);
    if (err) goto done;
    if (configured.ptr && strcmp(configured.ptr, new_url) == 0) {
        output_summary(out, OUTPUT_NORMAL, "Remote '{cyan}%s{reset}' already has that URL", name);
        goto done;
    }

    /* Another repository reached: what this store took of the old one forgotten
     * before the URL is written — each tracking ref beside a branch here, which
     * would read the old remote's line as the new one's (sys/remote.h
     * remote_forget). So a refusal of either leaves the old URL, whose next contact
     * writes each forgotten ref again from none, and the same run again completes
     * it; written first, a refused forget would leave the old refs under the
     * new URL, which the run again would find unchanged. The same repository
     * under another spelling forgets nothing. */
    if (!git_remote_url(remote) || strcmp(git_remote_url(reached), git_remote_url(remote)) != 0) {
        err = remote_forget(repo, name, &forgotten);
        if (err) {
            err = error_wrap(err, "Cannot set the URL of remote '%s'", name);
            goto done;
        }
    }

    /* Set new URL */
    rc = git_remote_set_url(repo, name, new_url);
    if (rc < 0) {
        err = error_git(rc, "Cannot set the URL of remote '%s'", name);
        goto done;
    }

    /* The act, and what it forgot a clause of its line, as disable says the target
     * it forgets (cmds/profile.c profile_disable); what the next sync does with
     * each profile is the help's to say */
    if (forgotten > 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Updated URL for remote '{cyan}%s{reset}' (forgot where %zu profile%s stood "
            "on the old URL)", name, forgotten, forgotten == 1 ? "" : "s"
        );
    } else {
        output_success(out, OUTPUT_NORMAL, "Updated URL for remote '{cyan}%s{reset}'", name);
    }

done:
    git_buf_dispose(&configured);
    git_remote_free(reached);
    git_remote_free(remote);
    return err;
}

/**
 * Rename remote — both names Git's to judge, as remote_add's is
 *
 * libgit2 renames each tracking ref and its log, under a line of its own, "renamed
 * remote <old> to <new>" (lib/libgit2/src/libgit2/remote.c
 * rename_one_remote_reference): a move no writer of dotta's makes, so those lines
 * name no dotta command, and the history each log holds is kept.
 */
static error_t remote_rename(
    git_repository *repo,
    output_t *out,
    const char *old_name,
    const char *new_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(old_name);
    CHECK_NULL(new_name);

    /* Check if old remote exists */
    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, old_name);
    if (rc == GIT_ENOTFOUND) {
        return error_create(ERR_NOT_FOUND, "Remote '%s' not found", old_name);
    } else if (rc < 0) {
        return error_git(rc, "Cannot rename remote '%s' to '%s'", old_name, new_name);
    }
    git_remote_free(remote);

    /* Check if new name already exists */
    rc = git_remote_lookup(&remote, repo, new_name);
    if (rc == 0) {
        git_remote_free(remote);
        return error_create(ERR_EXISTS, "Remote '%s' already exists", new_name);
    } else if (rc != GIT_ENOTFOUND) {
        return error_git(rc, "Cannot rename remote '%s' to '%s'", old_name, new_name);
    }

    /* Rename remote */
    git_strarray problems = { 0 };
    rc = git_remote_rename(&problems, repo, old_name, new_name);

    if (problems.count > 0) {
        /* Show warnings about problematic refspecs */
        output_warning(
            out, OUTPUT_NORMAL, "The following refspecs could not be updated:"
        );

        for (size_t i = 0; i < problems.count; i++) {
            output_print(
                out, OUTPUT_NORMAL, "  %s\n",
                problems.strings[i]
            );
        }
    }

    git_strarray_dispose(&problems);

    if (rc < 0) return error_git(rc, "Cannot rename remote '%s' to '%s'", old_name, new_name);

    /* Success message */
    output_success(
        out, OUTPUT_NORMAL, "Renamed remote '{cyan}%s{reset}' to '{cyan}%s{reset}'",
        old_name, new_name
    );

    return NULL;
}

/**
 * Show a remote: where a fetch reaches it, and where a push does
 *
 * The two URLs are the answer, said as the run's summary (base/output.h
 * output_summary) in git's labels. The push URL is the one configured for pushes,
 * else the fetch URL, as a push connects (lib/libgit2/src/libgit2/remote.c
 * git_remote__urlfordirection) — save on a path remote, whose push libgit2 writes
 * through the fetch URL whatever this one says (sys/remote.h). A URL the
 * configuration holds none of, a remote written by hand, is none, as remote_list
 * says it.
 *
 * The remote's refspecs are git's to show (dotta git remote show): no fetch or
 * push of dotta's reads them, each handing libgit2 refspecs of its own
 * (sys/remote.h remote_fetch, remote_push).
 */
static error_t remote_show(
    git_repository *repo,
    output_t *out,
    const char *name
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    /* Lookup remote */
    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, name);
    if (rc == GIT_ENOTFOUND) {
        return error_create(ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (rc < 0) {
        return error_git(rc, "Cannot read remote '%s'", name);
    }

    const char *fetch_url = git_remote_url(remote);
    const char *push_url = git_remote_pushurl(remote);
    if (!push_url) push_url = fetch_url;

    output_summary(out, OUTPUT_NORMAL, "Fetch URL: %s", fetch_url ? fetch_url : "none");
    output_summary(out, OUTPUT_NORMAL, "Push URL: %s", push_url ? push_url : "none");

    git_remote_free(remote);

    return NULL;
}

/**
 * Remote command implementation
 */
error_t cmd_remote(const dotta_ctx_t *ctx, const cmd_remote_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    /* The operands are required rows of their subcommands: the parser rejected
     * a line without them. */
    switch (opts->subcommand) {
        case REMOTE_LIST:
            return remote_list(repo, out);

        case REMOTE_ADD:
            return remote_add(repo, out, opts->name, opts->url);

        case REMOTE_REMOVE:
            return remote_remove(repo, out, opts->name);

        case REMOTE_SET_URL:
            return remote_set_url(repo, out, opts->name, opts->url);

        case REMOTE_RENAME:
            return remote_rename(repo, out, opts->name, opts->new_name);

        case REMOTE_SHOW:
            return remote_show(repo, out, opts->name);
    }

    CHECK_ARG(false, "a remote subcommand no enumerator names");
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Single dispatch wrapper shared by every subcommand.
 *
 * Each sub's `init_defaults` already set the `subcommand` discriminator, so
 * `cmd_remote`'s switch routes the call.
 */
static error_t remote_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_remote(ctx, (const cmd_remote_options_t *) opts_v);
}

/**
 * What can stand at the cursor of the subcommands that act on a remote: its name,
 * while the row is open; what follows — a URL, a new name — is typed.
 */
static args_want_t remote_name_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) at;
    const cmd_remote_options_t *o = opts_v;

    if (o->name == NULL) {
        completion_remotes(ctx_v, out);
    }
    return ARGS_WANT_NONE;
}

/* --- list --- */

static void remote_list_defaults(void *o) {
    ((cmd_remote_options_t *) o)->subcommand = REMOTE_LIST;
}

static const args_opt_t remote_list_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_remote_options_t,verbosity,  DOTTA_VERBOSITY_VERBOSE,
        "Show URLs"
    ),
    ARGS_END,
};

static const args_command_t spec_remote_list = {
    .name          = "remote list",
    .summary       = "List remotes",
    .usage         = "%s remote [list] [-v]",
    .opts_size     = sizeof(cmd_remote_options_t),
    .opts          = remote_list_opts,
    .init_defaults = remote_list_defaults,
    .payload       = &(const dotta_needs_t){ .repo = DOTTA_REPO_OPEN },
    .dispatch      = remote_dispatch,
};

/* --- add --- */

static void remote_add_defaults(void *o) {
    ((cmd_remote_options_t *) o)->subcommand = REMOTE_ADD;
}

static const args_opt_t remote_add_opts[] = {
    ARGS_POSITIONAL_ANY_ARG(
        "<name>",
        cmd_remote_options_t,name,  1,
        "Name of the new remote"
    ),
    ARGS_POSITIONAL_ANY_ARG(
        "<url>",
        cmd_remote_options_t,url,   1,
        "Its URL"
    ),
    ARGS_END,
};

static const args_command_t spec_remote_add = {
    .name          = "remote add",
    .summary       = "Add remote",
    .usage         = "%s remote add <name> <url>",
    .opts_size     = sizeof(cmd_remote_options_t),
    .opts          = remote_add_opts,
    .init_defaults = remote_add_defaults,
    .payload       = &(const dotta_needs_t){ .repo = DOTTA_REPO_OPEN },
    .dispatch      = remote_dispatch,
};

/* --- remove --- */

static void remote_remove_defaults(void *o) {
    ((cmd_remote_options_t *) o)->subcommand = REMOTE_REMOVE;
}

static const args_opt_t remote_remove_opts[] = {
    ARGS_POSITIONAL_ANY_ARG(
        "<name>",
        cmd_remote_options_t,name,  1,
        "Remote to remove"
    ),
    ARGS_END,
};

static const args_command_t spec_remote_remove = {
    .name          = "remote remove",
    .summary       = "Remove remote",
    .usage         = "%s remote remove <name>",
    .opts_size     = sizeof(cmd_remote_options_t),
    .opts          = remote_remove_opts,
    .init_defaults = remote_remove_defaults,
    .complete      = remote_name_complete,
    .payload       = &(const dotta_needs_t){ .repo = DOTTA_REPO_OPEN },
    .dispatch      = remote_dispatch,
};

/* --- set-url --- */

static void remote_set_url_defaults(void *o) {
    ((cmd_remote_options_t *) o)->subcommand = REMOTE_SET_URL;
}

static const args_opt_t remote_set_url_opts[] = {
    ARGS_POSITIONAL_ANY_ARG(
        "<name>",
        cmd_remote_options_t,name,  1,
        "Remote to change"
    ),
    ARGS_POSITIONAL_ANY_ARG(
        "<url>",
        cmd_remote_options_t,url,   1,
        "Its new URL"
    ),
    ARGS_END,
};

static const args_command_t spec_remote_set_url = {
    .name          = "remote set-url",
    .summary       = "Set remote URL",
    .usage         = "%s remote set-url <name> <url>",
    .description   =
        "Points the remote at another URL: the next sync pushes every profile the\n"
        "new URL lacks. Sync first — a profile another machine deleted or recreated\n"
        "since this machine's last sync is otherwise pushed back, or merged with its\n"
        "old history.\n",
    .opts_size     = sizeof(cmd_remote_options_t),
    .opts          = remote_set_url_opts,
    .init_defaults = remote_set_url_defaults,
    .complete      = remote_name_complete,
    .payload       = &(const dotta_needs_t){ .repo = DOTTA_REPO_OPEN },
    .dispatch      = remote_dispatch,
};

/* --- rename --- */

static void remote_rename_defaults(void *o) {
    ((cmd_remote_options_t *) o)->subcommand = REMOTE_RENAME;
}

static const args_opt_t remote_rename_opts[] = {
    ARGS_POSITIONAL_ANY_ARG(
        "<old>",
        cmd_remote_options_t,name,      1,
        "Remote to rename"
    ),
    ARGS_POSITIONAL_ANY_ARG(
        "<new>",
        cmd_remote_options_t,new_name,  1,
        "Its new name"
    ),
    ARGS_END,
};

static const args_command_t spec_remote_rename = {
    .name          = "remote rename",
    .summary       = "Rename remote",
    .usage         = "%s remote rename <old> <new>",
    .opts_size     = sizeof(cmd_remote_options_t),
    .opts          = remote_rename_opts,
    .init_defaults = remote_rename_defaults,
    .complete      = remote_name_complete,
    .payload       = &(const dotta_needs_t){ .repo = DOTTA_REPO_OPEN },
    .dispatch      = remote_dispatch,
};

/* --- show --- */

static void remote_show_defaults(void *o) {
    ((cmd_remote_options_t *) o)->subcommand = REMOTE_SHOW;
}

static const args_opt_t remote_show_opts[] = {
    ARGS_POSITIONAL_ANY_ARG(
        "<name>",
        cmd_remote_options_t,name,  1,
        "Remote to show"
    ),
    ARGS_END,
};

static const args_command_t spec_remote_show = {
    .name          = "remote show",
    .summary       = "Show remote",
    .usage         = "%s remote show <name>",
    .opts_size     = sizeof(cmd_remote_options_t),
    .opts          = remote_show_opts,
    .init_defaults = remote_show_defaults,
    .complete      = remote_name_complete,
    .payload       = &(const dotta_needs_t){ .repo = DOTTA_REPO_OPEN },
    .dispatch      = remote_dispatch,
};

/* --- parent: subcommand index + spec --- */

static const args_subcommand_t remote_subs[] = {
    /* aliases      spec                  hidden shortcut */
    { "list",      &spec_remote_list,    false, false },
    { "add",       &spec_remote_add,     false, false },
    { "remove rm", &spec_remote_remove,  false, false },
    { "set-url",   &spec_remote_set_url, false, false },
    { "rename",    &spec_remote_rename,  false, false },
    { "show",      &spec_remote_show,    false, false },
    { NULL,        NULL,                 false, false }
};

const args_command_t spec_remote = {
    .name               = "remote",
    .summary            = "Manage remote repositories",
    .usage              = "%s remote [<subcommand> [args...]]",
    .description        =
        "Without a subcommand, lists the remotes.\n",
    .examples           =
        "  %s remote\n"
        "  %s remote -v\n"
        "  %s remote add origin git@github.com:user/dotfiles.git\n"
        "  %s remote set-url origin https://github.com/user/dotfiles.git\n"
        "  %s remote show origin\n",
    .opts_size          = sizeof(cmd_remote_options_t),
    .subcommands        = remote_subs,
    .default_subcommand = &spec_remote_list,
};
