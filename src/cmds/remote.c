/**
 * remote.c - Manage remote repositories
 */

#include "cmds/remote.h"

#include <ctype.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/args.h"
#include "base/error.h"
#include "base/output.h"
#include "cmds/completion.h"

/**
 * Validate remote name
 *
 * Remote names must be alphanumeric with hyphens and underscores only.
 */
static bool validate_remote_name(const char *name) {
    if (!name || name[0] == '\0') {
        return false;
    }

    for (const char *p = name; *p; p++) {
        if (!isalnum(*p) && *p != '-' && *p != '_') {
            return false;
        }
    }

    return true;
}

/**
 * Validate remote URL structure
 *
 * Accepts:
 * - URL-style: https://, http://, ssh://, git://, file:// schemes
 * - SSH SCP-style: user@host:path (e.g., git@github.com:user/repo.git)
 * - Local paths: absolute (/path) or relative (./path, ../path)
 */
static bool validate_remote_url(const char *url) {
    if (!url || !*url) {
        return false;
    }

    /* Reject whitespace */
    for (const char *p = url; *p; p++) {
        if (isspace((unsigned char) *p)) {
            return false;
        }
    }

    /* URL-style: scheme://... */
    const char *scheme_end = strstr(url, "://");
    if (scheme_end) {
        size_t scheme_len = (size_t) (scheme_end - url);
        if ((scheme_len == 5 && strncmp(url, "https", 5) == 0) ||
            (scheme_len == 4 && strncmp(url, "http", 4) == 0) ||
            (scheme_len == 3 && strncmp(url, "ssh", 3) == 0) ||
            (scheme_len == 3 && strncmp(url, "git", 3) == 0) ||
            (scheme_len == 4 && strncmp(url, "file", 4) == 0)) {
            /* Must have something after scheme:// */
            return *(scheme_end + 3) != '\0';
        }
        return false;
    }

    /* SSH SCP-style: user@host:path */
    const char *at = strchr(url, '@');
    if (at && at > url) {
        const char *colon = strchr(at + 1, ':');
        if (colon && colon > at + 1 && *(colon + 1) != '\0') {
            return true;
        }
    }

    /* Local path: absolute or explicitly relative */
    if (url[0] == '/') {
        return true;
    }
    if (url[0] == '.' && (url[1] == '/' ||
        (url[1] == '.' && url[2] == '/'))) {
        return true;
    }

    return false;
}

/**
 * List remotes
 */
static error_t *remote_list(
    git_repository *repo,
    output_t *out,
    bool verbose
) {
    CHECK_NULL(repo);

    if (verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    git_strarray remotes = { 0 };
    int git_err = git_remote_list(&remotes, repo);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    if (remotes.count == 0) {
        output_info(out, OUTPUT_NORMAL, "No remotes configured");
        git_strarray_dispose(&remotes);
        return NULL;
    }

    /* List each remote */
    for (size_t i = 0; i < remotes.count; i++) {
        const char *remote_name = remotes.strings[i];

        if (output_is_verbose(out)) {
            /* Show URLs for fetch and push */
            git_remote *remote = NULL;
            git_err = git_remote_lookup(&remote, repo, remote_name);
            if (git_err < 0) {
                git_strarray_dispose(&remotes);
                return error_from_git(git_err);
            }

            const char *fetch_url = git_remote_url(remote);
            const char *push_url = git_remote_pushurl(remote);

            /* Use fetch URL for push if push URL not set */
            if (!push_url) {
                push_url = fetch_url;
            }

            output_styled(
                out, OUTPUT_NORMAL, "{cyan}%-15s{reset} %s (fetch)\n",
                remote_name, fetch_url
            );
            output_styled(
                out, OUTPUT_NORMAL, "{cyan}%-15s{reset} %s (push)\n",
                remote_name, push_url
            );

            git_remote_free(remote);
        } else {
            /* Just show names */
            output_styled(
                out, OUTPUT_NORMAL, "{cyan}%s{reset}\n",
                remote_name
            );
        }
    }

    output_newline(out, OUTPUT_NORMAL);

    git_strarray_dispose(&remotes);

    return NULL;
}

/**
 * Add remote
 */
static error_t *remote_add(
    git_repository *repo,
    output_t *out,
    const char *name,
    const char *url
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(url);

    /* Validate remote name */
    if (!validate_remote_name(name)) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid remote name '%s'\n"
            "Only letters, numbers, hyphens, and underscores allowed",
            name
        );
    }

    /* Validate URL */
    if (!validate_remote_url(url)) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid remote URL '%s'\n"
            "Expected: https://..., git@host:path, ssh://..., or /local/path",
            url
        );
    }

    /* Check if remote already exists */
    git_remote *existing = NULL;
    int git_err = git_remote_lookup(&existing, repo, name);
    if (git_err == 0) {
        /* Remote exists */
        git_remote_free(existing);
        return ERROR(
            ERR_EXISTS, "Remote '%s' already exists\n"
            "Hint: Use 'dotta remote set-url %s <url>' to change the URL",
            name, name
        );
    } else if (git_err != GIT_ENOTFOUND) {
        /* Unexpected error */
        return error_from_git(git_err);
    }

    /* Create remote */
    git_remote *remote = NULL;
    git_err = git_remote_create(&remote, repo, name, url);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_remote_free(remote);

    /* Success message */
    output_success(
        out, OUTPUT_NORMAL, "Remote '{cyan}%s{reset}' added successfully",
        name
    );

    return NULL;
}

/**
 * Remove remote
 */
static error_t *remote_remove(
    git_repository *repo,
    output_t *out,
    const char *name
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    /* Delete remote */
    git_err = git_remote_delete(repo, name);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Success message */
    output_success(
        out, OUTPUT_NORMAL, "Removed remote '{cyan}%s{reset}'",
        name
    );

    return NULL;
}

/**
 * Set remote URL
 */
static error_t *remote_set_url(
    git_repository *repo,
    output_t *out,
    const char *name,
    const char *new_url
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);
    CHECK_NULL(new_url);

    /* Validate URL */
    if (!validate_remote_url(new_url)) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid remote URL '%s'\n"
            "Expected: https://..., git@host:path, ssh://..., or /local/path",
            new_url
        );
    }

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    /* Set new URL */
    git_err = git_remote_set_url(repo, name, new_url);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Success message */
    output_success(
        out, OUTPUT_NORMAL, "Remote '{cyan}%s{reset}' URL updated",
        name
    );

    return NULL;
}

/**
 * Rename remote
 */
static error_t *remote_rename(
    git_repository *repo,
    output_t *out,
    const char *old_name,
    const char *new_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(old_name);
    CHECK_NULL(new_name);

    /* Validate new name */
    if (!validate_remote_name(new_name)) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid remote name '%s'\n"
            "Only letters, numbers, hyphens, and underscores allowed",
            new_name
        );
    }

    /* Check if old remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, old_name);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(ERR_NOT_FOUND, "Remote '%s' not found", old_name);
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    /* Check if new name already exists */
    git_err = git_remote_lookup(&remote, repo, new_name);
    if (git_err == 0) {
        git_remote_free(remote);
        return ERROR(ERR_EXISTS, "Remote '%s' already exists", new_name);
    } else if (git_err != GIT_ENOTFOUND) {
        return error_from_git(git_err);
    }

    /* Rename remote */
    git_strarray problems = { 0 };
    git_err = git_remote_rename(&problems, repo, old_name, new_name);

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

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Success message */
    output_success(
        out, OUTPUT_NORMAL, "Renamed remote '{cyan}%s{reset}' to '{cyan}%s{reset}'",
        old_name, new_name
    );

    return NULL;
}

/**
 * Show remote details
 */
static error_t *remote_show(
    git_repository *repo,
    output_t *out,
    const char *name
) {
    CHECK_NULL(repo);
    CHECK_NULL(name);

    /* Lookup remote */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, name);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(ERR_NOT_FOUND, "Remote '%s' not found", name);
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Show remote information */
    output_styled(out, OUTPUT_NORMAL, "Remote: {cyan}%s{reset}\n", name);

    const char *fetch_url = git_remote_url(remote);
    const char *push_url = git_remote_pushurl(remote);

    if (!push_url) {
        push_url = fetch_url;
    }

    output_print(out, OUTPUT_NORMAL, "  Fetch URL: %s\n", fetch_url);
    output_print(out, OUTPUT_NORMAL, "  Push URL:  %s\n", push_url);

    /* Show fetch refspecs */
    git_strarray refspecs = { 0 };
    git_err = git_remote_get_fetch_refspecs(&refspecs, remote);
    if (git_err == 0 && refspecs.count > 0) {
        output_print(out, OUTPUT_NORMAL, "  Fetch refspecs:\n");
        for (size_t i = 0; i < refspecs.count; i++) {
            output_print(out, OUTPUT_NORMAL, "    %s\n", refspecs.strings[i]);
        }
    }
    if (git_err == 0) {
        git_strarray_dispose(&refspecs);
    }

    /* Show push refspecs */
    memset(&refspecs, 0, sizeof(refspecs));
    git_err = git_remote_get_push_refspecs(&refspecs, remote);

    if (git_err == 0 && refspecs.count > 0) {
        output_print(
            out, OUTPUT_NORMAL, "  Push refspecs:\n"
        );
        for (size_t i = 0; i < refspecs.count; i++) {
            output_print(
                out, OUTPUT_NORMAL, "    %s\n",
                refspecs.strings[i]
            );
        }
    }
    if (git_err == 0) {
        git_strarray_dispose(&refspecs);
    }

    git_remote_free(remote);

    return NULL;
}

/**
 * Remote command implementation
 */
error_t *cmd_remote(const dotta_ctx_t *ctx, const cmd_remote_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    output_t *out = ctx->out;

    /* The operands are required rows of their subcommands: the parser
     * rejected a line without them. */
    switch (opts->subcommand) {
        case REMOTE_LIST:
            return remote_list(repo, out, opts->verbose);

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

        default:
            return ERROR(ERR_INVALID_ARG, "Unknown remote subcommand");
    }
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
static error_t *remote_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_remote(ctx, (const cmd_remote_options_t *) opts_v);
}

/**
 * What can stand at the cursor of the subcommands that act on a remote: its
 * name, while the row is open; what follows — a URL, a new name — is typed.
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
    ARGS_FLAG(
        "v verbose",
        cmd_remote_options_t,verbose,
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
    .payload       = &dotta_ext_repo_only,
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
    .payload       = &dotta_ext_repo_only,
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
    .payload       = &dotta_ext_repo_only,
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
    .opts_size     = sizeof(cmd_remote_options_t),
    .opts          = remote_set_url_opts,
    .init_defaults = remote_set_url_defaults,
    .complete      = remote_name_complete,
    .payload       = &dotta_ext_repo_only,
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
    .payload       = &dotta_ext_repo_only,
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
    .payload       = &dotta_ext_repo_only,
    .dispatch      = remote_dispatch,
};

/* --- parent: subcommand index + spec --- */

static const args_subcommand_t remote_subs[] = {
    { "list",      &spec_remote_list,    false },
    { "add",       &spec_remote_add,     false },
    { "remove rm", &spec_remote_remove,  false },
    { "set-url",   &spec_remote_set_url, false },
    { "rename",    &spec_remote_rename,  false },
    { "show",      &spec_remote_show,    false },
    { NULL,        NULL,                 false }
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
