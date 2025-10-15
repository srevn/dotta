/**
 * main.c - Dotta entry point
 *
 * Dotfile manager using git branches as profiles.
 */

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "cmds/add.h"
#include "cmds/apply.h"
#include "cmds/bootstrap.h"
#include "cmds/clone.h"
#include "cmds/diff.h"
#include "cmds/git.h"
#include "cmds/ignore.h"
#include "cmds/init.h"
#include "cmds/list.h"
#include "cmds/profile.h"
#include "cmds/remote.h"
#include "cmds/remove.h"
#include "cmds/revert.h"
#include "cmds/show.h"
#include "cmds/status.h"
#include "cmds/sync.h"
#include "cmds/update.h"
#include "types.h"
#include "utils/help.h"
#include "utils/repo.h"

/**
 * Helper: Open resolved repository
 *
 * Resolves the repository path and opens it. If the repository doesn't exist,
 * prints a helpful error message and returns NULL.
 */
static git_repository *open_resolved_repo(char **repo_path_out) {
    char *repo_path = NULL;
    git_repository *repo = NULL;

    /* Resolve repository path */
    error_t *err = resolve_repo_path(&repo_path);
    if (err) {
        fprintf(stderr, "Error: Failed to resolve repository path\n");
        error_print(err, stderr);
        error_free(err);
        return NULL;
    }

    /* Check if repository exists */
    if (!gitops_is_repository(repo_path)) {
        fprintf(stderr, "Error: No dotta repository found at: %s\n", repo_path);
        fprintf(stderr, "\nRun 'dotta init' to create a new repository\n");

        /* Show hint about DOTTA_REPO_DIR */
        const char *env_repo = getenv("DOTTA_REPO_DIR");
        if (env_repo) {
            fprintf(stderr, "Note: DOTTA_REPO_DIR is set to: %s\n", env_repo);
        }

        free(repo_path);
        return NULL;
    }

    /* Open repository */
    err = gitops_open_repository(&repo, repo_path);
    if (err) {
        fprintf(stderr, "Error: Failed to open repository at: %s\n", repo_path);
        error_print(err, stderr);
        error_free(err);
        free(repo_path);
        return NULL;
    }

    /* Return repository (caller must free both repo and repo_path) */
    if (repo_path_out) {
        *repo_path_out = repo_path;
    } else {
        free(repo_path);
    }

    return repo;
}

/**
 * Parse init command
 */
static int cmd_init_main(int argc, char **argv) {
    cmd_init_options_t opts = {
        .repo_path = NULL,
        .quiet = false
    };

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_init_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            opts.quiet = true;
        } else {
            opts.repo_path = argv[i];
        }
    }

    /* Execute command */
    error_t *err = cmd_init(&opts);
    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse add command
 */
static int cmd_add_main(int argc, char **argv) {
    cmd_add_options_t opts = {
        .profile = NULL,
        .files = NULL,
        .file_count = 0,
        .message = NULL,
        .exclude_patterns = NULL,
        .exclude_count = 0,
        .force = false,
        .verbose = false
    };

    /* Collect file and exclude pattern arguments */
    const char **files = malloc((size_t)argc * sizeof(char *));
    const char **excludes = malloc((size_t)argc * sizeof(char *));
    if (!files || !excludes) {
        fprintf(stderr, "Failed to allocate memory\n");
        free(files);
        free(excludes);
        return 1;
    }
    size_t file_count = 0;
    size_t exclude_count = 0;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            free(files);
            free(excludes);
            print_add_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                free(files);
                free(excludes);
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            opts.profile = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--message") == 0) {
            if (i + 1 >= argc) {
                free(files);
                free(excludes);
                fprintf(stderr, "Error: --message requires an argument\n");
                return 1;
            }
            opts.message = argv[++i];
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--exclude") == 0) {
            if (i + 1 >= argc) {
                free(files);
                free(excludes);
                fprintf(stderr, "Error: --exclude requires an argument\n");
                return 1;
            }
            excludes[exclude_count++] = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            opts.force = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else {
            files[file_count++] = argv[i];
        }
    }

    opts.files = files;
    opts.file_count = file_count;
    opts.exclude_patterns = excludes;
    opts.exclude_count = exclude_count;

    /* Validate */
    if (!opts.profile) {
        free(files);
        free(excludes);
        fprintf(stderr, "Error: --profile is required\n");
        print_add_help(argv[0]);
        return 1;
    }

    if (file_count == 0) {
        free(files);
        free(excludes);
        fprintf(stderr, "Error: at least one file is required\n");
        print_add_help(argv[0]);
        return 1;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        free(files);
        free(excludes);
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_add(repo, &opts);
    free(files);
    free(excludes);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse remove command
 */
static int cmd_remove_main(int argc, char **argv) {
    cmd_remove_options_t opts = {
        .profile = NULL,
        .paths = NULL,
        .path_count = 0,
        .delete_profile = false,
        .dry_run = false,
        .force = false,
        .interactive = false,
        .verbose = false,
        .quiet = false,
        .message = NULL
    };

    /* Collect path arguments */
    const char **paths = malloc((size_t)argc * sizeof(char *));
    if (!paths) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    size_t path_count = 0;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            free(paths);
            print_remove_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                free(paths);
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            opts.profile = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--message") == 0) {
            if (i + 1 >= argc) {
                free(paths);
                fprintf(stderr, "Error: --message requires an argument\n");
                return 1;
            }
            opts.message = argv[++i];
        } else if (strcmp(argv[i], "--delete-profile") == 0) {
            opts.delete_profile = true;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
            opts.dry_run = true;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            opts.force = true;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            opts.interactive = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            opts.quiet = true;
        } else {
            paths[path_count++] = argv[i];
        }
    }

    opts.paths = paths;
    opts.path_count = path_count;

    /* Validate */
    if (!opts.profile) {
        free(paths);
        fprintf(stderr, "Error: --profile is required\n");
        print_remove_help(argv[0]);
        return 1;
    }

    if (!opts.delete_profile && path_count == 0) {
        free(paths);
        fprintf(stderr, "Error: at least one path is required (or use --delete-profile)\n");
        print_remove_help(argv[0]);
        return 1;
    }

    if (opts.delete_profile && path_count > 0) {
        free(paths);
        fprintf(stderr, "Error: cannot specify paths when using --delete-profile\n");
        print_remove_help(argv[0]);
        return 1;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        free(paths);
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_remove(repo, &opts);
    free(paths);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse apply command
 */
static int cmd_apply_main(int argc, char **argv) {
    cmd_apply_options_t opts = {
        .profiles = NULL,
        .profile_count = 0,
        .force = false,
        .dry_run = false,
        .keep_orphans = false,  /* Default: prune orphaned files */
        .verbose = false,
        .skip_existing = false,
        .skip_unchanged = true  /* Default: enabled for efficiency */
    };

    /* Collect profile arguments */
    const char **profiles = malloc((size_t)argc * sizeof(char *));
    if (!profiles) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    size_t profile_count = 0;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            free(profiles);
            print_apply_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            opts.force = true;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
            opts.dry_run = true;
        } else if (strcmp(argv[i], "--keep-orphans") == 0) {
            opts.keep_orphans = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (strcmp(argv[i], "--skip-existing") == 0) {
            opts.skip_existing = true;
        } else if (strcmp(argv[i], "--no-skip-unchanged") == 0) {
            opts.skip_unchanged = false;  /* Disable smart skip */
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --profile requires an argument\n");
                free(profiles);
                return 1;
            }
            profiles[profile_count++] = argv[++i];
        } else if (argv[i][0] != '-') {
            /* Positional argument - treat as profile name */
            profiles[profile_count++] = argv[i];
        } else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            free(profiles);
            print_apply_help(argv[0]);
            return 1;
        }
    }

    if (profile_count > 0) {
        opts.profiles = profiles;
        opts.profile_count = profile_count;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        free(profiles);
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_apply(repo, &opts);
    free(profiles);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse status command
 */
static int cmd_status_main(int argc, char **argv) {
    cmd_status_options_t opts = {
        .profiles = NULL,
        .profile_count = 0,
        .verbose = false,
        .show_local = true,   /* Default: show filesystem status */
        .show_remote = true,  /* Default: show remote status */
        .no_fetch = false,    /* Default: fetch before remote check */
        .all_profiles = false /* Default: show only active profiles */
    };

    /* Collect profile arguments */
    const char **profiles = malloc((size_t)argc * sizeof(char *));
    if (!profiles) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    size_t profile_count = 0;

    /* Track if user explicitly set --local or --remote */
    bool local_set = false;
    bool remote_set = false;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            free(profiles);
            print_status_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (strcmp(argv[i], "--local") == 0) {
            local_set = true;
        } else if (strcmp(argv[i], "--remote") == 0) {
            remote_set = true;
        } else if (strcmp(argv[i], "--no-fetch") == 0) {
            opts.no_fetch = true;
        } else if (strcmp(argv[i], "--all") == 0) {
            opts.all_profiles = true;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --profile requires an argument\n");
                free(profiles);
                return 1;
            }
            profiles[profile_count++] = argv[++i];
        } else if (argv[i][0] != '-') {
            /* Positional argument - treat as profile name */
            profiles[profile_count++] = argv[i];
        } else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            free(profiles);
            print_status_help(argv[0]);
            return 1;
        }
    }

    /* Handle --local / --remote flag logic:
     * - Neither set: show both (default)
     * - Only --local: show only local
     * - Only --remote: show only remote
     * - Both set: show both (explicit)
     */
    if (local_set && !remote_set) {
        opts.show_local = true;
        opts.show_remote = false;
    } else if (remote_set && !local_set) {
        opts.show_local = false;
        opts.show_remote = true;
    } else if (local_set && remote_set) {
        opts.show_local = true;
        opts.show_remote = true;
    }
    /* else: both default to true (neither flag set) */

    if (profile_count > 0) {
        opts.profiles = profiles;
        opts.profile_count = profile_count;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        free(profiles);
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_status(repo, &opts);
    free(profiles);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse list command
 */
static int cmd_list_main(int argc, char **argv) {
    cmd_list_options_t opts = {
        .mode = LIST_PROFILES,
        .profile = NULL,
        .verbose = false,
        .max_count = 0,
        .oneline = false,
        .remote = false
    };

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_list_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--log") == 0) {
            opts.mode = LIST_LOG;
        } else if (strcmp(argv[i], "--remote") == 0) {
            opts.remote = true;
        } else if (strcmp(argv[i], "--oneline") == 0) {
            opts.oneline = true;
        } else if (strcmp(argv[i], "-n") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -n requires an argument\n");
                return 1;
            }
            opts.max_count = (size_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            opts.profile = argv[++i];
            /* If mode wasn't explicitly set, default to FILES when profile specified */
            if (opts.mode == LIST_PROFILES) {
                opts.mode = LIST_FILES;
            }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (argv[i][0] != '-') {
            /* Positional argument - treat as profile name */
            opts.profile = argv[i];
            /* If mode wasn't explicitly set, default to FILES when profile specified */
            if (opts.mode == LIST_PROFILES) {
                opts.mode = LIST_FILES;
            }
        } else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            print_list_help(argv[0]);
            return 1;
        }
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_list(repo, &opts);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse profile command
 */
static int cmd_profile_main(int argc, char **argv) {
    cmd_profile_options_t opts = {
        .subcommand = PROFILE_LIST,  /* Default subcommand */
        .profiles = NULL,
        .profile_count = 0,
        .show_remote = false,
        .show_available = true,  /* Default: show available profiles */
        .fetch_all = false,
        .all_profiles = false,
        .fix = false,
        .verbose = false,
        .quiet = false
    };

    /* Parse subcommand */
    if (argc < 3) {
        /* No subcommand - default to list */
        opts.subcommand = PROFILE_LIST;
    } else if (strcmp(argv[2], "--help") == 0) {
        print_profile_help(argv[0]);
        return 0;
    } else if (strcmp(argv[2], "list") == 0) {
        opts.subcommand = PROFILE_LIST;

        /* Parse list options */
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0) {
                print_profile_help(argv[0]);
                return 0;
            } else if (strcmp(argv[i], "--remote") == 0) {
                opts.show_remote = true;
            } else if (strcmp(argv[i], "--available") == 0) {
                opts.show_available = true;
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                opts.verbose = true;
            } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
                opts.quiet = true;
            } else {
                fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
                print_profile_help(argv[0]);
                return 1;
            }
        }
    } else if (strcmp(argv[2], "fetch") == 0) {
        opts.subcommand = PROFILE_FETCH;

        /* Collect profile arguments */
        const char **profiles = malloc((size_t)argc * sizeof(char *));
        if (!profiles) {
            fprintf(stderr, "Failed to allocate memory\n");
            return 1;
        }
        size_t profile_count = 0;

        /* Parse fetch options */
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0) {
                free(profiles);
                print_profile_help(argv[0]);
                return 0;
            } else if (strcmp(argv[i], "--all") == 0) {
                opts.fetch_all = true;
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                opts.verbose = true;
            } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
                opts.quiet = true;
            } else if (argv[i][0] != '-') {
                profiles[profile_count++] = argv[i];
            } else {
                fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
                free(profiles);
                print_profile_help(argv[0]);
                return 1;
            }
        }

        opts.profiles = profiles;
        opts.profile_count = profile_count;
    } else if (strcmp(argv[2], "activate") == 0) {
        opts.subcommand = PROFILE_ACTIVATE;

        /* Collect profile arguments */
        const char **profiles = malloc((size_t)argc * sizeof(char *));
        if (!profiles) {
            fprintf(stderr, "Failed to allocate memory\n");
            return 1;
        }
        size_t profile_count = 0;

        /* Parse activate options */
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0) {
                free(profiles);
                print_profile_help(argv[0]);
                return 0;
            } else if (strcmp(argv[i], "--all") == 0) {
                opts.all_profiles = true;
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                opts.verbose = true;
            } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
                opts.quiet = true;
            } else if (argv[i][0] != '-') {
                profiles[profile_count++] = argv[i];
            } else {
                fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
                free(profiles);
                print_profile_help(argv[0]);
                return 1;
            }
        }

        opts.profiles = profiles;
        opts.profile_count = profile_count;
    } else if (strcmp(argv[2], "deactivate") == 0) {
        opts.subcommand = PROFILE_DEACTIVATE;

        /* Collect profile arguments */
        const char **profiles = malloc((size_t)argc * sizeof(char *));
        if (!profiles) {
            fprintf(stderr, "Failed to allocate memory\n");
            return 1;
        }
        size_t profile_count = 0;

        /* Parse deactivate options */
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0) {
                free(profiles);
                print_profile_help(argv[0]);
                return 0;
            } else if (strcmp(argv[i], "--all") == 0) {
                opts.all_profiles = true;
            } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
                opts.dry_run = true;
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                opts.verbose = true;
            } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
                opts.quiet = true;
            } else if (argv[i][0] != '-') {
                profiles[profile_count++] = argv[i];
            } else {
                fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
                free(profiles);
                print_profile_help(argv[0]);
                return 1;
            }
        }

        opts.profiles = profiles;
        opts.profile_count = profile_count;
    } else if (strcmp(argv[2], "reorder") == 0) {
        opts.subcommand = PROFILE_REORDER;

        /* Collect profile arguments */
        const char **profiles = malloc((size_t)argc * sizeof(char *));
        if (!profiles) {
            fprintf(stderr, "Failed to allocate memory\n");
            return 1;
        }
        size_t profile_count = 0;

        /* Parse reorder options */
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0) {
                free(profiles);
                print_profile_help(argv[0]);
                return 0;
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                opts.verbose = true;
            } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
                opts.quiet = true;
            } else if (argv[i][0] != '-') {
                profiles[profile_count++] = argv[i];
            } else {
                fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
                free(profiles);
                print_profile_help(argv[0]);
                return 1;
            }
        }

        opts.profiles = profiles;
        opts.profile_count = profile_count;
    } else if (strcmp(argv[2], "validate") == 0) {
        opts.subcommand = PROFILE_VALIDATE;

        /* Parse validate options */
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0) {
                print_profile_help(argv[0]);
                return 0;
            } else if (strcmp(argv[i], "--fix") == 0) {
                opts.fix = true;
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                opts.verbose = true;
            } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
                opts.quiet = true;
            } else {
                fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
                print_profile_help(argv[0]);
                return 1;
            }
        }
    } else {
        fprintf(stderr, "Error: Unknown subcommand '%s'\n", argv[2]);
        print_profile_help(argv[0]);
        return 1;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        if (opts.profiles) {
            free(opts.profiles);
        }
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_profile(repo, &opts);
    if (opts.profiles) {
        free(opts.profiles);
    }
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse diff command
 */
static int cmd_diff_main(int argc, char **argv) {
    cmd_diff_options_t opts = {
        .files = NULL,
        .file_count = 0,
        .profiles = NULL,
        .profile_count = 0,
        .name_only = false,
        .all_changes = false,
        .direction = DIFF_UPSTREAM  /* Default: show repo → filesystem */
    };

    /* Collect file arguments */
    const char **files = malloc((size_t)argc * sizeof(char *));
    if (!files) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    size_t file_count = 0;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            free(files);
            print_diff_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--name-only") == 0) {
            opts.name_only = true;
        } else if (strcmp(argv[i], "--upstream") == 0) {
            opts.direction = DIFF_UPSTREAM;
        } else if (strcmp(argv[i], "--downstream") == 0) {
            opts.direction = DIFF_DOWNSTREAM;
        } else if (strcmp(argv[i], "--all") == 0 || strcmp(argv[i], "-a") == 0) {
            opts.all_changes = true;
            opts.direction = DIFF_BOTH;  /* --all shows both directions */
        } else {
            files[file_count++] = argv[i];
        }
    }

    if (file_count > 0) {
        opts.files = files;
        opts.file_count = file_count;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        free(files);
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_diff(repo, &opts);
    free(files);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse clone command
 */
static int cmd_clone_main(int argc, char **argv) {
    cmd_clone_options_t opts = {
        .url = NULL,
        .path = NULL,
        .quiet = false,
        .verbose = false,
        .bootstrap = false,
        .no_bootstrap = false,
        .fetch_all = false,
        .profiles = NULL,
        .profile_count = 0
    };

    /* Collect explicit profiles */
    const char **profiles = malloc((size_t)argc * sizeof(char *));
    if (!profiles) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    size_t profile_count = 0;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            free(profiles);
            print_clone_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            opts.quiet = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (strcmp(argv[i], "--bootstrap") == 0) {
            opts.bootstrap = true;
        } else if (strcmp(argv[i], "--no-bootstrap") == 0) {
            opts.no_bootstrap = true;
        } else if (strcmp(argv[i], "--all") == 0) {
            opts.fetch_all = true;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0 || strcmp(argv[i], "--profiles") == 0) {
            if (i + 1 >= argc) {
                free(profiles);
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            /* Collect all remaining args as profile names until next flag */
            i++;
            while (i < argc && argv[i][0] != '-') {
                profiles[profile_count++] = argv[i];
                i++;
            }
            i--; /* Back up one since the for loop will increment */
        } else if (!opts.url) {
            opts.url = argv[i];
        } else if (!opts.path) {
            opts.path = argv[i];
        } else {
            free(profiles);
            fprintf(stderr, "Error: Unexpected argument '%s'\n", argv[i]);
            print_clone_help(argv[0]);
            return 1;
        }
    }

    if (!opts.url) {
        free(profiles);
        fprintf(stderr, "Error: URL required\n");
        print_clone_help(argv[0]);
        return 1;
    }

    /* Set profiles if any were specified */
    if (profile_count > 0) {
        opts.profiles = profiles;
        opts.profile_count = profile_count;
    }

    /* Execute command */
    error_t *err = cmd_clone(&opts);
    free(profiles);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}


/**
 * Parse update command
 */
static int cmd_update_main(int argc, char **argv) {
    cmd_update_options_t opts = {
        .files = NULL,
        .file_count = 0,
        .profiles = NULL,
        .profile_count = 0,
        .message = NULL,
        .dry_run = false,
        .interactive = false,
        .verbose = false,
        .include_new = false,
        .only_new = false
    };

    /* Collect file arguments */
    const char **files = malloc((size_t)argc * sizeof(char *));
    const char **profiles = malloc((size_t)argc * sizeof(char *));
    if (!files || !profiles) {
        fprintf(stderr, "Failed to allocate memory\n");
        free(files);
        free(profiles);
        return 1;
    }
    size_t file_count = 0;
    size_t profile_count = 0;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            free(files);
            free(profiles);
            print_update_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--message") == 0) {
            if (i + 1 >= argc) {
                free(files);
                free(profiles);
                fprintf(stderr, "Error: --message requires an argument\n");
                return 1;
            }
            opts.message = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                free(files);
                free(profiles);
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            profiles[profile_count++] = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
            opts.dry_run = true;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            opts.interactive = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (strcmp(argv[i], "--include-new") == 0) {
            opts.include_new = true;
        } else if (strcmp(argv[i], "--only-new") == 0) {
            opts.only_new = true;
        } else {
            files[file_count++] = argv[i];
        }
    }

    if (file_count > 0) {
        opts.files = files;
        opts.file_count = file_count;
    }

    if (profile_count > 0) {
        opts.profiles = profiles;
        opts.profile_count = profile_count;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        free(files);
        free(profiles);
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_update(repo, &opts);
    free(files);
    free(profiles);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse ignore command
 */
static int cmd_ignore_main(int argc, char **argv) {
    /* Temporary storage for patterns (max 100 each) */
    const char *add_patterns_temp[100];
    const char *remove_patterns_temp[100];
    size_t add_count = 0;
    size_t remove_count = 0;

    cmd_ignore_options_t opts = {
        .profile = NULL,
        .test_path = NULL,
        .verbose = false,
        .add_patterns = NULL,
        .add_count = 0,
        .remove_patterns = NULL,
        .remove_count = 0
    };

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_ignore_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            opts.profile = argv[++i];
        } else if (strcmp(argv[i], "--test") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --test requires an argument\n");
                return 1;
            }
            opts.test_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (strcmp(argv[i], "--add") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --add requires a pattern argument\n");
                return 1;
            }
            if (add_count >= 100) {
                fprintf(stderr, "Error: Maximum 100 patterns can be added at once\n");
                return 1;
            }
            add_patterns_temp[add_count++] = argv[++i];
        } else if (strcmp(argv[i], "--remove") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --remove requires a pattern argument\n");
                return 1;
            }
            if (remove_count >= 100) {
                fprintf(stderr, "Error: Maximum 100 patterns can be removed at once\n");
                return 1;
            }
            remove_patterns_temp[remove_count++] = argv[++i];
        } else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            print_ignore_help(argv[0]);
            return 1;
        }
    }

    /* Set pattern arrays in opts */
    opts.add_patterns = add_patterns_temp;
    opts.add_count = add_count;
    opts.remove_patterns = remove_patterns_temp;
    opts.remove_count = remove_count;

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_ignore(repo, &opts);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse git command
 */
static int cmd_git_main(int argc, char **argv) {
    /* Resolve repository path */
    char *repo_path = NULL;
    error_t *err = resolve_repo_path(&repo_path);
    if (err) {
        fprintf(stderr, "Error: Failed to resolve repository path\n");
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    /* Check if repository exists */
    if (!gitops_is_repository(repo_path)) {
        fprintf(stderr, "Error: No dotta repository found at: %s\n", repo_path);
        fprintf(stderr, "\nRun 'dotta init' to create a new repository\n");

        /* Show hint about DOTTA_REPO_DIR */
        const char *env_repo = getenv("DOTTA_REPO_DIR");
        if (env_repo) {
            fprintf(stderr, "Note: DOTTA_REPO_DIR is set to: %s\n", env_repo);
        }

        free(repo_path);
        return 1;
    }

    /* Build options from remaining arguments */
    cmd_git_options_t opts = {
        .args = &argv[2],           /* Skip "dotta" and "git" */
        .arg_count = argc - 2
    };

    /* Execute git command */
    int exit_code = cmd_git(repo_path, &opts);
    free(repo_path);

    return exit_code;
}

/**
 * Parse sync command
 */
static int cmd_sync_main(int argc, char **argv) {
    cmd_sync_options_t opts = {
        .profiles = NULL,
        .profile_count = 0,
        .dry_run = false,
        .no_push = false,
        .no_pull = false,
        .verbose = false,
        .force = false,
        .diverged = NULL
    };

    /* Collect profile arguments */
    const char **profiles = malloc((size_t)argc * sizeof(char *));
    if (!profiles) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    size_t profile_count = 0;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            free(profiles);
            print_sync_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                free(profiles);
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            profiles[profile_count++] = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
            opts.dry_run = true;
        } else if (strcmp(argv[i], "--no-push") == 0) {
            opts.no_push = true;
        } else if (strcmp(argv[i], "--no-pull") == 0) {
            opts.no_pull = true;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            opts.force = true;
        } else if (strcmp(argv[i], "--diverged") == 0) {
            if (i + 1 >= argc) {
                free(profiles);
                fprintf(stderr, "Error: --diverged requires an argument\n");
                return 1;
            }
            opts.diverged = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else {
            free(profiles);
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            print_sync_help(argv[0]);
            return 1;
        }
    }

    if (profile_count > 0) {
        opts.profiles = profiles;
        opts.profile_count = profile_count;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        free(profiles);
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_sync(repo, &opts);
    free(profiles);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse remote command
 */
static int cmd_remote_main(int argc, char **argv) {
    cmd_remote_options_t opts = {
        .subcommand = REMOTE_LIST,
        .name = NULL,
        .url = NULL,
        .new_name = NULL,
        .verbose = false
    };

    /* Parse subcommand and arguments */
    if (argc == 2) {
        /* No subcommand - list remotes */
        opts.subcommand = REMOTE_LIST;
    } else if (strcmp(argv[2], "--help") == 0) {
        print_remote_help(argv[0]);
        return 0;
    } else if (strcmp(argv[2], "-v") == 0 || strcmp(argv[2], "--verbose") == 0) {
        opts.subcommand = REMOTE_LIST;
        opts.verbose = true;
    } else if (strcmp(argv[2], "add") == 0) {
        opts.subcommand = REMOTE_ADD;
        if (argc < 5) {
            fprintf(stderr, "Error: 'remote add' requires name and URL\n");
            print_remote_help(argv[0]);
            return 1;
        }
        opts.name = argv[3];
        opts.url = argv[4];
    } else if (strcmp(argv[2], "remove") == 0) {
        opts.subcommand = REMOTE_REMOVE;
        if (argc < 4) {
            fprintf(stderr, "Error: 'remote remove' requires name\n");
            print_remote_help(argv[0]);
            return 1;
        }
        opts.name = argv[3];
    } else if (strcmp(argv[2], "set-url") == 0) {
        opts.subcommand = REMOTE_SET_URL;
        if (argc < 5) {
            fprintf(stderr, "Error: 'remote set-url' requires name and URL\n");
            print_remote_help(argv[0]);
            return 1;
        }
        opts.name = argv[3];
        opts.url = argv[4];
    } else if (strcmp(argv[2], "rename") == 0) {
        opts.subcommand = REMOTE_RENAME;
        if (argc < 5) {
            fprintf(stderr, "Error: 'remote rename' requires old and new names\n");
            print_remote_help(argv[0]);
            return 1;
        }
        opts.name = argv[3];
        opts.new_name = argv[4];
    } else if (strcmp(argv[2], "show") == 0) {
        opts.subcommand = REMOTE_SHOW;
        if (argc < 4) {
            fprintf(stderr, "Error: 'remote show' requires name\n");
            print_remote_help(argv[0]);
            return 1;
        }
        opts.name = argv[3];
    } else {
        /* Assume it's a remote name to list (treat as verbose list) */
        opts.subcommand = REMOTE_LIST;
        opts.verbose = true;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_remote(repo, &opts);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse show command
 */
static int cmd_show_main(int argc, char **argv) {
    cmd_show_options_t opts = {
        .profile = NULL,
        .file_path = NULL,
        .commit = NULL,
        .raw = false
    };

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_show_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            opts.profile = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--commit") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --commit requires an argument\n");
                return 1;
            }
            opts.commit = argv[++i];
        } else if (strcmp(argv[i], "--raw") == 0) {
            opts.raw = true;
        } else if (!opts.file_path) {
            opts.file_path = argv[i];
        } else {
            fprintf(stderr, "Error: Unexpected argument '%s'\n", argv[i]);
            print_show_help(argv[0]);
            return 1;
        }
    }

    /* Validate required arguments */
    if (!opts.file_path) {
        fprintf(stderr, "Error: file path is required\n");
        print_show_help(argv[0]);
        return 1;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_show(repo, &opts);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse revert command
 */
static int cmd_revert_main(int argc, char **argv) {
    cmd_revert_options_t opts = {
        .file_path = NULL,
        .commit = NULL,
        .profile = NULL,
        .apply = false,
        .commit_changes = false,
        .message = NULL,
        .force = false,
        .dry_run = false,
        .verbose = false
    };

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_revert_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --profile requires an argument\n");
                return 1;
            }
            opts.profile = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--message") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --message requires an argument\n");
                return 1;
            }
            opts.message = argv[++i];
        } else if (strcmp(argv[i], "--apply") == 0) {
            opts.apply = true;
        } else if (strcmp(argv[i], "--commit") == 0) {
            opts.commit_changes = true;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            opts.force = true;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            opts.dry_run = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opts.verbose = true;
        } else if (!opts.file_path) {
            opts.file_path = argv[i];
        } else if (!opts.commit) {
            opts.commit = argv[i];
        } else {
            fprintf(stderr, "Error: Unexpected argument '%s'\n", argv[i]);
            print_revert_help(argv[0]);
            return 1;
        }
    }

    /* Validate required arguments */
    if (!opts.file_path) {
        fprintf(stderr, "Error: file path is required\n");
        print_revert_help(argv[0]);
        return 1;
    }

    if (!opts.commit) {
        fprintf(stderr, "Error: commit reference is required\n");
        print_revert_help(argv[0]);
        return 1;
    }

    /* Validate option combinations */
    if (opts.message && !opts.commit_changes) {
        fprintf(stderr, "Error: --message requires --commit\n");
        return 1;
    }

    /* Open resolved repository */
    git_repository *repo = open_resolved_repo(NULL);
    if (!repo) {
        return 1;
    }

    /* Execute command */
    error_t *err = cmd_revert(repo, &opts);
    git_repository_free(repo);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

/**
 * Parse bootstrap command
 */
static int cmd_bootstrap_main(int argc, char **argv) {
    /* Collect profile arguments */
    const char **profiles = malloc((size_t)argc * sizeof(char *));
    if (!profiles) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    size_t profile_count = 0;

    cmd_bootstrap_options_t opts = {
        .profiles = NULL,
        .profile_count = 0,
        .all_profiles = false,
        .edit = false,
        .show = false,
        .list = false,
        .dry_run = false,
        .yes = false,
        .continue_on_error = false
    };

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_bootstrap_help(argv[0]);
            free(profiles);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --profile requires an argument\n");
                free(profiles);
                return 1;
            }
            profiles[profile_count++] = argv[++i];
        } else if (strcmp(argv[i], "--all") == 0) {
            opts.all_profiles = true;
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--edit") == 0) {
            opts.edit = true;
        } else if (strcmp(argv[i], "--show") == 0) {
            opts.show = true;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            opts.list = true;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--dry-run") == 0) {
            opts.dry_run = true;
        } else if (strcmp(argv[i], "-y") == 0 || strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "--no-confirm") == 0) {
            opts.yes = true;
        } else if (strcmp(argv[i], "--continue-on-error") == 0) {
            opts.continue_on_error = true;
        } else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            free(profiles);
            return 1;
        }
    }

    if (profile_count > 0) {
        opts.profiles = profiles;
        opts.profile_count = profile_count;
    }

    /* Execute command */
    error_t *err = cmd_bootstrap(&opts);
    free(profiles);

    if (err) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }

    return 0;
}

int main(int argc, char **argv) {
    /* Initialize libgit2 */
    if (git_libgit2_init() < 0) {
        fprintf(stderr, "Failed to initialize libgit2\n");
        return 1;
    }

    /* Parse command */
    if (argc < 2) {
        print_usage(argv[0]);
        git_libgit2_shutdown();
        return 1;
    }

    const char *command = argv[1];
    int ret = 0;

    if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage(argv[0]);
    } else if (strcmp(command, "--version") == 0 || strcmp(command, "-v") == 0) {
        print_version();
    } else if (strcmp(command, "init") == 0) {
        ret = cmd_init_main(argc, argv);
    } else if (strcmp(command, "clone") == 0) {
        ret = cmd_clone_main(argc, argv);
    } else if (strcmp(command, "add") == 0) {
        ret = cmd_add_main(argc, argv);
    } else if (strcmp(command, "remove") == 0) {
        ret = cmd_remove_main(argc, argv);
    } else if (strcmp(command, "apply") == 0) {
        ret = cmd_apply_main(argc, argv);
    } else if (strcmp(command, "status") == 0) {
        ret = cmd_status_main(argc, argv);
    } else if (strcmp(command, "list") == 0) {
        ret = cmd_list_main(argc, argv);
    } else if (strcmp(command, "profile") == 0) {
        ret = cmd_profile_main(argc, argv);
    } else if (strcmp(command, "diff") == 0) {
        ret = cmd_diff_main(argc, argv);
    } else if (strcmp(command, "show") == 0) {
        ret = cmd_show_main(argc, argv);
    } else if (strcmp(command, "revert") == 0) {
        ret = cmd_revert_main(argc, argv);
    } else if (strcmp(command, "remote") == 0) {
        ret = cmd_remote_main(argc, argv);
    } else if (strcmp(command, "update") == 0) {
        ret = cmd_update_main(argc, argv);
    } else if (strcmp(command, "sync") == 0) {
        ret = cmd_sync_main(argc, argv);
    } else if (strcmp(command, "ignore") == 0) {
        ret = cmd_ignore_main(argc, argv);
    } else if (strcmp(command, "bootstrap") == 0) {
        ret = cmd_bootstrap_main(argc, argv);
    } else if (strcmp(command, "git") == 0) {
        ret = cmd_git_main(argc, argv);
    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage(argv[0]);
        ret = 1;
    }

    git_libgit2_shutdown();
    return ret;
}
