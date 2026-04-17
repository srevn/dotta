/**
 * runtime.c - Per-mode dispatch payloads
 *
 * One `const dotta_spec_ext_t` value per repo mode. Commands point
 * `args_command_t::user_data` at the matching constant; main.c reads
 * it back in run_spec to decide how to open the repository. The
 * registry itself is `static` inside main.c — it never appears here.
 */

#include "cmds/runtime.h"

const dotta_spec_ext_t dotta_ext_none = {
    .repo_mode = DOTTA_REPO_NONE
};

const dotta_spec_ext_t dotta_ext_required = {
    .repo_mode = DOTTA_REPO_REQUIRED
};

const dotta_spec_ext_t dotta_ext_optional_silent = {
    .repo_mode = DOTTA_REPO_OPTIONAL_SILENT
};

const dotta_spec_ext_t dotta_ext_path_only = {
    .repo_mode = DOTTA_REPO_PATH_ONLY
};
