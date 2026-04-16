/**
 * registry.c - Root command registry (data definition)
 *
 * One array, one line per command. Consumers are in registry.h.
 */

#include "cmds/registry.h"

#include "cmds/add.h"
#include "cmds/apply.h"
#include "cmds/bootstrap.h"
#include "cmds/clone.h"
#include "cmds/completion.h"
#include "cmds/diff.h"
#include "cmds/git.h"
#include "cmds/ignore.h"
#include "cmds/init.h"
#include "cmds/interactive.h"
#include "cmds/key.h"
#include "cmds/list.h"
#include "cmds/profile.h"
#include "cmds/remote.h"
#include "cmds/remove.h"
#include "cmds/revert.h"
#include "cmds/show.h"
#include "cmds/status.h"
#include "cmds/sync.h"
#include "cmds/update.h"

/* Ordered for root-help readability: setup → file ops → deploy/undo →
 * inspect → remote → profile/remote mgmt → config → passthrough →
 * special. Every projection (dispatch, help, fish export) walks this
 * array, so the order is the display order everywhere. */
const args_command_t *const dotta_root_commands[] = {
    &spec_init,
    &spec_clone,
    &spec_add,
    &spec_remove,
    &spec_update,
    &spec_apply,
    &spec_revert,
    &spec_status,
    &spec_diff,
    &spec_list,
    &spec_show,
    &spec_sync,
    &spec_profile,
    &spec_remote,
    &spec_ignore,
    &spec_bootstrap,
    &spec_key,
    &spec_git,
    &spec_interactive,
    &spec_completion,
    NULL
};
