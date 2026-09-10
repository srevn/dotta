/**
 * add.c - Add files to profiles
 */

#include "cmds/add.h"

#include <config.h>
#include <errno.h>
#include <git2.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/hashmap.h"
#include "base/output.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/policy.h"
#include "core/state.h"
#include "infra/content.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/stage.h"
#include "sys/identity.h"
#include "sys/source.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * One path this command listed, under the claim it gives it
 *
 * `location` is where the claim stands, which is the view's own key for it
 * (mount_resolve's answer): the record joins by it with no round trip. It is
 * the path the bytes are read at for every listing but one — a typed name standing
 * at a binder's own spelling is a claim of the link, and the directory the walk
 * enumerates beneath it is mount_locate's (infra/mount.h, the stated exception).
 *
 * `claim` is the pair the namer reads (core/manifest.h manifest_claim_t): the
 * name the capture commits under, and the kind that says whether anything can
 * be named beneath it. The listing indexes it by location, so every path beneath
 * one already listed is named from it and the walk carries no frame of its own.
 *
 * `stat` is the file capture's own triple — the fstat of the descriptor the bytes
 * came off — so the record binds the committed blob to it. A directory's stays
 * unset, as apply records them.
 */
typedef struct {
    const char *location;         /* Where the claim stands (arena) */
    manifest_claim_t claim;       /* The name and kind it was listed under (arena) */
    stat_cache_t stat;            /* The capture's triple; STAT_CACHE_UNSET for a directory */
} add_path_t;

/**
 * The walk: what every frame reads, and the two lists it fills
 *
 * `listing` is this command's own claims, which is exactly the layer
 * manifest_name reads as `pending`: location -> &item->claim, with a NULL *value*
 * for a location entered without claiming (a root met from above). hashmap_has
 * says this command settled the location, hashmap_get says it claimed it. So
 * overlapping CLI arguments (~/.config and ~/.config/fish) list each path once
 * — a directory already walked is skipped with its subtree, a file already listed
 * is not listed again — and every path beneath one already listed is named from
 * its claim, which is why no frame is carried down the walk. The key is the
 * location, so two spellings of one argument — `~/x` beside its physical,
 * tab-completion beside `find`'s output — are one key for every alias the table
 * knows; a link no binding names is two, as two claims through and around it
 * are two claims (infra/mount.h). Keys and values borrow the arena the items
 * live in.
 *
 * `view` is the branch as this command opened it: this profile's contribution
 * alone, from the tree the stage opened at, under this command's table. Every
 * name comes from it (core/manifest.h manifest_name, over `listing`), the kind
 * question reads it (manifest_lookup_claim), and so does the one refusal the
 * completed selection owes (refuse_moved_name).
 *
 * `stage` and `sheet` are the two documents one commit carries, and the walk
 * asks both whether the branch has room for a name before a byte is read: the
 * tree holds every blob (sys/stage.h, the two admissions), and the sheet holds
 * the directories a tree cannot — an empty one has no entry, so a claim the index
 * cannot see is the sheet's to answer for (core/metadata.h
 * metadata_directory_beneath). Both are the branch as this command found it;
 * what the command itself authors is read once at the end, where both are final.
 */
typedef struct {
    const dotta_ctx_t *ctx;              /* The arena the paths live in, and the output */
    const mount_table_t *mounts;         /* The command's table (see cmd_add) */
    const char *profile;                 /* The asker: whose claims name what is found */
    const manifest_t *view;              /* The branch as this command opened it */
    const gitignore_ruleset_t *rules;    /* The profile's .dottaignore layers */
    source_filter_t *source_filter;      /* The source tree's .gitignore, when consulted */
    const stage_t *stage;                /* The branch's tree, asked once per listing */
    const metadata_t *sheet;             /* The branch's claims, asked with it */
    hashmap_t *listing;                  /* location -> &item->claim (borrowed both) */
    ptr_array_t files;                   /* add_path_t *: every non-directory listed */
    ptr_array_t directories;             /* add_path_t *: every directory walked into */
} add_walk_t;

/**
 * What the record phase did, for the receipt
 *
 * `updated` is the phase's word that the anchor pass ran and its transaction
 * committed — the receipt's "Record updated" line and its counts speak only then;
 * false reads "profile not enabled". The counts qualify it: how many of the
 * captured files this profile's rows actually took, and how many of those took
 * over a record another profile's deployment had written.
 *
 * A capture the rows did not take has two causes, and each is counted where the
 * row that says which is in hand rather than read off a difference: a
 * higher-precedence profile holds the location (`overridden`), or this profile's
 * own other name stands there (`unkept`) — a second name of one profile being a
 * thing a branch can hold and a sync can bring here (core/manifest.h
 * manifest_unkept, whose screen word is "unused path"), whose repair is the health
 * channel's on the same screen, not this receipt's. A difference would name
 * whichever cause the line happened to be written for; the sum falls short of
 * the captures only for a claim this machine cannot place, which has no row to
 * blame and goes unnamed.
 *
 * `unkept` is now one thing only. This command cannot author a second name, and
 * a capture at a contested location lands on the name the next settle will keep
 * — refuse_moved_name is the last word on that — so a non-zero count is a typed
 * re-capture of a loser, deliberately made, which is exactly what "captured under
 * an unused path" says.
 */
typedef struct {
    bool updated;          /* The anchor pass ran and the transaction committed */
    size_t synced;         /* Files anchored under this profile's rows */
    size_t taken_over;     /* Of those, records taken over from another profile */
    size_t overridden;     /* Files whose location a higher-precedence profile holds */
    size_t unkept;         /* Files committed under a path the view does not use */
} record_receipt_t;

/**
 * Validate command options
 */
static error_t *validate_options(const cmd_add_options_t *opts) {
    CHECK_NULL(opts);

    if (!opts->profile || opts->profile[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name is required");
    }

    if (!opts->files || opts->file_count == 0) {
        return ERROR(ERR_INVALID_ARG, "At least one path is required");
    }

    return NULL;
}

/**
 * Is this spelling the target, or beneath it?
 *
 * Asked of the table, one folded prefix at a time — "/", "/a", "/a/b", … — until
 * a prefix stands where the target does. One directory has as many spellings as
 * the aliases above it: as its binder typed it, as realpath spells it, read through
 * HOME's own link, read through another profile's declared binding. Arguments
 * arrive under all of them — tab-completion and find give the physical one, the
 * flag usually the typed one — and the table is the only thing that knows they
 * are one place, so the boundary is found by asking it rather than by holding a
 * pair of strings and comparing bytes. The last prefix asked is the whole spelling,
 * so the target is inside itself and `add web --target ~/jail ~/jail` is the
 * jail, walked.
 *
 * The prefix is folded and the tail is not: the decision is about where the
 * argument was *spelled from*, and folding the tail first destroys it —
 * `<target>/../secret` folds to a path outside the target, would be re-rooted
 * under it, and would name a different file that may well exist. Past the boundary
 * the tail is read as typed: a declared link inside the jail that reaches outside
 * is typed inside and named for where it lands.
 *
 * Every prefix is folded before it is asked, because mount_locate's input is
 * absolute and folded (infra/mount.h) — `/a/..` is a spelling of nowhere. The
 * boundary is not always found before the first `..`, and does not need to be:
 * `/a/../<target>/x` meets one first, and the fold is per prefix, not per argument.
 * A `.` leaves the prefix as it was and a `..` returns it to one the append that
 * made it already asked about, so neither asks again; the root the walk starts
 * from is no binding's spelling (the table spells it "") and no target is "/"
 * (mount_validate_target), so it is not the boundary either.
 *
 * `spelling` is absolute: the caller's grammar decides who is asked at all, and
 * a bare relative path is the jail's without a question (spell_argument). The
 * scratch is sized for one regardless — folding never grows a path — so the gate
 * is a rule about meaning, never about memory.
 *
 * O(depth) locates per argument, never per child. Asked twice for each argument:
 * before the compose, on the bytes as typed — unfolded, so a `..` beneath the
 * target is inside here and walks out at the fold, where the escape rule reads
 * it — and after it, on the folded spelling, to refuse what walked out. The scratch
 * is the arena's and abandoned, the module's idiom, so no path here has a free
 * to get wrong.
 *
 * @param mounts          The command's table (must not be NULL)
 * @param spelling        Absolute filesystem spelling, as typed (must not be NULL)
 * @param target_location Where the table says the target stands (must not be NULL)
 * @param arena           Arena for the scratch and the locates
 * @param out_inside      True iff a prefix of `spelling` stands at the target
 * @return Error or NULL on success
 */
static error_t *inside_target(
    const mount_table_t *mounts, const char *spelling, const char *target_location,
    arena_t *arena, bool *out_inside
) {
    *out_inside = false;

    /* The folded prefix, grown one component at a time, with "." dropped and
     * ".." popping — the fold fs_normalize_path performs over a whole argument,
     * applied per prefix so the prefixes exist to be asked about. Folding never
     * grows a path, so the spelling's own length plus a leading slash and a
     * terminator bounds it, absolute or not. */
    char *folded = arena_alloc(arena, strlen(spelling) + 2);
    if (!folded) {
        return ERROR(ERR_MEMORY, "Failed to allocate the boundary scratch");
    }
    folded[0] = '/';
    folded[1] = '\0';
    size_t len = 1;

    const char *cursor = spelling;
    while (*cursor) {
        while (*cursor == '/') cursor++;
        if (!*cursor) break;

        const char *component = cursor;
        while (*cursor && *cursor != '/') cursor++;
        size_t length = (size_t) (cursor - component);

        if (length == 1 && component[0] == '.') continue;
        if (length == 2 && component[0] == '.' && component[1] == '.') {
            /* str_path_parent_len keeps the root's own slash ("/etc" -> 1, "/"
             * -> 1), so the root pops to itself (base/string.h). */
            len = str_path_parent_len(folded);
            folded[len] = '\0';
            continue;
        }

        if (len > 1) folded[len++] = '/';
        memcpy(folded + len, component, length);
        len += length;
        folded[len] = '\0';

        const char *location = NULL;
        error_t *err = mount_locate(mounts, folded, arena, &location);
        if (err) return err;
        if (strcmp(location, target_location) == 0) {
            *out_inside = true;   /* The tail is unread: past here it is Git's */
            return NULL;
        }
    }

    return NULL;
}

/**
 * The argument as add reads it: absolute, and the target's when one stands
 *
 * `--target <dir>` makes that directory a virtual root — an argument is read as
 * if the user stood inside it, the way a chroot reads a path — which is how a
 * jail, a container overlay, a fakeroot tree or a staging area is populated from
 * outside. Two spellings are the shell's and are never re-rooted: a tilde path
 * (`~/x` is HOME's, its own namespace, as a shell resolves '~' before any cd
 * context applies) and a path spelled from here (`./x`, `../x`, a dotfile's `.x`
 * — the file in front of the user, wherever they stand, the way the resolver
 * reads a leading '.'). A bare relative path is the jail's.
 *
 *   cd anywhere;     ~/file                  -> $HOME/file        (HOME's)
 *                    etc/foo                 -> <target>/etc/foo  (the jail's)
 *                    /etc/foo                -> <target>/etc/foo  (re-rooted)
 *                    <target>/etc/foo        -> as typed          (inside)
 *                    <any spelling of the    -> as typed          (inside, under
 *                     target>/etc/x                                a spelling only
 *                                                                  the table knows)
 *   cd <target>/etc; ./x                     -> <target>/etc/x    (from here)
 *                    ../x                    -> <target>/x        (from here,
 *                                                                  still inside)
 *   cd ~;            ./x                     -> ERROR             (from here,
 *                                                                  outside)
 *                    <target>/../etc/secret  -> ERROR             (walked out)
 *                    ""                      -> ERROR             (no path in any
 *                                                                  grammar)
 *
 * The refusal is lexical, on the spelling: what a path reaches through a link
 * is not this rule's business — a declared link inside the target that reaches
 * outside is typed inside and admitted, named for where it lands.
 *
 * @param mounts          The command's table, which the boundary is found through
 *                        (must not be NULL)
 * @param input           The argument as typed (must not be NULL)
 * @param target          --target, absolute and validated, or NULL: nothing
 *                        re-roots
 * @param target_location Where the table says the target stands; unread with no
 *                        target
 * @param arena           Arena the boundary reads and writes through
 * @param out             Normalized absolute path (caller must free)
 * @return Error or NULL on success
 */
static error_t *spell_argument(
    const mount_table_t *mounts, const char *input, const char *target,
    const char *target_location, arena_t *arena, char **out
) {
    /* The shell's own reading: no target to read the argument as, a tilde path,
     * or an empty argument — no path in any grammar, and the normalizer is the
     * one place that says so, rather than the joiner below refusing it by accident
     * of validating its own component. */
    if (!target || input[0] == '~' || input[0] == '\0') {
        return path_input_normalize(input, out);
    }

    /* Standing inside the target is something only an absolute spelling can be
     * doing: a bare relative path is the jail's by the grammar above, and folding
     * one onto the root to ask would read `etc/foo` under `--target /etc` as
     * the target itself and leave the argument wherever the user happens to
     * stand. */
    error_t *err = NULL;
    bool inside = false;
    if (input[0] == '/') {
        err = inside_target(mounts, input, target_location, arena, &inside);
        if (err) return err;
    }

    /* Re-root, unless the argument is already the target's: spelled from here,
     * or standing inside it. The join reads a host-absolute input's leading '/'
     * as its own separator, so `/etc/foo` and `etc/foo` both land at
     * <target>/etc/foo — and it composes under the target as the row spells it,
     * which is the spelling the refusal below prints. */
    char *composed = NULL;
    if (input[0] != '.' && !inside) {
        err = fs_path_join(target, input, &composed);
        if (err) return err;
    }

    err = path_input_normalize(composed ? composed : input, out);
    free(composed);
    if (err) return err;

    /* One check for every escape, whatever the shape: `..` walked out of a path
     * that started inside, or a path spelled from here while the user stands
     * outside. No per-shape pre-validation in the compose step. */
    bool landed_inside = false;
    err = inside_target(mounts, *out, target_location, arena, &landed_inside);
    if (!err && !landed_inside) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Path '%s' resolves outside target root '%s'.\n"
            "A path spelled from here, or one walking out with '..', cannot "
            "escape the target.", *out, target
        );
    }
    if (err) {
        free(*out);
        *out = NULL;
    }

    return err;
}

/**
 * Check if path should be ignored.
 *
 * Consults two independent mechanisms in order, each on the name it is written
 * against:
 *   1. The `.dottaignore` layers (baseline, profile, config, CLI) compiled into
 *      a single gitignore ruleset, evaluated on the mount-relative path
 *      (mount_strip_label of `storage_path`): what a `.gitignore` at the mount
 *      root would see.
 *   2. The source tree's own `.gitignore`, if the command built a filter (gated
 *      on `config.respect_gitignore`), evaluated on `location`: that repository's
 *      root is the root its rules are relative to. The lowest layer: asked only
 *      when no `.dottaignore` layer decided, so a `!` rule in any of them overrides
 *      it.
 *
 * The subject of the first is the name this command chose, whatever produced it
 * — a claim the profile already held, a composition beneath a tracked directory,
 * a typed argument — so a path beneath a tracked `home/jail/etc` is matched as
 * `jail/etc/x` and not as `etc/x` (cmds/add.h). The subject of the second is
 * where the path stands, which no naming decision moves.
 *
 * Either mechanism may be absent. `*out_match` is the rules' verdict — the layer
 * and the rule as written when they decided, undecided when the source tree's
 * .gitignore gave the verdict — so a caller can say who excluded the path.
 * Source-filter errors degrade to a verbose warning and a "not excluded" verdict
 * so an odd source repo never blocks the user from adding a file they explicitly
 * named. The gitignore evaluator never fails — its verdict is applied directly.
 */
static bool is_excluded(
    const add_walk_t *walk, const char *location, const char *storage_path,
    path_kind_t kind, gitignore_match_t *out_match
) {
    /* Both layers ask for the directory bit, which is the kind read as the two
     * APIs want it: a gitignore rule with a trailing slash matches a directory
     * alone, and the source filter's attr stack needs the same distinction. */
    bool is_directory = kind == PATH_KIND_DIRECTORY;

    gitignore_eval(
        walk->rules, mount_strip_label(storage_path), is_directory, out_match
    );
    if (out_match->decided) {
        return out_match->ignored;
    }

    if (walk->source_filter) {
        bool excluded = false;
        error_t *err = source_filter_is_excluded(
            walk->source_filter, location, is_directory, &excluded
        );
        if (err) {
            output_warning(
                walk->ctx->out, OUTPUT_VERBOSE,
                "Source .gitignore check failed for %s: %s", location,
                error_message(err)
            );
            error_free(err);
            return false;
        }
        return excluded;
    }

    return false;
}

/**
 * List `location` under `claim`: the item, its bucket, and the listing's index
 *
 * The item is the arena's and stable, which is what lets the index borrow its
 * claim rather than a loop-local pair — and that is what makes every path beneath
 * this one nameable from it (core/manifest.h manifest_name, the `pending` layer).
 * The claim's kind chooses the bucket: the walk is the sole source of directory
 * tracking, and every phase after reads the two lists apart.
 *
 * Both fallible steps are checked. The listing is what this command promises to
 * capture, so an entry lost to a failed push and captured anyway would break
 * the selection model; a failure here aborts the command, and nothing reads the
 * listing after one.
 */
static error_t *list_path(
    add_walk_t *walk, const char *location, manifest_claim_t claim
) {
    add_path_t *path = arena_calloc(walk->ctx->arena, 1, sizeof(*path));
    if (!path) {
        return ERROR(ERR_MEMORY, "Failed to allocate path entry");
    }
    path->location = location;
    path->claim = claim;
    path->stat = STAT_CACHE_UNSET;

    error_t *err = ptr_array_push(
        claim.kind == PATH_KIND_DIRECTORY ? &walk->directories : &walk->files,
        path
    );
    if (err) return err;

    return hashmap_set(walk->listing, location, &path->claim);
}

/**
 * Has the branch room for this name — in its tree, and in its sheet?
 *
 * One commit carries two documents, and they name one namespace: the tree holds
 * every blob, and the sheet holds the directories a tree cannot, since an empty
 * one has no entry at all. A blob at a name is incompatible with anything standing
 * at that name and with everything standing beneath it, whichever document the
 * thing beneath it lives in — so a blob asks both and a subtree asks the tree,
 * a directory claim beneath another being ordinary.
 *
 * The subject is the branch as this command found it: the index seeded at the
 * open, and the sheet loaded from the same tree. What this command itself authors
 * is read once at the end, where both are final (cmd_add).
 *
 * One producer, two voices: every refusal is ERR_CONFLICT and says which name
 * stands in the way, and the callers give it their own — the argument arm wraps
 * it as an error, the walk prints it and skips the subtree. Anything else is
 * the run failing to decide, which is never a verdict about the path.
 */
static error_t *admit_name(
    const add_walk_t *walk, const char *storage_path, path_kind_t kind
) {
    if (kind == PATH_KIND_DIRECTORY) {
        return stage_admit_subtree(walk->stage, storage_path);
    }

    /* The sheet first: a directory it claims beneath this name has no tree entry
     * to find, so the index cannot answer for it. */
    const metadata_item_t *claimed = metadata_directory_beneath(
        walk->sheet, storage_path
    );
    if (claimed) {
        return ERROR(
            ERR_CONFLICT,
            "Cannot stage '%s': '%s' is a directory this profile claims beneath it",
            storage_path, claimed->key
        );
    }

    return stage_admit_blob(walk->stage, storage_path);
}

/**
 * Collect a directory's children into the walk.
 *
 * `directory` is the directory that stands at the frame's own location, and so
 * is every path this frame joins beneath it: the caller located what it began
 * at, and a directory child is read through the table before the walk enters
 * it. The frame itself is neither named nor listed here — its caller has already
 * settled it, the argument arm before it descends and the recursion below before
 * it recurses — which is what lets a claim's key differ from the directory it
 * enumerates: a typed name standing at a binder's own spelling keys at the link
 * and enumerates the binding's directory (infra/mount.h, mount_resolve's
 * exception).
 *
 * Every directory walked into is listed — the walk is the sole source of directory
 * tracking — and so is every regular file and symlink child a branch can hold.
 * Symlinks are never followed: a symlink to a directory is an entry like any
 * other, and a special file is no entry at all.
 *
 * Each child is named here, once, by the claim standing at it — this command's
 * own where it has listed one there, else the profile's own (core/manifest.h
 * manifest_name over `listing`) — and the recursion names it again for no one.
 * Another profile's target is an ordinary directory here: the walk lists it and
 * enters it, and what it finds beneath is named portably (infra/mount.h). A child
 * that is one of *this* profile's roots has no name at all: it is entered unlisted
 * when it is a directory, and skipped otherwise.
 *
 * Two verdicts skip a child with its subtree, each with one line at NORMAL: a
 * kind the profile's own claim at the location contradicts, and a name the branch
 * has no room for (admit_name). Neither may fail the command — a stale claim
 * deep inside $HOME must not fail `dotta add p ~`, and the capture that would
 * have refused it arrives too late to skip anything. `depth` bounds the recursion
 * at FS_WALK_MAX_DEPTH, and that is the one walked verdict that refuses rather
 * than skips — collection precedes capture, so a refusal there costs nothing,
 * where a skip would leave the profile permanently short of a subtree that can
 * in fact be captured.
 *
 * On error the lists keep what was collected; the caller's cleanup owns them.
 */
static error_t *collect_tree(
    add_walk_t *walk, const char *directory, size_t depth
) {
    CHECK_NULL(walk);
    CHECK_NULL(directory);

    arena_t *arena = walk->ctx->arena;
    output_t *out = walk->ctx->out;

    /* The bound is the frame's own, tested before it enumerates. A directory
     * already settled never reaches here: the callers test the listing before
     * they descend, so a deeper argument collected first does not make its parent's
     * walk fail when the parent arrives at the limit. */
    if (depth >= FS_WALK_MAX_DEPTH) {
        return ERROR(
            ERR_INVALID_ARG,
            "Cannot walk '%s': it is %d directories below where this walk began; "
            "name it as an argument of its own, or exclude it",
            directory, FS_WALK_MAX_DEPTH
        );
    }

    /* "/" is the one directory whose spelling ends in its separator: a child
     * beneath it is joined with none. */
    const char *separator = directory[1] ? "/" : "";

    /* The whole listing, and the stream closed with it: one open at a time down
     * the recursion rather than one per frame, and the errno discipline is
     * fs_list_dir's. */
    string_array_t *entries = NULL;
    RETURN_IF_ERROR(fs_list_dir(directory, &entries));

    error_t *err = NULL;

    for (size_t i = 0; i < entries->count; i++) {
        const char *child_fs = arena_str_format(
            arena, "%s%s%s", directory, separator, entries->items[i]
        );
        if (!child_fs) {
            err = ERROR(ERR_MEMORY, "Failed to allocate path");
            goto cleanup;
        }

        /* One lstat names what stands there, and the kind follows from it: a
         * symlink is never a directory here. Absence is a skip — the listing
         * and this look are two moments, and a path that left between them is
         * not this command's failure — while a path that cannot be read is the
         * same refusal the enumeration itself would have raised, and is fatal
         * with it. What no branch can hold, a device or a socket or a FIFO, is
         * skipped by its noun rather than carried to a capture that would refuse
         * it and take every sibling with it. */
        struct stat st;
        path_kind_t kind = PATH_KIND_FILE;
        switch (fs_lstat_occupant(child_fs, &st)) {
            case FS_OCCUPANT_NONE:
                output_info(out, OUTPUT_VERBOSE, "Skipped absent: %s", child_fs);
                continue;

            case FS_OCCUPANT_UNKNOWN: {
                int saved_errno = errno;
                err = error_from_errno(
                    saved_errno, "Failed to stat '%s'", child_fs
                );
                goto cleanup;
            }

            case FS_OCCUPANT_OTHER:
                output_info(
                    out, OUTPUT_VERBOSE, "Skipped %s: %s", fs_stat_noun(&st),
                    child_fs
                );
                continue;

            case FS_OCCUPANT_DIRECTORY:
                kind = PATH_KIND_DIRECTORY;
                break;

            case FS_OCCUPANT_REGULAR:
            case FS_OCCUPANT_SYMLINK:
                break;
        }

        /* Where the child stands. A directory is the directory it is: one met
         * at a binder's own spelling — a root reached through a link no binding
         * names — is read through to the physical, so this frame's join and every
         * one below it is a location, which is what the namer's input must be.
         * A leaf keeps the spelling it stands under: the very link a binding is
         * declared through is a claim of the link (mount_locate's stated
         * exception), and the walk does not follow one. */
        if (kind == PATH_KIND_DIRECTORY) {
            const char *joined = child_fs;
            err = mount_locate(walk->mounts, joined, arena, &child_fs);
            if (err) {
                err = error_wrap(err, "Failed to locate '%s'", joined);
                goto cleanup;
            }
        }

        /* Walked whole, or listed already: asked before a name, so nothing this
         * command has settled is settled a second time — and so a verdict against
         * a path is reached once, whichever of the two said it. */
        if (hashmap_has(walk->listing, child_fs)) continue;

        /* The crossing: what this profile calls the child — the claim standing
         * there, this command's own or the branch's, else the composition beneath
         * the nearest claim above it — or nothing when the child is one of the
         * profile's own roots, which has no name in the namespace and so is neither
         * excludable nor listed. */
        const char *child_storage = NULL;
        err = manifest_name(
            walk->view, walk->profile, child_fs, walk->listing, arena,
            &child_storage
        );
        if (err) {
            err = error_wrap(err, "Failed to name '%s'", child_fs);
            goto cleanup;
        }

        if (!child_storage) {
            if (kind != PATH_KIND_DIRECTORY) {
                /* A symlink standing at one of this profile's own roots: $HOME
                 * itself when HOME is a link, or its target reached through one.
                 * The walk does not follow symlinks, and the root itself has no
                 * name. */
                output_info(out, OUTPUT_VERBOSE, "Skipped root: %s", child_fs);
                continue;
            }

            /* A root met from above: entered and never listed, so the frames
             * below it compose beneath its label and nothing is settled twice. */
            err = hashmap_set(walk->listing, child_fs, NULL);
        } else {
            /* Check exclude patterns */
            gitignore_match_t match;
            if (is_excluded(walk, child_fs, child_storage, kind, &match)) {
                if (match.decided) {
                    output_info(
                        out, OUTPUT_VERBOSE, "Excluded: %s (%s: '%s')", child_fs,
                        ignore_origin_describe((ignore_origin_t) match.origin),
                        match.pattern
                    );
                } else {
                    output_info(
                        out, OUTPUT_VERBOSE, "Excluded: %s (source .gitignore)",
                        child_fs
                    );
                }
                continue;
            }

            /* What the profile already claims at the location, against what stands
             * there now. The row is the location's own authority on kind, a derived
             * one included — it says the profile holds a subtree beneath the
             * path, which a path that became a file cannot carry — and it is
             * the one reading that sees a claim with nothing beneath it for either
             * of the branch's documents to find, where admit_name below covers
             * the rest, by the name. */
            const manifest_row_t *held = manifest_lookup_claim(
                walk->view, walk->profile, child_fs
            );
            if (held && path_type_kind(held->type) != kind) {
                output_warning(
                    out, OUTPUT_NORMAL,
                    "Skipping '%s': profile '%s' holds it as the %s '%s', and a "
                    "%s stands there now", child_fs, walk->profile,
                    held->type == PATH_TYPE_DIRECTORY ? "directory" : "file",
                    held->storage_path, fs_stat_noun(&st)
                );
                continue;
            }

            /* What the branch can hold, asked before a byte is read. Only a shape
             * conflict is a verdict about the path; a failure to decide is the
             * run failing, and publishing a selection past one would commit a
             * silently partial capture. */
            err = admit_name(walk, child_storage, kind);
            if (err) {
                if (error_code(err) != ERR_CONFLICT) goto cleanup;
                output_warning(
                    out, OUTPUT_NORMAL, "Skipping '%s': %s", child_fs,
                    error_message(err)
                );
                error_free(err);
                err = NULL;
                continue;
            }

            err = list_path(
                walk, child_fs, (manifest_claim_t){ child_storage, kind }
            );
        }

        /* Settled either way, so the descent is one statement: a listed directory
         * and a root entered unlisted are both walked, and nothing else is. */
        if (!err && kind == PATH_KIND_DIRECTORY) {
            err = collect_tree(walk, child_fs, depth + 1);
        }
        if (err) goto cleanup;
    }

cleanup:
    string_array_free(entries);

    return err;
}

/**
 * Refuse a selection that moves a name without capturing the one it moves to
 *
 * A location this branch names twice is decided by the settle, and this command's
 * own claims can change that decision: a directory claim admitted above such a
 * location changes what its ascent composes, and with it which of the profile's
 * names stands there (core/manifest.h manifest_name, "what the next settle will
 * keep"). Where the name that will stand is not one this command captured, the
 * next apply deploys bytes this command never read — over the ones it just
 * committed under the other name.
 *
 * The subject is exactly manifest_unkept's slice: no verb can give a profile a
 * second name for a location it already names (manifest_holds_name), and a listing
 * that is not typed takes the namer's own answer — so the groups are the branch's,
 * and only which member stands can move. Asked once, with the selection complete,
 * because naming is a snapshot taken when a path is listed and a later argument
 * can change what an earlier one composed.
 *
 * `kept` is the settle's own answer at the location and needs no second lookup;
 * the view is one profile's, so the slice needs no profile filter. A location
 * its profile names three times appears twice and is asked twice — the question
 * is pure, and a set to spend on that repetition would cost more than it saves.
 *
 * The name to give up is the one this command would move *to*: with it gone the
 * location is named once, the pre-command winner stands, and nothing moves. Giving
 * up the kept name performs the move instead of preventing it.
 *
 * Not liftable by --force: --force overwrites bytes under a name the profile
 * holds, which is not what abandoning a name is.
 */
static error_t *refuse_moved_name(const add_walk_t *walk) {
    manifest_unkept_t unkept = manifest_unkept(walk->view);

    for (size_t i = 0; i < unkept.count; i++) {
        const char *location = unkept.entries[i].filesystem_path;
        const char *kept = unkept.entries[i].kept;

        const char *next = NULL;
        error_t *err = manifest_name(
            walk->view, walk->profile, location, walk->listing,
            walk->ctx->arena, &next
        );
        if (err) {
            return error_wrap(err, "Failed to name '%s'", location);
        }
        if (strcmp(kept, next) == 0) continue;   /* nothing moved here */

        /* The one selection that may move a name: the command captured the location
         * under the very name the next settle will keep. */
        const manifest_claim_t *listed = hashmap_get(walk->listing, location);
        if (listed && strcmp(listed->storage_path, next) == 0) continue;

        /* The location is the one path in the sentence the user never typed, so
         * it is spelled the way the shell spells it — as the screen that reports
         * this pair already spells it (cmds/status.c's unused-path listing).
         * The opening is revert.c refuse_second_name's, deliberately: one profile
         * names one location once, and these are that rule read from its two
         * ends. */
        char shown[PATH_MAX];
        output_format_path(location, identity()->home, shown, sizeof(shown));

        return ERROR(
            ERR_INVALID_ARG,
            "Profile '%s' names '%s' as '%s'\n\n"
            "This command's directory claims would name it '%s', which it does "
            "not capture — a directory must be named before the paths beneath "
            "it.\n"
            "  dotta add %s --force %s   captures those bytes under that name\n"
            "  dotta remove %s %s   gives that name up instead",
            walk->profile, shown, kept, next,
            walk->profile, next, walk->profile, next
        );
    }

    return NULL;
}

/**
 * Say what a capture claimed — the claim decides the shape
 *
 * Three claim shapes exist, by the sheet's own existence rule (an item exists
 * iff it claims something): mode and ownership, mode alone, ownership alone — a
 * home/ symlink's entry, which a directory capture never produces since a directory
 * always claims its mode. The fourth combination has no line to print: such an
 * item does not exist, the capture returned NULL instead. Ownership is all-or-none
 * at the capture boundary (core/metadata's capture_ownership), so a present owner
 * implies a present group.
 *
 * The one voice for the file capture and the directory capture, which had drifted
 * apart; update's sibling line is not this one — it speaks at the receipt's indent
 * and carries the copy's encrypted suffix.
 *
 * @param out Output context (must not be NULL)
 * @param what The claim's noun: "metadata" or "directory metadata"
 * @param filesystem_path The captured path (must not be NULL)
 * @param item The capture's claim (must not be NULL)
 */
static void report_capture(
    output_t *out, const char *what, const char *filesystem_path,
    const metadata_item_t *item
) {
    if (item->mode != MODE_UNCLAIMED && item->owner) {
        output_info(
            out, OUTPUT_VERBOSE, "Captured %s: %s (mode: %04o, owner: %s:%s)",
            what, filesystem_path, item->mode, item->owner, item->group
        );
    } else if (item->mode != MODE_UNCLAIMED) {
        output_info(
            out, OUTPUT_VERBOSE, "Captured %s: %s (mode: %04o)",
            what, filesystem_path, item->mode
        );
    } else {
        output_info(
            out, OUTPUT_VERBOSE, "Captured %s: %s (owner: %s:%s)",
            what, filesystem_path, item->owner, item->group
        );
    }
}

/**
 * Add single file to the stage and capture metadata
 *
 * Handles file storage, encryption, and metadata capture in a single operation.
 * Uses stat data from content layer to eliminate race conditions.
 *
 * @param ctx Dispatch context (must not be NULL; reads ctx->run.keymgr for
 *            encryption — NULL when encryption is disabled — and ctx->config
 *            for the encryption policy)
 * @param stage The profile's stage (must not be NULL)
 * @param filesystem_path Source path on filesystem
 * @param storage_path Pre-computed storage path (e.g., "home/.bashrc")
 * @param opts Command options
 * @param metadata Metadata collection (captured entry will be added here)
 * @param out_stat The capture's stat triple — taken from the same stat as the
 *                 bytes staged, so the record can bind the committed blob to it
 *                 (must not be NULL; set on every success)
 * @return Error or NULL on success
 */
static error_t *add_file_to_stage(
    const dotta_ctx_t *ctx,
    stage_t *stage,
    const char *filesystem_path,
    const char *storage_path,
    const cmd_add_options_t *opts,
    metadata_t *metadata,
    stat_cache_t *out_stat
) {
    CHECK_NULL(ctx);
    CHECK_NULL(stage);
    CHECK_NULL(filesystem_path);
    CHECK_NULL(storage_path);
    CHECK_NULL(opts);
    CHECK_NULL(metadata);
    CHECK_NULL(out_stat);

    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;  /* NULL if encryption disabled */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    *out_stat = STAT_CACHE_UNSET;

    error_t *err = NULL;
    metadata_item_t *item = NULL;  /* Will be created from captured metadata */
    struct stat file_stat;         /* Captured from content layer */

    /* The entry the profile already holds at this path, if any: the stage was
     * seeded from the branch's tree, so an entry here is the committed one —
     * read here, before the capture's put overwrites it in place with the staged
     * one. A first-time add finds none. */
    const git_index_entry *prior = git_index_get_bypath(
        stage_index(stage), storage_path, 0
    );
    if (prior && !opts->force) {
        return ERROR(
            ERR_EXISTS, "File '%s' (as '%s') already exists in profile '%s'. "
            "Use --force to overwrite.", filesystem_path, storage_path,
            opts->profile
        );
    }

    /* Encryption policy priority-3 source: prior committed bytes.
     *
     * The prior entry's blob is the cheapest source of byte truth for priority-3
     * — classified by its own header, never by a claim. A first-time add has no
     * prior and the flag stays false; priorities 4/5 then decide. A blob that
     * cannot be read is an error, not "not encrypted": a sniff that defaulted
     * would flip the policy silently. Only consumed in the regular-file branch
     * below (symlinks carry no encryption state to maintain). */
    bool previously_encrypted = false;
    if (prior) {
        content_kind_t prior_kind = CONTENT_PLAINTEXT;
        err = content_classify(repo, &prior->id, &prior_kind, NULL);
        if (err) {
            return error_wrap(
                err, "Failed to classify the committed bytes of '%s'",
                storage_path
            );
        }
        previously_encrypted = (prior_kind != CONTENT_PLAINTEXT);
    }

    /* Capture onto the stage */
    if (fs_is_symlink(filesystem_path)) {
        /* Handle symlink: the entry is the link's target, as its bytes */
        char *target = NULL;
        err = fs_read_symlink(filesystem_path, &target);
        if (err) {
            return error_wrap(
                err, "Failed to read symlink '%s'",
                filesystem_path
            );
        }

        err = stage_put(
            stage, storage_path, target, strlen(target), GIT_FILEMODE_LINK
        );
        free(target);
        if (err) {
            return err;
        }

        /* Capture the link's claim from its own lstat (the link's uid/gid, not
         * the target's). The link was read and staged lines above, so a failed
         * look here is a mid-add race — refused, the way the regular arm's capture
         * fails on its equivalent. */
        struct stat link_stat;
        if (fs_lstat(filesystem_path, &link_stat) != 0) {
            return error_from_errno(
                errno, "Failed to stat symlink '%s'", filesystem_path
            );
        }
        err = metadata_capture_from_file(
            filesystem_path, storage_path, &link_stat, &item
        );
        if (err) {
            return error_wrap(
                err, "Failed to capture symlink metadata for '%s'",
                filesystem_path
            );
        }
        *out_stat = stat_cache_from_stat(&link_stat);

        /* The capture claims nothing (a link with no ownership to track): an
         * item standing at the key is the replaced state's — retire it. */
        if (!item) {
            metadata_remove_item(metadata, storage_path);
        }

        output_info(
            out, OUTPUT_VERBOSE, "Added symlink: %s -> %s",
            filesystem_path, storage_path
        );
    } else {
        /* Regular file. previously_encrypted was classified from the prior
         * committed blob above (force re-add) or stays false (first-time add);
         * priority-3 in the encryption policy reads byte truth either way. */
        bool should_encrypt = false;
        err = encryption_policy_should_encrypt(
            config,
            storage_path,
            opts->encrypt_mode,
            previously_encrypted,
            &should_encrypt
        );
        /* Returned as it is. The policy's refusals are the user's to read — they
         * name the path, the fact that stood and the way on — and a wrap saying
         * the policy could not be determined would say the opposite of what
         * happened. */
        if (err) {
            return err;
        }

        /* Capture onto the stage (read → encrypt → the entry) and take the stat.
         * SECURITY: the stat is the fstat of the fd the capture read — bytes
         * and triple one inode by construction. */
        err = content_stage_file(
            stage,
            filesystem_path,
            storage_path,
            opts->profile,
            keymgr,
            should_encrypt,
            &file_stat
        );
        if (err) {
            return err;
        }

        /* Capture metadata from file using stat data from content layer
         * SECURITY: Single stat() call eliminates race condition */
        err = metadata_capture_from_file(
            filesystem_path, storage_path, &file_stat, &item
        );
        if (err) {
            return error_wrap(
                err, "Failed to capture metadata for '%s'",
                filesystem_path
            );
        }
        *out_stat = stat_cache_from_stat(&file_stat);

        /* The capture's write-time invariant: the bytes it staged classify as
         * the decision says (a plaintext that would not is refused there), so
         * the claim is stamped from the decision and every reader of the bytes
         * agrees with it. */
        if (item) item->encrypted = should_encrypt;

        /* Verbose output */
        if (should_encrypt) {
            output_info(
                out, OUTPUT_VERBOSE, "Encrypted: %s -> %s",
                filesystem_path, storage_path
            );
        }
        output_info(
            out, OUTPUT_VERBOSE, "Added: %s -> %s",
            filesystem_path, storage_path
        );
    }

    /* Add metadata item to collection (NULL for home/ prefix symlinks) */
    if (item) {
        report_capture(out, "metadata", filesystem_path, item);

        err = metadata_add_item(metadata, &item);
        if (err) {
            metadata_item_free(item);
            return error_wrap(
                err, "Failed to add metadata item for '%s'",
                filesystem_path
            );
        }
    }

    return NULL;
}

/**
 * Commit the stage
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param stage The profile's stage, every capture on it (must not be NULL)
 * @param opts Command options
 * @param added_files The files the walk listed, as captured (must not be NULL)
 * @param out_committed Whether a commit was made: false when the stage holds
 *                      the branch's own tree, so a re-add of what the profile
 *                      already holds moves nothing (must not be NULL)
 * @return Error or NULL on success
 */
static error_t *create_commit(
    const dotta_ctx_t *ctx,
    stage_t *stage,
    const cmd_add_options_t *opts,
    const ptr_array_t *added_files,
    bool *out_committed
) {
    CHECK_NULL(ctx);
    CHECK_NULL(stage);
    CHECK_NULL(opts);
    CHECK_NULL(added_files);
    CHECK_NULL(out_committed);

    const config_t *config = ctx->config;

    /* Build commit message using storage paths — the walk's, classified once. */
    string_array_t *storage_paths = string_array_new(0);
    if (!storage_paths) {
        return ERROR(ERR_MEMORY, "Failed to allocate storage paths array");
    }

    error_t *err = NULL;
    for (size_t i = 0; i < added_files->count; i++) {
        const add_path_t *path = added_files->items[i];
        err = string_array_push(storage_paths, path->claim.storage_path);
        if (err) {
            string_array_free(storage_paths);
            return err;
        }
    }

    /* Build commit message context */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_ADD,
        .profile       = opts->profile,
        .files         = storage_paths->items,
        .file_count    = storage_paths->count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    char *message = build_commit_message(config, &msg_ctx);
    string_array_free(storage_paths);

    if (!message) {
        return ERROR(ERR_MEMORY, "Failed to build commit message");
    }

    /* Create commit */
    err = stage_commit(stage, message, out_committed);
    free(message);

    if (err) {
        return error_wrap(err, "Failed to create commit");
    }

    return NULL;
}

/**
 * Write the record after a successful add operation
 *
 * Called after Git commit succeeds, for a new profile and an existing one alike.
 * Anchors the files this add captured: they were captured FROM disk, so their
 * record is anchored to the just-committed blob with the stat the capture took,
 * and the next status hits the fast path; the directories it tracked are anchored
 * by the same rule — captured, so dotta's. The view is computed, so nothing
 * projects; one build over the enabled set says which of this add's own claims
 * won their locations.
 *
 * Algorithm:
 *   1. Scope. A new profile is enabled here with its deployment target — creating
 *      a profile via add enables it, in the same transaction as the record. An
 *      existing profile has rows in the view only if it is already enabled: not
 *      enabled skips the anchor pass (nothing to win) and the target UPSERT
 *      (enable's business), never the settle
 *   2. Build the mount table from the post-mutation row cache
 *   3. Build the view; anchor each captured claim's own row, found at the location
 *      the table gives its storage path; settle what the commit let go
 *   4. Commit transaction (state_save)
 *
 * CRITICAL ORDER: Step 1 must precede step 3. The target stored in step 1 is
 * what lets the mount table built in step 2 resolve custom/ storage paths for
 * the view. Transaction atomicity ensures: enable + record succeed together or
 * fail together (automatic rollback on error).
 *
 * A new branch's enabled_profiles row can pre-exist only as a leftover of a branch
 * deleted behind it. state_enable_profile is an UPSERT — the row keeps its
 * position, takes this add's target when it brings one and keeps the leftover's
 * otherwise — and whatever records the old branch left are orphans the next load
 * reads, since the new HEAD does not have them.
 *
 * Target Update (existing profile):
 *   When adding custom/ files to an already-enabled profile, the target must be
 *   stored in state BEFORE the view is built — the same target-before-build
 *   ordering as the new profile's enable. Written only when the run brought one;
 *   the pre-flight refused a differing value, so the UPSERT binds an unbound
 *   row or repeats an equal one (a NULL would clear nothing either way: the UPSERT
 *   keeps the row's target for one).
 *
 * Ownership:
 *   Captured rows get deployed_at = time(NULL) because ADD captures files and
 *   directories FROM the filesystem. They're already at their target locations,
 *   so deployed_at is set to indicate dotta put them there. A captured file whose
 *   record another profile's deployment had written is taken over — the write
 *   rewrites the record under this profile — and counted for the receipt: nothing
 *   later says so (apply acknowledges a reassignment the scope made, not one
 *   the user's own add made).
 *
 * Error Handling:
 *   - Profile not enabled, nothing let go → rollback transaction, return NULL
 *     (success, no update)
 *   - The view fails to build → rollback, return error
 *
 * Non-Fatal Integration:
 *   Caller should treat a record write failure as non-fatal warning. Git commit
 *   already succeeded; the next status reads the committed blob from Git and
 *   confirms the file on its slow path. A new profile that failed to enable is
 *   enabled by hand.
 *
 * Performance: one view build + O(N) point lookups, N = files added
 *
 * @param ctx Dispatch context (must not be NULL; reads the repository, the state
 *            and the command arena)
 * @param mounts The command's table: this machine's rows, with the run's own
 *               binding standing for this profile's (must not be NULL). It is
 *               built from the rows STEP 1 below leaves for the view — a row
 *               that exists holds this very target (the pre-flight took the row's
 *               spelling), one that does not is written here as this target,
 *               and a disabled profile has no anchor pass at all — so the location
 *               this resolves a claim to and the location its row stands at are
 *               one string, and the join is a lookup rather than a hope
 * @param profile The profile added to (must not be NULL)
 * @param target The binding the run brought, absolute, or NULL: written for a
 *               new profile and an enabled one (the UPSERT keeps a row's own
 *               for a NULL)
 * @param profile_created This add created the profile's branch: enable it here
 * @param added_files The files the walk listed, each with the capture's stat
 *                    (must not be NULL)
 * @param added_dirs The directories the walk passed through (must not be NULL)
 * @param retired The ancestor claims the ancestry pass dropped, by key (must
 *                not be NULL)
 * @param receipt What the phase did, zeroed first (must not be NULL)
 * @return Error or NULL on success (non-fatal - caller treats as warning)
 */
static error_t *update_manifest_after_add(
    const dotta_ctx_t *ctx,
    const mount_table_t *mounts,
    const char *profile,
    const char *target,
    bool profile_created,
    const ptr_array_t *added_files,
    const ptr_array_t *added_dirs,
    const string_array_t *retired,
    record_receipt_t *receipt
) {
    CHECK_NULL(ctx);
    CHECK_NULL(mounts);
    CHECK_NULL(profile);
    CHECK_NULL(added_files);
    CHECK_NULL(added_dirs);
    CHECK_NULL(retired);
    CHECK_NULL(receipt);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;   /* Borrowed from dispatcher (WRITE) */

    error_t *err = NULL;

    *receipt = (record_receipt_t){ 0 };

    /* STEP 1: Scope.
     *
     * CRITICAL ORDER: Must enable (or re-bind) BEFORE the view is built so target
     * is available in state for path resolution during the tree walk. The
     * deployment target is stored in the enabled_profiles table and read by the
     * mount table built below to resolve custom/ storage paths.
     *
     * Transaction Safety: If the record write below fails, the dispatcher's
     * state_free automatically rolls back this change. */
    bool enabled = true;
    if (profile_created) {
        err = state_enable_profile(state, profile, target);
        if (err) {
            return error_wrap(err, "Failed to enable profile in state");
        }
    } else if (!state_has_profile(state, profile)) {
        /* Only an enabled profile has rows in the view, so the anchor pass has
         * no subject and a given target stays unbound (enable's business, when
         * the user gets there). The settle is not gated with them: the commit
         * just dropped whatever `retired` names, whatever the enabled set says,
         * and a path the commit let go settles by its record, enabled set or
         * no. With nothing let go there is nothing to write at all — success,
         * and the dispatcher's state_free rolls back the untouched transaction. */
        if (retired->count == 0) {
            return NULL;
        }
        enabled = false;
    } else if (target) {
        err = state_enable_profile(state, profile, target);
        if (err) {
            return error_wrap(err, "Failed to update deployment target for profile");
        }
    }

    /* STEP 2: Build the view; anchor the rows this profile won; settle what the
     * commit let go.
     *
     * The builder reads the rows as STEP 1 left them — a new row, or a target
     * re-bound — so a path under the just-bound target is a custom/ row here. A
     * disabled profile contributes no rows, and that is the build the settle
     * wants: its guard asks what the view still claims without this profile. */
    manifest_t *manifest = NULL;
    err = manifest_build(repo, state, ctx->arena, &manifest);
    if (err) return err;

    hashmap_t *anchor_index = NULL;   /* Built with the anchor pass it serves */
    if (enabled) {
        /* Anchor only the rows this add's own claims won: the row standing at a
         * captured claim's location is anchored iff it IS that claim, both halves
         * (core/manifest.h's manifest_is_claim). It is another's whenever a
         * higher-precedence profile owns the location — and also when a second
         * claim of this very profile does, which a machine whose roots kept two
         * names apart can commit and a sync can bring here. Either way the row
         * is someone else's word and so is its record, and the capture's stat
         * would certify a blob these bytes are not (receipt->synced < added_files).
         * The two are told apart here, where the row is in hand, so the receipt
         * names the cause it checked rather than a difference: only a row of
         * another profile is an override. Write failures are non-fatal: disk is
         * the just-committed blob, and the next status's slow path confirms it.
         *
         * A row is found at the location this profile gives the storage path —
         * the view's own spelling, resolved through the table as the build resolved
         * it — never at the walk's path, which is the user's spelling (a physical
         * path, a shell with no $PWD) and joins the view by string only when
         * the two happen to agree. An unbound claim has no location here and no
         * row.
         *
         * The record as it stands first, indexed by path, so a takeover is known
         * before the write that rewrites it. */
        anchor_t *anchors = NULL;
        size_t anchor_count = 0;
        err = state_get_all_anchors(state, ctx->arena, &anchors, &anchor_count);
        if (err) {
            manifest_free(manifest);
            return error_wrap(err, "Failed to read anchors");
        }

        anchor_index = hashmap_borrow(anchor_count > 0 ? anchor_count : 16);
        if (!anchor_index) {
            manifest_free(manifest);
            return ERROR(ERR_MEMORY, "Failed to create anchors index");
        }
        for (size_t i = 0; i < anchor_count; i++) {
            err = hashmap_set(anchor_index, anchors[i].filesystem_path, &anchors[i]);
            if (err) {
                hashmap_free(anchor_index, NULL);
                manifest_free(manifest);
                return error_wrap(err, "Failed to index anchors");
            }
        }

        time_t now = time(NULL);
        for (size_t i = 0; i < added_files->count; i++) {
            const add_path_t *path = added_files->items[i];
            const char *at = NULL;

            /* The resolve is a round-trip over one string: a listing's location
             * is where its own claim resolves under this very table, which is
             * what the walk's key invariant says (cmds/add.h). It goes with the
             * receipt work that owns this function. */
            err = mount_resolve(
                mounts, profile, path->claim.storage_path, ctx->arena, &at
            );
            if (err) {
                hashmap_free(anchor_index, NULL);
                manifest_free(manifest);
                return error_wrap(
                    err, "Failed to derive filesystem path from storage path: %s",
                    path->claim.storage_path
                );
            }
            if (!at) continue;

            const manifest_row_t *row = manifest_lookup(manifest, at);
            if (!manifest_is_claim(row, profile, path->claim.storage_path)) {
                if (row) {
                    if (strcmp(row->profile, profile) != 0) receipt->overridden++;
                    else receipt->unkept++;
                }
                continue;
            }

            error_t *anchor_err = state_anchor(state, row, &path->stat, now, NULL);
            if (anchor_err) {
                error_free(anchor_err);
                continue;
            }
            receipt->synced++;

            const anchor_t *was = hashmap_get(anchor_index, row->filesystem_path);
            if (was && was->deployed_at > 0 && strcmp(was->profile, profile) != 0) {
                receipt->taken_over++;
            }
        }

        /* The directories this add tracked, by the same rule: captured from disk,
         * so dotta's to prune on scope exit — the ownership the gate asks for,
         * which nothing later grants a directory that was already there (apply
         * observes those; it anchors only the ones it makes). Cleanup's emptiness
         * rule guards their contents. No stat triple: a directory has no content
         * confirmation, as apply records them. */
        for (size_t i = 0; i < added_dirs->count; i++) {
            const add_path_t *path = added_dirs->items[i];
            const char *at = NULL;

            err = mount_resolve(
                mounts, profile, path->claim.storage_path, ctx->arena, &at
            );
            if (err) {
                hashmap_free(anchor_index, NULL);
                manifest_free(manifest);
                return error_wrap(
                    err, "Failed to derive filesystem path from storage path: %s",
                    path->claim.storage_path
                );
            }
            if (!at) continue;

            const manifest_row_t *row = manifest_lookup(manifest, at);
            if (!manifest_is_claim(row, profile, path->claim.storage_path)) continue;

            error_t *anchor_err = state_anchor(state, row, NULL, now, NULL);
            if (anchor_err) error_free(anchor_err);
        }
    }

    /* What the commit let go: an ancestor claim the derivation retired leaves
     * the view by this very commit, so its record settles here rather than
     * orphaning until an apply gets around to it — the record the commit stranded
     * is the commit's to settle. It refuses nothing while it stands: a directory
     * only a record remembers reaches no view row (the reach rule,
     * core/workspace.h), so the leaf this add just captured through the arrangement
     * is judged on its own occupant either way, and a retire that fails here
     * leaves a [released] [type] row under status's Issues until an apply releases
     * it. Enablement was not consulted on the way here: the derivation saw the
     * disk contradict the claim whatever the enabled set says, and the record
     * its drop strands is stale under a disabled profile exactly as under an
     * enabled one. A rung some other profile still claims keeps its row and its
     * record — the retire is this profile's word about its own claim, never about
     * the path — and an unbound claim names nothing on this machine to retire. */
    for (size_t i = 0; i < retired->count; i++) {
        const char *fs_path = NULL;

        err = mount_resolve(mounts, profile, retired->items[i], ctx->arena, &fs_path);
        if (err) {
            hashmap_free(anchor_index, NULL);
            manifest_free(manifest);
            return error_wrap(
                err, "Failed to derive filesystem path from storage path: %s",
                retired->items[i]
            );
        }
        if (!fs_path || manifest_lookup(manifest, fs_path)) continue;

        error_t *retire_err = state_retire_anchor(state, fs_path);
        if (retire_err) error_free(retire_err);
    }

    hashmap_free(anchor_index, NULL);
    manifest_free(manifest);

    /* STEP 3: Commit transaction. state is borrowed from the dispatcher: if
     * state_save succeeds the transaction is committed; otherwise the dispatcher's
     * state_free rolls it back. */
    err = state_save(state);
    if (err) {
        return error_wrap(err, "Failed to save record updates");
    }

    /* Success. A settle committed for a disabled profile is not the anchor pass
     * having run: the receipt still reads "profile not enabled". */
    receipt->updated = enabled;

    return NULL;
}

/**
 * Add command implementation
 */
error_t *cmd_add(const dotta_ctx_t *ctx, const cmd_add_options_t *opts) {
    CHECK_NULL(ctx);

    git_repository *repo = ctx->run.repo;
    const char *repo_path = ctx->run.repo_path;
    state_t *state = ctx->run.state;   /* Borrowed from dispatcher (WRITE) */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    error_t *err = validate_options(opts);
    if (err) return err;

    /* Initialize all resources to NULL for safe cleanup */
    ignore_rules_t *ignore_rules = NULL;
    const gitignore_ruleset_t *profile_rules = NULL;
    source_filter_t *source_filter = NULL;
    stage_t *stage = NULL;
    manifest_t *view = NULL;             /* The branch as the stage opened it: see below */
    add_walk_t walk = { .ctx = ctx };    /* Filled once the table and the rules are known */
    bool profile_exists = false;
    bool profile_created = false;
    bool committed = false;
    metadata_t *metadata = NULL;
    mount_table_t *mounts = NULL;         /* The command's table: see below */
    const char *target = NULL;            /* --target, absolute: what the row stores */
    const char *target_location = NULL;   /* ...where the table says it stands */

    /* The ancestry pass's other half: the keys it retired, read by the record
     * write once the commit that drops them has landed. */
    string_array_t ancestry_retired STRING_ARRAY_AUTO = { 0 };

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* The branch this add will write to: its stage is opened below when it is
     * there, an orphan's when it is not. Both answers are needed here, before
     * the command has any effect — a name Git's ref namespace cannot hold beside
     * the names already there is refused now, ahead of the pre-add hook and the
     * stage, because a refusal that has already run the user's hook is not a
     * refusal.
     *
     * A branch and any branch beneath it are exclusive, which is why a base profile
     * and its variants are (docs/profiles.md). libgit2 refuses at commit time
     * with a message about directories that names neither profile; this refuses
     * by name, and names both. */
    err = gitops_branch_exists(repo, opts->profile, &profile_exists);
    if (err) goto cleanup;

    if (!profile_exists) {
        char *blocker = NULL;
        err = gitops_branch_blocker(repo, opts->profile, &blocker);
        if (err) goto cleanup;
        if (blocker) {
            const char *base = strlen(blocker) < strlen(opts->profile)
                ? blocker : opts->profile;
            err = ERROR(
                ERR_INVALID_ARG, "Profile '%s' cannot exist beside profile '%s'\n\n"
                "Git stores each profile as a branch, and '%s' cannot be both "
                "a branch and a folder of branches.\n", opts->profile, blocker, base
            );
            free(blocker);
            goto cleanup;
        }
    }

    /* The target, when the run brought one: a filesystem-shaped argument —
     * absolute, tilde, or relative to the working directory — resolved to the
     * absolute path the row stores, then held to the target's rules. */
    if (opts->target) {
        char *absolute = NULL;
        err = path_input_normalize(opts->target, &absolute);
        if (err) goto cleanup;
        target = arena_strdup(ctx->arena, absolute);
        free(absolute);
        if (!target) {
            err = ERROR(ERR_MEMORY, "Failed to allocate the target");
            goto cleanup;
        }
        err = mount_validate_target(target);
        if (err) goto cleanup;

        /* Refuse a silent move, before the commit it would have shaped. A branch
         * has one custom/ namespace, so a profile holds one relocatable tree:
         * enable is the verb that moves it, in place, and a second tree is a
         * second profile. Both ways out are named — the first for the user who
         * moved the tree, the second for the one who has two. Binding a row that
         * has no target is fine, and so is naming the row's own directory, under
         * its spelling or another (mount_same_target): the row's is the binding
         * — the table below, the UPSERT after the commit and the record's join
         * through the view all spell it the row's way — so the flag takes the
         * row's spelling here, and the arguments re-root under it. */
        const char *existing = state_peek_profile_target(state, opts->profile);
        if (existing && !mount_same_target(existing, target)) {
            err = ERROR(
                ERR_INVALID_ARG,
                "Profile '%s' is bound at %s, and a profile has one target\n"
                "  dotta profile enable %s --target %s    moves it; "
                "the next apply relocates its paths\n"
                "  dotta add <profile> --target %s <path>    "
                "a second tree is a second profile",
                opts->profile, existing, opts->profile, opts->target, opts->target
            );
            goto cleanup;
        }
        if (existing) {
            target = arena_strdup(ctx->arena, existing);
            if (!target) {
                err = ERROR(ERR_MEMORY, "Failed to allocate the target");
                goto cleanup;
            }
        }
    }

    /* The topology this command reads: this machine's rows, with the binding
     * the run brought standing for this profile's — which is why add declares
     * no `mounts` need and the dispatcher builds none (include/runtime.h). One
     * table for the walk, the argument arm, the boundary above and the record's
     * join below. A table holding this binding alone would hide every other,
     * and mount_locate is asker-free by contract: with a second profile bound
     * through a link inside this target, it left `<target>/link/x` as written
     * where the post-commit view reads it through, and the ownership event went
     * nowhere.
     *
     * The flag's own target is the row's whenever a row exists (the pre-flight
     * above took the row's spelling), and where none does the binding is simply
     * added — so the rows this table is built from are the rows STEP 1 of the
     * record phase leaves for the view, and the two key alike. */
    const mount_t binding = { .profile = opts->profile, .target = target };
    err = manifest_mount_table(state, target ? &binding : NULL, ctx->arena, &mounts);
    if (err) goto cleanup;

    if (target) {
        /* Where the table says the target stands: the one spelling the boundary
         * compares against, taken once here — where the flag's value and the
         * row's have settled — and never once per argument. The table is the
         * producer, its entry for this binding holding the pair already; a binding
         * realpath cannot answer is known by its own settled spelling, which is
         * as far as the table says it reaches (infra/mount.h). */
        err = mount_locate(mounts, target, ctx->arena, &target_location);
        if (err) goto cleanup;
    }

    /* Build ignore rules once per command.
     *
     * Fatal on failure: if we cannot build the ignore rules, proceeding would
     * risk tracking files the user explicitly told us to ignore (via baseline,
     * profile, config, or CLI). Surface the error.
     *
     * The profile-specific ruleset (which layers the profile's own `.dottaignore`
     * on top of the common layers) is resolved below, after the branch exists —
     * for a brand-new profile the builder would otherwise try to load a
     * non-existent branch (a non-error, but no point walking that code path). */
    err = ignore_rules_create(
        repo, config,
        opts->exclude_patterns, opts->exclude_count,
        ctx->arena, &ignore_rules
    );
    if (err) {
        err = error_wrap(err, "Failed to build ignore rules");
        goto cleanup;
    }

    /* Source-tree .gitignore filter (opt-in via config).
     *
     * Built once per command and shared across the whole collection walk so the
     * discovered source-repo handle is reused for every file under the same source
     * tree. A non-fatal build failure leaves source_filter NULL, which
     * is_excluded() treats as "layer skipped". */
    if (config && config->respect_gitignore) {
        err = source_filter_create(&source_filter);
        if (err) {
            err = error_wrap(err, "Failed to build source .gitignore filter");
            goto cleanup;
        }
    }

    /* Build hook invocation */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_ADD,
        .profile    = opts->profile,
        .files      = opts->files,
        .file_count = opts->file_count,
        .dry_run    = false,
    };

    /* Execute pre-add hook */
    err = hook_fire_pre(config, out, repo_path, &hook_inv);
    if (err) goto cleanup;

    /* The profile's stage, as the pre-flight above resolved it: the branch's
     * tip and tree when it exists, the empty tree and a root commit-to-be when
     * it does not. A branch that appeared or vanished since the pre-flight is
     * refused by the open rather than silently taken the other way. */
    char refname[DOTTA_REFNAME_MAX];
    err = gitops_branch_refname(refname, sizeof(refname), opts->profile);
    if (err) goto cleanup;

    if (profile_exists) {
        err = stage_open(repo, refname, &stage);
    } else {
        err = stage_orphan(repo, refname, &stage);
        profile_created = true;   /* This add is what brought the branch */
    }

    if (err) {
        err = error_wrap(err, "Failed to open profile '%s'", opts->profile);
        goto cleanup;
    }

    /* Resolve the profile-specific ruleset. Safe for both paths: existing profile
     * → loads the profile's `.dottaignore`; new profile → branch doesn't exist
     * yet, builder treats that as "no profile layer" and the common layers still
     * apply. */
    err = ignore_rules_for_profile(ignore_rules, opts->profile, &profile_rules);
    if (err) {
        err = error_wrap(
            err, "Failed to load ignore rules for profile '%s'", opts->profile
        );
        goto cleanup;
    }

    /* The profile's sheet, from the tree the stage opened at: the branch's own
     * bytes, an empty sheet for a new profile (the loader's contract). Read before
     * the walk, which asks it what the branch already claims beneath a name
     * (admit_name); mutated as the captures go, and saved once. A sheet that
     * will not load refuses the add here rather than after the arguments have
     * been diagnosed — the branch's own state is the earlier question.
     */
    err = metadata_load_from_tree(repo, stage_tree(stage), opts->profile, &metadata);
    if (err) {
        err = error_wrap(err, "Failed to load existing metadata");
        goto cleanup;
    }

    /* The branch as this command found it, under this command's table: one
     * contribution, this profile's, from the tree the stage opened at. Built
     * after the sheet load so a sheet that will not load is still the earlier
     * refusal — the builder loads it again and would say the same thing later.
     * Every naming question below reads it, so does the kind question, and so
     * does the refusal the completed selection owes; freed once, at cleanup. */
    err = manifest_build_tree(
        repo, stage_tree(stage), opts->profile, mounts, ctx->arena, &view
    );
    if (err) goto cleanup;

    /* Collect every path to add, expanding directories. Each listing is named
     * once, by the claim standing at it; what the walk finds beneath one already
     * listed is named from that claim. */
    walk.mounts = mounts;
    walk.profile = opts->profile;
    walk.view = view;
    walk.rules = profile_rules;
    walk.source_filter = source_filter;
    walk.stage = stage;
    walk.sheet = metadata;
    walk.listing = hashmap_borrow(0);
    if (!walk.listing) {
        err = ERROR(ERR_MEMORY, "Failed to allocate the walk's listing");
        goto cleanup;
    }

    /* Process each input path. Two parsing heads — a storage shape and a filesystem
     * shape — and one ladder beneath them: what stands at the path, this command's
     * own listing, the name, the rules, the claim the profile holds at the
     * location, the branch's shape, and the listing itself. `typed` is the whole
     * of what the user's choice of shape means, and it discriminates at exactly
     * four places: the absent path's hint, the three sentences the dedup gate
     * owes, the choice of name, and the membership gate that is the one place a
     * second name for one location can be born. */
    for (size_t i = 0; i < opts->file_count; i++) {
        const char *file = opts->files[i];
        const char *location = NULL;
        const char *typed = NULL;   /* The name the user wrote, or NULL for a spelling */

        if (mount_spec_for_path(file)) {
            /* A storage shape, read by the one resolver that reads input shapes
             * — STORAGE by construction, since the same predicate dispatched
             * here. It validates the shape and sheds a trailing slash, so `add
             * p home/dir/` is the spelling every other consumer already accepts
             * (infra/path.h). */
            path_input_t in;
            err = path_input_resolve(mounts, file, ctx->arena, &in);
            if (err) goto cleanup;
            typed = in.storage_path;

            /* Where the claim stands, through the table: home/ and root/ resolve
             * for every profile, custom/ through this one's binding — the row's,
             * or the flag's. A custom/ path with no binding names nothing on
             * this machine, and the way to give it one is the flag. The table's
             * answer is absolute and the arena's already. */
            err = mount_resolve(mounts, opts->profile, typed, ctx->arena, &location);
            if (err) {
                err = error_wrap(err, "Failed to convert storage path '%s'", file);
                goto cleanup;
            }
            if (!location) {
                err = ERROR(
                    ERR_INVALID_ARG, "'%s' has no location for '%s' on this machine\n"
                    "  dotta add %s --target /path %s", file, opts->profile,
                    opts->profile, file
                );
                goto cleanup;
            }
        } else {
            /* Regular filesystem path — as add reads it: the target's when one
             * stands (spell_argument), the shell's when none does — then located,
             * so the walk begins at where the spelling stands and everything it
             * joins beneath is a location too. */
            char *absolute = NULL;
            err = spell_argument(
                mounts, file, target, target_location, ctx->arena, &absolute
            );
            if (err) {
                err = error_wrap(err, "Failed to resolve path '%s'", file);
                goto cleanup;
            }
            err = mount_locate(mounts, absolute, ctx->arena, &location);
            free(absolute);
            if (err) {
                err = error_wrap(err, "Failed to locate '%s'", file);
                goto cleanup;
            }
        }

        /* What stands at the path — the link itself for a symlink, a broken one
         * included, and the kind of every supported occupant with it. Absence
         * and a refusal are two answers: a storage path that resolves to nothing
         * is as likely a relative path whose first component happens to be a
         * label — `root/x` typed from `/` — so the message says where it looked
         * and how to say the other; a path the invoker cannot reach names its
         * reason, and the dispatch tail names the command that could. A special
         * file is refused by its noun here, before a name is asked for and long
         * before a capture would refuse it in the same breath as its siblings. */
        struct stat st;
        path_kind_t kind = PATH_KIND_FILE;
        switch (fs_lstat_occupant(location, &st)) {
            case FS_OCCUPANT_NONE:
                if (typed) {
                    err = ERROR(
                        ERR_NOT_FOUND, "Path not found: %s (storage path '%s')\n"
                        "For a relative path, write ./%s", location, file, file
                    );
                } else {
                    err = ERROR(ERR_NOT_FOUND, "Path not found: %s", location);
                }
                goto cleanup;

            case FS_OCCUPANT_UNKNOWN: {
                int saved_errno = errno;
                err = error_from_errno(
                    saved_errno, "Cannot access '%s'", location
                );
                goto cleanup;
            }

            case FS_OCCUPANT_OTHER:
                err = ERROR(
                    ERR_INVALID_ARG,
                    "'%s' is a %s, and a profile holds files, symlinks and "
                    "directories", file, fs_stat_noun(&st)
                );
                goto cleanup;

            case FS_OCCUPANT_DIRECTORY:
                kind = PATH_KIND_DIRECTORY;
                break;

            case FS_OCCUPANT_REGULAR:
            case FS_OCCUPANT_SYMLINK:
                break;
        }

        /* This command's own listing. A location already settled here says nothing
         * new — a second spelling of one argument, or an argument beneath a
         * directory already walked — and a spelling simply moves on. A typed
         * name is the one input that can disagree with what was settled, so it
         * is the only one the gate owes a sentence. */
        if (hashmap_has(walk.listing, location)) {
            if (!typed) continue;

            const manifest_claim_t *listed = hashmap_get(walk.listing, location);
            if (!listed) {
                /* Entered without claiming, which happens at a root of the profile
                 * alone — so mount_root answers, as it did when the entry was
                 * made. The walk beneath it has already composed its children
                 * under the root's label, and a claim admitted now would move
                 * their prefix. */
                char buf[MOUNT_NOUN_MAX];
                err = ERROR(
                    ERR_INVALID_ARG,
                    "'%s' names %s, which this command has already walked through\n\n"
                    "A directory must be named before the paths beneath it.",
                    file,
                    mount_root_describe(
                    mount_root(mounts, opts->profile, location), opts->profile,
                    buf, sizeof(buf)
                    )
                );
                goto cleanup;
            }
            if (strcmp(listed->storage_path, typed) != 0) {
                char shown[PATH_MAX];
                output_format_path(location, identity()->home, shown, sizeof(shown));
                err = ERROR(
                    ERR_INVALID_ARG,
                    "'%s' is named twice in this command: as '%s' and as '%s'",
                    shown, listed->storage_path, typed
                );
                goto cleanup;
            }
            continue;                       /* the same claim, twice */
        }

        /* Before this argument's own listing, so the verbose line below counts
         * the directory it names along with what lies beneath it. */
        size_t files_before = walk.files.count;
        size_t dirs_before = walk.directories.count;

        /* The name the capture lands under: the user's own where they typed one,
         * and otherwise what this profile calls the location — the claim standing
         * there, this command's own or the branch's, else the composition beneath
         * the nearest claim above it, else what the profile's own roots make of
         * it, which is NULL at a root. */
        const char *storage_path = typed;
        if (!storage_path) {
            err = manifest_name(
                view, opts->profile, location, walk.listing, ctx->arena,
                &storage_path
            );
            if (err) {
                err = error_wrap(err, "Failed to name '%s'", file);
                goto cleanup;
            }
        }

        if (!storage_path) {
            /* One of this profile's own roots ($HOME, "/", its target), which
             * has no name: a directory is walked through unlisted and its
             * descendants are listed, and anything else cannot be added at all
             * — $HOME itself when HOME is a symlink, or its target reached through
             * one. A typed name never arrives here, the user's own name being
             * the answer. */
            if (kind != PATH_KIND_DIRECTORY) {
                char buf[MOUNT_NOUN_MAX];
                const char *noun = mount_root_describe(
                    mount_root(mounts, opts->profile, location), opts->profile,
                    buf, sizeof(buf)
                );
                err = ERROR(
                    ERR_INVALID_ARG,
                    "'%s' is %s and cannot be added itself; name what is inside it",
                    file, noun
                );
                goto cleanup;
            }

            err = hashmap_set(walk.listing, location, NULL);
            if (err) goto cleanup;
        } else {
            /* A path named on the command line is subject to the rules like any
             * the walk finds, but a verdict against it is an error, not a silent
             * skip: the user asked for it by name, and the answer says which
             * rule stands in the way and how to get past it. */
            gitignore_match_t match;
            if (is_excluded(&walk, location, storage_path, kind, &match)) {
                if (match.decided) {
                    err = ERROR(
                        ERR_INVALID_ARG, "'%s' is ignored by %s: '%s'\n"
                        "Add it anyway with -e '!%s', or edit the rule with "
                        "'dotta ignore'",
                        file, ignore_origin_describe((ignore_origin_t) match.origin),
                        match.pattern, match.pattern
                    );
                } else {
                    err = ERROR(
                        ERR_INVALID_ARG,
                        "'%s' is ignored by its source tree's .gitignore\n"
                        "Set respect_gitignore = false in the config to add it",
                        file
                    );
                }
                goto cleanup;
            }

            /* What the profile already claims at the location, against what stands
             * there now. The row is the location's own authority on kind, a derived
             * one included — it says the profile holds a subtree beneath the
             * path, which a path that became a file cannot carry — and it is
             * the one reading that sees a claim with nothing beneath it for either
             * document to find, where the name's own admission below covers the
             * rest. The removal is name-shaped: it takes that claim and everything
             * beneath it, under every topology, where a filesystem-shaped one
             * addresses another key at a binder's own spelling. */
            const manifest_row_t *held = manifest_lookup_claim(
                view, opts->profile, location
            );
            if (held && path_type_kind(held->type) != kind) {
                char shown[PATH_MAX];
                output_format_path(location, identity()->home, shown, sizeof(shown));
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Profile '%s' holds '%s' as the %s '%s', and a %s stands "
                    "there now\n\n"
                    "  dotta remove %s %s   gives that claim up, and everything "
                    "beneath it",
                    opts->profile, shown,
                    held->type == PATH_TYPE_DIRECTORY ? "directory" : "file",
                    held->storage_path, fs_stat_noun(&st),
                    opts->profile, held->storage_path
                );
                goto cleanup;
            }

            /* The name, by the profile's own claims — the authority on names. A
             * typed name is the one input the namer did not produce, so it is
             * the one place a second name for one location can be born; a name
             * the profile already holds is a re-capture, gated by --force at
             * the pre-flight, and a derived claim names nothing and blocks nothing
             * (core/manifest.h manifest_is_derived). revert.c refuse_second_name
             * is the same condition for the same rule, with its own verb's
             * remedies. */
            if (typed && held && !manifest_is_derived(held) &&
                !manifest_holds_name(view, opts->profile, location, typed)) {
                char shown[PATH_MAX];
                output_format_path(location, identity()->home, shown, sizeof(shown));
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Profile '%s' names '%s' as '%s'\n\n"
                    "'%s' would be a second name for it, and a profile names a "
                    "location once.\n"
                    "  dotta add %s --force %s   re-captures it under the name "
                    "it has\n"
                    "  dotta remove %s %s   gives that name up first",
                    opts->profile, shown, held->storage_path, typed,
                    opts->profile, held->storage_path,
                    opts->profile, held->storage_path
                );
                goto cleanup;
            }

            /* What the branch can hold, before a byte is read. The verdict a
             * walked entry answers with a skip is an error here: the user asked
             * for this path by name, and working around a claim they did not
             * mention is not this command's to do. */
            err = admit_name(&walk, storage_path, kind);
            if (err) {
                err = error_wrap(err, "Cannot add '%s'", file);
                goto cleanup;
            }

            err = list_path(
                &walk, location, (manifest_claim_t){ storage_path, kind }
            );
            if (err) goto cleanup;
        }

        if (kind == PATH_KIND_DIRECTORY) {
            /* The directory that stands at the claim's key — one string for every
             * argument but one: a typed name at a binder's own spelling keys at
             * the link and enumerates the binding's directory, and locate is
             * the producer of both readings (infra/mount.h). Every other location
             * is its own answer here. */
            const char *directory = NULL;
            err = mount_locate(mounts, location, ctx->arena, &directory);
            if (err) {
                err = error_wrap(err, "Failed to locate '%s'", location);
                goto cleanup;
            }

            err = collect_tree(&walk, directory, 0);
            if (err) {
                err = error_wrap(err, "Failed to collect from '%s'", file);
                goto cleanup;
            }

            size_t files_found = walk.files.count - files_before;
            size_t dirs_found = walk.directories.count - dirs_before;
            output_info(
                out, OUTPUT_VERBOSE,
                "Collected %zu file%s and %zu director%s under %s",
                files_found, files_found == 1 ? "" : "s",
                dirs_found, dirs_found == 1 ? "y" : "ies", location
            );
        }
    }

    /* Check if we have anything to add (files or directories). A named path the
     * rules refused was an error above, so this is a mount root the walk found
     * nothing listable beneath — either because nothing is there, or because
     * every entry was excluded, unsupported, or a name the branch has no room
     * for. */
    if (walk.files.count == 0 && walk.directories.count == 0) {
        err = ERROR(ERR_INVALID_ARG, "No files or directories to add");
        goto cleanup;
    }

    /* The selection is complete, so the one question its parts cannot answer is
     * asked here: does this command abandon a name it moves? */
    err = refuse_moved_name(&walk);
    if (err) goto cleanup;

    /* What the branch already holds under a name this command chose. Asked over
     * the whole listing before a byte is read, so a refusal at the last file
     * does not leave the first four in the object database. Keyed by the name
     * and not by the location: at a location the profile names twice, a typed
     * re-capture of the loser must be gated by the name the user typed, not by
     * the row that happens to stand there. The capture keeps its own
     * git_index_get_bypath for the encryption policy's priority-3 read — two
     * questions, one lookup each. */
    if (!opts->force) {
        for (size_t i = 0; i < walk.files.count; i++) {
            const add_path_t *path = walk.files.items[i];
            if (!git_index_get_bypath(
                stage_index(stage), path->claim.storage_path, 0
                )) {
                continue;
            }
            err = ERROR(
                ERR_EXISTS, "File '%s' (as '%s') already exists in profile '%s'. "
                "Use --force to overwrite.", path->location,
                path->claim.storage_path, opts->profile
            );
            goto cleanup;
        }
    }

    /* Capture directory metadata for every directory this command listed.
     *
     * The walk lists every directory it walks into — including the argument itself
     * — so this loop captures the full tree, not just the named entry points. A
     * mount root ($HOME, "/", --target) is never listed: it has no storage name;
     * its descendants are captured normally.
     *
     * Required, where update's sibling loop warns and carries on: a directory
     * this command listed is the *name* its walk composed beneath, so a claim
     * that does not land leaves the files captured under a name nothing authors
     * — and the listing, which refuse_moved_name reads as a promise of the commit,
     * would be a wish (core/metadata.h metadata_capture_from_directory). Ahead
     * of the file captures for the same reason: a directory that cannot be claimed
     * is found before any source blob reaches the object database.
     */
    for (size_t i = 0; i < walk.directories.count; i++) {
        const add_path_t *path = walk.directories.items[i];
        const char *storage_path = path->claim.storage_path;

        /* Stat directory to capture mode (and ownership if root/custom). lstat
         * + S_ISDIR: the race guard update's capture arm has. The walk classified
         * with lstat, so anything else standing here changed since. */
        struct stat dir_stat;
        if (fs_lstat(path->location, &dir_stat) != 0) {
            err = error_from_errno(
                errno, "Failed to stat directory '%s'", path->location
            );
            goto cleanup;
        }
        if (!S_ISDIR(dir_stat.st_mode)) {
            err = ERROR(
                ERR_CONFLICT,
                "Cannot add '%s': it was walked as a directory and its type "
                "changed on disk", path->location
            );
            goto cleanup;
        }

        /* Capture directory metadata using stat data. The walk entered this
         * directory, so the claim is a tracked one: the profile manages the path
         * itself, scans it for new files and converges its attributes. */
        metadata_item_t *dir_item = NULL;
        err = metadata_capture_from_directory(storage_path, &dir_stat, true, &dir_item);
        if (err) {
            err = error_wrap(
                err, "Failed to capture directory '%s'", path->location
            );
            goto cleanup;
        }

        /* Verbose output before consuming the item */
        report_capture(out, "directory metadata", path->location, dir_item);

        /* Add directory to metadata */
        err = metadata_add_item(metadata, &dir_item);
        if (err) {
            metadata_item_free(dir_item);
            err = error_wrap(
                err, "Failed to track directory '%s'", path->location
            );
            goto cleanup;
        }
        output_info(
            out, OUTPUT_VERBOSE, "Tracked directory: %s -> %s", path->location,
            storage_path
        );
    }

    /* Single-pass: add files and capture metadata inline. Each capture's stat
     * triple is kept on the path, for the record: it is the stat of the bytes
     * committed, which a later lstat could not promise. */
    for (size_t i = 0; i < walk.files.count; i++) {
        add_path_t *path = walk.files.items[i];

        /* Add file to the stage and capture metadata
         * ARCHITECTURE: add_file_to_stage handles both operations atomically,
         * sharing stat() data between content and metadata layers to eliminate
         * TOCTOU */
        err = add_file_to_stage(
            ctx, stage, path->location, path->claim.storage_path, opts, metadata,
            &path->stat
        );
        if (err) {
            err = error_wrap(err, "Failed to add file '%s'", path->location);
            goto cleanup;
        }
    }

    /* The ancestry: the chain above every path this add captured, claimed as
     * the derivation it is — the attributes to give a rung if dotta ever has to
     * create it, and nothing more. It runs after the walk's own claims so that
     * a rung the walk entered is left exactly as the loop above wrote it, and
     * over both lists: a directory the walk listed has a chain of its own, and
     * an empty one has no file beneath it to carry that chain. Scope-blind by
     * design, as the pass that reads it is — an exclusion names a path, never
     * the way to it.
     */
    size_t ancestors_captured = 0;
    const ptr_array_t *chains[] = { &walk.files, &walk.directories };
    for (size_t b = 0; b < sizeof(chains) / sizeof(chains[0]); b++) {
        for (size_t i = 0; i < chains[b]->count; i++) {
            const add_path_t *path = chains[b]->items[i];

            err = metadata_capture_ancestors(
                metadata, mounts, opts->profile, path->claim.storage_path, ctx->arena,
                &ancestors_captured, &ancestry_retired
            );
            if (err) goto cleanup;
        }
    }
    if (ancestors_captured > 0) {
        output_info(
            out, OUTPUT_VERBOSE, "Captured %zu ancestor director%s",
            ancestors_captured, ancestors_captured == 1 ? "y" : "ies"
        );
    }

    /* The two documents this commit carries name one namespace, and this is where
     * they meet — once, with both of them final. The tree holds every blob; the
     * sheet holds the directories a tree cannot, since an empty one has no entry.
     * A blob and a directory cannot stand at one name, and nothing stands beneath
     * a blob. Every listing was admitted against the branch as this command found
     * it (admit_name); the index has moved since, by this command's own puts,
     * and the sheet has gained this command's own claims — so what the listing
     * could not see is exactly what this pass reads. A contradiction the branch
     * already carried is refused here too: nothing repairs it silently, and `dotta
     * remove` is the verb that gives a claim up.
     */
    size_t item_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);
    for (size_t i = 0; i < item_count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;

        err = stage_admit_subtree(stage, items[i]->key);
        if (err) {
            /* The stage names the storage path and the obstruction; the wrap
             * says whose claim it is and that a claim is the subject, so an add
             * of one path does not answer with a sentence about another the user
             * never typed. No remedy line: where both sides are this command's
             * own, nothing is committed for a `dotta remove` to take. */
            err = error_wrap(
                err, "Profile '%s' claims a directory its tree cannot hold",
                opts->profile
            );
            goto cleanup;
        }
    }

    /* A new profile's .dottaignore: the template, on the stage beside the sheet
     * — the two blobs this commit carries that no capture wrote. Here rather
     * than at the orphan's open, where the add has decided nothing yet: stage_put
     * writes the blob to the object database at once, so a refusal between the
     * two — a path that is not there, an argument the rules exclude, an unreadable
     * file — would leave it there for a profile that was never created. */
    if (!profile_exists) {
        const char *template = ignore_profile_template();
        err = stage_put(
            stage, ".dottaignore", template, strlen(template), GIT_FILEMODE_BLOB
        );
        if (err) {
            err = error_wrap(
                err, "Failed to initialize .dottaignore for profile '%s'",
                opts->profile
            );
            goto cleanup;
        }
        output_info(
            out, OUTPUT_VERBOSE, "Created .dottaignore for profile '%s'",
            opts->profile
        );
    }

    /* The sheet onto the stage, beside the captures */
    err = metadata_save_to_stage(stage, metadata);
    if (err) {
        err = error_wrap(err, "Failed to save metadata");
        goto cleanup;
    }

    /* Verbose summary. Every count from here on is a list's own: each capture
     * loop above is total over its list, so a run that reaches this line captured
     * everything it listed and no accumulator says it twice. */
    if (walk.directories.count > 0) {
        output_info(
            out, OUTPUT_VERBOSE,
            "Tracked %zu director%s for change detection",
            walk.directories.count, walk.directories.count == 1 ? "y" : "ies"
        );
    }

    /* Create commit. A stage that holds the branch's own tree — every capture
     * as the profile already had it, a --force re-add of identical bytes — commits
     * nothing, and the summary says so. */
    err = create_commit(ctx, stage, opts, &walk.files, &committed);
    if (err) goto cleanup;

    /* Write the record - auto-enable new profiles, anchor for enabled ones
     *
     * The files were captured from disk, so their record is anchored to the
     * committed blob now rather than left for a later status to confirm — an
     * ownership event whether or not Git moved, since the capture's stat is fresh
     * either way. The view itself is computed at every load and needs no update.
     *
     * For NEW profiles: Auto-enable provides intuitive UX (creating via 'add'
     * enables it). UX Decision: Creating a profile via 'add' should enable it
     * automatically. This matches user expectations: "I just added a file, it
     * should be active." For EXISTING profiles: Standard behavior (anchor only
     * if already enabled).
     *
     * Both end in the same loop: one view build says which rows this profile
     * won, and add's contribution is the anchor — the files were just captured
     * from disk, so the anchor is stamped from that capture rather than left
     * for a later status to fill in.
     *
     * Non-fatal: If the record write fails, Git commit still succeeded. A new
     * profile that failed to enable is enabled by hand; the next status confirms
     * the committed files on its slow path.
     */
    record_receipt_t record = { 0 };

    error_t *manifest_err = update_manifest_after_add(
        ctx, mounts, opts->profile, target, profile_created,
        &walk.files, &walk.directories, &ancestry_retired, &record
    );
    if (manifest_err) {
        if (profile_created) {
            /* Non-fatal: Git commit succeeded, user can manually enable later */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to auto-enable profile: %s",
                error_message(manifest_err)
            );
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile enable %s' to enable manually",
                opts->profile
            );
        } else {
            /* Non-fatal: Git commit succeeded */
            output_warning(
                out, OUTPUT_NORMAL, "Failed to update the record: %s",
                error_message(manifest_err)
            );
            output_info(
                out, OUTPUT_NORMAL, "Paths committed to Git successfully"
            );
        }
        error_free(manifest_err);
        record = (record_receipt_t){ 0 };
    }

    /* Execute post-add hook */
    hook_fire_post(config, out, repo_path, &hook_inv);

    /* Show summary on success. The empty selection was refused above and both
     * capture loops are total over their lists, so there is always something to
     * report here. */

    /* Primary success message */
    if (!committed && walk.files.count > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Nothing changed in profile '%s' (%zu file%s already as captured)",
            opts->profile, walk.files.count, walk.files.count == 1 ? "" : "s"
        );
    } else if (!committed) {
        output_info(
            out, OUTPUT_NORMAL,
            "Nothing changed in profile '%s' (%zu director%s already as tracked)",
            opts->profile, walk.directories.count,
            walk.directories.count == 1 ? "y" : "ies"
        );
    } else if (walk.files.count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Added %zu file%s to profile '%s'",
            walk.files.count, walk.files.count == 1 ? "" : "s",
            opts->profile
        );
    } else {
        /* Directory-only add */
        output_success(
            out, OUTPUT_NORMAL, "Tracking %zu director%s in profile '%s'",
            walk.directories.count, walk.directories.count == 1 ? "y" : "ies",
            opts->profile
        );
    }

    if (profile_created) {
        output_success(
            out, OUTPUT_NORMAL, "Profile '%s' created and enabled", opts->profile
        );
    }

    /* Show directory tracking info only when files were also added — and only
     * when the commit landed: under "Nothing changed" the directories were already
     * tracked as claimed. */
    if (committed && walk.files.count > 0 && walk.directories.count > 0) {
        output_info(
            out, OUTPUT_NORMAL, "Tracking %zu director%s for change detection",
            walk.directories.count, walk.directories.count == 1 ? "y" : "ies"
        );
    }

    output_newline(out, OUTPUT_NORMAL);

    /* Record status feedback */
    if (record.updated) {
        if (walk.files.count > 0) {
            /* Files were added — the sync results, and what the rows did with
             * each capture: a location this profile's claim did not win got no
             * anchor, and the records another profile's deployment had written
             * were taken over. */
            if (record.synced == walk.files.count) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Record updated (%zu file%s marked as deployed)",
                    record.synced, record.synced == 1 ? "" : "s"
                );
            } else {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Record updated (%zu/%zu file%s marked as deployed)",
                    record.synced, walk.files.count,
                    walk.files.count == 1 ? "" : "s"
                );

                /* Each cause named by the count that checked it, never by the
                 * shortfall (record_receipt_t): a row of another profile is an
                 * override, a row of this one under another of its own names is
                 * an unused path, and the health channel carries that one's repair
                 * on the status screen. */
                if (record.overridden > 0) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Note: %zu file%s overridden by higher-precedence profiles",
                        record.overridden, record.overridden == 1 ? "" : "s"
                    );
                }
                if (record.unkept > 0) {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "Note: %zu file%s captured under an unused path; "
                        "'dotta status -v' names %s",
                        record.unkept, record.unkept == 1 ? "" : "s",
                        record.unkept == 1 ? "it" : "them"
                    );
                }
            }
            if (record.taken_over > 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Note: %zu file%s taken over from other profiles",
                    record.taken_over, record.taken_over == 1 ? "" : "s"
                );
            }
            if (!profile_created) {
                /* Existing enabled profile */
                output_hint(
                    out, OUTPUT_NORMAL,
                    "Paths captured from filesystem (already deployed)"
                );
            }
        } else {
            /* Directory-only add */
            output_info(
                out, OUTPUT_NORMAL, "Record updated (%zu director%s synced)",
                walk.directories.count, walk.directories.count == 1 ? "y" : "ies"
            );
        }
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta status' to verify");
    } else {
        /* Existing disabled profile: the tree is shaped, no row holds a binding,
         * and the hint names what enable will accept — the target as the user
         * typed it, when the run brought one. */
        output_info(
            out, OUTPUT_NORMAL, "Profile not enabled - nothing marked as deployed"
        );
        if (opts->target) {
            output_hint(
                out, OUTPUT_NORMAL,
                "Run 'dotta profile enable %s --target %s' to deploy it here",
                opts->profile, opts->target
            );
        } else {
            output_hint(
                out, OUTPUT_NORMAL,
                "Run 'dotta profile enable %s' to activate and deploy",
                opts->profile
            );
        }
    }

cleanup:
    /* Free resources in reverse order of allocation. The listing's keys and values
     * are the arena's, and so is every row the view points at: only the heap
     * indexes are freed here. */
    if (metadata) metadata_free(metadata);
    ptr_array_deinit(&walk.directories);
    ptr_array_deinit(&walk.files);
    hashmap_free(walk.listing, NULL);
    manifest_free(view);
    stage_free(stage);
    source_filter_free(source_filter);
    ignore_rules_free(ignore_rules);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `profile` and `files[]`.
 *
 * Two legacy-compatible cases:
 *   1. -p/--profile was given: every positional is a file path.
 *   2. -p not given: first positional is the profile, rest are files.
 *
 * The count check lives here, after the routing, so the error message can reference
 * the effective invariant rather than a raw count.
 */
static error_t *add_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_add_options_t *o = opts_v;

    if (o->profile != NULL) {
        o->files = o->positional_args;
        o->file_count = o->positional_count;
    } else {
        if (o->positional_count == 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "profile name is required (as first positional or via -p)"
            );
        }
        o->profile = o->positional_args[0];
        o->files = o->positional_args + 1;
        o->file_count = o->positional_count - 1;
    }

    if (o->file_count == 0) {
        return ERROR(
            ERR_INVALID_ARG, "at least one path is required"
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor, read off the buckets add_post_parse routes: a
 * local profile in the profile slot — the first positional, unless -p took it —
 * then filesystem paths, listed under --target when one re-roots them. A new
 * profile's name is typed, not offered.
 */
static args_want_t add_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_add_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_add_options_t, profile)) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (ARGS_VALUE_IS(at, cmd_add_options_t, target)) {
        return ARGS_WANT_DIRS;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* -m, -e: free text */
    }

    if (o->profile == NULL && o->positional_count == 0) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    return completion_paths_under(out, o->target, at->current)
        ? ARGS_WANT_NONE : ARGS_WANT_FILES;
}

static error_t *add_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    error_t *err = cmd_add(ctx, (const cmd_add_options_t *) opts_v);

    /* A refusal the invoker met reading a source — the walk's listing and lstat,
     * the open behind the capture (infra/content), the existence check — ends
     * the add before anything durable is written: the stage is in memory and
     * the commit is after the walk. The code is enough to say so without matching
     * prose: ERR_PERMISSION is a refusal an identity met and never an answer
     * dotta looked up (base/error.h), everything add reads is a source, and a
     * read the kernel refuses is one a run that holds root reads through
     * (sys/filesystem's second try) — EROFS and an immutable flag refuse writes,
     * never reads, and code ERR_FS besides. So the one thing left to say is
     * sudo. */
    if (err && err->code == ERR_PERMISSION && !identity()->privileged) {
        err = error_wrap(err, "Only root can read it; re-run under sudo");
    }

    return err;
}

static const args_opt_t add_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",                 "<name>",
        cmd_add_options_t,           profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_STRING(
        "target",                    "<path>",
        cmd_add_options_t,           target,
        "Bind the profile's custom/ tree at this directory"
    ),
    ARGS_STRING(
        "m message",                 "<msg>",
        cmd_add_options_t,           message,
        "Commit message"
    ),
    ARGS_APPEND(
        "e exclude",                 "<pattern>",
        cmd_add_options_t,           exclude_patterns, exclude_count,
        "Skip paths matching a .dottaignore-style pattern (repeatable)"
    ),
    ARGS_FLAG(
        "f force",
        cmd_add_options_t,           force,
        "Overwrite existing entries in the profile"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_add_options_t,           verbose,
        "Verbose output"
    ),
    ARGS_FLAG_SET(
        "encrypt",
        cmd_add_options_t,           encrypt_mode,
        ENCRYPTION_REQUEST_ENCRYPT,
        "Force encryption for the given files"
    ),
    ARGS_FLAG_SET(
        "no-encrypt",
        cmd_add_options_t,           encrypt_mode,
        ENCRYPTION_REQUEST_PLAINTEXT,
        "Bypass auto-encryption patterns"
    ),
    /* <profile> <file|dir>... — order-dependent, first is profile. Mirrors clone's
     * raw-bucket-plus-post_parse approach. */
    ARGS_POSITIONAL_RAW(
        cmd_add_options_t,           positional_args,  positional_count,
        0,                           0
    ),
    ARGS_END,
};

const args_command_t spec_add = {
    .name        = "add",
    .summary     = "Add files or directories to a profile",
    .usage       =
        "%s add [options] <profile> <file|dir>...\n"
        "   or: %s add [options] --profile <name> <file|dir>...",
    .description =
        "Import files or directories into a profile branch. Each path is\n"
        "stored under a prefix for where it lives: home/ under your home\n"
        "directory, root/ anywhere else, custom/ under the profile's target.\n"
        "\n"
        "A path the profile already has keeps the name it has, and a new path\n"
        "inside a directory the profile tracks is stored under that directory.\n"
        "So names stay put as targets come and go.\n"
        "\n"
        "You can write the prefix yourself (home/..., root/..., custom/...).\n"
        "Under --target, root/etc/foo still means /etc/foo. A second name for\n"
        "a path the profile already has is refused.\n"
        "\n"
        "--target <dir> binds the profile's custom/ tree at that directory.\n"
        "A profile has one target; 'dotta profile enable --target' moves it.\n"
        "Filesystem paths are then read as the jail reads them: etc/foo and\n"
        "/etc/foo both mean <target>/etc/foo. A path spelled from here (./x,\n"
        "../x) is read where you stand.\n"
        "\n"
        "Modes are captured for every file and directory; ownership only\n"
        "under root/ and custom/.\n",
    .notes       =
        "Exclude Patterns:\n"
        "  Glob syntax with *, ?, [abc]. Flag is repeatable.\n"
        "    --exclude '*.log'                    # Skip .log files\n"
        "    --exclude '.git/*'                   # Skip .git directory\n"
        "    --exclude '*.log' --exclude '*.tmp'  # Multiple patterns\n",
    .examples    =
        "  %s add global ~/.bashrc                   # Basic add\n"
        "  %s add darwin ~/.config/nvim              # Directory\n"
        "  %s add global ~/.ssh/config -e '*.pub'    # With exclude\n"
        "  %s add global ~/.ssh/id_rsa --encrypt     # Force encryption\n"
        "  %s add web /mnt/jails/web/nginx.conf --target /mnt/jails/web\n"
        "  cd /mnt/jails/web && %s add web --target . etc/nginx.conf\n",
    .epilogue    =
        "See also:\n"
        "  %s key set                 # Set encryption passphrase\n"
        "  %s apply                   # Deploy the new entries\n",
    .opts_size   = sizeof(cmd_add_options_t),
    .opts        = add_opts,
    .post_parse  = add_post_parse,
    .complete    = add_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_WRITE,
        .crypto  = DOTTA_CRYPTO_OBTAIN,
    },
    .dispatch    = add_dispatch,
};
