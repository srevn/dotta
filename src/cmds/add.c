/**
 * add.c - Add files to profiles
 */

#include "cmds/add.h"

#include <config.h>
#include <errno.h>
#include <git2.h>
#include <limits.h>
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
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/stage.h"
#include "sys/identity.h"
#include "utils/commit.h"
#include "utils/hooks.h"

/**
 * One path this command listed, under the claim it gives it
 *
 * `filesystem_path` is where the claim stands, which is the view's own key for
 * it (mount_resolve's answer): the record joins by it with no round trip, and
 * it is the path the bytes are read at.
 *
 * `claim` is the pair the namer reads (core/manifest.h manifest_claim_t): the
 * name the capture commits under, and the kind that says whether anything can
 * be named beneath it. The listing indexes it by that key, so every path beneath
 * one already listed is named from it, and no name is carried down the walk.
 *
 * `occupant` is what the listing's lstat found there, and it chooses the capture:
 * a link's (content_capture_link) or a regular file's (content_capture_file),
 * each refusing the other's occupant, so a path is captured as the kind it was
 * listed as or not at all. The claim's kind is derived from it where the path
 * is listed (add_list), so the two cannot disagree.
 *
 * `should_encrypt` is the decision pass's verdict (cmd_add), reached with the
 * name before any capture runs — false but for a regular file, since a link's
 * entry is its target and the policy is never asked about one.
 *
 * `record` is what the capture committed, as the record keeps it: the path, the
 * name and the node the listing found — which the capture held to, refusing another
 * — the blob the stage wrote, the triple its bytes were read with (the fstat
 * beside a file's, the lstat before a link's target; none for a directory, which
 * confirms no content), and the claim the sheet took. Set by the capture, empty
 * until it lands, and written by the record phase wherever the claim still stands
 * (add_write_record) — every column but the stamp the capture's, so the record
 * says what dotta put there, never what a later tip of the branch says should be.
 */
typedef struct {
    const char *filesystem_path;  /* Where the claim stands (arena) */
    manifest_claim_t claim;       /* The name and kind it was listed under (arena) */
    fs_occupant_t occupant;       /* What the listing found there: chooses the capture */
    bool should_encrypt;          /* The decision pass's verdict; false but for a regular file */
    state_record_t record;        /* What the capture committed; empty until it lands */
} path_t;

/**
 * The walk: what every frame reads, and the two lists it fills
 *
 * `listing` is this command's own claims, which is exactly the layer
 * manifest_name reads as `pending`: filesystem path -> &item->claim, one entry per
 * path this command settled and every entry a claim (add_list). So overlapping
 * CLI arguments (~/.config and ~/.config/fish) list each path once — a directory
 * already walked is skipped with its subtree, a file already listed is not listed
 * again — and every path beneath one already listed is named from its claim,
 * which is why no name is carried down the walk. The key is the path, so two
 * spellings of one argument — `~/x` beside its absolute, `./x` beside `~/x` from
 * inside HOME — are one key; a link is a component, so a path through one and
 * the path around it are two, as two claims through and around it are two claims
 * (infra/mount.h). Keys and values borrow the arena the items live in.
 *
 * `view` is the branch as this command opened it: this profile's contribution
 * alone, from the tree the stage opened at, under this command's table. Every
 * name comes from it (core/manifest.h manifest_name, over `listing`), so does
 * the claim standing at a path (manifest_lookup_claim) — which rules reach the
 * path (add_verdict) and what kind it must be — and so does the one refusal the
 * completed selection owes (add_refuse_moves).
 *
 * `admission` and `sheet` are the two documents one commit carries, and the walk
 * asks both whether the commit has room for a name before a byte is read. The
 * tree holds every blob (sys/stage.h, the admission: the branch's entries and
 * every blob this command listed before), and the sheet holds the directories a
 * tree cannot — an empty one has no entry, so a claim the index cannot see is
 * the sheet's to answer for (core/metadata.h metadata_directory_beneath). The
 * admission grows with every blob listed; the sheet is the branch's and holds
 * no directory this command lists, so those are read once more with the selection
 * complete (cmd_add).
 */
typedef struct {
    const dotta_ctx_t *ctx;              /* The arena the paths live in, and the output */
    const char *profile;                 /* The asker: whose claims name what is found */
    const manifest_t *view;              /* The branch as this command opened it */
    const gitignore_ruleset_t *rules;    /* The profile's .dottaignore layers */
    const gitignore_ruleset_t *excludes; /* The -e layer alone, what a claim meets; NULL: none */
    source_filter_t *source;             /* The source layer, the builder's; NULL: turned off */
    stage_admission_t *admission;        /* The branch's tree, and every blob listed since */
    const metadata_t *sheet;             /* The branch's claims, asked with it */
    hashmap_t *listing;                  /* filesystem path -> &item->claim (borrowed both) */
    ptr_array_t files;                   /* path_t *: every non-directory listed */
    ptr_array_t directories;             /* path_t *: every directory walked into */
} walk_t;

/**
 * What the record phase did, for the receipt
 *
 * The phase's fate is its error return and is not restated here: a field for it
 * would be a second producer of one fact. The caller renders both together
 * (cmd_add's tail), and every count below speaks for a phase that returned NULL
 * — a statement is not durable until state_save commits the transaction the
 * dispatcher opened.
 *
 * Nor is whether a row holds this profile, which the error cannot carry either
 * — a row can hold it through a failure (a branch recreated over a leftover row)
 * and fail to hold it through a success. The handle's rows are the table as the
 * phase settled it — STEP 1's where the save landed, the ones the phase began
 * with where it rolled back (state_rollback) — so the tail asks the handle.
 *
 * `anchored` is both kinds. The record's unit is the path — one row per managed
 * path, a directory's differing only in the columns a directory has no content
 * for — so the ownership event a capture earns is one event, and the kinds are
 * named where they were captured, above this line.
 *
 * The four counts partition the capture exactly: a claim whose own row took the
 * event, one a higher-precedence profile's row holds, one another name of this
 * profile holds — a second name of one profile being a thing a branch can hold
 * and a sync can bring here (core/manifest.h manifest_unkept, whose screen word
 * is "unused path"), whose repair is the health channel's on the same screen,
 * not this receipt's — and one whose name the profile no longer holds at the
 * path at all. Nothing falls through, which is what makes the sum total and each
 * cause checked where the row that says it is in hand rather than read off a
 * difference.
 *
 * `unkept` is one thing only. This command cannot author a second name, and a
 * capture at a contested path lands on the name the next settle will keep —
 * add_refuse_moves is the last word on that — so a non-zero count is a typed
 * re-capture of a loser, deliberately made, which is exactly what "captured under
 * an unused path" says.
 *
 * `gone` is Git's, never this command's: the store's lock is not Git's, so another
 * writer's commit can land between this add's and the view its record phase builds,
 * and take the name away. The claim no longer stands, so nothing is written for it.
 */
typedef struct {
    size_t anchored;       /* Captures whose own row took the ownership event */
    size_t taken_over;     /* Of the anchored, records taken from another profile */
    size_t overridden;     /* Captures a higher-precedence profile's row holds */
    size_t unkept;         /* Captures another name of this profile holds */
    size_t gone;           /* Captures whose name the profile no longer holds at the path */
} receipt_t;

/**
 * Is this argument the target, or beneath it?
 *
 * Asked one folded prefix at a time — "/", "/a", "/a/b", … — until a prefix is
 * the target's spelling. The last prefix asked is the whole argument, so the
 * target is inside itself and `add web --target ~/jail ~/jail` is the jail, walked.
 * A string's test, because a key is a string of the rows' own: the target is
 * the row's spelling, and the argument keys under it exactly when a prefix of
 * it is that spelling (infra/mount.h).
 *
 * The prefix is folded and the tail is not: the decision is about where the
 * argument was *spelled from*, and folding the tail first destroys it —
 * `<target>/../secret` folds to a path outside the target, would be re-rooted
 * under it, and would name a different file that may well exist. Past the boundary
 * the tail is read as typed: a link inside the jail that reaches outside is typed
 * inside and named for where it lands.
 *
 * Every prefix is folded before it is asked, because the target is folded — its
 * binder read it through its door (infra/path.h path_input_target), and a row
 * holds no other shape (core/state.c), so `bound` is folded too — and `/a/..`
 * is a spelling of nowhere. The boundary is not always found before the first
 * `..`, and does not need to be: `/a/../<target>/x` meets one first, and the
 * fold is per prefix, not per argument. The root the walk starts from is asked
 * like every other prefix, which is what makes a target at "/" a prefix of every
 * absolute argument; a `.` leaves the prefix as it was and a `..` returns it to
 * one the walk already stood on, so neither can be the first answer.
 *
 * `input` is absolute: the caller's grammar decides who is asked at all, and a
 * bare relative path is the jail's without a question (add_spell). The scratch
 * is sized for one regardless — folding never grows a path — so the gate is a
 * rule about meaning, never about memory. Asked on the bytes as typed, before
 * the compose — unfolded, so a `..` beneath the target is inside here and walks
 * out at the fold, where the escape rule reads it (add_spell) — and once more
 * where a re-rooted argument is not found, since the sentence owed there turns
 * on the answer (cmd_add). The scratch is the arena's and abandoned, the module's
 * idiom, so no path here has a free to get wrong.
 *
 * @param input      The argument as typed, absolute (must not be NULL)
 * @param target     The target as the row spells it (must not be NULL)
 * @param arena      Arena for the scratch
 * @return True iff a prefix of `input` is the target
 */
static bool add_inside(const char *input, const char *target, arena_t *arena) {
    /* The folded prefix, grown one component at a time, with "." dropped and
     * ".." popping — the fold str_path_fold performs over a whole argument, applied
     * per prefix so the prefixes exist to be asked about. Folding never grows a
     * path, so the argument's own length plus a leading slash and a terminator
     * bounds it, absolute or not. */
    char *folded = arena_alloc(arena, strlen(input) + 2);
    folded[0] = '/';
    folded[1] = '\0';
    size_t len = 1;

    /* Grown until it is the target, or the argument runs out: the loop's own
     * condition is the question, asked of every prefix the walk stands on, the
     * root it starts from first. */
    const char *cursor = input;
    while (strcmp(folded, target) != 0) {
        while (*cursor == '/') cursor++;
        if (!*cursor) return false;

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
    }

    return true;   /* The tail is unread: past here it is Git's */
}

/**
 * The argument as add reads it: absolute, and the target's when one stands
 *
 * `--target <dir>` makes that directory a virtual root — an argument is read as
 * if the user stood inside it, the way a chroot reads a path — which is how a
 * jail, a container overlay, a fakeroot tree or a staging area is populated from
 * outside. Two spellings are the shell's and are never re-rooted: a tilde path
 * (`~/x` is HOME's, its own namespace, as a shell resolves '~' before any cd
 * context applies — even when the jail lies beneath HOME) and a path spelled
 * from here (`./x`, `../x`, a dotfile's `.x` — the file in front of the user,
 * wherever they stand, the way the resolver reads a leading '.'). A bare relative
 * path is the jail's.
 *
 *   cd anywhere;     ~/file                  -> $HOME/file        (HOME's)
 *                    ~/x     (jail under ~)  -> $HOME/x           (HOME's still)
 *                    etc/foo                 -> <target>/etc/foo  (the jail's)
 *                    /etc/foo                -> <target>/etc/foo  (re-rooted)
 *                    <target>/etc/foo        -> as typed          (inside)
 *   cd <target>/etc; ./x                     -> <target>/etc/x    (from here)
 *                    ../x                    -> <target>/x        (from here,
 *                                                                  still inside)
 *   cd ~;            ./x                     -> ERROR             (from here,
 *                                                                  outside)
 *                    <target>/../etc/secret  -> ERROR             (walked out)
 *                    ""                      -> ERROR             (no path in any
 *                                                                  grammar)
 *   --target /;      /etc/foo, etc/foo       -> /etc/foo          (the root
 *                                                                  encloses all)
 *
 * The refusal is lexical, on the spelling: what a path reaches through a link
 * is not this rule's business — a link inside the target that reaches outside
 * is typed inside and admitted, named for where it lands. The target is one
 * spelling, the row's, and "inside" is a prefix of the argument being that spelling
 * (add_inside): a path typed through another spelling of the target's directory
 * is outside by this rule and re-rooted, which the not-found arm says in words
 * (cmd_add).
 *
 * @param input  The argument as typed (must not be NULL)
 * @param target --target as the row spells it, absolute and folded, "/" included
 *               — nothing re-roots under it and nothing escapes it — or NULL:
 *               nothing re-roots at all
 * @param arena  Arena the boundary reads through and the answer lives in
 * @param out    Normalized absolute path, the arena's; NULL after an error
 * @return Error or NULL on success
 */
static error_t add_spell(
    const char *input, const char *target, arena_t *arena, const char **out
) {
    *out = NULL;

    /* The grammar, by the argument's first byte: what the argument is spelled
     * from. Three spellings are the shell's own and are never re-rooted — a tilde
     * path, a path spelled from here, and an empty argument, which is no path
     * in any grammar and which the argument's door is the one place to say so
     * of: the join takes no empty name. A host-absolute path is the jail's unless
     * a prefix of it is the target — something only an absolute spelling can
     * be, since folding a bare relative path onto the root to ask would read
     * `etc/foo` under `--target /etc` as the target itself — and a bare relative
     * path is the jail's outright. The join reads a host-absolute input's leading
     * '/' as its own separator, so `/etc/foo` and `etc/foo` both land at
     * <target>/etc/foo, and it composes under the target as the row spells it,
     * which is the spelling the refusal below prints. */
    const char *composed = input;
    if (target && input[0] != '~' && input[0] != '.' && input[0] != '\0') {
        bool inside = input[0] == '/' && add_inside(input, target, arena);
        if (!inside) composed = str_path_join(arena, target, input);
    }

    /* The answer is the arena's, as the composition it reads is: the caller keys,
     * names and walks from it, and the refusal below simply returns. */
    const char *spelled = NULL;
    error_t err = path_input_filesystem_path(composed, arena, &spelled);
    if (err) return err;

    /* One check for every escape, whatever the shape: `..` walked out of a path
     * that started inside, or a path spelled from here while the user stands
     * outside. The subject is folded (path_input_filesystem_path), so the whole
     * test is a string's, where the boundary above had to be asked per prefix
     * on the bytes as typed. A tilde path is HOME's and is read against no target,
     * even one beneath HOME. The root's own slash is its separator, so as a prefix
     * it is "" — the table's spelling of it (infra/mount.h) — and every absolute
     * path is beneath it. */
    if (target && input[0] != '~' && strcmp(spelled, target) != 0 &&
        !str_path_beneath(spelled, target, target[1] ? strlen(target) : 0)) {
        return ERROR(
            ERR_INVALID_ARG,
            "Path '%s' resolves outside target root '%s'.\n"
            "A path spelled from here, or one walking out with '..', cannot "
            "escape the target.", spelled, target
        );
    }

    *out = spelled;

    return NULL;
}

/**
 * The ladder's answer for a path this add would list, as the command reads it
 *
 * Which rules are asked turns on whose the path is (core/ignore.h, what the rules
 * reach). `held` is the row the profile holds at the path, NULL where it holds
 * none (core/manifest.h manifest_lookup_claim). A path the profile claims — a
 * file, or a directory it tracks — is no discovery, and meets the operation's
 * own -e alone. Anything else is discovered, a directory the profile only passes
 * through included, since naming it makes a new claim; it meets every layer,
 * through the ladder's one question (core/ignore.h ignore_verdict): the
 * `.dottaignore` layers on the name, and the source tree's rules, where the builder
 * opened them, on the place.
 *
 * The name is the one this command chose, whatever produced it — a claim the
 * profile already held, a composition beneath a tracked directory, a typed argument
 * — so a path beneath a tracked `home/jail/etc` is matched as `jail/etc/x` and
 * not as `etc/x` (cmds/add.h). The place is where the path stands, which no naming
 * decision moves.
 *
 * The verdict names the layer and the rule as written, so a caller can say who
 * excluded the path. The rule it names is the outermost of the four's that excludes
 * the path, where one of theirs does, else the source tree's: within each an
 * excluded directory is final, so the climb ends at the first rung a rule excludes
 * and never reaches the rules below it (core/ignore.h ignore_verdict). Clearing
 * that one can uncover the next, beneath it or in the layer below: the refusal
 * offers the `-e` re-opening exactly that rung, and the next refusal names the
 * next (add_refuse_excluded). A source layer that cannot answer, where no rung
 * is excluded, answers its failure, and the path is refused rather than read as
 * excluded by nothing — what could not be read may be what git excludes — named
 * or walked (add_refuse_unjudged).
 *
 * @return The source layer's failure, where no rung is excluded; NULL otherwise
 */
static error_t add_verdict(
    const walk_t *walk, const manifest_row_t *held, const char *filesystem_path,
    const char *storage_path, path_kind_t kind, ignore_verdict_t *out
) {
    /* A claim meets the operation's own filter and no rule of discovery: the -e
     * layer alone, as apply and update ask it of what they hold (core/scope.h
     * scope_is_excluded). So a claim a rule names is re-captured, as update
     * re-captures it and as git stages a tracked file its rules ignore, and a
     * `-e` still leaves it out. No source layer is asked, so nothing can fail. */
    if (held && !manifest_is_derived(held)) {
        return ignore_verdict(walk->excludes, NULL, storage_path, NULL, kind, out);
    }

    /* Anything else meets every layer, and a source layer that cannot answer
     * where no rung is excluded answers its failure: the one error its repository,
     * directory or rule file gave, the same for every entry that reaches it
     * (sys/source.h). */
    return ignore_verdict(
        walk->rules, walk->source, storage_path, filesystem_path, kind, out
    );
}

/**
 * List `filesystem_path` under the name it was given: the item, its bucket, and
 * the listing's index
 *
 * The one door a walked path leaves the walk's scratch through: both strings
 * are copied into the command arena, where the item lives, so the index's key
 * and the claim it lends are the item's own and outlive the entry that found
 * them (sys/filesystem.h fs_listing_t). The item is the arena's and stable, which
 * is what lets the index borrow its claim rather than a loop-local pair — and
 * that is what makes every path beneath this one nameable from it (core/manifest.h
 * manifest_name, the `pending` layer). The claim's kind is the occupant's reading
 * — a directory is a directory, and anything else the listing keeps is a file,
 * a link among them — so the kind and the occupant the capture is chosen by are
 * one fact. The kind chooses the bucket: the walk is the sole source of directory
 * tracking, and every phase after reads the two lists apart.
 */
static void add_list(
    walk_t *walk, const char *filesystem_path, const char *storage_path,
    fs_occupant_t occupant
) {
    arena_t *arena = walk->ctx->arena;

    path_t *path = arena_calloc(arena, 1, sizeof(*path));
    path->filesystem_path = arena_strdup(arena, filesystem_path);
    path->claim = (manifest_claim_t){
        arena_strdup(arena, storage_path),
        occupant == FS_OCCUPANT_DIRECTORY ? PATH_KIND_DIRECTORY : PATH_KIND_FILE
    };
    path->occupant = occupant;

    ptr_array_push(
        path->claim.kind == PATH_KIND_DIRECTORY ? &walk->directories : &walk->files,
        path
    );
    hashmap_set(walk->listing, path->filesystem_path, &path->claim);
}

/**
 * Has the commit room for this name — in its tree, and in its sheet?
 *
 * One commit carries two documents, and they name one namespace: the tree holds
 * every blob, and the sheet holds the directories a tree cannot, since an empty
 * one has no entry at all. A blob leaves no room for a directory at its name or
 * for anything beneath it, whichever document the thing beneath it lives in —
 * so a blob asks both and a subtree asks the tree, a directory claim beneath
 * another being ordinary.
 *
 * The subject is the commit as this command has chosen it so far: the admission
 * — the branch's tree and every blob listed before this one — and the branch's
 * sheet. A directory this command listed is in neither until its capture, so a
 * blob chosen above one is asked about once more, with the selection complete
 * (cmd_add).
 *
 * One producer, two voices: every refusal is ERR_CONFLICT and says which name
 * stands in the way, and the callers give it their own — the argument arm wraps
 * it as an error, the walk prints it and skips the subtree. Anything else is
 * the run failing to decide, which is never a verdict about the path.
 */
static error_t add_admit(
    const walk_t *walk, const char *storage_path, path_kind_t kind
) {
    if (kind == PATH_KIND_DIRECTORY) {
        return stage_admit_subtree(walk->admission, storage_path);
    }

    /* The sheet first: a directory it claims beneath this name has no tree entry
     * to find, so the admission cannot answer for it. */
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

    return stage_admit_blob(walk->admission, storage_path);
}

/**
 * Refuse a walk that met an entry Git's ignore rules could not judge
 *
 * What the source layer cannot read may be what git excludes, so the walk refuses
 * rather than list it (core/ignore.h ignore_verdict): collection precedes capture,
 * and the refusal costs nothing. A frame's entries read one chain of lists, so
 * what failed for one fails for every sibling that chain has not decided first,
 * and the narrow way past is to leave the frame out. An -e excluding it is final
 * — the source layer is never asked beneath it — and is offered where the walk
 * found the frame beneath what the user named and a pattern names it; turning
 * Git's rules off is the other way, and at what the user named, or at a root,
 * the one.
 *
 * The way past is the refusal's hint (base/error.h "Hints"), read beneath the
 * whole chain: cmd_add wraps every refusal of the walk with the argument it began
 * at, and the depth bound's refusal is the same shape.
 */
static error_t add_refuse_unjudged(
    const walk_t *walk, arena_t *scratch, const char *directory, size_t depth,
    error_t failure
) {
    /* The question the walk could not answer, over the source layer's failure
     * that kept it from answering */
    error_t err = error_wrap(
        failure, "Cannot tell what Git's ignore rules exclude in '%s'", directory
    );

    /* The frame's name, as the walk named it — its claim, else its composition,
     * else a root's word — and the rule leaving exactly it out: none for what
     * the user named, nor for a root, whose empty tail no pattern names. Both
     * are the entry's scratch: the hint copies what it prints. */
    const char *name = manifest_name(
        scratch, walk->view, walk->profile, directory, walk->listing
    );
    const char *leave = depth > 0 ? gitignore_literal(scratch, label_tail(name), true) : NULL;
    if (!leave) {
        return error_hint(err, "Turn Git's rules off with respect_gitignore = false to add it");
    }

    return error_hint(
        err, "Leave it out with -e %s, or turn Git's rules off with respect_gitignore "
        "= false", str_shell_quote(scratch, leave)
    );
}

/**
 * Collect a directory's children into the walk.
 *
 * `directory` is the key the frame stands at, and so is every path this frame
 * joins beneath it: a child joined onto a key is a key (infra/mount.h). The frame
 * itself is neither named nor listed here — its caller has already settled it,
 * the argument arm before it descends and the recursion below before it recurses.
 *
 * Every directory walked into is listed — the walk is the sole source of directory
 * tracking — and so is every regular file and symlink child a branch can hold.
 * Symlinks are never followed: a symlink to a directory is an entry like any
 * other, and a special file is no entry at all. One directory is walked into
 * and never listed: one the profile only passes through, which a rule of discovery
 * excludes — entered for the claims beneath it wherever the operation's -e admits
 * it, while beneath it every entry but a claim meets the rung that closed it;
 * as the ancestry's rungs earn no record, it earns none.
 *
 * Each child is named here, once, by the claim standing at it — this command's
 * own where it has listed one there, else the profile's own (core/manifest.h
 * manifest_name over `listing`) — and the recursion names it again for no one.
 * Another profile's target is an ordinary directory here: the walk lists it and
 * enters it, and what it finds beneath is named portably (infra/mount.h). A child
 * that is one of *this* profile's roots is named by its label's word and listed
 * like any directory — or, a link standing at the spelling, like any link.
 *
 * Two verdicts skip a child with its subtree, each with one line at NORMAL: a
 * kind the profile's own claim at the path contradicts, and a name the commit
 * has no room for, or one Git will not hold (add_admit). Neither may fail the
 * command — a stale claim deep inside $HOME must not fail `dotta add p ~`, and
 * the capture that would have refused it arrives too late to skip anything. `depth`
 * bounds the recursion at FS_WALK_MAX_DEPTH, and that is the one walked verdict
 * that refuses rather than skips — collection precedes capture, so a refusal
 * there costs nothing, where a skip would leave the profile permanently short
 * of a subtree that can in fact be captured.
 *
 * On error the lists keep what was collected, in the command arena, and the scratch
 * is left as it stands, for the walk's driver to free.
 *
 * @param walk      The walk (must not be NULL)
 * @param scratch   The walk's: every frame's listing and every entry's strings
 *                  (must not be NULL)
 * @param directory The key this frame enumerates, already settled (must not be
 *                  NULL)
 * @param depth     Frames beneath the argument the walk began at
 * @return Error or NULL on success
 */
static error_t add_collect(
    walk_t *walk, arena_t *scratch, const char *directory, size_t depth
) {
    CHECK_NULL(walk);
    CHECK_NULL(directory);

    output_t *out = walk->ctx->out;

    /* The bound is the frame's own, tested before it enumerates. A directory
     * already settled never reaches here: the callers test the listing before
     * they descend, so a deeper argument collected first does not make its parent's
     * walk fail when the parent arrives at the limit. */
    if (depth >= FS_WALK_MAX_DEPTH) {
        error_t err = ERROR(
            ERR_INVALID_ARG,
            "Cannot walk '%s': it is %d directories below where this walk began",
            directory, FS_WALK_MAX_DEPTH
        );
        return error_hint(err, "Name it as an argument of its own, or exclude it");
    }

    /* The frame's listing, in the walk's scratch (sys/filesystem.h fs_listing_t):
     * the whole of it, and the stream closed with it — one open at a time down
     * the recursion rather than one per frame. Each child's strings — its path
     * and its name — go at the next entry, the frames of its subtree with them;
     * what outlives the entry is a listed path's, copied at its door (add_list). */
    fs_listing_t listing;
    error_t err = fs_listing_init(&listing, scratch, directory);
    if (err) return err;

    for (const char *child_fs; (child_fs = fs_listing_next(&listing)) != NULL;) {
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
        const fs_occupant_t occupant = fs_lstat_occupant(child_fs, &st);
        switch (occupant) {
            case FS_OCCUPANT_NONE:
                output_info(out, OUTPUT_VERBOSE, "Skipped absent: %s", child_fs);
                continue;

            case FS_OCCUPANT_UNKNOWN:
                return error_from_errno(errno, "Failed to stat '%s'", child_fs);

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

        /* Walked whole, or listed already: asked before a name, so nothing this
         * command has settled is settled a second time — and so a verdict against
         * a path is reached once, whichever of the two said it. */
        if (hashmap_has(walk->listing, child_fs)) continue;

        /* The crossing: what this profile calls the child — the claim standing
         * there, this command's own or the branch's, else the composition beneath
         * the nearest claim above it, else the label of the root it lies under,
         * the word alone where the child is one of this profile's own roots. */
        const char *child_storage = manifest_name(
            scratch, walk->view, walk->profile, child_fs, walk->listing
        );

        /* What the profile already claims at the path, asked before any rule: a
         * claim is no discovery, and meets the -e layer alone (add_verdict).
         * The row is the path's own authority on kind too, a derived one included
         * — it says the profile holds a subtree beneath the path, which a path
         * that became a file cannot carry — and it is the one reading that sees
         * a claim with nothing beneath it for either of the branch's documents
         * to find, where add_admit below covers the rest, by the name. */
        const manifest_row_t *held = manifest_lookup_claim(
            walk->view, walk->profile, child_fs
        );

        /* What Git's rules could not judge refuses the walk, whose frame was
         * entered clean: beneath an excluded rung every verdict is that exclusion,
         * so the failure is this entry's own, asked of the frame's lists. */
        ignore_verdict_t verdict;
        error_t failure = add_verdict(walk, held, child_fs, child_storage, kind, &verdict);
        if (failure) return add_refuse_unjudged(walk, scratch, directory, depth, failure);

        /* Left out by a rule, and never listed. */
        if (verdict.origin != IGNORE_ORIGIN_NONE) {
            /* A directory the profile only passes through holds claims beneath
             * it, and a claim meets the operation's -e alone: the walk enters
             * it wherever that layer admits it, and every entry beneath but a
             * claim meets the rung that closed it. Anything else goes with its
             * subtree. */
            ignore_verdict_t claims = verdict;
            if (manifest_is_derived(held) && kind == PATH_KIND_DIRECTORY) {
                (void) ignore_verdict(
                    walk->excludes, NULL, child_storage, NULL, kind, &claims
                );
            }

            /* Said at VERBOSE where the rule decided this very entry, under the
             * layer and the rule: beneath a directory the walk passes through,
             * that directory's own line said it. The words are made only where
             * they print — a walk can exclude thousands — in the entry's
             * scratch. */
            if (verdict.rung == 0 && output_is_verbose(out)) {
                output_info(
                    out, OUTPUT_VERBOSE, "Excluded: %s (%s)%s", child_fs,
                    ignore_verdict_describe(scratch, &verdict),
                    claims.origin == IGNORE_ORIGIN_NONE
                        ? ", entered for the claims beneath it" : ""
                );
            }
            err = claims.origin == IGNORE_ORIGIN_NONE
                ? add_collect(walk, scratch, child_fs, depth + 1) : NULL;
            if (err) return err;
            continue;
        }

        /* A kind the claim contradicts: what stands there now is not what the
         * profile holds there. */
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

        /* What the commit can hold, asked before a byte is read. Only a conflict
         * is a verdict about the path — a name the tree or the sheet has no room
         * for, or one Git will not hold (sys/stage.h); a failure to decide is
         * the run failing, and publishing a selection past one would commit a
         * silently partial capture. A conflict is warned and dropped, one per
         * child it skips. */
        err = add_admit(walk, child_storage, kind);
        if (err) {
            if (error_code(err) != ERR_CONFLICT) return err;
            output_warning(
                out, OUTPUT_NORMAL, "Skipping '%s': %s", child_fs,
                error_message(err)
            );
            continue;
        }

        add_list(walk, child_fs, child_storage, occupant);

        /* Settled, so the descent is one statement. */
        err = kind == PATH_KIND_DIRECTORY
            ? add_collect(walk, scratch, child_fs, depth + 1) : NULL;
        if (err) return err;
    }

    return NULL;
}

/**
 * Refuse a path named on the command line that a rule excludes
 *
 * The refusal names the rule — the layer, and for Git's rules the file and line
 * it was read at (core/ignore.h ignore_verdict_describe) — and offers the -e
 * that re-opens exactly the rung it closed (ignore_verdict_negation): clearing
 * it can uncover the next rung, which the next refusal names. The operation's
 * own -e is named and offered nothing, since this command said it. Where no -e
 * reaches the rung, the refusal says so and names what does: respect_gitignore
 * for Git's rules, the rule itself for the four's. A directory the profile only
 * passes through holds claims beneath it, which update re-captures without making
 * the directory one, and the refusal names that too.
 *
 * The argument is echoed as typed, and every command line it offers is quoted
 * for the shell the user types it back into (base/string.h str_shell_quote).
 */
static error_t add_refuse_excluded(
    const walk_t *walk, const char *file, const char *storage_path, path_kind_t kind,
    const manifest_row_t *held, const ignore_verdict_t *verdict
) {
    arena_t *arena = walk->ctx->arena;
    const char *rule = ignore_verdict_describe(arena, verdict);

    /* The operation's own -e: this command said it, and nothing is offered. */
    if (verdict->origin == IGNORE_ORIGIN_CLI) {
        return ERROR(ERR_INVALID_ARG, "'%s' is ignored by %s", file, rule);
    }

    /* A directory the profile only passes through: naming it makes a claim, and
     * what the profile already holds beneath it is update's to re-capture,
     * whichever way past the rule is taken. */
    const char *beneath = manifest_is_derived(held)
        ? arena_str_format(
        arena, "\nProfile '%s' holds paths beneath it: dotta update -p %s %s "
        "re-captures them", walk->profile, walk->profile, str_shell_quote(arena, file)
        ) : "";

    /* The -e re-opening the rung, where a pattern reaches it: beside the switch
     * for Git's rules, which dotta does not write, and alone for the four's. */
    const char *negation = ignore_verdict_negation(arena, verdict, storage_path, kind);
    if (negation && verdict->origin == IGNORE_ORIGIN_SOURCE) {
        return ERROR(
            ERR_INVALID_ARG, "'%s' is ignored by %s\n"
            "Add it anyway with -e %s, or turn Git's rules off with respect_gitignore = "
            "false%s", file, rule, str_shell_quote(arena, negation), beneath
        );
    }
    if (negation) {
        return ERROR(
            ERR_INVALID_ARG, "'%s' is ignored by %s\nAdd it anyway with -e %s%s", file,
            rule, str_shell_quote(arena, negation), beneath
        );
    }

    /* No pattern reaches the rung, and the layer's own way past is the one left. */
    if (verdict->origin == IGNORE_ORIGIN_SOURCE) {
        return ERROR(
            ERR_INVALID_ARG, "'%s' is ignored by %s\n"
            "No -e can re-open it; turn Git's rules off with respect_gitignore = false "
            "to add it%s", file, rule, beneath
        );
    }
    return ERROR(
        ERR_INVALID_ARG, "'%s' is ignored by %s\n"
        "No -e can re-open it; change that rule to add it%s", file, rule, beneath
    );
}

/**
 * Refuse a selection that moves a name without capturing the one it moves to
 *
 * A path this branch names twice is decided by the settle, and this command's
 * own claims can change that decision: a directory claim admitted above such a
 * path changes what its ascent composes, and with it which of the profile's names
 * stands there (core/manifest.h manifest_name, "what the next settle will keep").
 * Where the name that will stand is not one this command captured, the next apply
 * deploys bytes this command never read — over the ones it just committed under
 * the other name.
 *
 * The subject is exactly manifest_unkept's slice: no verb can give a profile a
 * second name for a path it already names (manifest_holds_name), and a listing
 * that is not typed takes the namer's own answer — so the groups are the branch's,
 * and only which member stands can move. Asked once, with the selection complete,
 * because naming is a snapshot taken when a path is listed and a later argument
 * can change what an earlier one composed.
 *
 * `kept` is the settle's own answer at the path and needs no second lookup; the
 * view is one profile's, so the slice needs no profile filter. A path its profile
 * names three times appears twice and is asked twice — the question is pure,
 * and a set to spend on that repetition would cost more than it saves.
 *
 * The name to give up is the one this command would move *to*: with it gone the
 * path is named once, the pre-command winner stands, and nothing moves. Giving
 * up the kept name performs the move instead of preventing it.
 *
 * Not liftable by --force: --force overwrites bytes under a name the profile
 * holds, which is not what abandoning a name is.
 */
static error_t add_refuse_moves(const walk_t *walk) {
    manifest_unkept_t unkept = manifest_unkept(walk->view);

    for (size_t i = 0; i < unkept.count; i++) {
        const char *filesystem_path = unkept.entries[i].filesystem_path;
        const char *kept = unkept.entries[i].kept;

        const char *next = manifest_name(
            walk->ctx->arena, walk->view, walk->profile, filesystem_path, walk->listing
        );
        if (strcmp(kept, next) == 0) continue;   /* nothing moved here */

        /* The one selection that may move a name: the command captured the path
         * under the very name the next settle will keep. */
        const manifest_claim_t *listed = hashmap_get(walk->listing, filesystem_path);
        if (listed && strcmp(listed->storage_path, next) == 0) continue;

        /* The path is the one path in the sentence the user never typed, so it
         * is spelled the way the shell spells it — as the screen that reports
         * this pair already spells it (cmds/status.c's unused-path listing).
         * The opening is revert.c refuse_second_name's, deliberately: one profile
         * names one path once, and these are that rule read from its two ends. */
        char shown[PATH_MAX];
        output_format_path(filesystem_path, identity()->home, shown, sizeof(shown));

        return ERROR(
            ERR_INVALID_ARG, "Profile '%s' names '%s' as '%s'\n\n"
            "This command's directory claims would name it '%s', which it does "
            "not capture — a directory must be named before the paths beneath it.\n"
            "  dotta add %s --force %s   captures those bytes under that name\n"
            "  dotta remove %s %s   gives that name up instead",
            walk->profile, shown, kept, next, walk->profile, next, walk->profile, next
        );
    }

    return NULL;
}

/**
 * Say what a capture claimed — the claim decides the shape
 *
 * Three claim shapes exist, by the sheet's own existence rule (an item exists
 * iff it claims something): mode and ownership, mode alone, ownership alone —
 * the entry of a link another owner holds, which a directory capture never produces
 * since a directory always claims its mode. The fourth combination has no line
 * to print: such an item does not exist, the capture returned NULL instead.
 * Ownership is all-or-none at the capture boundary (core/metadata.c
 * metadata_capture_ownership), so a present owner implies a present group.
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
static void add_print_capture(
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
 * Name the command that gives a profile no row holds its place here
 *
 * The one remedy an add into such a profile leaves, whichever screen says it:
 * the receipt's, where the record phase found no row, and the preview's, where
 * the rows it read say the same. Enable is the verb, and what it must bring is
 * one of three things. The target as the user typed it, when the run brought
 * one — "here" is where they typed it. Else a target, when the branch as this
 * command opened it holds a claim no binding places (core/manifest.h
 * manifest_unbound): the reading `profile enable` refuses on, so the hint never
 * names a command that refuses — the branch's custom/ paths were there before
 * this add and are there after it, whatever this add captured beside them. Else
 * enable alone.
 *
 * @param out     Output context (must not be NULL)
 * @param profile The profile (must not be NULL)
 * @param target  The --target the run brought, as typed; NULL without one
 * @param view    The branch as this command opened it, under its table (must
 *                not be NULL)
 */
static void add_print_enable(
    output_t *out, const char *profile, const char *target, const manifest_t *view
) {
    if (target) {
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta profile enable %s --target %s' to deploy it here",
            profile, target
        );
    } else if (manifest_unbound(view).count > 0) {
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta profile enable %s --target /path' to activate and deploy",
            profile
        );
    } else {
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta profile enable %s' to activate and deploy", profile
        );
    }
}

/**
 * Say which labels the captured paths landed under
 *
 * A capture's name is the one typed for it, or the claim standing at its path —
 * this command's own, the profile's, a directory claim above it — and its root's
 * label only where none stands (cmds/add.h, the name a capture lands under). So
 * a label is the profile's history, not the command line's: `/` encloses HOME,
 * so a path beneath HOME can take two labels in any profile, and a third beneath
 * a binding. The counts above say which kinds were captured; this says where
 * their names went, and it is where a name that stayed put shows.
 *
 * One line per label that took a path, in the labels' own order, counting paths:
 * a file and a directory are one name each, so the lines sum to the kinds the
 * counts above them name, in every arm. A label whose root the user chose names
 * where it stands, spelled as every screen that prints a bound target spells it
 * (base/output.h); the machine's own roots are where the word says. No tense: a
 * noun phrase, true of a capture and of one about to happen.
 *
 * The place is the table's, asked of the view the walk named through — the same
 * table, which lends it back (core/manifest.h manifest_mounts) — so the line
 * and the names it counts cannot disagree about where a binding stands.
 *
 * @param walk The selection, the table it named through, and the output (must
 *             not be NULL)
 */
static void add_print_labels(const walk_t *walk) {
    output_t *out = walk->ctx->out;
    const mount_table_t *mounts = manifest_mounts(walk->view);
    const ptr_array_t *listed[] = { &walk->files, &walk->directories };

    /* One pass over both lists, a slot per label: a name says its own
     * (infra/label.h label_of). */
    size_t count[LABEL_COUNT] = { 0 };
    for (size_t b = 0; b < sizeof(listed) / sizeof(listed[0]); b++) {
        for (size_t i = 0; i < listed[b]->count; i++) {
            const path_t *path = listed[b]->entries[i];
            count[label_of(path->claim.storage_path)]++;
        }
    }

    for (label_t label = LABEL_HOME; label < LABEL_COUNT; label++) {
        if (count[label] == 0) continue;

        /* A name was listed under a label only where the asker has that root,
         * so the table holds one — and whether the user chose the place is the
         * root's own answer, not the label's. */
        const mount_root_t *root = mount_root_of(mounts, walk->profile, label);
        if (root && root->profile) {
            char shown[PATH_MAX];
            output_format_path(root->filesystem_path, identity()->home, shown, sizeof(shown));
            output_info(
                out, OUTPUT_NORMAL, "  %zu path%s as %s/ under %s",
                count[label], count[label] == 1 ? "" : "s",
                label_words[label], shown
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL, "  %zu path%s as %s/",
                count[label], count[label] == 1 ? "" : "s", label_words[label]
            );
        }
    }
}

/**
 * Capture one listed path onto the stage, and its claim onto the sheet
 *
 * As the kind it was listed as: the occupant chooses the capture, and each capture
 * refuses the other's (infra/content.h), so a path whose kind changed after its
 * listing is refused rather than read as what it has become — and the verdict
 * the decision pass reached for a regular file is read by a regular file's capture
 * alone. Sealed as that pass decided. The capture answers with the entry's bytes
 * and the look they were read with; this function places both — the entry on
 * the stage, the claim on the sheet — and keeps what it placed as the path's
 * record (path->record): the blob the put wrote, the look's triple, the claim.
 *
 * @param ctx Dispatch context (must not be NULL; the key manager for a seal,
 *            the arena the record's names are copied into, and the output)
 * @param stage The profile's stage (must not be NULL)
 * @param profile The profile, for the seal's key and the record's binding (must
 *                not be NULL)
 * @param path The listed path (must not be NULL; its record is the capture's
 *             once the capture lands)
 * @param metadata The sheet the claim goes onto (must not be NULL)
 * @return Error or NULL on success
 */
static error_t add_capture(
    const dotta_ctx_t *ctx,
    stage_t *stage,
    const char *profile,
    path_t *path,
    metadata_t *metadata
) {
    CHECK_NULL(ctx);
    CHECK_NULL(stage);
    CHECK_NULL(profile);
    CHECK_NULL(path);
    CHECK_NULL(metadata);

    output_t *out = ctx->out;
    const char *filesystem_path = path->filesystem_path;
    const char *storage_path = path->claim.storage_path;

    /* The capture the path was listed for, fulfilled or refused. Each takes its
     * own stat — a link's before its target, the link's uid/gid and not the
     * target's; a file's the fstat of the descriptor its bytes came off, bytes
     * and triple one inode by construction — and that stat is the claim's and
     * the record's both.
     *
     * Then the entry, at the name the capture was made under: a sealed capture
     * binds it (infra/content.h), so the put repeats it and never a second name.
     * One tail past the door — the bytes are the stage's now, or nobody's, and
     * the look stays readable for the claim and the record below. */
    content_capture_t capture = { 0 };
    git_oid blob;
    error_t err = NULL;
    if (path->occupant == FS_OCCUPANT_SYMLINK) {
        err = content_capture_link(filesystem_path, &capture);
    } else {
        err = content_capture_file(
            filesystem_path, storage_path, profile, ctx->run.keymgr,
            path->should_encrypt, &capture
        );
    }
    if (!err) {
        err = stage_put(
            stage, storage_path, capture.bytes.data, capture.bytes.size,
            capture.mode, &blob
        );
    }
    content_capture_free(&capture);
    if (err) return err;

    /* The claim from the capture's own look, sealed as the capture says: its
     * write-time invariant makes that verdict the byte truth (a plaintext that
     * would read as ciphertext is refused there), so the claim and every reader
     * of the bytes agree — and a link is never sealed. */
    metadata_item_t *item = NULL;
    err = metadata_capture_file(
        storage_path, &capture.st, capture.encrypted, &item
    );
    if (err) {
        return error_wrap(
            err, "Failed to capture metadata for '%s'",
            filesystem_path
        );
    }

    /* What the capture committed, as the record keeps it: the node the listing
     * found and the capture held to, the blob the put wrote under the look its
     * bytes came off, and the claim — taken before the sheet takes the item */
    path->record = (state_record_t){
        .filesystem_path = filesystem_path,
        .storage_path = storage_path,
        .profile = profile,
        .kind = path->occupant,
        .blob_oid = blob,
        .stat = state_stat_from_read(&capture.st),
    };
    metadata_item_claim(item, ctx->arena, &path->record);

    if (capture.encrypted) {
        output_info(
            out, OUTPUT_VERBOSE, "Encrypted: %s -> %s",
            filesystem_path, storage_path
        );
    }
    output_info(
        out, OUTPUT_VERBOSE,
        path->occupant == FS_OCCUPANT_SYMLINK ? "Added symlink: %s -> %s"
                                              : "Added: %s -> %s",
        filesystem_path, storage_path
    );

    /* NULL is a links-only answer (core/metadata.h): the capture claims nothing
     * — a link with no ownership to track — and an item standing at the key is
     * the replaced state's, retired. */
    if (!item) {
        metadata_remove_item(metadata, storage_path);
        return NULL;
    }

    add_print_capture(out, "metadata", filesystem_path, item);

    metadata_add_item(metadata, &item);

    return NULL;
}

/**
 * Commit the stage
 *
 * The message names both kinds this commit carries — the message's unit is the
 * path (utils/commit.h), and a commit that claimed a directory and no file has
 * a path to name and no file — so the walk goes in, not one of its lists.
 *
 * @param walk The selection, both lists, and the arena the names live in (must
 *             not be NULL)
 * @param stage The profile's stage, every capture on it (must not be NULL)
 * @param opts Command options
 * @param out_committed Whether a commit was made: false when the stage holds
 *                      the branch's own tree, so a re-add of what the profile
 *                      already holds moves nothing (must not be NULL)
 * @return Error or NULL on success
 */
static error_t add_commit(
    const walk_t *walk,
    stage_t *stage,
    const cmd_add_options_t *opts,
    bool *out_committed
) {
    CHECK_NULL(walk);
    CHECK_NULL(stage);
    CHECK_NULL(opts);
    CHECK_NULL(out_committed);

    /* The names this commit takes, borrowed from the claims the walk listed them
     * under: every listed path has one (add_list). Both kinds, in the order every
     * other reader of the two takes them. The message reads them once and the
     * arena outlives the call, so nothing is copied. */
    const ptr_array_t *listed[] = { &walk->files, &walk->directories };
    size_t count = walk->files.count + walk->directories.count;

    const char **paths = arena_calloc(walk->ctx->arena, count, sizeof(*paths));

    size_t named = 0;
    for (size_t b = 0; b < sizeof(listed) / sizeof(listed[0]); b++) {
        for (size_t i = 0; i < listed[b]->count; i++) {
            const path_t *path = listed[b]->entries[i];
            paths[named++] = path->claim.storage_path;
        }
    }

    /* Build commit message context */
    commit_message_context_t msg_ctx = {
        .action        = COMMIT_ACTION_ADD,
        .profile       = opts->profile,
        .paths         = paths,
        .path_count    = count,
        .custom_msg    = opts->message,
        .target_commit = NULL
    };

    /* Create commit */
    error_t err = stage_commit(
        stage, commit_message(walk->ctx->arena, walk->ctx->config, &msg_ctx),
        out_committed
    );

    if (err) {
        return error_wrap(err, "Failed to create commit");
    }

    return NULL;
}

/**
 * Write the record after a successful add operation
 *
 * Called after Git commit succeeds, for a new profile and an existing one alike.
 * Anchors what this add captured: every path was captured FROM disk, so its record
 * is what the capture committed (path_t's record) — the blob, under the stat
 * the capture took, so the next status hits the fast path, and the node and the
 * claim — stamped as an ownership event; a directory's carries no stat, having
 * no content to confirm. The view is computed, so nothing projects; one build
 * over the enabled set says which of this add's own claims still stand at their
 * paths — whose each path is, and nothing the record says.
 *
 * Algorithm:
 *   1. Scope. A new profile is enabled here with its deployment target — creating
 *      a profile via add enables it, in the same transaction as the record. An
 *      existing profile has rows in the view only if it is already enabled: not
 *      enabled skips the anchor pass (nothing to win) and the target UPSERT
 *      (enable's business), never the settle
 *   2. Build the view; anchor each capture where its own claim stands at the
 *      path the walk read it at, its record the capture's; settle what the commit
 *      let go
 *   3. Commit the transaction (state_save), and finish it either way
 *
 * CRITICAL ORDER: step 1 must precede step 2. The builder's own table is built
 * from the rows, so a custom/ claim of this profile stands nowhere until the
 * row holds the target. Atomicity is the transaction's: the enable and the record
 * commit together or not at all.
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
 *   directories FROM the filesystem. They're already at their target paths, so
 *   deployed_at is set to indicate dotta put them there. A captured path whose
 *   record another profile's deployment had written is taken over — the write
 *   rewrites the record under this profile — and counted for the receipt: nothing
 *   later says so (apply acknowledges a reassignment the scope made, not one
 *   the user's own add made).
 *
 * Error Handling:
 *   - Profile not enabled and nothing let go → NULL, with nothing written
 *   - A refused statement ends the phase at the first one. The phase's writes
 *     are one transaction and a database that refuses one write may have ended
 *     it, so every write past an unexamined refusal is a coin flip between "in
 *     the transaction" and "committed on its own"
 *
 * Postcondition, on every path: the transaction the dispatcher opened is finished
 * when this function returns — committed by state_save, or rolled back here.
 * The caller runs the post-add hook next, and a hook that asks the database must
 * not meet a lock this run has no further use for (cmds/apply commits before
 * its hook and cmds/update rolls back before its own, for this reason).
 *
 * Non-Fatal Integration:
 *   Caller should treat a record write failure as a non-fatal warning: Git's
 *   commit stands and the exit is zero. Nothing this phase wrote stands either
 *   — the first refusal ended the pass and the rollback took the rest — so what
 *   the record already held is what it still holds, and the retry is this command
 *   again with --force. Not an apply: apply re-earns the ownership event for a
 *   file it adopts and never for a directory, whose ownership is the capture's
 *   alone (cmds/apply.c, the adoption loop).
 *
 * Performance: one view build and one read of the record, then each captured
 * path looked up in both — O(N log A), N = paths captured, A = records
 *
 * @param ctx Dispatch context (must not be NULL; reads the repository, the state
 *            and the command arena)
 * @param mounts The command's table, read here by the settle alone: `retired`
 *               holds names the ancestry pass dropped, and a name stands nowhere
 *               until the table gives it one (must not be NULL). The anchor pass
 *               needs no table — a listing carries the path its own claim resolves
 *               to under this very table (the key invariant, cmds/add.h)
 * @param profile The profile added to (must not be NULL)
 * @param target The binding the run brought, absolute, or NULL: written for a
 *               new profile and an enabled one (the UPSERT keeps a row's own
 *               for a NULL)
 * @param profile_created This add created the profile's branch: enable it here
 * @param added_files The files the walk listed, each with the record its capture
 *                    made (must not be NULL)
 * @param added_dirs The directories the walk passed through, each with the record
 *                   its capture made (must not be NULL)
 * @param retired The ancestor claims the ancestry pass dropped, by key (must
 *                not be NULL)
 * @param receipt What the phase did, zeroed first (must not be NULL)
 * @return Error or NULL on success (non-fatal - caller treats as warning)
 */
static error_t add_write_record(
    const dotta_ctx_t *ctx,
    const mount_table_t *mounts,
    const char *profile,
    const char *target,
    bool profile_created,
    const ptr_array_t *added_files,
    const ptr_array_t *added_dirs,
    const string_array_t *retired,
    receipt_t *receipt
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

    error_t err = NULL;

    *receipt = (receipt_t){ 0 };

    /* STEP 1: Scope.
     *
     * Does a row hold this profile? The handle answers from the rows as this
     * transaction holds them, so the question is asked where each answer is wanted:
     * before the write, whether a row takes the run's binding; after it, whether
     * the anchor pass has a row to win — the only row this phase can add being
     * a created profile's.
     *
     * CRITICAL ORDER: the binding is written before the view is built. The
     * builder's own table is built from the rows, so a custom/ claim of this
     * profile stands nowhere until the row holds the target. Atomicity is the
     * transaction's: the enable and the record commit together or not at all. */
    if (profile_created || (target && state_enabled(state, profile))) {
        /* One UPSERT for two acts. A created profile's branch may still meet a
         * row a deleted branch left behind: the row keeps its position, takes
         * this run's binding when it brought one and keeps the leftover's
         * otherwise. An enabled profile's re-bind is the same statement — the
         * pre-flight refused a differing value, so this repeats the row's own
         * spelling or binds an unbound row. */
        err = state_enable_profile(state, profile, target);
        if (err) goto cleanup;
    } else if (!state_enabled(state, profile) && retired->count == 0) {
        /* Nothing to write at all: no row for a capture to win, a target the
         * run brought left unbound (enable's business, when the user gets there),
         * and no claim let go. The settle below is not gated on enablement —
         * the commit dropped whatever `retired` names whatever the enabled set
         * says, and a path the commit let go settles by its record — but with
         * nothing let go it has nothing to do either. */
        goto cleanup;                                  /* err is NULL */
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
    if (err) goto cleanup;

    if (state_enabled(state, profile)) {
        /* The record as it stands first, read before the write that rewrites
         * it, so a takeover is known — looked up by path in the read
         * (state_find_record). */
        state_record_t *records = NULL;
        size_t record_count = 0;
        err = state_records(state, ctx->arena, &records, &record_count);
        if (err) goto cleanup;

        time_t now = time(NULL);

        /* Both lists, one rule and one count: each capture's record is what it
         * committed, a directory's carrying no content because its capture set
         * none, so nothing here asks the kind — and the accounting cannot drift
         * apart between two loops, as it once did, the directory count the receipt
         * printed being the sheet's, taken before the pass that could refuse it.
         *
         * Both kinds earn one event. A path was captured from disk, so it is
         * dotta's to prune on scope exit — the ownership the gate asks for, which
         * nothing later grants a directory that was already there: apply observes
         * those and anchors only the ones it makes, so an unowned directory is
         * released where an owned one is pruned. Cleanup's emptiness rule guards
         * their contents.
         *
         * The view says whose the path is, and nothing the record says: the
         * capture's record is written only where the row standing at the path
         * the walk read IS the capture's claim, both halves (core/manifest.h's
         * manifest_is_claim). No round trip through the name: for every listing
         * mount_resolve of its own claim is that path (the key invariant,
         * cmds/add.h), and the table this view was built from is the table the
         * walk used — STEP 1 wrote the very binding it holds.
         *
         * What Git holds at the name is not the record's to say either. The key
         * cannot move under the command — the run holds the store's write lock,
         * so the rows the view is built from are the rows the walk's table was
         * — but the lock is not Git's, and another writer's commit can land between
         * this add's and this build: other bytes at the name, another claim,
         * another kind, or no name. The first three leave the claim standing,
         * and the record carries the capture as it was made, so the next load
         * reads Git's move past it ([stale]) and never bytes dotta put there;
         * the last is a miss.
         *
         * A miss is three things, each counted where the row that says it is in
         * hand, so the receipt names the cause it checked rather than a difference:
         * the claim lost the path — to a higher-precedence profile's row, or to
         * another name of this very profile that the settle kept, which a machine
         * whose roots held two names apart can commit and a sync can bring here
         * — so the row is someone else's word, and so is the record at the path;
         * or the profile no longer names the path by this name at all, a later
         * commit having removed it.
         *
         * The profile's own contribution answers which, and answering it first
         * is what lets the arms below read the row without asking whether there
         * is one: a name this profile holds at a path has a row at that path,
         * the layering inserting every explicit row of every contribution
         * (core/manifest.h manifest_holds_name). That is the gone arm's second
         * job: it is the NULL-`row` guard the two counting arms rest on.
         *
         * A refused statement ends the pass. The phase's writes are one transaction
         * and a database that refuses one write may have ended it — SQLite rolls
         * back under a whole class of errors — so every write after an unexamined
         * refusal is a coin flip between "in the transaction" and "committed on
         * its own". The first refusal is the phase's failure, which is what makes
         * the receipt's recovery line true of every prior state: nothing this
         * phase wrote stands. Non-fatal is still the contract one level up —
         * Git's commit stands and the receipt names the retry. */
        const ptr_array_t *captured[] = { added_files, added_dirs };
        for (size_t b = 0; b < sizeof(captured) / sizeof(captured[0]); b++) {
            for (size_t i = 0; i < captured[b]->count; i++) {
                const path_t *path = captured[b]->entries[i];

                const manifest_row_t *row = manifest_lookup(manifest, path->filesystem_path);
                if (!manifest_is_claim(row, profile, path->claim.storage_path)) {
                    if (!manifest_holds_name(
                        manifest, profile, path->filesystem_path, path->claim.storage_path
                        )) {
                        receipt->gone++;
                    } else if (strcmp(row->profile, profile) != 0) {
                        receipt->overridden++;
                    } else {
                        receipt->unkept++;
                    }
                    continue;
                }

                /* The ownership event: what the capture committed, and the phase's
                 * stamp */
                state_record_t record = path->record;
                record.deployed_at = now;

                err = state_write(state, &record);
                if (err) goto cleanup;
                receipt->anchored++;

                const state_record_t *was = state_find_record(
                    records, record_count, row->filesystem_path
                );
                if (was && was->deployed_at > 0 && strcmp(was->profile, profile) != 0) {
                    receipt->taken_over++;
                }
            }
        }
    }

    /* What the commit let go: an ancestor claim the derivation retired leaves
     * the view by this very commit, so its record settles here rather than
     * orphaning until an apply gets around to it — the record the commit stranded
     * is the commit's to settle. It refuses nothing while it stands: a directory
     * only a record remembers reaches no view row (the reach rule,
     * core/workspace.h), so the leaf this add just captured through the arrangement
     * is judged on its own occupant either way, and a retire that fails ends
     * the phase without refusing the add — the retry re-anchors and re-runs no
     * retire, the sheet already lacking the claim, so the stranded record stays
     * apply's to release under status's Issues exactly as before. Enablement
     * was not consulted on the way here: the derivation saw the disk contradict
     * the claim whatever the enabled set says, and the record its drop strands
     * is stale under a disabled profile exactly as under an enabled one. A rung
     * some other profile still claims keeps its row and its record — the retire
     * is this profile's word about its own claim, never about the path — and an
     * unbound claim names nothing on this machine to retire. */
    for (size_t i = 0; i < retired->count; i++) {
        const char *filesystem_path = mount_resolve(
            ctx->arena, mounts, profile, retired->entries[i]
        );
        if (!filesystem_path || manifest_lookup(manifest, filesystem_path)) continue;

        err = state_retire(state, filesystem_path);
        if (err) goto cleanup;
    }

    /* STEP 3: the transaction the dispatcher opened is this phase's to close.
     * The tail is the label's — a failed save falls into the same settle a failed
     * statement does. */
    err = state_save(state);

cleanup:
    /* The phase finishes its own transaction, because the caller runs the post-add
     * hook next and a hook that asks the database must not meet a lock this run
     * has no further use for. state_rollback is a no-op once state_save has
     * committed, and is also the one call that clears the handle's flag after
     * SQLite rolled the transaction back itself.
     *
     * And it settles the rows the tail asks about this profile: STEP 1's where
     * the save landed, the ones this phase began with where it did not
     * (state_rollback). */
    state_rollback(state);

    return err;
}

/**
 * Add command implementation
 */
error_t cmd_add(const dotta_ctx_t *ctx, const cmd_add_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;   /* Borrowed from dispatcher (WRITE; READ under -n) */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Initialize all resources to NULL for safe cleanup */
    error_t err = NULL;
    ignore_rules_t *ignore_rules = NULL;
    const gitignore_ruleset_t *profile_rules = NULL;
    stage_t *stage = NULL;
    stage_admission_t *admission = NULL; /* The tree as its names are chosen: see below */
    manifest_t *view = NULL;         /* The branch as the stage opened it: see below */
    walk_t walk = { .ctx = ctx };    /* Filled once the table and the rules are known */
    bool profile_exists = false;     /* The pre-flight's question, read by both modes */
    bool profile_created = false;    /* The orphan open's answer, read below the commit */
    bool committed = false;
    metadata_t *metadata = NULL;
    mount_table_t *mounts = NULL;         /* The command's table: see below */
    const char *target = NULL;            /* --target, absolute: what the row stores */

    /* The ancestry pass's other half: the keys it retired, read by the record
     * write once the commit that drops them has landed. */
    string_array_t ancestry_retired;
    string_array_init(&ancestry_retired, ctx->arena);

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
        const char *blocker = NULL;
        err = gitops_branch_blocker(repo, opts->profile, ctx->arena, &blocker);
        if (err) goto cleanup;
        if (blocker) {
            const char *base = strlen(blocker) < strlen(opts->profile)
                ? blocker : opts->profile;
            err = ERROR(
                ERR_INVALID_ARG, "Profile '%s' cannot exist beside profile '%s'\n\n"
                "Git stores each profile as a branch, and '%s' cannot be both "
                "a branch and a folder of branches.\n", opts->profile, blocker, base
            );
            goto cleanup;
        }
    }

    /* Where this profile's custom/ tree stands, as its row spells it — the binding
     * this command's table holds for the profile whenever the row has one, a
     * --target below being held to it and taking its spelling. A copy and not
     * the borrow: the record phase's enable and its rollback each replace the
     * row cache state_target lends from (core/state.h, state_profiles), and the
     * receipt names this binding after both. `target` is the flag's alone, NULL
     * without it: re-rooting an argument is the flag's grammar (add_spell), never
     * a row's. */
    const char *bound = arena_strdup(ctx->arena, state_target(state, opts->profile));

    /* The target, when the run brought one: a filesystem-shaped argument —
     * absolute, tilde, or relative to the working directory — read through the
     * target's door (infra/path.h path_input_target): the absolute path the row
     * stores, held to the target's rules. */
    if (opts->target) {
        err = path_input_target(opts->target, ctx->arena, &target);
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
        if (bound && !mount_same_target(bound, target)) {
            err = ERROR(
                ERR_INVALID_ARG,
                "Profile '%s' is bound at %s, and a profile has one target\n"
                "  dotta profile enable %s --target %s    moves it; "
                "the next apply relocates its paths\n"
                "  dotta add <profile> --target %s <path>    "
                "a second tree is a second profile",
                opts->profile, bound, opts->profile, opts->target, opts->target
            );
            goto cleanup;
        }
        /* The row's own directory, spelled another way: the binding stands and
         * keeps the spelling its binder typed, because that spelling is the key
         * of every path beneath it (infra/mount.h). Said at NORMAL: the flag's
         * value was not written, and the row's spelling is the one every argument
         * below is read under. */
        if (bound && strcmp(bound, target) != 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "  %s is bound at %s — the same directory, spelled another way; "
                "the arguments are read under that spelling", opts->profile, bound
            );
        }
        if (bound) target = bound;
    }

    /* The topology this command reads: this machine's rows, with the binding
     * the run brought standing for this profile's — which is why add declares
     * no `mounts` need and the dispatcher builds none (include/runtime.h). One
     * table for the walk, the argument arm and the record's join below, from
     * the one derivation of the topology there is (core/manifest.h
     * manifest_mount_table): every verb reads the asker's own entries, so a table
     * holding this binding alone would answer the same, and what the one derivation
     * buys is the sentence below.
     *
     * The flag's own target is the row's whenever a row exists (the pre-flight
     * above took the row's spelling), and where none does the binding is simply
     * added — so the rows this table is built from are the rows STEP 1 of the
     * record phase leaves for the view, and the two key alike. */
    const mount_t binding = { .profile = opts->profile, .target = target };
    err = manifest_mount_table(state, target ? &binding : NULL, ctx->arena, &mounts);
    if (err) goto cleanup;

    /* The -e layer, compiled once: a pattern the grammar refuses is refused here,
     * under the flag's name and before the pre-add hook runs. The same rules
     * are the builder's top layer, and the whole of what a claim meets
     * (add_verdict). */
    const gitignore_ruleset_t *excludes = NULL;
    err = ignore_excludes_compile(
        opts->exclude_patterns, opts->exclude_count, ctx->arena, &excludes
    );
    if (err) goto cleanup;

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
    err = ignore_rules_create(repo, config, excludes, ctx->arena, &ignore_rules);
    if (err) goto cleanup;

    /* Build hook invocation */
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_ADD,
        .profile    = opts->profile,
        .files      = opts->files,
        .file_count = opts->file_count,
        .dry_run    = opts->dry_run,
    };

    /* Execute pre-add hook */
    err = hook_fire_pre(config, out, &hook_inv);
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
        profile_created = true;   /* This add is what brings the branch */
    }

    if (err) {
        err = error_wrap(err, "Failed to open profile '%s'", opts->profile);
        goto cleanup;
    }

    /* Resolve the profile-specific ruleset. Safe for both paths: existing profile
     * → loads the profile's `.dottaignore`; new profile → branch doesn't exist
     * yet, builder treats that as "no profile layer" and the common layers still
     * apply. */
    err = ignore_ruleset(ignore_rules, opts->profile, &profile_rules);
    if (err) goto cleanup;

    /* The profile's sheet, from the tree the stage opened at: the branch's own
     * bytes, an empty sheet for a new profile (the loader's contract). Read before
     * the walk, which asks it what the branch already claims beneath a name
     * (add_admit). The decide phase gives up a claim a listed file takes the
     * place of, the captures write the rest, and it is saved once. A sheet that
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
     * does the refusal the completed selection owes; the command's arena's, as
     * every view is. */
    err = manifest_build_tree(
        repo, stage_tree(stage), opts->profile, mounts, ctx->arena, &view
    );
    if (err) goto cleanup;

    /* The tree this commit will write, as its names are chosen: the branch's
     * entries, and every blob this command lists from here on (sys/stage.h).
     * The walk and the argument arm record into it as they list; the sheet's
     * directories are read against it once more, below. */
    err = stage_admission_create(stage, &admission);
    if (err) goto cleanup;

    /* Collect every path to add, expanding directories. Each listing is named
     * once, by the claim standing at it; what the walk finds beneath one already
     * listed is named from that claim. */
    walk.profile = opts->profile;
    walk.view = view;
    walk.rules = profile_rules;
    walk.excludes = excludes;
    walk.source = ignore_source(ignore_rules);
    walk.admission = admission;
    walk.sheet = metadata;
    walk.listing = hashmap_borrow(ctx->arena, 0);
    ptr_array_init(&walk.files, ctx->arena);
    ptr_array_init(&walk.directories, ctx->arena);

    /* Process each input path. Two parsing heads — a storage shape and a filesystem
     * shape — and one ladder beneath them: what stands at the path, this command's
     * own listing, the name, the rules, the claim the profile holds at the path,
     * the branch's shape, and the listing itself. `typed` is the whole of what
     * the user's choice of shape means, and it discriminates at exactly four
     * places: the absent path's hint, the three sentences the dedup gate owes,
     * the choice of name, and the membership gate that is the one place a second
     * name for one path can be born. */
    for (size_t i = 0; i < opts->file_count; i++) {
        const char *file = opts->files[i];
        const char *filesystem_path = NULL;
        const char *typed = NULL;   /* The name the user wrote, or NULL for a spelling */

        if (label_prefixes(file)) {
            /* A storage shape, read by the one resolver that reads input shapes
             * — a name and never a path, since the same predicate dispatched
             * here. It validates the shape and sheds a trailing slash, so `add
             * p home/dir/` is the spelling every other consumer already accepts,
             * and `add p home/` names the namespace's own directory as `add p
             * ~` names the same place by its spelling (infra/path.h). */
            path_input_t arg;
            err = path_input_resolve(file, ctx->arena, &arg);
            if (err) goto cleanup;

            /* The keys the predicate above can hand this head, and what each is
             * to a capture (infra/path.h). */
            switch (arg.key) {
                case PATH_KEY_STORAGE:
                    typed = arg.storage_path;
                    break;

                case PATH_KEY_FILESYSTEM:
                    /* The shape predicate above dispatched here, so the resolver
                     * answered the storage key and never this one: a filesystem
                     * spelling is add's own grammar and reaches add_spell instead.
                     * Said, so a third key is a decision at this head rather
                     * than a read of the member the tag does not name. */
                    CHECK_ARG(false, "add's storage head was handed a filesystem path");
            }

            /* Where the claim stands, through the table: home/ and root/ resolve
             * for every profile, custom/ through this one's binding — the row's,
             * or the flag's. A custom/ path with no binding names nothing on
             * this machine, and the way to give it one is the flag. The table's
             * answer is absolute and the arena's already. */
            filesystem_path = mount_resolve(ctx->arena, mounts, opts->profile, typed);
            if (!filesystem_path) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "'%s' has no filesystem path for '%s' on this machine\n"
                    "  dotta add %s --target /path %s", file, opts->profile,
                    opts->profile, file
                );
                goto cleanup;
            }
        } else {
            /* Regular filesystem path — as add reads it: the target's when one
             * stands (add_spell), the shell's when none does. The key the walk
             * begins at, and everything it joins beneath is a key too. */
            err = add_spell(file, target, ctx->arena, &filesystem_path);
            if (err) {
                err = error_wrap(err, "Failed to resolve path '%s'", file);
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
        const fs_occupant_t occupant = fs_lstat_occupant(filesystem_path, &st);
        switch (occupant) {
            case FS_OCCUPANT_NONE: {
                /* Absence has three sentences, and which is owed turns on how
                 * the argument was read: a typed name, an absolute path the target
                 * re-rooted, or a path read where it was typed. Most specific
                 * first, so each arm leaves on its own. */
                if (typed) {
                    err = ERROR(
                        ERR_NOT_FOUND, "Path not found: %s (storage path '%s')\n"
                        "For a relative path, write ./%s", filesystem_path, file, file
                    );
                    goto cleanup;
                }

                /* Re-rooted, or spelled where it stands: the boundary is asked
                 * once more, on the argument itself, because the sentence owed
                 * turns on the answer and a guess about `..` would be worse than
                 * none. Only here, where the path ends the command. Nothing is
                 * re-rooted under a target that is not there. */
                if (target && file[0] == '/') {
                    if (!add_inside(file, target, ctx->arena)) {
                        err = ERROR(
                            ERR_NOT_FOUND, "Path not found: %s\n"
                            "  --target is bound at %s, and an absolute path is "
                            "read inside it, so '%s' was re-rooted beneath it.\n"
                            "  Spell the argument the way the target is spelled, "
                            "or give it relative to the target.",
                            filesystem_path, target, file
                        );
                        goto cleanup;
                    }
                }

                err = ERROR(ERR_NOT_FOUND, "Path not found: %s", filesystem_path);
                goto cleanup;
            }

            case FS_OCCUPANT_UNKNOWN:
                err = error_from_errno(errno, "Cannot access '%s'", filesystem_path);
                goto cleanup;

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

        /* This command's own listing. A path already settled here says nothing
         * new — a second spelling of one argument, or an argument beneath a
         * directory already walked — and a spelling simply moves on. A typed
         * name is the one input that can disagree with what was settled, so it
         * is the only one the gate owes a sentence. One lookup answers both:
         * every path this command listed carries the claim it was listed under
         * (add_list), a root's included, so an entry is a claim and there is no
         * absent value to fold. */
        const manifest_claim_t *listed = hashmap_get(walk.listing, filesystem_path);
        if (listed) {
            if (typed && strcmp(listed->storage_path, typed) != 0) {
                char shown[PATH_MAX];
                output_format_path(filesystem_path, identity()->home, shown, sizeof(shown));
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
         * and otherwise what this profile calls the path — the claim standing
         * there, this command's own or the branch's, else the composition beneath
         * the nearest claim above it, else the label of the root it lies under,
         * which at the root itself is the word alone. */
        const char *storage_path = typed ? typed : manifest_name(
            ctx->arena, view, opts->profile, filesystem_path, walk.listing
        );

        /* What the profile already claims at the path, asked before any rule: a
         * claim is no discovery, and meets the -e layer alone (add_verdict).
         * The row is the path's own authority on kind too, a derived one included
         * — it says the profile holds a subtree beneath the path, which a path
         * that became a file cannot carry — and it is the one reading that sees
         * a claim with nothing beneath it for either document to find, where
         * the name's own admission below covers the rest. */
        const manifest_row_t *held = manifest_lookup_claim(
            view, opts->profile, filesystem_path
        );

        /* A path named on the command line meets the rules the walk would ask
         * of it, but a verdict against it is an error, not a silent skip: the
         * user asked for it by name, and the answer says which rule stands in
         * the way and how to get past it (add_refuse_excluded). A re-capture of
         * a claim meets -e alone, so no rule of discovery refuses it. The source
         * tree's rules read where the path physically stands and not the name,
         * over every rung of it, so a root standing inside a repository whose
         * rules name it, or name a directory above it, is refused here as any
         * ignored directory is, unless the profile already tracks it; at "/"
         * the path names no entry and asks nothing. */
        ignore_verdict_t verdict;
        err = add_verdict(&walk, held, filesystem_path, storage_path, kind, &verdict);
        if (err) {
            /* Git's rules could not be read for the path, the four having excluded
             * nothing: never read as admitted, since what could not be read may
             * be what git excludes. The failure names what could not be read;
             * the way past is the repository's to mend, or the switch, the
             * refusal's hint — read before the sudo one add_dispatch attaches
             * where the run's identity met the refusal. No -e is offered: a `!`
             * at a rung that cannot be read re-opens it (core/ignore.h
             * ignore_verdict), which would admit what git may exclude, and a
             * repository that fails whole fails at every rung inside it. */
            err = error_wrap(
                err, "Cannot tell whether '%s' is ignored by Git's ignore rules", file
            );
            err = error_hint(
                err, "Turn Git's rules off with respect_gitignore = false to add it anyway"
            );
            goto cleanup;
        }
        if (verdict.origin != IGNORE_ORIGIN_NONE) {
            err = add_refuse_excluded(&walk, file, storage_path, kind, held, &verdict);
            goto cleanup;
        }

        /* A kind the claim contradicts: what stands there now is not what the
         * profile holds there. The removal is name-shaped: it takes that claim
         * and everything beneath it, under every topology, where a
         * filesystem-shaped one addresses another key at a binder's own
         * spelling. */
        if (held && path_type_kind(held->type) != kind) {
            char shown[PATH_MAX];
            output_format_path(filesystem_path, identity()->home, shown, sizeof(shown));
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

        /* The name, by the profile's own claims — the authority on names. A typed
         * name is the one input the namer did not produce, so it is the one place
         * a second name for one path can be born; a name the profile already
         * holds is a re-capture, gated by --force at the pre-flight, and a derived
         * claim names nothing and blocks nothing (core/manifest.h
         * manifest_is_derived). revert.c refuse_second_name is the same condition
         * for the same rule, with its own verb's remedies. */
        if (typed && held && !manifest_is_derived(held) &&
            !manifest_holds_name(view, opts->profile, filesystem_path, typed)) {
            char shown[PATH_MAX];
            output_format_path(filesystem_path, identity()->home, shown, sizeof(shown));
            err = ERROR(
                ERR_INVALID_ARG,
                "Profile '%s' names '%s' as '%s'\n\n"
                "'%s' would be a second name for it, and a profile names a "
                "path once.\n"
                "  dotta add %s --force %s   re-captures it under the name "
                "it has\n"
                "  dotta remove %s %s   gives that name up first",
                opts->profile, shown, held->storage_path, typed,
                opts->profile, held->storage_path,
                opts->profile, held->storage_path
            );
            goto cleanup;
        }

        /* What the commit can hold, before a byte is read. The verdict a walked
         * entry answers with a skip is an error here: the user asked for this
         * path by name, and working around a claim they did not mention is not
         * this command's to do. */
        err = add_admit(&walk, storage_path, kind);
        if (err) {
            err = error_wrap(err, "Cannot add '%s'", file);
            goto cleanup;
        }

        add_list(&walk, filesystem_path, storage_path, occupant);

        if (kind == PATH_KIND_DIRECTORY) {
            /* The walk's one scratch, freed whatever the walk met: every frame's
             * listing and every entry's strings, none of which outlives it. */
            arena_t *scratch = arena_create(0);
            err = add_collect(&walk, scratch, filesystem_path, 0);
            arena_free(scratch);
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
                dirs_found, dirs_found == 1 ? "y" : "ies", filesystem_path
            );
        }
    }

    /* A file listed at a name the sheet claims a directory at takes that claim's
     * place: its capture replaces the item, kind and all (metadata_add_item),
     * or retires it where the capture claims nothing (a link). The kind question
     * the listing asked of the view is why that is the whole story — a claim
     * the view held at this path would have refused a file here — so what gives
     * way is a claim the view already reads as no claim, the tree holding a blob
     * at its name, or as another name's, the settle having kept another member.
     * Given up here, with the selection complete, so that the sheet the sweep
     * below reads is the one the commit will carry. */
    for (size_t i = 0; i < walk.files.count; i++) {
        const path_t *path = walk.files.entries[i];
        const metadata_item_t *standing = metadata_lookup(
            metadata, path->claim.storage_path
        );
        if (standing && standing->kind == PATH_KIND_DIRECTORY) {
            metadata_remove_item(metadata, path->claim.storage_path);
        }
    }

    /* The two documents this commit carries name one namespace, and this is where
     * they meet: with the selection complete, before any byte is read. The tree
     * holds every blob and the sheet the directories a tree cannot, and a blob
     * leaves no room for a directory at its name or for anything beneath it.
     *
     * Every listing met both documents as the command stood when it was made
     * (add_admit): the admission held the branch's entries and every blob listed
     * before, and the sheet held the branch's claims. Two readings remain, and
     * they are this pass's two loops:
     *   - the branch's own claims, against every name the tree will hold. A blob
     *     this command chose above one was refused at its name, and a file listed
     *     at one's own name has just taken its place, so what refuses here is a
     *     contradiction the branch arrived with. Nothing repairs it silently,
     *     and its remedies are two — `dotta remove` gives up a claim beneath a
     *     blob, and a forced re-capture of the file takes the place of one at
     *     the blob's own name — so no one line names them;
     *   - this command's own directories, against the blobs chosen after them.
     *     The sheet holds them only once they are captured, so no listing could
     *     see them.
     *
     * That is every directory the commit's sheet will claim, and nothing the
     * captures do can escape it. The directory loop writes the keys the second
     * loop asks about, under the same kind. The file captures write file items,
     * which claim no room beneath them, at keys where no directory claim still
     * stands. The ancestry pass claims proper prefixes of names this command
     * captured (metadata_capture_ancestors: the mount root is excluded by where
     * the scan starts and the leaf by where it ends); a blob at or above such a
     * prefix is a proper prefix of the captured name itself, which that name's
     * own admission refused. It also retires claims, and giving one up cannot
     * make room narrower.
     */
    size_t item_count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &item_count);
    for (size_t i = 0; i < item_count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;

        err = stage_admit_subtree(admission, items[i]->key);
        if (err) {
            /* The stage names the storage path and the obstruction; the wrap
             * says whose claim it is and that a claim is the subject, so an add
             * of one path does not answer with a sentence about another the user
             * never typed. */
            err = error_wrap(
                err, "Profile '%s' claims a directory its tree cannot hold",
                opts->profile
            );
            goto cleanup;
        }
    }
    for (size_t i = 0; i < walk.directories.count; i++) {
        const path_t *path = walk.directories.entries[i];

        err = stage_admit_subtree(admission, path->claim.storage_path);
        if (err) {
            /* A pair this command made, named by its directory — as the argument
             * arm names it in the other order, where the directory's own admission
             * met the blob first. */
            char shown[PATH_MAX];
            output_format_path(
                path->filesystem_path, identity()->home, shown, sizeof(shown)
            );
            err = error_wrap(err, "Cannot add '%s'", shown);
            goto cleanup;
        }
    }

    /* The selection is complete, so the question of names its parts cannot answer
     * is asked here: does this command abandon a name it moves? */
    err = add_refuse_moves(&walk);
    if (err) goto cleanup;

    /* What the branch already holds under a name this command chose. Asked over
     * the whole listing before a byte is read, so a refusal at the last file
     * does not leave the first four in the object database. Keyed by the name
     * and not by the path: at a path the profile names twice, a typed re-capture
     * of the loser must be gated by the name the user typed, not by the row that
     * happens to stand there. The decision pass below keeps its own
     * git_index_get_bypath for the encryption policy's priority-3 read — two
     * questions, one lookup each. */
    if (!opts->force) {
        for (size_t i = 0; i < walk.files.count; i++) {
            const path_t *path = walk.files.entries[i];
            if (!git_index_get_bypath(
                stage_index(stage), path->claim.storage_path, 0
                )) {
                continue;
            }
            err = ERROR(
                ERR_EXISTS, "File '%s' (as '%s') already exists in profile '%s'. "
                "Use --force to overwrite.", path->filesystem_path,
                path->claim.storage_path, opts->profile
            );
            goto cleanup;
        }
    }

    /* The encryption decision, taken with the name and never with a source byte.
     * Its inputs are the config, the name this command chose, the request, and
     * the entry the branch holds at that name — judged by its mode and its header
     * through the index the stage opened on, never by a claim, with no key and
     * no source file (infra/content.h content_classify) — so it is a decision
     * and is made with the others, before any capture runs. The capture is told
     * (add_capture).
     *
     * A regular file alone: a link's entry is its target and carries no seal
     * (core/policy.h), so the policy is never asked about one; and the capture
     * a link was listed for is the link's — a regular file standing there by
     * then is refused by it, never stored under a verdict nobody reached.
     *
     * After the held-entry gate, so an entry is met here only under --force;
     * with none there are no prior bytes, and priorities 4 and 5 decide. A blob
     * that cannot be read is an error, not "not encrypted": a sniff that defaulted
     * would flip the policy silently. And a verdict that seals is refused here
     * when this run can never seal — encryption turned off — rather than at a
     * capture the others would already have preceded into the object database. */
    for (size_t i = 0; i < walk.files.count; i++) {
        path_t *path = walk.files.entries[i];
        if (path->occupant == FS_OCCUPANT_SYMLINK) continue;

        const char *storage_path = path->claim.storage_path;
        const git_index_entry *prior = git_index_get_bypath(
            stage_index(stage), storage_path, 0
        );
        content_kind_t prior_kind = CONTENT_PLAINTEXT;
        if (prior) {
            err = content_classify(repo, &prior->id, prior->mode, &prior_kind, NULL);
            if (err) {
                err = error_wrap(
                    err, "Failed to classify the committed bytes of '%s'",
                    storage_path
                );
                goto cleanup;
            }
        }

        /* Returned as they are. The policy's refusals are the user's to read —
         * they name the path, the fact that stood and the way on — and a wrap
         * saying the verdict could not be reached would say the opposite of what
         * happened; the encryption switch's refusal names the path and its cause
         * the same way. */
        err = encryption_policy_should_encrypt(
            config, storage_path, opts->encrypt_mode,
            prior_kind != CONTENT_PLAINTEXT, &path->should_encrypt
        );
        if (err) goto cleanup;

        if (path->should_encrypt) {
            err = content_require_encryption(ctx->run.keymgr, storage_path);
            if (err) goto cleanup;
        }
    }

    /* A preview ends here, and this is the whole of the difference between the
     * two modes: everything above decided, and everything below reads the sources
     * and writes.
     *
     * So a preview answers what the selection answers — every name, admitted
     * together against the tree and the sheet the commit would carry (sys/stage.h,
     * the admission); the name a directory claim would abandon; the entries the
     * branch holds under a chosen name; and each file's encryption verdict, with
     * whether this run could seal at all — and a run refused over any of them
     * is a preview refused in the same words. What only a source, or a later
     * writer, can say is below: bytes that cannot be read, a plaintext that would
     * read as ciphertext, the key a seal needs, an owner a claim cannot name, a
     * kind that changes before its capture, the chain above each path, whether
     * the commit moves anything, and the record (cmds/add.h).
     *
     * And nothing above wrote anything of dotta's: the state was opened in the
     * read shape and holds no lock (include/runtime.h), the stage and the admission
     * are indexes in memory over the tree the open read — Git's empty tree for
     * a profile that does not exist yet, read and never written (sys/stage.h) —
     * and the sheet's edit is dropped unsaved. The pre-add hook was told it is
     * a dry run; the post-add hook is below. */
    if (opts->dry_run) {
        /* The captures' own lines, in their order and in the future tense: every
         * directory, then every file, by the capture its listed occupant chooses
         * and sealed as the decision pass said. What a capture reads off its
         * source — the mode and the owner a claim takes — is the capture's. */
        for (size_t i = 0; i < walk.directories.count; i++) {
            const path_t *path = walk.directories.entries[i];
            output_info(
                out, OUTPUT_VERBOSE, "Would track directory: %s -> %s",
                path->filesystem_path, path->claim.storage_path
            );
        }
        for (size_t i = 0; i < walk.files.count; i++) {
            const path_t *path = walk.files.entries[i];
            if (path->should_encrypt) {
                output_info(
                    out, OUTPUT_VERBOSE, "Would encrypt: %s -> %s",
                    path->filesystem_path, path->claim.storage_path
                );
            }
            output_info(
                out, OUTPUT_VERBOSE,
                path->occupant == FS_OCCUPANT_SYMLINK ? "Would add symlink: %s -> %s"
                                                      : "Would add: %s -> %s",
                path->filesystem_path, path->claim.storage_path
            );
        }

        /* The receipt's block in the future tense, arm for arm but one: whether
         * the commit moves anything is the bytes' to say, so a preview counts
         * what it would capture and "Nothing changed" is the run's alone. */
        if (walk.files.count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Would add %zu file%s to profile '%s'",
                walk.files.count, walk.files.count == 1 ? "" : "s", opts->profile
            );
            if (walk.directories.count > 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Would track %zu director%s for change detection",
                    walk.directories.count, walk.directories.count == 1 ? "y" : "ies"
                );
            }
        } else {
            output_info(
                out, OUTPUT_NORMAL, "Would track %zu director%s in profile '%s'",
                walk.directories.count, walk.directories.count == 1 ? "y" : "ies",
                opts->profile
            );
        }
        add_print_labels(&walk);
        if (!profile_exists) {
            output_info(
                out, OUTPUT_NORMAL, "Would create profile '%s' and enable it",
                opts->profile
            );
        }
        output_gap(out, OUTPUT_NORMAL);

        /* The one fact of the record a preview has: no row holds the profile
         * and this add does not create it — the tail's question, asked before
         * any phase has run, off the rows the dispatcher loaded. What the rows
         * would take otherwise is the post-commit view's to say, and a preview
         * builds none. */
        if (profile_exists && !state_enabled(state, opts->profile)) {
            output_info(
                out, OUTPUT_NORMAL,
                "Profile not enabled - nothing would be marked as deployed"
            );
            add_print_enable(out, opts->profile, opts->target, view);
            output_gap(out, OUTPUT_NORMAL);
        }

        output_info(out, OUTPUT_NORMAL, "Dry run: nothing was committed");
        goto cleanup;                                    /* err is NULL */
    }

    /* Capture directory metadata for every directory this command listed.
     *
     * The walk lists every directory it walks into — including the argument itself
     * — so this loop captures the full tree, not just the named entry points. A
     * root named by its spelling ($HOME, "/", --target) or by its label's word
     * (`add p home/`) is listed like any directory, and captured like one.
     *
     * Required, where update's sibling loop warns and carries on: a directory
     * this command listed is the *name* its walk composed beneath, so a claim
     * that does not land leaves the files captured under a name nothing authors
     * — and the listing, which add_refuse_moves reads as a promise of the commit,
     * would be a wish (core/metadata.h metadata_capture_directory). Ahead of
     * the file captures for the same reason: a directory that cannot be claimed
     * is found before any source blob reaches the object database.
     */
    for (size_t i = 0; i < walk.directories.count; i++) {
        path_t *path = walk.directories.entries[i];
        const char *storage_path = path->claim.storage_path;

        /* Stat directory to capture mode (and ownership if root/custom). lstat
         * + S_ISDIR: the race guard update's capture arm has. The walk classified
         * with lstat, so anything else standing here changed since. */
        struct stat dir_stat;
        if (fs_lstat(path->filesystem_path, &dir_stat) != 0) {
            err = error_from_errno(
                errno, "Failed to stat directory '%s'", path->filesystem_path
            );
            goto cleanup;
        }
        if (!S_ISDIR(dir_stat.st_mode)) {
            err = ERROR(
                ERR_CONFLICT,
                "Cannot add '%s': it was walked as a directory and its type "
                "changed on disk", path->filesystem_path
            );
            goto cleanup;
        }

        /* Capture directory metadata using stat data. The walk entered this
         * directory, so the claim is a tracked one: the profile tracks the path
         * itself, scans it for new files and converges its attributes. */
        metadata_item_t *dir_item = NULL;
        err = metadata_capture_directory(storage_path, &dir_stat, true, &dir_item);
        if (err) {
            err = error_wrap(
                err, "Failed to capture directory '%s'", path->filesystem_path
            );
            goto cleanup;
        }

        /* What the capture committed, as the record keeps it: the directory the
         * guard above just held it to, and its claim — no content, which a
         * directory never confirms — taken before the sheet takes the item */
        path->record = (state_record_t){
            .filesystem_path = path->filesystem_path,
            .storage_path = storage_path,
            .profile = opts->profile,
            .kind = FS_OCCUPANT_DIRECTORY,
        };
        metadata_item_claim(dir_item, ctx->arena, &path->record);

        /* Verbose output before consuming the item */
        add_print_capture(out, "directory metadata", path->filesystem_path, dir_item);

        /* Add directory to metadata */
        metadata_add_item(metadata, &dir_item);
        output_info(
            out, OUTPUT_VERBOSE, "Tracked directory: %s -> %s", path->filesystem_path,
            storage_path
        );
    }

    /* Every file, as it was listed and as the decision pass sealed it
     * (add_capture). Each capture's record is kept on the path: the blob the
     * put wrote and the stat of the bytes committed, which a later lstat could
     * not promise. */
    for (size_t i = 0; i < walk.files.count; i++) {
        path_t *path = walk.files.entries[i];

        err = add_capture(ctx, stage, opts->profile, path, metadata);
        if (err) {
            err = error_wrap(err, "Failed to add file '%s'", path->filesystem_path);
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
            const path_t *path = chains[b]->entries[i];

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

    /* A new profile's .dottaignore: the template, on the stage beside the sheet
     * — the two blobs this commit carries that no capture wrote. Here rather
     * than at the orphan's open, where the add has decided nothing yet: stage_put
     * writes the blob to the object database at once, so a refusal between the
     * two — a path that is not there, an argument the rules exclude, an unreadable
     * file — would leave it there for a profile that was never created. */
    if (profile_created) {
        const char *template = ignore_profile_template();
        err = stage_put(
            stage, ".dottaignore", template, strlen(template), GIT_FILEMODE_BLOB,
            NULL
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
    err = add_commit(&walk, stage, opts, &committed);
    if (err) goto cleanup;

    /* Write the record - auto-enable new profiles, anchor for enabled ones
     *
     * Every path was captured from disk, so its record — what the capture committed
     * — is written now rather than left for a later status to confirm: an ownership
     * event whether or not the commit moved the branch, since the capture's stat
     * is fresh either way. The view itself is computed at every load and needs
     * no update.
     *
     * For NEW profiles: Auto-enable provides intuitive UX (creating via 'add'
     * enables it). UX Decision: Creating a profile via 'add' should enable it
     * automatically. This matches user expectations: "I just added a file, it
     * should be active." For EXISTING profiles: Standard behavior (anchor only
     * if already enabled).
     *
     * Both end in the same loop: one view build says which rows this profile
     * won, and add's contribution is the ownership event.
     *
     * Non-fatal, and rendered in the tail with the counts: the phase's fate is
     * its error and a warning above the ✓ lines would read as a refusal of the
     * add, which a record failure is not. The error is therefore carried from
     * here to the screen that renders it, and the region between holds no exit.
     */
    receipt_t receipt = { 0 };

    error_t record_err = add_write_record(
        ctx, mounts, opts->profile, target, profile_created,
        &walk.files, &walk.directories, &ancestry_retired, &receipt
    );

    /* Execute post-add hook. The record phase settled its own transaction before
     * returning, so the hook meets the database this run leaves — committed or
     * rolled back — and not a lock nothing will use again. */
    hook_fire_post(config, out, &hook_inv);

    /* Show summary on success. Every argument lists itself or ends the command,
     * and both capture loops are total over their lists, so there is always
     * something to report here. */

    /* What the capture took, both kinds. A commit that moved nothing names what
     * it found already standing, both kinds in one phrase — the directories were
     * captured as surely as the files were. One that landed names its files on
     * the ✓ line and its directories beneath them, or on a ✓ line of their own
     * when they are all it took. */
    if (!committed) {
        char counts[64];
        output_format_counts(
            walk.files.count, walk.directories.count, counts, sizeof(counts)
        );
        output_info(
            out, OUTPUT_NORMAL,
            "Nothing changed in profile '%s' (%s already as captured)",
            opts->profile, counts
        );
    } else if (walk.files.count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Added %zu file%s to profile '%s'",
            walk.files.count, walk.files.count == 1 ? "" : "s",
            opts->profile
        );
        if (walk.directories.count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "Tracking %zu director%s for change detection",
                walk.directories.count, walk.directories.count == 1 ? "y" : "ies"
            );
        }
    } else {
        /* Directory-only add */
        output_success(
            out, OUTPUT_NORMAL, "Tracking %zu director%s in profile '%s'",
            walk.directories.count, walk.directories.count == 1 ? "y" : "ies",
            opts->profile
        );
    }

    /* The labels the names landed under, beneath the counts they sum to and in
     * every arm — a re-capture that moved no byte included, the label a path
     * keeps being its claim's and not the command line's. Under the binding this
     * command's table holds: the flag's when the run brought one, else the row's
     * the pre-flight copied. */
    add_print_labels(&walk);

    /* The branch is Git's fact and stands whatever the record did; the enabling
     * is a row, which a failed phase can leave standing (a branch recreated over
     * a leftover row) and a successful one cannot invent. So the second clause
     * keys on membership — the handle's rows, as the phase settled them (receipt_t)
     * — not on the fate. */
    if (profile_created) {
        output_success(
            out, OUTPUT_NORMAL,
            state_enabled(state, opts->profile) ? "Profile '%s' created and enabled"
                                                : "Profile '%s' created",
            opts->profile
        );
    }

    output_gap(out, OUTPUT_NORMAL);

    /* The record phase's own screen, below the ✓ lines the add earned: the cause
     * and what it left standing, what the rows took, or the fact that no row
     * holds this profile. The fate is the error — the receipt carries no field
     * for it — and it renders here with the other two rather than at the call. */
    if (record_err) {
        output_warning(
            out, OUTPUT_NORMAL, "Failed to update the record: %s",
            error_message(record_err)
        );

        /* Nothing this phase wrote stands: the first refused statement ended
         * the pass and the rollback took the rest, so every path's record is
         * what it was — an ownership event that stood still stands, and a path
         * with no record has none. */
        output_info(
            out, OUTPUT_NORMAL,
            "The record was not written - what it already held stands"
        );
    } else if (state_enabled(state, opts->profile)) {
        /* What the record took of what the capture listed. The unit is the path
         * — one row per managed path, both kinds — and the kinds are named where
         * they were captured, above. Never zero: every argument lists itself or
         * ends the command (cmd_add's loop), so the count line and the notes
         * below always have a capture to speak of. */
        const size_t captured = walk.files.count + walk.directories.count;
        const bool whole = receipt.anchored == captured;

        if (whole) {
            output_info(
                out, OUTPUT_NORMAL, "Record updated (%zu path%s marked as deployed)",
                captured, captured == 1 ? "" : "s"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL,
                "Record updated (%zu/%zu path%s marked as deployed)",
                receipt.anchored, captured, captured == 1 ? "" : "s"
            );

            /* Each cause named by the count that checked it, never by the shortfall
             * (receipt_t): a row of another profile is an override, a row of
             * this one under another of its own names is an unused path, whose
             * repair the health channel carries on the status screen, and a name
             * the profile no longer holds is one a later commit removed. The
             * three sum to the shortfall exactly. */
            if (receipt.overridden > 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Note: %zu path%s overridden by higher-precedence profiles",
                    receipt.overridden, receipt.overridden == 1 ? "" : "s"
                );
            }
            if (receipt.unkept > 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Note: %zu path%s captured under an unused path; "
                    "'dotta status -v' names %s",
                    receipt.unkept, receipt.unkept == 1 ? "" : "s",
                    receipt.unkept == 1 ? "it" : "them"
                );
            }
            if (receipt.gone > 0) {
                output_info(
                    out, OUTPUT_NORMAL,
                    "Note: %zu path%s no longer in profile '%s'; a later commit "
                    "removed %s",
                    receipt.gone, receipt.gone == 1 ? "" : "s", opts->profile,
                    receipt.gone == 1 ? "it" : "them"
                );
            }
        }
        if (receipt.taken_over > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "Note: %zu path%s taken over from other profiles",
                receipt.taken_over, receipt.taken_over == 1 ? "" : "s"
            );
        }
        /* Why nothing needs deploying: the bytes were read off disk, so the record
         * names them deployed without an apply having run — what this add captured;
         * a commit another writer landed since is Git's move past it, the next
         * status's to name. Said only where it is true of every path on the line
         * — a capture a row did not take is not standing at the winner's blob. */
        if (whole) {
            output_hint(
                out, OUTPUT_NORMAL, "Paths captured from filesystem (already deployed)"
            );
        }
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta status' to verify");
    } else {
        output_info(
            out, OUTPUT_NORMAL, "Profile not enabled - nothing marked as deployed"
        );
    }

    /* The remedy the run leaves, keyed on the one fact that decides it. No row
     * holding this profile makes enable the first verb whichever fate brought
     * the run here — the tree is shaped and enable is what gives it a place
     * (add_print_enable, which the preview's screen reads too). A row that does
     * hold it leaves only a failure to answer, and the retry is this add again
     * with --force over a branch that now holds the bytes: an apply re-earns
     * the event for the files it adopts and never for a directory, and an unowned
     * directory is released at scope exit where an owned one is pruned. */
    if (!state_enabled(state, opts->profile)) {
        add_print_enable(out, opts->profile, opts->target, view);
    } else if (record_err) {
        output_hint(
            out, OUTPUT_NORMAL, "Re-run this add with --force to record these paths"
        );
    }

cleanup:
    /* Free resources in reverse order of allocation. The listing, the view and
     * the source filter are the arena's. */
    if (metadata) metadata_free(metadata);
    stage_admission_free(admission);
    stage_free(stage);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the raw positional bucket into `profile` and `files[]` — the one place
 * the arguments' shape is judged, which cmd_add trusts:
 *   1. -p/--profile was given: every positional is a file path.
 *   2. -p not given: first positional is the profile, rest are files.
 *
 * The count check lives here, after the routing, so the error message can reference
 * the effective invariant rather than a raw count.
 */
static error_t add_post_parse(
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
 * then filesystem paths, listed under the binding the command reads them under
 * when --target re-roots them. A new profile's name is typed, not offered.
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
    const char *profile = o->profile ? o->profile : o->positional_args[0];
    return completion_paths_under(ctx, out, profile, o->target, at->current)
        ? ARGS_WANT_NONE : ARGS_WANT_FILES;
}

static error_t add_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    error_t err = cmd_add(ctx, (const cmd_add_options_t *) opts_v);

    /* A refusal the invoker met reading a source — the walk's listing and lstat,
     * the open behind the capture (infra/content), the existence check — ends
     * the add before anything durable is written: the stage is in memory and
     * the commit is after the walk. The code is enough to say so without matching
     * prose: ERR_PERMISSION is the bits refusing the identity the run held (EACCES)
     * and never an answer dotta looked up (base/error.h), and everything add
     * reads is a source. A run that holds no root has not asked as root, which
     * sys/filesystem's second try would — an EPERM codes ERR_FS and is offered
     * nothing, a flag, SIP, TCC or a sandbox refusing root as flatly. So the
     * one thing left to say is sudo, as an offer — a hint, the refusal standing
     * as the fact: a policy may deny root the read as well, and the bits are
     * the owner's to change besides. */
    if (error_code(err) == ERR_PERMISSION && !identity()->privileged) {
        err = error_hint(err, "Re-run under sudo to read it");
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
        "n dry-run",
        cmd_add_options_t,           dry_run,
        "Preview without writing"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_add_options_t,           verbosity,        DOTTA_VERBOSITY_VERBOSE,
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
        "under root/ and custom/.\n"
        "\n"
        "-n shows what the add would do and writes nothing. It refuses what\n"
        "the add would refuse about names, but captures no file's contents,\n"
        "so a file that cannot be read or needs a key is only found by the\n"
        "add. -v lists each path with the name it would take.\n",
    .notes       =
        "Exclude Patterns:\n"
        "  Glob syntax with *, ?, [abc]. Flag is repeatable.\n"
        "    --exclude '*.log'                    # Skip .log files\n"
        "    --exclude '.git/*'                   # Skip .git directory\n"
        "    --exclude '*.log' --exclude '*.tmp'  # Multiple patterns\n",
    .examples    =
        "  %s add global ~/.bashrc                   # Basic add\n"
        "  %s add darwin ~/.config/nvim              # Directory\n"
        "  %s add -n -v darwin ~/.config/nvim        # Preview the names\n"
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
