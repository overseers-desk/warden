# Rules: working with the Dropbox sharing API

These rules summarise behaviour observed while writing and using `dropbox-acl-manager.tcl`. Read them before adding any sharing-API code path. The recurring failure mode in this codebase has been treating the API surface as if it matched its semantics; most of these rules are points where the surface lies.

## unshare_folder is async; poll check_job_status

`POST /2/sharing/unshare_folder` returns `LaunchEmptyResult`, a union of:

- `{".tag": "complete"}`: ran synchronously, rare.
- `{".tag": "async_job_id", "async_job_id": "..."}`: usual path; the actual outcome appears later via `/2/sharing/check_job_status`.

Treating the launch's HTTP 200 as success is wrong. The job can fail server-side seconds to minutes later. Poll until `{".tag": "complete"}` or `{".tag": "failed"}`. The same async pattern applies to `/2/sharing/share_folder`, `/2/sharing/set_access_inheritance`, `/2/sharing/transfer_folder`, and other sharing-mutation endpoints.

## JobStatus.failed nests two levels

Failure shape:

```
{".tag": "failed", "failed": {".tag": "<wrapper_tag>", "<wrapper_tag>": {".tag": "<reason>"}}}
```

The wrapper_tag is the operation-specific error type (e.g. `unshare_folder_error`); the actual reason is one level deeper. Read both. Just the wrapper is the same string for every failure of the same endpoint and gives no diagnostic.

## Sharing-graph nesting is independent of file-tree paths

A folder at the top of the file path can still have `parent_shared_folder_id` pointing to another shared folder. `/2/files/get_metadata` reports `sharing_info.parent_shared_folder_id` only when there is path-tree nesting; for sharing-graph parents, query `/2/sharing/get_folder_metadata` on the sfid.

The Web UI message "within multiple shared folders" refers to sharing-graph nesting, not path-tree nesting. It is misleading on a top-level folder.

## A deleted shared folder's record persists without a path

Deleting a shared folder does not remove its sharing record. `/2/sharing/list_folders` returns the record with empty `path_display`, its sfid persists indefinitely, and public shared links issued before deletion stay LIVE and reachable by anyone holding the URL.

To enumerate the account's no-path shared folders: paginate `/2/sharing/list_folders` and filter for empty `path_display`.

## Child shared folders block parent unshare

Both kinds of shared folder, with a path and without, block their parent's unshare. If any shared folder has `parent_shared_folder_id == X`, then `X` cannot be unshared until that child is itself unshared, recursively. The API surfaces this as nested `no_permission`; the Web UI says "within multiple shared folders". In `list_folders` output, children with a path show non-empty `path_display`; children without a path show it empty. Both must be cleared.

## list_folders omits parent_shared_folder_id for some entries that have a path

Do not trust `list_folders` as the authoritative source for `parent_shared_folder_id`. The field is documented as optional and is reliably present on entries without a path, but on nested shared folders that have a path it is sometimes returned and sometimes silently omitted, even though `/2/sharing/get_folder_metadata` on the same sfid reports it consistently.

The reliable enumeration of children of `parent_sfid` therefore is: list_folders to get all sfids, and for any entry that does not include `parent_shared_folder_id`, re-query that sfid via `get_folder_metadata`. The `dbx_list_children` helper in this codebase does that.

## mount_folder on a no-path child drops its parent_shared_folder_id

When `/2/sharing/mount_folder` is called on a shared folder without a path that previously had `parent_shared_folder_id == X`, the resulting folder (now with a path) has the parent field absent in `get_folder_metadata` output. This is the mechanism that makes the recursive unshare recipe work: the freshly-mounted folder is no longer a "child shared folder" in Dropbox's eyes, so it can be unshared on its own without breaking the parent shared folder's rules. After the child is unshared, the parent loses one obstruction.

## Nested children with a path: move-to-top to sever inheritance

For a shared folder with a path where `parent_shared_folder_id` is set, `/2/sharing/unshare_folder` fails with `no_permission` on a Basic plan. `set_access_inheritance no_inherit` would clear the inheritance, but it is team-only.

The escape hatch is `/2/files/move_v2`. Moving the nested shared folder to a destination outside any shared-folder ancestry (top-level is the simple choice) clears `parent_shared_folder_id` in `get_folder_metadata` output. After the move, `unshare_folder` accepts the call. Dropbox's own help page confirms this: "If a subfolder is moved from a shared folder, the Unshare button will become available."

This works on Basic accounts. The two writes that achieve the same effect (mount-from-no-path and move-from-nested) are interchangeable mechanisms for the underlying state change: clearing `parent_shared_folder_id`.

## Greedy sunset: pair every move-out with a move-back

Each recursive frame in `try_unshare_sfid` that performs a move-to-top also performs a move-back to the original path before returning, regardless of whether the unshare succeeded. The call stack unwinds in reverse order of the moves, so the original tree is reconstructed automatically without any global state: when a deeply-nested frame `Z` returns, `Z` is back at its original path; when its parent frame `Y` then performs its own move-out, the just-restored `Z` is carried with `Y`, and is carried back when `Y`'s move-back runs.

Move-back is best-effort. If the destination is now occupied or an intermediate parent directory is missing, the folder remains at its top-level `new_path` and the script logs that path so the user can manually relocate. Restore failures do not change the function's return value: a successful unshare returns 1 even if its move-back failed.

A move-back into a still-shared parent during the unwind is safe: by the time we move `Y` back into `/X/path/Y` while `X` is still shared, `Y` is a regular (just-unshared) folder, so it becomes a regular subfolder of `X`. No new sharing relationship is created. `X`'s existing members had access to `Y`'s contents via inheritance before the run, so no new exposure arises during the brief window before `X` itself is unshared.

## Recipe: recursive unshare of a folder with shared children

```
try_unshare_sfid(sfid):
    saved_original = get_folder_metadata(sfid).path_display
    revoke any shared links on saved_original
    try unshare_folder(sfid)
    if success: return 1
    if failure tag is no_permission:
        kids = list_children(sfid)               # with-path + no-path
        if kids:
            for each kid:
                if kid has no path: mount_folder(kid)
                try_unshare_sfid(kid)            # recurse
            retry unshare_folder(sfid)
            if success: return 1
        if sfid has path AND has parent_shared_folder_id:
            new_path = move_v2(saved_original -> /<basename>, autorename=true)
            try unshare_folder(sfid)
            move_v2(new_path -> saved_original)  # best-effort restore
            return success-flag-of-unshare
    return 0
```

The recursion bottoms out at leaf shared folders with no children, no parent inheritance, or both. No-path children that get mounted become regular folders at a Dropbox-chosen path (often top-level); the recursion does not move them back, because their original location no longer existed. Children that already had a path and got moved out are restored by their own frame's move-back.

## set_access_inheritance is gated to team accounts

Returns HTTP 409 `no_permission` for Basic personal accounts, even when the user owns the target sfid. Per Dropbox docs the endpoint is "only permitted for shared folders in a shared team root". Skip this avenue on Basic accounts; it is not a permissions issue with the specific folder.

## /2/files/restore is for files only

There is no API to restore a deleted folder in one call. For a deleted shared folder, `/2/sharing/mount_folder` on the surviving sfid is the practical equivalent: it brings the folder and its files back without requiring per-file revs.

## list_folder_members may omit the calling user

For shared folders where the caller's access is inherited from a parent, `/2/sharing/list_folder_members` can list only the explicit members and omit the calling user. Do not infer absence of the calling user from this output alone; cross-check with `/2/users/get_current_account` before drawing conclusions about ownership.

## list_folder recursive=true includes the queried path

When `/2/files/list_folder` is called with `recursive=true`, the queried path itself is one of the entries returned (as the first entry). Filter by `path_lower` equality with the root before treating entries as descendants.

## list_folder_members marks inheritance on the record

Each member record in `/2/sharing/list_folder_members` carries `is_inherited`; an inherited record additionally carries `inherited_access_type`. A nested share therefore reports both its own members (`is_inherited: false`) and members reaching it from ancestor shares (`is_inherited: true`) in one call, so classifying direct vs inherited membership needs no ancestor walk. The walk is still needed to name which ancestor a membership comes from, and for links.

## The file id ("id:...") round-trips for every folder

`/2/files/get_metadata` accepts the `id:` form in its `path` argument and resolves it for shared roots, nested shares, and plain unshared folders alike. For folders, `sharing_info` in the same response carries `shared_folder_id` and, when nested, `parent_shared_folder_id`, so the sharing-graph ancestor chain is reachable from file metadata. The `id:` form is the stable folder reference; a shared-folder id (sfid) appears and disappears with share state.

## Viewer members work on this Basic account

`add_folder_member` with `access_level: viewer` and an email selector returns HTTP 200 on this Basic account, and the invitee appears with `access_type: viewer` (observed live on a sacrificial folder, 2026-08-14). The API spec's doc string ("adding a read-only member ... can only be performed by users that have upgraded to a Pro or Business plan", `insufficient_plan`) did not fire. Live shares on the account also hold accepted viewer members. So read-only grants are addable here; treat `insufficient_plan` as a runtime error to surface if it ever appears (perhaps for existing-user selectors or for `update_folder_member` downgrades, both untested), not as a precondition to code around.

## Unshare can change the folder's file id

A folder created as `id:...rKg`, shared, then unshared (`leave_a_copy false`) was deleted moments later under `id:...rOQ`: the id: changed across the share-state transition. The id survives renames and moves, so it is still the right policy reference for folders whose share state the tool does not flip; any unshare/reshare cycle (the sever path) re-resolves the folder by path afterwards and reports when the id no longer matches the policy.

# Story: 2026-05-09, /2023-05 Signed unshare blocked by no-path child sfid 4087858721

## Setting out

The Tcl tool was asked to unshare /2023-05 Signed (sfid 4033641409) via the existing `unshare` command. The calling rclone Dropbox token belonged to the registered owner of that folder. A plain `/2/sharing/unshare_folder` should have completed it.

## Initial false success

The script reported "Done" on first run because it treated the HTTP 200 from `/2/sharing/unshare_folder` as final. That launch had actually returned `{".tag": "async_job_id", ...}`; the real outcome would only have surfaced later via `/2/sharing/check_job_status`. The user, checking in the Dropbox Web UI, saw the folder still shared and the message "Can't unshare a folder that is within multiple shared folders".

## Wrong turns

The Web UI's "within multiple shared folders" was attached to a path-tree-nesting hypothesis without reading the path. /2023-05 Signed has one slash; it is a top-level folder, so the path-nesting story was disproven by the string itself.

The `/2/sharing/list_folder_members` result for the no-path child sfid showed only one member with a personal Gmail address and `is_inherited: true`. Without checking, that was treated as a different person from the rclone token's owner. `/2/users/get_current_account` showed they were the same account; `list_folder_members` simply omits the inheriting caller in some cases.

The polling parser was reading only the outer `JobStatus.failed.tag` (`unshare_folder_error`) and missing the deeper nested reason (`no_permission`).

## What was actually wrong

A subfolder of /2023-05 Signed had once been a shared folder of its own (sfid 4087858721, name "10-05-2023") and had been deleted some time ago. When deleted, the file-tree entry was removed from the visible tree; the sharing record was not. `/2/sharing/list_folders` surfaced it with empty `path_display`, alongside 35 other no-path shared-folder records accumulated through the account's history. `/2/sharing/get_folder_metadata` on sfid 4087858721 returned `parent_shared_folder_id=4033641409`, the same id as /2023-05 Signed. So in Dropbox's sharing graph, /2023-05 Signed had a child shared folder and was therefore not unshareable, even though the file-tree showed it as a leaf top-level folder.

Two live `dropbox.com/scl/fo/9pg4b7ufuxnpbkrl3vohe/...` public links were also still LIVE, pointing at the contents of the no-path folder. These were not visible from /2023-05 Signed's sharing settings because the no-path child was hidden from any path UI.

## Things tried that did not work

`/2/sharing/unshare_folder` directly on sfid 4087858721 launched async, polled, and failed with nested `no_permission`.

`/2/sharing/set_access_inheritance` with `no_inherit` on either sfid (parent or no-path child) returned HTTP 409 `no_permission`. Per Dropbox docs the endpoint is "only permitted for shared folders in a shared team root, and only if the current user is the owner". The account in this story is `account_type: basic` and both folders had `is_team_folder=false, is_inside_team_folder=false`, so the endpoint is gated off entirely.

`/2/files/list_folder` on `/2023-05 Signed/10-05-2023` with `include_deleted=true` returned `path/not_found`. Deleted folders do not respond to path-based list calls.

## What worked

`/2/sharing/mount_folder shared_folder_id=4087858721` succeeded. Dropbox placed the folder at /10-05-2023, top-level, chosen by Dropbox (not under /2023-05 Signed). `/2/sharing/list_shared_links path=/10-05-2023` then surfaced the two live public links, and `/2/sharing/revoke_shared_link` cleared each. `/2/sharing/unshare_folder shared_folder_id=4087858721` then succeeded normally: the async job completed in seconds, the sharing record cleared. Finally `/2/sharing/unshare_folder shared_folder_id=4033641409` (the original target) succeeded with no further obstruction.

## Cleanup

`/2/sharing/get_folder_metadata` for sfid 4087858721 returned `not_a_member`, confirming the sharing record was gone. `/2/files/get_metadata` for /10-05-2023 returned no `sharing_info`. `/2/files/delete_v2 path=/10-05-2023` removed the now-orphan folder.
