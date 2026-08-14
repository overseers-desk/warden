# Cloud ACL Manager

A drive tells you who can access a folder, but only the one you're looking at, not the subfolders beneath it. Someone you shared a subfolder with years ago may still have access, and you won't know unless you open every folder by hand. Cloud ACL Manager audits OneDrive and Dropbox against one policy file that names your people once, whatever address each drive knows them by, and it can fix what drifted.

## What it does

- Audit both drives against one policy (people, groups, folder collections, grants) and enforce it, with a dry-run preview
- Recursive ACL scan of a folder tree, with smart pruning of inherited permissions
- Find everything a given user can access across a tree
- Remove a user's access across a tree, with a dry-run preview
- Invite a user to a folder, inherited by its children (optionally written into the policy in the same act)
- Scan folders, files, or both
- Reads tokens from rclone's config (both remotes) and its own `token.json` for elevated OneDrive work

Two interfaces: a Tcl/Tk browser with Access, Policy, People, and Audit tabs over both drives, and a command line with the full set of operations, including the recursive scans and scheduled audits.

## Install

### Windows (tested on Windows 11)

1. Copy the repository directory where you like (`acl-manager.tcl` loads the `lib/` beside it).
2. Provide `rclone.conf` at `%APPDATA%\rclone\rclone.conf`. A working config is required (untested without one). You don't need rclone itself installed; copying a working `rclone.conf` from another machine is enough.
3. Install Magicsplat Tcl/Tk 9.0 (other versions untested); it lands at `%APPDATA%\Local\Apps\Tcl90`.
4. Run it:
   ```
   C:>"AppData\Local\Apps\Tcl90\bin\wish.exe" acl-manager.tcl
   ```

### Linux and macOS

```bash
rclone config                              # set up your OneDrive and Dropbox remotes
sudo apt-get install tcl9.0 tk9.0 tcllib tcl-tls   # Ubuntu/Debian; tk9.0 is for the browser
brew install tcl-tk                                # macOS
```

The browser shows one folder tree root per configured remote. A machine with only the OneDrive remote simply has no Dropbox root.

## Usage

GUI:
```bash
./acl-manager                              # opens the browser at the drive root
wish9.0 acl-manager.tcl "Finance"          # ...starting at a folder
```

Run with no arguments and it opens the browser, loading Tk into the interpreter it is already running in. Any argument sends it to the command line instead, so starting the browser at a particular folder means running it under `wish9.0` and naming the folder. Tcl and Tk 9 are required: names on the drive carry characters an older Tcl cannot hold in a string, so the script stops on one rather than show you a name that is not the name.

In the browser, the left pane holds the folder trees (with a per-folder policy badge) and a Groups view of the policy; the right pane holds four tabs. Access shows a folder's ACL with the policy's intent beside the drive's actuality. Policy edits groups, members, collections, and grants (edits rewrite the YAML file, keeping a `.bak`). People shows one row per human with their account on each platform, plus unmapped identities seen on a drive with actions to map, create, or mark them outsiders. Audit runs the same audit as the command line, lets you tick which fixes to apply, previews them as a dry-run change list, and applies only what you ticked.

Command line:
```bash
./acl-manager [OPTIONS] [PATH]
```

`PATH` is the folder or file to inspect (default `/`, the root) and must come after all options. Options take either one dash or two (`-r` or `--recursive`); help prints the single-dash form, both work.

- `-r, --recursive` - scan a folder and its subfolders (default max depth 3)
- `--max-depth N` - set recursion depth (with `-r`, or alone for any depth)
- `--type folders|files|both` - what to scan (default `folders`)
- `--only-user USER` - show only what USER can access (with or without `-r`)
- `--remove-user USER` - remove USER's access from what's found; destructive, needs `-r` or an explicit depth
- `--invite USER` - invite USER with read/write, inherited by children; not usable with `-r`
- `--audit POLICY` - compare live ACLs against a policy file (read-only; see below)
- `--enforce POLICY` - audit, then fix the drives to match the policy
- `--platform onedrive|dropbox` - restrict `--audit`/`--enforce` to one platform
- `--convert-policy POLICY` - print the version-2 (person-based) form of an email-per-member policy file
- `--dry-run` - preview a `--remove-user` or `--enforce` without changing anything
- `--read-only` - invite with read-only instead of read/write
- `--debug` - debug output
- `--remote REMOTE` - OneDrive remote name (default `OneDrive`)
- `--help` - show help

### Examples

```bash
# Audit a folder and everything under it
./acl-manager -r "Finance"

# ...deeper than the default 3 levels
./acl-manager -r --max-depth 10 "Projects"

# ...including files, not just folders
./acl-manager -r --type both "Confidential"

# Find everywhere an ex-employee still has access
./acl-manager --only-user exemployee@example.com -r "Company"

# One folder, no recursion
./acl-manager "Finance/Budget2025"

# Whether one user can reach one folder
./acl-manager --only-user bob@example.com "Finance/Budget2025"

# Remove an ex-employee across a tree: preview first, then do it
./acl-manager --remove-user exemployee@example.com -r --dry-run "Projects"
./acl-manager --remove-user exemployee@example.com -r "Projects"

# Invite someone to a folder (children inherit it)
./acl-manager --invite newaccountant@example.com "Finance"

# ...read-only
./acl-manager --invite auditor@example.com --read-only "Reports"

# Audit the drive against a policy file, then apply the fixes
./acl-manager --audit acl-policy.yaml
./acl-manager --enforce acl-policy.yaml --dry-run
./acl-manager --enforce acl-policy.yaml

# GUI for interactive browsing
wish9.0 acl-manager.tcl "Finance"
```

## Policy files

People forget permissions: they share a folder mid-task, staff leave, folders move, and nobody notices until data has leaked. A policy file turns the intended sharing state into data the tool can check and restore. It is YAML (version 2) with four sections. `people` name each human once, with their contractual relationship, why they hold access, and their account address on each platform (a person can hold several addresses on one platform, and can lack a platform entirely). `groups` collect people by their keys. `collections` name folder sets, each folder carrying its platform, its path (the human label), and its stable id (the id survives renames and moves, which is how drift is caught). `grants` join a group to a collection with a role (`read` or `write`). An optional `outsiders` section lists accounts that belong to no person on purpose, which quiets the People view's suggestions about them.

```yaml
version: 2
people:
  alice:
    name: Alice Example
    relationship: accountant
    reason: quarterly filings
    accounts:
      onedrive: alice@corp.example
      dropbox: [alice.p@gmail.example, alice@old.example]
groups:
  finance: {members: [alice]}
collections:
  tax:
    closed: true
    folders:
      - {platform: onedrive, path: "Finance/Tax", id: "ABC!456"}
      - {platform: dropbox,  path: "/Tax",        id: "id:AAA"}
grants:
  - {collection: tax, group: finance, roles: [write]}
```

A policy written in the older email-per-member form converts once with `--convert-policy old.yaml > new.yaml`; members sharing a display name merge into one person holding each address.

Folder paths run from the drive root, so one policy file covers every top-level folder on a drive. A drive holding several companies' folders is governed by one file, and a folder outside every collection is simply not audited. A grant reaching a person with no account on that platform is reported as an unreachable warning, not a violation: the policy records the intent the platform cannot yet carry.

To get the item ids for a new collection, right-click a folder in the browser ("Copy item id"), or list the folder with rclone:

```bash
rclone lsjson "OneDrive:Some Folder" --dirs-only | jq -r '.[] | [.ID, .Name] | @tsv'
```

rclone prints a OneDrive id as `<drive>#<item>` and the policy file takes the part after the `#`; a Dropbox id is used whole (the `id:...` form).

A grant reaches descendants through the platform's inheritance, so a folder's entitlements are its own grants plus its policy ancestors' on the same platform. A collection marked `closed: true` is the exception: its folders admit exactly their own grants, and anything beyond, direct or inherited, is a violation, as is a shared link on a closed Dropbox folder. `--audit` reports violations folder by folder (`--format csv` for machines) and exits nonzero on any; on Dropbox it also lists records of deleted shares, which persist and can keep live public links (`docs/DROPBOX.md`). `--enforce` invites missing users quietly (no notification email), downgrades or removes wrong ones, and severs inherited excess where the platform allows it: on OneDrive with the move-to-root cycle described in `docs/PHANTOM-INHERITANCE-BUG.md` (re-checking descendants of changed folders for leaked copies afterwards); on Dropbox, where a folder inside a shared folder cannot be detached in place, by naming the ancestor share so the owner decides between removing the member there and relocating the folder.

## Scheduled audits

Permission drift accumulates quietly, so the audit is worth running on a schedule (weekly suits a small organisation) rather than when someone remembers. The recurring task:

1. Run `./acl-manager --audit <policy file>`. The repository holding your policy file may wrap this in a make target; if so, run that instead, since it pins the right policy path. A make target reaching a tool in a sibling repository expects both checkouts under one parent directory.
2. Exit 1 with `❌` lines: the drive drifted. Read what drifted. New shares by colleagues mid-task and leaked inherited copies in locked folders are the common kinds.
3. Fix by running `--enforce` with the same policy file: first with `--dry-run` to see the change list, then for real. Enforcement touches only what the report showed.
4. Exit 0 means no violation, and the run is done. The `ℹ️` lines it may still carry are accounts on open collections that the policy does not name, tolerated because enforcement never removes them unasked. They are worth a look when one is new: identify the person (a contacts file or staff register usually settles it), then either send it to the policy's owner to be written into a group with name, relationship, and reason, or to have the access removed. An `ℹ️` line you have already recognised needs nothing.
5. Exit 2 is a policy-file error, and transport errors mean the run could not see some folders; re-run before trusting either.

Changes to this procedure land in this section, so re-read it when the audit starts behaving differently than described.

## Permissions and tokens

Reading (scanning, listing ACLs) needs the `Files.Read` scope; writing (invite, remove) needs `Files.ReadWrite` plus `Sites.Manage.All`.

OneDrive tokens come from two places: `rclone.conf` (usually read-only, `Files.Read`) and `token.json` in the application directory (full permissions, created automatically when needed). The app prefers `token.json` and falls back to `rclone.conf` for read-only work. When a write needs more than `rclone.conf` grants, it opens a web sign-in to create or update `token.json`. Expired tokens are refreshed automatically when possible.

The Dropbox token is rclone's for the Dropbox remote, used for reading and writing alike; when it has expired, the app has rclone refresh it in place.

Safety: destructive operations prompt for confirmation (not bypassable) and owner permissions can't be removed. Always `--dry-run` a removal first.

## Troubleshooting

**Token expired and auto-refresh failed.** For `token.json`, run the GUI and do any write operation to trigger a fresh web sign-in. For `rclone.conf`, run any rclone command, e.g. `rclone about OneDrive:`.

**Missing packages.** `sudo apt-get install tcl9.0 tcllib tcl-tls`.

**`version conflict for package "Tcl": have 8.6.x, need 9`.** The shell that started the script is Tcl 8. On Debian and Ubuntu the unversioned `tclsh` and `wish` are the 8.6 ones, so name `tclsh9.0` or `wish9.0` explicitly.

**Access denied.** Check the path, that you're allowed to view the ACL, and that your rclone token has enough scope.

## API

Dropbox: the `/2/files` and `/2/sharing` HTTP endpoints; the behavioural rules the sharing API actually follows are recorded in `docs/DROPBOX.md`.

Microsoft Graph:
- `GET /me/drive/root:/{item-path}` (item info)
- `GET /me/drive/items/{item-id}/permissions` (permissions)
- `GET /me/drive/items/{item-id}/children` (folder contents)
- `POST /me/drive/items/{item-id}/invite` (invite)
- `DELETE /me/drive/items/{item-id}/permissions/{perm-id}` (remove permission)

OAuth tokens (from `token.json` for full access, else `rclone.conf` read-only) go straight into the requests. The rclone config path is `%APPDATA%\rclone\rclone.conf` on Windows and `~/.config/rclone/rclone.conf` on Unix-like systems.

## License

MIT, see [LICENSE](LICENSE).
