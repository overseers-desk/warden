# OneDrive ACL Manager (TCL version)

OneDrive tells you who can access a folder, but only the one you're looking at, not the subfolders beneath it. Someone you shared a subfolder with years ago may still have access, and you won't know unless you open every folder by hand. OneDrive ACL Manager scans a whole folder tree at once and reports every permission at every level, so you can see who has access to what.

## What it does

- Recursive ACL scan of a folder tree, with smart pruning of inherited permissions
- Find everything a given user can access across a tree
- Remove a user's access across a tree, with a dry-run preview
- Invite a user to a folder, inherited by its children
- Scan folders, files, or both
- Reads tokens from both rclone's config and its own `token.json`, for read-only or full-permission work

Two interfaces: a Tcl/Tk GUI for browsing folders and viewing permissions (a subset of the commands), and a command line with the full set, including the recursive operations.

## Install

### Windows (tested on Windows 11)

1. Put `acl-manager.tcl` where you like (e.g. your home directory).
2. Provide `rclone.conf` at `%APPDATA%\rclone\rclone.conf`. A working config is required (untested without one). You don't need rclone itself installed; copying a working `rclone.conf` from another machine is enough.
3. Install Magicsplat Tcl/Tk 9.0 (other versions untested); it lands at `%APPDATA%\Local\Apps\Tcl90`.
4. Run it:
   ```
   C:>"AppData\Local\Apps\Tcl90\bin\wish.exe" acl-manager.tcl
   ```

### Linux and macOS

```bash
rclone config                              # set up your OneDrive remote
sudo apt-get install tcllib tcl-tls        # Ubuntu/Debian
brew install tcl-tk                        # macOS
```

## Usage

GUI:
```bash
wish acl-manager [item_path] [remote_name]
```

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
- `--enforce POLICY` - audit, then fix the drive to match the policy
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
wish acl-manager "Finance"
```

## Policy files

People forget permissions: they share a folder mid-task, staff leave, folders move, and nobody notices until data has leaked. A policy file turns the intended sharing state into data the tool can check and restore. It is YAML with three sections: `groups` name people once (each member records email, name, contractual relationship, and why they have access), `collections` name folder sets by path plus stable item id (the id survives renames and moves, which is how drift is caught), and `grants` join a group to a collection with a role (`read` or `write`).

Folder paths run from the drive root, so one policy file covers every top-level folder on a drive. A drive holding several companies' folders is governed by one file, and a folder outside every collection is simply not audited.

To get the item ids for a new collection, list the folder with rclone:

```bash
rclone lsjson "OneDrive:Some Folder" --dirs-only | jq -r '.[] | [.ID, .Name] | @tsv'
```

rclone prints the id as `<drive>#<item>`; the policy file takes the part after the `#`.

A grant reaches descendants through OneDrive inheritance, so a folder's entitlements are its own grants plus its policy ancestors'. A collection marked `closed: true` is the exception: its folders admit exactly their own grants, and anything beyond, direct or inherited, is a violation. `--audit` reports violations folder by folder (`--format csv` for machines) and exits nonzero on any; `--enforce` invites missing users quietly (no notification email), downgrades or removes wrong ones, and handles inherited permissions with the move-to-root cycle described in `docs/PHANTOM-INHERITANCE-BUG.md`, re-checking descendants of changed folders for leaked copies afterwards.

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

Tokens come from two places: `rclone.conf` (usually read-only, `Files.Read`) and `token.json` in the application directory (full permissions, created automatically when needed). The app prefers `token.json` and falls back to `rclone.conf` for read-only work. When a write needs more than `rclone.conf` grants, it opens a web sign-in to create or update `token.json`. Expired tokens are refreshed automatically when possible.

Safety: destructive operations prompt for confirmation (not bypassable) and owner permissions can't be removed. Always `--dry-run` a removal first.

## Troubleshooting

**Token expired and auto-refresh failed.** For `token.json`, run the GUI and do any write operation to trigger a fresh web sign-in. For `rclone.conf`, run any rclone command, e.g. `rclone about OneDrive:`.

**Missing packages.** `sudo apt-get install tcllib tcl-tls`.

**Access denied.** Check the path, that you're allowed to view the ACL, and that your rclone token has enough scope.

## API

Microsoft Graph:
- `GET /me/drive/root:/{item-path}` (item info)
- `GET /me/drive/items/{item-id}/permissions` (permissions)
- `GET /me/drive/items/{item-id}/children` (folder contents)
- `POST /me/drive/items/{item-id}/invite` (invite)
- `DELETE /me/drive/items/{item-id}/permissions/{perm-id}` (remove permission)

OAuth tokens (from `token.json` for full access, else `rclone.conf` read-only) go straight into the requests. The rclone config path is `%APPDATA%\rclone\rclone.conf` on Windows and `~/.config/rclone/rclone.conf` on Unix-like systems.

## License

MIT, see [LICENSE](LICENSE).
