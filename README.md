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
wish acl-manager.tcl [item_path] [remote_name]
```

Command line:
```bash
tclsh acl-manager.tcl [OPTIONS] [PATH]
```

`PATH` is the folder or file to inspect (default `/`, the root) and must come after all options. Options take either one dash or two (`-r` or `--recursive`); help prints the single-dash form, both work.

- `-r, --recursive` - scan a folder and its subfolders (default max depth 3)
- `--max-depth N` - set recursion depth (with `-r`, or alone for any depth)
- `--type folders|files|both` - what to scan (default `folders`)
- `--only-user USER` - show only what USER can access (with or without `-r`)
- `--remove-user USER` - remove USER's access from what's found; destructive, needs `-r` or an explicit depth
- `--invite USER` - invite USER with read/write, inherited by children; not usable with `-r`
- `--dry-run` - preview a `--remove-user` without changing anything
- `--read-only` - invite with read-only instead of read/write
- `--debug` - debug output
- `--remote REMOTE` - OneDrive remote name (default `OneDrive`)
- `--help` - show help

### Examples

```bash
# Audit a folder and everything under it
tclsh acl-manager.tcl -r "Finance"

# ...deeper than the default 3 levels
tclsh acl-manager.tcl -r --max-depth 10 "Projects"

# ...including files, not just folders
tclsh acl-manager.tcl -r --type both "Confidential"

# Find everywhere an ex-employee still has access
tclsh acl-manager.tcl --only-user exemployee@example.com -r "Company"

# One folder, no recursion
tclsh acl-manager.tcl "Finance/Budget2025"

# Whether one user can reach one folder
tclsh acl-manager.tcl --only-user bob@example.com "Finance/Budget2025"

# Remove an ex-employee across a tree: preview first, then do it
tclsh acl-manager.tcl --remove-user exemployee@example.com -r --dry-run "Projects"
tclsh acl-manager.tcl --remove-user exemployee@example.com -r "Projects"

# Invite someone to a folder (children inherit it)
tclsh acl-manager.tcl --invite newaccountant@example.com "Finance"

# ...read-only
tclsh acl-manager.tcl --invite auditor@example.com --read-only "Reports"

# GUI for interactive browsing
wish acl-manager.tcl "Finance"
```

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
