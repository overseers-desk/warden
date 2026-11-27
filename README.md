# Warden: the people you shared with are still in there

Consumer OneDrive and Dropbox Basic let you share a folder with a person, and that is the whole of what they offer. There is no role you can hand someone. There is no group you can put people into. There is no screen anywhere that lists everyone who can currently reach anything. The bookkeeper you added to Finance three years ago is still in Finance, and you will not discover that by looking, because looking means opening every folder in turn and reading a sharing panel that describes only the folder you are standing in.

Warden supplies the missing layer. You write one policy file naming your people, the groups they belong to, the folder collections those groups may reach, and at what role. Warden reads the live sharing state of your drives, compares it against that policy, and reports every place where the drives disagree with what you wrote. On request it repairs the difference.

Warden is a Tcl/Tk program with a browser and a command line. Both work from the same policy file and produce the same findings.

## Situations warden is for

**A contractor leaves and you cannot remember what they touched.** Over a couple of years you shared a handful of folders with a bookkeeper, some by invitation and some by a link sent in a hurry. Now the engagement is over. Removing them means finding them, and the drive gives you no way to search for a person. Warden asks a single question across a whole folder tree: what can this address still reach? It answers with a list, and it can strip the access it found, showing you the removals first if you ask for a preview. That sweep runs on OneDrive. The same question is answered on either drive by auditing against the policy, which reports every person holding every governed folder.

**Client folders that must not see each other.** An accountant or a solicitor keeps a folder per client, and the confidentiality duty is not satisfied by having been careful at the time. It is satisfied by being able to show, at any moment, that only the intended people are in each folder. In warden you mark a collection `closed: true`. Anyone reaching a closed folder who is not granted it is reported as a violation rather than a note, including access that leaks down from a parent folder. The audit changes nothing and prints a report, and `--format csv` prints the whole finding set as CSV you can redirect to a file and keep as evidence.

**A household drive with one folder that must stay shut.** The holiday photos are open to the whole family, the tax folder is not, and the two live on the same drive under folders that were shared and reshared at different times. Warden lets you say that once: a family group with a grant over the photos, a second group with a grant over the tax folder, and `closed: true` on the tax collection so nothing inherited into it goes unremarked.

**Sharing you no longer remember creating.** Public links live on long after the reason for them. Warden lists the links it finds on a governed folder, and treats a link on a closed collection as a violation. On Dropbox it also sweeps for the records of shared folders you have already deleted, which persist in the account without a path and can still carry a live link.

## How it works

Everything lives in one YAML file.

**People** are the humans. Each person has a key you choose, a name, and per-platform accounts. A person may hold more than one address on a platform, and the policy still names them once. A person can also have no account on a platform at all; a grant that reaches them there is reported as an unreachable grant, a warning rather than an error, because the policy is recording intent the platform cannot yet carry.

**Groups** contain people. A group may include other groups, and the membership resolves through the includes.

**Collections** are named sets of folders. Each folder is addressed by platform, path, and the drive's own stable id, so renaming or moving a folder does not lose it. A collection may include other collections. Marking a collection `closed: true` is the strong statement: at its folders, anyone not entitled is a violation, whether their access is direct or inherited from above.

**Grants** join a group to a collection at a role. The roles are `read` and `write`.

A grant applies at its collection's folders and reaches everything beneath them through the drive's own inheritance, so a folder's effective access is what is granted on it plus what is granted on every policy ancestor on the same platform. A closed folder is hermetic: its effective access is what is granted on it alone. Path prefixes on one platform mean nothing on the other, and inheritance is worked out per platform.

```yaml
version: 2
people:
  alice:
    name: Alice Example
    relationship: bookkeeper
    reason: quarterly BAS
    accounts:
      onedrive: alice@corp.example
      dropbox: [alice.p@gmail.example, alice@old.example]
groups:
  finance: {members: [alice], includes: []}
collections:
  tax:
    closed: true
    folders:
      - {platform: onedrive, path: "/Finance/Tax", id: "ABC!456"}
      - {platform: dropbox,  path: "/Tax",        id: "id:AAA"}
grants:
  - {collection: tax, group: finance, roles: [write]}
```

## The browser

Run warden with no arguments and it opens the browser. Chips along the top show which drives it found, and the policy strip shows which policy file is loaded, with buttons to open another or reload the current one.

The left side carries the folder trees, one root per connected drive, expanded as you click. A badge column marks whether a folder is governed by the policy, and after an audit it carries the audit result too. Right-clicking a folder offers to copy its item id, which is what you paste into a collection's folder entry. The Groups view on the left reads the other way round: each group, the collections it has been granted, the role, and the folders inside each collection. Clicking a folder there jumps to that folder's live access.

The right side holds tabs.

*Access* shows one folder. Selecting it lists, straight away, the people the policy expects there and the role each is granted. That includes people granted through a policy folder above it, and people the policy names who have no account on that platform. A line above the table says it shows the policy only. Below that line, a large Fetch ACL button reads the folder's actual permissions from the cloud. The fetch fills the same rows with the actual role, how it is held (directly, inherited from a parent folder, or through a link), and the audit's verdict. Accounts the policy does not expect appear in a section of their own, and the button then reads Refresh ACL. With no policy loaded, the button stands alone, and the fetch lists the permissions as they are. Reloading or editing the policy redraws the table from the last fetch without reading the folder again. Buttons at the foot remove the entries you select and invite a person; selecting a missing account fills the invitation in. Selecting an account the policy does not name offers to add it to a person. On a Dropbox folder, Remove and Invite stand down and say so, because Dropbox changes are made through the Audit tab's fixes or through `--enforce`.

*Policy* is an editor. Groups sit beside the selected group's members, and collections beside that group's grants. The Everyone entry at the head of the groups lists every person in the policy with their accounts, and marks anyone who has none. Selecting a person lists every grant that reaches them and the group it comes through. You can create and delete groups, add and remove members, add and remove grants, and read the current YAML. Every edit rewrites the policy file itself: warden emits the new file, loads it back to check it parses, keeps a `.bak` of the original, and only then renames the new file into place. An emission that fails to load is discarded and the original is untouched.

*Audit* runs the same audit as the command line, over the whole policy or over the selected folder and below. Findings are grouped by folder. Each fixable finding has a tick box, so you choose what to act on. Preview shows the chosen fixes as a change list with nothing yet done, and from there you apply them. Below the findings sit the accounts the audit saw that belong to no person in the policy. Each can be mapped to an existing person, turned into a new person, or marked an outsider. The tab's label counts the violations and those accounts.

## The command line

Any argument other than a bare `-debug` sends warden to the command line.

```
warden [OPTIONS] [PATH]
```

`PATH` is the folder or file to inspect and defaults to the drive root. Options take one dash or two. Outside `--audit` and `--enforce`, the command line works on OneDrive; Dropbox is reached through the policy.

- `--audit POLICY` compares the live drives against a policy file and changes nothing. It takes no path and no recursion flags, because the policy defines the folder set. It exits 0 when clean, 1 when it found violations, and 2 when it could not get that far, meaning a policy it could not load or credentials it could not obtain.
- `--enforce POLICY` audits and then fixes the drives to match, after showing the plan. Add `--dry-run` to see the plan and stop, or `-y` to skip the confirmation.
- `--platform onedrive|dropbox` restricts an audit or an enforcement to one drive.
- `-r` scans a folder and everything under it, three levels deep by default; `--max-depth N` sets the depth. `--type folders|files|both` chooses what is scanned.
- `--only-user USER` reports only what that address can reach, alone for one folder or with `-r` across a tree.
- `--remove-user USER` strips that address from the folder you name, and with `-r` or an explicit depth from everything beneath it as well. It is destructive, so preview it with `--dry-run` first.
- `--invite USER` invites someone to a folder with read and write access, inherited by the children below it. `--read-only` invites them as a reader instead.
- `--set-caption TEXT` writes a OneDrive item's description, which is searchable on the drive. An empty string clears it.
- `--convert-policy FILE` prints the version-2 form of a policy written with emails in place of people. It touches no drive and needs no credentials.
- `--format csv` writes the plain access listing or an audit as CSV.
- `--remote NAME` names the OneDrive rclone remote, `OneDrive` by default.
- `--debug` prints the service traffic. `--help` lists everything.

```bash
# Check the drives against the policy, changing nothing
warden --audit ~/policy.yaml

# Fix them to match it, but show me the plan first
warden --enforce ~/policy.yaml --dry-run

# Everywhere a departing contractor can still reach, ten levels down
warden --only-user contractor@example.com -r --max-depth 10 "Projects"

# Take that access away, preview then apply
warden --remove-user contractor@example.com -r --dry-run "Projects"
warden --remove-user contractor@example.com -r "Projects"
```

## What warden cannot do

These are the drives' limits, not warden's preferences. Warden reports each of them in plain words rather than failing quietly, but it cannot get past them.

**Dropbox will not grant access to a folder inside a shared folder.** Dropbox shares at the root of a share and nowhere else. If your policy grants someone a folder that sits inside an already-shared ancestor, warden cannot satisfy that grant there. It names the ancestor share and stops. Your options are to grant at the ancestor instead, or to move the folder out of the share.

**Dropbox will not let warden take away inherited access at the folder that inherits it.** Warden can remove a member or invitee of the folder's own share. Access arriving from an ancestor share is not removable at the folder, and there is no in-place fix on a Basic plan. Turning inheritance off through the API is restricted to team accounts and is refused on personal ones. Moving the folder out of the share cuts the inheritance only for as long as it stays out. Removing the person at the ancestor takes their access to every sibling folder under it, not just this one. All of those change more than the folder in front of you, so warden names the ancestor share and leaves the decision with you.

**A Dropbox plan can refuse a membership outright.** When Dropbox answers an invitation with `insufficient_plan`, warden reports that grant as unenforceable and carries on with the rest. Read-only members have worked on the Basic account this was tested against, so this is a refusal warden surfaces if it happens rather than a rule it assumes.

**OneDrive refuses to share with an address that is not a Microsoft account.** The invitation fails and warden says so. Separately, OneDrive sometimes refuses to send an invitation silently; warden retries in the ordinary way, which means the person receives a notification email, and it tells you that happened.

**OneDrive will not delete an inherited permission in place, and the workaround moves your folder.** Microsoft Graph declines to remove a permission that was inherited from a parent. To sever it, warden moves the folder to the top of your drive, where inheritance no longer applies, deletes the offending permissions there, plants the folder's correct access as explicit permissions so returning it will not simply reattach the old inheritance, and then moves it back. For the duration of that cycle, which includes deliberate waits for the service to settle, the folder is not where it belongs. If the move back fails, warden says so loudly and the folder is left sitting at the drive root for you to put back. Deletions on OneDrive have also been observed to report success while the entry survives, so warden re-reads the folder before it believes any removal, on either drive.

Two smaller things worth knowing. Unsharing a folder on Dropbox can change the file id the folder is known by, so an id written into your policy can go stale; warden looks each folder up by its id and reports it as moved when the path it finds is not the path you wrote. And on an open collection, access warden did not expect is reported as a note and tolerated; it is only a violation when you have marked the collection closed.

## Install

Warden needs Tcl and Tk version 9. Version 8.6 is refused rather than run in a degraded state: folder and file names on these drives carry characters, emoji among them, that Tcl 8 cannot hold in a string, and warden would rather stop than show you a name that is not the name.

Copy the repository directory wherever you like. Warden loads its `lib/` from beside itself, so a copied directory is a complete install.

```bash
sudo apt-get install tcl9.0 tk9.0 tcllib tcl-tls    # Debian and Ubuntu
brew install tcl-tk tcllib tcl-tls                  # macOS
```

On Windows, Magicsplat Tcl/Tk 9.0 provides both, and warden runs under its `wish.exe`.

## Authenticate

Warden reads its credentials from rclone's configuration file, in the usual place for your system. Set up a remote for each drive you want warden to see:

```bash
rclone config
```

Warden discovers every `onedrive` and `dropbox` remote in that file and offers one folder tree per remote. A machine with only a OneDrive remote simply has no Dropbox tree. The browser takes the first remote of each kind it finds, whatever it is called, though its OneDrive calls expect one named `OneDrive` unless you have the stored token described below. On the command line, `--remote` names the OneDrive remote and the Dropbox one is looked for under the name `Dropbox`. Dropbox access tokens expire hourly, and warden asks the installed rclone to refresh one when it finds it stale, so rclone itself needs to be present for Dropbox work rather than just its configuration file.

The rclone credentials are enough for everything that only reads: browsing folders, listing a folder's access, `--only-user` on OneDrive, and `--audit` on either drive. They are also enough for every Dropbox change warden makes.

Changing anything on OneDrive needs a second, more privileged token, because the token rclone holds does not carry the permission to edit sharing. That covers `--invite`, `--remove-user`, `--set-caption`, and `--enforce`. Enforcement opens every platform in the policy for writing before it touches anything, so a policy naming both drives stops without that token even for its Dropbox half, unless you narrow the run with `--platform dropbox`. To obtain it, open the browser and start an operation that changes something. Warden offers you a sign-in through your web browser, stores the resulting token as `token.json` under warden's own configuration directory, and refreshes it there as needed. Once it is stored, the command line uses it too. Asking the command line for a OneDrive change without it produces a refusal that tells you to go and get one.

With the remotes in place, the way in is to open the browser, walk the folder trees to the folders you care about, copy their item ids into a policy file, and run `warden --audit` against it.
