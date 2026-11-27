# Policy schema version 2: people are first-class, accounts are per-platform.
#
#   version: 2
#   people:
#     alice:                          # person key, human-chosen slug
#       name: Alice Example
#       relationship: accountant
#       reason: quarterly filings
#       accounts:
#         onedrive: alice@corp.example
#         dropbox: [alice.p@gmail.example, alice@old.example]
#   groups:
#     finance: {members: [alice], includes: []}
#   collections:
#     tax:
#       closed: true
#       folders:
#         - {platform: onedrive, path: "/Finance/Tax", id: "ABC!456"}
#         - {platform: dropbox,  path: "/Tax",        id: "id:AAA"}
#   grants:
#     - {collection: finance, group: finance, roles: [write]}
#
# An account value is one email or a list of emails: the same human can hold
# several sharing identities on one platform, and the policy names the person
# once however many addresses the drives know. A person may lack an account
# on a platform; a grant reaching them there is an unreachable_grant warning,
# not an error, since the policy records intent that the platform cannot yet
# carry.
#
# The loaded model:
#   people      slug -> {name relationship reason accounts {platform {email ...}}}
#   identity    platform -> email(lowercased) -> slug
#   plan        platform -> folder-id -> {path closed collection expected effective}
#   collections name -> {closed platforms folders {{platform path id} ...}}
#   warnings    list of {type ... platform ... person ... ...}
#   raw         the parsed YAML dict, for editors that rewrite the file
#
# expected/effective are email -> role (read|write) dicts, exactly the shape
# the audit compares against live drive ACLs; person resolution happens at
# the reporting boundary via the identity dict, so an email the drive knows
# but the policy does not falls out naturally as an unmapped identity.
# Inheritance (effective = own grants plus every policy ancestor's, closed
# folders hermetic) is computed within each platform; a path prefix on one
# platform means nothing on the other.

package require yaml

proc policy_known_platforms {} {
    return {onedrive dropbox}
}

proc policy_v2_resolve_group {groups name chain} {
    # Recursive union of a group's member slugs and includes.
    # Errors on unknown names and cycles.
    if {[lsearch -exact $chain $name] >= 0} {
        error "group include cycle: [join $chain { -> }] -> $name"
    }
    if {![dict exists $groups $name]} {
        if {[llength $chain] > 0} {
            error "group '$name' referenced by '[lindex $chain end]' does not exist"
        }
        error "group '$name' does not exist"
    }
    set g [dict get $groups $name]
    set slugs {}
    if {[dict exists $g members]} {
        foreach m [dict get $g members] { lappend slugs $m }
    }
    if {[dict exists $g includes]} {
        foreach inc [dict get $g includes] {
            lappend slugs {*}[policy_v2_resolve_group $groups $inc [concat $chain [list $name]]]
        }
    }
    return [lsort -unique $slugs]
}

proc policy_v2_resolve_collection {collections name chain} {
    # Recursive union of a collection's folders and includes.
    # Returns a list of {platform <p> path <p> id <i>} dicts; errors on
    # unknown names, cycles, and folder entries missing a field.
    if {[lsearch -exact $chain $name] >= 0} {
        error "collection include cycle: [join $chain { -> }] -> $name"
    }
    if {![dict exists $collections $name]} {
        if {[llength $chain] > 0} {
            error "collection '$name' referenced by '[lindex $chain end]' does not exist"
        }
        error "collection '$name' does not exist"
    }
    set c [dict get $collections $name]
    set folders {}
    if {[dict exists $c folders]} {
        foreach f [dict get $c folders] {
            foreach key {platform path id} {
                if {![dict exists $f $key]} {
                    error "collection '$name' has a folder entry without a '$key'"
                }
            }
            set p [dict get $f platform]
            if {$p ni [policy_known_platforms]} {
                error "collection '$name' names unknown platform '$p' ([join [policy_known_platforms] {, }])"
            }
            lappend folders $f
        }
    }
    if {[dict exists $c includes]} {
        foreach inc [dict get $c includes] {
            lappend folders {*}[policy_v2_resolve_collection $collections $inc [concat $chain [list $name]]]
        }
    }
    return $folders
}

proc policy_person_accounts {person platform} {
    # Emails a person holds on a platform, lowercased; empty when none.
    if {![dict exists $person accounts $platform]} { return {} }
    set v [dict get $person accounts $platform]
    set emails {}
    foreach e $v { lappend emails [string tolower $e] }
    return $emails
}

proc policy_load_v2 {yaml_path} {
    # Load and validate a version-2 policy file into the model above.
    # Throws a plain-message error on any structural problem.
    set f [open $yaml_path r]
    fconfigure $f -encoding utf-8
    set yaml_text [read $f]
    close $f

    set policy [yaml::yaml2dict $yaml_text]
    if {![dict exists $policy version] || [dict get $policy version] != 2} {
        error "policy is not version 2; convert it first (--convert-policy FILE prints the converted file)"
    }
    foreach key {people groups collections grants} {
        if {![dict exists $policy $key]} {
            error "policy is missing its '$key' section"
        }
    }
    set groups [dict get $policy groups]
    set collections_raw [dict get $policy collections]

    # People: normalize each account value to a lowercased email list
    set people {}
    dict for {slug p} [dict get $policy people] {
        set rec {}
        foreach field {name relationship reason} {
            if {[dict exists $p $field]} { dict set rec $field [dict get $p $field] }
        }
        set accounts {}
        if {[dict exists $p accounts]} {
            dict for {platform v} [dict get $p accounts] {
                if {$platform ni [policy_known_platforms]} {
                    error "person '$slug' names unknown platform '$platform'"
                }
                set emails {}
                foreach e $v { lappend emails [string tolower $e] }
                dict set accounts $platform $emails
            }
        }
        dict set rec accounts $accounts
        dict set people $slug $rec
    }

    # Identity: platform -> email -> slug; an email owned twice is ambiguous
    set identity {}
    dict for {slug p} $people {
        dict for {platform emails} [dict get $p accounts] {
            foreach email $emails {
                if {[dict exists $identity $platform $email]} {
                    error "account '$email' on $platform belongs to both '[dict get $identity $platform $email]' and '$slug'"
                }
                dict set identity $platform $email $slug
            }
        }
    }

    # Group members are person slugs
    dict for {gname g} $groups {
        if {![dict exists $g members]} { continue }
        foreach slug [dict get $g members] {
            if {![dict exists $people $slug]} {
                error "group '$gname' names unknown person '$slug'"
            }
        }
    }

    # Collections view for editors and the browser: name -> closed/platforms/folders,
    # plus each folder's defining collection (the one whose own folders list
    # holds it, first wins) for the plan's collection label.
    set collections {}
    set defining {}
    dict for {cname c} $collections_raw {
        set folders [policy_v2_resolve_collection $collections_raw $cname {}]
        set platforms {}
        foreach f $folders {
            set p [dict get $f platform]
            if {$p ni $platforms} { lappend platforms $p }
        }
        dict set collections $cname [dict create \
            closed [expr {[dict exists $c closed] && [dict get $c closed] ? 1 : 0}] \
            platforms $platforms \
            folders $folders]
        if {[dict exists $c folders]} {
            foreach f [dict get $c folders] {
                set key [list [dict get $f platform] [dict get $f id]]
                if {![dict exists $defining $key]} { dict set defining $key $cname }
            }
        }
    }

    # Closed flag per (platform, folder id): closed if any closed collection holds it
    set closed_ids {}
    dict for {cname c} $collections_raw {
        if {![dict exists $c closed] || ![dict get $c closed]} { continue }
        foreach f [policy_v2_resolve_collection $collections_raw $cname {}] {
            dict set closed_ids [list [dict get $f platform] [dict get $f id]] 1
        }
    }

    # Expected ACL per platform and folder from the grants
    set plan {}
    set warnings {}
    set warned {}
    foreach grant [dict get $policy grants] {
        foreach key {collection group roles} {
            if {![dict exists $grant $key]} {
                error "a grant is missing its '$key' field: $grant"
            }
        }
        set role "read"
        foreach r [dict get $grant roles] {
            if {$r ni {read write}} {
                error "grant on '[dict get $grant collection]' has unknown role '$r' (read or write)"
            }
            if {$r eq "write"} { set role "write" }
        }
        set slugs [policy_v2_resolve_group $groups [dict get $grant group] {}]
        foreach f [policy_v2_resolve_collection $collections_raw [dict get $grant collection] {}] {
            set platform [dict get $f platform]
            set fid [dict get $f id]
            if {![dict exists $plan $platform $fid]} {
                set ckey [list $platform $fid]
                dict set plan $platform $fid [dict create \
                    path [dict get $f path] \
                    closed [expr {[dict exists $closed_ids $ckey] ? 1 : 0}] \
                    collection [expr {[dict exists $defining $ckey] ? [dict get $defining $ckey] : ""}] \
                    expected {}]
            }
            set expected [dict get $plan $platform $fid expected]
            foreach slug $slugs {
                set emails [policy_person_accounts [dict get $people $slug] $platform]
                if {[llength $emails] == 0} {
                    set wkey [list $slug $platform [dict get $grant collection]]
                    if {![dict exists $warned $wkey]} {
                        dict set warned $wkey 1
                        lappend warnings [dict create \
                            type unreachable_grant platform $platform person $slug \
                            group [dict get $grant group] \
                            collection [dict get $grant collection] role $role \
                            detail "no $platform account; the grant cannot reach them there"]
                    }
                    continue
                }
                foreach email $emails {
                    if {![dict exists $expected $email] || [dict get $expected $email] ne "write"} {
                        dict set expected $email $role
                    }
                }
            }
            dict set plan $platform $fid expected $expected
        }
    }

    # Folders in collections but granted nothing still deserve auditing
    dict for {cname c} $collections_raw {
        foreach f [policy_v2_resolve_collection $collections_raw $cname {}] {
            set platform [dict get $f platform]
            set fid [dict get $f id]
            if {![dict exists $plan $platform $fid]} {
                set ckey [list $platform $fid]
                dict set plan $platform $fid [dict create \
                    path [dict get $f path] \
                    closed [expr {[dict exists $closed_ids $ckey] ? 1 : 0}] \
                    collection [expr {[dict exists $defining $ckey] ? [dict get $defining $ckey] : ""}] \
                    expected {}]
            }
        }
    }

    # Effective ACL: the folder's own grants plus every policy ancestor's on
    # the same platform, write beating read; a closed folder absorbs nothing.
    dict for {platform subplan} $plan {
        dict for {fid fentry} $subplan {
            if {[dict get $fentry closed]} {
                dict set plan $platform $fid effective [dict get $fentry expected]
                continue
            }
            set fpath [dict get $fentry path]
            set effective [dict get $fentry expected]
            dict for {aid aentry} $subplan {
                if {$aid eq $fid} { continue }
                set apath [dict get $aentry path]
                if {$apath eq "/" || [string match "$apath/*" $fpath]} {
                    dict for {email role} [dict get $aentry expected] {
                        if {![dict exists $effective $email] || [dict get $effective $email] ne "write"} {
                            dict set effective $email $role
                        }
                    }
                }
            }
            dict set plan $platform $fid effective $effective
        }
    }

    # Outsiders: accounts seen on a drive that belong to no person and,
    # by the owner's decision, never will; the Audit tab stops listing
    # them among the accounts no person holds.
    set outsiders {}
    if {[dict exists $policy outsiders]} {
        foreach o [dict get $policy outsiders] {
            if {[dict exists $o platform] && [dict exists $o email]} {
                lappend outsiders [dict create platform [dict get $o platform] \
                    email [string tolower [dict get $o email]]]
            }
        }
    }

    return [dict create version 2 people $people identity $identity \
        plan $plan collections $collections warnings $warnings \
        outsiders $outsiders raw $policy]
}

proc identity_person_for {model platform email} {
    # Person slug owning an account email on a platform, or "".
    set email [string tolower $email]
    if {[dict exists $model identity $platform $email]} {
        return [dict get $model identity $platform $email]
    }
    return ""
}

proc identity_display {model slug} {
    # A person's display name, falling back to the slug.
    if {$slug ne "" && [dict exists $model people $slug name]} {
        return [dict get $model people $slug name]
    }
    return $slug
}

proc identity_is_outsider {model platform email} {
    # Marked by the owner as belonging to no person, on purpose
    set email [string tolower $email]
    if {![dict exists $model outsiders]} { return 0 }
    foreach o [dict get $model outsiders] {
        if {[dict get $o platform] eq $platform && [dict get $o email] eq $email} {
            return 1
        }
    }
    return 0
}

proc identity_unmapped {model platform live_emails} {
    # Emails seen on a platform that belong to no person and are not
    # marked outsiders.
    set out {}
    foreach email $live_emails {
        set email [string tolower $email]
        if {[identity_person_for $model $platform $email] eq "" && \
            ![identity_is_outsider $model $platform $email]} {
            lappend out $email
        }
    }
    return [lsort -unique $out]
}

# ---------------------------------------------------------------------------
# One-off converter from the email-per-member format

proc policy_yaml_quote {s} {
    # Double-quote a scalar unless it is plainly safe unquoted.
    if {[regexp {^[A-Za-z0-9@._/-]+$} $s]} { return $s }
    set s [string map {\\ \\\\ \" \\\"} $s]
    return "\"$s\""
}

proc policy_slugify {s} {
    # Person key from a display name: lowercase, runs of non-alphanumerics
    # become single hyphens. Non-ASCII letters survive (Tcl 9 is_alnum is
    # Unicode-aware), so "Bárbara" keeps its accent.
    set s [string tolower [string trim $s]]
    set out ""
    set hyphen 0
    foreach ch [split $s ""] {
        if {[string is alnum $ch]} {
            append out $ch
            set hyphen 0
        } elseif {!$hyphen && $out ne ""} {
            append out -
            set hyphen 1
        }
    }
    return [string trimright $out -]
}

proc policy_convert_v1_v2 {v1_path} {
    # Print the version-2 form of an email-per-member policy to stdout.
    # Every distinct member email becomes (part of) a person whose onedrive
    # account it is; members with the same name merge into one person holding
    # each of their emails, since one human may have several Microsoft
    # sharing identities. Comments and key order do not survive; review the
    # output before adopting it.
    set f [open $v1_path r]
    fconfigure $f -encoding utf-8
    set yaml_text [read $f]
    close $f
    set policy [yaml::yaml2dict $yaml_text]
    foreach key {groups collections grants} {
        if {![dict exists $policy $key]} {
            error "policy is missing its '$key' section"
        }
    }
    set groups [dict get $policy groups]

    # First pass: email -> person record and slug; same display name -> same person
    set email_slug {}
    set persons {}
    set slug_order {}
    dict for {gname g} $groups {
        if {![dict exists $g members]} { continue }
        foreach m [dict get $g members] {
            if {[llength $m] % 2 == 0 && [dict exists $m email]} {
                set email [string tolower [dict get $m email]]
                set name [expr {[dict exists $m name] ? [dict get $m name] : ""}]
            } else {
                set email [string tolower $m]
                set name ""
            }
            if {[dict exists $email_slug $email]} { continue }
            if {$name ne ""} {
                set slug [policy_slugify $name]
            } else {
                set slug [policy_slugify [lindex [split $email @] 0]]
            }
            if {[dict exists $persons $slug]} {
                set existing [dict get $persons $slug]
                if {$name ne "" && [dict exists $existing name] && [dict get $existing name] eq $name} {
                    # Same person, another sharing identity
                    dict set persons $slug emails \
                        [concat [dict get $existing emails] [list $email]]
                    dict set email_slug $email $slug
                    continue
                }
                set n 2
                while {[dict exists $persons "$slug-$n"]} { incr n }
                set slug "$slug-$n"
            }
            set rec [dict create emails [list $email]]
            foreach field {name relationship reason} {
                if {[llength $m] % 2 == 0 && [dict exists $m $field]} {
                    dict set rec $field [dict get $m $field]
                }
            }
            dict set persons $slug $rec
            lappend slug_order $slug
            dict set email_slug $email $slug
        }
    }

    set out {}
    lappend out "# Desired sharing state, audited and enforced with warden"
    lappend out "# (--audit / --enforce). People are named once with their per-platform"
    lappend out "# accounts; groups reference people; grants join a group to a collection."
    lappend out "version: 2"
    lappend out ""
    lappend out "people:"
    foreach slug $slug_order {
        set p [dict get $persons $slug]
        lappend out "  ${slug}:"
        foreach field {name relationship reason} {
            if {[dict exists $p $field]} {
                lappend out "    ${field}: [policy_yaml_quote [dict get $p $field]]"
            }
        }
        lappend out "    accounts:"
        set emails [dict get $p emails]
        if {[llength $emails] == 1} {
            lappend out "      onedrive: [policy_yaml_quote [lindex $emails 0]]"
        } else {
            set quoted {}
            foreach e $emails { lappend quoted [policy_yaml_quote $e] }
            lappend out "      onedrive: \[[join $quoted {, }]\]"
        }
    }
    lappend out ""
    lappend out "groups:"
    dict for {gname g} $groups {
        lappend out "  ${gname}:"
        if {[dict exists $g includes] && [llength [dict get $g includes]] > 0} {
            set quoted {}
            foreach inc [dict get $g includes] { lappend quoted [policy_yaml_quote $inc] }
            lappend out "    includes: \[[join $quoted {, }]\]"
        }
        set slugs {}
        if {[dict exists $g members]} {
            foreach m [dict get $g members] {
                set email [policy_member_email_v1 $m]
                set slug [dict get $email_slug $email]
                if {$slug ni $slugs} { lappend slugs $slug }
            }
        }
        if {[llength $slugs] > 0} {
            lappend out "    members: \[[join $slugs {, }]\]"
        } elseif {![dict exists $g includes] || [llength [dict get $g includes]] == 0} {
            lappend out "    members: \[\]"
        }
    }
    lappend out ""
    lappend out "collections:"
    dict for {cname c} [dict get $policy collections] {
        lappend out "  ${cname}:"
        if {[dict exists $c closed] && [dict get $c closed]} {
            lappend out "    closed: true"
        }
        if {[dict exists $c includes] && [llength [dict get $c includes]] > 0} {
            set quoted {}
            foreach inc [dict get $c includes] { lappend quoted [policy_yaml_quote $inc] }
            lappend out "    includes: \[[join $quoted {, }]\]"
        }
        if {[dict exists $c folders]} {
            lappend out "    folders:"
            foreach f [dict get $c folders] {
                lappend out "      - {platform: onedrive, path: [policy_yaml_quote [dict get $f path]], id: [policy_yaml_quote [dict get $f id]]}"
            }
        }
    }
    lappend out ""
    lappend out "grants:"
    foreach grant [dict get $policy grants] {
        set quoted {}
        foreach r [dict get $grant roles] { lappend quoted $r }
        lappend out "  - {collection: [policy_yaml_quote [dict get $grant collection]], group: [policy_yaml_quote [dict get $grant group]], roles: \[[join $quoted {, }]\]}"
    }
    return [join $out \n]\n
}

proc policy_member_email_v1 {member} {
    # An email-per-member group entry is a bare email string or a record
    # {email ... name ...}; the converter reads both.
    if {[llength $member] % 2 == 0 && [dict exists $member email]} {
        return [string tolower [dict get $member email]]
    }
    return [string tolower $member]
}

# ---------------------------------------------------------------------------
# Writing a policy back out (editors: the GUI's policy-changing buttons)

proc policy_v2_emit {raw} {
    # The version-2 YAML text for a parsed policy dict. Comments and key
    # order of the source file do not survive a rewrite; sections come out
    # in the canonical order with people, groups, collections sorted by key.
    set out {}
    lappend out "# Desired sharing state, audited and enforced with warden"
    lappend out "# (--audit / --enforce). People are named once with their per-platform"
    lappend out "# accounts; groups reference people; grants join a group to a collection."
    lappend out "version: 2"
    lappend out ""
    lappend out "people:"
    foreach slug [lsort [dict keys [dict get $raw people]]] {
        set p [dict get $raw people $slug]
        lappend out "  ${slug}:"
        foreach field {name relationship reason} {
            if {[dict exists $p $field]} {
                lappend out "    ${field}: [policy_yaml_quote [dict get $p $field]]"
            }
        }
        if {[dict exists $p accounts]} {
            lappend out "    accounts:"
            dict for {platform v} [dict get $p accounts] {
                if {[llength $v] == 1} {
                    lappend out "      ${platform}: [policy_yaml_quote [lindex $v 0]]"
                } else {
                    set quoted {}
                    foreach e $v { lappend quoted [policy_yaml_quote $e] }
                    lappend out "      ${platform}: \[[join $quoted {, }]\]"
                }
            }
        }
    }
    lappend out ""
    lappend out "groups:"
    foreach gname [lsort [dict keys [dict get $raw groups]]] {
        set g [dict get $raw groups $gname]
        lappend out "  ${gname}:"
        if {[dict exists $g includes] && [llength [dict get $g includes]] > 0} {
            set quoted {}
            foreach inc [dict get $g includes] { lappend quoted [policy_yaml_quote $inc] }
            lappend out "    includes: \[[join $quoted {, }]\]"
        }
        if {[dict exists $g members] && [llength [dict get $g members]] > 0} {
            lappend out "    members: \[[join [dict get $g members] {, }]\]"
        } elseif {![dict exists $g includes] || [llength [dict get $g includes]] == 0} {
            lappend out "    members: \[\]"
        }
    }
    lappend out ""
    lappend out "collections:"
    foreach cname [lsort [dict keys [dict get $raw collections]]] {
        set c [dict get $raw collections $cname]
        lappend out "  ${cname}:"
        if {[dict exists $c closed] && [dict get $c closed]} {
            lappend out "    closed: true"
        }
        if {[dict exists $c includes] && [llength [dict get $c includes]] > 0} {
            set quoted {}
            foreach inc [dict get $c includes] { lappend quoted [policy_yaml_quote $inc] }
            lappend out "    includes: \[[join $quoted {, }]\]"
        }
        if {[dict exists $c folders]} {
            lappend out "    folders:"
            foreach f [dict get $c folders] {
                lappend out "      - {platform: [dict get $f platform], path: [policy_yaml_quote [dict get $f path]], id: [policy_yaml_quote [dict get $f id]]}"
            }
        }
    }
    lappend out ""
    lappend out "grants:"
    foreach grant [dict get $raw grants] {
        set roles {}
        foreach r [dict get $grant roles] { lappend roles $r }
        lappend out "  - {collection: [policy_yaml_quote [dict get $grant collection]], group: [policy_yaml_quote [dict get $grant group]], roles: \[[join $roles {, }]\]}"
    }
    if {[dict exists $raw outsiders] && [llength [dict get $raw outsiders]] > 0} {
        lappend out ""
        lappend out "outsiders:"
        foreach o [dict get $raw outsiders] {
            lappend out "  - {platform: [dict get $o platform], email: [policy_yaml_quote [dict get $o email]]}"
        }
    }
    return [join $out \n]\n
}

proc policy_save {path raw} {
    # Guarded rewrite: emit next to the file, load-validate the emission,
    # keep a .bak of the original, then rename into place. Fails without
    # touching the original when the emission does not load.
    set text [policy_v2_emit $raw]
    set tmp "$path.new"
    set f [open $tmp w]
    fconfigure $f -encoding utf-8
    puts -nonewline $f $text
    close $f
    if {[catch {policy_load_v2 $tmp} err]} {
        file delete $tmp
        error "refusing to save: the rewritten policy does not load: $err"
    }
    catch {file copy -force $path "$path.bak"}
    file rename -force $tmp $path
}
