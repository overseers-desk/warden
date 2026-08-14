# Policy audit and enforcement over a live drive.
package require yaml

# ============================================================================
# Policy Audit & Enforcement
# ============================================================================
# A policy YAML file declares desired sharing state: groups (people),
# collections (folder sets addressed by stable item id), and grants joining
# the two. A grant binds at the folders of its collection ("bound" ACL,
# write beating read) and reaches descendants through OneDrive inheritance,
# so a folder's "effective" ACL is the union of bound ACLs over itself and
# every policy ancestor; a closed folder's is its own bound ACL alone.
# Live direct permissions are judged against the
# folder's own entitlements; live inherited permissions are judged at their
# source, so only inherited access exceeding the effective ACL is flagged
# here. closed: true on a collection makes excess a violation; on open
# collections it is reported but tolerated. Owner permissions are out of
# scope on both sides.
proc policy_member_email {member} {
    # A group member is either a bare email string or a record
    # {email ... name ... relationship ... reason ...}
    if {[llength $member] % 2 == 0 && [dict exists $member email]} {
        return [string tolower [dict get $member email]]
    }
    return [string tolower $member]
}

proc policy_resolve_group {groups name chain} {
    # Recursive union of a group's members and includes.
    # Returns a lowercased email list; errors on unknown names and cycles.
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
    set emails {}
    if {[dict exists $g members]} {
        foreach m [dict get $g members] {
            lappend emails [policy_member_email $m]
        }
    }
    if {[dict exists $g includes]} {
        foreach inc [dict get $g includes] {
            lappend emails {*}[policy_resolve_group $groups $inc [concat $chain [list $name]]]
        }
    }
    return [lsort -unique $emails]
}

proc policy_resolve_collection {collections name chain} {
    # Recursive union of a collection's folders and includes.
    # Returns a list of {path <p> id <i>} dicts; errors on unknown names,
    # cycles, and folder entries missing path or id.
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
            if {![dict exists $f path] || ![dict exists $f id]} {
                error "collection '$name' has a folder entry without both path and id"
            }
            lappend folders $f
        }
    }
    if {[dict exists $c includes]} {
        foreach inc [dict get $c includes] {
            lappend folders {*}[policy_resolve_collection $collections $inc [concat $chain [list $name]]]
        }
    }
    return $folders
}

proc policy_load {yaml_path} {
    # Load and validate a policy file into the model the audit runs on:
    #   people  - email -> {name relationship reason} (for reporting)
    #   plan    - folder id -> {path closed expected} with expected an
    #             email -> role dict
    # Throws a plain-message error on any structural problem.
    set f [open $yaml_path r]
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
    set collections [dict get $policy collections]

    # People metadata for reporting, first record wins
    set people {}
    dict for {gname g} $groups {
        if {![dict exists $g members]} { continue }
        foreach m [dict get $g members] {
            if {[llength $m] % 2 != 0 || ![dict exists $m email]} { continue }
            set email [string tolower [dict get $m email]]
            if {[dict exists $people $email]} { continue }
            set rec {}
            foreach field {name relationship reason} {
                if {[dict exists $m $field]} {
                    dict set rec $field [dict get $m $field]
                }
            }
            dict set people $email $rec
        }
    }

    # Closed flag per folder id: closed if any collection containing it is closed
    set closed_ids {}
    dict for {cname c} $collections {
        if {![dict exists $c closed] || ![dict get $c closed]} { continue }
        foreach f [policy_resolve_collection $collections $cname {}] {
            dict set closed_ids [dict get $f id] 1
        }
    }

    # Expected ACL per folder from the grants
    set plan {}
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
        set emails [policy_resolve_group $groups [dict get $grant group] {}]
        foreach f [policy_resolve_collection $collections [dict get $grant collection] {}] {
            set fid [dict get $f id]
            if {![dict exists $plan $fid]} {
                dict set plan $fid [dict create \
                    path [dict get $f path] \
                    closed [expr {[dict exists $closed_ids $fid] ? 1 : 0}] \
                    expected {}]
            }
            set expected [dict get $plan $fid expected]
            foreach email $emails {
                if {![dict exists $expected $email] || [dict get $expected $email] ne "write"} {
                    dict set expected $email $role
                }
            }
            dict set plan $fid expected $expected
        }
    }

    # Folders in collections but granted nothing still deserve auditing
    dict for {cname c} $collections {
        foreach f [policy_resolve_collection $collections $cname {}] {
            set fid [dict get $f id]
            if {![dict exists $plan $fid]} {
                dict set plan $fid [dict create \
                    path [dict get $f path] \
                    closed [expr {[dict exists $closed_ids $fid] ? 1 : 0}] \
                    expected {}]
            }
        }
    }

    # Effective ACL: what a user may hold at this folder from any source,
    # the folder's own grants plus every policy ancestor's (OneDrive
    # inheritance carries ancestor grants down), write beating read.
    # A closed folder absorbs nothing: its ACL is exhaustively its own
    # grants, and enforcement severs inheritance to make that real.
    dict for {fid fentry} $plan {
        if {[dict get $fentry closed]} {
            dict set plan $fid effective [dict get $fentry expected]
            continue
        }
        set fpath [dict get $fentry path]
        set effective [dict get $fentry expected]
        dict for {aid aentry} $plan {
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
        dict set plan $fid effective $effective
    }

    return [dict create people $people plan $plan]
}

proc audit_folder {fid fentry access_token} {
    # Audit one policy folder against the live drive.
    # Returns {violations live_dict item_dict}; live_dict/item_dict are {} when
    # the folder id no longer resolves.
    set violations {}
    set rel_path [dict get $fentry path]
    set full_path $rel_path

    lassign [get_item_by_id $fid $access_token] status item_dict
    if {$status eq "not_found"} {
        lappend violations [dict create type not_found path $rel_path id $fid \
            email "" expected "" actual "" detail "item id no longer resolves; folder deleted or id changed"]
        return [list $violations {} {}]
    } elseif {$status ne "ok"} {
        lappend violations [dict create type error path $rel_path id $fid \
            email "" expected "" actual "" detail "could not fetch item by id"]
        return [list $violations {} {}]
    }

    # Drift: the id is authoritative, the path is the human label
    set actual_path [item_actual_path $item_dict]
    if {$actual_path ne "" && $actual_path ne $full_path} {
        lappend violations [dict create type moved path $rel_path id $fid \
            email "" expected "" actual "" \
            detail "policy says '$full_path', actually at '$actual_path'"]
    }

    lassign [get_folder_permissions $fid $access_token] pstatus permissions
    if {$pstatus ne "ok"} {
        lappend violations [dict create type error path $rel_path id $fid \
            email "" expected "" actual "" detail "could not read permissions"]
        return [list $violations {} $item_dict]
    }

    set direct_perms {}
    set inherited_perms {}
    foreach perm $permissions {
        if {[is_owner_permission $perm]} { continue }
        if {[is_inherited_permission $perm]} {
            lappend inherited_perms $perm
        } else {
            lappend direct_perms $perm
        }
    }
    set live_direct [extract_users_from_permissions $direct_perms]
    set live_inherited [extract_users_from_permissions $inherited_perms]
    set live_all [extract_users_from_permissions $permissions]

    set bound [dict get $fentry expected]
    set effective [dict get $fentry effective]
    set closed [dict get $fentry closed]

    # Grants binding here must be satisfied here (inherited access counts)
    dict for {email role} $bound {
        if {![dict exists $live_all $email]} {
            lappend violations [dict create type missing_user path $rel_path id $fid \
                email $email expected $role actual "" detail ""]
        } elseif {$role eq "write" && [dict get $live_all $email] ne "write"} {
            lappend violations [dict create type missing_user path $rel_path id $fid \
                email $email expected $role actual [dict get $live_all $email] \
                detail "holds read only; a direct write invite raises it"]
        }
    }

    # Direct permissions answer to this folder's entitlements
    dict for {email drole} $live_direct {
        if {[dict exists $bound $email] && [dict get $bound $email] eq $drole} { continue }
        if {[dict exists $effective $email]} {
            set erole [dict get $effective $email]
            if {$drole eq $erole || $erole eq "write"} { continue }
            lappend violations [dict create type wrong_role path $rel_path id $fid \
                email $email expected $erole actual $drole detail "direct permission exceeds entitlement"]
        } elseif {$closed} {
            lappend violations [dict create type extra_user path $rel_path id $fid \
                email $email expected "" actual $drole detail "closed collection"]
        } else {
            lappend violations [dict create type open_extra path $rel_path id $fid \
                email $email expected "" actual $drole detail "open collection, tolerated"]
        }
    }

    # Inherited permissions are fixed at their source folder; flagged here
    # only when they exceed what any source could legitimately confer
    dict for {email irole} $live_inherited {
        set ok [expr {[dict exists $effective $email] && \
            ([dict get $effective $email] eq "write" || $irole eq "read")}]
        if {$ok} { continue }
        if {$closed} {
            lappend violations [dict create type leaked_inherited path $rel_path id $fid \
                email $email expected "" actual $irole \
                detail "inherited access beyond entitlement; removal severs inheritance"]
        } else {
            lappend violations [dict create type open_inherited path $rel_path id $fid \
                email $email expected "" actual $irole \
                detail "inherited access beyond entitlement on open collection, tolerated"]
        }
    }

    return [list $violations $live_all $item_dict]
}

proc plan_ids_parents_first {plan} {
    # Folder ids ordered by path depth so parent-level changes land before
    # their descendants are examined
    set with_depth {}
    dict for {fid fentry} $plan {
        set p [dict get $fentry path]
        set depth [expr {$p eq "/" ? 0 : [llength [split $p "/"]]}]
        lappend with_depth [list $depth $fid]
    }
    set ids {}
    foreach pair [lsort -integer -index 0 $with_depth] {
        lappend ids [lindex $pair 1]
    }
    return $ids
}

proc violation_is_informational {v} {
    # Tolerated-by-policy excess on open collections and the moved
    # advisory (id is authoritative) do not fail an audit
    return [expr {[dict get $v type] in {open_extra open_inherited moved}}]
}

proc audit_print_report {violations people format} {
    if {$format eq "csv"} {
        puts "path,folder_id,violation_type,email,expected_role,actual_role,detail"
        foreach v $violations {
            set row {}
            foreach field {path id type email expected actual detail} {
                set val [dict get $v $field]
                if {[string first "," $val] >= 0 || [string first "\"" $val] >= 0} {
                    set val "\"[string map {\" \"\"} $val]\""
                }
                lappend row $val
            }
            puts [join $row ","]
        }
        return
    }

    set by_path {}
    foreach v $violations {
        dict lappend by_path [dict get $v path] $v
    }
    set real 0
    set info 0
    dict for {path vlist} $by_path {
        puts "📁 $path"
        foreach v $vlist {
            set email [dict get $v email]
            set who $email
            if {$email ne "" && [dict exists $people $email name]} {
                set who "$email ([dict get $people $email name])"
            }
            switch [dict get $v type] {
                missing_user {
                    puts "   ❌ MISSING $who (expected [dict get $v expected])"
                    incr real
                }
                wrong_role {
                    puts "   ❌ WRONG ROLE $who (expected [dict get $v expected], has [dict get $v actual])"
                    incr real
                }
                extra_user {
                    puts "   ❌ EXTRA $who (has [dict get $v actual]; [dict get $v detail])"
                    incr real
                }
                leaked_inherited {
                    puts "   ❌ LEAKED $who (inherited [dict get $v actual]; [dict get $v detail])"
                    incr real
                }
                open_extra {
                    puts "   ℹ️  extra $who (has [dict get $v actual]; [dict get $v detail])"
                    incr info
                }
                open_inherited {
                    puts "   ℹ️  inherited extra $who ([dict get $v actual]; [dict get $v detail])"
                    incr info
                }
                moved {
                    puts "   ⚠️  MOVED: [dict get $v detail]"
                    incr info
                }
                not_found -
                error {
                    puts "   ❌ [string toupper [dict get $v type]]: [dict get $v detail]"
                    incr real
                }
            }
        }
        puts ""
    }
    puts "Summary: $real violation(s), $info informational note(s)"
}

proc audit_cli {policy_path format remote_name} {
    # Returns the process exit code: 0 clean, 1 violations, 2 policy error
    global quiet_mode
    set quiet_mode [expr {$format eq "csv"}]

    if {[catch {policy_load $policy_path} model]} {
        puts "❌ Policy error: $model"
        return 2
    }
    set plan [dict get $model plan]

    if {!$quiet_mode} {
        puts "🔍 Auditing [dict size $plan] folder(s) against $policy_path"
        puts ""
    }

    set result [get_access_token $remote_name "" "detailed" 1]
    set access_token [lindex $result 0]
    if {$access_token eq ""} {
        puts "❌ Failed to get access token"
        return 2
    }

    set violations {}
    foreach fid [plan_ids_parents_first $plan] {
        lassign [audit_folder $fid [dict get $plan $fid] $access_token] v _ _
        lappend violations {*}$v
    }

    audit_print_report $violations [dict get $model people] $format

    foreach v $violations {
        if {![violation_is_informational $v]} {
            return 1
        }
    }
    return 0
}

proc enforce_remove_emails {fid emails access_token} {
    # Remove every permission naming one of the emails on this folder,
    # trying in place first: Graph refuses deletion of inherited permissions
    # (inheritedFrom must be null), but probing keeps the tool correct the
    # day Microsoft lifts that rule.
    # Returns {removed_emails blocked_emails}: blocked = still inherited here
    lassign [get_folder_permissions $fid $access_token] status permissions
    if {$status ne "ok"} {
        return [list {} $emails]
    }
    set removed {}
    set blocked {}
    foreach email $emails {
        set done 0
        set seen 0
        foreach perm $permissions {
            if {[is_owner_permission $perm]} { continue }
            set match 0
            foreach user_info [extract_users_from_perm $perm] {
                if {[string tolower [lindex $user_info 1]] eq $email} {
                    set match 1
                    break
                }
            }
            if {!$match} { continue }
            set seen 1
            lassign [remove_permission $fid [dict get $perm id] $access_token] rstatus rmsg
            if {$rstatus eq "ok"} {
                set done 1
            }
        }
        if {$done} {
            lappend removed $email
        } elseif {$seen} {
            lappend blocked $email
        }
    }

    # Deleting an inherited copy of a leaked permission reports success yet
    # the entry survives (docs/PHANTOM-INHERITANCE-BUG.md, retest
    # 2026-08-05), so success is only believed after a re-read
    if {[llength $removed] > 0} {
        after 1000
        lassign [get_folder_permissions $fid $access_token] vstatus vperms
        if {$vstatus eq "ok"} {
            set still [extract_users_from_permissions $vperms]
            set truly_removed {}
            foreach email $removed {
                if {[dict exists $still $email]} {
                    lappend blocked $email
                } else {
                    lappend truly_removed $email
                }
            }
            set removed $truly_removed
        }
    }
    return [list $removed $blocked]
}

proc enforce_folder {fid fentry root_id access_token dry_run} {
    # Bring one folder to its expected ACL.
    # Returns {status changed_something violations_left} where status is
    # ok | warning | error
    lassign [audit_folder $fid $fentry $access_token] violations live item_dict
    set rel_path [dict get $fentry path]

    set to_add {}
    set to_fix {}
    set to_remove {}
    foreach v $violations {
        switch [dict get $v type] {
            missing_user      { dict set to_add [dict get $v email] [dict get $v expected] }
            wrong_role        { dict set to_fix [dict get $v email] [dict get $v expected] }
            extra_user -
            leaked_inherited  { dict set to_remove [dict get $v email] [dict get $v actual] }
            not_found -
            error             { return [list error 0 $violations] }
        }
    }

    if {[dict size $to_add] == 0 && [dict size $to_fix] == 0 && [dict size $to_remove] == 0} {
        return [list ok 0 {}]
    }

    if {$dry_run} {
        dict for {email role} $to_add { puts "  \[dry-run\] would invite $email ($role) to $rel_path" }
        dict for {email role} $to_fix { puts "  \[dry-run\] would re-invite $email as $role on $rel_path" }
        dict for {email role} $to_remove { puts "  \[dry-run\] would remove $email from $rel_path" }
        return [list ok 0 {}]
    }

    set removal_emails [concat [dict keys $to_remove] [dict keys $to_fix]]
    set moved 0
    set original_parent ""

    if {[llength $removal_emails] > 0} {
        lassign [enforce_remove_emails $fid $removal_emails $access_token] removed blocked
        foreach email $removed { puts "  ✂️  removed $email" }
        if {[llength $blocked] > 0} {
            # Live inherited permissions resist in-place deletion. At the
            # drive root they detach entirely, and a folder returned to a
            # shared tree re-attaches to the parent's inheritance unless it
            # carries its own permission scope. So: move out, delete
            # whatever explicit residue names the blocked users, plant the
            # folder's full effective ACL as explicit permissions, and only
            # then move back.
            puts "  🚚 inherited permissions on [join $blocked {, }]: moving folder to root to sever inheritance"
            if {![dict exists $item_dict parentReference id]} {
                return [list error 0 $violations]
            }
            set original_parent [dict get $item_dict parentReference id]
            lassign [move_item $fid $root_id $access_token] mstatus mmsg
            if {$mstatus ne "ok"} {
                puts "  ❌ move failed: $mmsg"
                return [list error 0 $violations]
            }
            set moved 1
            after 2000
            lassign [enforce_remove_emails $fid $blocked $access_token] removed2 blocked2
            foreach email $removed2 { puts "  ✂️  removed $email (after move)" }
            foreach email $blocked2 { puts "  ❌ still cannot remove $email" }
        }
    }

    if {$moved} {
        # Plant the effective ACL while inheritance is severed; the
        # explicit scope keeps the folder from re-inheriting on return
        lassign [get_folder_permissions $fid $access_token] pstatus perms_now
        if {$pstatus ne "ok"} {
            puts "  ❌ cannot read permissions at root; leaving folder in place"
        } else {
            set live_now [extract_users_from_permissions $perms_now]
            dict for {email role} [dict get $fentry effective] {
                if {[dict exists $live_now $email] && \
                    ([dict get $live_now $email] eq $role || [dict get $live_now $email] eq "write")} { continue }
                lassign [invite_user_to_item $fid $email $role $access_token 1] istatus imsg
                if {$istatus eq "ok"} {
                    puts "  🌱 planted $email ($role)"
                } elseif {$istatus eq "ok-notified"} {
                    puts "  🌱 planted $email ($role); ⚠️ notification email was sent"
                } else {
                    puts "  ❌ plant $email failed: $imsg"
                }
            }
        }
        lassign [move_item $fid $original_parent $access_token] mstatus mmsg
        if {$mstatus ne "ok"} {
            puts "  ❌ MOVE BACK FAILED: $mmsg  (folder is sitting at the drive root)"
            return [list error 1 $violations]
        }
        after 2000
    } else {
        dict for {email role} $to_add {
            lassign [invite_user_to_item $fid $email $role $access_token 1] istatus imsg
            if {$istatus eq "ok"} {
                puts "  ➕ invited $email ($role)"
            } elseif {$istatus eq "ok-notified"} {
                puts "  ➕ invited $email ($role); ⚠️ notification email was sent"
            } else {
                puts "  ❌ invite $email failed: $imsg"
            }
        }
        dict for {email role} $to_fix {
            lassign [invite_user_to_item $fid $email $role $access_token 1] istatus imsg
            if {$istatus in {ok ok-notified}} {
                puts "  🔁 re-invited $email as $role"
            } else {
                puts "  ❌ re-invite $email failed: $imsg"
            }
        }
    }

    # Verify, allowing one settle-and-retry for propagation
    foreach wait {0 3000} {
        if {$wait > 0} { after $wait }
        lassign [audit_folder $fid $fentry $access_token] vleft _ _
        set remaining {}
        foreach v $vleft {
            if {![violation_is_informational $v]} { lappend remaining $v }
        }
        if {[llength $remaining] == 0} {
            puts "  ✅ verified"
            return [list ok 1 {}]
        }
    }
    puts "  ⚠️  still differs after enforcement"
    return [list warning 1 $remaining]
}

proc enforce_cli {policy_path dry_run auto_yes remote_name} {
    # Returns the process exit code: 0 clean, 1 residue, 2 policy error
    if {[catch {policy_load $policy_path} model]} {
        puts "❌ Policy error: $model"
        return 2
    }
    set plan [dict get $model plan]
    set people [dict get $model people]

    set access_token [cli_get_full_token $remote_name]
    if {$access_token eq ""} {
        return 2
    }

    # The drive root receives folders moved to sever inheritance
    set root_result [cli_path_to_item_id_and_dict "/" $access_token]
    if {[llength $root_result] == 0} {
        return 2
    }
    set root_id [lindex $root_result 0]

    # Show the whole plan before touching anything
    puts "🔍 Auditing [dict size $plan] folder(s) against $policy_path"
    puts ""
    set violations {}
    set dirty_ids {}
    set audit_errors 0
    foreach fid [plan_ids_parents_first $plan] {
        lassign [audit_folder $fid [dict get $plan $fid] $access_token] v _ _
        lappend violations {*}$v
        foreach viol $v {
            if {[dict get $viol type] in {missing_user wrong_role extra_user leaked_inherited}} {
                if {[lsearch -exact $dirty_ids $fid] < 0} { lappend dirty_ids $fid }
            } elseif {[dict get $viol type] in {error not_found}} {
                incr audit_errors
            }
        }
    }
    audit_print_report $violations $people text

    if {[llength $dirty_ids] == 0} {
        puts "Nothing to enforce."
        foreach v $violations {
            if {![violation_is_informational $v]} { return 1 }
        }
        return 0
    }

    if {$dry_run} {
        puts "⚠️  DRY RUN MODE - No changes will be made"
        puts ""
    } elseif {!$auto_yes} {
        puts -nonewline "Apply the fixes above to [llength $dirty_ids] folder(s)? \[Y/n\]: "
        flush stdout
        set answer [gets stdin]
        if {$answer ne "" && [string tolower $answer] ne "y" && [string tolower $answer] ne "yes"} {
            puts "Aborted."
            return 1
        }
    }

    set exit_code 0
    set changed_paths {}
    foreach fid $dirty_ids {
        set fentry [dict get $plan $fid]
        puts "📁 [dict get $fentry path]"
        lassign [enforce_folder $fid $fentry $root_id $access_token $dry_run] status changed _
        if {$status ne "ok"} { set exit_code 1 }
        if {$changed} { lappend changed_paths [dict get $fentry path] }
        puts ""
    }

    if {$dry_run} {
        return $exit_code
    }

    # A change at a parent cascades: an added user leaks an inherited copy
    # into locked descendants (docs/INHERITANCE-LEAKING-IN-LOCKED-FOLDERS.md),
    # and a role downgrade at a parent can strip a descendant's team below
    # its own grant. One repair pass over every policy folder below a
    # changed one.
    set repair_ids {}
    dict for {fid fentry} $plan {
        set fpath [dict get $fentry path]
        foreach cpath $changed_paths {
            if {$cpath eq $fpath} { continue }
            if {$cpath eq "/" || [string match "$cpath/*" $fpath]} {
                if {[lsearch -exact $repair_ids $fid] < 0} { lappend repair_ids $fid }
                break
            }
        }
    }
    if {[llength $repair_ids] > 0} {
        puts "🔁 Re-checking [llength $repair_ids] folder(s) below changed parents for cascade effects"
        foreach fid $repair_ids {
            set fentry [dict get $plan $fid]
            puts "📁 [dict get $fentry path]"
            lassign [enforce_folder $fid $fentry $root_id $access_token 0] status _ _
            if {$status ne "ok"} { set exit_code 1 }
            puts ""
        }
    }

    if {$audit_errors > 0} {
        puts "⚠️  $audit_errors folder(s) could not be audited and were not enforced; re-run."
        set exit_code 1
    }
    if {$exit_code == 0} {
        puts "✅ Enforcement complete; drive matches the policy."
    } else {
        puts "⚠️  Enforcement finished with residue; re-run --audit for the current state."
    }
    return $exit_code
}
