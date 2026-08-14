# Platform-neutral policy audit and enforcement over live drives.
#
# The policy (lib/policy.tcl, version 2) declares desired sharing state:
# people with per-platform accounts, groups of people, collections of
# folders addressed by platform + stable id, and grants joining group to
# collection. A grant binds at its collection's folders ("bound" ACL, write
# beating read) and reaches descendants through the platform's inheritance,
# so a folder's "effective" ACL is the union of bound ACLs over itself and
# every policy ancestor on the same platform; a closed folder's is its own
# bound ACL alone. Live direct permissions are judged against the folder's
# own entitlements; live inherited permissions are judged at their source,
# so only inherited access exceeding the effective ACL is flagged here.
# closed: true on a collection makes excess a violation; on open collections
# it is reported but tolerated. Owner permissions are out of scope on both
# sides.
#
# Drives are reached through a provider dict of proc names (connect,
# get_item, item_path, get_acl, invite, remove, sever, capabilities);
# everything in this file is platform-independent given one.

package require yaml

proc provider_for {platform} {
    switch -- $platform {
        onedrive { return [onedrive_provider] }
        dropbox { return [dropbox_provider] }
        default { error "no provider for platform '$platform'" }
    }
}

proc platform_remote {platform remote_name} {
    # --remote names the OneDrive rclone remote; other platforms read their
    # own rclone section.
    switch -- $platform {
        onedrive { return $remote_name }
        dropbox { return "Dropbox" }
        default { error "no rclone remote mapping for platform '$platform'" }
    }
}

proc audit_folder {provider ctx fid fentry} {
    # Audit one policy folder against the live drive behind provider/ctx.
    # Returns {violations live_dict item_dict}; live_dict/item_dict are {}
    # when the folder id no longer resolves.
    set violations {}
    set rel_path [dict get $fentry path]
    set full_path $rel_path

    lassign [{*}[dict get $provider get_item] $ctx $fid] status item_dict
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
    set actual_path [{*}[dict get $provider item_path] $ctx $item_dict]
    if {$actual_path ne "" && $actual_path ne $full_path} {
        lappend violations [dict create type moved path $rel_path id $fid \
            email "" expected "" actual "" \
            detail "policy says '$full_path', actually at '$actual_path'"]
    }

    lassign [{*}[dict get $provider get_acl] $ctx $fid] pstatus acl
    if {$pstatus ne "ok"} {
        lappend violations [dict create type error path $rel_path id $fid \
            email "" expected "" actual "" detail "could not read permissions"]
        return [list $violations {} $item_dict]
    }
    set live_direct [dict get $acl direct]
    set live_inherited [dict get $acl inherited]
    set live_all [dict get $acl all]

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

    # Shared links grant access to anyone holding the URL; a link on a
    # closed folder is a violation, on an open one a note. OneDrive links
    # arrive as permission entries and are judged above; this pass serves
    # providers whose links live outside the member list.
    if {[dict exists $acl links]} {
        foreach link [dict get $acl links] {
            set url [dict get $link url]
            if {$closed} {
                lappend violations [dict create type shared_link path $rel_path id $fid \
                    email "" expected "" actual "" detail "$url on a closed collection"]
            } else {
                lappend violations [dict create type open_link path $rel_path id $fid \
                    email "" expected "" actual "" detail "$url; open collection, tolerated"]
            }
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
    # Tolerated-by-policy excess on open collections, the moved advisory
    # (id is authoritative), links on open collections, and account-wide
    # sweep findings do not fail an audit
    return [expr {[dict get $v type] in {open_extra open_inherited moved open_link phantom_share}}]
}

proc violation_display_name {model v} {
    # "email (Person Name)" when the account maps to a person, else the email
    set email [dict get $v email]
    if {$email eq ""} { return "" }
    set slug ""
    if {[dict exists $v person]} { set slug [dict get $v person] }
    if {$slug ne ""} {
        return "$email ([identity_display $model $slug])"
    }
    return $email
}

proc audit_print_report {violations model format {multi 0}} {
    # multi: more than one platform in play; folder headings then carry the
    # platform so identical paths on two drives stay distinct.
    if {$format eq "csv"} {
        puts "path,folder_id,violation_type,email,expected_role,actual_role,detail,platform,person"
        foreach v $violations {
            set row {}
            foreach field {path id type email expected actual detail platform person} {
                set val [expr {[dict exists $v $field] ? [dict get $v $field] : ""}]
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
        set label [dict get $v path]
        if {$multi && [dict exists $v platform]} {
            set label "\[[dict get $v platform]\] $label"
        }
        dict lappend by_path $label $v
    }
    set real 0
    set info 0
    dict for {path vlist} $by_path {
        puts "📁 $path"
        foreach v $vlist {
            set who [violation_display_name $model $v]
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
                shared_link {
                    puts "   ❌ LINK [dict get $v detail]"
                    incr real
                }
                open_link {
                    puts "   ℹ️  link [dict get $v detail]"
                    incr info
                }
                phantom_share {
                    puts "   ℹ️  [dict get $v detail]"
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

proc print_policy_warnings {model} {
    # Grants the policy holds but no platform account can carry
    foreach w [dict get $model warnings] {
        if {[dict get $w type] eq "unreachable_grant"} {
            puts "⚠️  unreachable grant: [identity_display $model [dict get $w person]] has no [dict get $w platform] account (collection [dict get $w collection], [dict get $w role])"
        }
    }
}

proc stamp_platform_person {model platform violations} {
    # Every violation carries its platform and, where the account maps to a
    # person, the person's slug.
    set out {}
    foreach v $violations {
        dict set v platform $platform
        dict set v person [identity_person_for $model $platform [dict get $v email]]
        lappend out $v
    }
    return $out
}

proc audit_cli {policy_path format remote_name {platform_filter ""}} {
    # Returns the process exit code: 0 clean, 1 violations, 2 policy error
    global quiet_mode
    set quiet_mode [expr {$format eq "csv"}]

    if {[catch {policy_load_v2 $policy_path} model]} {
        puts "❌ Policy error: $model"
        return 2
    }
    set plans [plans_filtered $model $platform_filter]
    set total 0
    dict for {platform subplan} $plans { incr total [dict size $subplan] }

    if {!$quiet_mode} {
        puts "🔍 Auditing $total folder(s) against $policy_path"
        puts ""
        print_policy_warnings $model
    }
    set multi [expr {[dict size $plans] > 1}]

    set violations {}
    dict for {platform subplan} $plans {
        if {[catch {provider_for $platform} provider]} {
            puts "❌ $provider"
            return 2
        }
        set ctx [{*}[dict get $provider connect] [platform_remote $platform $remote_name] read]
        if {$ctx eq ""} {
            puts "❌ Failed to get access token"
            return 2
        }
        foreach fid [plan_ids_parents_first $subplan] {
            lassign [audit_folder $provider $ctx $fid [dict get $subplan $fid]] v _ _
            lappend violations {*}[stamp_platform_person $model $platform $v]
        }
        if {[dict exists $provider sweep]} {
            lappend violations {*}[stamp_platform_person $model $platform \
                [{*}[dict get $provider sweep] $ctx]]
        }
    }

    audit_print_report $violations $model $format $multi

    foreach v $violations {
        if {![violation_is_informational $v]} {
            return 1
        }
    }
    return 0
}

proc enforce_folder {provider ctx fid fentry dry_run} {
    # Bring one folder to its expected ACL.
    # Returns {status changed_something violations_left} where status is
    # ok | warning | error
    lassign [audit_folder $provider $ctx $fid $fentry] violations live item_dict
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

    if {[llength $removal_emails] > 0} {
        lassign [{*}[dict get $provider remove] $ctx $fid $removal_emails] removed blocked
        foreach email $removed { puts "  ✂️  removed $email" }
        if {[llength $blocked] > 0} {
            # Inherited access resists in-place removal; the provider's
            # sever operation detaches the folder from its source and
            # plants the effective ACL explicitly.
            lassign [{*}[dict get $provider sever] $ctx $fid $fentry $item_dict $blocked] sstatus schanged
            if {$sstatus ne "ok"} {
                return [list error $schanged $violations]
            }
            set moved 1
        }
    }

    set unenforceable {}
    if {!$moved} {
        dict for {email role} $to_add {
            lassign [{*}[dict get $provider invite] $ctx $fid $email $role] istatus imsg
            if {$istatus eq "ok"} {
                puts "  ➕ invited $email ($role)"
            } elseif {$istatus eq "ok-notified"} {
                puts "  ➕ invited $email ($role); ⚠️ notification email was sent"
            } elseif {$istatus eq "unenforceable"} {
                puts "  ⛔ $email: $imsg"
                dict set unenforceable $email 1
            } else {
                puts "  ❌ invite $email failed: $imsg"
            }
        }
        dict for {email role} $to_fix {
            lassign [{*}[dict get $provider invite] $ctx $fid $email $role] istatus imsg
            if {$istatus in {ok ok-notified}} {
                puts "  🔁 re-invited $email as $role"
            } elseif {$istatus eq "unenforceable"} {
                puts "  ⛔ $email: $imsg"
                dict set unenforceable $email 1
            } else {
                puts "  ❌ re-invite $email failed: $imsg"
            }
        }
    }

    # Verify, allowing one settle-and-retry for propagation. A violation
    # whose fix the platform's plan refused is residue of a known kind:
    # reported, never blocking the exit.
    foreach wait {0 3000} {
        if {$wait > 0} { after $wait }
        lassign [audit_folder $provider $ctx $fid $fentry] vleft _ _
        set remaining {}
        foreach v $vleft {
            if {[violation_is_informational $v]} { continue }
            if {[dict exists $unenforceable [dict get $v email]] && \
                [dict get $v type] in {missing_user wrong_role}} { continue }
            lappend remaining $v
        }
        if {[llength $remaining] == 0} {
            if {[dict size $unenforceable] > 0} {
                puts "  ✅ verified ([dict size $unenforceable] grant(s) unenforceable on the current plan, listed above)"
            } else {
                puts "  ✅ verified"
            }
            return [list ok 1 {}]
        }
    }
    puts "  ⚠️  still differs after enforcement"
    return [list warning 1 $remaining]
}

proc plans_filtered {model platform_filter} {
    # The per-platform plans, cut to one platform when a filter names it
    set plans [dict get $model plan]
    if {$platform_filter eq ""} { return $plans }
    if {![dict exists $plans $platform_filter]} {
        error "the policy has no $platform_filter folders"
    }
    return [dict create $platform_filter [dict get $plans $platform_filter]]
}

proc enforce_cli {policy_path dry_run auto_yes remote_name {platform_filter ""}} {
    # Returns the process exit code: 0 clean, 1 residue, 2 policy error
    if {[catch {policy_load_v2 $policy_path} model]} {
        puts "❌ Policy error: $model"
        return 2
    }
    if {[catch {plans_filtered $model $platform_filter} plans]} {
        puts "❌ $plans"
        return 2
    }
    set total 0
    dict for {platform subplan} $plans { incr total [dict size $subplan] }
    set multi [expr {[dict size $plans] > 1}]

    # Connect every platform up front (write mode): a missing token stops
    # the run before anything is touched anywhere.
    set ctxs {}
    set providers {}
    dict for {platform subplan} $plans {
        if {[catch {provider_for $platform} provider]} {
            puts "❌ $provider"
            return 2
        }
        if {![dict exists $provider invite]} {
            puts "❌ the $platform provider audits only; enforcement for it is not built yet (--platform can exclude it)"
            return 2
        }
        set ctx [{*}[dict get $provider connect] [platform_remote $platform $remote_name] write]
        if {$ctx eq ""} {
            return 2
        }
        dict set providers $platform $provider
        dict set ctxs $platform $ctx
    }

    # Show the whole plan before touching anything
    puts "🔍 Auditing $total folder(s) against $policy_path"
    puts ""
    print_policy_warnings $model
    set violations {}
    set dirty {}
    set audit_errors 0
    dict for {platform subplan} $plans {
        set provider [dict get $providers $platform]
        set ctx [dict get $ctxs $platform]
        foreach fid [plan_ids_parents_first $subplan] {
            lassign [audit_folder $provider $ctx $fid [dict get $subplan $fid]] v _ _
            lappend violations {*}[stamp_platform_person $model $platform $v]
            foreach viol $v {
                if {[dict get $viol type] in {missing_user wrong_role extra_user leaked_inherited}} {
                    if {[list $platform $fid] ni $dirty} { lappend dirty [list $platform $fid] }
                } elseif {[dict get $viol type] in {error not_found}} {
                    incr audit_errors
                }
            }
        }
    }
    audit_print_report $violations $model text $multi

    if {[llength $dirty] == 0} {
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
        puts -nonewline "Apply the fixes above to [llength $dirty] folder(s)? \[Y/n\]: "
        flush stdout
        set answer [gets stdin]
        if {$answer ne "" && [string tolower $answer] ne "y" && [string tolower $answer] ne "yes"} {
            puts "Aborted."
            return 1
        }
    }

    set exit_code 0
    set changed {}
    foreach pf $dirty {
        lassign $pf platform fid
        set fentry [dict get $plans $platform $fid]
        puts "📁 [expr {$multi ? "\[$platform\] " : ""}][dict get $fentry path]"
        lassign [enforce_folder [dict get $providers $platform] [dict get $ctxs $platform] $fid $fentry $dry_run] status was_changed _
        if {$status ne "ok"} { set exit_code 1 }
        if {$was_changed} { lappend changed [list $platform [dict get $fentry path]] }
        puts ""
    }

    if {$dry_run} {
        return $exit_code
    }

    # A change at a parent cascades: an added user leaks an inherited copy
    # into locked descendants (docs/INHERITANCE-LEAKING-IN-LOCKED-FOLDERS.md),
    # and a role downgrade at a parent can strip a descendant's team below
    # its own grant. One repair pass over every policy folder below a
    # changed one, on that folder's platform.
    set repair {}
    dict for {platform subplan} $plans {
        dict for {fid fentry} $subplan {
            set fpath [dict get $fentry path]
            foreach cp $changed {
                lassign $cp cplatform cpath
                if {$cplatform ne $platform || $cpath eq $fpath} { continue }
                if {$cpath eq "/" || [string match "$cpath/*" $fpath]} {
                    if {[list $platform $fid] ni $repair} { lappend repair [list $platform $fid] }
                    break
                }
            }
        }
    }
    if {[llength $repair] > 0} {
        puts "🔁 Re-checking [llength $repair] folder(s) below changed parents for cascade effects"
        foreach pf $repair {
            lassign $pf platform fid
            set fentry [dict get $plans $platform $fid]
            puts "📁 [expr {$multi ? "\[$platform\] " : ""}][dict get $fentry path]"
            lassign [enforce_folder [dict get $providers $platform] [dict get $ctxs $platform] $fid $fentry 0] status _ _
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
