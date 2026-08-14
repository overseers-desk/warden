# Dropbox via the sharing and files APIs, using the OAuth token rclone
# stores for its Dropbox remote. Behavioural rules learned the hard way
# live in docs/DROPBOX.md; the sharing API's surface routinely differs
# from its semantics, so read them before touching a sharing endpoint.
package require http
package require tls
package require json
package require json::write

proc read_dropbox_token {remote} {
    # The OAuth access token rclone stores for the named remote.
    if {[info exists ::env(APPDATA)]} {
        set conf [file join $::env(APPDATA) rclone rclone.conf]
    } else {
        set conf [file join $::env(HOME) .config rclone rclone.conf]
    }
    if {![file exists $conf]} {
        error "rclone.conf not found at $conf"
    }
    set f [open $conf r]
    set data [read $f]
    close $f

    set in_section 0
    set token_json ""
    foreach line [split $data \n] {
        set line [string trim $line]
        if {[regexp {^\[(.+)\]$} $line -> name]} {
            set in_section [expr {$name eq $remote}]
            continue
        }
        if {!$in_section} continue
        if {[regexp {^token\s*=\s*(.*)$} $line -> rest]} {
            set token_json [string trim $rest]
        }
    }
    if {$token_json eq ""} {
        error "no token found for \[$remote\] in $conf"
    }
    set d [::json::json2dict $token_json]
    if {![dict exists $d access_token]} {
        error "no access_token in token JSON"
    }
    return [string trim [dict get $d access_token]]
}

proc dbx_call {token endpoint body_json} {
    set url "https://api.dropboxapi.com$endpoint"
    set body_bytes [encoding convertto utf-8 $body_json]
    set tok [::http::geturl $url \
        -method POST \
        -query $body_bytes \
        -type "application/json; charset=utf-8" \
        -headers [list Authorization "Bearer $token"]]
    set status [::http::ncode $tok]
    set data [::http::data $tok]
    ::http::cleanup $tok
    if {$status >= 200 && $status < 300} {
        if {$data eq "" || $data eq "null"} { return [dict create] }
        return [::json::json2dict [combine_surrogate_escapes [encoding convertfrom utf-8 $data]]]
    }
    error "Dropbox $endpoint HTTP $status: $data"
}

proc dbx_get_metadata {token path} {
    return [dbx_call $token /2/files/get_metadata \
        [::json::write::object path [::json::write::string $path]]]
}

proc dbx_list_links {token path} {
    set urls [list]
    set body [::json::write::object path [::json::write::string $path]]
    while {1} {
        set resp [dbx_call $token /2/sharing/list_shared_links $body]
        foreach link [dict get $resp links] {
            lappend urls [dict get $link url]
        }
        if {[dict exists $resp has_more] && [dict get $resp has_more]} {
            set body [::json::write::object \
                path [::json::write::string $path] \
                cursor [::json::write::string [dict get $resp cursor]]]
        } else break
    }
    return $urls
}

proc dbx_revoke_link {token url} {
    dbx_call $token /2/sharing/revoke_shared_link \
        [::json::write::object url [::json::write::string $url]]
}

proc dbx_unshare_file {token path} {
    dbx_call $token /2/sharing/unshare_file \
        [::json::write::object file [::json::write::string $path]]
}

proc dbx_wait_share_job {token job_id} {
    # JobStatus.failed nests two levels: failed.<wrapper>.tag holds the
    # actual reason (e.g. no_permission); reading just failed.tag returns
    # the operation-specific wrapper (e.g. unshare_folder_error) which is
    # the same string for every failure of the endpoint and gives no
    # diagnostic. See docs/DROPBOX.md.
    set body [::json::write::object \
        async_job_id [::json::write::string $job_id]]
    while {1} {
        set st [dbx_call $token /2/sharing/check_job_status $body]
        set tag [dict get $st .tag]
        if {$tag eq "in_progress"} { after 2000; continue }
        if {$tag eq "complete"} return
        if {$tag eq "failed"} {
            set reason "unknown"
            if {[dict exists $st failed]} {
                set f [dict get $st failed]
                if {[dict exists $f .tag]} {
                    set outer [dict get $f .tag]
                    set reason $outer
                    if {[dict exists $f $outer .tag]} {
                        set reason "$outer/[dict get $f $outer .tag]"
                    }
                }
            }
            error "job failed: $reason"
        }
        error "unexpected check_job_status response: $st"
    }
}

proc dbx_mount_folder {token sfid} {
    return [dbx_call $token /2/sharing/mount_folder \
        [::json::write::object shared_folder_id [::json::write::string $sfid]]]
}

proc dbx_list_all_folders {token} {
    # Paginates /2/sharing/list_folders and returns every SharedFolderMetadata
    # entry the account knows about (with-path, no-path, owned, joined).
    set out [list]
    set body [::json::write::object limit 1000]
    set resp [dbx_call $token /2/sharing/list_folders $body]
    while {1} {
        foreach e [dict get $resp entries] { lappend out $e }
        if {[dict exists $resp cursor] && [dict get $resp cursor] ne ""} {
            set body [::json::write::object cursor [::json::write::string [dict get $resp cursor]]]
            set resp [dbx_call $token /2/sharing/list_folders/continue $body]
        } else break
    }
    return $out
}

proc dbx_list_children {token parent_sfid} {
    # Returns SharedFolderMetadata for all shared folders (with or
    # without a path) whose parent_shared_folder_id matches parent_sfid.
    # Both kinds block the parent's unshare per Dropbox's rules.
    #
    # list_folders is unreliable: it omits parent_shared_folder_id from
    # some entries that have a path even when get_folder_metadata reports
    # it. We therefore re-query get_folder_metadata for any entry where
    # the field is missing in the list result. See docs/DROPBOX.md.
    set out [list]
    set all [dbx_list_all_folders $token]
    foreach e $all {
        set sfid [dict get $e shared_folder_id]
        if {$sfid eq $parent_sfid} continue
        if {[dict exists $e parent_shared_folder_id]} {
            if {[dict get $e parent_shared_folder_id] eq $parent_sfid} {
                lappend out $e
            }
            continue
        }
        # Field missing from list result; re-query.
        if {[catch {set m [dbx_call $token /2/sharing/get_folder_metadata \
                [::json::write::object shared_folder_id [::json::write::string $sfid]]]}]} {
            continue
        }
        if {[dict exists $m parent_shared_folder_id] && \
            [dict get $m parent_shared_folder_id] eq $parent_sfid} {
            lappend out $m
        }
    }
    return $out
}

proc try_unshare_sfid {token sfid} {
    # Recursively unshare a shared folder by sfid. Revokes any shared links
    # on its path if it has one, attempts unshare_folder, and on no_permission
    # tries two escape hatches in order:
    #   1. enumerate child shared folders (with and without a path), mount
    #      the no-path ones, recurse on each, retry the parent;
    #   2. if the folder is itself a nested shared folder with a path (has
    #      parent_shared_folder_id and a path), move it to top-level via
    #      files/move_v2 to sever the inheritance link, retry.
    # Returns 1 on success, 0 otherwise. See docs/DROPBOX.md.
    set m [dbx_call $token /2/sharing/get_folder_metadata \
        [::json::write::object shared_folder_id [::json::write::string $sfid]]]
    set path ""
    if {[dict exists $m path_display]} { set path [dict get $m path_display] }
    set name ""
    if {[dict exists $m name]} { set name [dict get $m name] }
    set has_parent [dict exists $m parent_shared_folder_id]
    if {$path ne ""} {
        set label "$path (id $sfid)"
    } else {
        set label "\"$name\" (id $sfid, no path)"
    }

    if {$path ne ""} {
        foreach url [dbx_list_links $token $path] {
            puts "  revoke link: $url"
            dbx_revoke_link $token $url
        }
    }

    puts "  unshare_folder: $label"
    if {![catch {dbx_unshare_folder $token $sfid} err]} {
        return 1
    }
    puts "    failed: $err"
    if {![string match "*no_permission*" $err]} {
        return 0
    }

    set kids [dbx_list_children $token $sfid]
    if {[llength $kids] > 0} {
        puts "    descending into [llength $kids] child shared folder(s) ..."
        foreach k $kids {
            set k_sfid [dict get $k shared_folder_id]
            set k_has_path 0
            if {[dict exists $k path_display] && [dict get $k path_display] ne ""} {
                set k_has_path 1
            }
            if {!$k_has_path} {
                if {[catch {set mm [dbx_mount_folder $token $k_sfid]} merr]} {
                    puts "    mount_folder $k_sfid failed: $merr; skipping"
                    continue
                }
                puts "    mounted no-path child $k_sfid at [dict get $mm path_display]"
            }
            if {[catch {try_unshare_sfid $token $k_sfid} kerr]} {
                puts "    error processing child $k_sfid: $kerr"
            }
        }
        puts "  retrying unshare_folder: $label"
        if {![catch {dbx_unshare_folder $token $sfid} err2]} {
            return 1
        }
        puts "    retry failed: $err2"
    }

    if {$has_parent && $path ne ""} {
        # Greedy sunset: each frame pairs its own move-out with a matching
        # move-back, so the call stack unwinds in reverse order of the
        # moves and the original tree is reconstructed without any global
        # state. Move-back is best-effort; on failure the folder remains
        # at new_path and the user is told where it lives.
        set saved_original $path
        set basename [lindex [file split $saved_original] end]
        set to_path "/$basename"
        puts "    move-to-top: $saved_original -> $to_path (autorename on collision)"
        if {[catch {set mv [dbx_call $token /2/files/move_v2 \
                [::json::write::object \
                    from_path [::json::write::string $saved_original] \
                    to_path [::json::write::string $to_path] \
                    autorename true \
                    allow_ownership_transfer false]]} merr]} {
            puts "    move_v2 failed: $merr"
            return 0
        }
        set new_path [dict get $mv metadata path_display]
        puts "    moved to $new_path"
        puts "  retrying unshare_folder: $new_path (id $sfid)"
        set unshare_ok 0
        if {![catch {dbx_unshare_folder $token $sfid} err3]} {
            set unshare_ok 1
        } else {
            puts "    post-move retry failed: $err3"
        }
        puts "    move-back: $new_path -> $saved_original"
        if {[catch {dbx_call $token /2/files/move_v2 \
                [::json::write::object \
                    from_path [::json::write::string $new_path] \
                    to_path [::json::write::string $saved_original] \
                    autorename false \
                    allow_ownership_transfer false]} berr]} {
            puts "    move-back failed: $berr (folder remains at $new_path)"
        }
        return $unshare_ok
    }

    return 0
}

proc dbx_unshare_folder {token shared_folder_id} {
    set resp [dbx_call $token /2/sharing/unshare_folder \
        [::json::write::object \
            shared_folder_id [::json::write::string $shared_folder_id] \
            leave_a_copy false]]
    set tag [dict get $resp .tag]
    if {$tag eq "complete"} return
    if {$tag eq "async_job_id"} {
        dbx_wait_share_job $token [dict get $resp async_job_id]
        return
    }
    error "unexpected unshare_folder response: $resp"
}

proc dbx_list_folder_recursive {token path} {
    # Dropbox's recursive list_folder includes the queried path itself as
    # one of the entries; we filter it out so the result is descendants only.
    set root_lower [string tolower $path]
    set entries [list]
    set body [::json::write::object \
        path [::json::write::string $path] \
        recursive true]
    set resp [dbx_call $token /2/files/list_folder $body]
    while {1} {
        foreach e [dict get $resp entries] {
            if {[dict get $e path_lower] eq $root_lower} continue
            lappend entries $e
        }
        if {[dict exists $resp has_more] && [dict get $resp has_more]} {
            set body [::json::write::object \
                cursor [::json::write::string [dict get $resp cursor]]]
            set resp [dbx_call $token /2/files/list_folder/continue $body]
        } else break
    }
    return $entries
}

proc unshare_item {token meta} {
    set tag [dict get $meta .tag]
    if {$tag eq "deleted"} return
    set path [dict get $meta path_display]

    if {$tag eq "file"} {
        foreach url [dbx_list_links $token $path] {
            puts "  revoke link: $url"
            dbx_revoke_link $token $url
        }
        if {[catch {dbx_unshare_file $token $path} err]} {
            if {![string match "*not_shared*" $err]} {
                puts "  $path: unshare_file failed: $err"
            }
        }
    } elseif {$tag eq "folder"} {
        if {[dict exists $meta sharing_info shared_folder_id]} {
            try_unshare_sfid $token [dict get $meta sharing_info shared_folder_id]
        } else {
            foreach url [dbx_list_links $token $path] {
                puts "  revoke link: $url"
                dbx_revoke_link $token $url
            }
        }
    }
}

proc cmd_unshare {path force_recursive} {
    if {![string match "/*" $path]} { set path "/$path" }
    set token [read_dropbox_token Dropbox]

    puts "Looking up: $path"
    set meta [dbx_get_metadata $token $path]
    set tag [dict get $meta .tag]
    set path [dict get $meta path_display]
    puts "Type: $tag"

    if {$tag ne "folder"} {
        unshare_item $token $meta
        puts "Done."
        return
    }

    set folder_unshared 0
    if {[dict exists $meta sharing_info shared_folder_id]} {
        set sfid [dict get $meta sharing_info shared_folder_id]
        set folder_unshared [try_unshare_sfid $token $sfid]
        if {!$folder_unshared} {
            puts "Falling back to recursing into contents."
        }
    } else {
        # Path is not a shared folder root; revoke any direct links anyway.
        foreach url [dbx_list_links $token $path] {
            puts "  revoke link: $url"
            dbx_revoke_link $token $url
        }
    }

    if {$folder_unshared && !$force_recursive} {
        puts "Done (folder unshared; pass -r to also revoke per-item shares inside)."
        return
    }

    if {$force_recursive} {
        puts "Recursing into contents (-r)..."
    } elseif {!$folder_unshared} {
        puts "Recursing into contents..."
    }
    set entries [dbx_list_folder_recursive $token $path]
    puts "Visiting [llength $entries] descendant(s)."
    foreach e $entries {
        if {[catch {unshare_item $token $e} err]} {
            puts "  [dict get $e path_display]: $err"
        }
    }
    puts "Done."
}

proc cmd_list_shares {} {
    # Lists shared folders that are top of the sharing graph: with a path
    # and not inherited from another share. Skips no-path (deleted) records;
    # they need a separate command. Folder scope only this turn.
    set token [read_dropbox_token Dropbox]
    set all [dbx_list_all_folders $token]
    set total [llength $all]
    set rows [list]
    foreach e $all {
        if {![dict exists $e path_display]} continue
        set path [dict get $e path_display]
        if {$path eq ""} continue
        if {[dict exists $e parent_shared_folder_id]} continue
        set sfid [dict get $e shared_folder_id]
        # list_folders may have silently omitted parent_shared_folder_id;
        # confirm via get_folder_metadata before declaring top-level.
        if {[catch {set m [dbx_call $token /2/sharing/get_folder_metadata \
                [::json::write::object shared_folder_id [::json::write::string $sfid]]]}]} {
            continue
        }
        if {[dict exists $m parent_shared_folder_id]} continue
        set access ""
        if {[dict exists $e access_type .tag]} { set access [dict get $e access_type .tag] }
        lappend rows [list $path $sfid $access]
    }
    set rows [lsort -index 0 -nocase $rows]
    foreach r $rows {
        lassign $r p s a
        if {$a ne ""} {
            puts "$p (id $s)  \[$a\]"
        } else {
            puts "$p (id $s)"
        }
    }
    puts "[llength $rows] top-level shared folder(s) (of $total total in list_folders)."
}

proc dbx_list_folder_members {token sfid} {
    # All member and invitee records of a shared folder, paginated.
    # Each record keeps the API's shape; is_inherited marks membership
    # reaching this share from an ancestor share (docs/DROPBOX.md).
    set out {}
    set resp [dbx_call $token /2/sharing/list_folder_members \
        [::json::write::object shared_folder_id [::json::write::string $sfid] limit 300]]
    while {1} {
        foreach u [dict get $resp users] { lappend out $u }
        foreach i [dict get $resp invitees] { lappend out $i }
        if {[dict exists $resp cursor] && [dict get $resp cursor] ne ""} {
            set resp [dbx_call $token /2/sharing/list_folder_members/continue \
                [::json::write::object cursor [::json::write::string [dict get $resp cursor]]]]
        } else break
    }
    return $out
}

# ============================================================================
# Provider interface
# ============================================================================
# The audit reads through get_item/get_acl/sweep; enforcement writes
# through invite and remove. sever refuses with the reasons: on Dropbox
# a folder inside a shared folder cannot be detached in place (moving it
# out severs only while it stays out, and set_access_inheritance is
# team-gated), so inherited excess is fixed at the ancestor share or by
# relocating the folder, both decisions the owner makes.

namespace eval ::dbx {
    variable meta_cache {}   ;# sfid -> get_folder_metadata dict, per connect
}

proc dropbox_provider {} {
    return [dict create \
        name dropbox \
        connect dbx_connect \
        get_item dbx_get_item \
        item_path dbx_item_path \
        get_acl dbx_get_acl \
        sweep dbx_sweep \
        invite dbx_invite \
        remove dbx_remove \
        sever dbx_sever \
        capabilities [dict create roles {read write} sever 0]]
}

proc dbx_connect {remote mode} {
    # Returns a ctx dict, or "" when no usable token exists. The rclone
    # token expires hourly; a cheap probe catches that and one rclone call
    # makes rclone refresh it in place.
    if {[catch {read_dropbox_token $remote} token]} {
        puts "❌ $token"
        return ""
    }
    if {[catch {dbx_call $token /2/users/get_current_account null} acct]} {
        if {[string match "*expired_access_token*" $acct]} {
            if {[catch {exec rclone about ${remote}:} rerr]} {
                puts "❌ Dropbox token expired and rclone could not refresh it: $rerr"
                return ""
            }
            set token [read_dropbox_token $remote]
            if {[catch {dbx_call $token /2/users/get_current_account null} acct]} {
                puts "❌ Dropbox token still unusable after refresh: $acct"
                return ""
            }
        } else {
            puts "❌ Dropbox token probe failed: $acct"
            return ""
        }
    }
    set ::dbx::meta_cache {}
    # The full share list (with-path, no-path, owned, joined) backs the
    # phantom sweep; one paginated fetch per run.
    set shares {}
    foreach e [dbx_list_all_folders $token] {
        dict set shares [dict get $e shared_folder_id] $e
    }
    return [dict create token $token remote $remote shares $shares]
}

proc dbx_folder_meta {token sfid} {
    # get_folder_metadata with a per-connect cache: ACL resolution walks
    # ancestor chains and siblings share ancestors.
    if {[dict exists $::dbx::meta_cache $sfid]} {
        return [dict get $::dbx::meta_cache $sfid]
    }
    set m [dbx_call $token /2/sharing/get_folder_metadata \
        [::json::write::object shared_folder_id [::json::write::string $sfid]]]
    dict set ::dbx::meta_cache $sfid $m
    return $m
}

proc dbx_get_item {ctx fid} {
    # {status item_dict}; fid is the "id:..." form (docs/DROPBOX.md: it
    # round-trips for shared, nested, and plain folders alike).
    if {[catch {dbx_get_metadata [dict get $ctx token] $fid} m]} {
        if {[string match "*not_found*" $m]} {
            return [list not_found {}]
        }
        return [list error {}]
    }
    return [list ok $m]
}

proc dbx_item_path {ctx item_dict} {
    if {[dict exists $item_dict path_display]} {
        return [dict get $item_dict path_display]
    }
    return ""
}

proc dbx_member_email_role {record} {
    # {email role inherited} from a member or invitee record; email "" for
    # records without one (the owner is filtered by role before this
    # matters). editor maps to write; viewer variants map to read.
    set email ""
    if {[dict exists $record user email]} {
        set email [string tolower [dict get $record user email]]
    } elseif {[dict exists $record invitee email]} {
        set email [string tolower [dict get $record invitee email]]
    }
    set access ""
    catch {set access [dict get $record access_type .tag]}
    set role ""
    switch -- $access {
        editor { set role write }
        viewer - viewer_no_comment { set role read }
        owner { set role owner }
    }
    set inherited 0
    if {[dict exists $record is_inherited] && [dict get $record is_inherited]} {
        set inherited 1
    }
    return [list $email $role $inherited]
}

proc dbx_get_acl {ctx fid} {
    # {status acl}. A folder's members live on its own share record when it
    # is a share root; a folder inside a shared folder holds everything by
    # inheritance from the nearest ancestor share, whose member list
    # already aggregates the deeper ancestors (is_inherited marks those).
    set token [dict get $ctx token]
    lassign [dbx_get_item $ctx $fid] status m
    if {$status ne "ok"} { return [list $status {}] }

    set own_sfid ""
    set parent_sfid ""
    if {[dict exists $m sharing_info shared_folder_id]} {
        set own_sfid [dict get $m sharing_info shared_folder_id]
    }
    if {[dict exists $m sharing_info parent_shared_folder_id]} {
        set parent_sfid [dict get $m sharing_info parent_shared_folder_id]
    }

    set direct {}
    set inherited {}
    if {$own_sfid ne ""} {
        set records [dbx_list_folder_members $token $own_sfid]
        foreach r $records {
            lassign [dbx_member_email_role $r] email role rinh
            if {$email eq "" || $role in {"" owner}} { continue }
            if {$rinh} {
                if {![dict exists $inherited $email] || [dict get $inherited $email] ne "write"} {
                    dict set inherited $email $role
                }
            } else {
                if {![dict exists $direct $email] || [dict get $direct $email] ne "write"} {
                    dict set direct $email $role
                }
            }
        }
    } elseif {$parent_sfid ne ""} {
        # Everything at this folder is inherited, including the ancestor
        # share's own direct members.
        foreach r [dbx_list_folder_members $token $parent_sfid] {
            lassign [dbx_member_email_role $r] email role rinh
            if {$email eq "" || $role in {"" owner}} { continue }
            if {![dict exists $inherited $email] || [dict get $inherited $email] ne "write"} {
                dict set inherited $email $role
            }
        }
    }

    set all $inherited
    dict for {email role} $direct {
        if {![dict exists $all $email] || [dict get $all $email] ne "write"} {
            dict set all $email $role
        }
    }

    set links {}
    set path [dbx_item_path $ctx $m]
    if {$path ne ""} {
        if {![catch {dbx_list_links $token $path} urls]} {
            foreach url $urls {
                lappend links [dict create url $url]
            }
        }
    }

    return [list ok [dict create direct $direct inherited $inherited all $all links $links]]
}

proc dbx_sweep {ctx} {
    # Account-wide findings no single policy folder owns: records of
    # deleted shares (no path) persist indefinitely and can keep live
    # public links (docs/DROPBOX.md).
    set violations {}
    dict for {sfid e} [dict get $ctx shares] {
        set path ""
        if {[dict exists $e path_display]} { set path [dict get $e path_display] }
        if {$path ne ""} { continue }
        set name ""
        if {[dict exists $e name]} { set name [dict get $e name] }
        lappend violations [dict create type phantom_share \
            path "(deleted share) $name" id $sfid email "" expected "" actual "" \
            detail "share record survives deletion; any links on it are still live"]
    }
    return $violations
}

proc dbx_wait_remove_job {token job_id} {
    # remove_folder_member has its own poll endpoint; failure nests the
    # same two levels as the sharing jobs (docs/DROPBOX.md).
    set body [::json::write::object \
        async_job_id [::json::write::string $job_id]]
    while {1} {
        set st [dbx_call $token /2/sharing/check_remove_member_job_status $body]
        set tag [dict get $st .tag]
        if {$tag eq "in_progress"} { after 2000; continue }
        if {$tag eq "complete"} return
        if {$tag eq "failed"} {
            set reason "unknown"
            if {[dict exists $st failed]} {
                set f [dict get $st failed]
                if {[dict exists $f .tag]} {
                    set outer [dict get $f .tag]
                    set reason $outer
                    if {[dict exists $f $outer .tag]} {
                        set reason "$outer/[dict get $f $outer .tag]"
                    }
                }
            }
            error "job failed: $reason"
        }
        error "unexpected check_remove_member_job_status response: $st"
    }
}

proc dbx_share_folder {token path} {
    # Share a folder and return its sfid, polling the async launch.
    set resp [dbx_call $token /2/sharing/share_folder \
        [::json::write::object path [::json::write::string $path]]]
    set tag [dict get $resp .tag]
    if {$tag eq "async_job_id"} {
        set body [::json::write::object \
            async_job_id [::json::write::string [dict get $resp async_job_id]]]
        while {1} {
            set st [dbx_call $token /2/sharing/check_share_job_status $body]
            set stag [dict get $st .tag]
            if {$stag eq "in_progress"} { after 2000; continue }
            if {$stag eq "complete"} { set resp $st; break }
            error "share_folder failed: $st"
        }
    }
    if {[dict exists $resp shared_folder_id]} {
        return [dict get $resp shared_folder_id]
    }
    if {[dict exists $resp complete shared_folder_id]} {
        return [dict get $resp complete shared_folder_id]
    }
    error "share_folder returned no shared_folder_id: $resp"
}

proc dbx_role_access_level {role} {
    switch -- $role {
        write { return editor }
        read { return viewer }
    }
    error "unknown role '$role'"
}

proc dbx_invite {ctx fid email role} {
    # {status msg}: ok | failed | unenforceable. Shares the folder first
    # when it is not shared; a folder inside a shared folder cannot be
    # shared on its own (inside_shared_folder), so a grant binding there
    # is satisfiable only at the enclosing share.
    set token [dict get $ctx token]
    lassign [dbx_get_item $ctx $fid] status m
    if {$status ne "ok"} { return [list failed "cannot resolve folder"] }

    set own_sfid ""
    if {[dict exists $m sharing_info shared_folder_id]} {
        set own_sfid [dict get $m sharing_info shared_folder_id]
    }
    if {$own_sfid eq ""} {
        if {[dict exists $m sharing_info parent_shared_folder_id]} {
            set anc [dict get $m sharing_info parent_shared_folder_id]
            set apath "(sfid $anc)"
            catch {set apath [dict get [dbx_folder_meta $token $anc] path_display]}
            return [list failed "inside the shared folder $apath; Dropbox only grants at a share root, so this grant is satisfiable only there"]
        }
        if {[catch {dbx_share_folder $token [dict get $m path_display]} own_sfid]} {
            return [list failed "share_folder: $own_sfid"]
        }
    }

    set body [::json::write::object \
        shared_folder_id [::json::write::string $own_sfid] \
        members [::json::write::array [::json::write::object \
            member [::json::write::object \
                .tag [::json::write::string email] \
                email [::json::write::string $email]] \
            access_level [::json::write::object \
                .tag [::json::write::string [dbx_role_access_level $role]]]]] \
        quiet true]
    if {[catch {dbx_call $token /2/sharing/add_folder_member $body} err]} {
        if {[string match "*insufficient_plan*" $err]} {
            # TODO(plan-upgrade): on a plan where this stops failing,
            # nothing else changes; the invite below already sends the
            # viewer access level.
            return [list unenforceable "the current Dropbox plan refuses this membership: $err"]
        }
        return [list failed $err]
    }
    return [list ok ""]
}

proc dbx_remove {ctx fid emails} {
    # {removed blocked}: a member or invitee of this folder's own share is
    # removable here; access reaching this folder from an ancestor share
    # is not, and lands in blocked for the sever path to explain.
    set token [dict get $ctx token]
    lassign [dbx_get_item $ctx $fid] status m
    if {$status ne "ok"} { return [list {} $emails] }
    set own_sfid ""
    if {[dict exists $m sharing_info shared_folder_id]} {
        set own_sfid [dict get $m sharing_info shared_folder_id]
    }
    if {$own_sfid eq ""} {
        return [list {} $emails]
    }

    set own {}
    foreach r [dbx_list_folder_members $token $own_sfid] {
        lassign [dbx_member_email_role $r] remail rrole rinh
        if {$remail eq "" || $rinh} { continue }
        dict set own $remail 1
    }

    set removed {}
    set blocked {}
    foreach email $emails {
        if {![dict exists $own $email]} {
            lappend blocked $email
            continue
        }
        set body [::json::write::object \
            shared_folder_id [::json::write::string $own_sfid] \
            member [::json::write::object \
                .tag [::json::write::string email] \
                email [::json::write::string $email]] \
            leave_a_copy false]
        if {[catch {dbx_call $token /2/sharing/remove_folder_member $body} resp]} {
            lappend blocked $email
            continue
        }
        if {[dict exists $resp .tag] && [dict get $resp .tag] eq "async_job_id"} {
            if {[catch {dbx_wait_remove_job $token [dict get $resp async_job_id]} jerr]} {
                puts "  ❌ remove $email: $jerr"
                lappend blocked $email
                continue
            }
        }
        lappend removed $email
    }

    # Believe success only after a re-read, in the spirit of the OneDrive
    # phantom-permission lesson.
    if {[llength $removed] > 0} {
        after 1000
        set still {}
        foreach r [dbx_list_folder_members $token $own_sfid] {
            lassign [dbx_member_email_role $r] remail rrole rinh
            if {$remail ne "" && !$rinh} { dict set still $remail 1 }
        }
        set truly {}
        foreach email $removed {
            if {[dict exists $still $email]} {
                lappend blocked $email
            } else {
                lappend truly $email
            }
        }
        set removed $truly
    }
    return [list $removed $blocked]
}

proc dbx_sever {ctx fid fentry item_dict blocked} {
    # Inherited excess at a folder inside a shared folder has no in-place
    # fix on this plan: relocating the folder severs only while it stays
    # relocated, and dropping the member at the ancestor share strips
    # their access to every sibling. Both change more than this folder,
    # so the choice belongs to the owner; name the ancestor and stop.
    set token [dict get $ctx token]
    set anc ""
    if {[dict exists $item_dict sharing_info parent_shared_folder_id]} {
        set anc [dict get $item_dict sharing_info parent_shared_folder_id]
    }
    set where "an ancestor share"
    if {$anc ne ""} {
        catch {set where [dict get [dbx_folder_meta $token $anc] path_display]}
    }
    puts "  ⛔ [join $blocked {, }]: access is inherited from $where; fix it there (remove the member, or relocate this folder out of the share for good)"
    return [list error 0]
}
