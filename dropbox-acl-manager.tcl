#!/usr/bin/env tclsh
# Dropbox sharing operations via the Dropbox API, using the OAuth token
# stored by rclone in rclone.conf under the [Dropbox] remote.
#
# Usage:
#   tclsh dropbox-acl-manager.tcl unshare <dropbox-path>

package require http
package require tls
package require json
package require json::write

::http::register https 443 [list ::tls::socket -autoservername 1 -tls1 0 -tls1.1 0 -tls1.2 1]

proc read_dropbox_token {} {
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
            set in_section [expr {$name eq "Dropbox"}]
            continue
        }
        if {!$in_section} continue
        if {[regexp {^token\s*=\s*(.*)$} $line -> rest]} {
            set token_json [string trim $rest]
        }
    }
    if {$token_json eq ""} {
        error "no token found for \[Dropbox\] in $conf"
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
        return [::json::json2dict [encoding convertfrom utf-8 $data]]
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

proc dbx_list_children {token parent_sfid} {
    # Returns SharedFolderMetadata for all shared folders (active or
    # inactive) whose parent_shared_folder_id matches parent_sfid. Both
    # kinds block the parent's unshare per Dropbox's rules.
    #
    # list_folders is unreliable: it omits parent_shared_folder_id from
    # some active entries even when get_folder_metadata reports it. We
    # therefore re-query get_folder_metadata for any entry where the
    # field is missing in the list result. See docs/DROPBOX.md.
    set out [list]
    set all [list]
    set body [::json::write::object limit 1000]
    set resp [dbx_call $token /2/sharing/list_folders $body]
    while {1} {
        foreach e [dict get $resp entries] { lappend all $e }
        if {[dict exists $resp cursor] && [dict get $resp cursor] ne ""} {
            set body [::json::write::object cursor [::json::write::string [dict get $resp cursor]]]
            set resp [dbx_call $token /2/sharing/list_folders/continue $body]
        } else break
    }
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
    # on the active path, attempts unshare_folder, and on no_permission
    # tries two escape hatches in order:
    #   1. enumerate child shared folders (active and inactive), mount the
    #      inactive ones, recurse on each, retry the parent;
    #   2. if the folder is itself an active nested shared folder (has
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
        set label "\"$name\" (id $sfid, inactive)"
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
            set k_active 0
            if {[dict exists $k path_display] && [dict get $k path_display] ne ""} {
                set k_active 1
            }
            if {!$k_active} {
                if {[catch {set mm [dbx_mount_folder $token $k_sfid]} merr]} {
                    puts "    mount_folder $k_sfid failed: $merr; skipping"
                    continue
                }
                puts "    mounted inactive child $k_sfid at [dict get $mm path_display]"
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
    set token [read_dropbox_token]

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

set usage "Usage: tclsh dropbox-acl-manager.tcl unshare \[-r\] <dropbox-path>"

if {[llength $argv] < 1} { puts stderr $usage; exit 1 }
switch -- [lindex $argv 0] {
    unshare {
        set force_recursive 0
        set path ""
        foreach arg [lrange $argv 1 end] {
            if {$arg eq "-r" || $arg eq "--recursive"} {
                set force_recursive 1
            } elseif {$path eq ""} {
                set path $arg
            } else { puts stderr $usage; exit 1 }
        }
        if {$path eq ""} { puts stderr $usage; exit 1 }
        cmd_unshare $path $force_recursive
    }
    default { puts stderr $usage; exit 1 }
}
