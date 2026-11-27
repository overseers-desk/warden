# OneDrive via the Microsoft Graph API: item metadata, permission listing and normalization, invite/remove/move.
package require json
package require json::write

proc convert_onedrive_url_to_path {url} {
    # Convert a OneDrive web URL to a relative path
    # Supports onedrive.live.com and *.sharepoint.com URLs
    # Returns the original string unchanged if not a OneDrive URL
    if {![string match "https://onedrive.live.com*" $url] && ![string match "https://*.sharepoint.com*" $url]} {
        return $url
    }

    # Extract the 'id' query parameter
    if {![regexp {[?&]id=([^&]*)} $url -> id_value]} {
        return $url
    }

    set decoded [url_decode $id_value]

    # Strip /personal/{drive_id}/Documents/ prefix
    if {[regexp {^/personal/[^/]+/Documents/(.+)$} $decoded -> rel_path]} {
        return $rel_path
    } elseif {[regexp {^/personal/[^/]+/Documents/?$} $decoded]} {
        return "/"
    }

    # Fallback: return decoded id as-is
    return $decoded
}

proc extract_item_metadata {item_dict} {
    # Safely extract metadata fields from a Graph API item dict
    # Returns a dict with keys: name, type, created_by, created_date, modified_by, modified_date, size, caption
    set meta {}

    dict set meta name [expr {[dict exists $item_dict name] ? [dict get $item_dict name] : "N/A"}]

    if {[dict exists $item_dict folder]} {
        dict set meta type "folder"
    } elseif {[dict exists $item_dict file]} {
        dict set meta type "file"
    } else {
        dict set meta type "item"
    }

    if {[dict exists $item_dict createdBy user displayName]} {
        dict set meta created_by [dict get $item_dict createdBy user displayName]
    } else {
        dict set meta created_by "N/A"
    }

    dict set meta created_date [expr {[dict exists $item_dict createdDateTime] ? [dict get $item_dict createdDateTime] : "N/A"}]

    if {[dict exists $item_dict lastModifiedBy user displayName]} {
        dict set meta modified_by [dict get $item_dict lastModifiedBy user displayName]
    } else {
        dict set meta modified_by "N/A"
    }

    dict set meta modified_date [expr {[dict exists $item_dict lastModifiedDateTime] ? [dict get $item_dict lastModifiedDateTime] : "N/A"}]

    if {[dict exists $item_dict size]} {
        dict set meta size [format_file_size [dict get $item_dict size]]
    } else {
        dict set meta size "N/A"
    }

    # Caption is the server-side description (the web "Add a caption" field)
    dict set meta caption [expr {[dict exists $item_dict description] ? [dict get $item_dict description] : ""}]

    return $meta
}

proc extract_users_from_perm {perm} {
    # Extract ALL users from grantedTo or grantedToIdentities
    # Returns list of {displayName email} pairs (can be multiple for grantedToIdentities)
    set users {}
    
    if {[dict exists $perm grantedTo user]} {
        set user [dict get $perm grantedTo user]
        lappend users [list [dict get $user displayName] [dict get $user email]]
    }
    
    if {[dict exists $perm grantedToIdentities]} {
        set identities [dict get $perm grantedToIdentities]
        foreach identity $identities {
            if {[dict exists $identity user]} {
                set user [dict get $identity user]
                lappend users [list [dict get $user displayName] [dict get $user email]]
            }
        }
    }
    
    return $users
}

proc extract_user_info {perm} {
    # Extract user display name and email from a permission object
    # Returns {displayName email} or {"N/A" "N/A"}
    set users [extract_users_from_perm $perm]
    if {[llength $users] > 0} {
        return [lindex $users 0]
    }
    return [list "N/A" "N/A"]
}

proc is_owner_permission {perm} {
    # Check if permission has owner role
    set roles [dict get $perm roles]
    return [expr {[lsearch $roles "owner"] >= 0}]
}

proc is_inherited_permission {perm} {
    # Check if permission is inherited
    return [dict exists $perm inheritedFrom]
}

proc build_graph_api_url {endpoint} {
    # Build Microsoft Graph API URL
    return "https://graph.microsoft.com/v1.0$endpoint"
}

proc extract_users_from_permissions {permissions} {
    # Extract all non-owner users from permissions
    # Returns: dict of {email role} pairs
    set users_dict {}
    
    foreach perm $permissions {
        if {[is_owner_permission $perm]} {
            continue
        }
        
        set roles [dict get $perm roles]
        set role "read"
        if {[lsearch -exact $roles "write"] >= 0} {
            set role "write"
        } elseif {[llength $roles] > 0} {
            set role [lindex $roles 0]
        }
        
        set user_list [extract_users_from_perm $perm]
        foreach user_info $user_list {
            set email [string tolower [lindex $user_info 1]]
            if {$email ne ""} {
                dict set users_dict $email $role
            }
        }
    }
    
    return $users_dict
}

proc invite_user_to_item {item_id email role access_token {quiet 0}} {
    # Invite a user to an item with specified role
    # role: "read" or "write"
    # quiet: suppress the notification email (sendInvitation:false); if the
    #        service rejects that (400), retry with notification and report
    #        status "ok-notified" so callers can surface the difference
    # Returns: {status message}

    set url "https://graph.microsoft.com/v1.0/me/drive/items/$item_id/invite"
    set headers [list Authorization "Bearer $access_token" Content-Type "application/json"]

    set body_common [list \
        requireSignIn true \
        roles [json::write array [json::write string $role]] \
        recipients [json::write array [json::write object email [json::write string $email]]]]
    if {$quiet} {
        set body_json [json::write object {*}$body_common sendInvitation false]
    } else {
        set body_json [json::write object {*}$body_common \
            message [json::write string "You have been granted $role access to this item."]]
    }

    set result [make_http_request $url $headers POST $body_json]
    set status [lindex $result 0]
    set data [lindex $result 1]

    if {$status eq "200" || $status eq "201"} {
        return [list "ok" "Successfully invited $email with $role permission"]
    } elseif {$quiet && $status eq "400"} {
        # Service refused the quiet form; fall back to a notifying invite
        set result [invite_user_to_item $item_id $email $role $access_token 0]
        if {[lindex $result 0] eq "ok"} {
            return [list "ok-notified" "Invited $email with $role permission (service refused quiet invite; notification email sent)"]
        }
        return $result
    } elseif {$status eq "400"} {
        # OneDrive answers "sharingFailed" whenever it will not create the
        # share, and the usual reason is that the address is not a Microsoft
        # account, so there is no identity to grant anything to
        return [list "error" "$email cannot be invited: OneDrive refused the share, usually because the address is not a Microsoft account"]
    } elseif {$status eq "403"} {
        return [list "error" "Insufficient permissions to invite users"]
    } elseif {$status eq "404"} {
        return [list "error" "Item not found"]
    } else {
        return [list "error" "Could not invite $email (HTTP $status); re-run with --debug for the service's reply"]
    }
}

proc get_item_by_id {item_id access_token} {
    # Fetch an item by its stable id; the id survives renames and moves,
    # which is what makes policy drift detectable.
    # Returns: {ok item_dict} | {not_found {}} | {error {}}
    set url [build_graph_api_url "/me/drive/items/$item_id?select=id,name,parentReference"]
    set headers [list Authorization "Bearer $access_token"]
    set result [make_http_request $url $headers]
    set status [lindex $result 0]
    if {$status eq "200"} {
        return [list "ok" [json::json2dict [lindex $result 1]]]
    } elseif {$status eq "404" || $status eq "400"} {
        return [list "not_found" {}]
    }
    return [list "error" {}]
}

proc item_actual_path {item_dict} {
    # Slash path of an item relative to the drive root, from one GET's
    # parentReference.path (format "/drive/root:/Parent/Sub"); empty string
    # when the reference is absent (rare; caller may fall back to
    # get_item_path's parent-chain walk).
    if {![dict exists $item_dict parentReference path]} {
        return ""
    }
    set parent_path [dict get $item_dict parentReference path]
    set idx [string first "root:" $parent_path]
    if {$idx < 0} { return "" }
    set rel [string range $parent_path [expr {$idx + 5}] end]
    set rel [string trimleft $rel "/"]
    # parentReference.path is URL-decoded by Graph already
    set name [dict get $item_dict name]
    if {$rel eq ""} { return $name }
    return "$rel/$name"
}

proc move_item {item_id new_parent_id access_token} {
    # Move an item under a new parent folder (PATCH parentReference).
    # Moving a folder to the drive root converts its inherited permissions
    # to unique ones, the only known way to delete inherited permissions on
    # consumer OneDrive (docs/PHANTOM-INHERITANCE-BUG.md).
    # Returns: {status message}
    set url [build_graph_api_url "/me/drive/items/$item_id"]
    set headers [list Authorization "Bearer $access_token" Content-Type "application/json"]
    set body_json [json::write object parentReference \
        [json::write object id [json::write string $new_parent_id]]]
    set result [make_http_request $url $headers PATCH $body_json]
    set status [lindex $result 0]
    if {$status eq "200"} {
        return [list "ok" "Moved"]
    } elseif {$status eq "409"} {
        return [list "error" "Name conflict at destination"]
    } elseif {$status eq "403"} {
        return [list "error" "Insufficient permissions to move item"]
    } elseif {$status eq "404"} {
        return [list "error" "Item not found"]
    }
    return [list "error" "Failed to move item: HTTP $status"]
}

proc set_item_description {item_id description access_token} {
    # Set (or clear) an item's server-side description, the field behind the
    # OneDrive web "Add a caption". Editable via PATCH with no file re-upload,
    # and indexed by OneDrive search.
    # Returns: {status message}

    set url [build_graph_api_url "/me/drive/items/$item_id"]
    set headers [list Authorization "Bearer $access_token" Content-Type "application/json"]

    # json::write escapes quotes, accents and newlines in arbitrary caption text
    set body_json [json::write object description [json::write string $description]]

    set result [make_http_request $url $headers PATCH $body_json]
    set status [lindex $result 0]

    if {$status eq "200"} {
        if {$description eq ""} {
            return [list "ok" "Caption cleared"]
        }
        return [list "ok" "Caption set to: $description"]
    } elseif {$status eq "403"} {
        return [list "error" "Insufficient permissions to set the caption"]
    } elseif {$status eq "404"} {
        return [list "error" "Item not found"]
    } elseif {$status eq "401"} {
        return [list "error" "Token expired or invalid"]
    } else {
        return [list "error" "Failed to set caption: HTTP $status"]
    }
}

proc remove_permission {item_id permission_id access_token} {
    # Remove a specific permission from an item
    # Returns: {status message}
    
    set url "https://graph.microsoft.com/v1.0/me/drive/items/$item_id/permissions/$permission_id"
    set headers [list Authorization "Bearer $access_token"]
    
    set result [make_http_request $url $headers DELETE]
    set status [lindex $result 0]
    
    if {$status eq "204"} {
        return [list "ok" "Permission removed successfully"]
    } elseif {$status eq "403"} {
        return [list "error" "Insufficient permissions to remove this permission"]
    } elseif {$status eq "404"} {
        return [list "error" "Permission not found (may already be removed)"]
    } elseif {$status eq "401"} {
        return [list "error" "Token expired or invalid"]
    } else {
        return [list "error" "Failed to remove permission: HTTP $status"]
    }
}

proc strip_explicit_permissions {item_id access_token} {
    # Remove all explicit (non-inherited, non-owner) permissions
    # Returns: {status count_removed message}
    
    # Get all permissions
    set permissions_url "https://graph.microsoft.com/v1.0/me/drive/items/$item_id/permissions"
    set headers [list Authorization "Bearer $access_token"]
    set result [make_http_request $permissions_url $headers]
    set status [lindex $result 0]
    set data [lindex $result 1]
    
    if {$status ne "200"} {
        return [list "error" 0 "Failed to fetch permissions: HTTP $status"]
    }
    
    set permissions_data [json::json2dict $data]
    set permissions [dict get $permissions_data value]
    
    set removed_count 0
    set failed_count 0
    
    foreach perm $permissions {
        # Skip owner permissions
        if {[is_owner_permission $perm]} {
            continue
        }
        
        # Skip inherited permissions
        if {[is_inherited_permission $perm]} {
            continue
        }
        
        # Remove this explicit permission
        set permission_id [dict get $perm id]
        set remove_result [remove_permission $item_id $permission_id $access_token]
        set remove_status [lindex $remove_result 0]
        
        if {$remove_status eq "ok"} {
            incr removed_count
        } else {
            incr failed_count
        }
    }
    
    if {$failed_count > 0} {
        return [list "warning" $removed_count "Removed $removed_count permission(s), $failed_count failed"]
    } else {
        return [list "ok" $removed_count "Removed $removed_count explicit permission(s)"]
    }
}

proc get_item_path {item_id access_token} {
    # Get the full path of an item using its parent chain
    set headers [list Authorization "Bearer $access_token"]
    set path_parts {}
    set current_id $item_id
    set result_path "Unknown"
    
    if {[catch {
        while {$current_id ne ""} {
            set url "https://graph.microsoft.com/v1.0/me/drive/items/$current_id"
            set result [make_http_request $url $headers]
            set status [lindex $result 0]
            set data [lindex $result 1]
            
            if {$status ne "200"} {
                break
            }
            
            set item_data [json::json2dict $data]
            set name [dict get $item_data name]
            set path_parts [linsert $path_parts 0 $name]
            
            if {[dict exists $item_data parentReference]} {
                set parent_ref [dict get $item_data parentReference]
                if {[dict exists $parent_ref path] && [dict get $parent_ref path] eq "/drive/root:"} {
                    break
                }
                if {[dict exists $parent_ref id]} {
                    set current_id [dict get $parent_ref id]
                } else {
                    break
                }
            } else {
                break
            }
        }
        
        # Remove 'root' from path if present
        if {[llength $path_parts] > 0 && [string tolower [lindex $path_parts 0]] eq "root"} {
            set path_parts [lrange $path_parts 1 end]
        }
        
        if {[llength $path_parts] > 0} {
            set result_path [join $path_parts "/"]
        }
    } error] != 0} {
        # Keep result_path as "Unknown"
    }
    
    return $result_path
}

proc graph_get_all {url headers} {
    # GET a Graph collection across every @odata.nextLink page; Graph pages
    # at 200, so anything read from page 1 alone silently loses the rest.
    # Returns {status items}: status is the failing HTTP status, or 200.
    set items {}
    while {$url ne ""} {
        lassign [make_http_request $url $headers] status data
        if {$status ne "200"} {
            return [list $status {}]
        }
        set page [json::json2dict $data]
        lappend items {*}[dict get $page value]
        set url [expr {[dict exists $page @odata.nextLink]
            ? [dict get $page @odata.nextLink] : ""}]
    }
    return [list 200 $items]
}

proc get_folder_permissions {folder_id access_token} {
    # Returns list of {status permissions} where status is "ok" or "error"
    lassign [graph_get_all \
        [build_graph_api_url "/me/drive/items/$folder_id/permissions"] \
        [list Authorization "Bearer $access_token"]] status permissions
    if {$status ne "200"} {
        return [list "error" {}]
    }
    return [list "ok" $permissions]
}

proc cli_path_to_item_id_and_dict {path access_token} {
    # Consolidated CLI lookup function - gets item ID and dict from path
    # Returns: {item_id item_dict} on success, empty list on failure
    # Handles all error messaging internally
    # THIS FUNCTION ONLY EXISTS IN CLI MODE - CANNOT BE CALLED FROM GUI
    
    # Build item URL from path (inlined from get_item_url_from_path)
    if {$path eq "/" || $path eq ""} {
        set item_url [build_graph_api_url "/me/drive/root"]
    } else {
        set encoded_path [url_encode $path]
        set item_url [build_graph_api_url "/me/drive/root:/$encoded_path"]
    }
    
    set headers [list Authorization "Bearer $access_token"]
    set result [make_http_request $item_url $headers]
    set status [lindex $result 0]
    set data [lindex $result 1]
    
    if {$status ne "200"} {
        puts "❌ Failed to get item: $status"
        return {}
    }
    
    set item_dict [json::json2dict $data]
    set item_id [dict get $item_dict id]
    
    return [list $item_id $item_dict]
}

proc cli_resolve_path_for_command {path remote_name} {
    # Helper function to resolve path to item ID for CLI commands
    # Handles token retrieval and all error cases
    # Returns: {access_token item_id item_dict} on success, empty list on failure
    # On failure, prints error message and returns empty list (caller should exit)
    
    # Get access token
    set access_token [get_access_token $remote_name]
    if {$access_token eq ""} {
        puts "❌ Failed to get access token"
        return {}
    }
    
    # Resolve path to item ID
    set item_result [cli_path_to_item_id_and_dict $path $access_token]
    if {[llength $item_result] == 0} {
        puts "❌ Failed to resolve path: $path"
        return {}
    }
    
    lassign $item_result item_id item_dict
    return [list $access_token $item_id $item_dict]
}

proc fetch_permissions_by_id {item_id access_token} {
    # Get permissions from Microsoft Graph API
    if {[catch {graph_get_all \
            [build_graph_api_url "/me/drive/items/$item_id/permissions"] \
            [list Authorization "Bearer $access_token"]} result]} {
        return [list "error" "Failed to parse permissions response: $result"]
    }
    lassign $result status permissions

    if {$status ne "200"} {
        if {$status eq "403"} {
            return [list "error" "Access denied - you may not have permission to view ACL for this item"]
        } else {
            return [list "error" "Failed to get ACL: $status"]
        }
    }
    return [list "ok" $permissions]
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

# ============================================================================
# Provider interface
# ============================================================================
# The audit and enforcement code drives a drive through this dict of proc
# names ({*}[dict get $provider verb] ctx ...), never through Graph calls
# directly. ctx comes from connect and carries the token (and, in write
# mode, the drive root id: the sever cycle moves folders there).

proc onedrive_provider {} {
    return [dict create \
        name onedrive \
        connect od_connect \
        get_item od_get_item \
        item_path od_item_path \
        get_acl od_get_acl \
        invite od_invite \
        remove od_remove \
        sever od_sever \
        capabilities [dict create roles {read write} sever 1]]
}

proc od_connect {remote mode} {
    # Returns a ctx dict, or "" when no usable token exists. mode read
    # accepts any token; mode write demands full capability and resolves
    # the drive root id.
    if {$mode eq "write"} {
        set token [cli_get_full_token $remote]
        if {$token eq ""} { return "" }
        set root_result [cli_path_to_item_id_and_dict "/" $token]
        if {[llength $root_result] == 0} { return "" }
        return [dict create token $token remote $remote root_id [lindex $root_result 0]]
    }
    set result [get_access_token $remote "" "detailed" 1]
    set token [lindex $result 0]
    if {$token eq ""} { return "" }
    return [dict create token $token remote $remote]
}

proc od_get_item {ctx fid} {
    return [get_item_by_id $fid [dict get $ctx token]]
}

proc od_item_path {ctx item_dict} {
    return [item_actual_path $item_dict]
}

proc od_get_acl {ctx fid} {
    # {status acl}, acl as od_acl_from_permissions builds it
    lassign [get_folder_permissions $fid [dict get $ctx token]] status permissions
    if {$status ne "ok"} { return [list $status {}] }
    return [list ok [od_acl_from_permissions $permissions]]
}

proc od_acl_from_permissions {permissions} {
    # email -> role dicts for direct, inherited, and all non-owner
    # permissions. links stays empty, and a link permission carries no
    # email, so the audit does not see OneDrive link shares yet.
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
    return [dict create \
        direct [extract_users_from_permissions $direct_perms] \
        inherited [extract_users_from_permissions $inherited_perms] \
        all [extract_users_from_permissions $permissions] \
        links {}]
}

proc od_invite {ctx fid email role} {
    return [invite_user_to_item $fid $email $role [dict get $ctx token] 1]
}

proc od_remove {ctx fid emails} {
    return [enforce_remove_emails $fid $emails [dict get $ctx token]]
}

proc od_sever {ctx fid fentry item_dict blocked} {
    # Inherited permissions resist in-place deletion. At the drive root
    # they detach entirely, and a folder returned to a shared tree
    # re-attaches to the parent's inheritance unless it carries its own
    # permission scope. So: move out, delete whatever explicit residue
    # names the blocked users, plant the folder's full effective ACL as
    # explicit permissions, and only then move back.
    # Returns {status changed}, status ok | error; changed once the move
    # has happened, whatever came after.
    set token [dict get $ctx token]
    enforce_log "  🚚 inherited permissions on [join $blocked {, }]: moving folder to root to sever inheritance"
    if {![dict exists $item_dict parentReference id]} {
        return [list error 0]
    }
    set original_parent [dict get $item_dict parentReference id]
    lassign [move_item $fid [dict get $ctx root_id] $token] mstatus mmsg
    if {$mstatus ne "ok"} {
        enforce_log "  ❌ move failed: $mmsg"
        return [list error 0]
    }
    after 2000
    lassign [enforce_remove_emails $fid $blocked $token] removed2 blocked2
    foreach email $removed2 { enforce_log "  ✂️  removed $email (after move)" }
    foreach email $blocked2 { enforce_log "  ❌ still cannot remove $email" }

    lassign [get_folder_permissions $fid $token] pstatus perms_now
    if {$pstatus ne "ok"} {
        enforce_log "  ❌ cannot read permissions at root; leaving folder in place"
    } else {
        set live_now [extract_users_from_permissions $perms_now]
        dict for {email role} [dict get $fentry effective] {
            if {[dict exists $live_now $email] && \
                ([dict get $live_now $email] eq $role || [dict get $live_now $email] eq "write")} { continue }
            lassign [invite_user_to_item $fid $email $role $token 1] istatus imsg
            if {$istatus eq "ok"} {
                enforce_log "  🌱 planted $email ($role)"
            } elseif {$istatus eq "ok-notified"} {
                enforce_log "  🌱 planted $email ($role); ⚠️ notification email was sent"
            } else {
                enforce_log "  ❌ plant $email failed: $imsg"
            }
        }
    }
    lassign [move_item $fid $original_parent $token] mstatus mmsg
    if {$mstatus ne "ok"} {
        enforce_log "  ❌ MOVE BACK FAILED: $mmsg  (folder is sitting at the drive root)"
        return [list error 1]
    }
    after 2000
    return [list ok 1]
}
