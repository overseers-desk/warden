# Microsoft account tokens: rclone.conf and token.json reading, capability checks, refresh, and the local-server OAuth flow.
package require json
package require json::write

# OAuth configuration
set ::oauth(client_id)     "b15665d9-eda6-4092-8539-0eec376afd59"
set ::oauth(client_secret) "qtyfaBBYA403=unZUP40~_#"
set ::oauth(redirect_uri)  "http://localhost:53682/"
set ::oauth(auth_url)      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
set ::oauth(token_url)     "https://login.microsoftonline.com/common/oauth2/v2.0/token"
set ::oauth(scope)         "Files.Read Files.ReadWrite Files.ReadWrite.All Sites.Manage.All offline_access"
set ::oauth(auth_code)     ""

proc get_rclone_conf_handler {} {
    if {$::tcl_platform(platform) eq "windows"} {
        set conf_path [file join $::env(APPDATA) rclone rclone.conf]
    } else {
        set conf_path [file join $::env(HOME) .config rclone rclone.conf]
    }
    if {![file exists $conf_path]} {
        debug_log "rclone.conf not found at $conf_path (this is OK if using token.json)"
        return ""
    }
    return [open $conf_path r]
}

proc get_token_file_path {} {
    # Get platform-specific path for token.json
    # Returns: Full path to token.json file

    # Determine config directory based on platform
    if {$::tcl_platform(platform) eq "windows"} {
        set config_dir [file join $::env(APPDATA) "OneDrive-ACL-Manager"]
    } elseif {$::tcl_platform(os) eq "Darwin"} {
        set config_dir [file join $::env(HOME) "Library" "Application Support" "OneDrive-ACL-Manager"]
    } else {
        set config_dir [file join $::env(HOME) ".config" "OneDrive-ACL-Manager"]
    }

    # Create directory if it doesn't exist
    if {![file exists $config_dir]} {
        file mkdir $config_dir
    }

    set token_path [file join $config_dir "token.json"]

    # Migration: Move old token.json from cwd to new location (one-time operation)
    set old_token_path "./token.json"
    if {[file exists $old_token_path] && ![file exists $token_path]} {
        debug_log "Migrating token.json from current directory to $config_dir"
        if {[catch {
            file rename $old_token_path $token_path
            debug_log "Successfully migrated token.json to $token_path"
        } err]} {
            debug_log "Warning: Could not migrate token.json: $err"
            debug_log "You may want to manually move $old_token_path to $token_path"
        }
    }

    return $token_path
}

proc find_onedrive_remotes {} {
    # Find all OneDrive remotes in rclone configuration
    
    set rconf_handler [get_rclone_conf_handler]
    if {$rconf_handler eq ""} {
        # No rclone.conf available
        return {}
    }
    
    set onedrive_remotes {}
    set config_data [read $rconf_handler]
    close $rconf_handler
    
    foreach line [split $config_data \n] {
        set line [string trim $line]
        if {[string match "\\\[*\\\]" $line]} {
            set section_name [string range $line 1 end-1]
            # Check if this is a OneDrive type remote
            if {[string match "*onedrive*" [string tolower $section_name]] || 
                [string match "*sharepoint*" [string tolower $section_name]]} {
                lappend onedrive_remotes $section_name
            }
        }
    }
    
    return $onedrive_remotes
}

proc parse_rclone_conf_token {rclone_remote} {
    # Parse rclone.conf and extract token JSON for specified remote
    # Returns: {success token_dict} where success is 1 if found, 0 if not found
    # On error, prints messages and returns {0 {}}
    
    # If no remote specified, find OneDrive remotes and use the first one
    if {$rclone_remote eq ""} {
        set onedrive_remotes [find_onedrive_remotes]
        
        if {[llength $onedrive_remotes] == 0} {
            debug_log "No OneDrive remotes found in rclone configuration (this is OK if using token.json)"
            return [list 0 {}]
        }
        
        if {[llength $onedrive_remotes] == 1} {
            set rclone_remote [lindex $onedrive_remotes 0]
            debug_log "No remote name given, using first OneDrive remote: $rclone_remote"
        } else {
            debug_log "No remote name given, found [llength $onedrive_remotes] OneDrive remotes"
            set rclone_remote [lindex $onedrive_remotes 0]
            debug_log "Using first OneDrive remote: $rclone_remote"
        }
    }
    
    # Read config file
    set rconf_handler [get_rclone_conf_handler]
    if {$rconf_handler eq ""} {
        # No rclone.conf available
        debug_log "No rclone.conf available (this is OK if using token.json)"
        return [list 0 {}]
    }
    
    set config_data [read $rconf_handler]
    close $rconf_handler
    
    # Parse INI file format properly
    set in_remote_section 0
    set token_json ""
    set remote_type ""
    
    foreach line [split $config_data \n] {
        set line [string trim $line]
        
        # Check for section header
        if {[string match "\\\[*\\\]" $line]} {
            set section_name [string range $line 1 end-1]
            if {$section_name eq $rclone_remote} {
                set in_remote_section 1
                continue
            } else {
                set in_remote_section 0
                continue
            }
        }
        
        # Process lines within the target section
        if {$in_remote_section} {
            if {[string match "type*" $line]} {
                set remote_type [string range $line 5 end]
                set remote_type [string trim $remote_type]
            } elseif {[string match "token*" $line]} {
                # Handle rclone.conf format: "token = {...}" or "token{...}"
                # Find the '=' and extract everything after it
                set equal_pos [string first "=" $line]
                if {$equal_pos >= 0} {
                    set token_json [string range $line [expr $equal_pos + 1] end]
                } else {
                    # No '=' found, try to extract after "token"
                    set token_json [string range $line 6 end]
                }
                set token_json [string trim $token_json]
            }
        }
    }
    
    if {$token_json eq ""} {
        debug_log "No token found for remote '$rclone_remote' (this is OK if using token.json)"
        return [list 0 {}]
    }
    
    # Parse JSON token
    if {[catch {json::json2dict $token_json} token_dict] == 0} {
        return [list 1 $token_dict]
    } else {
        debug_log "ERROR: Failed to parse token JSON. Error: $token_dict"
        puts "Error: Could not parse token JSON: $token_dict"
        return [list 0 {}]
    }
}

proc extract_and_sanitize_access_token {token_dict} {
    # Extract access_token from token dict and sanitize it
    # Returns: access_token string or empty string on failure
    
    if {![dict exists $token_dict access_token]} {
        debug_log "ERROR: No access_token key in token_dict. Available keys: [dict keys $token_dict]"
        return ""
    }
    
    set access_token [dict get $token_dict access_token]
    if {$access_token eq ""} {
        return ""
    }
    
    # Sanitize access token: remove quotes, trim whitespace, remove CR/LF
    set access_token [string trim $access_token]
    set access_token [regsub -all {^["']|["']$} $access_token ""]
    set access_token [regsub -all {\r|\n} $access_token ""]
    set access_token [string trim $access_token]
    
    return $access_token
}

proc get_access_token {rclone_remote {require_capability ""} {return_format "simple"} {try_token_json 1}} {
    # Internal implementation: Get access tokens from both token.json and rclone.conf
    # 
    # Parameters:
    #   rclone_remote        - Name of rclone remote (empty string = auto-detect)
    #   require_capability   - "full" to require full permissions, "" for any
    #   return_format        - "simple" (string) or "detailed" (list with capability)
    #   try_token_json       - 1 to try token.json first, 0 to skip token.json
    #
    # Returns:
    #   Simple format: access_token string or "" on failure
    #   Detailed format: {access_token capability expires_at} or {"" "unknown" "unknown"} on failure
    #
    # Save logic:
    #   - token.json refreshes ARE saved back to token.json
    #   - rclone.conf refreshes are NOT saved (in-memory only)
    
    # Try token.json first (if enabled and return_format is detailed or explicitly requested)
    if {$try_token_json} {
        set token_file [get_token_file_path]
        if {[file exists $token_file]} {
            set parse_error ""
            set token_data {}
            
            # Try to read and parse token.json
            if {[catch {
                set fh [open $token_file r]
                set token_json [read $fh]
                close $fh
                
                debug_log "Read token.json, length: [string length $token_json]"
                
                set token_data [json::json2dict $token_json]
                
                debug_log "Successfully parsed JSON, keys: [dict keys $token_data]"
            } parse_error] == 0} {
                # Successfully parsed, now check expiration and refresh if needed
                if {[dict exists $token_data access_token]} {
                    set original_access_token [dict get $token_data access_token]
                    
                    # Try to refresh token if expired
                    lassign [try_refresh_token_if_expired $token_data 0 "tokenjson"] refresh_success refreshed_token_data
                    
                    # Check if token was actually refreshed (access_token changed)
                    set token_was_refreshed 0
                    if {$refresh_success && [dict size $refreshed_token_data] > 0 && \
                        [dict exists $refreshed_token_data access_token] && \
                        [dict get $refreshed_token_data access_token] ne $original_access_token} {
                        # Token was refreshed - use refreshed version
                        set token_data $refreshed_token_data
                        set token_was_refreshed 1
                        debug_log "✓ Token refresh successful!"
                        
                        # Save refreshed token back to token.json (Rule 2: token.json refresh → save)
                        save_token_json $refreshed_token_data
                    } elseif {!$refresh_success} {
                        # Refresh failed - check if token was expired
                        set expiration_status [is_token_expired $token_data]
                        if {$expiration_status == 1} {
                            debug_log "Token expired and refresh failed, falling back to rclone.conf"
                            # Fall through to rclone.conf fallback below
                            set token_data {}
                        }
                    }
                    
                    # If we have valid token_data (either refreshed or original, not expired), use it
                    if {[dict size $token_data] > 0 && [dict exists $token_data access_token]} {
                        # Extract token info (from refreshed or original token_data)
                        set capability [check_token_capability $token_data]
                        set access_token [dict get $token_data access_token]
                        
                        if {[dict exists $token_data expires_at]} {
                            set expires_at [dict get $token_data expires_at]
                        } else {
                            set expires_at "unknown"
                        }
                        
                        debug_log "Token capability: $capability, expires: $expires_at"
                        debug_log "Using token.json with capability: $capability"
                        
                        # Check capability requirement
                        if {$require_capability eq "full" && $capability ne "full"} {
                            debug_log "Full capability required but token.json has $capability"
                            puts "❌ Operation requires full permissions. Please re-authenticate."
                            return [expr {$return_format eq "simple" ? "" : [list "" "insufficient" "n/a"]}]
                        }
                        
                        # Return in requested format
                        return [expr {$return_format eq "simple" ? $access_token : [list $access_token $capability $expires_at]}]
                    }
                    # If token_data is empty (expired and refresh failed), fall through to rclone.conf
                } else {
                    debug_log "ERROR: No access_token in parsed JSON"
                }
            } else {
                debug_log "Error reading token.json: $parse_error, falling back to rclone.conf"
            }
        } else {
            debug_log "token.json not found, using rclone.conf"
        }
    }
    
    # Fallback to rclone.conf
    if {$require_capability eq "full"} {
        debug_log "Full capability required but only rclone token available"
        puts "❌ Operation requires full permissions. Please re-authenticate."
        return [expr {$return_format eq "simple" ? "" : [list "" "insufficient" "n/a"]}]
    }
    
    # Parse rclone.conf
    lassign [parse_rclone_conf_token $rclone_remote] parse_success token_dict
    
    if {!$parse_success} {
        # Both token.json and rclone.conf failed - show helpful error
        puts "❌ No valid authentication found."
        puts ""
        puts "You need to authenticate with OneDrive. You have two options:"
        puts ""
        puts "Option 1: Use browser authentication (recommended)"
        puts "  1. Run this program in GUI mode: wish acl-manager.tcl"
        puts "  2. Click any operation requiring permissions (Invite/Remove)"
        puts "  3. Complete browser authentication"
        puts ""
        puts "Option 2: Use rclone"
        puts "  1. Install rclone: https://rclone.org"
        puts "  2. Configure OneDrive: rclone config"
        puts ""
        return [expr {$return_format eq "simple" ? "" : [list "" "unknown" "unknown"]}]
    }
    
    # Check if token is expired and refresh if needed
    lassign [try_refresh_token_if_expired $token_dict 0 "rclone"] refresh_success refreshed_token
    
    if {$refresh_success && [dict size $refreshed_token] > 0} {
        # Token was refreshed (expired and had refresh_token)
        debug_log "✓ Successfully refreshed rclone token"
        set token_dict $refreshed_token
        # Rule 1: DON'T save rclone.conf refreshed tokens - use in-memory only
        debug_log "Using refreshed token in-memory only (not saving)"
    } elseif {!$refresh_success && [dict exists $token_dict expiry]} {
        # Refresh was attempted but failed (expired with no refresh_token or refresh failed)
        set expiry_status [check_rclone_token_expiry $token_dict]
        if {$expiry_status == 1} {
            puts "❌ Error: Token has expired and refresh failed!"
            puts ""
            puts "To fix this, please refresh your rclone token:"
            puts "   rclone config reconnect $rclone_remote"
            puts "Or re-authenticate completely:"
            puts "   rclone config"
            return [expr {$return_format eq "simple" ? "" : [list "" "unknown" "unknown"]}]
        }
    }
    
    # Extract access_token from token_dict (either original or already checked)
    set access_token [extract_and_sanitize_access_token $token_dict]
    
    if {$access_token eq ""} {
        puts "Error: No access_token in token JSON"
        puts "Token may be expired. Please re-authenticate: rclone authorize onedrive"
        return [expr {$return_format eq "simple" ? "" : [list "" "unknown" "unknown"]}]
    }
    
    debug_log "Successfully extracted access token from rclone.conf"
    
    # IMPORTANT: rclone.conf tokens are in a format that Microsoft Graph API doesn't accept directly
    # They must be refreshed first, regardless of expiry timestamp
    if {[dict exists $token_dict refresh_token]} {
        debug_log "Refreshing rclone.conf token (required for Microsoft Graph API compatibility)"
        lassign [try_refresh_token_if_expired $token_dict 1 "rclone"] force_refresh_success force_refreshed_token
        
        if {$force_refresh_success && [dict size $force_refreshed_token] > 0} {
            debug_log "✓ Successfully refreshed rclone token"
            set access_token [dict get $force_refreshed_token access_token]
            # Rule 1: DON'T save rclone.conf refreshed tokens - use in-memory only
            debug_log "Using refreshed token in-memory only (not saving)"
        } else {
            debug_log "⚠️ Token refresh failed, trying original token anyway"
        }
    }
    
    # Return in requested format
    debug_log "Using rclone.conf token (read-only mode)"
    return [expr {$return_format eq "simple" ? $access_token : [list $access_token "read-only" "unknown"]}]
}

# ============================================================================
# Token Management with Capability Detection
# ============================================================================
proc check_token_capability {token_data} {
    # Check if token has ACL editing permissions based on scope
    # Returns: "full", "read-only", or "unknown"
    
    if {![dict exists $token_data scope]} {
        return "unknown"
    }
    
    set scope [dict get $token_data scope]
    
    # Check for required scopes for ACL editing
    # For OneDrive Personal: Files.ReadWrite.All is sufficient
    # For OneDrive Business: Sites.Manage.All may also be needed
    set has_write [expr {[string first "Files.ReadWrite.All" $scope] >= 0 || [string first "Files.ReadWrite" $scope] >= 0}]
    set has_manage [expr {[string first "Sites.Manage.All" $scope] >= 0}]
    
    # If we have Files.ReadWrite.All, that's sufficient for ACL editing on OneDrive Personal
    # Sites.Manage.All is nice to have but Microsoft often doesn't grant it to personal accounts
    if {$has_write} {
        return "full"
    }
    
    if {[string first "Files.Read" $scope] >= 0} {
        return "read-only"
    }
    
    return "unknown"
}

proc is_token_expired {token_data} {
    # Check if token is expired based on expires_at field
    # Returns: 1 if expired, 0 if valid, -1 if no expires_at field
    
    if {![dict exists $token_data expires_at]} {
        debug_log "No expires_at field in token, cannot determine expiration"
        return -1
    }
    
    set expires_at [dict get $token_data expires_at]
    debug_log "Token expires_at: $expires_at"
    
    # Parse ISO 8601 timestamp: 2025-10-22T23:53:05Z
    if {[catch {
        set exp_time [clock scan $expires_at -format "%Y-%m-%dT%H:%M:%SZ" -gmt 1]
        set now [clock seconds]
        
        debug_log "Current time: [clock format $now -gmt 1 -format "%Y-%m-%dT%H:%M:%SZ"]"
        debug_log "Token expiry: [clock format $exp_time -gmt 1 -format "%Y-%m-%dT%H:%M:%SZ"]"
        
        if {$now >= $exp_time} {
            debug_log "Token is EXPIRED"
            set result 1
        } else {
            set time_left [expr {$exp_time - $now}]
            debug_log "Token is valid, expires in $time_left seconds"
            set result 0
        }
    } error]} {
        debug_log "Error parsing expires_at: $error"
        return -1
    }
    
    return $result
}

proc check_rclone_token_expiry {token_data} {
    # Check if rclone.conf token is expired (uses "expiry" field, not "expires_at")
    # Returns: 1 if expired, 0 if valid, -1 if cannot determine
    # This handles rclone.conf format which uses "expiry" with timezone info
    
    if {![dict exists $token_data expiry]} {
        return -1
    }
    
    set expiry_str [dict get $token_data expiry]
    debug_log "Token expiry string: $expiry_str"
    
    if {[catch {
        # Normalize expiry string for cross-platform compatibility
        # Handle format: "2025-10-31T01:22:03.598349702+10:00"
        # Remove fractional seconds, normalize timezone
        set expiry_normalized [regsub {\.\d+} $expiry_str ""]
        
        # Try with timezone in +HH:MM format first
        set expiry_time ""
        if {[catch {
            set expiry_time [clock scan $expiry_normalized]
        }]} {
            # If that fails, try normalizing timezone to +HHMM (Windows compatibility)
            set expiry_no_tz [regsub {([+-]\d{2}):(\d{2})$} $expiry_normalized {\1\2}]
            if {[catch {
                set expiry_time [clock scan $expiry_no_tz]
            }]} {
                # Last resort: try without timezone
                set expiry_no_tz [regsub {[+-]\d{2}:?\d{2}$} $expiry_normalized ""]
                if {[catch {
                    set expiry_time [clock scan $expiry_no_tz]
                }]} {
                    error "Could not parse expiry time"
                }
            }
        }
        
        set current_time [clock seconds]
        
        if {$current_time >= $expiry_time} {
            debug_log "Token in rclone.conf is EXPIRED"
            debug_log "Token expired on: [clock format $expiry_time -format "%Y-%m-%d %H:%M:%S UTC"]"
            debug_log "Current time is: [clock format $current_time -format "%Y-%m-%d %H:%M:%S UTC"]"
            return 1
        } else {
            return 0
        }
    } error_msg]} {
        # Silently continue if expiry parsing fails - not critical
        debug_log "Could not parse token expiry time '$expiry_str': $error_msg"
        return -1
    }
}

proc try_refresh_token_if_expired {token_data {force_refresh 0} {token_source "auto"}} {
    # Unified token refresh helper that checks expiry and refreshes if needed
    # 
    # Parameters:
    #   token_data      - Token dictionary to check/refresh
    #   force_refresh   - If 1, refresh even if not expired (for rclone.conf Graph API compatibility)
    #   token_source    - "rclone" (uses expiry field) or "tokenjson" (uses expires_at) or "auto" (detect)
    #
    # Returns: {success refreshed_token_data} where success is 1 if refreshed/valid, 0 if failed
    #          On success, returns refreshed token_data dict (or original if not expired and not forced)
    #          On failure, returns empty dict
    
    # Detect token source if auto
    if {$token_source eq "auto"} {
        if {[dict exists $token_data expiry]} {
            set token_source "rclone"
        } elseif {[dict exists $token_data expires_at]} {
            set token_source "tokenjson"
        } else {
            # Cannot determine source, treat as potentially valid
            return [list 1 $token_data]
        }
    }
    
    # Check if refresh is needed
    set needs_refresh 0
    
    if {$force_refresh} {
        set needs_refresh 1
        debug_log "Force refresh requested (for Graph API compatibility)"
    } else {
        # Check expiry based on token source
        if {$token_source eq "rclone"} {
            set expiry_status [check_rclone_token_expiry $token_data]
            if {$expiry_status == 1} {
                set needs_refresh 1
                debug_log "rclone.conf token is expired, refresh needed"
            }
        } else {
            # token.json format
            set expiry_status [is_token_expired $token_data]
            if {$expiry_status == 1} {
                set needs_refresh 1
                debug_log "token.json token is expired, refresh needed"
            }
        }
    }
    
    # If no refresh needed, return original token
    if {!$needs_refresh} {
        return [list 1 $token_data]
    }
    
    # Check if refresh_token is available
    if {![dict exists $token_data refresh_token]} {
        debug_log "Token needs refresh but no refresh_token available"
        return [list 0 {}]
    }
    
    # Attempt refresh
    debug_log "Attempting to refresh token..."
    set refreshed_token [refresh_access_token $token_data]
    
    if {[dict size $refreshed_token] > 0 && [dict exists $refreshed_token access_token]} {
        debug_log "✓ Successfully refreshed token"
        return [list 1 $refreshed_token]
    } else {
        debug_log "Token refresh failed"
        return [list 0 {}]
    }
}

proc refresh_access_token {token_data} {
    # Refresh access token using refresh_token
    # Returns: new token_data dict on success, empty dict on failure
    
    global oauth
    
    if {![dict exists $token_data refresh_token]} {
        debug_log "No refresh_token available in token data"
        return {}
    }
    
    set refresh_token [dict get $token_data refresh_token]
    debug_log "Attempting to refresh access token..."
    
    set headers [list Content-Type application/x-www-form-urlencoded]
    set form [::http::formatQuery \
        grant_type    refresh_token \
        refresh_token $refresh_token \
        client_id     $oauth(client_id) \
        client_secret $oauth(client_secret) \
        scope         $oauth(scope)]
    
    # Use result variable pattern (avoid return inside catch)
    set result {}
    set error_msg ""
    set has_error 0
    
    if {[catch {
        set tok [::http::geturl $oauth(token_url) -method POST -headers $headers -query $form -timeout 30000]
        set status [::http::status $tok]
        set ncode [::http::ncode $tok]
        set data [::http::data $tok]
        
        debug_log "Token refresh HTTP status: $status"
        debug_log "Token refresh HTTP code: $ncode"
        
        ::http::cleanup $tok
        
        if {$status ne "ok"} {
            set error_msg "Token refresh failed: HTTP request status is $status"
            error $error_msg
        }
        
        if {$ncode != 200} {
            debug_log "Token refresh failed response: $data"
            set error_msg "Token refresh failed: HTTP $ncode - $data"
            error $error_msg
        }
        
        # Parse JSON response
        debug_log "Parsing token refresh JSON response..."
        set new_token_dict [json::json2dict $data]
        debug_log "New token dict keys: [dict keys $new_token_dict]"
        
        # Check if access_token exists
        if {[dict exists $new_token_dict access_token]} {
            debug_log "✓ Token refresh successful, received new access_token"
            
            # NOTE: We do NOT save to token.json here
            # The caller should decide whether to save (OAuth flow) or just use in-memory (rclone refresh)
            
            set result $new_token_dict
        } else {
            debug_log "ERROR: No access_token in refresh response!"
            set error_msg "No access_token in token refresh response"
            error $error_msg
        }
    } error] != 0} {
        debug_log "Token refresh error caught: $error"
        set error_msg "Token refresh error: $error"
        set has_error 1
    }
    
    # Return result or empty dict on error (outside catch)
    if {$has_error} {
        debug_log "Token refresh failed: $error_msg"
        return {}
    }
    return $result
}

proc save_token_json {token_dict} {
    # Save OAuth token to token.json with proper format using json::write
    # Ensures scope is preserved for capability detection
    
    debug_log "save_token_json called with dict keys: [dict keys $token_dict]"
    
    if {![dict exists $token_dict access_token]} {
        debug_log "ERROR: No access_token in token response!"
        debug_log "Token dict contents: $token_dict"
        return -code error "No access_token in token response"
    }
    
    # Calculate expiry timestamp
    set now [clock seconds]
    if {[dict exists $token_dict expires_in]} {
        set delta [dict get $token_dict expires_in]
        set exp [expr {$now + $delta}]
        set expires_at [clock format $exp -gmt 1 -format "%Y-%m-%dT%H:%M:%SZ"]
    } else {
        # Default to 1 hour if not specified
        set exp [expr {$now + 3600}]
        set expires_at [clock format $exp -gmt 1 -format "%Y-%m-%dT%H:%M:%SZ"]
    }
    
    # Build JSON using json::write for proper quoting
    # json::write object takes alternating key/value pairs
    set json_parts [list \
        access_token [json::write string [dict get $token_dict access_token]] \
        token_type [json::write string [dict get $token_dict token_type]] \
        expires_at [json::write string $expires_at]]
    
    # Add optional fields
    if {[dict exists $token_dict scope]} {
        lappend json_parts scope [json::write string [dict get $token_dict scope]]
    }
    if {[dict exists $token_dict expires_in]} {
        lappend json_parts expires_in [json::write string [dict get $token_dict expires_in]]
    }
    if {[dict exists $token_dict refresh_token]} {
        lappend json_parts refresh_token [json::write string [dict get $token_dict refresh_token]]
    }
    
    # Add drive information
    lappend json_parts drive_id [json::write string "5D1B2B3BE100F93B"]
    lappend json_parts drive_type [json::write string "personal"]
    
    # Generate JSON object
    set json_output [json::write object {*}$json_parts]

    # Write to file with restricted permissions
    set token_file [get_token_file_path]
    set fh [open $token_file w 0600]
    puts $fh $json_output
    close $fh

    if {[dict exists $token_dict scope]} {
        debug_log "Token saved to $token_file with scopes: [dict get $token_dict scope]"
    }
    return 1
}

# ============================================================================
# OAuth Flow Implementation
# ============================================================================
proc oauth_start_local_server {} {
    # Start local HTTP server to capture OAuth callback
    global serverSock
    
    # Close any existing server socket first
    if {$serverSock ne ""} {
        catch {close $serverSock}
        set serverSock ""
    }
    
    if {[catch {
        set serverSock [socket -server oauth_accept 53682]
        debug_log "OAuth callback server started on port 53682"
    } error]} {
        set errorMsg "Failed to start OAuth server on port 53682: $error"
        if {[string match "*address already in use*" $error] || [string match "*Address already in use*" $error]} {
            append errorMsg "\n\nPort 53682 is already in use. Please:"
            append errorMsg "\n1. Check if another instance of this program is running"
            append errorMsg "\n2. Wait a moment and try again"
            append errorMsg "\n3. Or run: lsof -i :53682 (to see what's using the port)"
        }
        gui_update_status "Error starting OAuth server: $error" red
        debug_log $errorMsg
        return ""
    }
    
    return $serverSock
}

proc oauth_accept {chan addr port} {
    # Handle OAuth callback from browser
    global oauth serverSock
    
    debug_log "OAuth callback received from $addr:$port"
    
    # Configure channel for HTTP
    fconfigure $chan -blocking 0 -buffering line -translation {auto crlf}
    
    # Set up fileevent to read HTTP request asynchronously
    fileevent $chan readable [list oauth_handle_request $chan]
}

proc oauth_handle_request {chan} {
    # Handle HTTP request from OAuth callback
    global oauth serverSock
    
    set should_return 0
    if {[catch {
        # Read the HTTP request line
        if {[gets $chan line] < 0} {
            if {[eof $chan]} {
                close $chan
            }
            set should_return 1
        }
        
        debug_log "OAuth callback request: $line"
        
        # Extract authorization code from request
        set code ""
        if {[regexp {GET\s+/\?code=([^&\s]+)} $line -> code]} {
            set oauth(auth_code) $code
            debug_log "Received authorization code: [string range $code 0 20]..."
            
            # Read remaining headers (we don't need them but must consume them)
            while {[gets $chan header] >= 0} {
                if {$header eq ""} {
                    break
                }
            }
            
            # Send success response
            set body "<html><head><title>Authentication Successful</title></head><body style=\"font-family:Arial,sans-serif;text-align:center;padding:50px;\"><h1 style=\"color:green;\">✓ Authentication Successful</h1><p>You can close this window and return to the application.</p></body></html>"
            
            puts $chan "HTTP/1.1 200 OK"
            puts $chan "Content-Type: text/html; charset=utf-8"
            puts $chan "Content-Length: [string length $body]"
            puts $chan "Connection: close"
            puts $chan ""
            puts $chan $body
            flush $chan
            
            # Schedule channel close after giving time to send
            after 100 [list catch [list close $chan]]
            
            # Stop listening after successful callback
            if {$serverSock ne ""} {
                debug_log "Closing OAuth server socket after successful callback"
                after 200 [list catch [list close $serverSock]]
                set serverSock ""
            }
        } else {
            # Read remaining headers
            while {[gets $chan header] >= 0} {
                if {$header eq ""} {
                    break
                }
            }
            
            # Send error response
            set body "<html><head><title>Authentication Error</title></head><body style=\"font-family:Arial,sans-serif;text-align:center;padding:50px;\"><h1 style=\"color:red;\">✗ Authentication Error</h1><p>No authorization code received.</p></body></html>"
            
            puts $chan "HTTP/1.1 400 Bad Request"
            puts $chan "Content-Type: text/html; charset=utf-8"
            puts $chan "Content-Length: [string length $body]"
            puts $chan "Connection: close"
            puts $chan ""
            puts $chan $body
            flush $chan
            
            after 100 [list catch [list close $chan]]
        }
    } error]} {
        debug_log "Error handling OAuth callback: $error"
        catch {close $chan}
    }
    
    if {$should_return} {
        return
    }
}

proc oauth_build_auth_url {} {
    # Build Microsoft authorization URL
    global oauth
    
    set query [::http::formatQuery \
        client_id     $oauth(client_id) \
        response_type code \
        redirect_uri  $oauth(redirect_uri) \
        scope         $oauth(scope) \
        response_mode query \
        prompt        select_account]
    
    return "$oauth(auth_url)?$query"
}

proc oauth_exchange_token {code} {
    # Exchange authorization code for access token
    global oauth
    
    set headers [list Content-Type application/x-www-form-urlencoded]
    set form [::http::formatQuery \
        grant_type    authorization_code \
        code          $code \
        client_id     $oauth(client_id) \
        client_secret $oauth(client_secret) \
        redirect_uri  $oauth(redirect_uri) \
        scope         $oauth(scope)]
    
    debug_log "Exchanging authorization code for access token..."
    debug_log "Token URL: $oauth(token_url)"
    
    # Use a result variable instead of returning from inside catch
    set result ""
    set error_msg ""
    set has_error 0
    
    if {[catch {
        set tok [::http::geturl $oauth(token_url) -method POST -headers $headers -query $form -timeout 30000]
        set status [::http::status $tok]
        set ncode [::http::ncode $tok]
        set data [::http::data $tok]
        set response_headers [::http::meta $tok]
        
        debug_log "Token exchange HTTP status: $status"
        debug_log "Token exchange HTTP code: $ncode"
        debug_log "Token exchange response data length: [string length $data]"
        
        ::http::cleanup $tok
        
        if {$status ne "ok"} {
            set error_msg "Token exchange failed: HTTP request status is $status"
            error $error_msg
        }
        
        if {$ncode != 200} {
            debug_log "Token exchange failed response: $data"
            set error_msg "Token exchange failed: HTTP $ncode - $data"
            error $error_msg
        }
        
        # Parse JSON response
        debug_log "Parsing token JSON response..."
        set result [json::json2dict $data]
        debug_log "Token dict keys: [dict keys $result]"
        
        # Check if access_token exists
        if {[dict exists $result access_token]} {
            debug_log "✓ Token exchange successful, received access_token"
        } else {
            debug_log "ERROR: No access_token in parsed response!"
            set error_msg "No access_token in token response"
            error $error_msg
        }
    } error] != 0} {
        debug_log "Token exchange error caught: $error"
        set error_msg "Token exchange error: $error"
        set has_error 1
    }
    
    # Return the result or error (outside catch)
    if {$has_error} {
        return -code error $error_msg
    }
    return $result
}

proc acquire_elevated_token {} {
    # Show modal dialog with authentication options
    # User chooses: browser auth OR reload token file
    global oauth
    
    gui_update_status "Elevated permissions required - please choose authentication method..." blue
    
    # Show modal dialog with two action buttons
    # Dialog handles everything: OAuth server, browser launch, token reload, etc.
    set success [show_oauth_modal_dialog]
    
    if {$success} {
        gui_update_status "✅ Authentication successful!" green
    } else {
        gui_update_status "Authentication cancelled or failed" orange
        cleanup_oauth_server
    }
    
    return $success
}

# ============================================================================
# Modal OAuth Dialog with Token Reload Support
# ============================================================================
proc cleanup_oauth_server {} {
    # Clean up OAuth server socket without resetting auth_code
    # Preserves the OAuth result if already set
    global serverSock
    
    if {[info exists serverSock] && $serverSock ne ""} {
        catch {close $serverSock}
        set serverSock ""
        debug_log "OAuth server socket closed"
    }
}

proc cli_get_full_token {remote_name} {
    # Helper function for CLI operations requiring full permissions
    # Returns: {access_token} on success, empty string on failure
    # Handles all error messaging internally
    
    set result [get_access_token $remote_name "full" "detailed" 1]
    set access_token [lindex $result 0]
    set capability [lindex $result 1]
    
    if {$access_token eq "" || $capability ne "full"} {
        puts "❌ Operation requires full permissions (Files.ReadWrite.All + Sites.Manage.All)"
        puts ""
        puts "This operation failed because:"
        if {$capability eq "insufficient"} {
            puts "  - token.json is expired or missing"
            puts "  - rclone.conf token only has read-only permissions"
        } else {
            puts "  - No valid authentication token available"
        }
        puts ""
        puts "To fix this:"
        puts "  1. Run the script in GUI mode (wish acl-inspector.tcl)"
        puts "  2. Trigger an operation requiring permissions (Invite or Remove)"
        puts "  3. Complete browser authentication"
        puts "  4. Try this command again"
        puts ""
        puts "Alternatively, manually update token.json with a valid full-permission token."
        return ""
    }
    
    puts "✅ Using token with full permissions"
    return $access_token
}
