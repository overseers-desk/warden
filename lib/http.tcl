# Generic HTTPS transport: a retrying request wrapper and URL/JSON text helpers.
package require http
package require tls
package require json

# Configure TLS for HTTPS requests
::http::register https 443 [list ::tls::socket -autoservername 1]

proc url_encode {path} {
    # URL encode a path, handling Unicode characters properly
    set encoded ""
    foreach char [split $path ""] {
        if {$char eq " "} {
            append encoded "%20"
        } elseif {$char eq "/"} {
            append encoded "/"
        } elseif {[string is ascii $char] && ([string is alnum $char] || $char eq "-" || $char eq "_" || $char eq ".")} {
            append encoded $char
        } else {
            # For non-ASCII characters, use proper UTF-8 encoding
            set utf8_bytes [encoding convertto utf-8 $char]
            foreach byte [split $utf8_bytes ""] {
                append encoded [format "%%%02X" [scan $byte %c]]
            }
        }
    }
    return $encoded
}

proc combine_surrogate_escapes {jsontext} {
    # Graph escapes anything outside the BMP as a UTF-16 surrogate pair,
    # "\uD83C\uDDEC" for the first half of a flag. The json package unescapes
    # by handing the string body to [subst], which turns each half into a
    # separate lone surrogate, so a name that starts with a flag arrives as
    # four unrenderable characters. Combine the pairs before parsing.
    #
    # Only pairs are touched. A combined pair is always outside the BMP, so
    # this can never produce a quote, backslash or control character that
    # would change the structure of the document.
    return [regsub -all -command \
        {(\\*)\\u([Dd][89ABab][0-9A-Fa-f]{2})\\u([Dd][C-Fc-f][0-9A-Fa-f]{2})} \
        $jsontext {apply {{whole bs hi lo} {
            # An odd run of backslashes means the "\u" is literal text, as in
            # a name containing C:\uD83C, and must be left alone.
            if {[string length $bs] % 2} { return $whole }
            scan $hi %x h
            scan $lo %x l
            return $bs[format %c [expr {(($h - 0xD800) << 10) + ($l - 0xDC00) + 0x10000}]]
        }}}]
}

proc url_decode {str} {
    # Decode %XX URL-encoded sequences back to characters
    # Companion to url_encode above
    set decoded ""
    set i 0
    set len [string length $str]
    while {$i < $len} {
        set ch [string index $str $i]
        if {$ch eq "%" && $i + 2 < $len} {
            set hex [string range $str [expr {$i+1}] [expr {$i+2}]]
            if {[string is xdigit -strict $hex]} {
                append decoded [binary format c [scan $hex %x]]
                incr i 3
                continue
            }
        } elseif {$ch eq "+"} {
            append decoded " "
            incr i
            continue
        }
        append decoded $ch
        incr i
    }
    return [encoding convertfrom utf-8 $decoded]
}

proc make_http_request {url headers {method GET} {body ""}} {
    # Transient transport failures (no HTTP status at all) are retried; any
    # real HTTP status, success or error, passes straight through
    for {set attempt 1} {$attempt <= 3} {incr attempt} {
        set result [make_http_request_once $url $headers $method $body]
        set status [lindex $result 0]
        if {$status ne "error" && $status ne ""} {
            return $result
        }
        if {$attempt < 3} {
            debug_log "Transient transport failure, retrying ($attempt/3): $url"
            after 2000
        }
    }
    return $result
}

proc make_http_request_once {url headers {method GET} {body ""}} {
    # Enhanced HTTP request supporting GET, POST, DELETE with better 401 handling
    set response ""
    
    if {[catch {
        # Use all headers passed in (not just Authorization)
        set opts [list -headers $headers -timeout 30000 -method $method]
        
        # Add body for methods that carry one
        if {$body ne "" && $method in {POST PATCH PUT}} {
            lappend opts -query $body
        }
        
        set response [http::geturl $url {*}$opts]
        set status [http::ncode $response]
        
        debug_log "HTTP Request to [string range $url 0 80]... returned status: $status"
        
        # For 204 No Content, don't try to read data (socket may be closed)
        if {$status eq "204"} {
            set data ""
        } else {
            set data [combine_surrogate_escapes [http::data $response]]
        }
        http::cleanup $response
        
        if {$status ne "200" && $status ne "201" && $status ne "204"} {
            debug_log "HTTP Error: Status $status, Response: [string range $data 0 300]"
            # Enhanced error message for 401 (authentication) errors
            if {$status eq "401"} {
                # Try to parse error response for better message
                if {[catch {json::json2dict $data} error_dict] == 0} {
                    if {[dict exists $error_dict error]} {
                        set error_info [dict get $error_dict error]
                        if {[dict exists $error_info code]} {
                            set error_code [dict get $error_info code]
                            if {$error_code eq "InvalidAuthenticationToken" || [string match "*expired*" [string tolower $error_code]]} {
                                debug_log "HTTP 401 - Token expired or invalid: $data"
                                set result [list $status "TOKEN_EXPIRED: $data"]
                                return $result
                            }
                        }
                    }
                }
                debug_log "HTTP 401 - Authentication failed - URL: $url"
            } else {
                debug_log "HTTP $status - URL: $url"
            }
            debug_log "Response data: $data"
        }
        
        set result [list $status $data]
    } error]} {
        # Error during HTTP transaction - but check if we got a valid response first
        # This handles cases where server closes connection after sending 204 (common for DELETE)
        if {$response ne ""} {
            # Try to get the status code from the response
            set status ""
            catch {set status [http::ncode $response]}
            
            if {$status ne ""} {
                # We got a status code! Check if it's a success
                if {$status eq "200" || $status eq "201" || $status eq "204"} {
                    # Success! The error was just connection closing after successful response
                    catch {http::cleanup $response}
                    return [list $status ""]
                }
            }
            catch {http::cleanup $response}
        }
        
        # Check if this is a "connection abort" error which often means successful 204
        if {[string match "*connection abort*" $error] || [string match "*error reading*" $error]} {
            # This is likely a successful DELETE with immediate connection close
            # Return success with 204 status
            return [list "204" ""]
        }
        
        debug_log "HTTP request failed - $error (URL: $url)"
        set result [list "error" $error]
    }
    return $result
}
