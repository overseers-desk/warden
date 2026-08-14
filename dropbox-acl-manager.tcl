#!/usr/bin/env tclsh
# Dropbox sharing operations from the command line: recursive unshare and
# a listing of top-level shared folders. The machinery lives in
# lib/provider-dropbox.tcl, shared with acl-manager's audit.
#
# Usage:
#   tclsh dropbox-acl-manager.tcl unshare [-r] <dropbox-path>
#   tclsh dropbox-acl-manager.tcl list-shares

set libdir [file join [file dirname [file normalize [info script]]] lib]
source [file join $libdir http.tcl]
source [file join $libdir provider-dropbox.tcl]

set usage "Usage: tclsh dropbox-acl-manager.tcl <subcommand> \[args\]
Subcommands:
  unshare \[-r\] <dropbox-path>
  list-shares"

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
    list-shares {
        if {[llength $argv] > 1} { puts stderr $usage; exit 1 }
        cmd_list_shares
    }
    default { puts stderr $usage; exit 1 }
}
