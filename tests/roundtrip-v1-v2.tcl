#!/usr/bin/env tclsh
# One-off conversion check: the version-2 form of an email-per-member policy
# must produce the same audit plan as the original. Compares expected,
# effective, closed, and path per folder id; exits nonzero on any difference.
# Retires with the email-per-member loader once the conversion has happened.
#
# Usage: tclsh9.0 tests/roundtrip-v1-v2.tcl <v1-policy.yaml>

package require yaml

set here [file dirname [file normalize [info script]]]
set repo [file dirname $here]
source [file join $repo lib policy.tcl]

# The email-per-member loader lives in acl-manager.tcl until the lib split;
# lift its four procs out by text range rather than sourcing the whole
# script (whose tail dispatches a CLI).
set f [open [file join $repo acl-manager.tcl] r]
fconfigure $f -encoding utf-8
set src [read $f]
close $f
set start [string first "proc policy_member_email \{" $src]
set end [string first "proc audit_folder" $src]
if {$start < 0 || $end < 0 || $end <= $start} {
    puts stderr "cannot locate the email-per-member policy procs in acl-manager.tcl"
    exit 2
}
eval [string range $src $start [expr {$end - 1}]]

lassign $argv v1_path
if {$v1_path eq ""} { puts stderr "usage: roundtrip-v1-v2.tcl <v1-policy.yaml>"; exit 2 }

set v1 [policy_load $v1_path]
set v2_text [policy_convert_v1_v2 $v1_path]
set tmp [file tempfile tmppath]
fconfigure $tmp -encoding utf-8
puts -nonewline $tmp $v2_text
close $tmp
set v2 [policy_load_v2 $tmppath]
file delete $tmppath

set plan1 [dict get $v1 plan]
set plan2 [expr {[dict exists $v2 plan onedrive] ? [dict get $v2 plan onedrive] : {}}]

set fail 0
proc mismatch {msg} { puts "❌ $msg"; set ::fail 1 }

foreach fid [lsort [dict keys $plan1]] {
    if {![dict exists $plan2 $fid]} { mismatch "folder $fid missing from converted plan"; continue }
    set e1 [dict get $plan1 $fid]
    set e2 [dict get $plan2 $fid]
    foreach key {path closed} {
        if {[dict get $e1 $key] ne [dict get $e2 $key]} {
            mismatch "folder $fid $key differs: '[dict get $e1 $key]' vs '[dict get $e2 $key]'"
        }
    }
    foreach key {expected effective} {
        set d1 [dict get $e1 $key]
        set d2 [dict get $e2 $key]
        foreach email [lsort -unique [concat [dict keys $d1] [dict keys $d2]]] {
            set r1 [expr {[dict exists $d1 $email] ? [dict get $d1 $email] : "(absent)"}]
            set r2 [expr {[dict exists $d2 $email] ? [dict get $d2 $email] : "(absent)"}]
            if {$r1 ne $r2} {
                mismatch "folder $fid $key\($email): $r1 vs $r2"
            }
        }
    }
}
foreach fid [lsort [dict keys $plan2]] {
    if {![dict exists $plan1 $fid]} { mismatch "folder $fid appears only in converted plan" }
}

if {$fail} { exit 1 }
puts "✅ plans identical: [dict size $plan1] folder(s), [dict size [dict get $v2 people]] person(s), [llength [dict get $v2 warnings]] warning(s)"
exit 0
