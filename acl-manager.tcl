#!/usr/bin/env tclsh9.0
#
# OneDrive ACL Lister - Tcl/Tk GUI Version with Command Line Support
# Using rclone.conf token to access Microsoft Graph API directly
#
# This script demonstrates how to:
# 1. Read the OAuth token from rclone.conf
# 2. Use it to make direct Microsoft Graph API calls
# 3. Display ACL (Access Control List) in a treeview widget or console
#
#
# Prerequisites:
# - Tcl/Tk 9. Item names carry characters outside the BMP, which Tcl 8 cannot
#   hold in a string, so an 8.x shell is refused rather than run degraded.
# - rclone must be installed and configured with OneDrive remote
# - tls package for HTTPS requests (package require tls)
# - Valid OAuth token in ~/.config/rclone/rclone.conf
#
# Usage:
#    Browser:  run with no arguments
#    CLI:      run with an item path, or with any option; -help lists them
#
#    item_path: Path to the folder or file in OneDrive

package require Tcl 9
package require http
package require json
package require json::write
package require tls
package require cmdline
package require yaml

# The library files carry everything below the entry points; source them
# next to this script so a directory copy is a complete install.
set libdir [file join [file dirname [file normalize [info script]]] lib]
foreach libfile {http.tcl auth-onedrive.tcl provider-onedrive.tcl provider-dropbox.tcl policy.tcl audit.tcl} {
    source [file join $libdir $libfile]
}
unset libfile


# Suppress TLS channel error messages (they're just warnings, not fatal)
# These get logged but don't affect functionality
proc bgerror {message} {
    # Suppress SSL channel errors (non-fatal warnings)
    if {[string match "*SSL channel*" $message]} {
        return
    }
    # Log other errors only if debug mode is on
    debug_log "Background error: $message"
}

# Global variables
set debug_mode 0  ;# Set to 1 to enable debug logging (WARNING: may fail with unicode in folder names)
set quiet_mode 0  ;# Set to 1 to suppress progress output (used by --format csv)
set access_token ""
set item_path ""
set remote_name "OneDrive"
set current_folder_id "root"
set current_folder_path ""
set acl_fetch_job ""  ;# Track pending ACL fetch job to allow cancellation
set token_capability "unknown"  ;# "full", "read-only", or "unknown"
set current_item_id ""       ;# Track current item for edit operations


# Glob patterns for items to hide from browser and recursive scans
set ignore_patterns [list \
    ".Trash-*" \
    "*Tsiko*"]
set ::serverSock           ""
set ::oauth_modal_result   0  ;# Result from OAuth modal dialog (0=failure/cancel, 1=success)

# Treeview browser variables
set selected_item {}      ;# Currently selected item {id is_folder}

# GUI widget handles live here instead of as scattered globals: ::ui::w(name)
# holds the widget path for anything the rest of the file needs to reach, and
# ::ui::state is free for any other GUI-only state that isn't a widget.
namespace eval ::ui {
    variable w
    array set w {}
    variable state
    array set state {}
}

# Tk 9 carries characters outside the BMP to the X11 clipboard intact, so a
# path holding an emoji copies as itself.
proc copy_to_clipboard {text} {
    clipboard clear
    clipboard append $text
}

# A bare invocation asks for the browser; every other one names work for the
# command line. Tk is loaded into this interpreter rather than reached by
# re-execing a wish, which keeps one process and makes the toolkit version
# follow the shell: a Tcl 9 interpreter can load nothing but Tk 9. Failure to
# load leaves tk undefined, so the blocks below stand down and the command
# line answers instead.
if {$argc == 0 || $argv eq {-debug}} {
    if {[catch {package require Tk} tk_error]} {
        puts stderr "The browser cannot open: $tk_error"
        if {[string match "can't find package*" $tk_error]} {
            puts stderr "(Debian/Ubuntu: sudo apt-get install tk9.0)"
        }
        puts stderr ""
    }
}

# Helper function to configure treeview columns
proc configure_tree_columns {tree columns} {
    foreach {col_id heading width minwidth} $columns {
        $tree heading $col_id -text $heading
        $tree column $col_id -width $width -minwidth $minwidth
    }
}

# Tk commands inside a proc resolve when the proc is called, not when it is
# defined, so these build procs are safe to define unconditionally even
# though they only ever run once Tk is confirmed loaded (see ::ui::start).

proc ::ui::build {} {
    variable w

    # Stated rather than assumed. Tk 9 provides Ttk as it loads, and the
    # browser is also reachable by starting the script under wish, which
    # never passes through the block above.
    package require Ttk

    # Create main window
    wm title . "Cloud ACL Manager"

    # Handle window close during OAuth flow
    wm protocol . WM_DELETE_WINDOW {
        global serverSock oauth

        # Clean up OAuth server if running
        if {[info exists serverSock] && $serverSock ne ""} {
            catch {close $serverSock}
            set serverSock ""
            debug_log "Closed OAuth server socket due to window close"
        }

        # Signal OAuth flow to stop by setting a cancel flag
        if {[info exists oauth(auth_code)] && $oauth(auth_code) eq ""} {
            set oauth(auth_code) "CANCELLED"
            debug_log "OAuth flow cancelled by user (window closed)"
        }

        # Exit cleanly
        destroy .
    }

    # Create main frame
    set w(root_frame) [ttk::frame .main]
    pack $w(root_frame) -fill both -expand yes -padx 10 -pady 10

    ::ui::build_chrome
    ::ui::build_addressbar

    # MAIN CONTENT: Left-Right Split Layout

    # Create horizontal panedwindow for left-middle-right layout
    pack [ttk::panedwindow $w(root_frame).paned -orient horizontal] -fill both -expand yes -pady {0 10}
    set w(paned) $w(root_frame).paned

    ::ui::build_browser
    ::ui::build_acl_pane
    ::ui::build_status
}

proc ::ui::connections_discover {} {
    # Drives this machine's rclone knows: one connection per onedrive or
    # dropbox remote in rclone.conf.
    variable state
    set state(connections) {}
    if {[info exists ::env(APPDATA)]} {
        set conf [file join $::env(APPDATA) rclone rclone.conf]
    } else {
        set conf [file join $::env(HOME) .config rclone rclone.conf]
    }
    if {![file exists $conf]} { return }
    set f [open $conf r]
    set data [read $f]
    close $f
    set section ""
    foreach line [split $data \n] {
        set line [string trim $line]
        if {[regexp {^\[(.+)\]$} $line -> name]} { set section $name; continue }
        if {[regexp {^type\s*=\s*(\S+)} $line -> rtype] && $section ne ""} {
            switch -- $rtype {
                onedrive - dropbox {
                    set pretty [expr {$rtype eq "onedrive" ? "OneDrive" : "Dropbox"}]
                    lappend state(connections) [dict create \
                        platform $rtype remote $section label "$pretty — $section"]
                }
            }
        }
    }
}

proc ::ui::build_chrome {} {
    # Top strip: connected drives and the policy file in charge.
    variable w
    variable state
    set f $w(root_frame)
    pack [ttk::frame $f.chrome] -fill x -pady {0 6}
    pack [ttk::label $f.chrome.conn -text "Connected:"] -side left
    foreach conn $state(connections) {
        set chip [string map {" " _ . _} [dict get $conn remote]]
        pack [ttk::label $f.chrome.chip_$chip \
            -text "● [dict get $conn label]" -foreground darkgreen \
            -relief solid -borderwidth 1 -padding {4 1}] -side left -padx 3
    }
    pack [ttk::button $f.chrome.reload -text "Reload" -command ::ui::policy_reload] -side right -padx {4 0}
    pack [ttk::button $f.chrome.open -text "Open…" -command ::ui::policy_open] -side right -padx {4 0}
    set w(policy_label) [ttk::label $f.chrome.policy -text "(no policy loaded)" -foreground gray40]
    pack $w(policy_label) -side right -padx {4 0}
    pack [ttk::label $f.chrome.plabel -text "Policy:"] -side right -padx {10 0}
}

proc ::ui::policy_conf_file {} {
    return [file join $::env(HOME) .config acl-manager gui-policy-path]
}

proc ::ui::policy_open {{path ""}} {
    # Load a policy file into the session model; remember it for next launch.
    variable state
    variable w
    if {$path eq ""} {
        set path [tk_getOpenFile -title "Open policy file" \
            -filetypes {{{YAML policy} {.yaml .yml}} {{All files} *}}]
        if {$path eq ""} { return }
    }
    if {[catch {policy_load_v2 $path} model]} {
        ::ui::status "Policy error: $model" red
        return
    }
    set state(policy_path) $path
    set state(model) $model
    catch {
        file mkdir [file dirname [::ui::policy_conf_file]]
        set pf [open [::ui::policy_conf_file] w]
        puts $pf $path
        close $pf
    }
    $w(policy_label) configure -text $path -foreground black
    catch {::ui::audit_restore}
    catch {::ui::badges_refresh}
    set nwarn [llength [dict get $model warnings]]
    set summary "Policy: [file tail $path] loaded"
    if {$nwarn > 0} { append summary " ($nwarn unreachable grant(s))" }
    ::ui::status $summary blue
}

proc ::ui::policy_reload {} {
    variable state
    if {[info exists state(policy_path)] && $state(policy_path) ne ""} {
        ::ui::policy_open $state(policy_path)
    } else {
        ::ui::policy_open
    }
}

proc ::ui::policy_startup {} {
    # Reopen the policy used last time, when it still exists.
    catch {
        set pf [open [::ui::policy_conf_file] r]
        set path [string trim [read $pf]]
        close $pf
        if {$path ne "" && [file exists $path]} { ::ui::policy_open $path }
    }
}

proc ::ui::build_addressbar {} {
    variable w
    set f $w(root_frame)

    # Create input frame (top section)
    pack [ttk::frame $f.input] -fill x -pady {0 10}

    # OneDrive URL address bar (read-only, at top)
    pack [ttk::frame $f.input.url] -fill x -pady 2
    ttk::label $f.input.url.label -text "URL:"
    pack $f.input.url.label -side left
    set w(url_entry) [ttk::entry $f.input.url.entry -width 60]
    pack $w(url_entry) -side left -fill x -expand yes -padx {5 0}
    $w(url_entry) insert 0 "https://onedrive.live.com/?id=root"
    $w(url_entry) configure -state readonly

    # Path bar showing hierarchical path from root
    pack [ttk::frame $f.input.path] -fill x -pady 2
    ttk::label $f.input.path.label -text "Path:"
    pack $f.input.path.label -side left
    set w(path_entry) [ttk::entry $f.input.path.entry -width 60]
    pack $w(path_entry) -side left -fill x -expand yes -padx {5 0}
    $w(path_entry) insert 0 ""
    $w(path_entry) configure -state readonly

    # Copy path button (workaround for Tk 8.x emoji clipboard bug)
    button $f.input.path.copy -text "Copy" -command {
        copy_to_clipboard [$::ui::w(path_entry) get]
    }
    pack $f.input.path.copy -side left -padx {5 0}

    # Hidden remote name entry (for rclone configuration)
    set w(remote_entry) [ttk::entry $f.input.remote_hidden -width 20]
    $w(remote_entry) insert 0 "OneDrive"
    # Don't pack this - it's hidden
}

proc ::ui::build_browser {} {
    variable w

    # LEFT PANE: Browser
    set left_frame [ttk::frame $w(paned).browser]
    $w(paned) add $left_frame -weight 1

    ttk::label $left_frame.label -text "Folders:"
    pack $left_frame.label -anchor w -pady {0 5}

    # Create treeview with scrollbars
    pack [ttk::scrollbar $left_frame.hscroll -orient horizontal -command "$left_frame.tree xview"] -side bottom -fill x
    pack [ttk::scrollbar $left_frame.vscroll -orient vertical -command "$left_frame.tree yview"] -side right -fill y

    set w(tree) [ttk::treeview $left_frame.tree \
        -columns {item_id type loaded provider badge} -show {tree headings} \
        -displaycolumns {badge} \
        -selectmode browse \
        -yscrollcommand "$left_frame.vscroll set" \
        -xscrollcommand "$left_frame.hscroll set"]
    pack $w(tree) -side left -fill both -expand yes

    $w(tree) heading #0 -text "Folder"
    $w(tree) heading badge -text "Policy"
    $w(tree) column badge -width 60 -stretch 0 -anchor center

    # Bind events for selection and expansion
    bind $w(tree) <<TreeviewSelect>> {on_tree_select $::ui::w(tree)}
    bind $w(tree) <<TreeviewOpen>> {on_tree_expand $::ui::w(tree) [%W focus]}

    # Bind double-click to toggle folder expansion
    bind $w(tree) <Double-Button-1> {
        set item [%W identify item %x %y]
        if {$item ne ""} {
            set values [%W item $item -values]
            set type [lindex $values 1]
            if {$type eq "folder"} {
                set is_open [%W item $item -open]
                if {$is_open} {
                    %W item $item -open 0
                } else {
                    %W item $item -open 1
                    on_tree_expand %W $item
                }
            }
        }
    }

    # One root per connected drive, each with a dummy child for the arrow
    variable state
    if {[llength $state(connections)] == 0} {
        set state(connections) [list [dict create \
            platform onedrive remote OneDrive label "OneDrive"]]
    }
    foreach conn $state(connections) {
        set root_id [expr {[dict get $conn platform] eq "onedrive" ? "root" : ""}]
        set root_item [$w(tree) insert {} end -text [dict get $conn label] \
            -values [list $root_id "folder" 0 [dict get $conn platform] ""]]
        $w(tree) insert $root_item end -text ""
    }
}

proc ::ui::build_acl_pane {} {
    variable w

    # RIGHT PANE: a notebook of Access / Policy / People / Audit
    set w(nb_right) [ttk::notebook $w(paned).nb]
    $w(paned) add $w(nb_right) -weight 2
    set right_frame [ttk::frame $w(nb_right).access]
    set w(tab_access) $right_frame
    $w(nb_right) add $right_frame -text "Access"
    foreach {name title} {policy Policy people People} {
        set w(tab_$name) [ttk::frame $w(nb_right).$name]
        $w(nb_right) add $w(tab_$name) -text $title
        pack [ttk::label $w(tab_$name).todo -text "(built in a later step this wave)" \
            -foreground gray50] -expand yes
    }
    ::ui::build_audit_tab

    # Set initial sash position after window is mapped (gives 35% to left, 65% to right)
    bind $w(paned) <Map> {
        after idle {
            if {[winfo exists .main.paned]} {
                set total_width [winfo width .main.paned]
                if {$total_width > 1} {
                    set left_width [expr {int($total_width * 0.35)}]
                    .main.paned sashpos 0 $left_width
                }
            }
        }
    }

    # Fetch button at top of right pane
    set w(fetch) [ttk::button $right_frame.fetch -text "Fetch ACL" \
        -command on_fetch_button_click -state disabled]
    pack $w(fetch) -anchor w -pady {0 5}

    # ACL path label (shows which item's ACL is displayed)
    pack [ttk::frame $right_frame.path] -fill x -pady {0 5}
    ttk::label $right_frame.path.label -text "Item:"
    pack $right_frame.path.label -side left
    set w(item_entry) [ttk::entry $right_frame.path.entry]
    pack $w(item_entry) -side left -fill x -expand yes -padx {5 0}
    $w(item_entry) configure -state readonly

    # What the policy says about this folder
    set w(governed) [ttk::label $right_frame.governed -text "" -wraplength 640 -justify left]
    pack $w(governed) -fill x -anchor w -pady {0 5}

    # Create treeview frame for ACL display
    pack [ttk::frame $right_frame.tree] -fill both -expand yes

    # Scrollbars
    pack [ttk::scrollbar $right_frame.tree.hscroll -orient horizontal -command "$right_frame.tree.list xview"] -side bottom -fill x
    pack [ttk::scrollbar $right_frame.tree.vscroll -orient vertical -command "$right_frame.tree.list yview"] -side right -fill y

    # Treeview widget (with multi-select enabled)
    set w(acl) [ttk::treeview $right_frame.tree.list -columns {user policy drive inherited link state id} -show {tree headings} -selectmode extended \
        -displaycolumns {user policy drive inherited link state} \
        -yscrollcommand "$right_frame.tree.vscroll set" -xscrollcommand "$right_frame.tree.hscroll set"]
    pack $w(acl) -side left -fill both -expand yes

    # Intended (policy) beside actual (drive), as in the design mockup
    configure_tree_columns $w(acl) {
        #0 "Email" 150 100
        user "User" 110 80
        policy "Policy" 90 60
        drive "Drive" 60 45
        inherited "Inherit" 55 45
        link "Link" 70 45
        state "State" 190 120
    }

    # Configure tags for different permission types
    $w(acl) tag configure owner -background lightgreen
    $w(acl) tag configure write -background lightblue
    $w(acl) tag configure read -background lightyellow
    $w(acl) tag configure inherited -background lightgray
    $w(acl) tag configure missing -foreground red3
    $w(acl) tag configure violation -foreground red3

    # Create context menu for copying email
    set w(context_menu) [menu $w(acl).context_menu -tearoff 0]
    $w(context_menu) add command -label "Copy Email" -command {
        set acl_tree $::ui::w(acl)
        set selection [$acl_tree selection]
        if {[llength $selection] > 0} {
            set item [lindex $selection 0]
            set email [$acl_tree item $item -text]
            clipboard clear
            clipboard append $email
        }
    }

    # Bind right-click to show context menu
    bind $w(acl) <Button-3> {
        set acl_tree %W
        set item [%W identify item %x %y]
        if {$item ne ""} {
            %W selection set $item
            tk_popup %W.context_menu %X %Y
        }
    }

    # Bind treeview selection event to enable/disable Remove button. Bound
    # once here rather than re-bound on every fetch.
    bind $w(acl) <<TreeviewSelect>> {
        set acl_tree $::ui::w(acl)
        set selection [$acl_tree selection]
        if {[llength $selection] > 0} {
            $::ui::w(btn_remove) configure -state normal
        } else {
            $::ui::w(btn_remove) configure -state disabled
        }
    }

    # Action buttons frame at bottom of right pane
    set w(action_frame) [ttk::frame $right_frame.actions]
    pack $w(action_frame) -side bottom -fill x -pady {10 0}

    set w(btn_remove) [ttk::button $right_frame.actions.remove -text "Remove Selected" -command on_remove_selected_click -state disabled]
    set w(btn_invite) [ttk::button $right_frame.actions.invite -text "Invite User" -command on_invite_user_click -state disabled]

    pack $w(btn_remove) -side left -padx 2
    pack $w(btn_invite) -side left -padx 2
}

proc ::ui::build_audit_tab {} {
    variable w
    set t [ttk::frame $w(nb_right).audit]
    set w(tab_audit) $t
    $w(nb_right) add $t -text "Audit"

    # Toolbar: scope, run, cancel, last-run line
    pack [ttk::frame $t.bar] -fill x -pady {6 4} -padx 4
    pack [ttk::label $t.bar.slabel -text "Scope:"] -side left
    set w(audit_scope) [ttk::combobox $t.bar.scope -state readonly -width 28 \
        -values {"Whole policy" "Selected folder and below"}]
    $w(audit_scope) set "Whole policy"
    pack $w(audit_scope) -side left -padx {4 8}
    pack [ttk::button $t.bar.run -text "Run audit" -command ::ui::audit_run] -side left
    set w(audit_cancel) [ttk::button $t.bar.cancel -text "Cancel" -state disabled \
        -command {set ::ui::state(audit_cancel) 1}]
    pack $w(audit_cancel) -side left -padx 4
    set w(audit_last) [ttk::label $t.bar.last -text "No audit in this session." -foreground gray40]
    pack $w(audit_last) -side right

    # Findings view
    set w(audit_findings_frame) [ttk::frame $t.findings]
    pack $w(audit_findings_frame) -fill both -expand yes -padx 4
    pack [ttk::scrollbar $t.findings.vs -orient vertical -command "$t.findings.list yview"] -side right -fill y
    set w(findings) [ttk::treeview $t.findings.list \
        -columns {fix person roles} -show {tree headings} -selectmode browse \
        -yscrollcommand "$t.findings.vs set"]
    pack $w(findings) -fill both -expand yes
    configure_tree_columns $w(findings) {
        #0 "Folder / finding" 340 200
        fix "Fix" 40 30
        person "Person" 230 140
        roles "Expected / actual" 120 80
    }
    $w(findings) column fix -anchor center -stretch 0
    $w(findings) tag configure folder -background gray92
    $w(findings) tag configure info -background {#faf8ee}
    $w(findings) tag configure real -foreground red3
    bind $w(findings) <Button-1> {::ui::finding_toggle %x %y}

    pack [ttk::frame $t.factions] -fill x -pady 6 -padx 4
    set w(audit_summary) [ttk::label $t.factions.summary -text "" -foreground gray30]
    pack $w(audit_summary) -side left
    set w(btn_apply) [ttk::button $t.factions.apply -text "Apply fixes" -state disabled \
        -command ::ui::audit_apply]
    pack $w(btn_apply) -side right -padx 2
    set w(btn_preview) [ttk::button $t.factions.preview -text "Preview fixes (dry run)" -state disabled \
        -command ::ui::audit_preview]
    pack $w(btn_preview) -side right -padx 2

    # Diff (dry-run) view, swapped in over the findings
    set w(audit_diff_frame) [ttk::frame $t.diff]
    pack [ttk::label $t.diff.head -text "Dry run — nothing has changed yet" -font TkHeadingFont] \
        -anchor w -pady {6 2} -padx 2
    pack [ttk::scrollbar $t.diff.vs -orient vertical -command "$t.diff.list yview"] -side right -fill y
    set w(diff) [ttk::treeview $t.diff.list -columns {who detail} -show {tree headings} \
        -yscrollcommand "$t.diff.vs set"]
    configure_tree_columns $w(diff) {
        #0 "Action" 110 80
        who "Who" 240 160
        detail "Detail" 420 200
    }
    pack $w(diff) -fill both -expand yes
    $w(diff) tag configure add -background {#d6f0d6}
    $w(diff) tag configure del -background {#f3dede}
    $w(diff) tag configure chg -background {#d3e6f5}
    $w(diff) tag configure note -background {#faf8ee}
    set w(apply_log) [text $t.diff.log -height 6 -state disabled -wrap word]

    pack [ttk::frame $t.dactions] -fill x -pady 6 -padx 4
    set w(diff_summary) [ttk::label $t.dactions.summary -text "" -foreground gray30]
    pack $w(diff_summary) -side left
    set w(btn_back) [ttk::button $t.dactions.back -text "Back to findings" \
        -command {::ui::audit_show results}]
    set w(btn_apply2) [ttk::button $t.dactions.apply -text "Apply these changes" \
        -command ::ui::audit_apply]

    ::ui::audit_show idle
}

proc ::ui::audit_show {phase} {
    # idle | results | diff: which body the Audit tab shows
    variable w
    variable state
    set state(audit_phase) $phase
    pack forget $w(audit_findings_frame)
    pack forget $w(audit_diff_frame)
    pack forget $w(btn_back)
    pack forget $w(btn_apply2)
    if {$phase eq "diff"} {
        pack $w(audit_diff_frame) -fill both -expand yes -padx 4 \
            -after [winfo parent $w(audit_diff_frame)].bar
        pack $w(btn_apply2) -side right -padx 2 -in [winfo parent $w(btn_back)]
        pack $w(btn_back) -side right -padx 2
    } else {
        pack $w(audit_findings_frame) -fill both -expand yes -padx 4 \
            -after [winfo parent $w(audit_findings_frame)].bar
    }
}

proc ::ui::audit_scope_plans {} {
    # The per-platform plans the chosen scope covers
    variable w
    variable state
    set plans [dict get $state(model) plan]
    if {[$w(audit_scope) get] ne "Selected folder and below"} { return $plans }
    if {![info exists state(sel_provider)]} { return $plans }
    set provider $state(sel_provider)
    set sel_path [$::ui::w(path_entry) get]
    if {$sel_path eq "" || ![dict exists $plans $provider]} { return $plans }
    set sub {}
    dict for {fid fentry} [dict get $plans $provider] {
        set fpath [dict get $fentry path]
        if {$fpath eq $sel_path || [string match "$sel_path/*" $fpath] || \
            [string match "*$sel_path" $fpath]} {
            dict set sub $fid $fentry
        }
    }
    if {[dict size $sub] == 0} { return $plans }
    return [dict create $provider $sub]
}

proc ::ui::audit_run {} {
    # The same walk audit_cli does, pumping the event loop per folder so
    # the window stays live and Cancel can interrupt.
    variable w
    variable state
    if {![info exists state(model)] || $state(model) eq ""} {
        ::ui::status "Open a policy first" red
        return
    }
    set model $state(model)
    set plans [::ui::audit_scope_plans]
    set state(audit_cancel) 0
    $w(audit_cancel) configure -state normal
    set findings {}
    set done 0
    set total 0
    dict for {platform subplan} $plans { incr total [dict size $subplan] }
    set fid_violations {}
    dict for {platform subplan} $plans {
        if {[catch {provider_for $platform} provider]} { continue }
        if {$platform eq "dropbox"} {
            set ctx [::ui::dropbox_ctx]
        } else {
            set result [get_access_token [$w(remote_entry) get] "" "detailed" 1]
            set token [lindex $result 0]
            set ctx [expr {$token eq "" ? "" : [dict create token $token remote [$w(remote_entry) get]]}]
        }
        if {$ctx eq ""} {
            ::ui::status "No $platform connection; skipped" red
            continue
        }
        foreach fid [plan_ids_parents_first $subplan] {
            if {$state(audit_cancel)} { break }
            incr done
            ::ui::status "Auditing $done/$total: [dict get $subplan $fid path]" blue
            update
            lassign [audit_folder $provider $ctx $fid [dict get $subplan $fid]] v _ _
            set v [stamp_platform_person $model $platform $v]
            lappend findings {*}$v
            dict set fid_violations [list $platform $fid] $v
        }
        if {!$state(audit_cancel) && [dict exists $provider sweep] && \
            [$w(audit_scope) get] eq "Whole policy"} {
            lappend findings {*}[stamp_platform_person $model $platform \
                [{*}[dict get $provider sweep] $ctx]]
        }
    }
    $w(audit_cancel) configure -state disabled
    if {$state(audit_cancel)} {
        ::ui::status "Audit cancelled" orange
        return
    }
    set state(findings) $findings
    set state(checks) {}

    # Badges, audit tier
    dict for {pf v} $fid_violations {
        lassign $pf platform fid
        set real 0
        set info 0
        set movedn 0
        foreach viol $v {
            if {[violation_is_informational $viol]} {
                if {[dict get $viol type] eq "moved"} { incr movedn } else { incr info }
            } else {
                incr real
            }
        }
        if {$real > 0} {
            set b "❌ $real"
        } elseif {$movedn > 0} {
            set b "⚠"
        } elseif {$info > 0} {
            set b "ℹ $info"
        } else {
            set b "✓"
        }
        set state(badge,$platform,$fid) $b
    }
    ::ui::badges_refresh
    ::ui::audit_render
    set ts [clock format [clock seconds] -format "%a %d %b %H:%M"]
    set real 0
    set info 0
    foreach v $findings {
        if {[violation_is_informational $v]} { incr info } else { incr real }
    }
    $w(audit_last) configure -text "Last run: $ts — $real violation(s), $info note(s)"
    set state(audit_ts) $ts
    ::ui::audit_persist
    ::ui::tab_counts
    ::ui::status "Audit finished: $real violation(s), $info note(s)" [expr {$real ? "red" : "blue"}]
}

proc ::ui::fixable {v} {
    return [expr {[dict get $v type] in {missing_user wrong_role extra_user leaked_inherited}}]
}

proc ::ui::finding_key {v} {
    return [list [dict get $v platform] [dict get $v id] [dict get $v email] [dict get $v type]]
}

proc ::ui::audit_render {} {
    # Findings grouped by folder; fixable rows carry a checkbox glyph
    variable w
    variable state
    foreach row [$w(findings) children {}] { $w(findings) delete $row }
    set multi [expr {[dict size [dict get $state(model) plan]] > 1}]
    set groups {}
    foreach v $state(findings) {
        set label [dict get $v path]
        if {$multi} { set label "\[[dict get $v platform]\] $label" }
        dict lappend groups $label $v
    }
    set nfix 0
    dict for {label vlist} $groups {
        set parent [$w(findings) insert {} end -text "📁 $label" -tags folder -open 1]
        foreach v $vlist {
            set who [dict get $v email]
            if {[dict get $v person] ne ""} {
                append who " ([identity_display $state(model) [dict get $v person]])"
            }
            set roles ""
            if {[dict get $v expected] ne "" || [dict get $v actual] ne ""} {
                set roles "[dict get $v expected] / [dict get $v actual]"
            }
            set label2 [::ui::finding_label $v]
            set tags [expr {[violation_is_informational $v] ? "info" : "real"}]
            set fix ""
            if {[::ui::fixable $v]} {
                set key [::ui::finding_key $v]
                if {![dict exists $state(checks) $key]} { dict set state(checks) $key 1 }
                set fix [expr {[dict get $state(checks) $key] ? "☑" : "☐"}]
                incr nfix
            }
            $w(findings) insert $parent end -text "   $label2" \
                -values [list $fix $who $roles] -tags $tags
        }
    }
    set sel 0
    dict for {k on} $state(checks) { if {$on} { incr sel } }
    $w(audit_summary) configure -text \
        "$sel fix(es) selected • notes are never changed by enforcement"
    $w(btn_preview) configure -state [expr {$nfix ? "normal" : "disabled"}]
    $w(btn_apply) configure -state disabled
    ::ui::audit_show results
}

proc ::ui::finding_label {v} {
    switch [dict get $v type] {
        missing_user { return "❌ MISSING — expected [dict get $v expected]" }
        wrong_role { return "❌ WRONG ROLE — direct permission exceeds entitlement" }
        extra_user { return "❌ EXTRA — closed collection" }
        leaked_inherited { return "❌ LEAKED — inherited beyond entitlement" }
        open_extra { return "ℹ extra, tolerated" }
        open_inherited { return "ℹ inherited extra, tolerated" }
        moved { return "⚠ MOVED — [dict get $v detail]" }
        shared_link { return "❌ LINK — [dict get $v detail]" }
        open_link { return "ℹ link — [dict get $v detail]" }
        phantom_share { return "ℹ [dict get $v detail]" }
        default { return "❌ [string toupper [dict get $v type]] — [dict get $v detail]" }
    }
}

proc ::ui::finding_toggle {x y} {
    # Click on a finding row toggles its Fix mark; on a folder row, all its
    # children together
    variable w
    variable state
    set row [$w(findings) identify item $x $y]
    if {$row eq ""} { return }
    set findings_by_key {}
    foreach v $state(findings) {
        if {[::ui::fixable $v]} { dict set findings_by_key [::ui::finding_key $v] $v }
    }
    set keys {}
    if {"folder" in [$w(findings) item $row -tags]} {
        foreach child [$w(findings) children $row] {
            set k [::ui::row_key $child]
            if {$k ne ""} { lappend keys $k }
        }
    } else {
        set k [::ui::row_key $row]
        if {$k ne ""} { lappend keys $k }
    }
    if {[llength $keys] == 0} { return }
    foreach k $keys {
        dict set state(checks) $k [expr {![dict get $state(checks) $k]}]
    }
    ::ui::audit_render
}

proc ::ui::row_key {row} {
    # Recover the finding behind a rendered row by position
    variable w
    variable state
    set parent [$w(findings) parent $row]
    if {$parent eq ""} { return "" }
    set label [$w(findings) item $parent -text]
    set idx [lsearch -exact [$w(findings) children $parent] $row]
    set multi [expr {[dict size [dict get $state(model) plan]] > 1}]
    set i -1
    foreach v $state(findings) {
        set l [dict get $v path]
        if {$multi} { set l "\[[dict get $v platform]\] $l" }
        if {"📁 $l" ne $label} { continue }
        incr i
        if {$i == $idx} {
            if {[::ui::fixable $v]} { return [::ui::finding_key $v] }
            return ""
        }
    }
    return ""
}

proc ::ui::checked_by_folder {} {
    # platform,fid -> list of {email type} pairs, from the ticked findings
    variable state
    set by {}
    dict for {key on} $state(checks) {
        if {!$on} { continue }
        lassign $key platform fid email type
        dict lappend by [list $platform $fid] [list $email $type]
    }
    return $by
}

proc ::ui::audit_preview {} {
    # A fresh single-folder audit per ticked folder feeds enforce_actions;
    # the diff shows exactly what Apply would do, plus the cascade re-checks
    variable w
    variable state
    set by [::ui::checked_by_folder]
    if {[dict size $by] == 0} {
        ::ui::status "Nothing ticked" orange
        return
    }
    foreach row [$w(diff) children {}] { $w(diff) delete $row }
    set model $state(model)
    set n 0
    set folders 0
    set state(diff_plan) {}
    dict for {pf only} $by {
        lassign $pf platform fid
        if {![dict exists $model plan $platform $fid]} { continue }
        set fentry [dict get $model plan $platform $fid]
        incr folders
        set violations {}
        foreach v $state(findings) {
            if {[dict get $v platform] eq $platform && [dict get $v id] eq $fid} {
                lappend violations $v
            }
        }
        foreach a [enforce_actions $fid $fentry $violations $only] {
            set verb [dict get $a verb]
            set tag [dict create invite add reinvite chg remove del sever del]
            set detail ""
            switch $verb {
                invite { set detail "[dict get $a role] on [dict get $a path] (quiet, no notification)" }
                reinvite { set detail "→ [dict get $a role] on [dict get $a path] — remove and re-invite" }
                remove { set detail "on [dict get $a path] — direct permission" }
                sever { set detail "inherited on [dict get $a path] — needs severing at the source" }
            }
            $w(diff) insert {} end -text $verb \
                -values [list [dict get $a email] $detail] -tags [dict get $tag $verb]
            incr n
        }
        dict set state(diff_plan) $pf $only
        # Cascade: descendants of this folder get re-checked after a change
        set fpath [dict get $fentry path]
        set kids 0
        dict for {ofid ofentry} [dict get $model plan $platform] {
            if {$ofid eq $fid} { continue }
            if {[string match "$fpath/*" [dict get $ofentry path]]} { incr kids }
        }
        if {$kids > 0} {
            $w(diff) insert {} end -text "re-check" \
                -values [list "descendants of $fpath" "$kids policy folder(s), for leaked copies after the change"] \
                -tags note
        }
    }
    $w(diff_summary) configure -text \
        "$n planned change(s) on $folders folder(s) • owner permissions are never touched"
    ::ui::audit_show diff
}

proc ::ui::audit_apply {} {
    # The ticked fixes, for real: per-folder enforcement with the same
    # engine the CLI uses, then the cascade repair pass, then a re-audit.
    variable w
    variable state
    set by $state(diff_plan)
    if {![info exists state(diff_plan)] || [dict size $by] == 0} {
        ::ui::status "Preview first" orange
        return
    }
    set total 0
    dict for {pf only} $by { incr total [llength $only] }
    set response [tk_messageBox -type yesno -icon warning -title "Apply fixes" \
        -message "Apply $total fix(es) to [dict size $by] folder(s)?\n\nRemovals cannot be undone."]
    if {$response ne "yes"} { return }

    # Write-capable connections per platform
    set model $state(model)
    set ctxs {}
    set providers {}
    dict for {pf only} $by {
        lassign $pf platform fid
        if {[dict exists $ctxs $platform]} { continue }
        set provider [provider_for $platform]
        if {![dict exists $provider invite]} {
            ::ui::status "$platform provider audits only; cannot apply" red
            return
        }
        if {$platform eq "onedrive"} {
            if {![ensure_edit_capability]} { return }
            set ctx [od_connect [$w(remote_entry) get] write]
        } else {
            set ctx [dbx_connect [platform_remote $platform ""] write]
        }
        if {$ctx eq ""} {
            ::ui::status "No $platform write connection" red
            return
        }
        dict set providers $platform $provider
        dict set ctxs $platform $ctx
    }

    # Stream enforcement output into the log pane under the diff
    pack $w(apply_log) -fill x -pady {4 0}
    $w(apply_log) configure -state normal
    $w(apply_log) delete 1.0 end
    $w(apply_log) configure -state disabled
    set ::enforce_log_cmd ::ui::apply_log_line
    set changed {}
    dict for {pf only} $by {
        lassign $pf platform fid
        set fentry [dict get $model plan $platform $fid]
        ::ui::apply_log_line "📁 [dict get $fentry path]"
        update
        lassign [enforce_folder [dict get $providers $platform] [dict get $ctxs $platform] \
            $fid $fentry 0 $only] status was_changed _ _
        if {$was_changed} { lappend changed [list $platform [dict get $fentry path]] }
        set state(badge,$platform,$fid) ""
        update
    }
    # Cascade repair pass, exactly the CLI's rule
    set repair {}
    dict for {platform subplan} [dict get $model plan] {
        if {![dict exists $providers $platform]} { continue }
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
    foreach pf $repair {
        lassign $pf platform fid
        set fentry [dict get $model plan $platform $fid]
        ::ui::apply_log_line "🔁 re-checking [dict get $fentry path]"
        update
        enforce_folder [dict get $providers $platform] [dict get $ctxs $platform] $fid $fentry 0
        set state(badge,$platform,$fid) ""
        update
    }
    set ::enforce_log_cmd ""
    ::ui::apply_log_line "Done. Re-auditing…"
    update
    set state(diff_plan) {}
    ::ui::audit_run
    pack forget $w(apply_log)
}

proc ::ui::apply_log_line {msg} {
    variable w
    $w(apply_log) configure -state normal
    $w(apply_log) insert end "$msg\n"
    $w(apply_log) see end
    $w(apply_log) configure -state disabled
}

proc ::ui::tab_counts {} {
    # Violation and identity counts on the tab labels
    variable w
    variable state
    set real 0
    if {[info exists state(findings)]} {
        foreach v $state(findings) {
            if {![violation_is_informational $v]} { incr real }
        }
    }
    set label "Audit"
    if {$real > 0} { append label " ❌ $real" }
    $w(nb_right) tab $w(tab_audit) -text $label
}

proc ::ui::audit_cache_file {} {
    variable state
    set hash [format %08x [zlib crc32 [encoding convertto utf-8 $state(policy_path)]]]
    return [file join $::env(HOME) .cache acl-manager audit-$hash.tcl]
}

proc ::ui::audit_persist {} {
    # Badges and the last-run stamp survive the session
    variable state
    catch {
        file mkdir [file dirname [::ui::audit_cache_file]]
        set f [open [::ui::audit_cache_file] w]
        fconfigure $f -encoding utf-8
        set badges {}
        foreach name [array names state badge,*] {
            dict set badges $name $state($name)
        }
        puts $f [list $state(audit_ts) $badges]
        close $f
    }
}

proc ::ui::audit_restore {} {
    # A previous run's badges, so a fresh session opens informed
    variable w
    variable state
    catch {
        set f [open [::ui::audit_cache_file] r]
        fconfigure $f -encoding utf-8
        lassign [read $f] ts badges
        close $f
        dict for {name b} $badges { set state($name) $b }
        if {$ts ne ""} {
            $w(audit_last) configure -text "Last run: $ts (earlier session)"
        }
        ::ui::badges_refresh
    }
}

proc ::ui::build_status {} {
    variable w

    # BOTTOM: Status Label
    set w(status) [ttk::label $w(root_frame).status -text "Ready" -foreground blue]
    pack $w(status) -fill x -pady {5 5}

    # Fix Treeview row height to match font (prevents text clipping on Linux HiDPI)
    set font_name [ttk::style lookup Treeview -font]
    if {$font_name eq ""} { set font_name TkDefaultFont }
    set h [expr {[font metrics $font_name -linespace] + 6}]  ;# a bit of padding
    ttk::style configure Treeview -rowheight $h
}

# Consolidated status reporter: logs to console (as ::ui::status used
# to) and, once the status widget exists, mirrors the message into it.
proc ::ui::status {message {color blue}} {
    variable w
    puts "STATUS ($color): $message"  ;# Still log to console for debugging
    if {[info exists w(status)] && [winfo exists $w(status)]} {
        $w(status) configure -text $message -foreground $color
    }
}

# ============================================================================
# Utility Functions
# ============================================================================

proc debug_log {message} {
    # Debug logging function
    # WARNING: Avoid logging user-provided strings (folder names, file names, etc.)
    # as they may contain unicode characters that crash console output on Windows
    global debug_mode
    if {$debug_mode} {
        puts "DEBUG: $message"
        
        # Also write to debug.log file
        if {[catch {
            set fh [open "debug.log" a]
            puts $fh "DEBUG: $message"
            close $fh
        }]} {
            # Silently ignore file write errors
        }
    }
}

proc is_ignored {item_name} {
    global ignore_patterns
    foreach pattern $ignore_patterns {
        if {[string match $pattern $item_name]} {
            return 1
        }
    }
    return 0
}

# ============================================================================
# Treeview Browser Functions
# ============================================================================

proc load_tree_children {tree parent_item} {
    # Lazy loading; a node's hidden values are {item_id type loaded provider}
    set values [$tree item $parent_item -values]
    lassign $values folder_id type loaded provider
    if {$loaded} {
        debug_log "Folder already loaded, skipping"
        return
    }
    debug_log "Loading tree children: provider=$provider id=$folder_id"

    switch -- $provider {
        onedrive { set entries [children_onedrive $folder_id] }
        dropbox  { set entries [children_dropbox $folder_id] }
        default  { return }
    }
    if {$entries eq "ERROR"} { return }

    foreach child [$tree children $parent_item] {
        $tree delete $child
    }

    set folders {}
    set files {}
    foreach e $entries {
        if {[is_ignored [dict get $e name]]} { continue }
        if {[dict get $e is_folder]} {
            lappend folders $e
        } else {
            lappend files $e
        }
    }
    foreach e $folders {
        set folder_item [$tree insert $parent_item end \
            -text [dict get $e name] \
            -values [list [dict get $e id] "folder" 0 $provider \
                [::ui::badge_for $provider [dict get $e id]]]]
        $tree insert $folder_item end -text ""
    }
    foreach e $files {
        $tree insert $parent_item end \
            -text [dict get $e name] \
            -values [list [dict get $e id] "file" 1 $provider ""]
    }
    set badge [lindex $values 4]
    $tree item $parent_item -values [list $folder_id $type 1 $provider $badge]
    debug_log "Tree children loaded: [llength $folders] folders, [llength $files] files"
}

proc children_onedrive {folder_id} {
    # Children of a OneDrive folder as {name id is_folder} dicts, or ERROR
    set result [get_access_token [$::ui::w(remote_entry) get] "" "detailed" 1]
    set access_token [lindex $result 0]
    if {$access_token eq ""} {
        debug_log "No access token available"
        return ERROR
    }
    set headers [list Authorization "Bearer $access_token"]
    if {$folder_id eq "root"} {
        set children_url [build_graph_api_url "/me/drive/root/children"]
    } else {
        set children_url [build_graph_api_url "/me/drive/items/$folder_id/children"]
    }
    lassign [make_http_request $children_url $headers] status data
    if {$status ne "200"} {
        debug_log "Error loading tree children: status $status"
        return ERROR
    }
    set entries {}
    foreach child [dict get [json::json2dict $data] value] {
        lappend entries [dict create \
            name [dict get $child name] \
            id [dict get $child id] \
            is_folder [dict exists $child folder]]
    }
    return $entries
}

proc children_dropbox {folder_id} {
    # Children of a Dropbox folder ("" is the root) as {name id is_folder}
    set ctx [::ui::dropbox_ctx]
    if {$ctx eq ""} { return ERROR }
    if {[catch {dbx_call [dict get $ctx token] /2/files/list_folder \
            [::json::write::object path [::json::write::string $folder_id] limit 500]} resp]} {
        debug_log "Dropbox list_folder failed: $resp"
        ::ui::status "Dropbox listing failed" red
        return ERROR
    }
    set entries {}
    while {1} {
        foreach e [dict get $resp entries] {
            lappend entries [dict create \
                name [dict get $e name] \
                id [dict get $e id] \
                is_folder [expr {[dict get $e .tag] eq "folder"}]]
        }
        if {[dict exists $resp has_more] && [dict get $resp has_more]} {
            if {[catch {dbx_call [dict get $ctx token] /2/files/list_folder/continue \
                    [::json::write::object cursor [::json::write::string [dict get $resp cursor]]]} resp]} {
                break
            }
        } else break
    }
    return $entries
}

proc ::ui::dropbox_ctx {} {
    # One Dropbox connection per session, made on first use
    variable state
    if {[info exists state(dbx_ctx)] && $state(dbx_ctx) ne ""} {
        return $state(dbx_ctx)
    }
    set remote [platform_remote dropbox ""]
    foreach conn $state(connections) {
        if {[dict get $conn platform] eq "dropbox"} {
            set remote [dict get $conn remote]
            break
        }
    }
    set state(dbx_ctx) [dbx_connect $remote read]
    return $state(dbx_ctx)
}

proc gui_clear_acl_display {} {
    set acl_tree $::ui::w(acl)
    foreach item [$acl_tree children {}] {
        $acl_tree delete $item
    }

    $::ui::w(item_entry) configure -state normal
    $::ui::w(item_entry) delete 0 end
    $::ui::w(item_entry) insert 0 "(No ACL loaded - click Fetch ACL)"
    $::ui::w(item_entry) configure -state readonly

    $::ui::w(btn_remove) configure -state disabled
    $::ui::w(btn_invite) configure -state disabled

    debug_log "ACL display cleared"
}

proc build_tree_path {tree item} {
    # Build hierarchical path from root to the given tree item
    set path_parts {}
    set current $item

    while {$current ne ""} {
        set parent [$tree parent $current]
        # Skip the root item (the one with no parent)
        if {$parent ne ""} {
            set text [$tree item $current -text]
            # Add to front of path
            set path_parts [linsert $path_parts 0 $text]
        }
        # Move to parent
        set current $parent
    }

    # Join with / separator, or return empty string if at root
    if {[llength $path_parts] == 0} {
        return ""
    }
    return [join $path_parts "/"]
}

proc on_tree_select {tree} {
    global selected_item

    set selection [$tree selection]
    if {[llength $selection] == 0} {
        return
    }

    set item [lindex $selection 0]
    set values [$tree item $item -values]

    set item_id [lindex $values 0]
    set type [lindex $values 1]
    set provider [lindex $values 3]
    if {$provider eq ""} { set provider onedrive }
    set is_folder [expr {$type eq "folder"}]
    set ::ui::state(sel_provider) $provider

    # Check if selection actually changed
    set selection_changed 0
    if {[llength $selected_item] == 0 || ![dict exists $selected_item id]} {
        set selection_changed 1
    } elseif {[dict get $selected_item id] ne $item_id} {
        set selection_changed 1
    }

    # Update selected item (simplified structure)
    set selected_item [dict create \
        id $item_id \
        is_folder $is_folder \
        provider $provider]

    debug_log "Item selected: ID=$item_id, is_folder=$is_folder, selection_changed=$selection_changed"

    # Only update UI if selection actually changed
    if {$selection_changed} {
        # Update URL bar
        if {$provider eq "dropbox"} {
            set url "https://www.dropbox.com/home"
        } else {
            set url "https://onedrive.live.com/?id=$item_id"
        }
        $::ui::w(url_entry) configure -state normal
        $::ui::w(url_entry) delete 0 end
        $::ui::w(url_entry) insert 0 $url
        $::ui::w(url_entry) configure -state readonly

        # Update Path bar with hierarchical path
        set path_widget $::ui::w(path_entry)
        set hierarchical_path [build_tree_path $tree $item]
        $path_widget configure -state normal
        $path_widget delete 0 end
        $path_widget insert 0 $hierarchical_path
        $path_widget configure -state readonly

        # Clear ACL display (user must click Fetch to see ACL)
        gui_clear_acl_display

        # Enable fetch button (user can now fetch ACL for this item)
        $::ui::w(fetch) configure -state normal
    }
}

proc on_tree_expand {tree item} {
    # Handle expansion of a folder in the treeview (lazy load children)
    set values [$tree item $item -values]
    set item_id [lindex $values 0]
    set type [lindex $values 1]
    set loaded [lindex $values 2]

    debug_log "Tree item expanded: ID=$item_id, type=$type, loaded=$loaded"

    # Only load if folder and not yet loaded
    if {$type eq "folder" && !$loaded} {
        load_tree_children $tree $item
    }
}

proc on_fetch_button_click {} {
    # Fetch ACL for the currently selected item
    global selected_item
    
    if {[llength $selected_item] == 0} {
        ::ui::status "No item selected" red
        return
    }
    
    if {![dict exists $selected_item id]} {
        ::ui::status "Error: Invalid item selection" red
        return
    }
    
    set item_id [dict get $selected_item id]
    if {[dict exists $selected_item provider] && [dict get $selected_item provider] eq "dropbox"} {
        gui_fetch_acl_dropbox $item_id
        return
    }
    set remote_name [$::ui::w(remote_entry) get]

    # Fetch ACL using ID directly (no lookup needed)
    gui_fetch_acl $item_id $remote_name
}

proc format_file_size {bytes} {
    # Convert bytes to human-readable size string
    if {$bytes eq "" || ![string is integer -strict $bytes]} {
        return "N/A"
    }
    if {$bytes < 1024} {
        return "${bytes} B"
    } elseif {$bytes < 1048576} {
        return [format "%.1f KB" [expr {$bytes / 1024.0}]]
    } elseif {$bytes < 1073741824} {
        return [format "%.1f MB" [expr {$bytes / 1048576.0}]]
    } else {
        return [format "%.2f GB" [expr {$bytes / 1073741824.0}]]
    }
}







# ============================================================================
# Core Functions
# ============================================================================

# Shared update_status - logs to console for both modes
# GUI code should use update_status, CLI code should use puts directly
proc update_status {message {color blue}} {
    # Always log to console for debugging
    puts "STATUS ($color): $message"
}

# ============================================================================
# Recursive ACL Display Functions
# ============================================================================


proc compare_permission_sets {child_users_dict parent_users_dict} {
    # Compare two permission sets to determine inheritance type
    # Returns: "inherited", "restricted", "extended", or "different"
    
    set child_emails [dict keys $child_users_dict]
    set parent_emails [dict keys $parent_users_dict]
    
    # If both empty, consider it inherited
    if {[llength $child_emails] == 0 && [llength $parent_emails] == 0} {
        return "inherited"
    }
    
    # If child is empty but parent has users, it's restricted
    if {[llength $child_emails] == 0 && [llength $parent_emails] > 0} {
        return "restricted"
    }
    
    # Count overlaps
    set only_in_child 0
    set only_in_parent 0
    set in_both 0
    
    foreach email $child_emails {
        if {[dict exists $parent_users_dict $email]} {
            incr in_both
        } else {
            incr only_in_child
        }
    }
    
    foreach email $parent_emails {
        if {![dict exists $child_users_dict $email]} {
            incr only_in_parent
        }
    }
    
    # Determine type based on overlap
    if {$only_in_child == 0 && $only_in_parent == 0} {
        # Same users - inherited
        return "inherited"
    } elseif {$only_in_child == 0 && $only_in_parent > 0} {
        # Subset of parent - restricted
        return "restricted"
    } elseif {$only_in_child > 0 && $only_in_parent == 0} {
        # Superset of parent - extended
        return "extended"
    } else {
        # Different sets - different
        return "different"
    }
}

proc build_user_folder_map {all_folders root_users_dict} {
    # Build a map of users to folders they have access to
    # Excludes root folder users unless they appear in subfolders with different permissions
    # Returns: dict with keys=email, values=list of {folder_path role inheritance_type}
    
    set user_map {}
    
    foreach folder $all_folders {
        set folder_path [dict get $folder path]
        set folder_perms [dict get $folder permissions]
        set parent_id [dict get $folder parent_id]
        set is_root [dict get $folder is_root]
        
        # Skip root folder for this analysis
        if {$is_root} {
            continue
        }
        
        set folder_users [extract_users_from_permissions $folder_perms]
        
        foreach {email role} $folder_users {
            # Check if user is in root
            set in_root [dict exists $root_users_dict $email]
            
            if {!$in_root} {
                # User not in root - add to map
                if {![dict exists $user_map $email]} {
                    dict set user_map $email {}
                }
                set folder_list [dict get $user_map $email]
                lappend folder_list [list $folder_path $role "additional"]
                dict set user_map $email $folder_list
            }
        }
    }
    
    return $user_map
}

proc detect_special_folders {all_folders root_users_dict} {
    # Detect folders with non-inherited permissions
    # Returns: list of folder info dicts with inheritance_type
    
    set special_folders {}
    
    foreach folder $all_folders {
        set is_root [dict get $folder is_root]
        
        # Skip root folder
        if {$is_root} {
            continue
        }
        
        set folder_path [dict get $folder path]
        set folder_perms [dict get $folder permissions]
        set folder_users [extract_users_from_permissions $folder_perms]
        
        # Compare with root permissions
        set inheritance_type [compare_permission_sets $folder_users $root_users_dict]
        
        # Only include if not inherited
        if {$inheritance_type ne "inherited"} {
            lappend special_folders [list \
                path $folder_path \
                permissions $folder_perms \
                users_dict $folder_users \
                inheritance_type $inheritance_type]
        }
    }
    
    return $special_folders
}

proc print_item_metadata {item_dict} {
    # Print formatted metadata block for an item
    if {[llength $item_dict] == 0} {
        return
    }
    set meta [extract_item_metadata $item_dict]
    puts "📋 Item Info:"
    puts [format "   %-17s %s" "Name:" [dict get $meta name]]
    puts [format "   %-17s %s" "Type:" [dict get $meta type]]
    puts [format "   %-17s %s" "Created by:" [dict get $meta created_by]]
    puts [format "   %-17s %s" "Created:" [dict get $meta created_date]]
    puts [format "   %-17s %s" "Modified by:" [dict get $meta modified_by]]
    puts [format "   %-17s %s" "Modified:" [dict get $meta modified_date]]
    puts [format "   %-17s %s" "Size:" [dict get $meta size]]
    if {[dict get $meta caption] ne ""} {
        puts [format "   %-17s %s" "Caption:" [dict get $meta caption]]
    }
    puts ""
}

proc print_recursive_acl {root_path root_permissions all_folders max_depth {item_dict {}}} {
    # Print ACL information in a user-centric recursive format
    # Shows: 1) Root permissions, 2) Additional users in subfolders, 3) Special folders

    set root_users_dict [extract_users_from_permissions $root_permissions]
    set root_emails [lsort [dict keys $root_users_dict]]

    # Count unique users and folders
    set all_users_dict $root_users_dict
    set subfolder_count 0
    foreach folder $all_folders {
        set is_root [dict get $folder is_root]
        if {!$is_root} {
            incr subfolder_count
            set folder_perms [dict get $folder permissions]
            set folder_users [extract_users_from_permissions $folder_perms]
            foreach {email role} $folder_users {
                if {![dict exists $all_users_dict $email]} {
                    dict set all_users_dict $email $role
                }
            }
        }
    }
    set total_users [dict size $all_users_dict]

    # Display header
    if {$max_depth == 0} {
        puts "\n[string repeat "=" 80]"
        puts "=== ACL for \"$root_path\" ==="
        puts "[string repeat "=" 80]\n"
    } else {
        puts "\n[string repeat "=" 80]"
        puts "=== ACL for \"$root_path\" (recursive scan, max depth: $max_depth) ==="
        puts "[string repeat "=" 80]\n"
    }

    # Show item metadata if available
    print_item_metadata $item_dict

    # Section 1: Root Folder Permissions
    puts "📊 Root Folder Permissions:"
    if {[llength $root_emails] == 0} {
        puts "   (No non-owner permissions found)\n"
    } else {
        foreach email $root_emails {
            set role [dict get $root_users_dict $email]
            puts [format "   • %-50s (%s)" $email $role]
        }
        puts ""
    }
    
    # Section 2: Additional Users in Subfolders (only if recursive)
    if {$max_depth > 0} {
        set user_folder_map [build_user_folder_map $all_folders $root_users_dict]
        set additional_users [lsort [dict keys $user_folder_map]]
        
        if {[llength $additional_users] > 0} {
            puts "📋 Additional Users in Subfolders:"
            foreach email $additional_users {
                puts "   $email"
                set folder_list [dict get $user_folder_map $email]
                foreach folder_info $folder_list {
                    lassign $folder_info folder_path role inheritance
                    puts [format "      └─ %s (%s)" $folder_path $role]
                }
                puts ""
            }
        }
        
        # Section 3: Special Folders (Non-Inherited Permissions)
        set special_folders [detect_special_folders $all_folders $root_users_dict]
        
        if {[llength $special_folders] > 0} {
            puts "⚠️  Special Folders (Non-Inherited Permissions):"
            foreach folder $special_folders {
                set folder_path [dict get $folder path]
                set folder_users_dict [dict get $folder users_dict]
                set inheritance_type [dict get $folder inheritance_type]
                
                # Display inheritance type
                set type_label "CUSTOM"
                if {$inheritance_type eq "restricted"} {
                    set type_label "RESTRICTED"
                } elseif {$inheritance_type eq "extended"} {
                    set type_label "EXTENDED"
                } elseif {$inheritance_type eq "different"} {
                    set type_label "DIFFERENT"
                }
                
                puts "   📁 $folder_path ($type_label)"
                
                # List users with access
                set folder_emails [lsort [dict keys $folder_users_dict]]
                if {[llength $folder_emails] > 0} {
                    foreach email $folder_emails {
                        set role [dict get $folder_users_dict $email]
                        puts [format "      • %-46s (%s)" $email $role]
                    }
                } else {
                    puts "      (No users with direct permissions)"
                }
                
                # Show who lost access (for restricted folders)
                if {$inheritance_type eq "restricted"} {
                    set lost_access {}
                    foreach {email role} $root_users_dict {
                        if {![dict exists $folder_users_dict $email]} {
                            lappend lost_access $email
                        }
                    }
                    if {[llength $lost_access] > 0} {
                        puts "      ⚠️  Access removed: [join $lost_access ", "]"
                    }
                }
                puts ""
            }
        }
    }
    
    # Summary
    if {$max_depth == 0} {
        puts "[string repeat "-" 80]"
        puts "Summary: $total_users user(s) with access"
        puts "[string repeat "-" 80]\n"
    } else {
        puts "[string repeat "-" 80]"
        puts "Summary: $total_users unique user(s) across 1 root folder + $subfolder_count subfolder(s)"
        puts "[string repeat "-" 80]\n"
    }
}

proc print_csv_acl {root_path root_permissions all_folders max_depth} {
    # Print ACL in CSV format for machine parsing

    if {$max_depth == 0} {
        # Non-recursive: email,role
        puts "email,role"
        set root_users_dict [extract_users_from_permissions $root_permissions]
        foreach email [lsort [dict keys $root_users_dict]] {
            set role [dict get $root_users_dict $email]
            puts "$email,$role"
        }
    } else {
        # Recursive: path,email,role
        puts "path,email,role"
        foreach folder $all_folders {
            set folder_path [dict get $folder path]
            set folder_perms [dict get $folder permissions]
            set folder_users [extract_users_from_permissions $folder_perms]
            foreach email [lsort [dict keys $folder_users]] {
                set role [dict get $folder_users $email]
                # Quote path if it contains commas
                if {[string match *,* $folder_path]} {
                    puts "\"$folder_path\",$email,$role"
                } else {
                    puts "$folder_path,$email,$role"
                }
            }
        }
    }
}























proc oauth_modal_start_browser_auth {modal_window browser_btn reload_btn} {
    # Start browser authentication when user clicks the button
    debug_log "oauth_modal_start_browser_auth called with args: modal=$modal_window, browser_btn=$browser_btn, reload_btn=$reload_btn"
    
    global oauth oauth_modal_result
    if {[info exists oauth_modal_result]} {
        debug_log "oauth_modal_result exists, current value: $oauth_modal_result"
    } else {
        debug_log "oauth_modal_result DOES NOT EXIST"
    }
    
    if {[catch {
        set oauth_modal_result 0
        debug_log "Successfully set oauth_modal_result to 0"
    } err]} {
        debug_log "ERROR setting oauth_modal_result: $err"
        debug_log "Error info: $::errorInfo"
    }
    
    set status_widget $modal_window.main.status
    
    # Disable browser button (can't start twice)
    $browser_btn configure -state disabled
    $status_widget configure -text "Starting OAuth server..." -foreground blue
    update
    
    # Start local server
    if {[oauth_start_local_server] eq ""} {
        $status_widget configure -text "Failed to start OAuth server" -foreground red
        $browser_btn configure -state normal
        return
    }
    
    # Build auth URL
    set auth_url [oauth_build_auth_url]
    
    $status_widget configure -text "Opening browser for authentication..." -foreground blue
    update
    
    # Open browser (platform-specific)
    if {[catch {
        if {$::tcl_platform(platform) eq "windows"} {
            exec cmd /c start $auth_url &
        } elseif {$::tcl_platform(os) eq "Darwin"} {
            exec open $auth_url &
        } else {
            exec xdg-open $auth_url &
        }
    } error]} {
        $status_widget configure -text "Error opening browser: $error" -foreground red
        cleanup_oauth_server
        $browser_btn configure -state normal
        return
    }
    
    $status_widget configure -text "Waiting for authentication in browser..." -foreground blue
    update
    
    # Start non-blocking completion checker
    set start_time [clock milliseconds]
    after 100 [list oauth_modal_check_completion $modal_window $start_time]
}

proc oauth_modal_check_completion {modal_window start_time} {
    # Non-blocking periodic check of OAuth completion status
    # Called via 'after' to avoid blocking the event loop
    global oauth oauth_modal_result
    
    # Check if window still exists (user might have closed it)
    if {![winfo exists $modal_window]} {
        debug_log "Modal window destroyed during OAuth wait"
        cleanup_oauth_server
        set oauth(auth_code) "CANCELLED"
        return
    }
    
    set status_widget $modal_window.main.status
    
    # Check OAuth status
    if {$oauth(auth_code) ne ""} {
        if {$oauth(auth_code) eq "CANCELLED"} {
            # User cancelled
            debug_log "OAuth flow cancelled"
            cleanup_oauth_server
            set oauth_modal_result 0
            destroy $modal_window
            return
        } else {
            # Got auth code - proceed to token exchange
            $status_widget configure -text "Exchanging authorization code for token..." -foreground blue
            update
            
            if {[catch {
                set token_dict [oauth_exchange_token $oauth(auth_code)]
                save_token_json $token_dict
                set oauth(auth_code) ""
                
                # Update token capability
                global token_capability
                set token_result [get_access_token [$::ui::w(remote_entry) get] "" "detailed" 1]
                set token_capability [lindex $token_result 1]
                # Ignore expires_at (3rd element) here
                
                # Success - close dialog immediately (no confirmation needed)
                set oauth_modal_result 1
                # Disable WM_DELETE_WINDOW before destroying to avoid triggering CANCELLED
                wm protocol $modal_window WM_DELETE_WINDOW {}
                destroy $modal_window
            } error]} {
                $status_widget configure -text "Token exchange failed: $error" -foreground red
                set oauth(auth_code) ""
                cleanup_oauth_server
                after 2500 [list destroy $modal_window]
                set oauth_modal_result 0
            }
            return
        }
    }
    
    # Check timeout (120 seconds)
    set elapsed [expr {[clock milliseconds] - $start_time}]
    if {$elapsed > 120000} {
        $status_widget configure -text "Authentication timeout - please try again or reload token file" -foreground red
        cleanup_oauth_server
        # Don't close on timeout - let user try reload or close manually
        return
    }
    
    # Update status with elapsed time
    set seconds [expr {$elapsed / 1000}]
    $status_widget configure -text "Waiting for browser authentication... ($seconds/120 seconds)" -foreground blue
    
    # Schedule next check
    after 100 [list oauth_modal_check_completion $modal_window $start_time]
}

proc oauth_modal_reload_token {modal_window reload_btn} {
    # Handle token reload from file with validation
    debug_log "oauth_modal_reload_token called with args: modal=$modal_window, reload_btn=$reload_btn"
    
    global oauth token_capability oauth_modal_result
    if {[info exists oauth_modal_result]} {
        debug_log "oauth_modal_result exists, current value: $oauth_modal_result"
    } else {
        debug_log "oauth_modal_result DOES NOT EXIST"
    }
    
    if {[catch {
        set oauth_modal_result 0
        debug_log "Successfully set oauth_modal_result to 0"
    } err]} {
        debug_log "ERROR setting oauth_modal_result: $err"
        debug_log "Error info: $::errorInfo"
    }
    
    set status_widget $modal_window.main.status
    
    # Disable button during check
    $reload_btn configure -state disabled
    $status_widget configure -text "Checking token.json file..." -foreground blue
    update
    
    # Check for race condition - auth already completing
    if {[info exists oauth(auth_code)] && $oauth(auth_code) ne "" && $oauth(auth_code) ne "CANCELLED"} {
        $status_widget configure -text "Browser authentication already completing..." -foreground orange
        $reload_btn configure -state normal
        return
    }
    
    # Try to load token
    set token_file [get_token_file_path]
    if {![file exists $token_file]} {
        $status_widget configure -text "Error: token.json file not found at $token_file" -foreground red
        $reload_btn configure -state normal
        return
    }
    
    # Load and validate token
    if {[catch {
        set token_result [get_access_token [$::ui::w(remote_entry) get] "" "detailed" 1]
        set access_token [lindex $token_result 0]
        set capability [lindex $token_result 1]
        # expires_at is 3rd element but not needed here
        
        if {$access_token eq ""} {
            error "Invalid or expired token"
        }
        
        if {$capability ne "full"} {
            error "Token has insufficient permissions (scope: $capability)\n\nToken must have Files.ReadWrite.All and Sites.Manage.All scopes"
        }
        
        # Success - valid token with full capability
        set token_capability $capability
        
        # Cleanup OAuth server and signal success
        cleanup_oauth_server
        set oauth(auth_code) "CANCELLED"  ;# Stop any pending OAuth wait
        
        # Close dialog immediately (no confirmation needed)
        set oauth_modal_result 1
        # Disable WM_DELETE_WINDOW before destroying to avoid triggering CANCELLED
        wm protocol $modal_window WM_DELETE_WINDOW {}
        destroy $modal_window
        
    } error]} {
        # Failed to load valid token
        $status_widget configure -text "Error: $error" -foreground red
        $reload_btn configure -state normal
    }
}

proc show_oauth_modal_dialog {} {
    # Display modal dialog with two authentication options
    # Returns: 1 if authentication succeeded (OAuth or reload), 0 otherwise
    debug_log "show_oauth_modal_dialog called"
    
    global oauth oauth_modal_result
    if {[info exists oauth_modal_result]} {
        debug_log "oauth_modal_result exists, current value: $oauth_modal_result"
    } else {
        debug_log "oauth_modal_result DOES NOT EXIST"
    }
    
    # Reset oauth state and result
    set oauth(auth_code) ""
    
    if {[catch {
        set oauth_modal_result 0
        debug_log "Successfully set oauth_modal_result to 0 in show_oauth_modal_dialog"
    } err]} {
        debug_log "ERROR setting oauth_modal_result in show_oauth_modal_dialog: $err"
        debug_log "Error info: $::errorInfo"
    }
    
    # Create modal toplevel
    set modal [toplevel .oauth_modal]
    wm title $modal "Elevated Permissions Required"
    wm transient $modal .
    wm protocol $modal WM_DELETE_WINDOW {
        # User closed window - cancel OAuth
        debug_log "WM_DELETE_WINDOW triggered"
        global oauth oauth_modal_result
        debug_log "In WM_DELETE_WINDOW: oauth_modal_result exists? [info exists oauth_modal_result]"
        
        if {[catch {
            set oauth(auth_code) "CANCELLED"
            debug_log "Set oauth(auth_code) to CANCELLED"
            set oauth_modal_result 0
            debug_log "Set oauth_modal_result to 0"
        } err]} {
            debug_log "ERROR in WM_DELETE_WINDOW: $err"
            debug_log "Error info: $::errorInfo"
        }
    }
    
    # Make it modal
    grab set $modal
    
    # Raise to top
    raise $modal
    focus $modal
    
    # Main frame with padding
    set f [ttk::frame $modal.main -padding 20]
    pack $f -fill both -expand yes
    
    # Title
    ttk::label $f.title -text "This operation requires elevated OneDrive permissions" \
        -font {TkDefaultFont 11 bold} -wraplength 510
    pack $f.title -pady {0 20}
    
    # Instructions
    ttk::label $f.instructions \
        -text "Please choose an authentication method:" \
        -justify left
    pack $f.instructions -anchor w -pady {0 15}
    
    # Button frame for the two main action buttons
    pack [ttk::frame $f.actions] -fill x -pady {0 15}
    
    # Browser authentication button
    set browser_btn [ttk::button $f.actions.browser \
        -text "Authenticate with Browser" \
        -width 30]
    pack $browser_btn -pady 5 -anchor center
    
    # Reload token button
    set reload_btn [ttk::button $f.actions.reload \
        -text "Reload Token File" \
        -width 30]
    pack $reload_btn -pady 5 -anchor center
    
    # Status label (shows progress after user clicks a button)
    pack [ttk::label $f.status -text "" -foreground blue -justify center] -pady {10 10}
    
    # Configure button commands after creating status label
    $browser_btn configure -command [list oauth_modal_start_browser_auth $modal $browser_btn $reload_btn]
    $reload_btn configure -command [list oauth_modal_reload_token $modal $reload_btn]
    
    # Wait for dialog to close (modal loop)
    tkwait window $modal
    
    # Release grab
    catch {grab release $modal}
    
    # Return result from global variable
    return $oauth_modal_result
}



# ============================================================================
# Edit Mode Button Handlers
# ============================================================================

proc ensure_edit_capability {} {
    # Check if we have edit capability, trigger OAuth flow if needed
    # Returns: 1 if we have edit capability, 0 if user cancelled or failed
    global token_capability
    
    # Get current token capability
    set result [get_access_token [$::ui::w(remote_entry) get] "" "detailed" 1]
    set access_token [lindex $result 0]
    set capability [lindex $result 1]
    # expires_at is 3rd element but not needed here
    set token_capability $capability
    
    if {$capability eq "full"} {
        # Already have edit capability
        return 1
    }
    
    # Need to acquire elevated token - show modal directly
    # Modal provides both options: browser auth OR token file reload
    # User can cancel if they don't want to proceed
    if {[acquire_elevated_token]} {
        return 1
    } else {
        return 0
    }
}

proc on_invite_user_click {} {
    if {[info exists ::ui::state(sel_provider)] && $::ui::state(sel_provider) eq "dropbox"} {
        ::ui::status "Inviting on Dropbox is done through policy enforcement for now" orange
        return
    }
    # Show dialog to invite a user
    global current_item_id
    set tree $::ui::w(acl)

    if {$current_item_id eq ""} {
        tk_messageBox -type ok -icon warning -title "No Item Selected" \
            -message "Please fetch ACL for an item first."
        return
    }
    
    # Check if we have edit capability (will prompt for OAuth if needed)
    if {![ensure_edit_capability]} {
        return
    }
    
    # Create dialog window
    set dialog [toplevel .invite_dialog]
    wm title $dialog "Invite User"
    wm transient $dialog .
    
    # Email entry
    ttk::label $dialog.email_label -text "Email address:"
    ttk::entry $dialog.email_entry -width 40
    
    # Role selection
    ttk::label $dialog.role_label -text "Permission level:"
    ttk::frame $dialog.role_frame
    ttk::radiobutton $dialog.role_frame.read -text "Read (view only)" -variable invite_role -value "read"
    ttk::radiobutton $dialog.role_frame.write -text "Write (can edit)" -variable invite_role -value "write"
    set ::invite_role "read"
    
    # Buttons
    ttk::frame $dialog.buttons
    ttk::button $dialog.buttons.ok -text "Invite" -command {set ::invite_dialog_result ok}
    ttk::button $dialog.buttons.cancel -text "Cancel" -command {set ::invite_dialog_result cancel}
    
    # Layout
    pack $dialog.email_label -anchor w -padx 10 -pady {10 0}
    pack $dialog.email_entry -fill x -padx 10 -pady {0 10}
    pack $dialog.role_label -anchor w -padx 10 -pady {10 0}
    pack $dialog.role_frame -anchor w -padx 20 -pady {0 10}
    pack $dialog.role_frame.read -anchor w
    pack $dialog.role_frame.write -anchor w
    pack $dialog.buttons -side bottom -pady 10
    pack $dialog.buttons.ok -side left -padx 5
    pack $dialog.buttons.cancel -side left -padx 5
    
    # Wait for dialog result
    set ::invite_dialog_result ""
    focus $dialog.email_entry
    grab $dialog
    tkwait variable ::invite_dialog_result
    
    if {$::invite_dialog_result eq "ok"} {
        set email [string trim [$dialog.email_entry get]]
        set role $::invite_role
        
        destroy $dialog
        
        if {$email eq ""} {
            tk_messageBox -type ok -icon warning -title "Invalid Input" \
                -message "Please enter an email address."
            return
        }
        
        # Get access token
        set result [get_access_token [$::ui::w(remote_entry) get] "" "detailed" 1]
        set access_token [lindex $result 0]
        # capability is 2nd element, expires_at is 3rd (not needed here)
        
        if {$access_token eq ""} {
            ::ui::status "Error: No access token available" red
            return
        }
        
        # Invite user
        ::ui::status "Inviting $email..." blue
        set invite_result [invite_user_to_item $current_item_id $email $role $access_token]
        set invite_status [lindex $invite_result 0]
        set invite_message [lindex $invite_result 1]
        
        if {$invite_status eq "ok"} {
            ::ui::status "✅ $invite_message" green
            # Refresh ACL display
            after 1000 {refresh_current_acl}
        } elseif {$invite_status eq "error" && [string match "*401*" $invite_message]} {
            ::ui::status "Token expired - please try again" red
        } else {
            ::ui::status "❌ $invite_message" red
        }
    } else {
        destroy $dialog
    }
}

proc on_remove_selected_click {} {
    if {[info exists ::ui::state(sel_provider)] && $::ui::state(sel_provider) eq "dropbox"} {
        ::ui::status "Removing on Dropbox is done through policy enforcement for now" orange
        return
    }
    # Remove selected permissions from treeview
    global current_item_id
    set tree $::ui::w(acl)

    if {$current_item_id eq ""} {
        tk_messageBox -type ok -icon warning -title "No Item Selected" \
            -message "Please fetch ACL for an item first."
        return
    }
    
    # Get selected items
    set selection [$tree selection]
    
    if {[llength $selection] == 0} {
        tk_messageBox -type ok -icon warning -title "No Selection" \
            -message "Please select one or more permissions to remove."
        return
    }
    
    # Check if we have edit capability (will prompt for OAuth if needed)
    if {![ensure_edit_capability]} {
        return
    }
    
    # Confirm removal
    set count [llength $selection]
    set response [tk_messageBox -type yesno -icon warning -title "Confirm Removal" \
        -message "Remove $count permission(s)?\n\nThis cannot be undone."]
    
    if {$response ne "yes"} {
        return
    }
    
    # Get access token
    set result [get_access_token [$::ui::w(remote_entry) get] "" "detailed" 1]
    set access_token [lindex $result 0]
    # capability is 2nd element, expires_at is 3rd (not needed here)
    
    if {$access_token eq ""} {
        ::ui::status "Error: No access token available" red
        return
    }
    
    # Remove each selected permission
    set success_count 0
    set fail_count 0
    
    ::ui::status "Removing $count permission(s)..." blue
    
    foreach item $selection {
        set values [$tree item $item -values]
        set permission_id [lindex $values 6]
        if {$permission_id eq ""} { continue }

        set remove_result [remove_permission $current_item_id $permission_id $access_token]
        set remove_status [lindex $remove_result 0]
        
        if {$remove_status eq "ok"} {
            incr success_count
        } else {
            incr fail_count
            set error_msg [lindex $remove_result 1]
            if {[string match "*401*" $error_msg]} {
                ::ui::status "Token expired - please try again" red
                return
            }
        }
    }
    
    if {$fail_count == 0} {
        ::ui::status "✅ Removed $success_count permission(s)" green
    } else {
        ::ui::status "⚠️ Removed $success_count, failed $fail_count" orange
    }
    
    # Refresh ACL display
    after 1000 {refresh_current_acl}
}

proc refresh_current_acl {} {
    # Refresh the current ACL display
    global selected_item
    
    if {[dict exists $selected_item id]} {
        set item_id [dict get $selected_item id]
        set remote_name [$::ui::w(remote_entry) get]
        gui_fetch_acl $item_id $remote_name
    }
}

proc analyze_permissions {permissions} {
    # Analyze permissions to determine sharing type and get shared user list.
    # Identifies owner by looking for "owner" role instead of requiring user ID.
    # Returns: List of {has_link_sharing has_direct_sharing permission_count shared_users}
    set has_link_sharing 0
    set has_direct_sharing 0
    set shared_users {}
    
    foreach perm $permissions {
        if {[is_owner_permission $perm]} {
            continue
        }
        
        if {[dict exists $perm link]} {
            set link [dict get $perm link]
            if {[dict exists $link type]} {
                set has_link_sharing 1
            }
        }
        
        set user_list [extract_users_from_perm $perm]
        if {[llength $user_list] > 0} {
            set has_direct_sharing 1
            foreach user_info $user_list {
                set email [lindex $user_info 1]
                # Fallback to displayName if email is empty (preserves original behavior)
                if {$email eq ""} {
                    set email [lindex $user_info 0]
                }
                if {$email ne "" && [lsearch $shared_users $email] < 0} {
                    lappend shared_users $email
                }
            }
        }
    }
    
    return [list $has_link_sharing $has_direct_sharing [llength $permissions] $shared_users]
}



proc has_explicit_user_permission {permissions target_user_lower} {
    # Check if any permission explicitly grants access to the target user
    # (non-inherited, non-owner)
    foreach perm $permissions {
        if {[is_owner_permission $perm]} {
            continue
        }
        
        if {[is_inherited_permission $perm]} {
            continue
        }
        
        set user_list [extract_users_from_perm $perm]
        foreach user_info $user_list {
            set user_email [string tolower [lindex $user_info 1]]
            if {[string first $target_user_lower $user_email] >= 0} {
                return 1
            }
        }
    }
    return 0
}

proc add_shared_folder_result {folder_id folder_path access_token has_link has_direct perm_count shared_users target_user_lower shared_folders_var} {
    # Add a shared folder to the results list
    upvar $shared_folders_var shared
    
    # Get folder name
    set folder_info_url [build_graph_api_url "/me/drive/items/$folder_id"]
    set headers [list Authorization "Bearer $access_token"]
    set info_result [make_http_request $folder_info_url $headers]
    set info_status [lindex $info_result 0]
    set info_data [lindex $info_result 1]
    set folder_name "Unknown"
    if {$info_status eq "200"} {
        set folder_data [json::json2dict $info_data]
        set folder_name [dict get $folder_data name]
    }
    
    # Determine symbol and sharing type
    if {$has_link} {
        set symbol "🔗"
        set share_type "Link sharing"
    } else {
        set symbol "👥"
        set share_type "Direct permissions"
    }
    
    # Use folder_id directly - no consistency check needed
    # The folder_id comes from the API, so it's already correct
    set consistent_folder_id $folder_id
    
    lappend shared [list \
        path $folder_path \
        name $folder_name \
        id $consistent_folder_id \
        symbol $symbol \
        share_type $share_type \
        has_link_sharing $has_link \
        has_direct_sharing $has_direct \
        permission_count $perm_count \
        shared_users $shared_users]
    
    if {$target_user_lower ne ""} {
        puts "   ✅ Found explicit permission: $symbol $folder_path"
    } else {
        puts "   ✅ Found shared: $symbol $folder_path"
    }
}

proc scan_items_recursive {folder_id access_token max_depth current_depth folder_path parent_id checked_folders folders_per_level results {mode "collect_all"} {target_user_lower ""} {item_type "folders"}} {
    # Unified recursive scanner that handles both collection and filtering modes
    # 
    # Parameters:
    #   folder_id           - ID of folder to scan
    #   access_token        - Microsoft Graph API access token
    #   max_depth          - Maximum recursion depth
    #   current_depth      - Current recursion depth
    #   folder_path        - Path string for display
    #   parent_id          - Parent folder ID (used in collect_all mode)
    #   checked_folders    - Variable name for tracking checked folders
    #   folders_per_level  - Variable name for tracking folder counts by level
    #   results            - Variable name for storing results
    #   mode               - "collect_all" (store all permissions) or "filter" (filter by criteria)
    #   target_user_lower  - Email of user to filter by (lowercase, for filter mode)
    #   item_type          - "folders", "files", or "both"
    #
    # Returns: Nothing (results stored in upvar variables)
    
    upvar $checked_folders checked
    upvar $folders_per_level folders
    upvar $results collected
    
    if {$current_depth > $max_depth || [lsearch $checked $folder_id] >= 0} {
        return
    }
    
    lappend checked $folder_id
    
    # Track folder count per level
    if {![info exists folders($current_depth)]} {
        set folders($current_depth) 0
    }
    incr folders($current_depth)
    
    # Show progress every 10 folders
    set total_checked [llength $checked]
    if {$total_checked % 10 == 0 && !$::quiet_mode} {
        puts "   📁 Scanned $total_checked folders..."
    }
    
    if {[catch {
        # Get permissions for this folder
        lassign [get_folder_permissions $folder_id $access_token] perm_status permissions
        
        if {$perm_status eq "ok"} {
            # Process based on mode
            if {$mode eq "collect_all"} {
                # Mode 1: Store complete folder information for display
                set is_root [expr {$current_depth == 0}]
                lappend collected [list \
                    path $folder_path \
                    id $folder_id \
                    parent_id $parent_id \
                    permissions $permissions \
                    is_root $is_root \
                    depth $current_depth]
                    
            } elseif {$mode eq "filter"} {
                # Mode 2: Filter and analyze permissions
                set analysis [analyze_permissions $permissions]
                set has_link [lindex $analysis 0]
                set has_direct [lindex $analysis 1]
                set perm_count [lindex $analysis 2]
                set shared_users [lindex $analysis 3]
                
                # Check for explicit user permissions if target_user is specified
                set has_explicit_user_perm 0
                if {$target_user_lower ne ""} {
                    set has_explicit_user_perm [has_explicit_user_permission $permissions $target_user_lower]
                }
                
                # Determine if this folder should be included in results
                set should_include_folder 0
                if {$target_user_lower ne ""} {
                    # When filtering by user, only include if explicit permission found
                    set should_include_folder $has_explicit_user_perm
                } else {
                    # When not filtering by user, include all shared folders
                    set should_include_folder [expr {$has_link || $has_direct}]
                }
                
                if {$should_include_folder} {
                    # Get full path if not already provided
                    if {$folder_path eq ""} {
                        set folder_path [get_item_path $folder_id $access_token]
                    }
                    
                    add_shared_folder_result $folder_id $folder_path $access_token $has_link $has_direct $perm_count $shared_users $target_user_lower collected
                }
                
                # Implement pruning: if explicit user permission found, skip children
                if {$target_user_lower ne "" && $has_explicit_user_perm} {
                    puts "   🚀 Pruning: User has access here, skipping descendants (they inherit)"
                    return
                }
            }
        }
        
        # Get children of this folder and recursively check them
        set headers [list Authorization "Bearer $access_token"]
        set children_url [build_graph_api_url "/me/drive/items/$folder_id/children"]
        set children_result [make_http_request $children_url $headers]
        set children_status [lindex $children_result 0]
        set children_data [lindex $children_result 1]
        
        if {$children_status eq "200"} {
            set children_dict [json::json2dict $children_data]
            set children [dict get $children_dict value]
            
            foreach child $children {
                set child_name [dict get $child name]
                
                # Skip ignored items
                if {[is_ignored $child_name]} {
                    continue
                }
                
                set is_folder [dict exists $child folder]
                set is_file [dict exists $child file]
                
                # Determine if we should process this child based on item_type
                set should_process 0
                if {$item_type eq "folders" && $is_folder} {
                    set should_process 1
                } elseif {$item_type eq "files" && $is_file} {
                    set should_process 1
                } elseif {$item_type eq "both"} {
                    set should_process 1
                }
                
                if {$should_process} {
                    set child_id [dict get $child id]
                    set child_name [dict get $child name]
                    set child_path "$folder_path/$child_name"
                    if {$folder_path eq ""} {
                        set child_path $child_name
                    }
                    
                    if {$is_folder} {
                        # Recursively scan this child folder
                        scan_items_recursive $child_id $access_token $max_depth [expr $current_depth + 1] $child_path $folder_id checked folders collected $mode $target_user_lower $item_type
                    } elseif {$is_file && $mode eq "filter" && ($item_type eq "files" || $item_type eq "both")} {
                        # For files in filter mode, check permissions but don't recurse
                        lassign [get_folder_permissions $child_id $access_token] file_perm_status file_permissions
                        
                        if {$file_perm_status eq "ok"} {
                            set file_analysis [analyze_permissions $file_permissions]
                            set file_has_link [lindex $file_analysis 0]
                            set file_has_direct [lindex $file_analysis 1]
                            set file_perm_count [lindex $file_analysis 2]
                            set file_shared_users [lindex $file_analysis 3]
                            
                            if {$target_user_lower ne ""} {
                                set file_has_user [has_explicit_user_permission $file_permissions $target_user_lower]
                                if {$file_has_user} {
                                    add_shared_folder_result $child_id $child_path $access_token $file_has_link $file_has_direct $file_perm_count $file_shared_users $target_user_lower collected
                                }
                            }
                        }
                    }
                }
            }
        }
        
    } error]} {
        # Skip folders we can't access
    }
}




proc remove_user_permissions_cli {item_id user_email max_depth item_type dry_run remote_name {auto_yes 0}} {
    # CLI wrapper for removing user permissions
    # Initial display messages should be handled by caller
    
    # Get access token with full capability requirement
    set access_token [cli_get_full_token $remote_name]
    if {$access_token eq ""} {
        return
    }
    
    set target_user_lower [string tolower $user_email]
    set items_to_remove {}
    
    # Collect items with user permissions
    if {$max_depth == 0} {
        # Non-recursive: just check this single item
        lassign [get_folder_permissions $item_id $access_token] perm_status permissions
        if {$perm_status eq "ok"} {
            set has_user_perm [has_explicit_user_permission $permissions $target_user_lower]
            if {$has_user_perm} {
                # Find permission ID for this user
                foreach perm $permissions {
                    set user_info [extract_user_info $perm]
                    set perm_user_email [lindex $user_info 1]
                    if {[string tolower $perm_user_email] eq $target_user_lower} {
                        set perm_id [dict get $perm id]
                        # Store item_id and perm_id; path will be fetched lazily if needed
                        lappend items_to_remove [dict create item_id $item_id perm_id $perm_id]
                    }
                }
            }
        }
    } else {
        # Recursive: scan and collect items
        puts "🔍 Scanning for items with user permissions..."
        
        set shared_folders {}
        set checked_folders {}
        set folders_per_level(0) 0
        
        # Recursively find items (pass "" for path - will be fetched lazily when needed)
        scan_items_recursive $item_id $access_token $max_depth 0 "" "" checked_folders folders_per_level shared_folders "filter" $target_user_lower $item_type
        
        puts "✅ Scan complete. Found [llength $shared_folders] items."
        puts ""
        
        # Extract item IDs and permission IDs from shared_folders
        foreach folder $shared_folders {
            set folder_id [dict get $folder id]
            # Note: folder_path from shared_folders dict will be "" or partial path
            # We don't need it anymore since we'll fetch lazily if needed
            
            # Get permissions to find the specific permission ID for this user
            lassign [get_folder_permissions $folder_id $access_token] perm_status permissions
            if {$perm_status eq "ok"} {
                foreach perm $permissions {
                    set user_info [extract_user_info $perm]
                    set perm_user_email [lindex $user_info 1]
                    if {[string tolower $perm_user_email] eq $target_user_lower} {
                        set perm_id [dict get $perm id]
                        # Store only item_id and perm_id; path will be fetched lazily when needed
                        lappend items_to_remove [dict create item_id $folder_id perm_id $perm_id]
                    }
                }
            }
        }
    }
    
    if {[llength $items_to_remove] == 0} {
        puts "ℹ️  No items found with permissions for $user_email"
        return
    }
    
    puts "Found [llength $items_to_remove] item(s) with permissions for $user_email:"
    foreach item $items_to_remove {
        set item_id [dict get $item item_id]
        # Fetch path lazily for display
        set item_path [get_item_path $item_id $access_token]
        puts "  - $item_path"
    }
    puts ""
    
    if {$dry_run} {
        puts "⚠️  DRY RUN: Would remove [llength $items_to_remove] permission(s)"
        return
    }
    
    # Confirm before removal (skip if --yes)
    if {!$auto_yes} {
        puts "⚠️  This will remove $user_email's access from [llength $items_to_remove] item(s)."
        puts -nonewline {Continue? [Y/n]: }
        flush stdout
        set response [gets stdin]

        if {$response ne "y" && $response ne "Y" && $response ne ""} {
            puts "❌ Cancelled by user"
            return
        }
    }
    
    # Perform removals
    puts ""
    puts "🗑️  Removing permissions..."
    set success_count 0
    set error_count 0
    
    foreach item $items_to_remove {
        set item_id [dict get $item item_id]
        set perm_id [dict get $item perm_id]
        
        # Fetch path lazily for display
        set item_path [get_item_path $item_id $access_token]
        
        set remove_result [remove_permission $item_id $perm_id $access_token]
        set remove_status [lindex $remove_result 0]
        
        if {$remove_status eq "ok"} {
            puts "  ✅ $item_path"
            incr success_count
        } else {
            set remove_message [lindex $remove_result 1]
            puts "  ❌ $item_path - $remove_message"
            incr error_count
        }
    }
    
    puts ""
    puts "=== Summary ==="
    puts "✅ Successfully removed: $success_count"
    if {$error_count > 0} {
        puts "❌ Errors: $error_count"
    }
}


proc invite_user_cli {item_id user_email read_only remote_name} {
    # CLI wrapper for inviting user to an item (by ID)
    # Initial display messages should be handled by caller
    
    # Get access token with full capability requirement
    set access_token [cli_get_full_token $remote_name]
    if {$access_token eq ""} {
        return
    }
    
    # Invite user
    set role [expr {$read_only ? "read" : "write"}]
    set invite_result [invite_user_to_item $item_id $user_email $role $access_token]
    set invite_status [lindex $invite_result 0]
    set invite_message [lindex $invite_result 1]
    
    if {$invite_status eq "ok"} {
        puts "✅ $invite_message"
        puts ""
        puts "ℹ️  Note: This permission is inherited by all children of this folder"
    } else {
        puts "❌ $invite_message"
    }
}

proc set_caption_cli {item_id caption remote_name} {
    # CLI wrapper for setting an item's caption (by ID)
    # Initial display messages should be handled by caller

    # Get access token with full capability requirement
    set access_token [cli_get_full_token $remote_name]
    if {$access_token eq ""} {
        return
    }

    set result [set_item_description $item_id $caption $access_token]
    set status [lindex $result 0]
    set message [lindex $result 1]

    if {$status eq "ok"} {
        puts "✅ $message"
    } else {
        puts "❌ $message"
    }
}

proc list_user_access {item_id user_email max_depth item_type remote_name} {
    # List items where user has access
    # Initial display messages should be handled by caller
    # Supports both recursive (max_depth > 0) and non-recursive (max_depth = 0) modes
    
    if {$max_depth == 0} {
        # Non-recursive mode: just check this item's ACL for user
        
        # Get access token
        set access_token [get_access_token $remote_name]
        if {$access_token eq ""} {
            return
        }
        
        puts "✅ Successfully extracted access token from rclone.conf"
        
        # Get permissions
        set headers [list Authorization "Bearer $access_token"]
        set permissions_url [build_graph_api_url "/me/drive/items/$item_id/permissions"]
        set result [make_http_request $permissions_url $headers]
        set status [lindex $result 0]
        set data [lindex $result 1]
        
        if {$status ne "200"} {
            puts "❌ Failed to get permissions: $status"
            return
        }
        
        set permissions_dict [json::json2dict $data]
        set permissions [dict get $permissions_dict value]
        
        # Check for user permission
        set target_user_lower [string tolower $user_email]
        set has_permission [has_explicit_user_permission $permissions $target_user_lower]
        
        if {$has_permission} {
            # Fetch path lazily for display
            set item_path [get_item_path $item_id $access_token]
            puts "✅ User $user_email has access to: $item_path"
            
            # Show permission details
            foreach perm $permissions {
                set user_info [extract_user_info $perm]
                set perm_user_name [lindex $user_info 0]
                set perm_user_email [lindex $user_info 1]
                
                if {[string tolower $perm_user_email] eq $target_user_lower} {
                    set roles [dict get $perm roles]
                    puts "   └─ Roles: [join $roles ", "]"
                }
            }
        } else {
            # Fetch path lazily for display
            set item_path [get_item_path $item_id $access_token]
            puts "ℹ️  User $user_email does not have explicit access to: $item_path"
        }
        
    } else {
        # Recursive mode: use existing scan logic
        scan_shared_folders_user_impl $item_id $user_email $max_depth $item_type $remote_name
    }
}

proc scan_shared_folders_user_impl {item_id user_email max_depth item_type remote_name} {
    # Internal implementation of recursive user scan (renamed from scan_shared_folders_user)
    # Initial display messages should be handled by caller
    
    # Get access token
    set access_token [get_access_token $remote_name]
    if {$access_token eq ""} {
        return
    }
    
    puts "✅ Successfully extracted access token from rclone.conf"
    
    set headers [list Authorization "Bearer $access_token"]
    set shared_folders {}
    set checked_folders {}
    set folders_per_level(0) 0
    set target_user_lower [string tolower $user_email]
    
    # Start scanning from provided item_id
    if {[catch {
        # Recursively scan (pass "" for path - will be fetched lazily when needed for display)
        scan_items_recursive $item_id $access_token $max_depth 0 "" "" checked_folders folders_per_level shared_folders "filter" $target_user_lower $item_type
    } error]} {
        puts "❌ Search error: $error"
    }
    
    # Print level statistics
    puts "\n📊 Folder count by level:"
    foreach level [lsort -integer [array names folders_per_level]] {
        set count $folders_per_level($level)
        puts "   Level $level: $count folders"
    }
    
    puts "\n✅ Scan complete. Found [llength $shared_folders] shared folders."
    puts "   Checked [llength $checked_folders] total folders recursively."
    
    # Display results
    if {[llength $shared_folders] > 0} {
        puts "\n[string repeat "=" 80]"
        puts "📁 Found [llength $shared_folders] shared folder(s):"
        puts [string repeat "=" 80]
        
        foreach folder $shared_folders {
            set folder_path [dict get $folder path]
            set symbol [dict get $folder symbol]
            set share_type [dict get $folder share_type]
            set perm_count [dict get $folder permission_count]
            set shared_users [dict get $folder shared_users]
            
            puts "$symbol $folder_path"
            puts "   └─ $share_type ($perm_count permission(s))"
            
            if {[llength $shared_users] > 0} {
                # Move the search user to the front if present
                set search_user_index [lsearch -exact $shared_users $user_email]
                if {$search_user_index >= 0} {
                    set search_user [lindex $shared_users $search_user_index]
                    set other_users [lreplace $shared_users $search_user_index $search_user_index]
                    set reordered_users [linsert $other_users 0 $search_user]
                } else {
                    set reordered_users $shared_users
                }
                
                set users_str [join [lrange $reordered_users 0 2] ", "]
                if {[llength $reordered_users] > 3} {
                    set users_str "$users_str and [expr [llength $reordered_users] - 3] more"
                }
                puts "   └─ Shared with: $users_str"
            }
            
            set has_link [dict get $folder has_link_sharing]
            set has_direct [dict get $folder has_direct_sharing]
            if {$has_link && $has_direct} {
                puts "   └─ Has both link sharing and direct permissions"
            }
            puts ""
        }
    } else {
        puts "\nℹ️  No shared folders found"
        puts "This could mean:"
        puts "  - No folders are shared with $user_email"
        puts "  - The user email '$user_email' doesn't match any shared users"
    }
    
    puts "\n=== Scan Complete ==="
}

# Shared function: Fetch permissions by item ID (used by both GUI and CLI)
# Returns: {status permissions} where status is "ok" or error message

# GUI wrapper: Fetch ACL and update GUI widgets
proc ::ui::badge_for {provider fid} {
    # Two tiers: the policy tier is free (governed vs not); the audit tier
    # is written only by audit runs and cached in state(badge,provider,fid).
    variable state
    if {[info exists state(badge,$provider,$fid)]} {
        return $state(badge,$provider,$fid)
    }
    if {![info exists state(model)] || $state(model) eq ""} { return "" }
    if {[dict exists $state(model) plan $provider $fid]} { return "\u00b7" }
    return "\u2013"
}

proc ::ui::badges_refresh {{root {}}} {
    # Re-stamp the badge cell of every loaded tree row (policy reload,
    # audit results). Cheap: dict lookups over already-loaded nodes.
    variable w
    foreach item [$w(tree) children $root] {
        set values [$w(tree) item $item -values]
        if {[llength $values] >= 4 && [lindex $values 1] eq "folder"} {
            set provider [lindex $values 3]
            set fid [lindex $values 0]
            if {$fid ni {root {}}} {
                lset values 4 [::ui::badge_for $provider $fid]
                $w(tree) item $item -values $values
            }
        }
        ::ui::badges_refresh $item
    }
}

proc ::ui::entitlement_summary {model platform fid} {
    # "groupA (write), groupB (read)" for the folder, from the raw grants
    set raw [dict get $model raw]
    set parts {}
    foreach grant [dict get $raw grants] {
        set role "read"
        foreach r [dict get $grant roles] { if {$r eq "write"} { set role "write" } }
        if {[catch {policy_v2_resolve_collection [dict get $raw collections] \
                [dict get $grant collection] {}} folders]} { continue }
        foreach f $folders {
            if {[dict get $f platform] eq $platform && [dict get $f id] eq $fid} {
                lappend parts "[dict get $grant group] ($role)"
                break
            }
        }
    }
    return [join $parts ", "]
}

proc ::ui::update_governed {platform fid} {
    # The governed-by line under the Item entry
    variable w
    variable state
    if {![info exists state(model)] || $state(model) eq ""} {
        $w(governed) configure -text "No policy loaded." -foreground gray40
        return
    }
    set model $state(model)
    if {![dict exists $model plan $platform $fid]} {
        $w(governed) configure -foreground gray30 -text \
            "Governed by nothing: this folder is in no collection, so the audit does not check it. Its access is whatever the drive says."
        return
    }
    set fentry [dict get $model plan $platform $fid]
    set cname [dict get $fentry collection]
    set closed [expr {[dict get $fentry closed] ? " (closed)" : ""}]
    set ent [::ui::entitlement_summary $model $platform $fid]
    set text "Governed by: $cname$closed"
    if {$ent ne ""} { append text "  \u2014 entitled: $ent" }
    if {[dict get $fentry closed]} { append text "; inheritance severed" }
    $w(governed) configure -foreground black -text $text
}

proc ::ui::state_cell {violations email} {
    # {text tag} for the State column from this folder's audit findings
    foreach v $violations {
        if {[dict get $v email] ne $email} { continue }
        switch [dict get $v type] {
            wrong_role { return [list "\u274c WRONG ROLE \u2014 exceeds entitlement" violation] }
            extra_user { return [list "\u274c EXTRA \u2014 closed collection" violation] }
            leaked_inherited { return [list "\u274c LEAKED \u2014 severs inheritance" violation] }
            open_extra { return [list "\u2139 extra, tolerated" {}] }
            open_inherited { return [list "\u2139 inherited extra, tolerated" {}] }
            missing_user { return [list "\u274c MISSING \u2014 invite as [dict get $v expected]" missing] }
        }
    }
    return [list "\u2713 matches policy" {}]
}

proc ::ui::audit_one_folder {platform fid} {
    # This folder's violations, or "" when it is ungoverned or offline.
    # Runs the same audit_folder the CLI uses, through the platform's
    # provider, so the Access tab can never disagree with the audit.
    variable state
    if {![info exists state(model)] || $state(model) eq ""} { return "" }
    if {![dict exists $state(model) plan $platform $fid]} { return "" }
    set provider [provider_for $platform]
    if {$platform eq "dropbox"} {
        set ctx [::ui::dropbox_ctx]
    } else {
        set result [get_access_token [$::ui::w(remote_entry) get] "" "detailed" 1]
        set token [lindex $result 0]
        if {$token eq ""} { return "" }
        set ctx [dict create token $token remote [$::ui::w(remote_entry) get]]
    }
    if {$ctx eq ""} { return "" }
    lassign [audit_folder $provider $ctx $fid [dict get $state(model) plan $platform $fid]] violations _ _
    return $violations
}

proc gui_fetch_acl_dropbox {fid} {
    # Fill the ACL table from the Dropbox provider's normalized view:
    # members split direct/inherited, then any shared links as rows of
    # their own. Rows are display-only; removal works through enforcement.
    set ctx [::ui::dropbox_ctx]
    if {$ctx eq ""} {
        ::ui::status "No Dropbox connection" red
        return
    }
    ::ui::status "Fetching Dropbox ACL..." blue
    update
    lassign [dbx_get_item $ctx $fid] istatus item
    if {$istatus ne "ok"} {
        ::ui::status "Cannot resolve the Dropbox folder" red
        return
    }
    set path [dbx_item_path $ctx $item]
    lassign [dbx_get_acl $ctx $fid] astatus acl
    if {$astatus ne "ok"} {
        ::ui::status "Cannot read Dropbox members" red
        return
    }

    set acl_tree $::ui::w(acl)
    foreach row [$acl_tree children {}] { $acl_tree delete $row }
    $::ui::w(item_entry) configure -state normal
    $::ui::w(item_entry) delete 0 end
    $::ui::w(item_entry) insert 0 $path
    $::ui::w(item_entry) configure -state readonly

    ::ui::update_governed dropbox $fid
    set model ""
    if {[info exists ::ui::state(model)]} { set model $::ui::state(model) }
    set violations [::ui::audit_one_folder dropbox $fid]
    set bound {}
    set governed 0
    if {$model ne "" && [dict exists $model plan dropbox $fid]} {
        set governed 1
        set bound [dict get $model plan dropbox $fid expected]
    }

    set rows 0
    set seen {}
    foreach {source inherited_str} {direct No inherited Yes} {
        foreach email [lsort [dict keys [dict get $acl $source]]] {
            set role [dict get $acl $source $email]
            dict set seen $email 1
            set who ""
            if {$model ne ""} {
                set who [identity_display $model [identity_person_for $model dropbox $email]]
            }
            set policy_cell "\u2014"
            if {[dict exists $bound $email]} { set policy_cell [dict get $bound $email] }
            if {$governed} {
                lassign [::ui::state_cell $violations $email] state_cell state_tag
            } else {
                set state_cell [expr {$model eq "" ? "" : "not audited"}]
                set state_tag {}
            }
            set tags [list $role]
            if {$source eq "inherited"} { lappend tags inherited }
            if {$state_tag ne ""} { lappend tags $state_tag }
            $acl_tree insert {} end -text $email \
                -values [list $who $policy_cell $role $inherited_str "-" $state_cell ""] \
                -tags $tags
            incr rows
        }
    }
    dict for {email role} $bound {
        if {[dict exists $seen $email]} { continue }
        set who ""
        if {$model ne ""} {
            set who [identity_display $model [identity_person_for $model dropbox $email]]
        }
        $acl_tree insert {} end -text $email \
            -values [list $who $role "\u2014" "\u2014" "-" "\u274c MISSING \u2014 invite as $role" ""] \
            -tags missing
        incr rows
    }
    foreach link [dict get $acl links] {
        $acl_tree insert {} end -text "(shared link)" \
            -values [list "anyone with the URL" "\u2014" read No link "" ""] \
            -tags read
        incr rows
    }
    ::ui::status "Dropbox ACL: $rows entr(ies) on $path" blue
}

proc gui_fetch_acl {item_id remote_name} {
    global current_item_id token_capability
    set acl_tree $::ui::w(acl)

    if {$item_id eq ""} {
        ::ui::status "Error: Invalid item ID" red
        return
    }
    
    # Get access token with capability detection
    set result [get_access_token $remote_name "" "detailed" 1]
    set access_token [lindex $result 0]
    set capability [lindex $result 1]
    set expires_at [lindex $result 2]
    set token_capability $capability
    
    if {$access_token eq ""} {
        return
    }
    
    debug_log "Token capability: $capability"
    
    # Format expiration info for status message
    if {$expires_at ne "unknown" && $expires_at ne "n/a"} {
        set exp_display " (expires: $expires_at)"
    } else {
        set exp_display ""
    }
    
    ::ui::status "✅ Using token (capability: $capability)$exp_display" green
    
    # Get item info by ID (no lookup needed - we already have ID)
    set item_url [build_graph_api_url "/me/drive/items/$item_id"]
    ::ui::status "Getting item info for ID: $item_id" blue
    
    set result [make_http_request $item_url [list Authorization "Bearer $access_token"]]
    set status [lindex $result 0]
    set data [lindex $result 1]
    
    if {$status ne "200"} {
        # Handle 401 errors specially - token might have expired
        if {$status eq "401" && $capability eq "full" && [string match "*TOKEN_EXPIRED*" $data]} {
            ::ui::status "❌ Token expired despite refresh attempt. Please re-authenticate." red
            return
        } elseif {$status eq "error"} {
            ::ui::status "❌ HTTP request failed: $data" red
        } else {
            ::ui::status "❌ Failed to get item info: $status - $data" red
        }
        return
    }
    
    # Parse item response
    if {[catch {json::json2dict $data} item_dict]} {
        ::ui::status "❌ Failed to parse item response: $item_dict" red
        return
    }
    
    set item_name [dict get $item_dict name]
    set item_type [expr {[dict exists $item_dict folder] ? "folder" : "file"}]
    
    # Store current item ID for edit operations
    set current_item_id $item_id
    
    # Update ACL path label with item name (no path lookup needed - GUI works with IDs only)
    $::ui::w(item_entry) configure -state normal
    $::ui::w(item_entry) delete 0 end
    $::ui::w(item_entry) insert 0 $item_name
    $::ui::w(item_entry) configure -state readonly
    
    ::ui::status "✅ Found $item_type" green

    foreach item [$acl_tree children {}] {
        $acl_tree delete $item
    }
    ::ui::status "Treeview cleared" green

    ::ui::status "Getting ACL..." blue
    set perm_result [fetch_permissions_by_id $item_id $access_token]
    set perm_status [lindex $perm_result 0]
    set permissions [lindex $perm_result 1]
    
    if {$perm_status ne "ok"} {
        ::ui::status "❌ $permissions" red
        return
    }
    
    set perm_count [llength $permissions]

    if {$perm_count == 0} {
        ::ui::status "ℹ️ No permissions found for this item (empty ACL)" orange
        return
    }
    
    ::ui::status "✅ Found $perm_count permission(s) in ACL (Token: $capability)" green

    # Sort permissions: non-inherited first, then inherited, each group sorted by email
    set sorted_permissions [lsort -command {
        apply {{a b} {
            set inherited_a [dict exists $a inheritedFrom]
            set inherited_b [dict exists $b inheritedFrom]

            # Non-inherited (0) comes before inherited (1)
            if {$inherited_a != $inherited_b} {
                return [expr {$inherited_a - $inherited_b}]
            }

            # Within same inheritance status, sort by email
            lassign [extract_user_info $a] _ email_a
            lassign [extract_user_info $b] _ email_b
            return [string compare -nocase $email_a $email_b]
        }}
    } $permissions]

    # The policy's view of this folder: entitlements, plus the same audit
    # findings the CLI would report, merged into the table's State column
    ::ui::update_governed onedrive $item_id
    set model ""
    if {[info exists ::ui::state(model)]} { set model $::ui::state(model) }
    set violations [::ui::audit_one_folder onedrive $item_id]
    set bound {}
    if {$model ne "" && [dict exists $model plan onedrive $item_id]} {
        set bound [dict get $model plan onedrive $item_id expected]
    }
    set governed [expr {$model ne "" && [dict exists $model plan onedrive $item_id]}]

    # Populate treeview; the owner rows stay visible but carry no
    # permission id, which is what keeps them out of removal
    set seen_emails {}
    foreach perm $sorted_permissions {
        set roles [dict get $perm roles]
        set is_owner [expr {[lsearch $roles "owner"] >= 0}]

        set perm_id [expr {$is_owner ? "" : [dict get $perm id]}]

        # Get user information; the policy's person name beats the drive's
        # display name (accounts get relabeled by their users)
        lassign [extract_user_info $perm] user_name user_email
        set email_lower [string tolower $user_email]
        dict set seen_emails $email_lower 1
        if {$model ne ""} {
            set slug [identity_person_for $model onedrive $email_lower]
            if {$slug ne ""} { set user_name [identity_display $model $slug] }
        }

        # Drive-actual role, normalized like the audit sees it
        if {$is_owner} {
            set drive_role "owner"
        } elseif {[lsearch $roles "write"] >= 0} {
            set drive_role "write"
        } else {
            set drive_role "read"
        }

        # Policy-intended role
        set policy_cell "\u2014"
        if {[dict exists $bound $email_lower]} {
            set policy_cell [dict get $bound $email_lower]
        } elseif {$model ne "" && !$governed} {
            set policy_cell "\u2014 not governed"
        }

        # Link column
        set link_cell "-"
        if {[dict exists $perm link]} {
            set lt ""
            set lsc ""
            catch {set lt [dict get $perm link type]}
            catch {set lsc [dict get $perm link scope]}
            set link_cell [string trim "$lt/$lsc" /]
        }

        set is_inherited [is_inherited_permission $perm]
        set inherited_str [expr {$is_inherited ? "Yes" : "No"}]

        # State from the audit, person-blind rows kept honest
        if {$is_owner} {
            set state_cell "owner"
            set state_tag {}
        } elseif {!$governed} {
            set state_cell [expr {$model eq "" ? "" : "not audited"}]
            set state_tag {}
        } else {
            lassign [::ui::state_cell $violations $email_lower] state_cell state_tag
        }

        set tags [list]
        if {$is_owner} {
            lappend tags "owner"
        } elseif {[lsearch $roles "read"] >= 0} {
            lappend tags "read"
        } else {
            lappend tags "write"
        }
        if {$is_inherited} { lappend tags "inherited" }
        if {$state_tag ne ""} { lappend tags $state_tag }

        $acl_tree insert {} end -text $user_email \
            -values [list $user_name $policy_cell $drive_role $inherited_str $link_cell $state_cell $perm_id] \
            -tags $tags
    }

    # Entitled people the drive does not know yet: synthetic MISSING rows
    dict for {email role} $bound {
        if {[dict exists $seen_emails $email]} { continue }
        set who ""
        if {$model ne ""} {
            set who [identity_display $model [identity_person_for $model onedrive $email]]
        }
        $acl_tree insert {} end -text $email \
            -values [list $who $role "\u2014" "\u2014" "-" "\u274c MISSING \u2014 invite as $role" ""] \
            -tags missing
    }

    # Enable invite button now that ACL is loaded
    $::ui::w(btn_invite) configure -state normal

    ::ui::status "✅ ACL listing of: https://onedrive.live.com/?id=$item_id" green
}


# Show help function














proc main {argc argv} {
    # CLI mode - process command line arguments with path-first interface
    # Usage: [PATH] [OPTIONS]

    # Define option specifications for cmdline
    set options {
        {only-user.arg "" "Filter to items USER has access to"}
        {remove-user.arg "" "Remove USER's access (destructive)"}
        {invite.arg "" "Invite USER with read/write access (inherited by children)"}
        {set-caption.arg "\x00" "Set the item's caption/description (searchable in OneDrive); use \"\" to clear"}
        {audit.arg "" "Audit live ACLs against a POLICY yaml file (read-only)"}
        {enforce.arg "" "Audit then fix live ACLs to match a POLICY yaml file"}
        {convert-policy.arg "" "Print the version-2 form of an email-per-member POLICY yaml file"}
        {platform.arg "" "Restrict --audit/--enforce to one platform (onedrive|dropbox)"}
        {r "Include children in scan (recursive, default depth: 3)"}
        {recursive "Include children in scan (recursive, default depth: 3)"}
        {max-depth.arg "0" "Max depth (default: 3 with -r, 0 otherwise)"}
        {type.arg "folders" "Item type: folders|files|both (default: folders)"}
        {format.arg "text" "Output format: text|csv (default: text)"}
        {dry-run "Preview changes (with --remove-user or --enforce)"}
        {read-only "Grant read-only access (with --invite, default: read/write)"}
        {y "Skip confirmation prompts (with --remove-user or --enforce)"}
        {yes "Skip confirmation prompts (with --remove-user or --enforce)"}
        {debug "Enable debug output"}
        {remote.arg "OneDrive" "OneDrive remote name"}
    }
    
    # Parse arguments (cmdline modifies argv in-place, leaving positional args)
    if {[catch {array set params [::cmdline::getoptions argv $options]} err]} {
        puts stderr $err
        exit 1
    }
    
    # Extract PATH (first remaining positional argument after cmdline processing)
    set path [lindex $argv 0]

    # Convert OneDrive web URL to path if needed
    if {[string match "https://*" $path]} {
        set converted [convert_onedrive_url_to_path $path]
        if {$converted ne $path} {
            puts "🔗 Converted URL to path: $converted"
            set path $converted
        }
    }

    # Set variables from parsed options
    set only_user $params(only-user)
    set remove_user $params(remove-user)
    set invite_user $params(invite)
    set caption $params(set-caption)
    set audit_policy $params(audit)
    set enforce_policy $params(enforce)
    set convert_policy $params(convert-policy)
    set item_type $params(type)
    set output_format $params(format)
    set dry_run $params(dry-run)
    set read_only $params(read-only)
    set auto_yes [expr {$params(y) || $params(yes)}]
    set remote_name $params(remote)
    
    # Handle recursive flags and max-depth
    set r_flag_used [expr {$params(r) || $params(recursive)}]
    set max_depth_explicit [expr {$params(max-depth) ne "0"}]
    
    if {$r_flag_used && !$max_depth_explicit} {
        set max_depth 3
    } elseif {$max_depth_explicit} {
        set max_depth $params(max-depth)
    } else {
        set max_depth 0
    }
    
    # Set global debug mode
    global debug_mode
    set debug_mode $params(debug)
    
    # Validation: mutual exclusions
    set action_count 0
    if {$only_user ne ""} { incr action_count }
    if {$remove_user ne ""} { incr action_count }
    if {$invite_user ne ""} { incr action_count }
    if {$caption ne "\x00"} { incr action_count }
    if {$audit_policy ne ""} { incr action_count }
    if {$enforce_policy ne ""} { incr action_count }
    if {$convert_policy ne ""} { incr action_count }

    if {$action_count > 1} {
        puts "Error: --only-user, --remove-user, --invite, --set-caption, --audit, --enforce, and --convert-policy are mutually exclusive"
        exit 1
    }

    # Conversion is pure text transformation: no drive, no token
    if {$convert_policy ne ""} {
        if {[catch {puts -nonewline [policy_convert_v1_v2 $convert_policy]} err]} {
            puts stderr "❌ Policy error: $err"
            exit 2
        }
        exit 0
    }

    # Policy modes take their folder set from the policy file
    if {($audit_policy ne "" || $enforce_policy ne "")} {
        if {$r_flag_used || $max_depth_explicit} {
            puts "Error: --audit/--enforce cannot be used with -r or --max-depth (the policy defines the folder set)"
            exit 1
        }
        if {$path ne ""} {
            puts "Error: --audit/--enforce take no PATH argument (the policy defines the folder set)"
            exit 1
        }
    }
    
    # Validate --invite is not used with recursive flags
    if {$invite_user ne "" && ($r_flag_used || $max_depth_explicit)} {
        puts "Error: --invite cannot be used with -r or --max-depth (invitations are always inherited)"
        exit 1
    }

    # Validate --set-caption is not used with recursive flags (captions are per-item)
    if {$caption ne "\x00" && ($r_flag_used || $max_depth_explicit)} {
        puts "Error: --set-caption cannot be used with -r or --max-depth (captions are per-item)"
        exit 1
    }
    
    # Validate --dry-run only with --remove-user or --enforce
    if {$dry_run && $remove_user eq "" && $enforce_policy eq ""} {
        puts "Error: --dry-run can only be used with --remove-user or --enforce"
        exit 1
    }
    
    # Validate --read-only only with --invite
    if {$read_only && $invite_user eq ""} {
        puts "Error: --read-only can only be used with --invite"
        exit 1
    }
    
    # Validate --type values
    if {$item_type ne "folders" && $item_type ne "files" && $item_type ne "both"} {
        puts "Error: --type must be 'folders', 'files', or 'both'"
        exit 1
    }

    # Validate --format values
    if {$output_format ne "text" && $output_format ne "csv"} {
        puts "Error: --format must be 'text' or 'csv'"
        exit 1
    }

    # Validate --platform: policy modes only, known platform names
    if {$params(platform) ne ""} {
        if {$audit_policy eq "" && $enforce_policy eq ""} {
            puts "Error: --platform can only be used with --audit or --enforce"
            exit 1
        }
        if {$params(platform) ni [policy_known_platforms]} {
            puts "Error: --platform must be one of: [join [policy_known_platforms] {, }]"
            exit 1
        }
    }

    # Validate --format csv only with default ACL display mode or --audit
    if {$output_format eq "csv" && ($only_user ne "" || $remove_user ne "" || $invite_user ne "" || $enforce_policy ne "")} {
        puts "Error: --format csv can only be used with default ACL display mode or --audit"
        exit 1
    }

    # Validate --yes only with --remove-user or --enforce
    if {$auto_yes && $remove_user eq "" && $enforce_policy eq ""} {
        puts "Error: --yes can only be used with --remove-user or --enforce"
        exit 1
    }

    # If -r was used without explicit --max-depth, inform user
    if {$max_depth == 3 && $r_flag_used && !$max_depth_explicit && $output_format ne "csv"} {
        puts "ℹ️  Using default max-depth: 3 (use --max-depth N to change)"
        puts ""
    }
    
    # Execute based on flags
    if {$audit_policy ne ""} {
        exit [audit_cli $audit_policy $output_format $remote_name $params(platform)]

    } elseif {$enforce_policy ne ""} {
        exit [enforce_cli $enforce_policy $dry_run $auto_yes $remote_name $params(platform)]

    } elseif {$invite_user ne ""} {
        # Invite user to path
        puts "📧 Inviting user to path: $path"
        puts "User: $invite_user"
        puts "Access level: [expr {$read_only ? "read-only" : "read/write"}]"
        puts ""
        
        # Resolve path to item ID (handles token and errors)
        set resolve_result [cli_resolve_path_for_command $path $remote_name]
        if {[llength $resolve_result] == 0} {
            exit 1
        }
        lassign $resolve_result access_token item_id item_dict
        set item_name [dict get $item_dict name]
        puts "📁 Found item: $item_name (ID: $item_id)"
        puts ""
        
        invite_user_cli $item_id $invite_user $read_only $remote_name

    } elseif {$caption ne "\x00"} {
        # Set (or clear) the item's caption (server-side description)
        if {$caption eq ""} {
            puts "🧹 Clearing caption on path: $path"
        } else {
            puts "📝 Setting caption on path: $path"
            puts "Caption: $caption"
        }
        puts ""

        # Resolve path to item ID (handles token and errors)
        set resolve_result [cli_resolve_path_for_command $path $remote_name]
        if {[llength $resolve_result] == 0} {
            exit 1
        }
        lassign $resolve_result access_token item_id item_dict
        set item_name [dict get $item_dict name]
        puts "📁 Found item: $item_name (ID: $item_id)"
        puts ""

        set_caption_cli $item_id $caption $remote_name

    } elseif {$remove_user ne ""} {
        # Remove user permissions
        puts "🗑️  Removing user permissions"
        puts "User: $remove_user"
        puts "Starting path: $path"
        if {$max_depth > 0} {
            puts "Max depth: $max_depth"
            puts "Item type: $item_type"
        } else {
            puts "Mode: Non-recursive (single item only)"
        }
        if {$dry_run} {
            puts "⚠️  DRY RUN MODE - No changes will be made"
        }
        puts ""
        
        # Resolve path to item ID (handles token and errors)
        set resolve_result [cli_resolve_path_for_command $path $remote_name]
        if {[llength $resolve_result] == 0} {
            exit 1
        }
        lassign $resolve_result access_token item_id item_dict
        
        remove_user_permissions_cli $item_id $remove_user $max_depth $item_type $dry_run $remote_name $auto_yes
        
    } elseif {$only_user ne ""} {
        # List user access
        puts "🔍 Checking access for user: $only_user"
        puts "Path: $path"
        if {$max_depth > 0} {
            puts "Max depth: $max_depth"
            puts "Item type: $item_type"
        }
        puts ""
        
        # Resolve path to item ID (handles token and errors)
        set resolve_result [cli_resolve_path_for_command $path $remote_name]
        if {[llength $resolve_result] == 0} {
            exit 1
        }
        lassign $resolve_result access_token item_id item_dict
        
        list_user_access $item_id $only_user $max_depth $item_type $remote_name
        
    } else {
        # Default: show ACL with new recursive format
        global quiet_mode
        set quiet_mode [expr {$output_format eq "csv"}]

        if {!$quiet_mode} {
            puts "OneDrive ACL Inspector"
            puts "Path: $path"
            puts "Remote: $remote_name"
            if {$max_depth > 0} {
                puts "Max depth: $max_depth"
            }
            puts ""
        }

        # Get access token with capability detection and auto-refresh
        set result [get_access_token $remote_name "" "detailed" 1]
        set access_token [lindex $result 0]
        set capability [lindex $result 1]

        if {$access_token eq ""} {
            puts "❌ Failed to get access token"
            exit 1
        }

        if {!$quiet_mode} {
            puts "✅ Using token (capability: $capability)"
            puts ""
        }

        # Resolve path to item ID using helper function
        set item_result [cli_path_to_item_id_and_dict $path $access_token]
        if {[llength $item_result] == 0} {
            puts "❌ Failed to resolve path: $path"
            exit 1
        }
        lassign $item_result start_id item_dict

        # Collect all folder permissions recursively
        set all_folders {}
        set checked_folders {}
        set folders_per_level(0) 0

        if {$max_depth > 0 && !$quiet_mode} {
            puts "🔍 Scanning folder hierarchy (max depth: $max_depth)..."
            puts ""
        }

        # max_depth is the maximum depth level to scan (0 = root only, 1 = root + direct children, etc.)
        scan_items_recursive $start_id $access_token $max_depth 0 $path "" checked_folders folders_per_level all_folders "collect_all" "" $item_type

        if {$max_depth > 0 && !$quiet_mode} {
            puts ""
            puts "✅ Scan complete. Scanned [llength $checked_folders] folder(s)."
        }

        # Get root permissions
        if {[llength $all_folders] > 0} {
            set root_folder [lindex $all_folders 0]
            set root_permissions [dict get $root_folder permissions]

            # Display using selected format
            if {$output_format eq "csv"} {
                print_csv_acl $path $root_permissions $all_folders $max_depth
            } else {
                print_recursive_acl $path $root_permissions $all_folders $max_depth $item_dict
            }
        } else {
            puts "❌ No folders found or unable to access permissions"
        }
    }
}

proc ::ui::start {} {
    variable w

    # GUI MODE - Parse command line arguments

    # Check for -debug flag in GUI mode
    global debug_mode argc argv
    if {[lsearch -exact $argv "-debug"] != -1} {
        set debug_mode 1
    }

    # GUI INITIALIZATION
    ::ui::connections_discover
    ::ui::build
    ::ui::policy_startup

    ::ui::status "Cloud ACL Manager - expand a drive to browse" blue

    # Open the first drive's root so the window is not empty
    set root_item [lindex [$w(tree) children {}] 0]
    if {$root_item ne ""} {
        load_tree_children $w(tree) $root_item
        $w(tree) item $root_item -open 1
    }

    # Test seam: a script named in ACL_GUI_SCRIPT runs inside the live GUI
    # once it is up, so the walkthrough can drive real handlers headlessly.
    if {[info exists ::env(ACL_GUI_SCRIPT)] && [file exists $::env(ACL_GUI_SCRIPT)]} {
        after 1200 [list source $::env(ACL_GUI_SCRIPT)]
    }

    # wish would enter the event loop on reaching the end of the script; a
    # tclsh has to be told. Waiting on the main window rather than a variable
    # that is never set means closing the browser ends the process.
    tkwait window .
}

if {[info commands tk] ne ""} {
    ::ui::start
} else {
    main $argc $argv
}

