#!/bin/bash

# Variables
output_file="privilege_escalation_audit.html"

# Functions
function create_html_header() {
    cat << EOF > "$output_file"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Privilege Escalation Audit Report</title>
    <style>
        /* Add your custom CSS styles here */
        body {
            font-family: Arial, sans-serif;
        }
        h1, h2, h3 {
            color: #333;
        }
        pre {
            background-color: #f8f8f8;
            padding: 1em;
            overflow-x: auto;
        }
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }
        tr:hover {background-color: #f5f5f5;}
        .critical {background-color: #ff9999;}
        .high {background-color: #ffcc99;}
        .medium {background-color: #ffff99;}
        .low {background-color: #ccffcc;}
    </style>
</head>
<body>
<h1>Privilege Escalation Audit Report</h1>
<p>Generated on: $(date)</p>
<h3>Contents</h3>
<ul>
<li><a href="#suid-sgid-files">SUID and SGID Files</a>: Files with SUID and SGID bits set can allow non-root users to execute programs with the privileges of the file owner, which can lead to privilege escalation.</li>
<li><a href="#user-accounts">User Accounts</a>: User accounts with UIDs above 1000 that are not the default "nobody" account can potentially be used for privilege escalation.</li>
<li><a href="#cron-jobs">Cron Jobs</a>: Cron jobs with elevated privileges can be exploited for privilege escalation.</li>
<li><a href="#weak-permissions">Weak File and Directory Permissions</a>: Files and directories with weak permissions can allow unauthorized users to access and modify sensitive data or execute malicious code, leading to privilege escalation.</li>
<li><a href="#sudoers-config">Sudoers Configuration</a>: Insecure Sudoers configuration can allow unauthorized users to execute commands with root privileges, leading to privilege escalation.</li>
<li><a href="#unsecured-configs">Unsecured Configuration Files</a>: Insecure configuration files can contain sensitive information or allow unauthorized access, leading to privilege escalation.</li>
<li><a href="#world-writable-dirs">World-Writable Directories</a>: Directories with world-writable permissions can allow unauthorized users to modify or replace files, leading to privilege escalation.</li>
<li><a href="#root-owned-files">Root-Owned Files in User Home Directories</a>: Files owned by root in user home directories can potentially be used for privilege escalation.</li>
<li><a href="#sensitive-files">Sensitive Files</a>: Sensitive files, such as SSH private keys, that are accessible by unauthorized users can lead to privilege escalation.</li>
<li><a href="#elevated-processes">Elevated Processes</a>: Processes running with elevated privileges, such as those owned by the root user or the sudo group, can be exploited for privilege escalation.</li>
<li><a href="#open-network-connections">Open Network Connections</a>: Open network connections can expose services and applications to potential attacks or unauthorized access, leading to privilege escalation.</li>
<li><a href="#weak-passwords">Users with Weak Passwords</a>: User accounts with weak passwords can be easily compromised, leading to privilege escalation.</li>
<li><a href="#outdated-software">Outdated Software Packages</a>: Outdated software packages can contain known vulnerabilities that can be exploited for privilege escalation.</li>
<li><a href="#unsecured-network-ports">Unsecured Network Ports</a>: Unsecured network ports can allow unauthorized access to services or applications, leading to privilege escalation.</li>
</ul>
EOF
}
function create_html_section() {
local section_id=$1
local section_title=$2
local section_output=$3
local section_severity=$4
cat << EOF >> "$output_file"

<h2 id="$section_id" class="$section_severity">$section_title</h2>
<pre>
$section_output
</pre>
EOF
}

function check_suid_sgid_files() {
    local suid_sgid_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null)
    if [[ -n "$suid_sgid_files" ]]; then
        create_html_section "suid-sgid-files" "SUID and SGID Files" "$suid_sgid_files" "medium"
    fi
}
function check_user_accounts() {
local user_accounts=$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd 2>/dev/null)
if [[ -n "$user_accounts" ]]; then
create_html_section "user-accounts" "User Accounts" "$user_accounts" "medium"
fi
}

function check_cron_jobs() {
local cron_jobs=$(for user in $(cut -f1 -d: /etc/passwd); do crontab -u "$user" -l 2>/dev/null; done)
if [[ -n "$cron_jobs" ]]; then
create_html_section "cron-jobs" "Cron Jobs" "$cron_jobs" "low"
fi
}
function check_weak_permissions() {
local weak_permissions=$(find / -type d -perm -0002 -a! -perm -1000 -ls 2>/dev/null)
if [[ -n "$weak_permissions" ]]; then
create_html_section "weak-permissions" "Weak File and Directory Permissions" "$weak_permissions" "medium"
fi
}

function check_sudoers_config() {
local sudoers_config=$(cat /etc/sudoers 2>/dev/null)
if [[ -n "$sudoers_config" ]]; then
create_html_section "sudoers-config" "Sudoers Configuration" "$sudoers_config" "low"
fi
}

function check_unsecured_configs() {
local unsecured_configs=$(find /etc -name '*.conf' -type f -perm -o=r -ls 2>/dev/null)
if [[ -n "$unsecured_configs" ]]; then
create_html_section "unsecured-configs" "Unsecured Configuration Files" "$unsecured_configs" "medium"
fi
}

function check_world_writable_directories() {
local world_writable_directories=$(find / -type d -perm -2 -ls 2>/dev/null)
if [[ -n "$world_writable_directories" ]]; then
create_html_section "world-writable-dirs" "World-Writable Directories" "$world_writable_directories" "medium"
fi
}

function check_root_owned_files_in_home() {
local root_owned_files=$(find /home -type f -user root -ls 2>/dev/null)
if [[ -n "$root_owned_files" ]]; then
create_html_section "root-owned-files" "Root-Owned Files in User Home Directories" "$root_owned_files" "medium"
fi
}

function check_sensitive_files() {
local sensitive_files=$(find / -name id_rsa -o -name id_dsa -o -name authorized_keys -ls 2>/dev/null)
if [[ -n "$sensitive_files" ]]; then
create_html_section "sensitive-files" "Sensitive Files" "$sensitive_files" "high"
fi
}

function check_elevated_processes() {
local elevated_processes=$(ps -ef | grep -E 'root|sudo' | grep -v grep)
if [[ -n "$elevated_processes" ]]; then
create_html_section "elevated-processes" "Elevated Processes" "$elevated_processes" "low"
fi
}

function check_open_network_connections() {
local open_connections=$(netstat -tulpn)
if [[ -n "$open_connections" ]]; then
create_html_section "open-network-connections" "Open Network Connections" "$open_connections" "low"
fi
}

function check_weak_passwords() {
local weak_passwords=$(awk -F: '($2 != "x" && $2 != "*") {print $1}' /etc/shadow 2>/dev/null)
if [[ -n "$weak_passwords" ]]; then
create_html_section "weak-passwords" "Users with Weak Passwords" "$weak_passwords" "high"
fi
}

function check_outdated_software() {
local outdated_packages=$(apt list --upgradable 2>/dev/null | grep -v Listing | grep -v "packages are already" | cut -d/ -f1)
if [[ -n "$outdated_packages" ]]; then
create_html_section "outdated-software" "Outdated Software Packages" "$outdated_packages" "low"
fi
}

function check_unsecured_network_ports() {
local unsecured_ports=$(ss -tulwn | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort | uniq)
if [[ -n "$unsecured_ports" ]]; then
create_html_section "unsecured-network-ports" "Unsecured Network Ports" "$unsecured_ports" "medium"
fi
}

function create_html_footer() {
cat << EOF >> "$output_file"

</body>
</html>
EOF
}
create_html_header
check_suid_sgid_files
check_user_accounts
check_cron_jobs
check_weak_permissions
check_sudoers_config
check_unsecured_configs
check_world_writable_directories
check_root_owned_files_in_home
check_sensitive_files
check_elevated_processes
check_open_network_connections
check_weak_passwords
check_outdated_software
check_unsecured_network_ports

create_html_footer

echo "Audit report generated: $output_file"
