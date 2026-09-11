# Linux Endpoint Security Dashboard

This dashboard analyzes Linux endpoint telemetry from BOTSv3 to provide visibility into SSH authentication activity, system configuration changes, user accounts, and potentially suspicious command execution.

## Data Sources

- Index: `botsv3`
- Sourcetypes:
  - `linux_audit`
  - `linux_secure`
  - `unix:service`
  - `unix:update`
  - `Unix:UserAccounts`

---

## Panel 1 — Linux System Activity Overview (Sudo & SSH Commands)

### Purpose
Provides an overview of Linux security activity by showing event volume across Linux audit and secure logs for each host.

### SPL

spl
index=botsv3 sourcetype="linux_audit" OR sourcetype="linux_secure"
| stats count by sourcetype, host
| sort - count
| head 20

Panel 2 — SSH Failed Login Attempts
Purpose

Identifies failed SSH authentication attempts involving invalid users and extracts the source IP associated with the attempt.

SPL
index=botsv3 sourcetype="linux_secure" "Invalid user" OR "input_userauth_request"
| rex field=_raw "Invalid user (?<invalid_user>\S+) from (?<src_ip>[\d\.]+)"
| where isnotnull(invalid_user)
| stats count by invalid_user, src_ip
| sort - count
| head 20
Panel 3 — System Configuration Changes (Service/Package Modifications)
Purpose

Provides visibility into service and package-related system changes by analyzing Unix service and update telemetry.

SPL
index=botsv3 sourcetype="unix:service" OR sourcetype="unix:update"
| stats count by sourcetype, host
| sort - count
Panel 4 — User Account Activity (System & Service Accounts)
Purpose

Analyzes Linux user-account information, including user IDs, shells, and associated hosts, to support endpoint account monitoring.

SPL
index=botsv3 sourcetype="Unix:UserAccounts"
| rex field=_raw "user=(?<user>\S+)\s+password=\S+\s+user_id=(?<user_id>\d+)\s+user_group_id=(?<user_group_id>\d+)\s+home=(?<home>\S+)\s+shell=(?<shell>\S+)"
| where isnotnull(user)
| stats count by user, user_id, shell, host
| sort - count
Panel 5 — Process Execution Monitoring (Suspicious Command Detection)
Purpose

Highlights Linux endpoint events containing command-line utilities that may warrant investigation, including wget, curl, nc, ncat, bash, sh, and python.

SPL
index=botsv3 sourcetype="linux_secure" OR sourcetype="linux_audit"
| regex _raw="(wget|curl|nc|ncat|bash|sh|python)" 
| stats count by host, _raw
| sort - count
| head 20
Security Monitoring Focus

The dashboard provides visibility into:

Linux system activity
SSH authentication failures
Invalid-user login attempts
Service and package modifications
Linux user-account activity
Potentially suspicious command execution
Endpoint-level security telemetry
Investigation Workflow
Review overall Linux audit and secure-log activity.
Investigate repeated SSH failed-login attempts and source IPs.
Review service and package modification activity.
Examine user-account activity for relevant system and service accounts.
Investigate suspicious command patterns and associated hosts
