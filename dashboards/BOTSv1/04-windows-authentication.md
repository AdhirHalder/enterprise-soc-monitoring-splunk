# Windows Authentication Dashboard

## Overview

The Windows Authentication Dashboard provides visibility into Windows security and authentication activity within the BOTSv1 dataset.

The dashboard analyzes successful and failed logons, potential brute-force patterns, privilege escalation events, process creation, network share access, and user logon activity over time.

## Data Source

- Index: `botsv1`
- Sourcetype: `WinEventLog:Security`

---

## Panel 1 — Successful vs Failed Logons

### Purpose

Provides a breakdown of Windows authentication-related events based on their Event IDs.

### SPL

spl
index=botsv1 sourcetype=WinEventLog:Security
| stats count by EventCode
| eval logon_type=case(
  EventCode="4624", "Successful Logon",
  EventCode="4625", "Failed Logon",
  EventCode="4740", "Account Lockout",
  EventCode="4672", "Private Escalation")
| where isnotnull(logon_type)
| stats count by logon_type

Analysis

The query maps selected Windows Security Event Codes to authentication and privilege-related activity and calculates the event count for each category.

Panel 2 — Brute Force Pattern Detection
Purpose

Identifies accounts and source IP addresses associated with multiple failed logon attempts.

SPL
index=botsv1 sourcetype=WinEventLog:Security
EventCode=4625
| stats count by Account_Name, scr_ip
| where count > 3
| sort -count
Analysis

The query filters failed logon events using Event Code 4625 and groups them by account and source IP.

Accounts and source IP combinations with more than three failed attempts are displayed as potential brute-force patterns.

Panel 3 — Privilege Escalation Events
Purpose

Identifies accounts associated with Windows special privilege events.

SPL
index=botsv1 sourcetype=WinEventLog:Security EventCode=4672
| stats count by Account_Name
| sort -count
Analysis

The query filters Event Code 4672 and counts occurrences by account.

This provides visibility into accounts associated with special privilege assignments in the Windows security telemetry.

Panel 4 — Suspicious Process Creation
Purpose

Provides visibility into Windows process creation activity.

SPL
index=botsv1 sourcetype=WinEventLog:Security
EventCode=4688
| stats count by New_Process_Name, Account_Name
| sort -count
| head 10
Analysis

The query filters Windows process creation events using Event Code 4688.

It groups the events by process name and account, then displays the top 10 combinations by event count.

Panel 5 — Network Share Access
Purpose

Identifies Windows network share access activity by account and share name.

SPL
index=botsv1 sourcetype=WinEventLog:Security
EventCode=5140
| stats count by Account_Name, Share_Name
| sort -count
| head 10
Analysis

The query filters network share access events using Event Code 5140.

It ranks the top account and network share combinations according to event count.

Panel 6 — Logon Activity by User Over Time
Purpose

Visualizes successful Windows logon activity by user over time.

SPL
index=botsv1 sourcetype=WinEventLog:Security EventCode=4624
| timechart span=1h count by Account_Name
Analysis

The query filters successful logon events using Event Code 4624 and creates an hourly time series grouped by account.

This provides visibility into user authentication activity over time.

Investigation Value

The dashboard provides multiple views of Windows authentication and security activity.

It can be used to:

Analyze successful and failed logons
Identify potential brute-force patterns
Review privilege-related events
Investigate process creation activity
Analyze network share access
Monitor user logon activity over time
Support Windows endpoint threat hunting
Related Documentation
BOTSv1 Dashboard Overview
BOTSv1 Findings
MITRE ATT&CK Mapping
