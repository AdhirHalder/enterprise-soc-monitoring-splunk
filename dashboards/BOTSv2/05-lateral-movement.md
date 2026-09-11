# Lateral Movement Dashboard

## Overview

The Lateral Movement Dashboard provides visibility into internal host-to-host communication, SMB activity, LDAP queries, and Active Directory authentication events within the BOTSv2 dataset.

The dashboard focuses on identifying patterns that may support investigation of lateral movement and authentication-related activity.

## Data Sources

- Index: `botsv2`
- Sourcetypes:
  - `stream:smb`
  - `stream:ldap`
  - `WinEventLog:Security`

---

## Panel 1 — SMB Connections Over Time (Internal Host-to-Host Traffic)

### Purpose

Visualizes SMB connection activity between hosts over time.

### SPL

spl
index=botsv2 sourcetype="stream:smb"
| timechart span=1h count as smb_connections

Analysis

The query generates an hourly time series of SMB connections, providing visibility into changes in internal host-to-host SMB activity.

Panel 2 — Top Source-Destination SMB Host Pairs
Purpose

Identifies the most frequently observed SMB source-destination host pairs associated with administrative share paths.

SPL
index=botsv2 sourcetype="stream:smb"
| stats count by src_ip, dest_ip, path
| where like(path, "%$$")
| sort -count
| head 20
Analysis

The query groups SMB events by source IP, destination IP, and path.

It filters paths matching the $-terminated administrative-share pattern and displays the top 20 combinations by event count.

Panel 3 — LDAP Query Activity by Source Host
Purpose

Provides visibility into LDAP query activity between source and destination hosts.

SPL
index=botsv2 sourcetype="stream:ldap"
| stats count by src_ip, dest_ip, message_type
| sort -count
| head 10
Analysis

The query groups LDAP events by source IP, destination IP, and message type.

The top 10 combinations are displayed based on event count.

Panel 4 — Bind Requests Over Time
Purpose

Visualizes LDAP bind request activity over time and identifies the source hosts generating the requests.

SPL
index=botsv2 sourcetype="stream:ldap" message_type="Bind request"
| timechart span=1h count by src_ip
Analysis

The query filters LDAP events for Bind request messages and creates an hourly time series grouped by source IP.

Panel 5 — AD Authentication Failure
Purpose

Identifies Active Directory authentication failures by source network address, computer, and account.

SPL
index=botsv2 sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address, ComputerName, Account_Name
| sort -count
| head 10
Analysis

The query filters Windows Security Event Code 4625, representing failed logon activity.

It groups the events by source network address, computer name, and account name and displays the top 10 combinations by event count.

Panel 6 — AD Successful Logon After Multiple Failures (Possible Brute-Force Success)
Purpose

Identifies source and computer combinations where multiple failed authentication attempts are followed by successful logon activity.

SPL
index=botsv2 sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failed_attempts, count(eval(EventCode=4624)) as success_attempts by Source_Network_Address, ComputerName
| where failed_attempts > 5 AND success_attempts > 0
| sort -failed_attempts
Analysis

The query analyzes both failed (4625) and successful (4624) Windows logon events.

It identifies source and computer combinations with more than five failed attempts and at least one successful logon.

These results can be prioritized for further investigation as possible brute-force success patterns.

Investigation Value

The dashboard provides multiple views of network and Active Directory activity relevant to lateral movement investigation.

It can be used to:

Monitor SMB connections over time
Identify frequently observed SMB host pairs
Analyze LDAP query activity
Monitor LDAP bind requests
Investigate Active Directory authentication failures
Identify possible successful authentication following multiple failures
Support lateral movement and credential-abuse investigations
Related Documentation
BOTSv2 Dashboard Overview
BOTSv2 Findings
MITRE ATT&CK Mapping
