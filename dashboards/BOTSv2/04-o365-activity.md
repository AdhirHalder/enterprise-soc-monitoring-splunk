# O365 Activity Dashboard

## Overview

The O365 Activity Dashboard provides visibility into Microsoft Office 365 activity within the BOTSv2 dataset.

The dashboard analyzes service health, user operations, operation timelines, workload activity, source IP activity, and potentially suspicious administrative operations.

## Data Source

- Index: `botsv2`
- Sourcetype: `ms:o365:management`

---

## Panel 1 — O365 Service Health Overview

### Purpose

Shows Office 365 service activity grouped by workload and status.

### SPL

spl
index=botsv2 sourcetype=ms:o365:management
| stats count by Workload, Status
| sort -count

Analysis

The query groups Office 365 management events by workload and status and sorts the results by event count.

Panel 2 — O365 User Operations
Purpose

Provides visibility into Office 365 operations performed by users and their resulting status.

SPL
index=botsv2 sourcetype=ms:o365:management
| search Operation=*
| stats count by UserId, Operation, ResultStatus
| sort -count
Analysis

The query filters events containing an operation and groups them by user, operation, and result status.

This helps analysts review user activity and the outcomes of Office 365 operations.

Panel 3 — O365 Operation Timeline
Purpose

Visualizes Office 365 operations over time.

SPL
index=botsv2 sourcetype=ms:o365:management
| search Operation=*
| timechart span=1h count by Operation
Analysis

The query generates an hourly time series of Office 365 operations, separated by operation type.

Panel 4 — O365 Activity Over Time
Purpose

Visualizes Office 365 activity over time according to workload.

SPL
index=botsv2 sourcetype=ms:o365:management
| timechart span=1h count by Workload
Analysis

The query generates an hourly time series and separates activity according to Office 365 workload.

Panel 5 — O365 Source IP Analysis
Purpose

Identifies source IP addresses associated with Office 365 activity and the users generating that activity.

SPL
index=botsv2 sourcetype=ms:o365:management
| search src_ip=*
| stats count by src_ip, user
| sort -count
Analysis

The query filters events containing a source IP address and groups the activity by source IP and user.

This provides visibility into the network sources associated with Office 365 activity.

Panel 6 — O365 Admin Operation Detection
Purpose

Identifies selected Office 365 administrative operations and tags them as suspicious when they match predefined operations.

SPL
index=botsv2 sourcetype=ms:o365:management
| search Operation=*
| eval suspicious=if(Operation="Add-MailboxPermission" OR Operation="Set-TransportConfig" OR Operation="Install-AdminAuditLogConfig" OR Operation="Set-AdminAuditLogConfig", "YES", "NO")
| stats count by Operation, suspicious
| sort -suspicious
Analysis

The query checks Office 365 operations against a predefined set of administrative operations.

Matching operations are tagged as YES, while other operations are tagged as NO.

The results are then counted by operation and suspicious classification.

Investigation Value

The dashboard provides multiple views of Office 365 management activity.

It can be used to:

Review Office 365 service activity
Analyze user operations
Monitor operation activity over time
Analyze workload activity
Investigate source IP and user relationships
Identify selected administrative operations
Support investigation of potentially suspicious O365 activity
Related Documentation
BOTSv2 Dashboard Overview
BOTSv2 Findings
MITRE ATT&CK Mapping
