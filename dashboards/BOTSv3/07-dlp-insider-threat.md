# DLP / Insider Threat Dashboard

This dashboard analyzes DLP and endpoint security telemetry from Code42 security events in BOTSv3. It focuses on policy violations, personal cloud storage usage, removable media activity, file access behavior, and combined insider-threat indicators.

## Data Source

- Index: `botsv3`
- Sourcetype: `code42:security`
- Dataset: BOTSv3
- Primary Event Types:
  - `RULE_MATCH`
  - `PERSONAL_CLOUD_SCAN_RESULT`
  - `DEVICE_APPEARED`
  - `FILE_OPENED`

---

## Panel 1 — Cisco ASA Firewall SPL documentation

### Purpose
Provides an event-type distribution from Code42 security telemetry to understand the overall composition of DLP and endpoint security events.

### SPL

spl
index=botsv3 sourcetype="code42:security"
| stats count by eventType
| sort - count
Panel 2 — DLP Rule Match Details
Purpose

Displays detailed DLP policy-match events, including the affected user, file, file path, and exposure type.

SPL
index=botsv3 sourcetype="code42:security" eventType="RULE_MATCH"
| table _time, deviceUsername, eventType, fileName, filePath, exposureType
Panel 3 — Personal Cloud Storage Usage
Purpose

Identifies activity involving personal cloud storage providers and the files associated with cloud-storage activity.

SPL
index=botsv3 sourcetype="code42:security" eventType="PERSONAL_CLOUD_SCAN_RESULT"
| spath
| table formattedTimestamp, deviceRemoteAddress, cloudStorageProvider.productName, files{}.filename
Panel 4 — Removable Media / USB Device Activity
Purpose

Provides visibility into removable-media device activity, including device identifiers and the associated user.

SPL
index=botsv3 sourcetype="code42:security" eventType="DEVICE_APPEARED"
| spath
| table formattedTimestamp, deviceRemoteAddress, deviceGuid, userUid
| sort - formattedTimestamp
Panel 5 — File Access & Download Patterns by User (Insider Behavior Analysis)
Purpose

Analyzes file-opening activity by user to identify users with higher volumes of file access.

SPL
index=botsv3 sourcetype="code42:security" eventType="FILE_OPENED"
| spath
| stats count by userUid, formattedTimestamp
| stats count as total_accesses by userUid
| sort - total_accesses
| head 20
Panel 6 — Insider Threat Risk Timeline (Combined Indicator View)
Purpose

Combines multiple Code42 event types into a time-based view and assigns a threat level to each event category.

SPL
index=botsv3 sourcetype="code42:security"
| spath
| eval threat_level=case(eventType="RULE_MATCH", "Critical", eventType="DEVICE_APPEARED", "High", eventType="PERSONAL_CLOUD_SCAN_RESULT", "Medium", eventType="FILE_OPENED", "Low", true(), "Info")
| timechart span=1h count by threat_level
Security Monitoring Focus

The dashboard provides visibility into:

DLP policy violations
Personal cloud storage activity
Removable media / USB activity
File access behavior
User-level insider behavior
Combined insider-threat indicators
Event activity over time
Investigation Workflow
Review the overall Code42 event distribution.
Investigate RULE_MATCH events for potential DLP policy violations.
Review personal cloud storage activity for possible unauthorized data movement.
Investigate removable-media activity and associated users.
Identify users with high file-access activity.
Correlate multiple event types using the combined threat timeline.
