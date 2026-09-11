# Azure AD/O365 Security Dashboard

## Overview

The Azure AD/O365 Security Dashboard provides visibility into Azure Active Directory sign-in activity and Microsoft 365 administrative and file-sharing activity within the BOTSv3 dataset.

The dashboard focuses on authentication activity, failed sign-ins, impossible-travel indicators, privileged O365 operations, external/anonymous sharing, and file access activity.

## Data Sources

- Index: `botsv3`
- Azure AD Sourcetype: `ms:aad:signin`
- O365 Sourcetype: `o365:management:activity`
- Data Type: Identity, Authentication, Microsoft 365 and File Activity

---

## Panel 1 — Azure AD Sign-In Activity Overview

### Purpose

Provides an overview of Azure AD sign-in activity by user, application, and login status.

### SPL
spl
index=botsv3 sourcetype="ms:aad:signin"
| stats count by userPrincipalName, appDisplayName, loginStatus
| sort - count
| head 20

Analysis

This panel provides visibility into user authentication activity and the applications involved in sign-in events.

Panel 2 — Failed Sign-In Attempts (Authentication Failures)
Purpose

Identifies failed Azure AD sign-in attempts and provides information about the affected user, source IP, geographic location, and failure reason.

SPL
index=botsv3 sourcetype="ms:aad:signin" loginStatus="Failure"
| stats count by userPrincipalName, ipAddress, location.country, failureReason
| sort - count
| head 20
Analysis

This panel helps analysts investigate authentication failures and identify users or source IPs associated with repeated failed sign-in activity.

Panel 3 — Impossible Travel Detection — Final Code Explanation
Purpose

Identifies successful sign-ins where the user's country changes between consecutive sign-in events.

SPL
index=botsv3 sourcetype="ms:aad:signin" loginStatus="Success"
| eval country='location.country'
| sort 0 userPrincipalName, signinDateTime
| streamstats current=f last(country) as prev_country by userPrincipalName
| where country!=prev_country AND isnotnull(prev_country)
| table userPrincipalName, prev_country, country, signinDateTime, ipAddress
Analysis

This panel highlights changes in geographic location between successful sign-ins for the same user. These events can be investigated as potential impossible-travel indicators.

Panel 4 — O365 Admin Activity Monitoring (Privileged Actions)
Purpose

Provides visibility into Microsoft 365 administrative activity by user, operation, and workload.

SPL
index=botsv3 sourcetype="o365:management:activity"
| spath
| stats count by UserId, Operation, Workload
| sort - count
| head 20
Analysis

This panel helps analysts identify administrative operations and determine which users are performing privileged or security-relevant actions within O365.

Panel 5 — Anonymous/External File Sharing (Data Exposure Risk)
Purpose

Identifies O365 sharing-related operations that may expose files or resources to external or anonymous users.

SPL
index=botsv3 sourcetype="o365:management:activity" Operation IN ("AnonymousLinkUsed", "SharingSet", "SharingInheritanceBroken")
| spath
| stats count by UserId, Operation, ObjectId
| sort - count
| head 20
Analysis

This panel provides visibility into file-sharing activity that may require investigation for potential data exposure or unauthorized sharing.

Panel 6 — File Access & Download Volume by User (Insider Threat Detection)
Purpose

Monitors file access, download, and upload activity by O365 user.

SPL
index=botsv3 sourcetype="o365:management:activity" Operation IN ("FileAccessed", "FileDownloaded", "FileUploaded")
| spath
| stats count by UserId, Operation
| sort - count
| head 20
Analysis

This panel helps identify users with significant file activity and provides context for investigating potentially unusual access, download, or upload behavior.

Investigation Value

The dashboard provides identity and Microsoft 365 security monitoring coverage across:

Azure AD sign-in activity
Authentication failures
Impossible-travel indicators
O365 administrative activity
Anonymous and external file sharing
File access and download activity

These views can be correlated to investigate account compromise, suspicious authentication activity, privileged administrative actions, and potential data-exposure or insider-threat indicators.

Related Documentation
findings/BOTSv3-findings.md
mitre/mitre-mapping.md
dashboards/BOTSv3/README.md
