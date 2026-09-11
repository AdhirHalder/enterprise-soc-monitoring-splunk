# AWS CloudTrail Security Dashboard

## Overview

The AWS CloudTrail Security Dashboard provides visibility into AWS API activity and security-relevant CloudTrail events in the BOTSv3 dataset.

The dashboard focuses on AWS event activity, console authentication, denied API requests, IAM changes, S3 permission changes, and CloudTrail logging tampering.

## Data Source

- Index: `botsv3`
- Sourcetype: `aws:cloudtrail`
- Data Type: AWS CloudTrail Security Telemetry

---

## Panel 1 — CloudTrail Events by Event Source & Event Name

### Purpose

Identifies the most frequently observed AWS event sources and event names.

### SPL

spl
index=botsv3 sourcetype="aws:cloudtrail"
| stats count by eventSource, eventName
| sort - count
| head 20

Analysis

This panel provides an overview of AWS API activity and helps analysts identify frequently occurring or potentially security-relevant CloudTrail events.

Panel 2 — Console Logins Without MFA
Purpose

Identifies AWS console login activity and displays the MFA usage status associated with each login.

SPL
index=botsv3 sourcetype="aws:cloudtrail" eventName="ConsoleLogin"
| stats count by userIdentity.userName, sourceIPAddress, additionalEventData.MFAUsed
| sort -count
Analysis

This panel helps analysts identify console login activity where MFA usage may require further investigation.

Panel 3 — Failed/Access Denied API Calls
Purpose

Identifies AWS API requests that resulted in AccessDenied errors.

SPL
index=botsv3 sourcetype="aws:cloudtrail" errorCode="AccessDenied"
| stats count by userIdentity.userName, eventName, sourceIPAddress
| sort - count
| head 20
Analysis

Repeated access-denied events can provide useful investigation context, particularly when associated with specific users, API operations, or source IP addresses.

Panel 4 — IAM User/Access Key Creation Activity
Purpose

Monitors security-sensitive IAM operations related to user, access key, login profile, and policy creation or attachment.

SPL
index=botsv3 sourcetype="aws:cloudtrail" eventName IN ("CreateUser", "CreateAccessKey", "CreateLoginProfile", "AttachUserPolicy")
| stats count by eventName, userIdentity.userName, sourceIPAddress
| sort - count
| head 20
Analysis

This panel provides visibility into IAM changes that may affect account access and privileges. Such activity can be investigated against the responsible user and source IP.

Panel 5 — S3 Bucket Policy & Permission Changes
Purpose

Monitors changes to S3 bucket policies, ACLs, public-access settings, and bucket policies.

SPL
index=botsv3 sourcetype="aws:cloudtrail" eventName IN ("PutBucketPolicy", "PutBucketACL", "PutBucketPublicAccessBlock", "DeleteBucketPolicy")
| stats count by eventName, userIdentity.userName, requestParameters.bucketName, sourceIPAddress
| sort -count
| head 20
Analysis

Changes to S3 access controls can affect the exposure and accessibility of stored data. This panel helps analysts identify permission-related activity and investigate the responsible identity and source IP.

Panel 6 — CloudTrail Logging Tampering Detection
Purpose

Detects CloudTrail operations that can modify, disable, or remove logging configurations.

SPL
index=botsv3 sourcetype="aws:cloudtrail" eventName IN ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors")
| stats count by eventName, userIdentity.userName, sourceIPAddress, eventTime
| sort - eventTime
Analysis

This panel provides visibility into CloudTrail configuration changes that may affect security logging. Such activity should be investigated to determine whether the changes were authorized.

Investigation Value

The dashboard provides AWS security monitoring coverage across:

CloudTrail event activity
Console authentication
Access-denied API requests
IAM account and access-key changes
S3 permission and policy changes
CloudTrail logging configuration changes

These views help analysts investigate identity-related activity, privilege changes, suspicious API behavior, and potential attempts to reduce cloud visibility.

Related Documentation
findings/BOTSv3-findings.md
mitre/mitre-mapping.md
dashboards/BOTSv3/README.md
