# AWS S3/RDS Access Dashboard

## Overview

The AWS S3/RDS Access Dashboard provides visibility into AWS S3 and RDS activity within the BOTSv3 dataset.

The dashboard focuses on S3 bucket access, bucket reconnaissance, RDS activity, public S3 bucket exposure, cross-service activity, and suspicious activity involving the same user across S3 and RDS.

## Data Source

- Index: `botsv3`
- Sourcetype: `aws:cloudtrail`
- Data Type: AWS CloudTrail Security Telemetry

---

## Panel 1 — S3 Bucket Access Activity Overview

### Purpose

Provides an overview of S3 bucket activity by AWS event name and bucket name.

### SPL

spl
index=botsv3 sourcetype="aws:cloudtrail" eventSource="s3.amazonaws.com"
| spath
| stats count by eventName, requestParameters.bucketName
| sort - count
| head 20

Analysis

This panel helps analysts understand which S3 operations and buckets are most frequently observed in the CloudTrail data.

Panel 2 — S3 Bucket Reconnaissance — Code Explanation
Purpose

Identifies S3 reconnaissance-related API operations such as bucket ACL, bucket policy, and bucket listing activity.

SPL
index=botsv3 sourcetype="aws:cloudtrail" eventSource="s3.amazonaws.com" eventName IN ("GetBucketAcl", "GetBucketPolicy", "ListBuckets")
| spath
| stats count by userIdentity.userName, sourceIPAddress, eventName, requestParameters.bucketName
| sort - count
| head 20
Analysis

This panel provides visibility into S3 reconnaissance activity and associates the operations with the responsible user identity and source IP address.

Panel 3 — RDS Database Activity (Snapshot & Instance Changes)
Purpose

Monitors AWS RDS activity and identifies database-related operations performed by users and source IP addresses.

SPL
index=botsv3 sourcetype="aws:cloudtrail" eventSource="rds.amazonaws.com"
| spath
| stats count by eventName, userIdentity.userName, sourceIPAddress
| sort - count
| head 20
Analysis

This panel provides visibility into RDS API activity and helps analysts investigate database-related changes and the identities responsible for those operations.

Panel 4 — Public S3 Bucket Exposure Check (Critical Misconfiguration)
Purpose

Identifies S3 bucket ACL modification activity and displays the associated access-control grant URI.

SPL
index=botsv3 sourcetype="aws:cloudtrail" eventSource="s3.amazonaws.com" eventName="PutBucketAcl"
| spath
| stats count by userIdentity.userName, sourceIPAddress, requestParameters.bucketName, requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI
| sort - count
Analysis

This panel helps identify S3 bucket ACL changes that may require investigation for potentially unintended or overly permissive access configurations.

Panel 5 — S3 & RDS Combined Activity Timeline (Correlation View)
Purpose

Provides a timeline of S3 and RDS activity to support cross-service event correlation.

SPL
index=botsv3 sourcetype="aws:cloudtrail" (eventSource="s3.amazonaws.com" OR eventSource="rds.amazonaws.com")
| spath
| timechart span=1h count by eventSource
Analysis

This panel allows analysts to compare S3 and RDS activity over time and identify periods where activity across both services increased or occurred concurrently.

Panel 6 — Cross-Service Suspicious Activity (Same User, S3 + RDS Both)
Purpose

Identifies users who performed activity across both S3 and RDS services.

SPL
index=botsv3 sourcetype="aws:cloudtrail" (eventSource="s3.amazonaws.com" OR eventSource="rds.amazonaws.com")
| spath
| stats dc(eventSource) as service_count, count by userIdentity.userName
| where service_count>1
| sort - count
Analysis

This panel highlights users associated with activity across multiple AWS services. Cross-service activity can provide useful context during investigation and correlation.

Investigation Value

The dashboard provides AWS data-service monitoring coverage across:

S3 bucket access activity
S3 reconnaissance
RDS database activity
S3 ACL changes
S3 and RDS activity timelines
Cross-service user activity

These views help analysts investigate cloud storage access, database activity, permission changes, reconnaissance behavior, and activity spanning multiple AWS services.

Related Documentation
findings/BOTSv3-findings.md
mitre/mitre-mapping.md
dashboards/BOTSv3/README.md
