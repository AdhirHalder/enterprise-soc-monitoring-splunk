# BOTSv3 Dashboards

This folder contains dashboards developed using the Splunk Boss of the SOC (BOTSv3) dataset for cloud, network, identity, endpoint, and data security monitoring.

## Dashboards

### 01. AWS CloudTrail Security Dashboard
Analyzes AWS CloudTrail activity to identify suspicious API activity, IAM changes, and potential cloud security incidents.

### 02. AWS GuardDuty Alert Dashboard
Provides visibility into GuardDuty findings, including reconnaissance and suspicious network activity.

### 03. AWS VPC Flow Log Dashboard
Analyzes VPC Flow Logs to identify suspicious network connections, rejected traffic, and potential communication with external infrastructure.

### 04. AWS S3/RDS Access Dashboard
Monitors AWS S3 and RDS-related activity, including access patterns and potential reconnaissance or unauthorized activity.

### 05. Azure AD/O365 Security Dashboard
Analyzes Azure AD and Office 365 security activity, including authentication and administrative events.

### 06. Cisco ASA Firewall Dashboard
Analyzes Cisco ASA firewall events to identify suspicious connections, failed attempts, and potential command-and-control activity.

### 07. DLP / Insider Threat Dashboard
Provides visibility into data movement and potential data-loss indicators involving personal storage, removable media, and personal cloud services.

### 08. Linux Endpoint Security Dashboard
Analyzes Linux endpoint security events, including SSH authentication activity and suspicious account or privilege-related behavior.

## Dataset

- BOTSv3
- AWS CloudTrail
- AWS GuardDuty
- AWS VPC Flow Logs
- AWS S3/RDS
- Azure AD / O365
- Cisco ASA
- DLP telemetry
- Linux endpoint telemetry

## Investigation Focus

The dashboards support investigation of:

- Cloud security events
- IAM activity
- Cloud reconnaissance
- Network reconnaissance
- Firewall activity
- Identity and authentication anomalies
- Data-loss indicators
- Linux endpoint activity
- Suspicious external communication

## Screenshots

Dashboard screenshots are available in this folder.

## MITRE ATT&CK

Relevant activities identified through BOTSv3 analysis were mapped to MITRE ATT&CK techniques in the repository's MITRE mapping documentation.
