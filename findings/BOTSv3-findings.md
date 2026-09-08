# BOTSv3 Findings

## Overview

BOTSv3 was analyzed using Splunk dashboards covering AWS cloud security, network traffic, cloud storage, identity, firewall, data loss prevention, and Linux endpoint security.

The analysis identified reconnaissance activity, suspicious IAM operations, blocked C2 attempts, cloud storage reconnaissance, account compromise indicators, perimeter attack activity, potential data exfiltration staging, and Linux SSH brute-force activity.

## 1. AWS CloudTrail Security

### Key Findings

- IAM user creation and access key generation activities were detected.
- Multiple `GetBucketAcl` and policy enumeration calls were observed.
- The activity suggested reconnaissance of S3 storage permissions.

### MITRE ATT&CK

- **T1098** — Account Manipulation
- **T1619** — Cloud Storage Object Discovery

## 2. AWS GuardDuty

### Key Finding

GuardDuty detected a `Recon:EC2/PortProbeUnprotectedPort` event from:

`122.112.243.11`

The source was identified as China Telecom and targeted SSH port **22** on a production EC2 instance.

The activity was classified as reconnaissance scanning.

### MITRE ATT&CK

**T1595 — Active Scanning**

## 3. AWS VPC Flow Logs

### Key Finding

Internal host:

`192.168.9.50`

attempted **1,000+ connections** to external IP:

`204.107.141.25`

on non-standard port:

`4282`

The connections had a **100% rejection rate**, indicating failed C2 beaconing attempts that were blocked by security controls.

### MITRE ATT&CK

**T1071 — Application Layer Protocol**

## 4. AWS S3/RDS Access

### Key Finding

S3 bucket reconnaissance was detected through multiple:

- `GetBucketAcl`
- `GetBucketPolicy`

calls.

The activity indicated that an attacker was mapping storage access controls before potential exploitation.

### MITRE ATT&CK

- **T1530**
- **T1619**

## 5. Azure AD / O365 Security

### Key Findings

Impossible travel was detected for:

`fyodor@froth.ly`

The account logged in from Hong Kong, followed by Canada approximately 2 hours later, and then the UK within 4 hours.

This represented a physically impossible travel pattern and was identified as an indicator of possible account compromise.

Another user:

`bgist@froth.ly`

showed US-to-Hong Kong login transitions within the same day, supporting a credential-theft scenario.

### MITRE ATT&CK

**T1078 — Valid Accounts**

## 6. Cisco ASA Firewall

### Key Finding

Cisco ASA firewall telemetry showed repeated failed connection attempts associated with suspicious external activity.

The activity was analyzed for scanning, denial-of-service attempts, and anomalous perimeter traffic.

## 7. DLP / Insider Threat

### Key Findings

- A user with employee OneDrive activity accessed personal storage.
- **99 bytes** of file transfers were detected through `Code42 PERSONAL_CLOUD_SCAN_RESULT` events.
- **5 removable media device connection events** were detected.
- **7 personal cloud sync results** were observed.

The combined activity indicated potential multi-channel exfiltration staging.

### MITRE ATT&CK

**T1567.002 — Exfiltration to Cloud Storage**

## 8. Linux Endpoint Security

### Key Findings

SSH brute-force activity was detected from external IPs:

- `121.18.238.115`
- `5.101.40.81`

Multiple invalid login attempts generated:

`Invalid user default`

errors, indicating an automated password-guessing campaign.

A suspicious account named:

`ec2-user`

was also created and immediately added to the `wheel` group, granting sudo privileges.

The timing suggested possible persistence setup.

### MITRE ATT&CK

**T1110.001 — Password Guessing**

## Cross-Source Security Observations

The BOTSv3 analysis demonstrated security monitoring across multiple cloud and endpoint layers:

- AWS IAM activity
- AWS reconnaissance
- Blocked C2 communication
- S3 reconnaissance
- Azure AD account compromise indicators
- O365 identity activity
- Cisco ASA perimeter activity
- Potential cloud-based data exfiltration
- Linux SSH brute-force activity
- Suspicious privileged account creation

## Conclusion

BOTSv3 demonstrated how Splunk can be used to investigate cloud, identity, network, DLP, and endpoint telemetry within a SOC environment.

The findings provide examples of reconnaissance, account manipulation, cloud storage discovery, C2 activity, credential compromise, data exfiltration indicators, and endpoint attack activity.
