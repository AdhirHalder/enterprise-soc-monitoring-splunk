# Detection Engineering & Investigation Workflow

This document describes the detection engineering and SOC investigation workflow used in the Enterprise SOC Monitoring & Threat Hunting Platform using Splunk.

## 1. Detection Engineering Overview

The project follows a structured detection engineering process to identify suspicious activity from security telemetry.

The workflow consists of:

1. Identify the security monitoring objective.
2. Explore the available data source and sourcetype.
3. Analyze available fields and event structure.
4. Develop an SPL-based detection query.
5. Test the detection against available security events.
6. Validate the detected activity.
7. Convert the detection logic into a dashboard panel or alert.
8. Apply severity and throttling where required.
9. Document the detection and investigation findings.
10. Map the detected behavior to MITRE ATT&CK where applicable.

## 2. Data Sources

The project uses multiple security telemetry sources.

### BOTSv1

- Fortinet firewall logs
- Suricata IDS/IPS events
- Windows Security events
- DNS telemetry
- IOC-related activity
- Windows registry activity

### BOTSv2

- Palo Alto firewall logs
- MySQL/database logs
- Symantec Endpoint Protection
- Office 365 activity
- SMB telemetry
- LDAP telemetry
- Web application logs
- Windows Security events

### BOTSv3

- AWS CloudTrail
- AWS GuardDuty
- AWS VPC Flow Logs
- AWS S3/RDS activity
- Azure AD/O365
- Cisco ASA
- DLP/Code42 telemetry
- Linux security telemetry

### DVWA

- DVWA authentication logs
- DVWA SQL Injection logs
- DVWA XSS logs
- Apache access logs

## 3. SPL Detection Development

Splunk Processing Language (SPL) is used to develop detection logic and investigate security events.

Common SPL commands used throughout the project include:

- `stats`
- `timechart`
- `eval`
- `rex`
- `spath`
- `mvexpand`
- `search`
- `where`
- `sort`
- `head`
- `streamstats`

Detection queries are developed according to the structure of each individual data source.

## 4. Brute Force Detection

The DVWA brute force detection monitors authentication activity for repeated failed login attempts.

The detection analyzes:

- Source IP
- Username
- Authentication result
- Target URI
- Authentication timeline

The documented detection logic identifies repeated failed authentication attempts from a source IP.

The corresponding alert is:

`Brute_Force_Attack_Detected`

Severity:

`High`

The alert configuration uses throttling to reduce repeated notifications from the same source.

Detailed documentation:

[detections/brute-force.md](../detections/brute-force.md)

[alerts/brute-force-alert.md](../alerts/brute-force-alert.md)

## 5. SQL Injection Detection

The DVWA SQL Injection detection monitors SQL injection activity recorded in the `dvwa:sqli` sourcetype.

Detection indicators include SQL injection payload patterns such as:

- `UNION SELECT`
- `OR 1=1`
- `--`

The corresponding alert is:

`SQL_Injection_Attack_Detected`

Severity:

`High`

The documented alert maps the activity to MITRE ATT&CK technique `T1190 - Exploit Public-Facing Application`.

Detailed documentation:

[detections/sql-injection.md](../detections/sql-injection.md)

[alerts/sql-injection-alert.md](../alerts/sql-injection-alert.md)

## 6. Cross-Site Scripting Detection

The DVWA XSS detection monitors payloads recorded in the `dvwa:xss` sourcetype.

Detection patterns include:

- `<script>`
- `onerror=`
- `javascript:`

The corresponding alert is:

`DVWA - XSS Attack Detected`

Severity:

`Medium`

The alert configuration includes throttling to reduce repeated alert generation from the same source IP.

No specific MITRE ATT&CK technique ID is assigned to the XSS detection in the project documentation.

Detailed documentation:

[detections/xss.md](../detections/xss.md)

[alerts/xss-alert.md](../alerts/xss-alert.md)

## 7. Dashboard-Based Detection

Security dashboards provide visual investigation and detection capabilities across the available datasets.

Dashboard panels are developed by:

1. Selecting the relevant index and sourcetype.
2. Extracting required fields.
3. Filtering relevant events.
4. Aggregating events using SPL.
5. Identifying suspicious patterns.
6. Visualizing the results.
7. Documenting the observed findings.

The repository contains individual SPL documentation for all 24 dashboards.

## 8. Threat Hunting Workflow

The threat hunting process follows a hypothesis-driven investigation approach.

### Step 1 — Identify Suspicious Activity

Investigate unusual:

- Event volumes
- Source IP addresses
- Destination IP addresses
- User accounts
- Domains
- Ports
- Authentication activity
- Cloud activity
- Network connections

### Step 2 — Analyze Related Events

Use SPL to investigate related events across the relevant sourcetypes.

### Step 3 — Correlate Indicators

Correlate indicators such as:

- IP addresses
- Domains
- Usernames
- Hostnames
- URLs
- Attack payloads
- Authentication activity

### Step 4 — Determine Security Context

Assess whether the observed activity represents:

- Reconnaissance
- Authentication attack
- Exploitation
- Lateral movement
- Command and control
- Privilege escalation
- Data access
- Data exfiltration indicators

### Step 5 — Document Findings

Important findings are documented with supporting evidence, relevant security context, and MITRE ATT&CK mappings where applicable.

## 9. Alert Investigation Workflow

When a detection condition is triggered, the investigation follows this general process:


Security Event
      ↓
SPL Detection
      ↓
Detection Match
      ↓
Alert Generation
      ↓
Source / User / Host Analysis
      ↓
Related Event Correlation
      ↓
Security Investigation
      ↓
Finding Documentation
      ↓
MITRE ATT&CK Mapping
