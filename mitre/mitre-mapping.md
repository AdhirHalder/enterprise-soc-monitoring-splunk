# MITRE ATT&CK Mapping

## Overview

The project maps identified security activities to relevant MITRE ATT&CK techniques and tactics to support structured threat analysis and detection coverage.

## BOTSv1

| Dashboard / Activity | MITRE ID | Technique | Tactic |
|---|---|---|---|
| SOC Executive Overview | T1595 | Active Scanning | Reconnaissance |
| Fortinet Firewall Traffic Analysis | T1071 | Application Layer Protocol | Command and Control |
| IDS/IPS Alert Dashboard | T1568.002 | Dynamic Resolution: Domain Generation Algorithms | Command and Control |
| Windows Authentication Dashboard | T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| Windows Authentication Dashboard | T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| DNS Threat Hunting Dashboard | T1071.004 | DNS | Command and Control |
| DNS Threat Hunting Dashboard | T1557 | Adversary-in-the-Middle | Credential Access |
| Threat Intel / IOC Correlation | T1547.001 | Registry Run Keys / Startup Folder | Persistence |

## BOTSv2

| Dashboard / Activity | MITRE ID | Technique | Tactic |
|---|---|---|---|
| Palo Alto Firewall Dashboard | T1071 | Application Layer Protocol | Command and Control |
| MySQL / Database Attack Dashboard | T1110 | Brute Force | Credential Access |
| MySQL / Database Attack Dashboard | T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| O365 Activity Dashboard | T1098 | Account Manipulation | Persistence |
| O365 Activity Dashboard | T1562 | Impair Defenses | Defense Evasion |
| Lateral Movement Dashboard | T1135 | Network Share Discovery | Discovery |
| Lateral Movement Dashboard | T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| Lateral Movement Dashboard | T1087 | Account Discovery | Discovery |
| Web Application Attack Dashboard | T1595 | Active Scanning | Reconnaissance |

## BOTSv3

| Dashboard / Activity | MITRE ID | Technique | Tactic |
|---|---|---|---|
| AWS CloudTrail Security Dashboard | T1098 | Account Manipulation | Persistence |
| AWS CloudTrail Security Dashboard | T1619 | Cloud Storage Object Discovery | Discovery |
| AWS GuardDuty Alert Dashboard | T1595 | Active Scanning | Reconnaissance |
| AWS VPC Flow Log Dashboard | T1071 | Application Layer Protocol | Command and Control |
| AWS S3/RDS Access Dashboard | T1530 | Data from Cloud Storage Object | Collection |
| AWS S3/RDS Access Dashboard | T1619 | Cloud Storage Object Discovery | Discovery |
| Azure AD/O365 Security Dashboard | T1078 | Valid Accounts | Defense Evasion / Persistence / Privilege Escalation / Initial Access |
| DLP/Insider Threat Dashboard | T1567.002 | Exfiltration to Cloud Storage | Exfiltration |
| Linux Endpoint Security Dashboard | T1110.001 | Password Guessing | Credential Access |

## DVWA

### Brute Force

**T1110.001 — Password Guessing**

Repeated failed authentication attempts against the DVWA Brute Force page were mapped to Password Guessing.

### SQL Injection

**T1190 — Exploit Public-Facing Application**

The project documentation maps the SQL Injection activity to Exploit Public-Facing Application.

### Cross-Site Scripting (XSS)

The project documentation describes XSS as a web application attack / XSS detection scenario but does not assign a specific MITRE ATT&CK technique ID.

## Mapping Purpose

MITRE ATT&CK mapping provides a standardized way to describe observed attacker behaviors and connect security detections with adversary tactics and techniques.
