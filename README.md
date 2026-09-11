# Enterprise SOC Monitoring & Threat Hunting Platform using Splunk

A hands-on Security Operations Center (SOC) project built using Splunk Enterprise for security monitoring, threat hunting, detection engineering, IOC correlation, security analytics, and real-time web attack detection.

## Project Overview

This project simulates an enterprise SOC environment using historical security datasets and a live vulnerable web application.

The platform combines:

- Splunk Enterprise SIEM
- Splunk Universal Forwarder
- BOTSv1, BOTSv2 and BOTSv3 security datasets
- DVWA (Damn Vulnerable Web Application)
- Apache/XAMPP logs
- SPL-based threat detection
- Threat hunting and security analytics
- IOC correlation
- MITRE ATT&CK mapping
- Real-time security monitoring and alerting

## Project Architecture

The lab environment uses Splunk Enterprise as the central SIEM platform.

### Main Data Flow

DVWA  
↓  
Apache / XAMPP Logs  
↓  
Splunk Universal Forwarder  
↓  
TCP :9997  
↓  
Splunk Enterprise  
↓  
Detection → Threat Hunting → Dashboards → Alerts → MITRE ATT&CK

Historical BOTSv1, BOTSv2 and BOTSv3 datasets are also analyzed directly in Splunk.

[Architecture Documentation](architecture/architecture.md)

[Architecture Diagram](architecture/SOC-architecture.png)

## Security Monitoring Coverage

- Network Security
- Firewall Monitoring
- IDS/IPS Monitoring
- Windows Authentication
- Linux Endpoint Security
- DNS Threat Hunting
- Web Application Security
- Database Security
- Cloud Security
- Identity Security
- Lateral Movement
- Data Loss Prevention
- Threat Intelligence / IOC Correlation
- Real-Time Attack Monitoring

## Dashboards

The project contains 24 documented Splunk dashboards across BOTSv1, BOTSv2, BOTSv3 and DVWA.

### BOTSv1

1. [SOC Executive Overview](dashboards/BOTSv1/01-soc-executive-overview.md)
2. [Fortinet Firewall Traffic Analysis](dashboards/BOTSv1/02-fortinet-firewall-traffic-analysis.md)
3. [IDS/IPS Alert Dashboard – Suricata](dashboards/BOTSv1/03-ids-ips-suricata.md)
4. [Windows Authentication Dashboard](dashboards/BOTSv1/04-windows-authentication.md)
5. [DNS Threat Hunting Dashboard](dashboards/BOTSv1/05-dns-threat-hunting.md)
6. [Threat Intel / IOC Correlation Dashboard](dashboards/BOTSv1/06-threat-intel-ioc-correlation.md)

### BOTSv2

7. [Palo Alto Firewall Dashboard](dashboards/BOTSv2/01-palo-alto-firewall.md)
8. [MySQL / Database Attack Dashboard](dashboards/BOTSv2/02-mysql-database-attack.md)
9. [Symantec Endpoint Protection Dashboard](dashboards/BOTSv2/03-symantec-endpoint-protection.md)
10. [O365 Activity Dashboard](dashboards/BOTSv2/04-o365-activity.md)
11. [Lateral Movement Dashboard](dashboards/BOTSv2/05-lateral-movement.md)
12. [Web Application Attack Dashboard](dashboards/BOTSv2/06-web-application-attack.md)

### BOTSv3

13. [AWS CloudTrail Security Dashboard](dashboards/BOTSv3/01-aws-cloudtrail-security.md)
14. [AWS GuardDuty Alert Dashboard](dashboards/BOTSv3/02-aws-guardduty-alert.md)
15. [AWS VPC Flow Log Dashboard](dashboards/BOTSv3/03-aws-vpc-flow-log.md)
16. [AWS S3/RDS Access Dashboard](dashboards/BOTSv3/04-aws-s3-rds-access.md)
17. [Azure AD/O365 Security Dashboard](dashboards/BOTSv3/05-azure-ad-o365-security.md)
18. [Cisco ASA Firewall Dashboard](dashboards/BOTSv3/06-cisco-asa-firewall.md)
19. [DLP / Insider Threat Dashboard](dashboards/BOTSv3/07-dlp-insider-threat.md)
20. [Linux Endpoint Security Dashboard](dashboards/BOTSv3/08-linux-endpoint-security.md)

### DVWA – Real-Time Attack Monitoring

21. [DVWA Brute Force Attack Dashboard](dashboards/DVWA/01-dvwa-brute-force.md)
22. [DVWA SQL Injection Attack Dashboard](dashboards/DVWA/02-dvwa-sql-injection.md)
23. [DVWA XSS Attack Dashboard](dashboards/DVWA/03-dvwa-xss.md)
24. [Unified DVWA SOC Console](dashboards/DVWA/04-unified-soc-console.md)

Dashboard screenshots are stored within their respective dashboard directories.

## Detection Engineering

The project includes SPL-based detection logic for:

- Brute Force
- SQL Injection
- Cross-Site Scripting (XSS)

Detection documentation:

- [Brute Force Detection](detections/brute-force.md)
- [SQL Injection Detection](detections/sql-injection.md)
- [XSS Detection](detections/xss.md)

## Security Alerts

Real-time Splunk alerts were configured for:

1. Brute Force Login Attack
2. SQL Injection Attack
3. Cross-Site Scripting Attack

Alert documentation:

- [Brute Force Alert](alerts/brute-force-alert.md)
- [SQL Injection Alert](alerts/sql-injection-alert.md)
- [XSS Alert](alerts/xss-alert.md)

> Note: Alert rules and notification actions are documented. External email delivery remains subject to SMTP configuration and validation.

## Threat Hunting & Findings

The project contains documented findings from:

- BOTSv1
- BOTSv2
- BOTSv3
- DVWA

Findings include suspicious network activity, authentication anomalies, DNS activity, cloud reconnaissance, IAM activity, lateral movement indicators, endpoint activity, DLP events, and web application attack activity.

- [BOTSv1 Findings](findings/BOTSv1-findings.md)
- [BOTSv2 Findings](findings/BOTSv2-findings.md)
- [BOTSv3 Findings](findings/BOTSv3-findings.md)
- [DVWA Findings](findings/DVWA-findings.md)

## MITRE ATT&CK Mapping

Detected activities are mapped to relevant MITRE ATT&CK tactics and techniques to provide structured threat analysis and detection coverage.

[MITRE ATT&CK Mapping](mitre/mitre-mapping.md)

## Tools & Technologies

### SIEM / SOC

- Splunk Enterprise 10.4.1
- Splunk Universal Forwarder 10.4.1
- Splunk SPL
- Splunk Common Information Model (CIM)

### Web Security

- DVWA
- Apache / XAMPP
- Burp Suite
- SQL Injection
- Cross-Site Scripting
- Brute Force Detection

### Network Security

- Suricata
- Fortinet
- Palo Alto
- Cisco ASA

### Cloud Security

- AWS CloudTrail
- AWS GuardDuty
- AWS VPC Flow Logs
- AWS S3 / RDS
- Azure AD / O365

### Endpoint / Data Security

- Windows Security Logs
- Linux Security Logs
- Symantec Endpoint Protection
- Code42 / DLP telemetry

## Repository Structure


enterprise-soc-monitoring-splunk/
├── README.md
├── LICENSE
├── .gitignore
├── architecture/
│   ├── architecture.md
│   └── SOC-architecture.png
├── dashboards/
│   ├── BOTSv1/
│   ├── BOTSv2/
│   ├── BOTSv3/
│   └── DVWA/
├── detections/
│   ├── brute-force.md
│   ├── sql-injection.md
│   └── xss.md
├── alerts/
│   ├── brute-force-alert.md
│   ├── sql-injection-alert.md
│   └── xss-alert.md
├── findings/
│   ├── BOTSv1-findings.md
│   ├── BOTSv2-findings.md
│   ├── BOTSv3-findings.md
│   └── DVWA-findings.md
├── mitre/
│   └── mitre-mapping.md
└── docs/
    ├── setup.md
    ├── methodology.md
    └── detection-workflow.md

Project Status

Core implementation and technical documentation completed.

The repository contains:

24 dashboard-specific SPL documentation files
Dashboard screenshots
Detection logic
Alert documentation
Threat hunting findings
MITRE ATT&CK mapping
SOC architecture documentation
Setup documentation
Project methodology
Detection engineering workflow

Final repository quality checks and presentation polish are being completed.

Author

Adhir Halder

B.Tech Computer Science & Engineering
Cybersecurity    
