# Enterprise SOC Monitoring & Threat Hunting Platform using Splunk

A hands-on Security Operations Center (SOC) project built using Splunk Enterprise for security monitoring, threat hunting, detection engineering, IOC correlation, and real-time attack detection.

## Project Overview

This project simulates an enterprise SOC environment using historical security datasets and a live vulnerable web application.

The platform combines:

- Splunk Enterprise SIEM
- BOTSv1, BOTSv2 and BOTSv3 datasets
- DVWA (Damn Vulnerable Web Application)
- Splunk Universal Forwarder
- Apache/XAMPP logs
- SPL-based threat detection
- IOC correlation
- MITRE ATT&CK mapping
- Real-time security alerts

## Security Monitoring Coverage

The project covers security monitoring across:

- Network Security
- Endpoint Security
- Windows Authentication
- DNS Threat Hunting
- Web Application Security
- Database Security
- Cloud Security
- Identity Security
- Lateral Movement
- Data Loss Prevention
- Threat Intelligence
- Real-Time Attack Monitoring

## Key Attack Scenarios

The project includes detection and analysis of:

- Brute Force / Password Guessing
- SQL Injection
- Cross-Site Scripting (XSS)
- DNS Tunneling
- DGA-based C2 Beaconing
- Lateral Movement
- SMB Enumeration
- Cloud Reconnaissance
- Suspicious IAM Activity
- O365 Administrative Abuse
- C2 Communication
- Data Exfiltration Indicators

## Project Architecture

The platform uses Splunk Enterprise as the central SIEM for collecting, indexing, searching and visualizing security telemetry.

Detailed architecture and data-flow documentation will be added to this repository.

## Dashboards

The project contains dashboards covering BOTSv1, BOTSv2, BOTSv3 and live DVWA attack monitoring.

Dashboard documentation and screenshots will be organized in the repository.

## Detection & Alerting

Real-time Splunk alerts were implemented for:

1. Brute Force Login Attack
2. SQL Injection Attack
3. Cross-Site Scripting Attack

Alerts use detection conditions and throttling to reduce alert flooding.

## MITRE ATT&CK

Detected activities were mapped to relevant MITRE ATT&CK tactics and techniques to support structured threat analysis and detection coverage.

## Tools & Technologies

- Splunk Enterprise
- Splunk Universal Forwarder
- Splunk SPL
- XAMPP
- DVWA
- BOTSv1
- BOTSv2
- BOTSv3
- Suricata
- Palo Alto
- Fortinet
- AWS
- Azure AD / O365
- Cisco ASA
- MITRE ATT&CK

## Project Status

Completed — documentation, dashboards, detection logic, findings and screenshots are being organized for publication.

## Author

**Adhir Halder**

B.Tech Computer Science & Engineering  
Cybersecurity
