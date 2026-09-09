# BOTSv1 Dashboards

This folder contains dashboards developed using the Splunk Boss of the SOC (BOTSv1) dataset for security monitoring, threat hunting, and investigation.

## Dashboards

### 01. SOC Executive Overview
Provides a high-level overview of security events and notable activity across the BOTSv1 dataset.

### 02. Fortinet Firewall Traffic Analysis
Analyzes Fortinet firewall traffic, including accepted and denied network connections and suspicious source activity.

### 03. IDS/IPS Alert Dashboard — Suricata
Provides visibility into Suricata IDS/IPS events and helps identify suspicious network activity and attack patterns.

### 04. Windows Authentication Dashboard
Analyzes Windows authentication activity, including suspicious login behavior and privilege-related events.

### 05. DNS Threat Hunting Dashboard
Investigates DNS activity for suspicious domains, DGA-like behavior, and potential command-and-control activity.

### 06. Threat Intelligence / IOC Correlation Dashboard
Correlates security telemetry with indicators of compromise (IOCs) to support threat investigation and hunting.

## Dataset

- BOTSv1
- Splunk Enterprise
- Suricata
- Fortinet Firewall
- Windows Security Events
- DNS Telemetry
- Threat Intelligence / IOC data

## Investigation Focus

The dashboards support investigation of:

- Network attacks
- Firewall activity
- IDS/IPS alerts
- Suspicious authentication
- DNS anomalies
- Command-and-control indicators
- Indicators of compromise

## Screenshots

Dashboard screenshots are available in this folder.

## MITRE ATT&CK

Relevant activities identified through BOTSv1 analysis were mapped to MITRE ATT&CK techniques in the repository's MITRE mapping documentation.
