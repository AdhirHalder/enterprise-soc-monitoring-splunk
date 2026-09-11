# AWS GuardDuty Alert Dashboard

## Overview

The AWS GuardDuty Alert Dashboard provides visibility into Amazon GuardDuty findings within the BOTSv3 dataset.

The dashboard focuses on finding severity, threat-source geolocation, reconnaissance activity, active threat counts, and GuardDuty findings over time.

## Data Source

- Index: `botsv3`
- Sourcetype: `aws:cloudwatch:guardduty`
- Data Type: AWS GuardDuty Security Findings

---

## Panel 1 — GuardDuty Findings by Severity & Type

### Purpose

Shows GuardDuty findings grouped by severity, finding type, and finding title.

### SPL

spl
index=botsv3 sourcetype="aws:cloudwatch:guardduty"
| stats count by detail.severity, detail.type, detail.title
| sort - count
| head 20

Analysis

This panel provides an overview of the most frequently observed GuardDuty findings and their associated severity levels and types.

Panel 2 — GuardDuty Threat Source Geolocation
Purpose

Displays information about remote IP addresses associated with GuardDuty port-probe findings, including country, organization, and targeted local port.

SPL
index=botsv3 sourcetype="aws:cloudwatch:guardduty"
| table detail.service.action.portProbeAction.portProbeDetails{}.remoteIpDetails.ipAddressV4, detail.service.action.portProbeAction.portProbeDetails{}.remoteIpDetails.country.countryName, detail.service.action.portProbeAction.portProbeDetails{}.remoteIpDetails.organization.org, detail.service.action.portProbeAction.portProbeDetails{}.localPortDetails.port
Analysis

This panel helps analysts examine the geographic and organizational context of remote sources associated with detected port-probing activity.

Panel 3 — GuardDuty Findings by Severity Level
Purpose

Groups GuardDuty findings into High, Medium, Low, and Informational severity categories.

SPL
index=botsv3 sourcetype="aws:cloudwatch:guardduty"
| eval sev=tonumber('detail.severity')
| eval severity_label=case(sev>=7, "High", sev>=4, "Medium", sev>=1, "Low", true(), "Informational")
| stats count by severity_label
Analysis

This panel provides a simplified severity-level view of GuardDuty findings, allowing analysts to quickly assess the distribution of findings by severity.

Panel 4 — Reconnaissance Findings (Port Scanning/Probing Activity)
Purpose

Identifies GuardDuty findings associated with reconnaissance activity.

SPL
index=botsv3 sourcetype="aws:cloudwatch:guardduty"
| spath
| where match('detail.type', "^Recon")
| stats count by detail.type, detail.title
Analysis

This panel focuses on GuardDuty findings whose type begins with Recon, providing visibility into detected reconnaissance-related activity such as port scanning or probing.

Panel 5 — GuardDuty Alert Summary (Single Value — Total Active Threats)
Purpose

Provides a high-level summary of the total GuardDuty findings and the number of unique threat types.

SPL
index=botsv3 sourcetype="aws:cloudwatch:guardduty"
| spath
| stats count as total_findings, dc('detail.type') as unique_threat_types
Analysis

This panel provides a quick summary of the overall GuardDuty finding volume and the diversity of detected threat types.

Panel 6 — GuardDuty Findings Timeline (Attack Detection Over Time)
Purpose

Displays GuardDuty findings over time, grouped by finding type.

SPL
index=botsv3 sourcetype="aws:cloudwatch:guardduty"
| spath
| eval sev=tonumber('detail.severity')
| timechart span=1h count by detail.type
Analysis

This panel helps analysts identify periods of increased GuardDuty activity and correlate findings with other security events occurring during the same timeframe.

Investigation Value

The dashboard provides GuardDuty monitoring coverage across:

Finding severity
Finding type and title
Threat-source geolocation
Reconnaissance activity
Overall finding volume
Threat activity over time

These views support investigation of AWS reconnaissance activity and other security findings detected by GuardDuty.

Related Documentation
findings/BOTSv3-findings.md
mitre/mitre-mapping.md
dashboards/BOTSv3/README.md
