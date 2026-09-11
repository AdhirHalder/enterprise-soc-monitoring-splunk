# Symantec Endpoint Protection Dashboard

## Overview

The Symantec Endpoint Protection Dashboard provides visibility into endpoint security events within the BOTSv2 dataset.

The dashboard analyzes security events by severity, intrusion detection signatures, attacker source IPs, and security activity over time.

## Data Source

- Index: `botsv2`
- Sourcetype: `symantec:ep:security:file`

---

## Panel 1 — Top Security Events by Severity

### Purpose

Shows the distribution of Symantec Endpoint Protection security events according to severity.

### SPL

spl
index=botsv2 sourcetype=symantec:ep:security:file
| stats count by severity
| sort -count

Analysis

The query groups security events by their severity level and sorts the results by event count.

This provides an overview of the severity distribution of endpoint security activity.

Panel 2 — Top Intrusion Detection Signature
Purpose

Identifies the most frequently observed intrusion detection signatures.

SPL
index=botsv2 sourcetype=symantec:ep:security:file
| stats count by signature
| sort -count
| head 10
Analysis

The query groups security events by intrusion detection signature and displays the top 10 signatures based on event count.

Panel 3 — Top Attacker Source IPs
Purpose

Identifies source IP addresses associated with the highest number of Symantec security events.

SPL
index=botsv2 sourcetype=symantec:ep:security:file
| stats count by src_ip
| sort -count
| head 10
Analysis

The query groups security events by source IP address and displays the top 10 source IPs based on event count.

These IPs can be further investigated as part of endpoint security analysis.

Panel 4 — Security Events Over Time
Purpose

Visualizes Symantec Endpoint Protection security events over time, separated by severity.

SPL
index=botsv2 sourcetype=symantec:ep:security:file
| timechart span=1h count by severity
Analysis

The query creates an hourly time series of security events and separates the activity according to severity.

This provides temporal visibility into changes in endpoint security activity.

Investigation Value

The dashboard provides multiple views of Symantec Endpoint Protection telemetry.

It can be used to:

Analyze endpoint security events by severity
Identify frequently observed intrusion detection signatures
Identify high-volume attacker source IPs
Monitor endpoint security activity over time
Support endpoint threat hunting and investigation
Related Documentation
BOTSv2 Dashboard Overview
BOTSv2 Findings
MITRE ATT&CK Mapping
