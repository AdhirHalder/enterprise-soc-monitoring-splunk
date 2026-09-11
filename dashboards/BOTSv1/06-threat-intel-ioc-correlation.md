# Threat Intel / IOC Correlation Dashboard

## Overview

The Threat Intel / IOC Correlation Dashboard provides visibility into indicators of compromise (IOCs) observed across BOTSv1 security telemetry.

The dashboard correlates suspicious DNS domains, external IP communication, IOC matches across data sources, severity-tagged IOC activity, and registry changes.

## Data Sources

- Index: `botsv1`
- Sourcetypes:
  - `stream:dns`
  - `fgt_traffic`
  - `winregistry`

---

## Panel 1 — Top Queried Domains

### Purpose

Identifies the most frequently queried DNS domains observed in the BOTSv1 dataset.

### SPL

spl
index=botsv1 sourcetype=stream:dns
| mvexpand query{}
| stats count by query{}
| sort -count
| head 10

Analysis

The query expands DNS query values and ranks the top 10 queried domains based on event count.

Panel 2 — Known Malicious IP Hits in Firewall Logs
Purpose

Identifies DNS domains matching the predefined suspicious indicators used in the dashboard.

SPL
index=botsv1 sourcetype=stream:dns
| mvexpand query{}
| rename query{} as domain 
| eval 
malicious=if(domain="EJFDEBFEEBFACACACACACACACACACAAA" OR domain="FHFAEBEECACACACACACACACACACACAAA" OR domain="wpad" OR domain="isatap", "YES", "NO")
| where malicious="YES"
| stats count by domain, malicious 
| sort -count
Analysis

The query compares observed DNS domains against predefined suspicious domain indicators.

Matching domains are marked as YES and ranked according to their observed frequency.

Panel 3 — Suspicious External IP Communication Timeline
Purpose

Visualizes communication activity involving predefined suspicious external IP addresses over time.

SPL
index=botsv1 sourcetype=fgt_traffic
| eval malicious=if(srcip="93.174.93.94" OR srcip="192.254.66.174" OR scrip="108.61.28.155" OR srcip="183.60.48.25", "YES", "NO")
| where malicious="YES"
| timechart span=1h count by srcip
Analysis

The query evaluates firewall traffic against a predefined list of suspicious IP addresses.

Matching traffic is filtered and visualized as an hourly timeline grouped by source IP.

Panel 4 — IOC Match Count by Source
Purpose

Provides a count of IOC-related activity across firewall and DNS data sources.

SPL
index=botsv1 (sourcetype=fgt_traffic OR sourcetype=stream:dns)
| eval ioc_type=case(
    sourcetype="fgt_traffic", "Malicious IP",
    sourcetype="stream:dns", "Malicious Domain")
| eval ioc_found=if(
    (sourcetype="fgt_traffic" AND (srcip="93.174.93.94" OR srcip="192.254.66.174" OR srcip="108.61.28.155" OR srcip="183.60.48.25")) OR
    (sourcetype="stream:dns"), "YES", "NO")
| where ioc_found="YES"
| stats count by ioc_type
Analysis

The query categorizes firewall telemetry as Malicious IP and DNS telemetry as Malicious Domain.

It then counts the resulting IOC activity by source category.

Panel 5 — Severity-Tagged IOC Alert Table
Purpose

Displays suspicious firewall communication with a severity classification based on the observed event count.

SPL
index=botsv1 sourcetype=fgt_traffic
| eval malicious=if(srcip="93.174.93.94" OR srcip="192.254.66.174" OR srcip="108.61.28.155" OR srcip="183.60.48.25", "YES", "NO")
| where malicious="YES"
| stats count by srcip, dstip, dstport, action
| eval severity=case(
    count>100, "High",
    count>50, "Medium",
    count<=50, "Low")
| table srcip, dstip, dstport, action, severity
| sort -count
Analysis

The query filters firewall traffic involving predefined suspicious source IP addresses.

It groups the activity by source IP, destination IP, destination port, and firewall action.

The resulting activity is assigned a severity level based on event count:

High — more than 100 events
Medium — more than 50 events
Low — 50 or fewer events
Panel 6 — Suspicious Registry Changes
Purpose

Identifies registry paths with the highest number of recorded events.

SPL
index=botsv1 sourcetype=winregistry
| stats count by key_path
| sort -count
| head 10
Analysis

The query analyzes Windows registry telemetry and ranks the top 10 registry paths based on event count.

This provides visibility into registry activity that may require further investigation.

Investigation Value

The dashboard provides IOC-focused visibility across multiple security data sources.

It can be used to:

Identify frequently queried domains
Detect predefined suspicious DNS indicators
Monitor communication with suspicious IP addresses
Correlate IOC activity across DNS and firewall telemetry
Prioritize IOC activity using severity tags
Investigate registry activity
Support threat intelligence-driven threat hunting
Related Documentation
BOTSv1 Dashboard Overview
BOTSv1 Findings
MITRE ATT&CK Mapping
