# Palo Alto Firewall Dashboard

## Overview

The Palo Alto Firewall Dashboard provides visibility into firewall traffic activity within the BOTSv2 dataset.

The dashboard analyzes allowed and denied traffic, source-destination communication pairs, destination ports, applications, traffic activity over time, and high-risk applications.

## Data Source

- Index: `botsv2`
- Sourcetype: `pan:traffic`

---

## Panel 1 — Allowed vs Denied Traffic

### Purpose

Shows the distribution of Palo Alto firewall traffic according to the recorded action.

### SPL

spl
index=botsv2 sourcetype=pan:traffic
| stats count by action
| sort -count

Analysis

The query counts firewall events by the action field and sorts the results in descending order.

Panel 2 — Top Source-Destination IP Pairs
Purpose

Identifies the source and destination IP address pairs generating the highest volume of Palo Alto firewall events.

SPL
index=botsv2 sourcetype=pan:traffic
| stats count by src_ip, dest_ip
| sort -count
| head 10
Analysis

The query groups firewall events by source and destination IP addresses and displays the top 10 communication pairs based on event count.

Panel 3 — Top Destination Ports
Purpose

Identifies the most frequently observed destination ports and associated protocols.

SPL
index=botsv2 sourcetype=pan:traffic
| stats count by dest_port, protocol
| sort -count
| head 10
Analysis

The query groups firewall traffic by destination port and protocol and displays the top 10 combinations based on event count.

Panel 4 — Top Applications (Palo Alto App-ID)
Purpose

Identifies the applications generating the highest volume of Palo Alto firewall traffic.

SPL
index=botsv2 sourcetype=pan:traffic
| stats count by app
| sort -count
| head 10
Analysis

The query groups traffic events by the Palo Alto app field and displays the top 10 applications based on event count.

Panel 5 — Traffic Volume Over Time
Purpose

Visualizes Palo Alto firewall traffic activity over time.

SPL
index=botsv2 sourcetype=pan:traffic
| timechart span=1h count
Analysis

The query generates an hourly time series of Palo Alto firewall events, providing visibility into changes in traffic activity over time.

Panel 6 — High Risk Application
Purpose

Identifies applications associated with higher Palo Alto application risk ratings.

SPL
index=botsv2 sourcetype=pan:traffic
| rename "app:risk" as app_risk
| stats count by app, app_risk
| where app_risk >= 4
| sort -count
| head 10
Analysis

The query renames the Palo Alto application risk field to app_risk, groups events by application and risk level, and filters for applications with a risk value of 4 or higher.

The top 10 matching applications are displayed based on event count.

Investigation Value

The dashboard provides multiple views of Palo Alto firewall telemetry.

It can be used to:

Compare allowed and denied firewall traffic
Identify high-volume source-destination communication
Analyze frequently observed destination ports
Identify commonly observed applications
Monitor firewall activity over time
Investigate higher-risk applications
Support network security threat hunting
Related Documentation
BOTSv2 Dashboard Overview
BOTSv2 Findings
MITRE ATT&CK Mapping
