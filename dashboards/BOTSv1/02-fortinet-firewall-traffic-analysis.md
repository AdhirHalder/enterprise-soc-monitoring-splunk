# Fortinet Firewall Traffic Analysis

## Overview

The Fortinet Firewall Traffic Analysis dashboard provides visibility into firewall traffic activity within the BOTSv1 dataset.

The dashboard analyzes allowed and denied traffic, source-destination IP communication pairs, and destination port activity.

## Data Source

- Index: `botsv1`
- Sourcetype: `fgt_traffic`

---

## Panel 1 — Allowed vs Denied Traffic

### Purpose

Shows the distribution of firewall traffic according to the recorded action.

### SPL

spl
index=botsv1 sourcetype=fgt_traffic
| stats count by action

Panel 2 — Top Source-Destination IP Pairs
Purpose

Identifies the source and destination IP pairs generating the highest number of firewall traffic events.

SPL
index=botsv1 sourcetype=fgt_traffic
| stats count by srcip, dstip
| sort -count
| head 10
Panel 3 — Top Destination Ports
Purpose

Identifies the destination ports associated with the highest volume of Fortinet firewall traffic.

SPL
index=botsv1 sourcetype=fgt_traffic
| stats count by dstport
| sort -count
| head 10
Panel 4 — Allowed vs Denied Traffic
Purpose

Provides an additional visualization of the allowed and denied firewall traffic distribution.

SPL
index=botsv1 sourcetype=fgt_traffic
| stats count by action
Panel 5 — Top Source-Destination IP Pairs
Purpose

Provides an additional visualization of the highest-volume source-destination communication pairs.

SPL
index=botsv1 sourcetype=fgt_traffic
| stats count by srcip, dstip
| sort -count
| head 10
Panel 6 — Top Destination Ports
Purpose

Provides an additional visualization of the most frequently observed destination ports.

SPL
index=botsv1 sourcetype=fgt_traffic
| stats count by dstport
| sort -count
| head 10
Investigation Value

The dashboard provides visibility into Fortinet firewall traffic within BOTSv1.

It can be used to:

Compare allowed and denied traffic
Identify high-volume source-destination communication pairs
Identify frequently observed destination ports
Support network traffic investigation
Provide context for further threat hunting
Related Documentation
BOTSv1 Dashboard Overview
BOTSv1 Findings
MITRE ATT&CK Mapping
