# SOC Executive Overview

## Overview

The SOC Executive Overview dashboard provides a high-level view of security activity within the BOTSv1 dataset.

The dashboard summarizes event volume, source IP activity, targeted destination IPs, Suricata event types, network protocols, and event activity over time.

## Data Source

- Index: `botsv1`
- Primary security telemetry: BOTSv1
- Suricata telemetry: `sourcetype=suricata`

---

## Panel 1 — Total Events by Sourcetype

### Purpose

Shows the total number of events grouped by sourcetype. This provides an overview of the different types of security telemetry available in the BOTSv1 dataset.

### SPL

spl
index=botsv1
| stats count by sourcetype
| sort -count


Analysis

The query counts events for each sourcetype and sorts the results in descending order, allowing the analyst to quickly identify the most prevalent sources of security telemetry.

Panel 2 — Top 10 Source IP
Purpose

Identifies the top 10 source IP addresses generating events in the BOTSv1 dataset.

SPL

index=botsv1
| top limit=10 src_ip

Analysis

The query uses the top command to identify the source IP addresses associated with the highest event activity.

These IPs can be further investigated for suspicious or anomalous behavior.

Panel 3 — Top Targeted Destination IPs
Purpose

Identifies the destination IP addresses receiving the highest volume of Suricata events.

SPL

index=botsv1 sourcetype=suricata
| spath dest_ip
| stats count by dest_ip
| sort -count
| head 10

Analysis

The query extracts the dest_ip field from Suricata events and ranks the destination IP addresses by event count.

This helps identify systems that may be receiving a high volume of network security events.

Panel 4 — Suricata Event Type Distribution
Purpose

Provides a distribution of Suricata event types within the BOTSv1 dataset.

SPL

index=botsv1 sourcetype=suricata
| spath event_type
| stats count by event_type
| sort -count

Analysis

The query extracts the Suricata event_type field and counts events for each type.

This provides visibility into the different categories of network security events recorded by Suricata.

Panel 5 — Protocol-wise Traffic Breakdown
Purpose

Shows the distribution of network traffic according to protocol.

SPL

index=botsv1 sourcetype=suricata
| spath proto
| stats count by proto
| sort -count

Analysis

The query extracts the protocol field from Suricata events and calculates the number of events associated with each protocol.

This helps analysts understand the protocol composition of observed network activity.

Panel 6 — Events Over Time
Purpose

Visualizes the volume of security events over time.

SPL

index=botsv1
| timechart span=1h count

Analysis

The query generates an hourly time series of events.

This allows analysts to identify periods of increased or decreased security activity and provides temporal context for further investigation.

Investigation Value

The dashboard provides an initial SOC-level view of the BOTSv1 environment.

It can be used to:

Understand overall event volume
Identify high-volume source IPs
Identify heavily targeted destination IPs
Analyze Suricata event categories
Understand protocol distribution
Identify changes in event activity over time

The dashboard can serve as an initial investigation point before moving into more specialized BOTSv1 dashboards.

Related Documentation
BOTSv1 Dashboard Overview
BOTSv1 Findings
MITRE ATT&CK Mapping
