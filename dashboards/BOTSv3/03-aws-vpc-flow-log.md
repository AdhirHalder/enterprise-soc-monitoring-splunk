# AWS VPC Flow Log Dashboard

## Overview

The AWS VPC Flow Log Dashboard provides visibility into network traffic recorded in the BOTSv3 dataset.

The dashboard focuses on accepted and rejected traffic, rejected connection patterns, destination ports targeted during scanning activity, high-volume accepted traffic, and unusual external IP communication.

## Data Source

- Index: `botsv3`
- Sourcetype: `aws:cloudwatchlogs:vpcflow`
- Data Type: AWS VPC Flow Logs

---

## Panel 1 — VPC Traffic Overview (Accept vs Reject)

### Purpose

Provides an overview of accepted and rejected VPC network traffic.

### SPL

spl
index=botsv3 sourcetype="aws:cloudwatchlogs:vpcflow"
| rex field=_raw "^\d+\s+\d+\s+\S+\s+(?<srcaddr>\S+)\s+(?<dstaddr>\S+)\s+(?<srcport>\d+)\s+(?<dstport>\d+)\s+(?<protocol>\d+)\s+(?<packets>\d+)\s+(?<bytes>\d+)\s+\d+\s+\d+\s+(?<action>\w+)"
| stats count by action
| sort - count

Analysis

This panel provides a high-level view of VPC traffic disposition by separating accepted and rejected connections.

Panel 2 — Rejected Connections by Source IP (Port Scanning Detection)
Purpose

Identifies rejected network connections and the source IPs, destination IPs, and destination ports associated with them.

SPL
index=botsv3 sourcetype="aws:cloudwatchlogs:vpcflow"
| rex field=_raw "^\d+\s+\d+\s+\S+\s+(?<srcaddr>\S+)\s+(?<dstaddr>\S+)\s+(?<srcport>\d+)\s+(?<dstport>\d+)\s+(?<protocol>\d+)\s+(?<packets>\d+)\s+(?<bytes>\d+)\s+\d+\s+\d+\s+(?<action>\w+)"
| where action="REJECT"
| stats count by srcaddr, dstaddr, dstport
| sort - count
| head 20
Analysis

Repeated rejected connections can provide useful indicators of possible scanning or probing activity. Source and destination details can be used for further investigation.

Panel 3 — Top Destination Ports Being Scanned
Purpose

Identifies destination ports receiving rejected connections and calculates the number of unique source IPs associated with each port.

SPL
index=botsv3 sourcetype="aws:cloudwatchlogs:vpcflow"
| rex field=_raw "^\d+\s+\d+\s+\S+\s+(?<srcaddr>\S+)\s+(?<dstaddr>\S+)\s+(?<srcport>\d+)\s+(?<dstport>\d+)\s+(?<protocol>\d+)\s+(?<packets>\d+)\s+(?<bytes>\d+)\s+\d+\s+\d+\s+(?<action>\w+)"
| where action="REJECT"
| stats dc(srcaddr) as unique_scanners count by dstport
| sort - unique_scanners
| head 20
Analysis

This panel highlights destination ports targeted by multiple source IPs. Ports with a high number of unique scanners can be prioritized for further investigation.

Panel 4 — Data Exfiltration Detection
Purpose

Identifies high-volume accepted network traffic between source and destination IP addresses by calculating the total number of transferred bytes.

SPL
index=botsv3 sourcetype="aws:cloudwatchlogs:vpcflow"
| rex field=_raw "^\d+\s+\d+\s+\S+\s+(?<srcaddr>\S+)\s+(?<dstaddr>\S+)\s+(?<srcport>\d+)\s+(?<dstport>\d+)\s+(?<protocol>\d+)\s+(?<packets>\d+)\s+(?<bytes>\d+)\s+\d+\s+\d+\s+(?<action>\w+)"
| where action="ACCEPT"
| eval bytes=tonumber(bytes)
| stats sum(bytes) as total_bytes by srcaddr, dstaddr
| eval total_MB=round(total_bytes/1024/1024, 2)
| sort - total_bytes
| head 20
Analysis

This panel highlights source-destination pairs with the highest volume of accepted network traffic. High-volume transfers can be investigated as potential data transfer or exfiltration indicators.

Panel 5 — Traffic to/from Unusual External IPs (Non-AWS Internal Ranges)
Purpose

Identifies accepted traffic involving destination IP addresses that do not match the specified 172.16. range.

SPL
index=botsv3 sourcetype="aws:cloudwatchlogs:vpcflow"
| rex field=_raw "^\d+\s+\d+\s+\S+\s+(?<srcaddr>\S+)\s+(?<dstaddr>\S+)\s+(?<srcport>\d+)\s+(?<dstport>\d+)\s+(?<protocol>\d+)\s+(?<packets>\d+)\s+(?<bytes>\d+)\s+\d+\s+\d+\s+(?<action>\w+)"
| where NOT match(dstaddr, "^172\.16\.") AND action="ACCEPT"
| stats count, sum(bytes) as total_bytes by srcaddr, dstaddr, dstport
| sort - count
| head 20
Analysis

This panel provides visibility into accepted traffic involving destination addresses outside the specified internal range. The resulting source, destination, and port information can support investigation of potentially unusual external communication.

Investigation Value

The dashboard provides VPC network monitoring coverage across:

Accepted vs rejected traffic
Rejected connection patterns
Potential port-scanning activity
High-volume network transfers
Unusual external IP communication

These views can be used together to investigate suspicious network activity and prioritize source-destination relationships for further analysis.

Related Documentation
findings/BOTSv3-findings.md
mitre/mitre-mapping.md
dashboards/BOTSv3/README.md
