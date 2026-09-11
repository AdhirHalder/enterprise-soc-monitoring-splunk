# DNS Threat Hunting Dashboard

## Overview

The DNS Threat Hunting Dashboard provides visibility into DNS activity within the BOTSv1 dataset.

The dashboard analyzes queried domains, DNS query types, potentially suspicious long domain names, DNS-querying hosts, NXDOMAIN activity, and DNS response-code distribution.

## Data Source

- Index: `botsv1`
- Sourcetype: `stream:dns`

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

The query expands the DNS query field and ranks the top 10 queried domains based on event count.

Panel 2 — DNS Query Type Breakdown
Purpose

Shows the distribution of DNS query types observed in the DNS telemetry.

SPL
index=botsv1 sourcetype=stream:dns
| mvexpand query_type{}
| stats count by query_type{}
| sort -count
Analysis

The query expands the DNS query type field and calculates the number of events associated with each query type.

Panel 3 — Suspicious Long Domain Names (DGA Detection)
Purpose

Identifies unusually long DNS domain names that may warrant investigation for potential DGA-related activity.

SPL
index=botsv1 sourcetype=stream:dns
| mvexpand query{}
| rename query{} as domain
| eval domain_length=len(domain)
| where domain_length > 30
| stats count by domain
| sort -count
| head 10
Analysis

The query expands DNS queries, renames the query field to domain, calculates the domain length, and filters domains longer than 30 characters.

The resulting domains are ranked by frequency for further investigation.

Panel 4 — Top DNS Querying Hosts
Purpose

Identifies the source hosts generating the highest number of DNS queries.

SPL
index=botsv1 sourcetype=stream:dns
| stats count by src_ip
| sort -count
| head 10
Analysis

The query counts DNS events for each source IP and displays the top 10 DNS-querying hosts.

This helps identify hosts generating significant DNS activity.

Panel 5 — NXDOMAIN Response Trend
Purpose

Visualizes NXDOMAIN responses over time.

SPL
index=botsv1 sourcetype=stream:dns
| mvexpand reply_code{}
| search reply_code{}="NXDOMAIN"
| timechart span=1h count
Analysis

The query filters DNS responses with an NXDOMAIN response code and generates an hourly time series.

This provides visibility into changes in NXDOMAIN activity over time.

Panel 6 — DNS Response Code Distribution
Purpose

Shows the distribution of DNS response codes observed in the dataset.

SPL
index=botsv1 sourcetype=stream:dns
| mvexpand reply_code{}
| stats count by reply_code{}
| sort -count
Analysis

The query expands the DNS response-code field and calculates the frequency of each response code.

This provides an overview of DNS response behavior within the monitored telemetry.

Investigation Value

The dashboard provides multiple views for DNS-focused threat hunting.

It can be used to:

Identify frequently queried domains
Analyze DNS query types
Investigate unusually long domain names
Identify hosts generating high DNS query volumes
Monitor NXDOMAIN activity over time
Analyze DNS response-code distribution
Support investigation of suspicious DNS behavior
Related Documentation
BOTSv1 Dashboard Overview
BOTSv1 Findings
MITRE ATT&CK Mapping
