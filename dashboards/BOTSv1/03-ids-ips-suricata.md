# IDS/IPS Alert Dashboard (Suricata)

## Overview

The IDS/IPS Alert Dashboard provides visibility into network security activity collected through Suricata within the BOTSv1 dataset.

The dashboard analyzes DNS queries, TLS certificate subjects, network flows, HTTP URLs, and files transferred over the network.

## Data Source

- Index: `botsv1`
- Sourcetype: `suricata`

---

## Panel 1 — Top Queried Domains (DNS)

### Purpose

Identifies the most frequently queried DNS domains observed in Suricata DNS events.

### SPL

spl
index=botsv1 sourcetype=suricata 
| spath event_type
| search event_type="dns"
| spath dns.rrname
| stats count by dns.rrname
| sort -count 
| head 10

Analysis

The query filters Suricata events for DNS activity and ranks the top 10 queried domain names by frequency.

Panel 2 — DNS Query Type Breakdown
Purpose

Shows the distribution of DNS query types observed in Suricata telemetry.

SPL
index=botsv1 sourcetype=suricata 
| spath event_type
| search event_type="dns"
| spath dns.type
| stats count by dns.type
Analysis

The query filters DNS events, extracts the DNS query type, and counts events for each query type.

Panel 3 — TLS Certificate Subjects
Purpose

Identifies the most frequently observed TLS certificate subjects in the network traffic.

SPL
index=botsv1 sourcetype=suricata 
| spath event_type
| search event_type="tls"
| spath tls.subject
| stats count by tls.subject
| sort -count
| head 10
Analysis

The query filters TLS events and extracts certificate subject information.

The top 10 certificate subjects are ranked according to their observed event count.

Panel 4 — Network Flow - Top Talkers
Purpose

Identifies source IP addresses generating the highest volume of network bytes sent to servers.

SPL
index=botsv1 sourcetype=suricata 
| spath event_type
| search event_type="flow"
| spath flow.bytes_toserver
| spath src_ip
| stats sum(flow.bytes_toserver) as total_bytes by src_ip
| sort -total_bytes
| head 10
Analysis

The query filters network flow events and calculates the total bytes sent to servers for each source IP.

The top 10 source IPs are then ranked by total traffic volume.

Panel 5 — HTTP URLs Accessed
Purpose

Identifies the most frequently accessed HTTP URLs observed in Suricata HTTP events.

SPL
index=botsv1 sourcetype=suricata 
| spath event_type
| search event_type="http"
| spath http.url
| stats count by http.url
| sort -count
| head 20
Analysis

The query filters HTTP events, extracts the requested URL, and ranks the top 20 URLs by frequency.

This provides visibility into web resources accessed within the monitored network traffic.

Panel 6 — Files Transferred Over Network
Purpose

Identifies files observed in Suricata fileinfo events.

SPL
index=botsv1 sourcetype=suricata 
| spath event_type
| search event_type="fileinfo"
| spath fileinfo.filename
| stats count by fileinfo.filename
| sort -count
Analysis

The query filters fileinfo events, extracts filenames, and counts their occurrences.

This provides visibility into files observed during network activity.

Investigation Value

The dashboard provides multiple views of network telemetry collected by Suricata.

It can be used to:

Identify frequently queried DNS domains
Analyze DNS query types
Review TLS certificate subjects
Identify high-volume network talkers
Investigate frequently accessed HTTP URLs
Identify files observed in network traffic
Support network threat hunting and investigation
Related Documentation
BOTSv1 Dashboard Overview
BOTSv1 Findings
MITRE ATT&CK Mapping
