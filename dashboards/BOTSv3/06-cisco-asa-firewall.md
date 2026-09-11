# Cisco ASA Firewall Dashboard

## Overview

The Cisco ASA Firewall Dashboard provides visibility into firewall traffic and security events recorded in the BOTSv3 dataset.

The dashboard focuses on overall firewall actions, denied source IPs, inbound connection denials, targeted ports, VPN/remote-access activity, and firewall denial trends over time.

## Data Source

- Index: `botsv3`
- Sourcetype: `cisco:asa`
- Data Type: Cisco ASA Firewall Logs

---

## Panel 1 — Cisco ASA Traffic Overview — Full Code Explanation

### Purpose

Provides an overview of Cisco ASA firewall traffic by identifying the observed firewall actions.

### SPL

spl
index=botsv3 sourcetype="cisco:asa"
| rex field=_raw "%ASA-\d-(?<msg_id>\d+):\s+(?<action>Teardown|Deny|Built|Inbound)"
| where isnotnull(action)
| stats count by action
| sort - count

Analysis

This panel provides a high-level view of Cisco ASA traffic and the different firewall actions observed in the dataset.

Panel 2 — Top Denied Source IPs (Blocked Attack Attempts)
Purpose

Identifies source IPs associated with denied traffic and shows the targeted destination IPs, ports, and protocols.

SPL
index=botsv3 sourcetype="cisco:asa"
| rex field=_raw "Deny\s+(?<protocol>\w+)\s+src\s+\w+:(?<src_ip>[\d\.]+)/\d+\s+dst\s+\w+:(?<dst_ip>[\d\.]+)/(?<dst_port>\d+)"
| where isnotnull(src_ip)
| stats count by src_ip, dst_ip, dst_port, protocol
| sort - count
| head 20
Analysis

This panel highlights repeated denied connection attempts and provides source, destination, port, and protocol information for further investigation.

Panel 3 — Inbound Connection Denials (External Attack Attempts)
Purpose

Identifies inbound TCP connections that were denied by the Cisco ASA firewall.

SPL
index=botsv3 sourcetype="cisco:asa"
| rex field=_raw "Inbound TCP connection denied from (?<src_ip>[\d\.]+)/(?<src_port>\d+) to (?<dst_ip>[\d\.]+)/(?<dst_port>\d+)"
| where isnotnull(src_ip)
| stats count by src_ip, dst_ip, dst_port
| sort - count
| head 20
Analysis

This panel provides visibility into inbound connection attempts that were denied by the firewall. Repeated attempts from the same source can be investigated as potential external attack activity.

Panel 4 — Top Targeted Ports (Service Enumeration by External Attackers)
Purpose

Identifies destination ports targeted by denied inbound connections and counts the number of unique source IPs targeting each port.

SPL
index=botsv3 sourcetype="cisco:asa"
| rex field=_raw "Inbound TCP connection denied from (?<src_ip>[\d\.]+)/(?<src_port>\d+) to (?<dst_ip>[\d\.]+)/(?<dst_port>\d+)"
| where isnotnull(dst_port)
| stats dc(src_ip) as unique_attackers, count by dst_port
| sort - unique_attackers
| head 20
Analysis

This panel helps identify ports targeted by multiple external sources. A high number of unique attackers targeting a port can provide useful context for service-enumeration investigations.

Panel 5 — VPN/Remote Access Activity (AnyConnect Sessions)
Purpose

Provides visibility into VPN or remote-access session activity by extracting username, IP address, and group information.

SPL
index=botsv3 sourcetype="cisco:asa"
| rex field=_raw "%ASA-\d-(?<msg_id>\d+):\s+Group\s+=\s+(?<group>\S+),\s+Username\s+=\s+(?<username>\S+),\s+IP\s+=\s+(?<ip>[\d\.]+)"
| where isnotnull(username)
| stats count by username, ip, group
| sort - count
| head 20
Analysis

This panel provides visibility into remote-access activity and associates sessions with usernames, IP addresses, and groups.

Panel 6 — Firewall Traffic Timeline (Deny Spike Detection)
Purpose

Shows denied and inbound firewall activity over time to identify periods of increased activity.

SPL
index=botsv3 sourcetype="cisco:asa"
| rex field=_raw "%ASA-\d-(?<msg_id>\d+):\s+(?<action>Teardown|Deny|Built|Inbound)"
| where action="Deny" OR action="Inbound"
| timechart span=1h count by action
Analysis

This panel helps identify spikes in denied or inbound connection activity and provides a timeline for correlating firewall events with other security events.

Investigation Value

The dashboard provides Cisco ASA monitoring coverage across:

Firewall traffic actions
Denied source IPs
Inbound connection denials
Targeted destination ports
VPN and remote-access activity
Firewall activity trends over time

These views support investigation of blocked connection attempts, potential reconnaissance, service enumeration, remote-access activity, and periods of elevated firewall activity.

Related Documentation
findings/BOTSv3-findings.md
mitre/mitre-mapping.md
dashboards/BOTSv3/README.md
