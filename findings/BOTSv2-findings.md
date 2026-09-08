# BOTSv2 Findings

## Overview

BOTSv2 was analyzed using Splunk dashboards covering Palo Alto firewall activity, MySQL database security, Symantec Endpoint Protection, Office 365 activity, lateral movement, and web application security.

The analysis identified indicators of command and control, database brute force, endpoint attack activity, cloud service abuse, lateral movement, and web reconnaissance.

## 1. Palo Alto Firewall

### Key Findings

- Host `10.0.1.200` communicated with `52.40.10.231` a total of **82,601 times**, identified as a primary C2 communication channel.
- Host `10.0.2.107` communicated with `45.77.65.211` **16,980 times**.
- The IP `45.77.65.211` was also observed in BOTSv1, providing cross-dataset evidence of shared attacker infrastructure.
- BitTorrent and Skype were detected with **risk score 5**, representing policy violations and potential exfiltration channels.

**MITRE ATT&CK:** T1071 – Application Layer Protocol

## 2. MySQL / Database Attack

### Key Findings

- MySQL root received **88 aborted connections** from `52.40.10.231`.
- The same IP was identified in the Palo Alto analysis, providing cross-layer correlation.
- AWS EC2 instance `ec2-52-201-187-24.compute-1.amazonaws.com` also connected as root.
- Database hosts **cassiopeia** and **jabbah** were both targeted, indicating a multi-database attack campaign.

### MITRE ATT&CK

| Technique | Tactic | Detection Indicator |
|---|---|---|
| T1110 | Credential Access | MySQL root aborted connections |
| T1048 | Exfiltration | MySQL `bytes_out` spike |

## 3. Symantec Endpoint Protection

### Key Findings

- Symantec endpoint security events correlated with attack windows identified in the Palo Alto and MySQL dashboards.
- This correlation indicated simultaneous activity across multiple security layers.
- Source IPs detected by Symantec overlapped with suspicious IPs identified by the Palo Alto firewall.
- The overlap provided cross-source IOC confirmation of attacker infrastructure.

## 4. O365 Activity

### Key Findings

- Exchange entered `RestoringService` state **48 times** and `ServiceRestored` state **69 times** during the attack period.
- `Add-MailboxPermission` was executed **twice**, indicating unauthorized mailbox access establishment.
- `AdminAuditLogConfig` was modified **twice**, indicating attempted audit-log disabling or defense evasion.
- `Set-TransportConfig` was executed **6 times**, indicating email-routing manipulation for potential data exfiltration through mail forwarding.

### MITRE ATT&CK

| Technique | Tactic | Activity |
|---|---|---|
| T1098 | Persistence | `Add-MailboxPermission` |
| T1562 | Defense Evasion | `AdminAuditLogConfig` modification |

## 5. Lateral Movement

### Key Findings

- Multiple internal workstations from `192.168.9.101` to `192.168.9.110` repeatedly connected to `192.168.10.100` (`mercury.frothly.local`).
- The activity targeted the `IPC$` share and generated **1,700+ connection attempts**.
- The activity was identified as SMB enumeration and lateral-movement reconnaissance.
- Heavy LDAP search activity from non-admin workstations to the Domain Controller was consistent with Active Directory enumeration.

### MITRE ATT&CK

| Technique | Tactic | Detection Indicator |
|---|---|---|
| T1135 | Discovery | SMB/network share enumeration |
| T1021.002 | Lateral Movement | SMB/Windows Admin Shares |
| T1087 | Discovery | Account discovery through LDAP |
| T1069 | Discovery | Permission group discovery |

## 6. Web Application Attack

### Key Finding

- Legitimate non-Mozilla user-agents such as the Splunk monitoring account and Slackbot were observed.
- A blank user-agent from IP `139.228.225.20` generated repeated requests.
- This behavior was identified as consistent with automated reconnaissance activity.

**MITRE ATT&CK:** T1595 – Active Scanning

## Cross-Source Correlation

One of the important outcomes of the BOTSv2 analysis was cross-source IOC correlation.

The IP `52.40.10.231` appeared in both:

- Palo Alto firewall activity
- MySQL database activity

Similarly, `45.77.65.211` was observed in BOTSv2 and was also identified in BOTSv1.

These overlaps strengthen the investigation by connecting activity across different security telemetry sources and datasets.

## Security Observations

The BOTSv2 analysis demonstrated several important SOC investigation scenarios:

- C2 communication
- Database brute-force activity
- Cross-layer IOC correlation
- Endpoint intrusion activity
- O365 administrative abuse
- Audit-log tampering
- SMB enumeration
- Active Directory enumeration
- Automated web reconnaissance
- Potential data-exfiltration channels

## Conclusion

BOTSv2 demonstrated how Splunk can correlate network, database, endpoint, identity, and web telemetry to identify multi-stage attack activity.

The combination of Palo Alto, MySQL, Symantec, O365, lateral movement, and web application dashboards provided a multi-layer view of attacker behavior.
