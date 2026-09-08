# BOTSv1 Findings

## Overview

BOTSv1 was analyzed using Splunk dashboards for network traffic, IDS/IPS activity, Windows authentication, DNS threat hunting, and IOC correlation.

The analysis identified multiple indicators associated with reconnaissance, command and control, DNS abuse, lateral movement, privilege escalation, and persistence.

## 1. SOC Executive Overview

### Key Findings

- BOTSv1 contained more than **1.3 million Suricata events**.
- DNS events: **18,259**
- Flow events: **25,197**
- Event volume spikes were concentrated in specific hourly windows, correlating with active attack phases.
- A small set of internal IP addresses were repeatedly targeted, indicating focused reconnaissance.

## 2. Fortinet Firewall Traffic Analysis

### Key Findings

- **195,545 deny actions** were observed compared with **62,675 accept actions**, indicating heavy firewall blocking during the attack period.
- External IPs **93.174.93.94** and **183.60.48.25** were identified as top suspicious source IPs.
- Google DNS servers **8.8.8.8** and **8.8.4.4** were primary destination IPs and were associated with DNS-based C2 patterns in the analysis.

## 3. IDS/IPS — Suricata

### Key Findings

- DGA domain:
  `EJFDEBFEEBFACACACACACACACACACAAA`
  generated **4,452 hits**.
- DGA domain:
  `FHFAEBEECACACACACACACACACACACAAA`
  generated **2,546 hits**.
- The two DGA patterns were identified as malware C2 beacons.
- **NIMLOC** DNS record type was detected **14,444 times**, indicating DNS tunneling activity.
- **WPAD** queries occurred **3,444 times**, indicating possible MITM attack preparation.
- `/UploadData.aspx` was accessed **321 times** through FileInfo, identified as a potential web shell upload indicator.

## 4. Windows Authentication

### Key Findings

- **6,100 privilege escalation events** (EventCode 4672) were detected.
- The Administrator account accessed the **C$ share 965 times**.
- The Administrator account accessed **IPC$ 1,884 times**.
- The Administrator account performed **800+ logins at approximately 2:00 AM**, identified as after-hours attacker-controlled access in the project analysis.

## 5. DNS Threat Hunting

### Key Findings

- Two distinct DGA domain patterns generated thousands of DNS query attempts.
- **NIMLOC** record type occurred **14,444 times**, identified as DNS abuse for covert data tunneling.
- Host **192.168.225.111** was identified as the primary infected machine based on DNS anomaly volume.

## 6. Threat Intelligence / IOC Correlation

### Key Findings

- IPs **93.174.93.94** and **183.60.48.25** were identified as malicious with sustained multi-hour C2 communication.
- Certificate-store registry keys were modified **3,620 times each**, identified as suspicious registry activity associated with MITM/persistence analysis.
- TCP/IP parameter registry settings were modified **2,390 times**, indicating network configuration tampering.

## Security Observations

The BOTSv1 analysis demonstrated multiple correlated indicators across network, endpoint, DNS, and Windows telemetry.

The most significant observations included:

- High-volume network security events
- Heavy firewall blocking
- Suspicious external source IPs
- DGA-based C2 communication
- DNS tunneling indicators
- WPAD-related MITM preparation
- Privilege escalation activity
- SMB administrative-share access
- After-hours authentication activity
- Suspicious registry modifications

## MITRE ATT&CK Coverage

The BOTSv1 dashboards were mapped to multiple MITRE ATT&CK techniques, including:

| Dashboard | MITRE ID | Technique | Tactic |
|---|---|---|---|
| SOC Executive Overview | T1595 | Active Scanning | Reconnaissance |
| Fortinet Firewall | T1071 | Application Layer Protocol | Command and Control |
| IDS/IPS Suricata | T1568.002 | Dynamic Resolution: Domain Generation Algorithms | Command and Control |
| Windows Authentication | T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| Windows Authentication | T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| DNS Threat Hunting | T1071.004 | DNS | Command and Control |
| DNS Threat Hunting | T1557 | Adversary-in-the-Middle | Credential Access |
| IOC Correlation | T1547.001 | Registry Run Keys / Startup Folder | Persistence |

## Conclusion

BOTSv1 threat hunting demonstrated how multiple Splunk data sources can be correlated to identify attacker infrastructure, DNS-based C2, lateral movement, privilege escalation, and suspicious endpoint activity.

The findings were derived from the corresponding BOTSv1 dashboards and documented investigation results.
