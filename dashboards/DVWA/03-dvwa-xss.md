# Real-Time DVWA Cross-Site Scripting (XSS) Attack Dashboard

This dashboard provides real-time monitoring of Cross-Site Scripting (XSS) activity against the DVWA web application using Splunk. It analyzes total XSS attempts, commonly observed payloads, targeted pages, recent attack activity, and attack patterns over time.

## Data Source

- Index: `dvwa`
- Sourcetype: `dvwa:xss`
- Primary monitored activity: DVWA XSS events
- Global time range: `$global_time.earliest$` to `$global_time.latest$`

---

## Panel 1 — Total XSS Attempts

### Purpose
Displays the total number of XSS attempts recorded in the DVWA XSS logs.

### SPL

spl
index=dvwa sourcetype="dvwa:xss"
| stats count AS "Total XSS Attempts"

Panel 2 — Top XSS Payloads
Purpose

Identifies and ranks the XSS payloads most frequently observed in the monitored events.

SPL
index=dvwa sourcetype="dvwa:xss"
| rex field=_raw "PAYLOAD=(?<Payload>.*?)\s+\|"
| eval Payload=trim(Payload)
| stats count AS Attempts by Payload
| sort - Attempts
Panel 3 — XSS Attack Timeline
Purpose

Shows XSS activity over time to identify attack bursts, repeated attempts, and periods of increased activity.

SPL
index=dvwa sourcetype="dvwa:xss"
| timechart span=1m count AS Attempts
Panel 4 — Latest XSS Activity
Purpose

Provides detailed visibility into recent XSS events, including source IP, payload, attack type, and target URI.

SPL
index=dvwa sourcetype="dvwa:xss"
| rex field=_raw "IP=(?<Source_IP>.*?)\s+\|"
| rex field=_raw "PAYLOAD=(?<Payload>.*?)\s+\|"
| rex field=_raw "ATTACK_TYPE=(?<Attack_Type>.*?)\s+\|"
| rex field=_raw "URI=(?<URI>.*)"
| eval Source_IP=trim(Source_IP)
| table _time Source_IP Payload Attack_Type URI
| sort - _time
Panel 5 — Target Pages Attacked
Purpose

Identifies the web pages targeted by XSS activity and ranks them by the number of observed attempts.

SPL
index=dvwa sourcetype="dvwa:xss"
| rex field=_raw "URI=(?<URI>.*)"
| rex field=URI "^(?<Target_Page>[^?]+)"
| stats count AS Attempts by Target_Page
| sort - Attempts
Security Monitoring Focus

The dashboard provides visibility into:

Total XSS attempts
Frequently observed XSS payloads
XSS attack activity over time
Source IP addresses associated with attacks
Attack types
Target URIs and web pages
Latest XSS activity
Investigation Workflow
Review the total XSS attempt count.
Identify the most frequently observed XSS payloads.
Analyze the attack timeline for bursts or repeated activity.
Review recent XSS events and associated source IPs.
Examine the attack type and target URI.
Identify web pages receiving high volumes of XSS attempts.
Correlate payload, source IP, target page, and attack timing during investigation.
Detection Context

The dashboard is designed to support monitoring and investigation of XSS activity against the DVWA application. The dvwa:xss telemetry provides visibility into the source IP, payload, attack type, and target URI associated with observed events.
