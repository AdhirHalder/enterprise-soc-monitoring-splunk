# Real-Time DVWA SQL Injection Attack Dashboard

This dashboard provides real-time monitoring of SQL injection activity against the DVWA web application using Splunk. It analyzes the total number of SQL injection attempts, attacking source IPs, recent SQL injection activity, attack timelines, and commonly observed SQL injection payloads.

## Data Source

- Index: `dvwa`
- Sourcetype: `dvwa:sqli`
- Primary monitored activity: DVWA SQL injection events
- Global time range: `$global_time.earliest$` to `$global_time.latest$`

---

## Panel 1 — Total SQL Injection Attempts

### Purpose
Displays the total number of SQL injection attempts recorded in the DVWA SQL injection logs.

### SPL

spl
index=dvwa sourcetype="dvwa:sqli"
| stats count AS "Total SQL Injection Attempts"

Panel 2 — Top Attacking Source IPs
Purpose

Identifies and ranks source IP addresses based on the number of SQL injection attempts they generated.

SPL
index=dvwa sourcetype="dvwa:sqli"
| rex field=_raw "IP=(?<Source_IP>.*?)\s+\|"
| eval Source_IP=trim(Source_IP)
| stats count AS Attempts by Source_IP
| sort - Attempts
Panel 3 — SQL Injection Attack Timeline
Purpose

Shows SQL injection activity over time to help identify attack bursts, repeated attempts, and periods of increased malicious activity.

SPL
index=dvwa sourcetype="dvwa:sqli"
| timechart span=1m count AS Attempts
Panel 4 — Top SQL Injection Payloads
Purpose

Identifies the SQL injection payloads most frequently observed in the monitored events.

SPL
index=dvwa sourcetype="dvwa:sqli"
| rex field=_raw "PAYLOAD=(?<Payload>.*?)\s+\|"
| eval Payload=trim(Payload)
| stats count AS Attempts by Payload
| sort - Attempts
Panel 5 — Latest SQL Injection Activity
Purpose

Provides detailed visibility into recent SQL injection events, including source IP, HTTP method, payload, result, and target URI.

SPL
index=dvwa sourcetype="dvwa:sqli"
| rex field=_raw "IP=(?<Source_IP>.*?)\s+\|"
| rex field=_raw "METHOD=(?<Method>.*?)\s+\|"
| rex field=_raw "PAYLOAD=(?<Payload>.*?)\s+\|"
| rex field=_raw "RESULT=(?<Result>.*?)\s+\|"
| rex field=_raw "URI=(?<URI>.*)"
| table _time Source_IP Method Payload Result URI
| sort - _time
Security Monitoring Focus

The dashboard provides visibility into:

Total SQL injection attempts
Attacking source IP addresses
SQL injection activity over time
Frequently observed SQL injection payloads
Latest SQL injection events
HTTP methods and target URIs associated with attacks
SQL injection results
Investigation Workflow
Review the total SQL injection attempt count.
Identify source IPs generating high volumes of SQL injection activity.
Examine the attack timeline for bursts or repeated activity.
Review the most frequently observed SQL injection payloads.
Investigate the latest SQL injection events.
Correlate source IP, payload, HTTP method, result, and target URI during investigation.
Detection Context

The dashboard is designed to support monitoring and investigation of SQL injection activity against the DVWA application. The dvwa:sqli telemetry provides structured visibility into the source IP, HTTP method, payload, result, and target URI associated with observed events.
