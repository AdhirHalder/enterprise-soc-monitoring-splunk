# Real-Time Unified DVWA SOC Console

This dashboard provides a centralized SOC view of DVWA security activity by correlating Brute Force, SQL Injection, and Cross-Site Scripting (XSS) events in Splunk. It combines overall security-event volume, attack-specific counts, attack distribution, source IP analysis, recent events, and attack activity over time.

## Data Sources

- Index: `dvwa`
- Sourcetypes:
  - `dvwa:auth`
  - `dvwa:sqli`
  - `dvwa:xss`
- Global time range: `$global_time.earliest$` to `$global_time.latest$`

---

## Panel 1 — Total Security Events

### Purpose
Displays the total number of security events across the monitored DVWA authentication, SQL injection, and XSS data sources.

### SPL

spl
index=dvwa sourcetype IN ("dvwa:auth","dvwa:sqli","dvwa:xss")
| stats count AS "Total Security Events"

Panel 2 — Brute Force Attempts
Purpose

Displays the total number of authentication events recorded in the DVWA authentication logs and uses them as the brute-force activity metric.

SPL
index=dvwa sourcetype="dvwa:auth"
| stats count AS "Brute Force Attempts"
Panel 3 — SQL Injection Attempts
Purpose

Displays the total number of SQL injection events recorded in the DVWA SQL injection logs.

SPL
index=dvwa sourcetype="dvwa:sqli"
| stats count AS "SQL Injection Attempts"
Panel 4 — XSS Attempts
Purpose

Displays the total number of XSS events recorded in the DVWA XSS logs.

SPL
index=dvwa sourcetype="dvwa:xss"
| stats count AS "XSS Attempts"
Panel 5 — Attack Distribution
Purpose

Categorizes authentication, SQL injection, and XSS events into attack types and compares their activity volume.

SPL
index=dvwa sourcetype IN ("dvwa:auth","dvwa:sqli","dvwa:xss")
| eval Attack_Type=case(
    sourcetype="dvwa:auth", "Brute Force",
    sourcetype="dvwa:sqli", "SQL Injection",
    sourcetype="dvwa:xss", "XSS"
)
| stats count AS Attempts by Attack_Type
| sort - Attempts
Panel 6 — Attack Timeline
Purpose

Provides a time-based view of Brute Force, SQL Injection, and XSS activity to support correlation and identification of attack bursts.

SPL
index=dvwa sourcetype IN ("dvwa:auth","dvwa:sqli","dvwa:xss")
| eval Attack_Type=case(
    sourcetype="dvwa:auth", "Brute Force",
    sourcetype="dvwa:sqli", "SQL Injection",
    sourcetype="dvwa:xss", "XSS"
)
| timechart span=1m count by Attack_Type
Panel 7 — Top Attacking Source IPs
Purpose

Identifies source IP addresses generating the highest volume of attack activity across the monitored DVWA attack types.

SPL
index=dvwa sourcetype IN ("dvwa:auth","dvwa:sqli","dvwa:xss")
| rex field=_raw "IP=(?<Source_IP>.*?)\s+\|"
| eval Source_IP=trim(Source_IP)
| stats count AS "Attack Attempts" by Source_IP
| sort - "Attack Attempts"
Panel 8 — Latest Security Events
Purpose

Provides a recent-event view across Brute Force, SQL Injection, and XSS activity, including the attack type, source IP, and raw event details.

SPL
index=dvwa sourcetype IN ("dvwa:auth","dvwa:sqli","dvwa:xss")
| eval Attack_Type=case(
    sourcetype="dvwa:auth", "Brute Force",
    sourcetype="dvwa:sqli", "SQL Injection",
    sourcetype="dvwa:xss", "XSS"
)
| rex field=_raw "IP=(?<Source_IP>.*?)\s+\|"
| eval Source_IP=trim(Source_IP)
| table _time Attack_Type Source_IP _raw
| sort - _time
| head 20
Security Monitoring Focus

The unified console provides centralized visibility into:

Total DVWA security events
Brute Force activity
SQL Injection activity
XSS activity
Attack-type distribution
Attack activity over time
Top attacking source IPs
Latest security events
Investigation Workflow
Review the total security-event volume.
Compare Brute Force, SQL Injection, and XSS activity.
Examine the attack distribution to identify the dominant attack type.
Review the attack timeline for temporal correlation and attack bursts.
Identify source IPs generating high volumes of attack activity.
Review the latest security events for detailed investigation.
Correlate multiple attack types, source IPs, and timestamps to understand the overall attack sequence.
SOC Correlation Context

The unified console brings the three DVWA attack telemetry sources together:

dvwa:auth → Brute Force
dvwa:sqli → SQL Injection
dvwa:xss → XSS

This provides a centralized monitoring view for investigating multiple web-application attack categories within the same SOC workflow.
