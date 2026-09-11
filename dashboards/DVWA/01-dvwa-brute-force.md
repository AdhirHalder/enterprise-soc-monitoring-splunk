# Real-Time DVWA Brute Force Attack Dashboard

This dashboard provides real-time monitoring of authentication activity against the DVWA brute-force endpoint using Splunk. It analyzes login attempts, failed and successful authentication, targeted usernames, source IPs, target URLs, and attack activity over time.

## Data Source

- Index: `dvwa`
- Sourcetype: `dvwa:auth`
- Primary monitored activity: DVWA brute-force authentication requests
- Global time range: `$global_time.earliest$` to `$global_time.latest$`

---

## Panel 1 — Total Login Attempts

### Purpose
Displays the total number of authentication attempts recorded in the DVWA authentication logs.

### SPL

spl
index=dvwa sourcetype="dvwa:auth"
| stats count AS "Total Login Attempts"

Panel 2 — Failed Login Attempts
Purpose

Counts authentication attempts that resulted in a failed login.

SPL
index=dvwa sourcetype="dvwa:auth" RESULT=FAILED
| stats count AS "Failed Login Attempts"
Panel 3 — Successful Login Attempts
Purpose

Counts authentication attempts that resulted in successful authentication.

SPL
index=dvwa sourcetype="dvwa:auth" RESULT=SUCCESS
| stats count AS "Successful Login Attempts"
Panel 4 — Source IP Analysis
Purpose

Identifies source IP addresses generating authentication attempts and ranks them by activity volume.

SPL
index=dvwa sourcetype="dvwa:auth"
| rex field=_raw "IP=(?<Source_IP>[^|]+)"
| stats count AS Attempts by Source_IP
| sort - Attempts
Panel 5 — Latest Authentication Activity
Purpose

Provides a chronological view of recent authentication activity, including source IP, username, authentication result, and target URI.

SPL
index=dvwa sourcetype="dvwa:auth"
| rex field=_raw "IP=(?<Source_IP>[^|]+)"
| rex field=_raw "USERNAME=(?<Username>[^|]+)"
| rex field=_raw "RESULT=(?<Result>[^|]+)"
| rex field=_raw "URI=(?<URI>.*)"
| eval Source_IP=trim(Source_IP)
| eval Username=trim(Username)
| eval Result=trim(Result)
| table _time Source_IP Username Result URI
| sort -_time
Panel 6 — Attack Timeline
Purpose

Shows authentication activity over time to identify bursts or sustained brute-force behavior.

SPL
index=dvwa sourcetype="dvwa:auth"
| timechart span=1m count AS "Login Attempts"
Panel 7 — Top Usernames Targeted
Purpose

Identifies the usernames most frequently targeted during authentication attempts.

SPL
index=dvwa sourcetype="dvwa:auth"
| rex field=_raw "USERNAME=(?<username>[^|]+)"
| eval username=trim(username)
| stats count AS Attempts by username
| sort - Attempts
Panel 8 — Target URL Analysis
Purpose

Analyzes the target URIs associated with authentication attempts to identify the endpoints receiving the highest volume of requests.

SPL
index=dvwa sourcetype="dvwa:auth"
| rex field=_raw "URI=(?<URI>.*)"
| stats count AS Attempts by URI
| sort - Attempts
Security Monitoring Focus

The dashboard provides visibility into:

Total authentication attempts
Failed authentication attempts
Successful authentication
Source IP activity
Targeted usernames
Target URLs
Authentication activity over time
Latest authentication events
Investigation Workflow
Review total and failed login attempts.
Identify source IPs generating high authentication volume.
Analyze targeted usernames.
Review the target URL associated with the activity.
Examine the attack timeline for bursts or repeated attempts.
Review latest authentication activity.
Check whether any successful authentication occurred during suspicious activity.
Brute Force Detection Context

The dashboard is designed to support investigation of repeated authentication attempts against the DVWA brute-force functionality. Analysts can correlate source IP, targeted username, authentication result, target URI, and attack timing to identify suspicious login behavior.
