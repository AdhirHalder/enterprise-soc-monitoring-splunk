# Brute Force Detection

## Detection Overview

This detection monitors repeated failed authentication attempts against the DVWA Brute Force page.

The objective is to identify password-guessing activity by detecting a spike in failed login attempts originating from a single source IP.

## Data Source

- Application: DVWA
- Log Source: DVWA authentication logs
- Sourcetype: `dvwa:auth`
- Additional Source: Apache access logs
- SIEM: Splunk Enterprise

## Detection Logic

The detection analyzes authentication activity and identifies repeated failed login attempts from the same source IP within a short time window.

The documented alert configuration uses a threshold of more than 5 failed login attempts from a single source IP within a 1-minute window on the DVWA login page.

## Detection Workflow

1. Collect DVWA authentication and Apache web access logs.
2. Forward Apache logs to Splunk using the Splunk Universal Forwarder.
3. Search authentication events in Splunk.
4. Identify failed login attempts.
5. Aggregate failed attempts by source IP.
6. Apply the configured threshold.
7. Generate a Splunk alert when the threshold is exceeded.
8. Investigate the source IP, targeted username, timestamps, and authentication activity.

## Example SPL Logic

```spl
index=dvwa sourcetype=dvwa:auth
| search result="failed"
| stats count as failed_attempts values(username) as usernames by src_ip
| where failed_attempts > 5
| sort - failed_attempts
