# Brute Force Alert

## Alert Overview

The `Brute_Force_Attack_Detected` alert is designed to identify repeated failed login attempts against the DVWA Brute Force page.

The alert uses DVWA authentication logs together with Apache access logs to provide visibility into password-guessing activity.

## Alert Configuration

| Parameter | Configuration |
|---|---|
| Alert Name | `Brute_Force_Attack_Detected` |
| Data Source | DVWA authentication logs + Apache access logs |
| Detection Condition | 20+ failed logins from a single source IP within 5 minutes |
| Severity | High |
| Action | Email notification |
| Throttling | 60-second suppression per source IP |

## Trigger Condition

The alert triggers when the configured threshold of repeated failed authentication attempts from a single source IP is exceeded within the defined time window.

This helps identify automated or repeated password-guessing activity against the DVWA application.

## Alert Response

When the alert condition is met, Splunk generates the configured security alert.

The alert is intended to provide the SOC analyst with:

- Source IP address
- Failed login activity
- Authentication timeline
- Targeted DVWA endpoint
- Related authentication events

## Throttling

A 60-second suppression window per source IP is configured to reduce repeated alert generation from the same attacking source.

## MITRE ATT&CK

The brute-force activity is mapped to:

**T1110.001 – Brute Force: Password Guessing**

## SOC Investigation

After receiving the alert, the analyst should:

1. Validate the failed authentication activity.
2. Identify the source IP.
3. Review the authentication timeline.
4. Check the targeted username and endpoint.
5. Look for a successful login following repeated failures.
6. Correlate the activity with Apache access logs.
7. Document the investigation and escalate if required.

## Notification Status

The Splunk alert and email notification action are configured as part of the project.

External email delivery should be considered **pending/troubleshooting** unless successful delivery has been independently verified.

## Related Detection

See [`../detections/brute-force.md`](../detections/brute-force.md) for the corresponding detection methodology.
