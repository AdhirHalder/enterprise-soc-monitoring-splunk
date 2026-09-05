# XSS Alert

## Alert Overview

The `DVWA - XSS Attack Detected` alert is designed to identify Cross-Site Scripting (XSS) activity against the DVWA application.

The alert monitors DVWA XSS logs for XSS-related request and payload indicators.

## Alert Configuration

| Parameter | Configuration |
|---|---|
| Alert Name | `DVWA - XSS Attack Detected` |
| Data Source | DVWA XSS logs |
| Sourcetype | `dvwa:xss` |
| Trigger Condition | XSS-related request/payload detected |
| Severity | Medium |
| Action | Real-time Splunk alert + email notification |
| Throttling | 60-second suppression per source IP |

## Detection Indicators

The documented detection methodology monitors XSS-related patterns including:

- `<script>`
- `onerror=`
- `javascript:`

These patterns are treated as indicators of potential XSS activity.

## Alert Response

When the configured condition is met, Splunk generates an alert for investigation.

The analyst should review:

- Source IP address
- XSS payload
- Targeted page
- Request timestamp
- Related requests from the same source

## SOC Investigation

After the alert triggers, the analyst should:

1. Validate the suspicious web request.
2. Identify the source IP.
3. Inspect the XSS payload.
4. Determine the targeted page.
5. Review related activity from the same source.
6. Document the investigation and escalate if required.

## MITRE ATT&CK

The project documentation describes this as a web application attack / XSS detection scenario.

No specific MITRE ATT&CK technique ID is assigned to the XSS alert in the project documentation.

## Project Dashboard

The corresponding Real-Time DVWA Cross-Site Scripting (XSS) Attack Dashboard provides visibility into:

- XSS activity
- Top XSS payloads
- Latest XSS activity
- Attacking source IPs
- Targeted pages
- Attack timeline

## Notification Status

The Splunk alert and email notification action are configured.

External email delivery should only be considered successful if delivery has been independently verified in the test environment.

## Validation Note

The project documentation focuses on detecting and monitoring XSS payloads.

Successful browser-side execution should not be claimed unless independently verified in the test environment.

## Related Detection

See [`../detections/xss.md`](../detections/xss.md) for the corresponding XSS detection methodology.
