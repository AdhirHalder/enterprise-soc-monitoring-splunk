# Cross-Site Scripting (XSS) Detection

## Detection Overview

This detection monitors the DVWA environment for Cross-Site Scripting (XSS) activity by identifying XSS-related payloads in web requests.

The objective is to provide real-time visibility into suspicious XSS activity and support investigation of source IPs, payloads, targeted pages, and attack timelines.

## Data Source

- Application: DVWA
- Log Source: DVWA XSS logs
- Sourcetype: `dvwa:xss`
- SIEM: Splunk Enterprise

## Detection Indicators

The detection methodology monitors XSS-related patterns including:

- `<script>`
- `onerror=`
- `javascript:`

These patterns are used as indicators of potential XSS activity.

## Detection Workflow

1. Generate XSS activity against the DVWA application.
2. Capture the resulting web activity in the DVWA XSS logs.
3. Forward or ingest the logs into Splunk.
4. Search for XSS-related payload patterns.
5. Identify the source IP and targeted page.
6. Review the payload and event timeline.
7. Trigger the configured Splunk alert.
8. Investigate related activity from the same source.

## Alert Configuration

| Parameter | Configuration |
|---|---|
| Alert Name | `DVWA - XSS Attack Detected` |
| Data Source | DVWA XSS logs |
| Sourcetype | `dvwa:xss` |
| Severity | Medium |
| Action | Real-time Splunk alert + email notification |
| Throttling | 60-second suppression per source IP |

## Investigation Indicators

When the alert triggers, the analyst should investigate:

- Source IP address
- XSS payload
- Targeted page
- Request timestamp
- Related requests from the same source
- Repeated XSS activity

## Dashboard

The project includes a dedicated:

**Real-Time DVWA Cross-Site Scripting (XSS) Attack Dashboard**

The dashboard provides visibility into:

- XSS activity
- Top XSS payloads
- Latest XSS activity
- Attacking source IPs
- Targeted pages
- Attack timeline

## MITRE ATT&CK

The project documentation describes this as a web application attack / XSS detection scenario.

No specific MITRE ATT&CK technique ID is assigned to the XSS alert in the project documentation.

## Expected SOC Response

A SOC analyst should:

1. Validate the suspicious request.
2. Inspect the XSS payload.
3. Identify the source IP.
4. Determine the targeted page.
5. Review related activity.
6. Document the finding and escalate according to the SOC workflow.

## Validation Note

The project documentation focuses on detecting and monitoring XSS payloads.

Successful browser-side execution should not be claimed unless it has been independently verified in the test environment.
