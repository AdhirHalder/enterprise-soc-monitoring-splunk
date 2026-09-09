# DVWA Dashboards

This folder contains real-time dashboards developed using DVWA (Damn Vulnerable Web Application) and Splunk for monitoring and detection of web application attacks.

## Dashboards

### 01. Real-Time DVWA Brute Force Attack Dashboard
Monitors DVWA authentication activity to identify repeated failed login attempts and potential brute-force attacks.

### 02. Real-Time DVWA SQL Injection Attack Dashboard
Monitors DVWA SQL injection logs for suspicious SQL injection payloads and attack activity.

### 03. Real-Time DVWA Cross-Site Scripting (XSS) Attack Dashboard
Monitors DVWA XSS logs for suspicious XSS-related payloads and attack activity.

### 04. Real-Time Unified SOC Console
Provides a consolidated view of real-time DVWA security activity, bringing together brute-force, SQL injection, and XSS monitoring.

## Data Sources

- DVWA
- Apache/XAMPP logs
- Splunk Universal Forwarder
- Splunk Enterprise
- Custom DVWA security logs

## Detection & Alerting

Real-time Splunk alerts were configured for:

- Brute Force Login Attack
- SQL Injection Attack
- Cross-Site Scripting (XSS)

Alert configuration and detection logic are documented separately in the repository.

## Investigation Workflow

The DVWA environment supports the following workflow:

1. Generate attack activity against DVWA.
2. Capture application and authentication logs.
3. Forward logs to Splunk.
4. Analyze events using SPL.
5. Identify suspicious attack patterns.
6. Visualize activity through dashboards.
7. Trigger configured security alerts.
8. Investigate and correlate the observed activity.

## Screenshots

Dashboard screenshots are available in this folder.

## Validation Note

The dashboards were developed and tested in a controlled lab environment using DVWA. External email delivery for configured alerts remains subject to SMTP configuration and was not treated as successfully delivered unless independently verified.
