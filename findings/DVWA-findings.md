# DVWA Findings

## Overview

The project uses Damn Vulnerable Web Application (DVWA) as a controlled vulnerable web application environment for real-time security monitoring and attack detection using Splunk.

The DVWA environment was used to generate and monitor:

- Brute Force attacks
- SQL Injection attempts
- Cross-Site Scripting (XSS) activity

## 1. Brute Force Attack

### Finding

Repeated failed authentication attempts were observed against the DVWA Brute Force page.

The activity demonstrated password-guessing behavior originating from a source IP.

### Investigation Indicators

The investigation focused on:

- Source IP address
- Failed login attempts
- Successful login attempts
- Targeted username
- Authentication timeline
- Apache web requests

### Detection

The project includes a dedicated Real-Time DVWA Brute Force Attack Dashboard.

The dashboard provides visibility into:

- Total login attempts
- Failed login attempts
- Successful login attempts
- Source IP analysis
- Latest authentication activity
- Response status distribution
- Attack timeline
- Top usernames attempted

## 2. SQL Injection

### Finding

SQL Injection activity was monitored through suspicious SQL-related payloads in web requests against DVWA.

Documented indicators include:

- `UNION SELECT`
- `OR 1=1`
- `--`

### Investigation Indicators

The investigation focused on:

- Attacking source IP
- SQL Injection payload
- Targeted endpoint
- Request timestamp
- Repeated suspicious requests

### Detection

The project includes a Real-Time DVWA SQL Injection Attack Dashboard.

The dashboard provides visibility into:

- SQL Injection attempts
- Payloads
- Attack timeline
- Latest activity
- Attacking source IPs

### MITRE ATT&CK

**T1190 — Exploit Public-Facing Application**

## 3. Cross-Site Scripting (XSS)

### Finding

XSS-related activity was monitored through suspicious web request and payload patterns against DVWA.

Documented XSS indicators include:

- `<script>`
- `onerror=`
- `javascript:`

### Investigation Indicators

The investigation focused on:

- Source IP address
- XSS payload
- Targeted page
- Request timestamp
- Related requests from the same source

### Detection

The project includes a Real-Time DVWA Cross-Site Scripting (XSS) Attack Dashboard.

The dashboard provides visibility into:

- XSS activity
- Top XSS payloads
- Latest XSS activity
- Attacking source IPs
- Targeted pages
- Attack timeline

## 4. Unified Attack Monitoring

The project also includes a Real-Time Unified SOC Console that correlates the three DVWA attack scenarios:

```text
Brute Force
     ↓
SQL Injection
     ↓
XSS
     ↓
Unified SOC Monitoring
