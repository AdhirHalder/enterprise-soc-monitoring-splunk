# SQL Injection Detection

## Detection Overview

This detection monitors web requests to identify potential SQL Injection activity against the DVWA application.

The detection focuses on suspicious SQL-related keywords and payload patterns appearing in HTTP request parameters.

## Data Source

- Application: DVWA
- Web Server: Apache
- Log Source: Apache access logs
- Index: `dvwa`
- Sourcetype: `access_combined`
- SIEM: Splunk Enterprise

## Detection Logic

The detection searches HTTP requests for SQL-related keywords commonly associated with SQL Injection attempts.

Examples include:

- `UNION`
- `SELECT`
- `DROP`
- `INSERT`

The presence of these patterns in URL parameters is treated as a potential SQL Injection indicator and requires further investigation.

## Detection Workflow

1. Generate or receive HTTP requests against the DVWA SQL Injection endpoint.
2. Collect Apache access logs.
3. Forward the logs to Splunk using the Splunk Universal Forwarder.
4. Search URL and request fields for SQL-related patterns.
5. Identify suspicious requests and source IP addresses.
6. Correlate repeated activity from the same source.
7. Trigger the configured Splunk alert when the detection condition is met.
8. Investigate the request, source IP, target endpoint, and associated activity.

## Example SPL Logic

```spl
index=dvwa sourcetype=access_combined
| search (uri_query="*UNION*" OR uri_query="*SELECT*" OR uri_query="*DROP*" OR uri_query="*INSERT*")
| stats count as suspicious_requests values(uri_path) as targeted_paths by clientip
| sort - suspicious_requests
