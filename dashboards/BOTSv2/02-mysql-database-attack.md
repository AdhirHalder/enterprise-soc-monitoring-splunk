# MySQL / Database Attack Dashboard

## Overview

The MySQL / Database Attack Dashboard provides visibility into MySQL database activity within the BOTSv2 dataset.

The dashboard analyzes MySQL error activity, aborted connections, connection statistics, transaction activity, table sizes, and network traffic.

## Data Sources

- Index: `botsv2`
- Sourcetypes:
  - `mysql:errorlog`
  - `mysql:connection:stats`
  - `mysql:transaction:stats`
  - `mysql:tableStatus`
  - `stream:mysql`

---

## Panel 1 — MySQL Error Log Overview

### Purpose

Provides an overview of error, warning, and note entries recorded in the MySQL error log.

### SPL

spl
index=botsv2 sourcetype=mysql:errorlog
| rex field=_raw "(?P<error_type>ERROR|WARNING|Note)"
| stats count by error_type
| sort -count

Analysis

The query extracts the error type from the raw MySQL error log and counts events for each category.

Panel 2 — Aborted MySQL Connections
Purpose

Identifies aborted MySQL connections by username and host.

SPL
index=botsv2 sourcetype=mysql:errorlog
| rex field=_raw "Aborted connection \d+ to db: '(?P<database>\S+)' user: '(?P<username>\S+)' host: '(?P<host>\S+)'"
| stats count by username, host
| sort -count
Analysis

The query extracts the database, username, and host information from aborted connection messages.

It then ranks usernames and hosts based on the number of aborted connections.

Panel 3 — MySQL Connection Stats
Purpose

Provides average and maximum MySQL connection statistics by host.

SPL
index=botsv2 sourcetype=mysql:connection:stats
| stats avg(connections) as avg_connections max(connections) as max_connections by host
| sort -max_connections
Analysis

The query calculates the average and maximum number of connections for each host and sorts the results according to maximum connection activity.

Panel 4 — MySQL Transaction Activity Over Time
Purpose

Visualizes MySQL transaction activity over time using transactions per second.

SPL
index=botsv2 sourcetype=mysql:transaction:stats
| timechart span=1h avg(Transactions_Per_Second) as avg_tps
Analysis

The query generates an hourly time series showing the average transactions per second.

This provides visibility into changes in database transaction activity over time.

Panel 5 — MySQL Table Status — Largest Tables
Purpose

Identifies the largest MySQL tables based on their recorded data size.

SPL
index=botsv2 sourcetype=mysql:tableStatus
| stats max(DATA_LENGTH) as data_size by TABLE_NAME, TABLE_SCHEMA
| sort -data_size
| head 10
Analysis

The query calculates the maximum recorded data size for each table and schema combination.

The top 10 tables are displayed based on data size.

Panel 6 — MySQL Network Traffic — Data In vs Data Out
Purpose

Visualizes MySQL network traffic by comparing inbound and outbound bytes over time.

SPL
index=botsv2 sourcetype=stream:mysql
| timechart span=1h sum(bytes_in) as bytes_in sum(bytes_out) as bytes_out
Analysis

The query generates an hourly time series showing total inbound and outbound MySQL network traffic.

Investigation Value

The dashboard provides multiple views of MySQL and database-related telemetry.

It can be used to:

Analyze MySQL error activity
Investigate aborted database connections
Monitor connection activity by host
Track transaction activity over time
Identify the largest database tables
Compare inbound and outbound database network traffic
Support database security investigation and threat hunting
Related Documentation
BOTSv2 Dashboard Overview
BOTSv2 Findings
MITRE ATT&CK Mapping
