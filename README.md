# WinEveLogAnalyzer

A Python-based Windows Security Event Log Analyzer for defensive security monitoring and authentication analysis.

The project reads Windows Security Event Logs, parses authentication-related events, detects repeated failed login attempts, and generates TXT and JSON security reports.

## Features

- Windows Security Event Log collection
- Authentication event parsing
- Successful login analysis
- Failed login analysis
- Logoff analysis
- Logon type classification
- RDP login identification
- Service login identification
- Repeated failed login detection
- Configurable brute-force threshold
- Configurable detection time window
- Configurable analysis period
- TXT report generation
- JSON report generation
- Automated unit tests

## Monitored Event IDs

| Event ID | Description |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4634 | Account Logoff |
| 4647 | User Initiated Logoff |
| 4672 | Special Privileges Assigned |

## Logon Types

| Type | Description |
|---|---|
| 2 | Interactive |
| 3 | Network |
| 5 | Service |
| 10 | Remote Interactive / RDP |

## Brute-Force Detection

The analyzer looks for repeated failed authentication attempts associated with the same username and source IP address within a configurable time window.

Default configuration:

- Threshold: 5 failed attempts
- Detection window: 5 minutes
- Risk level: HIGH

Example:

```text
5 failed login attempts
        +
same user
        +
same source IP
        +
within 5 minutes
        =
Possible Brute Force