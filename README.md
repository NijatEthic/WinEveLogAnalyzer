# WinEveLogAnalyzer

A Python-based Windows Security Event Log Analyzer for defensive security monitoring and authentication analysis.

## Project Overview

WinEveLogAnalyzer analyzes Windows Security Event Logs and extracts authentication-related security events.

The tool helps identify:

- Successful logons
- Failed logons
- Interactive logins
- RDP logins
- Network logins
- Service logons
- User logoffs
- Repeated failed authentication attempts
- Potential brute-force activity

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

## Detection

The current detection engine identifies repeated failed authentication attempts associated with the same username and source IP within a configurable time window.

Default configuration:

- Threshold: 5 failed attempts
- Time window: 5 minutes
- Risk level: HIGH

## Installation

Create a virtual environment:

```powershell
python -m venv .venv