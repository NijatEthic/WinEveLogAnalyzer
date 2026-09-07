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

## Features

- Windows Security Event Log collection
- Authentication event parsing
- Logon type classification
- Brute-force detection
- Configurable detection threshold
- Configurable detection time window
- TXT security reports
- JSON security reports
- Automated unit tests with pytest
- Command-line configuration

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
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext |
| 9 | NewCredentials |
| 10 | Remote Interactive / RDP |
| 11 | Cached Interactive |

## Brute-Force Detection

The detection engine identifies repeated failed authentication attempts associated with the same username and source IP within a configurable time window.

Default configuration:

- Threshold: 5 failed attempts
- Time window: 5 minutes
- Risk level: HIGH

For example, six failed authentication attempts from the same source within five minutes can trigger a possible brute-force alert.

> A detection alert is a security indicator and should be investigated in context. It is not by itself proof of a successful attack.

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator privileges for reading the Windows Security Event Log
- Git

## Installation

Clone the repository:

```powershell
git clone https://github.com/nijatethical/WinEveLogAnalyzer.git
cd WinEveLogAnalyzer
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment again:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Run PowerShell as Administrator.

Basic analysis:

```powershell
python .\src\main.py
```

Analyze the last 24 hours:

```powershell
python .\src\main.py --hours 24
```

Configure the brute-force threshold and detection window:

```powershell
python .\src\main.py --hours 24 --threshold 5 --window 5
```

Show command-line options:

```powershell
python .\src\main.py --help
```

### Command-line options

| Option | Description |
|---|---|
| `--hours` | Number of hours of Windows Security events to analyze |
| `--threshold` | Number of failed attempts required to trigger detection |
| `--window` | Detection time window in minutes |

Example:

```powershell
python .\src\main.py --hours 24 --threshold 5 --window 5
```

This means:

- Analyze the last 24 hours
- Trigger detection after 5 failed attempts
- Require the attempts to occur within a 5-minute window

## Output

The analyzer generates two reports in the `reports/` directory:

```text
reports/
├── security_report.txt
└── security_report.json
```

### TXT Report

The TXT report is designed for human-readable security analysis.

It contains:

- Authentication summary
- Security alerts
- Recent events

### JSON Report

The JSON report provides structured data suitable for:

- Automation
- Further analysis
- Integration with other tools
- Security dashboards

## Understanding the Results

### Successful Logins

Event ID `4624` represents successful authentication.

### Failed Logins

Event ID `4625` represents failed authentication.

A high number of failed logins may indicate:

- Incorrect passwords
- Automated authentication attempts
- Password spraying
- Brute-force activity

The events should always be investigated in context.

### RDP Logins

Logon Type `10` represents Remote Interactive / RDP authentication.

### Service Logins

Logon Type `5` represents service logons.

Windows systems can generate many service logons from legitimate system processes. A high service-login count is therefore not automatically malicious.

### Special Privileges

Event ID `4672` indicates that special privileges were assigned to a logon session.

This event alone does not prove malicious activity and should be investigated together with the associated account, process, time and other events.

## Example Detection

A synthetic brute-force example is provided in the `examples/` directory.

Example:

```text
User     : testuser
IP       : 192.0.2.10
Attempts : 6
Window   : 5 minutes
Risk     : HIGH
```

This is a synthetic demonstration and does not represent a real attack.

## Testing

Run the automated tests with:

```powershell
python -m pytest -v
```

The test suite covers:

- Brute-force detection
- Detection threshold
- Detection time window
- Normal authentication activity
- Summary analysis

## Project Structure

```text
WinEveLogAnalyzer/
│
├── src/
│   ├── analyzer.py
│   ├── event_parser.py
│   ├── event_reader.py
│   ├── main.py
│   └── reporter.py
│
├── tests/
│   └── test_analyzer.py
│
├── examples/
│   ├── example_brute_force.txt
│   ├── example_report.json
│   └── example_report.txt
│
├── reports/
│   └── Generated reports
│
├── .gitignore
├── README.md
└── requirements.txt
```

## Limitations

This project is a small defensive security monitoring and detection tool.

It is not intended to replace:

- SIEM platforms
- EDR solutions
- IDS/IPS systems
- Enterprise security monitoring platforms

Detection results should be treated as indicators that require investigation.

## Security Purpose

The project was developed as a defensive security and detection-engineering portfolio project.

It demonstrates practical experience with:

- Windows Security Event Logs
- Authentication monitoring
- Security event parsing
- Detection logic
- Brute-force detection
- Python
- pytest
- JSON/TXT reporting
- Git/GitHub

## Author

Nijat

GitHub:

https://github.com/nijatethical