# SecureWatch

SecureWatch is a Python-based File Integrity Monitoring (FIM) and threat detection tool designed to monitor files and directories for security-relevant changes.

The system uses SHA-256 hashing to detect file modifications, stores security events in a SQLite database, assigns severity levels based on file type and event behavior, and can export event history as CSV reports.

## Features

- SHA-256 file integrity monitoring
- Real-time directory monitoring
- File creation detection
- File modification detection
- File deletion detection
- Risk-based severity classification
- SQLite event database
- Security event history
- Security dashboard
- CSV security report generation
- JSON-based configuration
- Configurable scan intervals
- Directory and extension ignore lists
- Interactive CLI menu
- No external Python dependencies

## Detection Types

SecureWatch currently detects three primary file events:

| Event | Description |
|---|---|
| CREATED | A new file appears in the monitored directory |
| MODIFIED | The SHA-256 hash of an existing file changes |
| DELETED | A previously monitored file disappears |

## Severity Engine

SecureWatch classifies detected events using multiple severity levels.

### CRITICAL

High-risk file extensions such as:

```text
.exe
.dll
.sys
.bat
.cmd
.ps1
.vbs
.scr
```

### HIGH

Potentially security-relevant files such as:

```text
.py
.js
.jar
.msi
.reg
```

File modifications and deletions may also generate HIGH severity events.

### MEDIUM

Normal file creation events that do not match higher-risk rules.

## How It Works

SecureWatch calculates the SHA-256 hash of monitored files and stores the baseline information in SQLite.

During later scans:

```text
Current File
     |
     v
SHA-256 Calculation
     |
     v
Compare With Database
     |
     +------ Same ------> No Alert
     |
     +------ Different -> MODIFIED
     |
     +------ New -------> CREATED

Database File Missing
     |
     v
DELETED
```

Detected events are written to the event database with information including:

- Event type
- Severity
- File path
- Previous SHA-256
- New SHA-256
- Timestamp

## Project Structure

```text
SecureWatch/
|
|-- config/
|   `-- config.json
|
|-- database/
|   `-- securewatch.db
|
|-- reports/
|   `-- securewatch_report_*.csv
|
|-- main.py
|-- monitor.py
|-- detector.py
|-- hash_engine.py
|-- database.py
|-- reporter.py
|-- requirements.txt
|-- .gitignore
`-- README.md
```

Generated databases and reports are excluded from Git tracking.

## Configuration

SecureWatch can be configured using:

```text
config/config.json
```

Example:

```json
{
    "scan_interval": 5,
    "max_recent_events": 5,
    "report_on_exit": true,
    "ignored_directories": [
        ".git",
        "__pycache__",
        "node_modules"
    ],
    "ignored_extensions": [
        ".tmp",
        ".log",
        ".cache"
    ]
}
```

## Usage

SecureWatch requires Python 3.

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd SecureWatch
```

Run:

```bash
python main.py
```

The interactive menu will appear:

```text
============================================================
                     SECUREWATCH
          File Integrity & Threat Monitor
============================================================

 [1] Start Monitoring
 [2] Security Dashboard
 [3] Export Security Report
 [4] Exit

============================================================
```

Choose `Start Monitoring` and enter the directory that should be monitored.

Press `CTRL+C` to stop active monitoring and return to the SecureWatch interface.

## Example Detection

```text
[MEDIUM]   CREATED  -> document.txt
[HIGH]     MODIFIED -> application.py
[CRITICAL] CREATED  -> script.ps1
[HIGH]     DELETED  -> important.txt
```

## Security Dashboard

SecureWatch provides a summary of recorded security activity:

```text
=================================================================
                 SECUREWATCH SECURITY DASHBOARD
=================================================================
 Monitored Files  : 4
 Total Events     : 18
-----------------------------------------------------------------
 CRITICAL Alerts  : 2
 HIGH Alerts      : 9
 MEDIUM Alerts    : 7
-----------------------------------------------------------------
 CREATED          : 8
 MODIFIED         : 6
 DELETED          : 4
=================================================================
```

## Reports

Security events can be exported to CSV.

Example:

```text
reports/securewatch_report_2026-10-06_14-45-20.csv
```

Reports contain:

```text
ID
Event Type
Severity
File Path
Old SHA256
New SHA256
Timestamp
```

## Technologies

- Python
- SQLite
- SHA-256
- JSON
- CSV

## Purpose

SecureWatch was developed as a cybersecurity portfolio project to demonstrate concepts including file integrity monitoring, hashing, security event logging, risk classification, configuration management, database usage and security reporting.

## Disclaimer

SecureWatch is intended for educational, defensive security, and authorized monitoring purposes.