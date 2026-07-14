# Getting started

Install Endpoint & Auth Mapper and run a scan.

## 1. Install

Install locally via `pip`. Provides `authmap` CLI command.

```bash
pip install ./endpoint-auth-mapper
```

## 2. Scan Project

Run analysis on current directory.

```bash
authmap --project . 
```

**Console Output:**
Detects endpoints, evaluates auth coverage. Outputs table format.
Columns: `SEVERITY`, `STATE`, `ENDPOINT`, `LOCATION`, `CONF`.

Example:
```text
CRITICAL  EXPOSED    GET /api/users                   vulnerable.js:3        HIGH
INFO      PROTECTED  GET /api/profile                 vulnerable.js:19       HIGH
INFO      PUBLIC     GET /healthz                     vulnerable.js:23       HIGH
```

## 3. Export Formats

Export findings for pipeline integrations or dashboards.

**JSON Format:**
```bash
authmap --project . --format json > report.json
```

**SARIF Format:**
(Supported by GitHub Advanced Security)
```bash
authmap --project . --format sarif > report.sarif
```
