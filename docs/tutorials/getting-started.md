# Getting started

Install Endpoint & Auth Mapper and run a scan.

## 1. Install

Install locally via `pip`. Provides `authmap` CLI command.

```bash
pip install ./endpoint-auth-mapper
```

## 2. Inventory Project

Run the backwards-compatible legacy inventory on current directory.

```bash
authmap --project . 
```

**Console Output:**
Reports regex-matched route candidates and unverified compatibility states.
Columns: `SEVERITY`, `STATE`, `ENDPOINT`, `LOCATION`, `CONF`.

Example:
```text
CRITICAL  EXPOSED    GET /api/users                   vulnerable.js:3        HIGH
INFO      PROTECTED  GET /api/profile                 vulnerable.js:19       HIGH
INFO      PUBLIC     GET /healthz                     vulnerable.js:23       HIGH
```

Treat this output as review inventory, not proof of framework enforcement. For
supported Express JavaScript, continue with the
[Express evidence scan](../reference/express-evidence-scan.md).

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
