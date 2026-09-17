# Security Reconnaissance Report

- **Target:** `https://medistore.se`
- **Timestamp:** `2026-09-17 10:47:15`
- **Total Findings:** `10`

## Summary of Findings
| Module / Section | Severity / Type | Description / Details |
| :--- | :--- | :--- |
| Directory Brute-Forcer | **LOW** | Discovered hidden endpoint/file: https://medistore.se/database.sql [HTTP 403] |
| Directory Brute-Forcer | **LOW** | Discovered hidden endpoint/file: https://medistore.se/site.bak [HTTP 403] |
| Directory Brute-Forcer | **LOW** | Discovered hidden endpoint/file: https://medistore.se/.env [HTTP 403] |
| Directory Brute-Forcer | **MEDIUM** | Discovered hidden endpoint/file: https://medistore.se/robots.txt [HTTP 200] |
| Directory Brute-Forcer | **LOW** | Discovered hidden endpoint/file: https://medistore.se/.git/HEAD [HTTP 403] |
| Directory Brute-Forcer | **LOW** | Discovered hidden endpoint/file: https://medistore.se/xmlrpc.php [HTTP 403] |
| Directory Brute-Forcer | **LOW** | Discovered hidden endpoint/file: https://medistore.se/info.php [HTTP 403] |
| Directory Brute-Forcer | **MEDIUM** | Discovered hidden endpoint/file: https://medistore.se/admin/ [HTTP 302] |
| Directory Brute-Forcer | **MEDIUM** | Discovered hidden endpoint/file: https://medistore.se/wp-login.php [HTTP 200] |
| Directory Brute-Forcer | **MEDIUM** | Discovered hidden endpoint/file: https://medistore.se/sitemap.xml [HTTP 301] |
| Directory Brute-Force Analysis | **INFO** | Analyzed data successfully logged. |

## Detailed Module Sections

### Directory Brute-Force Analysis
```json
{
  "target": "https://medistore.se",
  "paths_checked": 28,
  "findings_count": 10,
  "findings": [
    {
      "path": "/database.sql",
      "url": "https://medistore.se/database.sql",
      "status": 403,
      "severity": "LOW"
    },
    {
      "path": "/site.bak",
      "url": "https://medistore.se/site.bak",
      "status": 403,
      "severity": "LOW"
    },
    {
      "path": "/.env",
      "url": "https://medistore.se/.env",
      "status": 403,
      "severity": "LOW"
    },
    {
      "path": "/robots.txt",
      "url": "https://medistore.se/robots.txt",
      "status": 200,
      "severity": "MEDIUM"
    },
    {
      "path": "/.git/HEAD",
      "url": "https://medistore.se/.git/HEAD",
      "status": 403,
      "severity": "LOW"
    },
    {
      "path": "/xmlrpc.php",
      "url": "https://medistore.se/xmlrpc.php",
      "status": 403,
      "severity": "LOW"
    },
    {
      "path": "/info.php",
      "url": "https://medistore.se/info.php",
      "status": 403,
      "severity": "LOW"
    },
    {
      "path": "/admin/",
      "url": "https://medistore.se/admin/",
      "status": 302,
      "severity": "MEDIUM"
    },
    {
      "path": "/wp-login.php",
      "url": "https://medistore.se/wp-login.php",
      "status": 200,
      "severity": "MEDIUM"
    },
    {
      "path": "/sitemap.xml",
      "url": "https://medistore.se/sitemap.xml",
      "status": 301,
      "severity": "MEDIUM"
    }
  ]
}
```
