# Security Reconnaissance Report

- **Target:** `https://medistore.se`
- **Timestamp:** `2026-09-17 12:20:46`
- **Total Findings:** `3`

## Summary of Findings
| Module / Section | Severity / Type | Description / Details |
| :--- | :--- | :--- |
| SRI Auditor | **MEDIUM** | External script loaded without SRI integrity hash: https://www.googletagmanager.com/gtag/js?id=G-ZC06GLL4HW&l=dataLayer |
| SRI Auditor | **MEDIUM** | External script loaded without SRI integrity hash: https://www.gstatic.com/shopping/merchant/merchantwidget.js |
| SRI Auditor | **MEDIUM** | External script loaded without SRI integrity hash: https://helloretailcdn.com/helloretail.js |
| Subresource Integrity (SRI) Analysis | **INFO** | Analyzed data successfully logged. |

## Detailed Module Sections

### Subresource Integrity (SRI) Analysis
```json
{
  "findings_count": 3,
  "findings": [
    {
      "tag": "script",
      "url": "https://www.googletagmanager.com/gtag/js?id=G-ZC06GLL4HW&l=dataLayer",
      "severity": "MEDIUM"
    },
    {
      "tag": "script",
      "url": "https://www.gstatic.com/shopping/merchant/merchantwidget.js",
      "severity": "MEDIUM"
    },
    {
      "tag": "script",
      "url": "https://helloretailcdn.com/helloretail.js",
      "severity": "MEDIUM"
    }
  ]
}
```
