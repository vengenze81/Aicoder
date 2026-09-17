# Security Reconnaissance Report

- **Target:** `https://medistore.se`
- **Timestamp:** `2026-09-17 11:08:39`
- **Total Findings:** `4`

## Summary of Findings
| Module / Section | Severity / Type | Description / Details |
| :--- | :--- | :--- |
| Header Auditor | **MEDIUM** | HSTS missing (Vulnerable to protocol downgrade attacks) |
| Header Auditor | **MEDIUM** | CSP missing (Vulnerable to XSS and data injection) |
| Header Auditor | **LOW** | X-Frame-Options missing (Vulnerable to clickjacking) |
| Header Auditor | **LOW** | Referrer-Policy missing (Potential information leakage in referrer header) |
| HTTP Security Header Analysis | **INFO** | Analyzed data successfully logged. |

## Detailed Module Sections

### HTTP Security Header Analysis
```json
{
  "findings_count": 4,
  "findings": [
    {
      "header": "Strict-Transport-Security",
      "status": "Missing",
      "severity": "MEDIUM",
      "description": "HSTS missing (Vulnerable to protocol downgrade attacks)"
    },
    {
      "header": "Content-Security-Policy",
      "status": "Missing",
      "severity": "MEDIUM",
      "description": "CSP missing (Vulnerable to XSS and data injection)"
    },
    {
      "header": "X-Frame-Options",
      "status": "Missing",
      "severity": "LOW",
      "description": "X-Frame-Options missing (Vulnerable to clickjacking)"
    },
    {
      "header": "Referrer-Policy",
      "status": "Missing",
      "severity": "LOW",
      "description": "Referrer-Policy missing (Potential information leakage in referrer header)"
    }
  ]
}
```
