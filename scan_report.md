# Security Reconnaissance & Audit Report
- **Target Domain**: https://medistore.se
- **Scan Timestamp**: 2026-09-17T08:18:44.639871
- **Total Findings**: 6

---

## Identified Vulnerabilities & Components

### [Medium] Missing Security Header: strict-transport-security
- **Details**: The target response is missing the strict-transport-security header, reducing client-side hardening.
- **Logged At**: 2026-09-17T08:18:44.913705

### [Medium] Missing Security Header: content-security-policy
- **Details**: The target response is missing the content-security-policy header, reducing client-side hardening.
- **Logged At**: 2026-09-17T08:18:44.913769

### [Low] Missing Security Header: x-frame-options
- **Details**: The target response is missing the x-frame-options header, reducing client-side hardening.
- **Logged At**: 2026-09-17T08:18:44.913796

### [Info] Security Header Present: x-content-type-options
- **Details**: Header is configured. Value: nosniff...
- **Logged At**: 2026-09-17T08:18:44.913819

### [Medium] Missing Security Header: referrer-policy
- **Details**: The target response is missing the referrer-policy header, reducing client-side hardening.
- **Logged At**: 2026-09-17T08:18:44.913836

### [Medium] Missing Security Header: permissions-policy
- **Details**: The target response is missing the permissions-policy header, reducing client-side hardening.
- **Logged At**: 2026-09-17T08:18:44.913851
