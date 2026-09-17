# Security Reconnaissance Report

- **Target:** `http://demo.testfire.net`
- **Timestamp:** `2026-09-17 09:23:00`
- **Total Findings:** `6`

## Summary of Findings
| Module / Section | Severity / Type | Description / Details |
| :--- | :--- | :--- |
| Missing Security Header: strict-transport-security | **MEDIUM** | The target response is missing the strict-transport-security header, reducing client-side hardening. |
| Missing Security Header: content-security-policy | **MEDIUM** | The target response is missing the content-security-policy header, reducing client-side hardening. |
| Missing Security Header: x-frame-options | **LOW** | The target response is missing the x-frame-options header, reducing client-side hardening. |
| Missing Security Header: x-content-type-options | **LOW** | The target response is missing the x-content-type-options header, reducing client-side hardening. |
| Missing Security Header: referrer-policy | **MEDIUM** | The target response is missing the referrer-policy header, reducing client-side hardening. |
| Missing Security Header: permissions-policy | **MEDIUM** | The target response is missing the permissions-policy header, reducing client-side hardening. |
