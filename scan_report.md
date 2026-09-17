# Security Reconnaissance Report

- **Target:** `https://medistore.se`
- **Timestamp:** `2026-09-17 08:52:39`
- **Total Findings:** `15`

## Summary of Findings
| Module / Section | Severity / Type | Description / Details |
| :--- | :--- | :--- |
| Component CVE Audit: commercegurus-commercekit | **Info** | Detected Version: 2.5.2 | Advisory Match: None Recorded | Status: Secure / Patched |
| Component CVE Audit: yith-infinite-scrolling | **Info** | Detected Version: 2.12.0 | Advisory Match: None Recorded | Status: Secure / Patched |
| Component CVE Audit: woocommerce-product-bundles | **Info** | Detected Version: 8.5.12 | Advisory Match: None Recorded | Status: Secure / Patched |
| Component CVE Audit: woo-swish-e-commerce | **Info** | Detected Version: 3.7.8 | Advisory Match: None Recorded | Status: Secure / Patched |
| Component CVE Audit: woocommerce | **Info** | Detected Version: 11.1.0 | Advisory Match: None Recorded | Status: Secure / Patched |
| Component CVE Audit: woocommerce-product-addons | **Info** | Detected Version: 8.4.2 | Advisory Match: None Recorded | Status: Secure / Patched |
| Component CVE Audit: woocommerce-table-rate-shipping | **Info** | Detected Version: 3.7.3 | Advisory Match: None Recorded | Status: Secure / Patched |
| XML-RPC Protected / Disabled | **Info** | xmlrpc.php returned HTTP status 403, indicating restriction. |
| Missing Security Header: strict-transport-security | **Medium** | The target response is missing the strict-transport-security header, reducing client-side hardening. |
| Missing Security Header: content-security-policy | **Medium** | The target response is missing the content-security-policy header, reducing client-side hardening. |
| Missing Security Header: x-frame-options | **Low** | The target response is missing the x-frame-options header, reducing client-side hardening. |
| Security Header Present: x-content-type-options | **Info** | Header is configured. Value: nosniff... |
| Missing Security Header: referrer-policy | **Medium** | The target response is missing the referrer-policy header, reducing client-side hardening. |
| Missing Security Header: permissions-policy | **Medium** | The target response is missing the permissions-policy header, reducing client-side hardening. |
| WAF Rate-Limit Profile Completed | **Info** | No strict rate-limiting detected up to concurrency 25. |
| JavaScript Asset Analysis | **INFO** | Analyzed data successfully logged. |

## Detailed Module Sections

### JavaScript Asset Analysis
```json
{
  "scripts_analyzed": 25,
  "secrets_found": [],
  "endpoints_discovered": []
}
```
