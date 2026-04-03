---
name: nextjs-security-scanner
description: Scan a Next.js project for CVE-2025-55182 (React2Shell, CVSS 10.0) and credential exposure. Checks vulnerable Next.js/React versions, App Router usage, .env secrets, SSH keys, cloud config, and Cisco Talos IOCs.
---

# Next.js Security Scanner

Detects CVE-2025-55182 (React2Shell): unauthenticated RCE via deserialization of Server Components in Next.js 15.x / 16.x and React 19.x.

## Trigger

Keywords: "next.js security", "CVE-2025-55182", "React2Shell", "Next.js vulnerability", "next.js security scan", "react2shell scan", "next.js credentials check"

## Usage

```bash
bash scan.sh [target-directory]
```

The scanner runs 8 phases:
1. Next.js version check (vulnerable range: 15.0.0–16.0.6)
2. React version check (vulnerable: 19.0.0, 19.1.0, 19.1.1, 19.2.0)
3. App Router / Server Components detection
4. Credential exposure (.env files, next.config.*, hardcoded secrets)
5. SSH key and secret file detection
6. Cloud configuration check (Docker Compose, K8s, AWS)
7. IOC check (Cisco Talos C2 IPs, /tmp/ dotfiles)
8. Summary report with remediation steps

## Exit Codes

- `0` — Clean
- `1` — Warnings (review needed)
- `2` — Critical (vulnerable version or hardcoded secrets confirmed)

## Remediation

If CRITICAL issues are found:
1. `npm install next@latest` — upgrade to patched version
2. `npm install react@latest react-dom@latest` — upgrade React
3. Rotate all secrets if exploitation suspected
4. Block C2 IPs: 144.172.102.88 / 172.86.127.128 / 144.172.112.136 / 144.172.117.112
5. Check for artifacts: unexpected processes, cron changes, /tmp/ dotfiles

## More Info

See the full README at: https://github.com/aliksir/nextjs-security-scanner
