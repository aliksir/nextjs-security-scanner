> 日本語版は [README.ja.md](README.ja.md) を参照してください。

# nextjs-security-scanner

Bash script to detect CVE-2025-55182 (React2Shell) and credential exposure in Next.js projects. Zero dependencies.

## CVE-2025-55182: React2Shell

CVSS: **10.0 (CRITICAL)** | CWE-502: Deserialization of Untrusted Data | SNORT SID: 65554

Unauthenticated remote code execution via deserialization of untrusted data in Next.js Server Components. An attacker sends a crafted HTTP request to any Next.js Server Component endpoint; the server deserializes the payload and executes arbitrary code.

**Affected versions:**

| Package | Vulnerable Range |
|---------|-----------------|
| Next.js | 15.0.0–15.0.4, 15.1.0–15.1.8, 15.2.0–15.2.5, 15.3.0–15.3.5, 15.4.0–15.4.7, 15.5.0–15.5.6, 15.6.0, 16.0.0–16.0.6 |
| React   | 19.0.0, 19.1.0, 19.1.1, 19.2.0 |

**References:**
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-55182
- Cisco Talos: search "React2Shell" at https://blog.talosintelligence.com/

## What this scanner checks

**Phase 1 — Next.js version:** Reads `package.json`, `package-lock.json`, and `yarn.lock` to find the resolved Next.js version and compares against the vulnerable range.

**Phase 2 — React version:** Same approach for React (19.0.0, 19.1.0, 19.1.1, 19.2.0).

**Phase 3 — App Router / Server Components:** Detects `app/` directory and `"use server"` directives. A vulnerable version with Server Components active is a live attack surface.

**Phase 4 — Credential exposure:** Scans `.env*` files (excludes `.env.example` and `.env.sample`), `next.config.*`, and source files for API keys, database URLs, JWT secrets, and hardcoded secret prefixes (`sk-`, `AKIA`, `ghp_`, `npm_`).

**Phase 5 — SSH keys:** Looks for private key files (`id_rsa`, `*.pem`, `*.p12`, etc.) and `.ssh/` directories committed inside the project.

**Phase 6 — Cloud config:** Checks Docker Compose files for hardcoded secrets, Kubernetes manifests for service account token exposure, and AWS SDK usage for IMDSv2 hints.

**Phase 7 — IOC check:** Searches for C2 IP addresses from Cisco Talos intelligence and suspicious `/tmp/` dotfile patterns (Linux).

```
C2 IPs (Cisco Talos): 144.172.102.88 / 172.86.127.128 / 144.172.112.136 / 144.172.117.112
```

**Phase 8 — Summary:** CRITICAL/WARNING/INFO counts with remediation steps.

## Install

No installation needed. Download and run:

```bash
curl -O https://raw.githubusercontent.com/aliksir/nextjs-security-scanner/main/scan.sh
bash scan.sh [target-directory]
```

Or clone:

```bash
git clone https://github.com/aliksir/nextjs-security-scanner.git
bash nextjs-security-scanner/scan.sh /path/to/your/nextjs-app
```

## Usage

```bash
# Scan current directory
bash scan.sh

# Scan a specific project
bash scan.sh /path/to/nextjs-app

# In CI/CD (non-zero exit = fail the pipeline)
bash scan.sh . || exit 1
```

**Exit codes:**
- `0` — No issues
- `1` — Warnings (credential patterns detected, review needed)
- `2` — Critical (vulnerable version confirmed, immediate action required)

## Output example

```
=== Next.js Security Scanner ===
Target: /home/user/myapp
Date: 2026-04-04 12:00
CVE: CVE-2025-55182 (React2Shell, CVSS 10.0)

[Phase 1] Next.js version check
  [CRITICAL] Next.js v15.2.4 is vulnerable to CVE-2025-55182 (React2Shell)
             -> package.json: "next": "^15.2.4"
             -> This version allows unauthenticated RCE via deserialization of Server Components

[Phase 2] React version check
  [CRITICAL] React v19.1.0 is in the CVE-2025-55182 vulnerable list

[Phase 3] App Router / Server Components detection
  [INFO]     App Router detected (app/ directory exists)
  [CRITICAL] Vulnerable Next.js + Server Components = active attack surface for React2Shell

...

=== Scan Summary ===
  CRITICAL : 3
  WARNING  : 0
  INFO     : 2

CRITICAL issues found. Immediate action required.

=== Remediation (CVE-2025-55182) ===

1. Upgrade Next.js to a patched version:
   npm install next@latest
...
```

## Remediation

**Upgrade immediately:**

```bash
npm install next@latest
npm install react@latest react-dom@latest
```

Check https://github.com/vercel/next.js/releases for the first patched version in each minor series.

**If exploitation is suspected:**
1. Rotate all secrets (API keys, database credentials, JWT secrets, SSH keys, cloud IAM)
2. Check for post-exploitation artifacts:
   ```bash
   ps aux | grep -E '\.sh|\.py'
   crontab -l; cat /etc/cron*
   ss -tnp | grep -E '144\.172|172\.86'
   ls -la /tmp/ | grep '^\.'
   ```
3. Block C2 IPs at firewall: `144.172.102.88`, `172.86.127.128`, `144.172.112.136`, `144.172.117.112`
4. Enable SNORT rule SID: 65554

## Using as a Claude Code skill

```bash
bash scan.sh [target-directory]
```

Trigger keywords: "next.js security check", "CVE-2025-55182", "React2Shell", "Next.js vulnerability scan"

See `claude-code/SKILL.md` for the skill wrapper.

---

## Disclaimer

This tool is provided for **defensive security purposes only**. It performs local-only, read-only checks against your own project files. No network connections are made, no data is sent externally, and no exploits are executed.

The vulnerability information and IOC data are based on publicly available sources (NVD, Cisco Talos). This scanner may produce false positives or miss certain attack vectors. It does not replace professional security audits, penetration testing, or vendor-provided security patches.

**Use at your own risk.** The authors assume no liability for damages resulting from the use of this tool.

## License

MIT — see [LICENSE](LICENSE)
