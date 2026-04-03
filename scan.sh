#!/usr/bin/env bash
# Next.js security scanner
# Detects CVE-2025-55182 (React2Shell, CVSS 10.0) and credential exposure in Next.js projects
# (React2Shell: Deserialization of untrusted data via Server Components, 2025)
# Cisco Talos IOC data: C2 IPs 144.172.102.88, 172.86.127.128, 144.172.112.136, 144.172.117.112
#
# Usage: bash scan.sh [target-directory]
# Exit codes: 0 = clean, 1 = warnings found, 2 = critical issues found

set -euo pipefail

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  YELLOW='\033[1;33m'
  GREEN='\033[0;32m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED='' YELLOW='' GREEN='' CYAN='' BOLD='' NC=''
fi

TARGET_DIR="${1:-.}"
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0

# ============================================================
# Helpers
# ============================================================

log_critical() { echo -e "  ${RED}[CRITICAL]${NC} $*"; CRITICAL_COUNT=$((CRITICAL_COUNT + 1)); }
log_warning()  { echo -e "  ${YELLOW}[WARNING]${NC}  $*"; WARNING_COUNT=$((WARNING_COUNT + 1)); }
log_info()     { echo -e "  [INFO]     $*"; INFO_COUNT=$((INFO_COUNT + 1)); }
log_pass()     { echo -e "  ${GREEN}[PASS]${NC}     $*"; }

# Extract plain version from a "^1.2.3", "~1.2.3", "1.2.3", ">=1.2.3" style string
strip_version_prefix() {
  echo "$1" | sed 's/[\^~>=<]//g' | tr -d ' '
}

# Compare version strings: returns 0 if $1 == $2
version_eq() { [[ "$1" == "$2" ]]; }

# Returns 0 (true) if version $1 is in the given next.js vulnerable range
is_nextjs_vulnerable() {
  local ver="$1"
  local major minor patch

  # Parse x.y.z
  IFS='.' read -r major minor patch <<< "$(echo "$ver" | sed 's/-[^.]*$//')"

  # Must be numeric
  [[ "$major" =~ ^[0-9]+$ ]] || return 1
  [[ "$minor" =~ ^[0-9]+$ ]] || return 1
  [[ "$patch" =~ ^[0-9]+$ ]] || return 1

  # Next.js vulnerable ranges (CVE-2025-55182, NVD confirmed)
  # 15.0.0 - 15.0.4
  if [[ $major -eq 15 && $minor -eq 0 && $patch -le 4 ]]; then return 0; fi
  # 15.1.0 - 15.1.8
  if [[ $major -eq 15 && $minor -eq 1 && $patch -le 8 ]]; then return 0; fi
  # 15.2.0 - 15.2.5
  if [[ $major -eq 15 && $minor -eq 2 && $patch -le 5 ]]; then return 0; fi
  # 15.3.0 - 15.3.5
  if [[ $major -eq 15 && $minor -eq 3 && $patch -le 5 ]]; then return 0; fi
  # 15.4.0 - 15.4.7
  if [[ $major -eq 15 && $minor -eq 4 && $patch -le 7 ]]; then return 0; fi
  # 15.5.0 - 15.5.6
  if [[ $major -eq 15 && $minor -eq 5 && $patch -le 6 ]]; then return 0; fi
  # 15.6.0
  if [[ $major -eq 15 && $minor -eq 6 && $patch -eq 0 ]]; then return 0; fi
  # 16.0.0 - 16.0.6
  if [[ $major -eq 16 && $minor -eq 0 && $patch -le 6 ]]; then return 0; fi

  return 1
}

# Returns 0 (true) if React version is in vulnerable list
is_react_vulnerable() {
  local ver="$1"
  local -a REACT_VULNERABLE=("19.0.0" "19.1.0" "19.1.1" "19.2.0")
  for v in "${REACT_VULNERABLE[@]}"; do
    [[ "$ver" == "$v" ]] && return 0
  done
  return 1
}

# ============================================================
# Header
# ============================================================
echo -e "${CYAN}${BOLD}=== Next.js Security Scanner ===${NC}"
echo "Target: $TARGET_DIR"
echo "Date: $(date '+%Y-%m-%d %H:%M')"
echo "CVE: CVE-2025-55182 (React2Shell, CVSS 10.0)"
echo ""

# Validate target directory
if [[ ! -d "$TARGET_DIR" ]]; then
  echo -e "${RED}Error: '$TARGET_DIR' is not a directory.${NC}" >&2
  exit 1
fi

# Check if this is a Next.js project
IS_NEXTJS=false
if [[ -f "$TARGET_DIR/package.json" ]] && grep -q '"next"' "$TARGET_DIR/package.json" 2>/dev/null; then
  IS_NEXTJS=true
fi

if [[ "$IS_NEXTJS" == "false" ]]; then
  echo -e "[INFO]     No Next.js project detected in '$TARGET_DIR' (no package.json with 'next' dependency)."
  echo -e "[INFO]     Proceeding with credential/IOC checks regardless."
  echo ""
fi

# ============================================================
# Phase 1: Next.js Version Check
# ============================================================
echo -e "${CYAN}[Phase 1] Next.js version check${NC}"

PHASE1_ISSUES=0
NEXTJS_VERSION=""

# Check package.json
if [[ -f "$TARGET_DIR/package.json" ]]; then
  raw_ver=$(grep -E '"next"\s*:\s*"[^"]*"' "$TARGET_DIR/package.json" 2>/dev/null | head -1 | sed 's/.*"next"[[:space:]]*:[[:space:]]*"//;s/".*//')
  if [[ -n "$raw_ver" ]]; then
    NEXTJS_VERSION=$(strip_version_prefix "$raw_ver")
    if is_nextjs_vulnerable "$NEXTJS_VERSION"; then
      log_critical "Next.js v$NEXTJS_VERSION is vulnerable to CVE-2025-55182 (React2Shell)"
      echo -e "  ${RED}  -> package.json: \"next\": \"$raw_ver\"${NC}"
      echo -e "  ${RED}  -> This version allows unauthenticated RCE via deserialization of Server Components${NC}"
      PHASE1_ISSUES=$((PHASE1_ISSUES + 1))
    else
      log_pass "Next.js v$NEXTJS_VERSION — not in vulnerable range"
    fi
  fi
fi

# Check package-lock.json for resolved version
if [[ -f "$TARGET_DIR/package-lock.json" ]]; then
  lock_ver=$(grep -A2 '"node_modules/next"' "$TARGET_DIR/package-lock.json" 2>/dev/null | grep '"version"' | head -1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"//;s/".*//' || true)
  if [[ -n "$lock_ver" ]] && [[ "$lock_ver" != "$NEXTJS_VERSION" ]]; then
    if is_nextjs_vulnerable "$lock_ver"; then
      log_critical "Next.js v$lock_ver (resolved in package-lock.json) is vulnerable to CVE-2025-55182"
      PHASE1_ISSUES=$((PHASE1_ISSUES + 1))
    else
      log_info "Resolved version in package-lock.json: Next.js v$lock_ver (safe)"
    fi
  fi
fi

# Check yarn.lock
if [[ -f "$TARGET_DIR/yarn.lock" ]]; then
  yarn_ver=$(grep -A2 '^next@' "$TARGET_DIR/yarn.lock" 2>/dev/null | grep '  version' | head -1 | sed 's/.*version "//;s/".*//' || true)
  if [[ -n "$yarn_ver" ]] && [[ "$yarn_ver" != "$NEXTJS_VERSION" ]]; then
    if is_nextjs_vulnerable "$yarn_ver"; then
      log_critical "Next.js v$yarn_ver (resolved in yarn.lock) is vulnerable to CVE-2025-55182"
      PHASE1_ISSUES=$((PHASE1_ISSUES + 1))
    else
      log_info "Resolved version in yarn.lock: Next.js v$yarn_ver (safe)"
    fi
  fi
fi

if [[ "$IS_NEXTJS" == "false" ]]; then
  log_pass "Not a Next.js project — version check skipped"
fi

# ============================================================
# Phase 2: React Version Check
# ============================================================
echo ""
echo -e "${CYAN}[Phase 2] React version check${NC}"

PHASE2_ISSUES=0
REACT_VERSION=""

if [[ -f "$TARGET_DIR/package.json" ]]; then
  raw_react=$(grep -E '"react"\s*:\s*"[^"]*"' "$TARGET_DIR/package.json" 2>/dev/null | head -1 | sed 's/.*"react"[[:space:]]*:[[:space:]]*"//;s/".*//')
  if [[ -n "$raw_react" ]]; then
    REACT_VERSION=$(strip_version_prefix "$raw_react")
    if is_react_vulnerable "$REACT_VERSION"; then
      log_critical "React v$REACT_VERSION is in the CVE-2025-55182 vulnerable list"
      echo -e "  ${RED}  -> package.json: \"react\": \"$raw_react\"${NC}"
      PHASE2_ISSUES=$((PHASE2_ISSUES + 1))
    else
      log_pass "React v$REACT_VERSION — not in vulnerable list (19.0.0, 19.1.0, 19.1.1, 19.2.0)"
    fi
  fi
fi

if [[ -f "$TARGET_DIR/package-lock.json" ]]; then
  lock_react=$(grep -A2 '"node_modules/react"' "$TARGET_DIR/package-lock.json" 2>/dev/null | grep '"version"' | head -1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"//;s/".*//' || true)
  if [[ -n "$lock_react" ]] && [[ "$lock_react" != "$REACT_VERSION" ]]; then
    if is_react_vulnerable "$lock_react"; then
      log_critical "React v$lock_react (resolved in package-lock.json) is in CVE-2025-55182 vulnerable list"
      PHASE2_ISSUES=$((PHASE2_ISSUES + 1))
    else
      log_info "Resolved React in package-lock.json: v$lock_react (safe)"
    fi
  fi
fi

if [[ $PHASE2_ISSUES -eq 0 ]] && [[ -z "$REACT_VERSION" ]]; then
  log_pass "No React dependency found"
fi

# ============================================================
# Phase 3: App Router / Server Components Detection
# ============================================================
echo ""
echo -e "${CYAN}[Phase 3] App Router / Server Components detection${NC}"

# Check for app/ directory
if [[ -d "$TARGET_DIR/app" ]]; then
  log_info "App Router detected (app/ directory exists)"
  # Check for Server Component directives
  server_count=$(grep -rEl '"use server"' "$TARGET_DIR/app" 2>/dev/null | grep -v node_modules | wc -l || echo "0")
  client_count=$(grep -rEl '"use client"' "$TARGET_DIR/app" 2>/dev/null | grep -v node_modules | wc -l || echo "0")
  if [[ "$server_count" -gt 0 ]]; then
    log_info "Server Components in use ($server_count files with \"use server\")"
    if [[ $PHASE1_ISSUES -gt 0 ]]; then
      log_critical "Vulnerable Next.js + Server Components = active attack surface for React2Shell"
    fi
  fi
  if [[ "$client_count" -gt 0 ]]; then
    log_info "Client Components in use ($client_count files with \"use client\")"
  fi
else
  log_pass "App Router not detected (no app/ directory)"
fi

# Check next.config.*
for cfg in "$TARGET_DIR"/next.config.js "$TARGET_DIR"/next.config.mjs "$TARGET_DIR"/next.config.ts; do
  if [[ -f "$cfg" ]]; then
    log_info "Next.js config found: $(basename "$cfg")"
    if grep -q 'experimental' "$cfg" 2>/dev/null; then
      log_info "Experimental features enabled in $(basename "$cfg") — review manually"
    fi
  fi
done

# ============================================================
# Phase 4: Credential Exposure Check
# ============================================================
echo ""
echo -e "${CYAN}[Phase 4] Credential exposure check${NC}"

PHASE4_ISSUES=0

# Secret key patterns to search for
declare -a SECRET_PATTERNS=(
  "AWS_SECRET_ACCESS_KEY"
  "AWS_ACCESS_KEY_ID"
  "STRIPE_SECRET_KEY"
  "STRIPE_SK_"
  "DATABASE_URL"
  "PRIVATE_KEY"
  "JWT_SECRET"
  "NEXTAUTH_SECRET"
  "OPENAI_API_KEY"
  "ANTHROPIC_API_KEY"
  "GITHUB_TOKEN"
  "NPM_TOKEN"
  "SLACK_BOT_TOKEN"
  "SENDGRID_API_KEY"
  "TWILIO_AUTH_TOKEN"
)

# Hardcoded secret prefixes to search in source
declare -a HARDCODED_PREFIXES=(
  "sk-[A-Za-z0-9]"
  "AKIA[0-9A-Z]"
  "ghp_[A-Za-z0-9]"
  "ghs_[A-Za-z0-9]"
  "npm_[A-Za-z0-9]"
)

# Check .env* files (exclude .env.example and .env.sample)
while IFS= read -r envfile; do
  basename_env=$(basename "$envfile")
  # Skip example/sample files
  if [[ "$basename_env" == ".env.example" ]] || [[ "$basename_env" == ".env.sample" ]]; then
    continue
  fi
  for pattern in "${SECRET_PATTERNS[@]}"; do
    if grep -q "$pattern" "$envfile" 2>/dev/null; then
      # Check if it has an actual value (not empty)
      line=$(grep "$pattern" "$envfile" 2>/dev/null | head -1)
      if echo "$line" | grep -qE '=.+'; then
        log_warning "$envfile: $pattern has a value set"
        PHASE4_ISSUES=$((PHASE4_ISSUES + 1))
      fi
    fi
  done
done < <(find "$TARGET_DIR" -maxdepth 3 -name ".env*" -type f -not -path "*/node_modules/*" -not -path "*/_deleted/*" 2>/dev/null)

# Check next.config.* for secrets in env / publicRuntimeConfig
for cfg in "$TARGET_DIR"/next.config.js "$TARGET_DIR"/next.config.mjs "$TARGET_DIR"/next.config.ts; do
  if [[ -f "$cfg" ]]; then
    for pattern in "${SECRET_PATTERNS[@]}"; do
      if grep -q "$pattern" "$cfg" 2>/dev/null; then
        log_warning "$(basename "$cfg"): $pattern found — check if secret is exposed to client"
        PHASE4_ISSUES=$((PHASE4_ISSUES + 1))
      fi
    done
    if grep -q 'publicRuntimeConfig' "$cfg" 2>/dev/null; then
      log_warning "$(basename "$cfg"): publicRuntimeConfig detected — secrets here are exposed to browser"
      PHASE4_ISSUES=$((PHASE4_ISSUES + 1))
    fi
  fi
done

# Check source code for hardcoded secret prefixes
# Limit to relevant extensions, skip node_modules
for prefix_pattern in "${HARDCODED_PREFIXES[@]}"; do
  while IFS= read -r match_file; do
    match_line=$(grep -m1 -E "$prefix_pattern" "$match_file" 2>/dev/null | head -c 120 || true)
    if [[ -n "$match_line" ]]; then
      log_critical "Possible hardcoded secret in $match_file"
      echo -e "  ${RED}  -> Pattern '$prefix_pattern' match: ${match_line:0:80}${NC}"
      PHASE4_ISSUES=$((PHASE4_ISSUES + 1))
    fi
  done < <(grep -rlE "$prefix_pattern" "$TARGET_DIR" \
    --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.mjs" \
    2>/dev/null | grep -v node_modules | grep -v _deleted | grep -v .git || true)
done

# Reminder about __NEXT_DATA__
if [[ "$IS_NEXTJS" == "true" ]]; then
  echo -e "  [INFO]     Check your browser: view-source of any page and search for __NEXT_DATA__"
  echo -e "  [INFO]     Server-side secrets should never appear in __NEXT_DATA__ JSON"
fi

if [[ $PHASE4_ISSUES -eq 0 ]]; then
  log_pass "No obvious credential exposure found"
fi

# ============================================================
# Phase 5: SSH Key & Secret File Check
# ============================================================
echo ""
echo -e "${CYAN}[Phase 5] SSH key and secret file check${NC}"

PHASE5_ISSUES=0

# Private key files
while IFS= read -r keyfile; do
  # Check if it actually looks like a private key
  if grep -q "PRIVATE KEY" "$keyfile" 2>/dev/null; then
    log_critical "Private key found: $keyfile"
    PHASE5_ISSUES=$((PHASE5_ISSUES + 1))
  fi
done < <(find "$TARGET_DIR" \
  -not -path "*/node_modules/*" \
  -not -path "*/_deleted/*" \
  -not -path "*/.git/*" \
  \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" \
     -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) \
  -type f 2>/dev/null)

# .ssh directory in project
if [[ -d "$TARGET_DIR/.ssh" ]]; then
  log_critical ".ssh/ directory found inside project root — should not be committed"
  PHASE5_ISSUES=$((PHASE5_ISSUES + 1))
fi

# known_hosts / authorized_keys
while IFS= read -r sshfile; do
  log_warning "SSH meta file found in project: $sshfile"
  PHASE5_ISSUES=$((PHASE5_ISSUES + 1))
done < <(find "$TARGET_DIR" \
  -not -path "*/node_modules/*" \
  -not -path "*/_deleted/*" \
  -not -path "*/.git/*" \
  \( -name "known_hosts" -o -name "authorized_keys" \) \
  -type f 2>/dev/null)

if [[ $PHASE5_ISSUES -eq 0 ]]; then
  log_pass "No SSH private keys or secret files found"
fi

# ============================================================
# Phase 6: Cloud Configuration Check
# ============================================================
echo ""
echo -e "${CYAN}[Phase 6] Cloud configuration check${NC}"

PHASE6_ISSUES=0

# Docker Compose: hardcoded secrets in environment: blocks
for compose_file in docker-compose.yml docker-compose.yaml docker-compose.prod.yml docker-compose.production.yml; do
  if [[ -f "$TARGET_DIR/$compose_file" ]]; then
    for pattern in "${SECRET_PATTERNS[@]}"; do
      if grep -qE "${pattern}[[:space:]]*:[[:space:]]*[^$\"\'][^{]" "$TARGET_DIR/$compose_file" 2>/dev/null; then
        log_warning "$compose_file: $pattern appears to have a hardcoded value (not using \${VAR} syntax)"
        PHASE6_ISSUES=$((PHASE6_ISSUES + 1))
      fi
    done
  fi
done

# K8s: service account token mounts in project
while IFS= read -r yamlfile; do
  if grep -q 'automountServiceAccountToken: true' "$yamlfile" 2>/dev/null; then
    log_warning "$yamlfile: automountServiceAccountToken: true — review if necessary"
    PHASE6_ISSUES=$((PHASE6_ISSUES + 1))
  fi
  if grep -q 'serviceAccountName' "$yamlfile" 2>/dev/null && \
     grep -q 'mountPath.*serviceaccount' "$yamlfile" 2>/dev/null; then
    log_warning "$yamlfile: service account token mount detected — verify token scope"
    PHASE6_ISSUES=$((PHASE6_ISSUES + 1))
  fi
done < <(find "$TARGET_DIR" \
  -not -path "*/node_modules/*" \
  -not -path "*/_deleted/*" \
  \( -name "*.yaml" -o -name "*.yml" \) \
  -type f 2>/dev/null | head -50)

# AWS: IMDSv2 check hint
if [[ -f "$TARGET_DIR/package.json" ]] && grep -qiE '"aws-sdk|@aws-sdk' "$TARGET_DIR/package.json" 2>/dev/null; then
  log_info "AWS SDK dependency detected — ensure IMDSv2 is enforced (AWS_EC2_METADATA_DISABLED or HttpPutResponseHopLimit=1)"
fi

if [[ $PHASE6_ISSUES -eq 0 ]]; then
  log_pass "No obvious cloud configuration issues found"
fi

# ============================================================
# Phase 7: IOC Check (Cisco Talos)
# ============================================================
echo ""
echo -e "${CYAN}[Phase 7] IOC check (Cisco Talos / CVE-2025-55182)${NC}"

PHASE7_ISSUES=0

# C2 IP addresses from Cisco Talos
declare -a C2_IPS=(
  "144.172.102.88"
  "172.86.127.128"
  "144.172.112.136"
  "144.172.117.112"
)

# Check source files for C2 IP references
for ip in "${C2_IPS[@]}"; do
  while IFS= read -r match_file; do
    log_critical "C2 IP address '$ip' found in source: $match_file"
    match_line=$(grep -m1 "$ip" "$match_file" 2>/dev/null | head -c 120 || true)
    echo -e "  ${RED}  -> $match_line${NC}"
    PHASE7_ISSUES=$((PHASE7_ISSUES + 1))
  done < <(grep -rl "$ip" "$TARGET_DIR" \
    --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" \
    --include="*.mjs" --include="*.json" --include="*.env" \
    2>/dev/null | grep -v node_modules | grep -v .git || true)
done

# /tmp/ random dot-prefix processes (Linux only)
if [[ "$(uname -s)" == "Linux" ]]; then
  while IFS= read -r tmpfile; do
    log_critical "Suspicious /tmp/ dotfile detected: $tmpfile"
    PHASE7_ISSUES=$((PHASE7_ISSUES + 1))
  done < <(find /tmp -maxdepth 1 -name ".*" -type f 2>/dev/null | grep -E '/tmp/\.[a-f0-9]{6,}' || true)
fi

# nohup in project scripts (suspicious usage)
for pkg_json in "$TARGET_DIR"/package.json "$TARGET_DIR"/package.scripts.json; do
  if [[ -f "$pkg_json" ]]; then
    if grep -qE '"[^"]*"[[:space:]]*:[[:space:]]*"[^"]*nohup[[:space:]]' "$pkg_json" 2>/dev/null; then
      match=$(grep -E 'nohup' "$pkg_json" 2>/dev/null | head -1 | head -c 120)
      log_warning "$(basename "$pkg_json"): nohup usage in scripts — review: $match"
      PHASE7_ISSUES=$((PHASE7_ISSUES + 1))
    fi
  fi
done

if [[ $PHASE7_ISSUES -eq 0 ]]; then
  log_pass "No known IOCs detected"
fi

# ============================================================
# Phase 8: Summary Report
# ============================================================
echo ""
echo -e "${CYAN}${BOLD}=== Scan Summary ===${NC}"
echo -e "  CRITICAL : ${RED}${BOLD}$CRITICAL_COUNT${NC}"
echo -e "  WARNING  : ${YELLOW}$WARNING_COUNT${NC}"
echo -e "  INFO     : $INFO_COUNT"
echo ""

if [[ $CRITICAL_COUNT -gt 0 ]]; then
  echo -e "${RED}${BOLD}CRITICAL issues found. Immediate action required.${NC}"
  echo ""
  echo -e "${YELLOW}=== Remediation (CVE-2025-55182) ===${NC}"
  echo ""
  echo "1. Upgrade Next.js to a patched version:"
  echo "   npm install next@latest"
  echo "   # or pin to a specific safe release:"
  echo "   npm install next@15.3.6   # check https://github.com/vercel/next.js/releases"
  echo ""
  echo "2. Upgrade React if on vulnerable version (19.0.0, 19.1.0, 19.1.1, 19.2.0):"
  echo "   npm install react@latest react-dom@latest"
  echo ""
  echo "3. Rotate all secrets immediately if exploitation is suspected:"
  echo "   - API keys, database credentials, JWT secrets"
  echo "   - SSH keys, cloud IAM credentials"
  echo "   - npm/GitHub tokens"
  echo ""
  echo "4. Check for post-exploitation artifacts:"
  echo "   - Unexpected processes: ps aux | grep -E '\\.sh|\\.py'"
  echo "   - Cron changes: crontab -l; cat /etc/cron*"
  echo "   - Network connections: ss -tnp | grep -E '144\\.172|172\\.86'"
  echo "   - /tmp/ anomalies: ls -la /tmp/ | grep '^\\.' "
  echo ""
  echo "5. SNORT rule for network detection: SID 65554"
  echo "   C2 IPs to block: 144.172.102.88 / 172.86.127.128 / 144.172.112.136 / 144.172.117.112"
  echo ""
  echo "Reference: https://nvd.nist.gov/vuln/detail/CVE-2025-55182"
  echo "           https://blog.talosintelligence.com/  (search: React2Shell)"
  exit 2
elif [[ $WARNING_COUNT -gt 0 ]]; then
  echo -e "${YELLOW}Warnings found. Review the items above.${NC}"
  echo ""
  echo "General recommendations:"
  echo "  - Store secrets in a vault (AWS Secrets Manager, HashiCorp Vault)"
  echo "  - Use NEXTAUTH_SECRET from environment, never hardcoded"
  echo "  - Add .env* to .gitignore (keep .env.example committed)"
  echo "  - Run this scanner in CI/CD on every PR"
  exit 1
else
  echo -e "${GREEN}${BOLD}No issues found. Project appears clean.${NC}"
  echo ""
  echo "Preventive recommendations:"
  echo "  - Pin dependency versions exactly (no ^ or ~)"
  echo "  - Enable Dependabot / Renovate for automatic security updates"
  echo "  - Run this scanner in CI/CD on every PR"
  echo "  - Subscribe to Next.js security advisories: https://github.com/vercel/next.js/security"
  exit 0
fi
