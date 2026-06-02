#!/bin/bash
# ============================================================
# Linux Hardening Script — Mini Shai-Hulud npm Supply Chain Defense
# Test ID: ae9002e4-3d82-4fcd-8b45-f7e0628f7375
# Target: developer workstations and CI runners
#
# Hardens against npm install-time supply-chain compromise:
#   - Disables npm lifecycle scripts by default (ignore-scripts)
#   - Enforces lockfile-only installs
#   - Restricts cloud metadata (IMDS) reachability from build processes
#   - Adds auditd rules for credential-file access and worm artifacts
#
# Usage:  sudo ./<uuid>_hardening_linux.sh [--apply]   (default: dry-run/report)
# ============================================================

set -u

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "This script should run as root to apply system-level controls."
    warn "Re-run with: sudo $0 ${1:-}"
    [[ $APPLY -eq 1 ]] && exit 1
  fi
}

apply_or_report() {
  local desc="$1"; shift
  if [[ $APPLY -eq 1 ]]; then
    log "APPLY: $desc"
    "$@"
  else
    warn "DRY-RUN (would apply): $desc"
  fi
}

require_root "$@"

echo "============================================================"
echo " Mini Shai-Hulud npm Supply Chain Hardening (Linux)"
echo " Mode: $([[ $APPLY -eq 1 ]] && echo APPLY || echo DRY-RUN)"
echo "============================================================"

# ------------------------------------------------------------
# 1. Disable npm lifecycle scripts globally (highest leverage)
# ------------------------------------------------------------
echo ""
echo "[1] npm: disable install lifecycle scripts (ignore-scripts)"
NPMRC_GLOBAL="/etc/npmrc"
write_npmrc() {
  touch "$NPMRC_GLOBAL"
  grep -q '^ignore-scripts=' "$NPMRC_GLOBAL" 2>/dev/null \
    && sed -i 's/^ignore-scripts=.*/ignore-scripts=true/' "$NPMRC_GLOBAL" \
    || echo 'ignore-scripts=true' >> "$NPMRC_GLOBAL"
  # Reduce blast radius of new versions
  grep -q '^audit=' "$NPMRC_GLOBAL" 2>/dev/null || echo 'audit=true' >> "$NPMRC_GLOBAL"
}
apply_or_report "set ignore-scripts=true in $NPMRC_GLOBAL" write_npmrc
echo "    Current global npm setting:"
npm config get ignore-scripts 2>/dev/null | sed 's/^/      /' || echo "      (npm not installed)"

# ------------------------------------------------------------
# 2. Enforce lockfile-only installs (advisory wrapper note)
# ------------------------------------------------------------
echo ""
echo "[2] CI guidance: prefer 'npm ci' (lockfile-enforced) over 'npm install'"
warn "Ensure CI pipelines invoke 'npm ci' against a reviewed package-lock.json."
warn "Route installs through a private registry/proxy with a quarantine window."

# ------------------------------------------------------------
# 3. Restrict cloud instance metadata (IMDS) reachability
# ------------------------------------------------------------
echo ""
echo "[3] Block cloud metadata endpoint (169.254.169.254) for non-root build users"
block_imds() {
  # Block IMDS from anything not owned by root (build processes run as build user).
  if command -v iptables >/dev/null 2>&1; then
    iptables -C OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP 2>/dev/null \
      || iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP
  else
    warn "iptables not present; apply equivalent egress policy via your CNI/cloud SG."
  fi
}
apply_or_report "drop egress to 169.254.169.254 from non-root users" block_imds
warn "On AWS, also enforce IMDSv2 with HttpPutResponseHopLimit=1 at the instance level."

# ------------------------------------------------------------
# 4. auditd rules: credential-file access + worm artifacts
# ------------------------------------------------------------
echo ""
echo "[4] auditd: monitor credential files and worm/workflow artifacts"
AUDIT_RULES="/etc/audit/rules.d/shaihulud.rules"
write_audit() {
  cat > "$AUDIT_RULES" <<'EOF'
## Mini Shai-Hulud supply-chain monitoring
# Credential file reads
-w /etc/npmrc -p wra -k shaihulud_cred
-a always,exit -F arch=b64 -S openat -F path=/root/.aws/credentials -F perm=r -k shaihulud_cred
-a always,exit -F arch=b64 -S openat -F path=/root/.ssh/id_ed25519 -F perm=r -k shaihulud_cred
-a always,exit -F arch=b64 -S openat -F path=/root/.git-credentials -F perm=r -k shaihulud_cred
# Bun staging temp dirs and anti-forensic payload temp files
-w /tmp -p wa -k shaihulud_tmp
EOF
  if command -v augenrules >/dev/null 2>&1; then augenrules --load 2>/dev/null || true
  elif command -v auditctl >/dev/null 2>&1; then auditctl -R "$AUDIT_RULES" 2>/dev/null || true; fi
}
if command -v auditctl >/dev/null 2>&1; then
  apply_or_report "install auditd rules to $AUDIT_RULES" write_audit
else
  warn "auditd not installed; install 'auditd' to enable file-access telemetry."
fi

# ------------------------------------------------------------
# 5. Posture report
# ------------------------------------------------------------
echo ""
echo "[5] Posture summary"
echo "    npm ignore-scripts : $(npm config get ignore-scripts 2>/dev/null || echo 'n/a')"
echo "    IMDS egress rule   : $(iptables -C OUTPUT -d 169.254.169.254 -m owner ! --uid-owner 0 -j DROP 2>/dev/null && echo present || echo absent)"
echo "    auditd rules       : $([[ -f "$AUDIT_RULES" ]] && echo installed || echo absent)"
echo ""
log "Hardening pass complete ($([[ $APPLY -eq 1 ]] && echo applied || echo dry-run))."
[[ $APPLY -eq 0 ]] && warn "Re-run with --apply to enforce these controls."
exit 0
