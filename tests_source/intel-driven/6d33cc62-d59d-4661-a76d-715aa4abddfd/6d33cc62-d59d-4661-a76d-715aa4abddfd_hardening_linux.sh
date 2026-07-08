#!/usr/bin/env bash
# ============================================================================
# Hardening / Posture Audit — PII Exfiltration to External Inference Services
# Test ID: 6d33cc62-d59d-4661-a76d-715aa4abddfd
# MITRE ATT&CK: T1552.001, T1119, T1005, T1567
# Platform: Linux
#
# Focus: shadow-AI PII egress. PRIMARY controls live in the network egress layer
# (forward proxy / CASB / DLP / protective DNS). This script AUDITS host-observable
# posture and can add a compensating nftables/iptables egress block with --apply.
#
# Usage:
#   ./6d33cc62-..._hardening_linux.sh            # audit only
#   sudo ./6d33cc62-..._hardening_linux.sh --apply   # add local egress block (compensating)
# ============================================================================

set -u

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

AI_HOSTS=(
  "api.openai.com" "chatgpt.com" "openai.com"
  "api.anthropic.com" "claude.ai" "anthropic.com"
  "generativelanguage.googleapis.com" "gemini.google.com"
  "api.githubcopilot.com" "copilot.microsoft.com"
)

echo "==================================================================="
echo " Shadow-AI PII Egress — Linux Posture Audit"
echo "==================================================================="

# ---- 1. Proxy environment (is egress inspected?) ----
echo
echo "[1] Proxy environment variables"
for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY; do
  if [ -n "${!v:-}" ]; then echo "    ${v}=${!v} (egress may be inspected)"; fi
done
if [ -z "${https_proxy:-}${HTTPS_PROXY:-}" ]; then
  echo "    WARNING: no https proxy configured — direct egress to AI vendors is likely uninspected."
fi

# ---- 2. DNS resolver (protective DNS recommended) ----
echo
echo "[2] DNS resolver configuration"
if command -v resolvectl >/dev/null 2>&1; then
  resolvectl status 2>/dev/null | grep -E 'DNS Servers|Current DNS' | head -n 5
else
  grep -E '^nameserver' /etc/resolv.conf 2>/dev/null || echo "    (could not read resolver config)"
fi

# ---- 3. Direct reachability of AI vendor hosts (reachable = potential leak path) ----
echo
echo "[3] Direct reachability of AI vendor hosts on 443"
for h in api.openai.com api.anthropic.com generativelanguage.googleapis.com api.githubcopilot.com; do
  if timeout 4 bash -c "exec 3<>/dev/tcp/${h}/443" 2>/dev/null; then
    echo "    ${h}: REACHABLE (no egress control)"
    exec 3>&- 2>/dev/null || true
  else
    echo "    ${h}: blocked/unreachable (good)"
  fi
done

# ---- 4. AI-service key exposure in common stores ----
echo
echo "[4] AI-service API-key exposure in common user stores"
KEY_RE='OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|sk-ant-|sk-proj-|AIza'
for f in "$HOME/.env" "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" \
         "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.aws/credentials" \
         "$HOME/.config/openai/auth.json" "$HOME/.config/anthropic/config.json" \
         "$HOME/.continue/config.json" "$HOME/.netrc"; do
  if [ -f "$f" ]; then
    if grep -Eq "$KEY_RE" "$f" 2>/dev/null; then
      echo "    WARNING: possible AI key material in: $f"
    fi
  fi
done
while IFS='=' read -r name _; do
  case "$name" in
    *OPENAI*|*ANTHROPIC*|*GEMINI*|*COPILOT*|*HUGGINGFACE*|*MISTRAL*|*COHERE*)
      echo "    WARNING: AI-service key present in environment variable: $name (value redacted)" ;;
  esac
done < <(env)

# ---- 5. Optional compensating control: egress firewall block ----
echo
echo "[5] Host-firewall compensating control"
if [ "$APPLY" -eq 1 ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "    WARNING: --apply requires root. Re-run with sudo to add firewall rules."
  elif command -v nft >/dev/null 2>&1; then
    nft add table inet f0rtika 2>/dev/null || true
    nft add chain inet f0rtika out '{ type filter hook output priority 0; }' 2>/dev/null || true
    added=0
    for h in "${AI_HOSTS[@]}"; do
      for ip in $(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u); do
        nft add rule inet f0rtika out ip daddr "$ip" tcp dport 443 drop 2>/dev/null && added=$((added+1))
      done
    done
    echo "    Added $added nftables drop rule(s) for resolved AI-vendor IPs (compensating only; IPs rotate)."
  else
    echo "    nft not available; add equivalent iptables OUTPUT drops for the AI-vendor IPs, or rely on the proxy/DNS layer."
  fi
else
  echo "    (audit only) Re-run with sudo --apply to add a local egress block. Prefer proxy/CASB/DNS controls as primary."
fi

echo
echo "==================================================================="
echo " Audit complete. PRIMARY control = forward proxy / CASB / DLP + protective DNS"
echo " with TLS inspection and PII content policies on AI-vendor egress."
echo "==================================================================="
