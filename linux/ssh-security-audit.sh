#!/usr/bin/env bash
# Read-only OpenSSH server configuration audit.
# Intended for systems you own or are explicitly authorized to assess.

set -u

SSHD_CONFIG="${1:-/etc/ssh/sshd_config}"

if [[ ! -r "$SSHD_CONFIG" ]]; then
  echo "ERROR: Cannot read $SSHD_CONFIG" >&2
  exit 1
fi

get_sshd_value() {
  local key="$1"
  awk -v k="$key" '
    BEGIN { IGNORECASE=1 }
    /^[[:space:]]*#/ { next }
    tolower($1)==tolower(k) { value=$2 }
    END { if (value != "") print value }
  ' "$SSHD_CONFIG"
}

print_check() {
  local label="$1" actual="$2" expected="$3" status="$4"
  printf "%-30s %-14s %-20s %s\n" "$label" "${actual:-default}" "$expected" "$status"
}

printf "OpenSSH server audit: %s\n\n" "$SSHD_CONFIG"
printf "%-30s %-14s %-20s %s\n" "Setting" "Observed" "Recommended" "Result"
printf '%*s\n' 82 '' | tr ' ' '-'

permit_root="$(get_sshd_value PermitRootLogin || true)"
case "${permit_root,,}" in
  no|prohibit-password|without-password) root_status="OK" ;;
  "") root_status="REVIEW" ;;
  *) root_status="WARN" ;;
esac
print_check "PermitRootLogin" "$permit_root" "no/prohibit-password" "$root_status"

password_auth="$(get_sshd_value PasswordAuthentication || true)"
case "${password_auth,,}" in
  no) pass_status="OK" ;;
  "") pass_status="REVIEW" ;;
  *) pass_status="WARN" ;;
esac
print_check "PasswordAuthentication" "$password_auth" "no" "$pass_status"

pubkey_auth="$(get_sshd_value PubkeyAuthentication || true)"
case "${pubkey_auth,,}" in
  yes|"") pubkey_status="OK" ;;
  *) pubkey_status="WARN" ;;
esac
print_check "PubkeyAuthentication" "$pubkey_auth" "yes" "$pubkey_status"

empty_passwords="$(get_sshd_value PermitEmptyPasswords || true)"
case "${empty_passwords,,}" in
  no|"") empty_status="OK" ;;
  *) empty_status="WARN" ;;
esac
print_check "PermitEmptyPasswords" "$empty_passwords" "no" "$empty_status"

x11_forwarding="$(get_sshd_value X11Forwarding || true)"
case "${x11_forwarding,,}" in
  no) x11_status="OK" ;;
  "") x11_status="REVIEW" ;;
  *) x11_status="WARN" ;;
esac
print_check "X11Forwarding" "$x11_forwarding" "no" "$x11_status"

max_auth="$(get_sshd_value MaxAuthTries || true)"
if [[ "$max_auth" =~ ^[0-9]+$ ]]; then
  if (( max_auth <= 4 )); then max_status="OK"; else max_status="WARN"; fi
else
  max_status="REVIEW"
fi
print_check "MaxAuthTries" "$max_auth" "4 or fewer" "$max_status"

login_grace="$(get_sshd_value LoginGraceTime || true)"
print_check "LoginGraceTime" "$login_grace" "60 or less" "INFO"

allow_users="$(get_sshd_value AllowUsers || true)"
allow_groups="$(get_sshd_value AllowGroups || true)"
if [[ -n "$allow_users" || -n "$allow_groups" ]]; then
  allow_status="OK"
else
  allow_status="REVIEW"
fi
print_check "AllowUsers/AllowGroups" "${allow_users:-${allow_groups:-unset}}" "restrict if practical" "$allow_status"

if command -v sshd >/dev/null 2>&1; then
  echo
  echo "Effective configuration validation:"
  if sshd -t -f "$SSHD_CONFIG" 2>/dev/null; then
    echo "OK: sshd configuration syntax is valid."
  else
    echo "WARN: sshd reported a configuration syntax problem or requires additional context."
  fi
fi

echo
echo "Notes:"
echo "- REVIEW means the setting is absent or environment-dependent; confirm the effective sshd defaults."
echo "- Disabling password authentication can lock out users unless key-based access is verified first."
echo "- This script does not modify the host."
