#!/usr/bin/env bash
set -u

OUT="linux-security-audit-$(date +%Y%m%d-%H%M%S).txt"
{
  echo "EZTech Linux Security Audit"
  echo "Generated: $(date -Is)"
  echo
  echo "== Host =="
  hostnamectl 2>/dev/null || uname -a
  echo
  echo "== Logged-in users =="
  who
  echo
  echo "== UID 0 accounts =="
  awk -F: '$3 == 0 {print $1}' /etc/passwd
  echo
  echo "== Listening sockets =="
  ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null
  echo
  echo "== Firewall =="
  command -v ufw >/dev/null && ufw status verbose
  command -v firewall-cmd >/dev/null && firewall-cmd --list-all
  command -v nft >/dev/null && nft list ruleset 2>/dev/null
  echo
  echo "== Failed SSH/login activity =="
  lastb -n 30 2>/dev/null || true
  echo
  echo "== SUID files =="
  find / -xdev -perm -4000 -type f 2>/dev/null
  echo
  echo "== World-writable files (local filesystems, first 200) =="
  find / -xdev -type f -perm -0002 2>/dev/null | head -200
  echo
  echo "== Recent package updates =="
  command -v apt >/dev/null && apt list --upgradable 2>/dev/null
  command -v dnf >/dev/null && dnf check-update 2>/dev/null || true
} > "$OUT"

echo "Security audit written to $OUT"
