#!/usr/bin/env bash
#
# fix_up.sh — Vulnix remediation & hardening script
#
# Target:   Ubuntu 12.04 (legacy init — uses `service`/`update-rc.d`, not systemd)
# Purpose:  Automates remediation of findings from the Vulnix security
#           assessment (NFS misconfig, legacy services, weak SSH config,
#           interactive service shells, backdoor user).
#
# WARNING:  LAB USE FIRST — verify against a snapshot before touching
#           anything resembling production. This script implements a
#           DEFAULT-DROP firewall policy. Run from console, not SSH,
#           or keep a rollback path (see SAFETY NOTE below).
#
# Author:   e-Itohan
# Source:   Manual remediation performed 2026-04, CyberSteps training lab

set -u  # abort on undefined vars (not -e: hardening must continue past individual failures)

LOG="/tmp/fix_up_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

banner() { printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }

banner "=== Vulnix hardening started ==="

# ------------------------------------------------------------------
# 5.1 System updates — clear stale dpkg locks, attempt refresh
# ------------------------------------------------------------------
banner "Clearing package-manager locks"

killall apt apt-get dpkg 2>/dev/null
rm -f /var/lib/apt/lists/lock
rm -f /var/cache/apt/archives/lock
rm -f /var/lib/dpkg/lock

apt-get update -qq || echo "[!] apt update failed — continuing (lab constraint)"

# ------------------------------------------------------------------
# 5.2 Remove/disable legacy & unnecessary services
# ------------------------------------------------------------------
banner "Removing legacy services (finger, rsh, uucp, dovecot, postfix)"

apt-get remove --purge -y finger fingerd rsh-server uucp dovecot-core postfix \
    && echo "[+] Legacy packages purged" \
    || echo "[!] Package purge reported errors — check log"

banner "Stopping and disabling NFS"

service nfs-kernel-server stop 2>/dev/null || echo "[!] nfs-kernel-server not running"
update-rc.d -f nfs-kernel-server remove
# NFS depends on rpcbind — disable that too
service rpcbind stop 2>/dev/null || true
update-rc.d -f rpcbind remove

# ------------------------------------------------------------------
# 5.3 User account hardening
# ------------------------------------------------------------------
banner "Removing persistence (backdoor user 'vulnix')"

if id vulnix &>/dev/null; then
    userdel -r vulnix && echo "[+] Backdoor user 'vulnix' deleted"
else
    echo "[*] User 'vulnix' not present — nothing to do"
fi

banner "Locking shells on service accounts (Principle of Least Privilege)"

LOCKED_ACCOUNTS="daemon bin sys games man lp mail news uucp proxy \
www-data backup list irc gnats nobody libuuid landscape statd"

for user in $LOCKED_ACCOUNTS; do
    if id "$user" &>/dev/null; then
        usermod -s /usr/sbin/nologin "$user"
        echo "[+] Locked shell for $user"
    fi
done

# ------------------------------------------------------------------
# 5.4 Network hardening — iptables, default-DROP
# ------------------------------------------------------------------
banner "Applying firewall rules"

# SAFETY NOTE: if this is run over SSH and something fails, you can be
# locked out. Rollback escape hatch: `iptables -P INPUT ACCEPT && iptables -F`
# Run that from console if the session dies mid-script.

# Allow SSH first — rules are evaluated top-down
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Keep established sessions alive (prevents self-lockout)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Block legacy / attack-vector ports
iptables -A INPUT -p tcp --dport 25   -j DROP  # SMTP      (plaintext mail)
iptables -A INPUT -p tcp --dport 79   -j DROP  # Finger    (info disclosure)
iptables -A INPUT -p tcp --dport 110  -j DROP  # POP3      (plaintext mail)
iptables -A INPUT -p tcp --dport 111  -j DROP  # RPCBind   (NFS support)
iptables -A INPUT -p tcp --dport 143  -j DROP  # IMAP      (plaintext mail)
iptables -A INPUT -p tcp --dport 512:514 -j DROP  # RSH/Rlogin (legacy remote shell)
iptables -A INPUT -p tcp --dport 993  -j DROP  # IMAPS
iptables -A INPUT -p tcp --dport 995  -j DROP  # POP3S
iptables -A INPUT -p tcp --dport 2049 -j DROP  # NFS       (exploited vector)

# Default policy: deny inbound, allow outbound
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

echo "[+] Firewall applied (default-DROP inbound, SSH + loopback only)"

# ------------------------------------------------------------------
# 5.5 SSH hardening
# ------------------------------------------------------------------
banner "Hardening SSH daemon"

sed -i 's/^PermitRootLogin yes/PermitRootLogin no/'        /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

service ssh restart
echo "[+] SSH: root login disabled, key-based auth only"

# ------------------------------------------------------------------
# Verification
# ------------------------------------------------------------------
banner "=== Post-hardening verification ==="

echo "--- Open ports ---"
netstat -tulnp 2>/dev/null | grep LISTEN || ss -tulnp | grep LISTEN

echo "--- NFS exports ---"
showmount -e localhost 2>&1 || true

echo "--- Backdoor user check ---"
id vulnix 2>/dev/null && echo "[!!] FAIL: vulnix still exists" || echo "[OK] vulnix removed"

echo "--- Service account shells ---"
grep -E '(nologin|/bin/(ba)?sh)$' /etc/passwd | grep -E 'www-data|uucp|nobody' || true

banner "=== Hardening complete — log saved to $LOG ==="
