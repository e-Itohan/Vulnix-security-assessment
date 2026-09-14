# 🔐 Vulnix — Vulnerability Assessment, Exploitation & Hardening

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Classification](https://img.shields.io/badge/Environment-Lab%20Only-blue)
![Platform](https://img.shields.io/badge/Target-Ubuntu%2012.04-red)
![Author](https://img.shields.io/badge/Author-e--Itohan-purple)

> ⚠️ **Disclaimer:** This assessment was performed in a controlled CyberSteps training lab environment against an intentionally vulnerable VM. All IPs shown are private lab addresses.

## 📋 Overview

Full-cycle security assessment of the **Vulnix** host (Ubuntu 12.04): reconnaissance → exploitation → post-exploitation → **automated remediation**. The assessment chained a series of misconfigurations into a complete system compromise, then reversed the damage with a custom hardening script.

**Role:** Pentester / Blue Team (full cycle) · **Written for:** CyberSteps Training Program · **April 2026**

### The Attack Chain

Recon (Nmap/Finger) → SSH Brute Force → Low-Priv Foothold ('user') → sudo misconfig (sudoedit /etc/exports, NOPASSWD) → NFS export abuse (add no_root_squash) → Mount share as remote root → SUID bash copy → ROOT → Persistence (backdoor user 'vulnix')


## 🎯 Key Findings

| # | Finding | Severity | Impact |
|---|---------|----------|--------|
| 1 | NFS `no_root_squash` misconfiguration | 🔴 Critical | Remote root via mounted share |
| 2 | Sudo misconfig — passwordless `sudoedit /etc/exports` | 🔴 Critical | Privilege escalation to root |
| 3 | Legacy services (Finger, RSH/Rlogin, UUCP) | 🟠 High | Information disclosure, legacy attack surface |
| 4 | Weak SSH configuration (root login + password auth) | 🟠 High | Susceptible to brute force |
| 5 | Service accounts with interactive shells (`/bin/sh`) | 🟡 Medium | Increased blast radius post-compromise |
| 6 | Plaintext mail protocols (POP3/IMAP) | 🟡 Medium | Credential/data interception |

## 🔍 Methodology

1. **Reconnaissance** — Nmap port/service enumeration, SSH user enumeration (Metasploit `auxiliary/scanner/ssh/ssh_enumusers`), Finger-based user info leak
2. **Exploitation** — Hydra brute force (rockyou wordlist), NFS share mounting, sudo misconfiguration abuse, SUID payload
3. **Post-Exploitation** — Backdoor user creation, persistence mechanisms
4. **Remediation** — Custom Bash hardening script (`fix_up.sh`), iptables firewall rules, account lockdown

## 🗡️ Exploitation Details

### 1. Initial Access — SSH Brute Force

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.134

```
### 2. Privilege Escalation — sudo + NFS Chain

The core of this box: sudo -l reveals passwordless sudoedit rights on /etc/exports:
User user may run the following commands:
    (root) NOPASSWD: sudoedit /etc/exports

Modifying the NFS export with no_root_squash lets a remote root user mount the share and interact as root:
# On attacker (Kali), as root:
ssh-keygen -t rsa -f vulnix_key
mount -t nfs -o rw,vers=3 10.10.10.134:/home/vulnix /mnt/vulnix
# ... authorized_keys planted, escalate via exported /etc/exports ...

# Final blow — SUID bash:
chown root:root bash
./bash -p    # root shell

**Why this chain matters:** individually, none of these misconfigs is fatal. Together they demonstrate why *configuration hygiene* (least privilege, service minimization) is the real defense — a recurring lesson of this assessment.

### 3. Persistence — Backdoor User

Created hidden user `vulnix` (UID 2008) to test persistence detection/removal during remediation.

## 🛠️ Remediation (`fix\_up.sh`)

Automated hardening script adapted for the legacy init environment (`service` vs `systemctl`):

- **Legacy service purge** — `finger`, `rsh-server`, `uucp`, `dovecot-core`, `postfix` removed 

- **NFS disabled** — `nfs-kernel-server` stopped and removed from runlevels 

- **Account lockdown** — 17 service accounts set to `/usr/sbin/nologin`, backdoor user deleted (`userdel -r vulnix`) 

- **Firewall** — iptables default-DROP policy; only SSH (22) permitted: 

`iptables -A INPUT -p tcp --dport 22 -j ACCEPT iptables -P INPUT DROP *\# ... blocking 25, 79, 110, 111, 143, 512-514, 993, 995, 2049 ...`*

- **SSH hardening** — `PermitRootLogin no`, `PasswordAuthentication no` 

`sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd\_config sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd\_config`

Full script: [`fix\_up.sh`](https://lumo.proton.me/fix_up.sh)

## 🚀 Usage — Running the Hardening Script

The remediation was performed manually during the assessment; [`fix_up.sh`](./fix_up.sh) reconstructs those steps as a repeatable, idempotent script (safe to re-run).

### Requirements

- Ubuntu 12.04 (legacy init — uses `service` / `update-rc.d`, not systemd)
- Root privileges
- **Physical console or VM console access** (see safety note below)

### Running

```bash
# Review what it does first — never blind-run hardening scripts
less fix_up.sh

# Make executable and run
chmod +x fix_up.sh
sudo ./fix_up.sh
```
## ✅ Verification

Post-hardening Nmap confirms attack surface reduction to a single SSH port:

| **Check** | **Before** | **After** |
| :-: | :-: | :-: |
| Open ports | 20+ (incl. 79, 111, 512–514, 2049) | 22 only |
| NFS exports | `/home/vulnix` readable | None (`showmount` empty) |
| Service account shells | `/bin/sh` | `/usr/sbin/nologin` |
| Backdoor user `vulnix` | Present (UID 2008) | Removed |
| SSH root login / passwords | Enabled | Disabled |

## 💡 Lessons Learned

> The unique exploit chain got the headlines, but the **generic misconfigurations** guaranteed maximum post-compromise freedom. Finger leaking the user list, service accounts with login shells, and untouched legacy services did more damage than any single "cool" exploit. **Security hygiene beats exploit sophistication.**

Interesting context from the research: UUCP isn't dead — it still runs on remote/isolated systems (some schools, even maritime communication) where no internet access exists. "Legacy" doesn't mean "gone."

## 📈 Production Recommendations

1. **OS Migration** — Ubuntu 12.04 is far past EOL; migrate to a supported LTS 

2. **Monitoring** — Deploy `fail2ban`/syslog alerting for brute-force detection *(couldn't be installed in this lab due to package-lock constraints)* 

3. **Periodic audits** — Schedule reviews of `/etc/passwd` and `/etc/exports` to catch configuration drift 

## 🧰 Toolset

`Nmap` · `Metasploit` · `Hydra` · `NFS` · `iptables` · `Bash` · `sed`


*Blue teamer practice: break it, understand it, then fix it better than it was.*

