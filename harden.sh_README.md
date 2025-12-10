# Debian Hardening Script v5.5 - Technical Summary

## Overview

Automated configuration and hardening script for Debian servers with Active Directory integration, Docker compatibility, and continuous security audit chain.

***

## Core Features

### 1. **Active Directory Integration**

- Automated AD domain join via SSSD/Realmd
- Kerberos authentication for domain users
- AD group-based sudo rights management
- Automatic home directory creation (PAM mkhomedir)


### 2. **User Management \& SSH Access**

- Dynamic system supporting up to 5 users
- Automated SSH public key injection
- Strict permission configuration (700 for .ssh, 600 for authorized_keys)
- AD user support with key-based authentication


### 3. **SSH Hardening**

- SSH port customization (per-machine configuration)
- Password authentication disabled
- Root login disabled
- Legal banners (issue/issue.net)
- Custom MOTD with connection information


### 4. **Kernel Hardening (Docker Compatible)**

Optimized sysctl parameters:

- SYN flood protection (tcp_syncookies)
- ICMP redirect disabled
- IP spoofing protection (rp_filter)
- Address Space Layout Randomization (ASLR)
- Kernel log access restriction (dmesg_restrict)


### 5. **Continuous Security Audit Chain**

#### AIDE (Advanced Intrusion Detection Environment)

- Daily filesystem integrity scan
- Detection of file modifications, additions, and deletions
- Automatic email alerts on changes


#### RKHunter (Rootkit Hunter)

- Daily rootkit scanning
- Weekly signature updates
- Detection of known backdoors and exploits


#### Auditd

- Weekly security event reports
- Critical file access monitoring
- Detailed system operation logging


### 6. **Intrusion Prevention**

- **Fail2Ban**: Automatic ban after 5 failed SSH attempts (1h duration)
- Custom configuration for modified SSH port
- Active authentication log monitoring


### 7. **Email Alert System**

- Centralized alerts to security email address
- Automatic Postfix configuration
- Notifications for:
    - AIDE-detected changes
    - RKHunter-suspected rootkits
    - Audit chain errors
    - Weekly Auditd reports


### 8. **Permissions \& Access Controls**

- Hardened sudoers permissions (0440)
- Restrictive cron directory permissions (700)
- ACL configuration for critical files
- Administrative privilege separation


### 9. **Log Rotation**

- Logrotate configured biweekly
- 7 compressed versions retained
- Separate archiving for AIDE and RKHunter logs


### 10. **Fixes \& Optimizations**

- CDROM sources disabled (prevents APT errors)
- Non-interactive Postfix and Kerberos configuration
- RKHunter mirrors.dat file fix
- Optimized RKHunter update parameters

***

## Execution Process (13 steps + initialization)

1. Configure sources.list (disable CDROM)
2. Pre-configure Postfix \& Kerberos (non-interactive)
3. Install dependencies (AD, audit, security)
4. Fix RKHunter configuration
5. Join Active Directory domain
6. Configure Postfix aliases (email alerts)
7. Configure sudoers and critical permissions
8. Create user profiles and inject SSH keys
9. SSH hardening and legal banners
10. Configure Fail2Ban and PAM
11. Kernel hardening (Docker-compatible sysctl)
12. Configure audit chain (cron scripts)
13. Configure custom MOTD
14. Initialize AIDE and RKHunter databases

***

## Key Strengths

✅ **Complete automation**: Installation and configuration in single execution
✅ **Production-ready**: Tested and validated on real infrastructure
✅ **Multi-layer security**: Kernel, network, application, audit
✅ **Docker compatible**: Hardening without container impact
✅ **Centralized management**: AD integration for authentication
✅ **Continuous monitoring**: Proactive email alerts
✅ **Traceability**: Weekly logs and reports
✅ **Idempotent**: Can be re-executed without breaking existing configuration

***

## Use Cases

- Production servers requiring centralized AD authentication
- Docker containerized infrastructures requiring hardening
- Regulated environments requiring audit and traceability
- Multi-server deployments with standardized configuration

***

## Prerequisites

- Freshly installed Debian 12/13
- Network access to Active Directory domain controller
- AD administrator account for domain join
- Functional SMTP/Postfix server for alerts

***

## Configuration Variables

| Variable | Description | Example |
| :-- | :-- | :-- |
| `DOMAIN` | AD domain name | example.com |
| `AD_JOIN_USER` | AD admin account | administrator |
| `AD_SUDO_GROUP` | AD group with sudo rights | LINUX_ADMINS |
| `SSH_PORT` | Custom SSH port | 2222 |
| `SECURITY_EMAIL` | Security alerts recipient | security@example.com |
| `USER_1` to `USER_5` | AD users to configure | user@example.com |
| `KEY_USER_1` to `KEY_USER_5` | SSH public keys | ssh-rsa AAA... |


***

## Security Features Summary

### Network Layer

- Custom SSH port (security by obscurity)
- Fail2Ban intrusion prevention
- ICMP flood protection
- SYN cookies enabled


### System Layer

- Kernel hardening (sysctl)
- ASLR enabled
- Core dumps disabled
- Restricted kernel logs access


### Application Layer

- SSH key-only authentication
- Root login disabled
- Agent forwarding disabled
- Legal access banners


### Audit Layer

- AIDE file integrity monitoring
- RKHunter rootkit detection
- Auditd system event logging
- Automated email reporting

***

## Cron Schedule

### Daily Tasks

- **AIDE Check**: 02:00 AM (via /etc/cron.daily)
- **RKHunter Scan**: 02:00 AM (via /etc/cron.daily)


### Weekly Tasks

- **RKHunter Update**: Sunday 02:00 AM (via /etc/cron.weekly)
- **Auditd Report**: Sunday 03:00 AM (via /etc/cron.weekly)


### Biweekly Tasks

- **Log Rotation**: AIDE and RKHunter logs (via logrotate)

***

## Testing Commands

```bash
# Test AIDE check
sudo /etc/cron.daily/aide-check

# Test RKHunter scan
sudo /etc/cron.daily/rkhunter-check

# Test RKHunter update
sudo /etc/cron.weekly/rkhunter-update

# Test Auditd report
sudo /etc/cron.weekly/auditd-report

# Test all daily scripts
sudo run-parts -v /etc/cron.daily

# Test all weekly scripts
sudo run-parts -v /etc/cron.weekly

# Check mail queue
mailq

# View mail logs
sudo tail -f /var/log/mail.log
```


***

## Post-Installation Checklist

- [ ] Verify SSH access with new port before closing current session
- [ ] Open custom SSH port in firewall
- [ ] Test SSH key authentication for all configured users
- [ ] Verify email alerts are being received
- [ ] Run manual AIDE check to establish baseline
- [ ] Test Fail2Ban by simulating failed login attempts
- [ ] Verify AD user authentication works
- [ ] Check sudo rights for AD group members
- [ ] Review sysctl hardening parameters
- [ ] Validate Docker functionality (if applicable)

***

## Maintenance

### Weekly

- Review Auditd security reports
- Check AIDE and RKHunter alerts


### Monthly

- Verify RKHunter database updates
- Review failed authentication attempts (Fail2Ban logs)
- Audit sudo usage logs


### Quarterly

- Update AIDE baseline after legitimate system changes
- Review and update SSH authorized keys
- Audit AD group memberships

***

## Troubleshooting

### SSH Connection Issues

```bash
# Verify SSH configuration
sudo sshd -t

# Check SSH service status
sudo systemctl status ssh

# View SSH logs
sudo journalctl -u ssh -f
```


### AD Authentication Issues

```bash
# Check domain join status
sudo realm list

# Test AD user lookup
id user@domain.com

# Restart SSSD service
sudo systemctl restart sssd
```


### Email Alert Issues

```bash
# Check Postfix status
sudo systemctl status postfix

# View mail queue
mailq

# Test email delivery
echo "Test" | mail -s "Test Alert" root
```


***

**Version**: 5.5
**Compatibility**: Debian 12/13, Docker
**Maintenance**: Automated cron scripts (daily/weekly)
**Support**: Two versions available (French/English, Named/Anonymous)
