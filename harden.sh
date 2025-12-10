#!/bin/bash
# -----------------------------------------------------------------------------
# Debian Configuration and Hardening Script (v5.5 - Dynamic Users)
# -----------------------------------------------------------------------------
# This script prepares a Debian server with AD integration, system hardening,
# and Docker compatibility, while enabling continuous audit chain (AIDE, RKHunter, Auditd).
#
# Process:
# 1. Variable Definition and Base Configuration (Sources.list, AD, MTA)
# 2. Installation of AD dependencies, Postfix, and Audit Chain (AIDE, RKHunter, Auditd)
# 3. User Management and SSH Key injection
# 4. Service Hardening (SSH, Banners) and Critical Permissions (Sudoers, Cron)
# 5. Kernel Hardening (Sysctl) while maintaining Docker compatibility
# 6. Cron Scripts Configuration for Audit (Email Alerts)
# 7. Logrotate Configuration for biweekly report retention
# -----------------------------------------------------------------------------

set -o errexit
set -o pipefail

# --- 1. CONFIGURATION VARIABLES ---
DOMAIN="example.com"
AD_JOIN_USER="admin"
AD_SUDO_GROUP="LINUX_ADMINS"
SSH_PORT="2222" # Change this on every machine for security
SECURITY_EMAIL="security@example.com"

# --- 2. SSH KEYS AND USERS (Configure according to your needs) ---
# Define users and their corresponding SSH keys
# You
