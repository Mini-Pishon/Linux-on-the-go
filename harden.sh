#!/bin/bash
# -----------------------------------------------------------------------------
# Debian Configuration and Hardening Script (v5.4 - Dynamic Users)
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
#
# NOTE: Bootloader hardening (GRUB) must be performed manually (Phase 4)
# -----------------------------------------------------------------------------

# --- 1. CONFIGURATION VARIABLES ---
DOMAIN="example.com"
AD_JOIN_USER="admin"
AD_SUDO_GROUP="LINUX_ADMINS"
SSH_PORT="2222" # Change this on every machine for security
SECURITY_EMAIL="security@example.com"

# --- 2. SSH KEYS AND USERS (Configure according to your needs) ---
# Define users and their corresponding SSH keys
# You can add/remove user/key pairs as needed
# Format: Uncomment and fill in the necessary lines

# User 1
USER_1="user1@$DOMAIN"
KEY_USER_1=""

# User 2 (Optional - uncomment if needed)
#USER_2="user2@$DOMAIN"
#KEY_USER_2=""

# User 3 (Optional - uncomment if needed)
#USER_3="user3@$DOMAIN"
#KEY_USER_3=""

# User 4 (Optional - uncomment if needed)
#USER_4="user4@$DOMAIN"
#KEY_USER_4=""

# User 5 (Optional - uncomment if needed)
#USER_5="user5@$DOMAIN"
#KEY_USER_5=""

# --- Automatic user array construction ---
# Do not modify this section
declare -a AD_USERS
declare -a SSH_KEYS

# Function to add a user if defined
add_user_if_defined() {
    local user_var=$1
    local key_var=$2
    
    if [ -n "${!user_var}" ]; then
        AD_USERS+=("${!user_var}")
        SSH_KEYS+=("${!key_var}")
    fi
}

# Build arrays dynamically
add_user_if_defined "USER_1" "KEY_USER_1"
add_user_if_defined "USER_2" "KEY_USER_2"
add_user_if_defined "USER_3" "KEY_USER_3"
add_user_if_defined "USER_4" "KEY_USER_4"
add_user_if_defined "USER_5" "KEY_USER_5"

# Verify at least one user is defined
if [ ${#AD_USERS[@]} -eq 0 ]; then
    echo -e "${RED}ERROR: No user defined. Please configure at least USER_1 and KEY_USER_1${NC}"
    exit 1
fi

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Starting configuration v5.4 (${#AD_USERS[@]} user(s) configured) ===${NC}"

# --- 3. SOURCES.LIST CONFIGURATION (FIRST!) ---
echo -e "${GREEN}[1/12] Configuring sources.list...${NC}"
SOURCES_FILE="/etc/apt/sources.list"
if [ -f "$SOURCES_FILE" ]; then
    cp "$SOURCES_FILE" "${SOURCES_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    # Comment out all cdrom lines to prevent Release file errors
    sed -i 's/^deb cdrom/#deb cdrom/g' "$SOURCES_FILE"
    sed -i '/^[^#].*cdrom/s/^/# /' "$SOURCES_FILE"
    echo "   ✓ Cdrom lines commented out."
else
    echo -e "${YELLOW}   ⚠ sources.list file not found, skipped.${NC}"
fi

# --- 4. POSTFIX & KERBEROS PRE-CONFIGURATION (Non-Interactive) ---
echo -e "${GREEN}[2/12] Pre-configuring Postfix & Kerberos (Non-Interactive)...${NC}"
HOSTNAME=$(hostname)

echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string $HOSTNAME.$DOMAIN" | debconf-set-selections
echo "postfix postfix/destinations string $HOSTNAME.$DOMAIN, localhost.$DOMAIN, localhost" | debconf-set-selections

echo "krb5-config krb5-config/default_realm string ${DOMAIN^^}" | debconf-set-selections
echo "krb5-config krb5-config/kerberos_servers string" | debconf-set-selections
echo "krb5-config krb5-config/admin_server string" | debconf-set-selections
echo "krb5-config krb5-config/add_servers_realm string ${DOMAIN^^}" | debconf-set-selections

echo "   ✓ Postfix and Kerberos pre-configured."

# --- 5. UPDATE & INSTALL DEPENDENCIES ---
echo -e "${GREEN}[3/12] Installing dependencies (AD, MTA, Audit)...${NC}"

DEBIAN_FRONTEND=noninteractive apt-get update 2>&1 | grep -v "cdrom" &>/dev/null

DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  realmd sssd sssd-tools libnss-sss libpam-sss adcli \
  samba-common-bin oddjob oddjob-mkhomedir packagekit \
  krb5-user acl auditd aide rkhunter postfix mailutils \
  audispd-plugins fail2ban 2>&1 | grep -v "cdrom"

if [ $? -eq 0 ]; then
    echo "   ✓ All packages installed successfully."
else
    echo -e "${RED}   ✗ Error during package installation.${NC}"
    exit 1
fi

# --- 6. AD DOMAIN JOIN (With Secure Prompt) ---
echo -e "${GREEN}[4/12] Joining Active Directory domain...${NC}"
if ! realm list | grep -q "$DOMAIN"; then
    echo "Joining domain $DOMAIN as $AD_JOIN_USER..."
    read -s -p "Enter password for $AD_JOIN_USER@$DOMAIN: " AD_PASSWORD
    echo ""
    
    echo "$AD_PASSWORD" | realm join --user=$AD_JOIN_USER $DOMAIN
    
    if [ $? -eq 0 ]; then
        echo "   ✓ Domain join successful."
    else
        echo -e "${RED}   ✗ Domain join failed. Check credentials and network.${NC}"
        exit 1
    fi
    
    unset AD_PASSWORD
else
    echo "   ✓ Already joined to domain."
fi

systemctl restart sssd
sleep 2

# --- 7. POSTFIX CONFIGURATION (Aliases) ---
echo -e "${GREEN}[5/12] Configuring Postfix aliases...${NC}"
if ! grep -q "^root: $SECURITY_EMAIL" /etc/aliases; then
    echo "root: $SECURITY_EMAIL" >> /etc/aliases
    newaliases
    echo "   ✓ Postfix alias configured for security alerts."
else
    echo "   ℹ Alias already configured."
fi

# --- 8. SUDOERS & PERMISSIONS (Lynis Hardening) ---
echo -e "${GREEN}[6/12] Configuring Sudoers and Critical Permissions...${NC}"
SUDO_FILE="/etc/sudoers.d/ad_admins"
echo "%$AD_SUDO_GROUP@$DOMAIN ALL=(ALL) ALL" > $SUDO_FILE
chmod 0440 $SUDO_FILE
chmod 0755 /etc/sudoers.d
echo "   ✓ AD sudo group configured and permissions hardened."

chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
echo "   ✓ Cron directories permissions hardened."

# --- 9. USER MANAGEMENT & SSH KEYS (DYNAMIC) ---
echo -e "${GREEN}[7/12] Creating profiles and injecting SSH keys (${#AD_USERS[@]} user(s))...${NC}"

configure_user_ssh() {
    local USER_FULL=$1
    local USER_KEY=$2

    echo -e "${YELLOW}-> Processing $USER_FULL...${NC}"

    # Check if key is empty
    if [ -z "$USER_KEY" ]; then
        echo -e "${YELLOW}   ⚠ No SSH key provided for $USER_FULL, skipped.${NC}"
        return
    fi

    if ! id "$USER_FULL" &>/dev/null; then
        echo -e "${RED}   ✗ Error: User $USER_FULL is not visible.${NC}"
        return
    fi

    USER_HOME=$(getent passwd "$USER_FULL" | cut -d: -f6)
    [ -z "$USER_HOME" ] && USER_HOME="/home/$USER_FULL"
    USER_GROUP=$(id -gn "$USER_FULL")

    if [ ! -d "$USER_HOME" ]; then
        mkdir -p "$USER_HOME"
        cp -r /etc/skel/. "$USER_HOME"
    fi

    SSH_DIR="$USER_HOME/.ssh"
    AUTH_FILE="$SSH_DIR/authorized_keys"

    mkdir -p "$SSH_DIR"

    if ! grep -q "$USER_KEY" "$AUTH_FILE" 2>/dev/null; then
        echo "$USER_KEY" >> "$AUTH_FILE"
        echo "   ✓ Key added."
    else
        echo "   ℹ This key is already present."
    fi

    chown -R "$USER_FULL":"$USER_GROUP" "$USER_HOME"
    chmod 700 "$SSH_DIR"
    chmod 600 "$AUTH_FILE"
    echo "   ✓ Permissions applied."
}

# Dynamic loop on all defined users
for i in "${!AD_USERS[@]}"; do
    configure_user_ssh "${AD_USERS[$i]}" "${SSH_KEYS[$i]}"
done

# --- 10. SSH & BANNER HARDENING ---
echo -e "${GREEN}[8/12] SSH and Banner Hardening (Port $SSH_PORT)...${NC}"
SSH_CONF="/etc/ssh/sshd_config"
cp $SSH_CONF "$SSH_CONF.bak"

sed -i "s/^#\? *Port 22/Port $SSH_PORT/" $SSH_CONF
if ! grep -q "^Port $SSH_PORT" $SSH_CONF; then
    echo "Port $SSH_PORT" >> $SSH_CONF
fi

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' $SSH_CONF
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' $SSH_CONF
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' $SSH_CONF
sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' $SSH_CONF
sed -i 's/^#\?TCPKeepAlive.*/TCPKeepAlive no/' $SSH_CONF
sed -i 's/^#\?AllowAgentForwarding.*/AllowAgentForwarding no/' $SSH_CONF
sed -i 's/^#\?Banner.*/Banner \/etc\/issue\.net/' $SSH_CONF
sed -i 's/^#\?PrintMotd.*/PrintMotd no/' $SSH_CONF

if ! grep -q "^PrintMotd" $SSH_CONF; then
    echo "PrintMotd no" >> $SSH_CONF
fi

echo "   ✓ SSH configuration hardened."

LEGAL_BANNER="WARNING: Access restricted to authorized users only. Any unauthorized or unlawful access attempt is strictly prohibited and will be subject to legal prosecution."
echo "$LEGAL_BANNER" > /etc/issue
echo "$LEGAL_BANNER" > /etc/issue.net
echo "   ✓ Legal banners configured."

# --- 11. FAIL2BAN & PAM ---
echo -e "${GREEN}[9/12] Configuring Fail2Ban and PAM...${NC}"
if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" >> /etc/pam.d/common-session
    echo "   ✓ PAM mkhomedir configured."
fi

cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = $SSH_PORT
bantime = 1h
findtime = 10m
maxretry = 5
EOF
systemctl restart fail2ban
echo "   ✓ Fail2Ban enabled on port $SSH_PORT."

# --- 12. KERNEL HARDENING (Sysctl - Docker Compatible) ---
echo -e "${GREEN}[10/12] Kernel Hardening (Sysctl) - Docker Compatible...${NC}"
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

cat << EOF > $SYSCTL_CONF
# =====================================================================
# Kernel Hardening - Docker Compatible
# =====================================================================
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
EOF

sysctl --system &>/dev/null
echo "   ✓ Kernel hardened (Docker compatible)."

# --- 13. AUDIT CHAIN (AIDE, RKHunter, Auditd) ---
echo -e "${GREEN}[11/12] Configuring Continuous Audit Chain...${NC}"
mkdir -p /var/log/aide /var/log/rkhunter

echo "SKIP_DIRS=/dev /run /proc" >> /etc/rkhunter.conf
echo "   ✓ RKHunter configured."

cat << 'EOF_AIDE' > /etc/cron.daily/aide-check
#!/bin/bash
REPORT=$(/usr/bin/aide --check 2>&1)
if echo "$REPORT" | grep -q 'changed\|added\|removed'; then
    echo -e "Changes detected by AIDE.\n\n$REPORT" | mail -s "SECURITY ALERT AIDE - Changes on $(hostname)" root
    exit 1
elif [ $? -eq 2 ]; then
    echo -e "AIDE error.\n\n$REPORT" | mail -s "SECURITY ALERT AIDE - ERROR on $(hostname)" root
    exit 2
fi
exit 0
EOF_AIDE
chmod +x /etc/cron.daily/aide-check

cat << 'EOF_RKHUNTER' > /etc/cron.daily/rkhunter-check
#!/bin/bash
REPORT_FILE=$(mktemp)
/usr/bin/rkhunter --check --nocolors --report-warnings-only > "$REPORT_FILE"
if [ $? -ne 0 ]; then
    REPORT_CONTENT=$(cat "$REPORT_FILE")
    echo -e "Suspicious rootkits found.\n\n$REPORT_CONTENT" | mail -s "SECURITY ALERT RKHUNTER - Rootkit Suspicion on $(hostname)" root
    rm "$REPORT_FILE"
    exit 1
fi
rm -f "$REPORT_FILE"
exit 0
EOF_RKHUNTER
chmod +x /etc/cron.daily/rkhunter-check

cat << 'EOF_RKHUNTER_UPD' > /etc/cron.weekly/rkhunter-update
#!/bin/sh
/usr/bin/rkhunter --update 
if [ $? -ne 0 ]; then
    echo "RKHunter update failed." | mail -s "ALERT RKHUNTER - UPDATE FAILED on $(hostname)" root
    exit 1
fi
exit 0
EOF_RKHUNTER_UPD
chmod +x /etc/cron.weekly/rkhunter-update

cat << 'EOF_AUDITD' > /etc/cron.weekly/auditd-report
#!/bin/bash
REPORT=$(/usr/sbin/aureport -ts "this week" -i --summary --failed --input-logs)
echo -e "Weekly Auditd report.\n\n$REPORT" | mail -s "WEEKLY AUDITD REPORT on $(hostname)" root
exit 0
EOF_AUDITD
chmod +x /etc/cron.weekly/auditd-report

echo "   ✓ Audit chain configured (AIDE, RKHunter, Auditd)."

cat << 'EOF_LOG_AIDE' > /etc/logrotate.d/aide
/var/log/aide/*.log {
    biweekly
    rotate 7
    compress
    missingok
    notifempty
    create 640 root adm
}
EOF_LOG_AIDE

cat << 'EOF_LOG_RKHUNTER' > /etc/logrotate.d/rkhunter
/var/log/rkhunter/*.log {
    biweekly
    rotate 7
    compress
    missingok
    notifempty
    create 640 root adm
}
/var/log/rkhunter.log {
    biweekly
    rotate 7
    compress
    missingok
    notifempty
    create 640 root adm
}
EOF_LOG_RKHUNTER

echo "   ✓ Logrotate configured (biweekly)."

# --- 14. CUSTOM MOTD CONFIGURATION ---
echo -e "${GREEN}[12/13] Configuring custom MOTD...${NC}"

if [ -d "/etc/update-motd.d" ]; then
    for script in /etc/update-motd.d/*; do
        [ -x "$script" ] && chmod -x "$script" 2>/dev/null
    done
    echo "   ✓ Default MOTD scripts disabled."
fi

mkdir -p /etc/update-motd.d

cat > /etc/update-motd.d/99-custom << 'EOFMOTD'
#!/bin/bash
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
LAST_LOGON=$(last -Fw $USER | grep -v "gone - no logout" | head -n 1)

MOTD_LINES=(
"Welcome to $HOSTNAME"
"IP Address: $IP"
"Last login:"
"$LAST_LOGON"
""
"Warning: All access is monitored and restricted to authorized personnel."
" Any unauthorized access attempt will be subject to prosecution."
)

max_len=0
for line in "${MOTD_LINES[@]}"; do
  [[ ${#line} -gt $max_len ]] && max_len=${#line}
done

print_border() {
  echo "+$(printf '%0.s-' $(seq 1 $((max_len + 2))))+"
}

print_border
for line in "${MOTD_LINES[@]}"; do
  printf "| %-${max_len}s |\n" "$line"
done
print_border
EOFMOTD

chmod +x /etc/update-motd.d/99-custom
echo "   ✓ Custom MOTD enabled."

# --- 15. AUDIT DATABASE INITIALIZATION ---
echo -e "${GREEN}[13/13] Initializing audit databases...${NC}"

# Initialize AIDE (May take several minutes)
echo -e "${YELLOW}   -> Initializing AIDE database (this may take time)...${NC}"
if [ ! -f /var/lib/aide/aide.db ]; then
    aideinit
    
    # Verify the new database was created
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        echo "   ✓ AIDE database initialized successfully."
    else
        echo -e "${RED}   ✗ Error during AIDE database initialization.${NC}"
    fi
else
    echo "   ℹ AIDE database already exists, skipped."
fi

# Initialize RKHunter
echo -e "${YELLOW}   -> Updating RKHunter database...${NC}"

# Update rootkit signatures
rkhunter --update &>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✓ RKHunter signatures updated."
else
    echo -e "${YELLOW}   ⚠ RKHunter signature update failed (may require Internet connection).${NC}"
fi

# Update system file properties
rkhunter --propupd &>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✓ RKHunter file properties recorded."
else
    echo -e "${RED}   ✗ Error recording RKHunter properties.${NC}"
fi

# --- 16. FINALIZATION ---
echo -e "${GREEN}[FINAL] Restarting SSH and verification...${NC}"
if sshd -t; then
    systemctl restart ssh
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         ✓ CONFIGURATION v5.4 COMPLETED SUCCESSFULLY       ║${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║ • Configured users: ${#AD_USERS[@]}                                     ║${NC}"
    echo -e "${GREEN}║ • Active SSH port: $SSH_PORT                                  ║${NC}"
    echo -e "${GREEN}║ • Custom MOTD: Enabled                                     ║${NC}"
    echo -e "${GREEN}║ • Audit chain: AIDE + RKHunter + Auditd                   ║${NC}"
    echo -e "${GREEN}║ • Audit databases: Initialized                            ║${NC}"
    echo -e "${GREEN}║ • Hardening: SSH, Kernel, Fail2Ban, Banners               ║${NC}"
    echo -e "${GREEN}║ • Email alerts: $SECURITY_EMAIL                   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}⚠  IMPORTANT: Remember to open port $SSH_PORT on the firewall!${NC}"
    echo -e "${YELLOW}⚠  NOTE: GRUB hardening (BOOT-5122) must be done manually.${NC}"
    echo -e "${GREEN}⚠  INFO: Audit scripts can be tested with:${NC}"
    echo -e "${GREEN}          sudo run-parts -v /etc/cron.daily${NC}"
    echo -e "${GREEN}          sudo run-parts -v /etc/cron.weekly${NC}"
    echo ""
else
    echo -e "${RED}✗ CRITICAL SSH ERROR: Invalid configuration.${NC}"
    echo -e "${RED}  Restore with: mv $SSH_CONF.bak $SSH_CONF${NC}"
    exit 1
fi
