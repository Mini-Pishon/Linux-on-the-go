#!/bin/bash
# Defines the interpreter to use (Bash) to execute this script.

# -----------------------------------------------------------------------------
# Debian Configuration and Hardening Script (v4 - Sources.list + MOTD)
# -----------------------------------------------------------------------------
# Header comment describing the script's purpose, version, and key features.

# --- 1. CONFIGURATION VARIABLES ---
# Section header indicating the start of user-configurable variables.

# ADAPT: Change this to your Active Directory domain
# Comment instructing the user to modify the domain name below.
DOMAIN="example.com"
# Sets the variable 'DOMAIN' to the Active Directory domain name (e.g., example.com).

# ADAPT: The AD user with permissions to join the machine to the domain
# Comment instructing the user to specify the AD admin user.
AD_JOIN_USER="your-ad-admin-user"
# Sets 'AD_JOIN_USER' to the username used for joining the AD domain.

# ADAPT: The AD group that should have sudo/root access
# Comment instructing the user to specify the AD group for sudo access.
AD_SUDO_GROUP="YOUR_AD_SUDO_GROUP"
# Sets 'AD_SUDO_GROUP' to the AD group name that will be granted sudo privileges.

# ADAPT: The SSH port to use (Change this on every machine for security)
# Comment instructing the user to change the SSH port for security hardening.
SSH_PORT="2222"
# Sets 'SSH_PORT' to the custom port number (2222) for SSH connections.

# --- 2. SSH KEYS (MANDATORY: FILL IN) ---
# Section header for SSH key configuration.

# ADAPT: Paste the public SSH key for the first user here (remove the empty string)
# Instruction to paste the first user's public SSH key.
KEY_USER_1=""
# Sets 'KEY_USER_1' to an empty string (placeholder for the actual key).

# ADAPT: Paste the public SSH key for the second user here (remove the empty string)
# Instruction to paste the second user's public SSH key.
KEY_USER_2=""
# Sets 'KEY_USER_2' to an empty string (placeholder for the actual key).

# ADAPT: List of AD users to configure. MUST match the order of keys above.
# Instruction explaining that the user array below must align with the key variables above.

# Format: "username@$DOMAIN"
# Shows the expected format for user entries (username@domain).
AD_USERS=("user1@$DOMAIN" "user2@$DOMAIN")
# Creates an array 'AD_USERS' containing two user identifiers formatted with the domain variable.

# Colors
# Comment indicating the start of color variable definitions for terminal output.
GREEN='\033[0;32m'
# Sets 'GREEN' to the ANSI escape code for green text.
YELLOW='\033[1;33m'
# Sets 'YELLOW' to the ANSI escape code for yellow text.
RED='\033[0;31m'
# Sets 'RED' to the ANSI escape code for red text.
NC='\033[0m'
# Sets 'NC' (No Color) to the ANSI escape code that resets text formatting.

echo -e "${GREEN}=== Starting Configuration v4 (Sources + MOTD) ===${NC}"
# Prints a green start message to the console to indicate the script has begun.

# --- 3. SOURCES.LIST CONFIGURATION (FIRST STEP!) ---
# Section header for configuring the APT sources list.

echo -e "${GREEN}[1/8] Configuring sources.list...${NC}"
# Prints a green status message indicating step 1 (sources.list config) is starting.

SOURCES_FILE="/etc/apt/sources.list"
# Sets 'SOURCES_FILE' to the path of the APT sources configuration file.

if [ -f "$SOURCES_FILE" ]; then
# Checks if the sources file exists.
    cp "$SOURCES_FILE" "${SOURCES_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    # Backs up the existing sources file with a timestamp suffix if it exists.
    
    # Comment out all cdrom lines
    # Comment explaining the next command.
    sed -i 's/^deb cdrom/#deb cdrom/g' "$SOURCES_FILE"
    # Uses 'sed' to find lines starting with "deb cdrom" and comment them out (add #) to prevent install errors.
    
    echo "   ✓ Cdrom lines commented out."
    # Prints a confirmation message that CD-ROM lines were commented out.
else
# Else block executed if the sources file does not exist.
    echo -e "${YELLOW}   ⚠ sources.list file not found, ignored.${NC}"
    # Prints a yellow warning message that the file was missing and the step was skipped.
fi
# Ends the if/else block.

# --- 4. DEPENDENCIES & AD ---
# Section header for installing dependencies and joining Active Directory.

echo -e "${GREEN}[2/8] Installing dependencies and joining AD...${NC}"
# Prints a green status message for step 2.

apt update && apt install realmd sssd sssd-tools libnss-sss libpam-sss adcli samba-common-bin oddjob oddjob-mkhomedir packagekit krb5-user acl -y &>/dev/null
# Updates package lists and installs necessary packages for AD integration (realmd, sssd, etc.) silently (redirects output to /dev/null).

if ! realm list | grep -q "$DOMAIN"; then
# Checks if the machine is NOT already joined to the specified domain (greps for domain name in 'realm list').
    echo "Joining domain $DOMAIN..."
    # Prints a message that the domain join process is starting.
    realm join --user=$AD_JOIN_USER $DOMAIN
    # Joins the domain using the specified admin user and domain variable.
else
# Else block if the machine is already joined.
    echo "   ✓ Already joined to domain."
    # Prints a confirmation that the join step was skipped.
fi
# Ends the if/else block.

systemctl restart sssd
# Restarts the SSSD service to apply changes.
sleep 2
# Pauses execution for 2 seconds to allow the service to stabilize.

# --- 5. SUDOERS ---
# Section header for sudo configuration.

echo -e "${GREEN}[3/8] Configuring Sudoers...${NC}"
# Prints a green status message for step 3.

SUDO_FILE="/etc/sudoers.d/ad_admins"
# Sets 'SUDO_FILE' to the path where the new sudo rule file will be created.

echo "%$AD_SUDO_GROUP@$DOMAIN ALL=(ALL) ALL" > $SUDO_FILE
# Writes the sudo rule granting full root access to the specified AD group into the file.

chmod 0440 $SUDO_FILE
# Sets strict permissions (read-only for owner/group) on the sudoers file, required for it to work.

echo "   ✓ AD sudo group configured."
# Prints confirmation that the sudo group was configured.

# --- 6. USER MANAGEMENT & SSH KEYS ---
# Section header for user and SSH key management.

echo -e "${GREEN}[4/8] Creating profiles and injecting SSH keys...${NC}"
# Prints a green status message for step 4.

configure_user_ssh() {
# Defines a function named 'configure_user_ssh' to handle user setup.
    local USER_FULL=$1
    # Captures the first argument passed to the function as 'USER_FULL' (username).
    local USER_KEY=$2
    # Captures the second argument as 'USER_KEY' (SSH public key).

    echo -e "${YELLOW}-> Processing $USER_FULL...${NC}"
    # Prints a yellow message indicating which user is currently being processed.

    # Check if user exists (via AD)
    # Comment explaining the check.
    if ! id "$USER_FULL" &>/dev/null; then
    # Checks if the user exists on the system (or via AD) using 'id'.
        echo -e "${RED}   ✗ Error: User $USER_FULL is not visible.${NC}"
        # Prints a red error if the user is not found.
        return
        # Exits the function for this user.
    fi
    # Ends the if block.

    # Dynamic retrieval of Home and Group
    # Comment explaining dynamic variable fetching.
    USER_HOME=$(getent passwd "$USER_FULL" | cut -d: -f6)
    # Gets the home directory path from the passwd database using 'getent' and 'cut'.
    [ -z "$USER_HOME" ] && USER_HOME="/home/$USER_FULL"
    # If 'USER_HOME' is empty (fallback), manually sets it to /home/username.

    # Dynamic detection of primary group
    # Comment explaining group detection.
    USER_GROUP=$(id -gn "$USER_FULL")
    # Gets the primary group name of the user.

    # Create Home if missing
    # Comment explaining home directory creation.
    if [ ! -d "$USER_HOME" ]; then
    # Checks if the home directory does NOT exist.
        mkdir -p "$USER_HOME"
        # Creates the directory and parents if needed.
        cp -r /etc/skel/. "$USER_HOME"
        # Copies default skeleton files (.bashrc, etc.) to the new home directory.
    fi
    # Ends the if block.

    # Configure SSH
    # Comment for SSH setup section.
    SSH_DIR="$USER_HOME/.ssh"
    # Defines the path to the .ssh directory.
    AUTH_FILE="$SSH_DIR/authorized_keys"
    # Defines the path to the authorized_keys file.

    mkdir -p "$SSH_DIR"
    # Creates the .ssh directory if it doesn't exist.

    if ! grep -q "ssh-" "$AUTH_FILE" 2>/dev/null; then
    # Checks if the authorized_keys file does NOT already contain an SSH key (prevents duplicates).
        echo "$USER_KEY" >> "$AUTH_FILE"
        # Appends the provided public key to the file.
        echo "   ✓ Key added."
        # Prints confirmation.
    else
    # Else block if a key exists.
        echo "   ℹ A key seems to be already present."
        # Prints info message.
    fi
    # Ends the if/else block.

    # Apply permissions with detected group
    # Comment for permission application.
    echo "   ✓ Applying permissions ($USER_FULL : $USER_GROUP)..."
    # Prints status of permission change.
    chown -R "$USER_FULL":"$USER_GROUP" "$USER_HOME"
    # Recursively sets ownership of the home directory to the user and their group.
    chmod 700 "$SSH_DIR"
    # Sets permissions on .ssh dir so only the owner can read/write/execute (required for SSH).
    chmod 600 "$AUTH_FILE"
    # Sets permissions on authorized_keys so only the owner can read/write (required for SSH).
}
# Ends the function definition.

# Execution for defined users
# Comment indicating the function is about to be called.
# ADAPT: Ensure you are passing the correct key variables here based on section 2
# Reminder to check key variables.
configure_user_ssh "${AD_USERS[0]}" "$KEY_USER_1"
# Calls the function for the first user in the array with their corresponding key.
configure_user_ssh "${AD_USERS[1]}" "$KEY_USER_2"
# Calls the function for the second user in the array with their corresponding key.

# --- 7. SSH HARDENING ---
# Section header for SSH security hardening.

echo -e "${GREEN}[5/8] SSH Hardening (Port $SSH_PORT)...${NC}"
# Prints a green status message for step 5.

SSH_CONF="/etc/ssh/sshd_config"
# Sets 'SSH_CONF' to the path of the SSH daemon configuration file.
cp $SSH_CONF "$SSH_CONF.bak"
# Creates a backup of the SSH config file.

# Change port
# Comment for port change.
sed -i "s/^#\? *Port 22/Port $SSH_PORT/" $SSH_CONF
# Uses 'sed' to find the Port 22 line (commented or not) and replace it with the custom port.

# Safety check if sed failed
# Comment for fallback check.
if ! grep -q "^Port $SSH_PORT" $SSH_CONF; then
# Checks if the new port line is present.
    echo "Port $SSH_PORT" >> $SSH_CONF
    # Appends the port configuration if the sed replacement failed.
fi
# Ends the if block.

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' $SSH_CONF
# Disables root login via SSH.
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' $SSH_CONF
# Enables public key authentication.
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' $SSH_CONF
# Disables password authentication (forcing key-based login).

echo "   ✓ SSH configuration hardened."
# Prints confirmation.

# --- 8. FAIL2BAN & PAM ---
# Section header for Fail2Ban and PAM setup.

echo -e "${GREEN}[6/8] Fail2Ban and PAM...${NC}"
# Prints a green status message for step 6.

if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
# Checks if pam_mkhomedir (auto home creation) is NOT already configured.
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask
