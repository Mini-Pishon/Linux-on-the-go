#!/bin/bash
# -----------------------------------------------------------------------------
# Script de Configuration et Hardening Debian (v4 - Sources.list + MOTD)
# -----------------------------------------------------------------------------

# --- 1. VARIABLES DE CONFIGURATION ---
DOMAIN="" # Mettre votre domaine
AD_JOIN_USER="" # Utiliser un compte pour joindre l'AD
AD_SUDO_GROUP="" # Groupe utilisateurs sudo présent dans l'AD
SSH_PORT="" # A changer sur chaque machine

# --- 2. CLÉS SSH (À REMPLIR OBLIGATOIREMENT) ---
KEY_LINK=""
KEY_SPONGEBOB="" # Clé publique des utilisateurs

# Liste des utilisateurs AD à configurer
AD_USERS=("link@$DOMAIN" "spongebob@$DOMAIN")

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Démarrage de la configuration v4 (Sources + MOTD) ===${NC}"

# --- 3. CONFIGURATION SOURCES.LIST (EN PREMIER !) ---
echo -e "${GREEN}[1/8] Configuration sources.list...${NC}"
SOURCES_FILE="/etc/apt/sources.list"
if [ -f "$SOURCES_FILE" ]; then
    cp "$SOURCES_FILE" "${SOURCES_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    # Commenter toutes les lignes cdrom
    sed -i 's/^deb cdrom/#deb cdrom/g' "$SOURCES_FILE"
    echo "   ✓ Lignes cdrom commentées."
else
    echo -e "${YELLOW}   ⚠ Fichier sources.list introuvable, ignoré.${NC}"
fi

# --- 4. DEPENDANCES & AD ---
echo -e "${GREEN}[2/8] Installation des dépendances et jonction AD...${NC}"
apt update && apt install realmd sssd sssd-tools libnss-sss libpam-sss adcli samba-common-bin oddjob oddjob-mkhomedir packagekit krb5-user acl -y &>/dev/null

if ! realm list | grep -q "$DOMAIN"; then
    echo "Jonction au domaine $DOMAIN..."
    realm join --user=$AD_JOIN_USER $DOMAIN
else
    echo "   ✓ Déjà joint au domaine."
fi

systemctl restart sssd
sleep 2

# --- 5. SUDOERS ---
echo -e "${GREEN}[3/8] Configuration Sudoers...${NC}"
SUDO_FILE="/etc/sudoers.d/ad_admins"
echo "%$AD_SUDO_GROUP@$DOMAIN ALL=(ALL) ALL" > $SUDO_FILE
chmod 0440 $SUDO_FILE
echo "   ✓ Groupe sudo AD configuré."

# --- 6. GESTION UTILISATEURS & CLES SSH ---
echo -e "${GREEN}[4/8] Création des profils et injection SSH...${NC}"

configure_user_ssh() {
    local USER_FULL=$1
    local USER_KEY=$2
    
    echo -e "${YELLOW}-> Traitement de $USER_FULL...${NC}"

    # Vérification existence utilisateur
    if ! id "$USER_FULL" &>/dev/null; then
        echo -e "${RED}   ✗ Erreur : L'utilisateur $USER_FULL n'est pas visible.${NC}"
        return
    fi

    # Récupération dynamique du Home et du Groupe
    USER_HOME=$(getent passwd "$USER_FULL" | cut -d: -f6)
    [ -z "$USER_HOME" ] && USER_HOME="/home/$USER_FULL"
    
    # Détection dynamique du groupe principal
    USER_GROUP=$(id -gn "$USER_FULL")

    # Création du Home
    if [ ! -d "$USER_HOME" ]; then
        mkdir -p "$USER_HOME"
        cp -r /etc/skel/. "$USER_HOME"
    fi

    # Configuration SSH
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_FILE="$SSH_DIR/authorized_keys"

    mkdir -p "$SSH_DIR"
    
    if ! grep -q "ssh-" "$AUTH_FILE" 2>/dev/null; then
        echo "$USER_KEY" >> "$AUTH_FILE"
        echo "   ✓ Clé ajoutée."
    else
        echo "   ℹ Une clé semble déjà présente."
    fi

    # Application des droits avec le groupe détecté
    echo "   ✓ Application des droits ($USER_FULL : $USER_GROUP)..."
    chown -R "$USER_FULL":"$USER_GROUP" "$USER_HOME"
    chmod 700 "$SSH_DIR"
    chmod 600 "$AUTH_FILE"
}

# Exécution pour les utilisateurs définis
configure_user_ssh "link@$DOMAIN" "$KEY_LINK"
configure_user_ssh "spongebob@$DOMAIN" "$KEY_SPONGEBOB"

# --- 7. HARDENING SSH ---
echo -e "${GREEN}[5/8] Hardening SSH (Port $SSH_PORT)...${NC}"
SSH_CONF="/etc/ssh/sshd_config"
cp $SSH_CONF "$SSH_CONF.bak"

# Changement de port
sed -i "s/^#\? *Port 22/Port $SSH_PORT/" $SSH_CONF

# Sécurité si le sed a échoué
if ! grep -q "^Port $SSH_PORT" $SSH_CONF; then
    echo "Port $SSH_PORT" >> $SSH_CONF
fi

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' $SSH_CONF
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' $SSH_CONF
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' $SSH_CONF

echo "   ✓ Configuration SSH durcie."

# --- 8. FAIL2BAN & PAM ---
echo -e "${GREEN}[6/8] Fail2Ban et PAM...${NC}"
if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" >> /etc/pam.d/common-session
    echo "   ✓ PAM mkhomedir configuré."
fi

apt install fail2ban -y &>/dev/null
cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = $SSH_PORT
bantime = 1h
findtime = 10m
maxretry = 5
EOF
systemctl restart fail2ban
echo "   ✓ Fail2Ban activé."

# --- 9. CONFIGURATION MOTD PERSONNALISÉ ---
echo -e "${GREEN}[7/8] Configuration MOTD personnalisé...${NC}"

# Désactiver les scripts MOTD par défaut si présents
if [ -d "/etc/update-motd.d" ]; then
    for script in /etc/update-motd.d/*; do
        [ -x "$script" ] && chmod -x "$script" 2>/dev/null
    done
    echo "   ✓ Scripts MOTD par défaut désactivés."
fi

# Créer le répertoire si nécessaire
mkdir -p /etc/update-motd.d

# Créer le script MOTD personnalisé
cat > /etc/update-motd.d/99-custom << 'EOFMOTD'
#!/bin/bash

# Données MOTD
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
LAST_LOGON=$(last -Fw $USER | grep -v "gone - no logout" | head -n 1)

MOTD_LINES=(
"Bienvenue sur $HOSTNAME"
"Adresse IP : $IP"
"Dernière connexion :"
"$LAST_LOGON"
""
"Attention : Tous les accès sont monitorés et limités aux personnes habilitées."
" Toute tentative d'accès non autorisée fera l'objet de poursuites."
)

# Calculer la largeur max
max_len=0
for line in "${MOTD_LINES[@]}"; do
  [[ ${#line} -gt $max_len ]] && max_len=${#line}
done

# Dessiner une ligne de bordure
print_border() {
  echo "+$(printf '%0.s-' $(seq 1 $((max_len + 2))))+"
}

# Afficher cadre et contenu
print_border
for line in "${MOTD_LINES[@]}"; do
  printf "| %-${max_len}s |\n" "$line"
done
print_border
EOFMOTD

# Rendre le script exécutable
chmod +x /etc/update-motd.d/99-custom
echo "   ✓ MOTD personnalisé créé et activé."

# S'assurer que PrintMotd est désactivé dans sshd_config
sed -i 's/^#\?PrintMotd.*/PrintMotd no/' $SSH_CONF
if ! grep -q "^PrintMotd" $SSH_CONF; then
    echo "PrintMotd no" >> $SSH_CONF
fi

# --- 10. FINALISATION ---
echo -e "${GREEN}[8/8] Redémarrage SSH...${NC}"
if sshd -t; then
    systemctl restart ssh
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           ✓ CONFIGURATION TERMINÉE AVEC SUCCÈS            ║${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║ • Port SSH actif : $SSH_PORT                                 ║${NC}"
    echo -e "${GREEN}║ • MOTD personnalisé : Activé                               ║${NC}"
    echo -e "${GREEN}║ • Sources.list : Lignes cdrom commentées                   ║${NC}"
    echo -e "${GREEN}║ • Fail2Ban : Actif sur port $SSH_PORT                        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}⚠  IMPORTANT : N'oubliez pas d'ouvrir le port $SSH_PORT sur le pare-feu !${NC}"
    echo ""
else
    echo -e "${RED}✗ ERREUR CRITIQUE SSH : Configuration invalide.${NC}"
    echo -e "${RED}  Restauration possible avec : mv $SSH_CONF.bak $SSH_CONF${NC}"
    exit 1
fi
