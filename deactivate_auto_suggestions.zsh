#!/bin/zsh

# Define the path to the zshrc file
ZSHRC_FILE="$HOME/.zshrc"

# Check if the zshrc file exists
if [[ -f "$ZSHRC_FILE" ]]; then
    # Backup the original zshrc file if it doesn't already exist
    if [[ ! -f "$ZSHRC_FILE.bak" ]]; then
        cp "$ZSHRC_FILE" "$ZSHRC_FILE.bak"
        echo "A backup of the original file has been created as $ZSHRC_FILE.bak."
    fi

    # Comment out the auto-suggestions configuration
    sed -i.bak '/# enable auto-suggestions based on the history/,/^fi/s/^/#/' "$ZSHRC_FILE"
fi

echo "Auto-suggestions have been deactivated in $ZSHRC_FILE."

# Source the updated zshrc file to apply changes
source "$ZSHRC_FILE"
echo "The updated $ZSHRC_FILE has been sourced."

