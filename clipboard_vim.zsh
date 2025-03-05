#!/bin/zsh

# Update package list and install vim-gtk3
sudo apt-get update
sudo apt-get install -y vim-gtk3

# Define the path to the vimrc file
VIMRC_FILE="$HOME/.vimrc"

# Create or update the .vimrc file with clipboard configuration
echo "set clipboard=unnamedplus" > "$VIMRC_FILE"

echo "Vim-gtk3 has been installed and .vimrc has been configured for clipboard support."

# Source the .vimrc file to apply changes
source "$VIMRC_FILE"
echo "The .vimrc file has been sourced."
