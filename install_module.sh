#!/bin/bash

set -e

MODULE_NAME="wireguard"
SOURCE_DIR="$(dirname "$(readlink -f "$0")")"
WEBMIN_MODULES_DIR="/usr/share/webmin"
WEBMIN_CONFIG_DIR="/etc/webmin"

echo "Installing WireGuard module to Webmin..."

# Detect distro and install qrencode
echo "Checking for qrencode..."
if ! command -v qrencode >/dev/null 2>&1; then
    echo "Installing qrencode..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y qrencode
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y qrencode
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y qrencode
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm qrencode
    else
        echo "Warning: Could not auto-install qrencode. Please install manually."
    fi
else
    echo "qrencode already installed."
fi

# Stop Webmin
echo "Stopping Webmin..."
sudo systemctl stop webmin 2>/dev/null || sudo /etc/webmin/stop 2>/dev/null || true

# Remove existing module
echo "Removing existing module..."
sudo rm -rf "$WEBMIN_MODULES_DIR/$MODULE_NAME"
sudo rm -rf "$WEBMIN_CONFIG_DIR/$MODULE_NAME"

# Copy module files
echo "Copying module files..."
sudo cp -r "$SOURCE_DIR" "$WEBMIN_MODULES_DIR/$MODULE_NAME"

# Create config directory and copy config
echo "Setting up configuration..."
sudo mkdir -p "$WEBMIN_CONFIG_DIR/$MODULE_NAME"
sudo cp "$SOURCE_DIR/config" "$WEBMIN_CONFIG_DIR/$MODULE_NAME/config"
sudo mkdir -p "$WEBMIN_CONFIG_DIR/$MODULE_NAME/peer-configs"

# Set proper permissions
echo "Setting permissions..."
sudo chown -R root:root "$WEBMIN_MODULES_DIR/$MODULE_NAME"
sudo chmod -R 755 "$WEBMIN_MODULES_DIR/$MODULE_NAME"
sudo chmod 755 "$WEBMIN_MODULES_DIR/$MODULE_NAME"/*.cgi
sudo chmod 755 "$WEBMIN_MODULES_DIR/$MODULE_NAME"/*.pl
sudo chown -R root:root "$WEBMIN_CONFIG_DIR/$MODULE_NAME"
sudo chmod 700 "$WEBMIN_CONFIG_DIR/$MODULE_NAME/peer-configs"
sudo chmod 600 "$WEBMIN_CONFIG_DIR/$MODULE_NAME/config"

# Clear module cache
echo "Clearing module cache..."
sudo rm -f /var/webmin/modules.cache 2>/dev/null || true

# Start Webmin
echo "Starting Webmin..."
sudo systemctl start webmin 2>/dev/null || sudo /etc/webmin/start 2>/dev/null || true

echo "Module installed successfully!"
echo "Go to Webmin -> Refresh Modules, then navigate to Networking -> WireGuard"
