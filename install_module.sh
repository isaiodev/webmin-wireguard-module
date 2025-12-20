#!/bin/bash

set -e

MODULE_NAME="wireguard"
SOURCE_DIR="/mnt/ia/DEV/webmin-wireguard-module"
WEBMIN_MODULES_DIR="/usr/share/webmin"
WEBMIN_CONFIG_DIR="/etc/webmin"

echo "Installing WireGuard module to Webmin..."

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

# Set proper permissions
echo "Setting permissions..."
sudo chown -R root:root "$WEBMIN_MODULES_DIR/$MODULE_NAME"
sudo chmod -R 755 "$WEBMIN_MODULES_DIR/$MODULE_NAME"
sudo chmod 644 "$WEBMIN_MODULES_DIR/$MODULE_NAME"/*.cgi
sudo chmod 644 "$WEBMIN_MODULES_DIR/$MODULE_NAME"/*.pl

# Clear module cache
echo "Clearing module cache..."
sudo rm -f /var/webmin/modules.cache 2>/dev/null || true

# Start Webmin
echo "Starting Webmin..."
sudo systemctl start webmin 2>/dev/null || sudo /etc/webmin/start 2>/dev/null || true

echo "Module installed successfully!"
echo "Go to Webmin -> Refresh Modules, then navigate to Networking -> WireGuard"