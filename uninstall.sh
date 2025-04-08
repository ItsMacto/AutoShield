#!/bin/bash
# AutoShield Uninstallation Script

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

echo "=== AutoShield Uninstaller ==="
echo "This will completely remove AutoShield from your system."
echo "Press Ctrl+C now to cancel or Enter to continue..."
read

# Get the full path to the repository (where this script is located)
REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Stop and disable services
echo "Stopping and disabling services..."
systemctl stop autoshield.service 2>/dev/null || true
systemctl stop autoshield-web.service 2>/dev/null || true
systemctl disable autoshield.service 2>/dev/null || true
systemctl disable autoshield-web.service 2>/dev/null || true

# Remove service files
echo "Removing systemd service files..."
rm -f /etc/systemd/system/autoshield.service
rm -f /etc/systemd/system/autoshield-web.service
systemctl daemon-reload


echo "Removing firewall rules..."
if command -v nft &> /dev/null; then

    if nft list table inet autoshield &> /dev/null; then

        echo "Clearing nftables rules..."
        nft flush chain inet autoshield input 2>/dev/null || true
        

        echo "Deleting nftables table..."
        nft delete table inet autoshield 2>/dev/null || true
    fi
fi


echo "Removing installation files..."
if [ -d "/opt/autoshield" ]; then

    if [[ "$REPO_DIR" == "/opt/autoshield"* ]]; then
        echo "Repository is inside installation directory, preserving repository files..."
        find /opt/autoshield -mindepth 1 -path "$REPO_DIR" -prune -o -exec rm -rf {} \; 2>/dev/null || true
    else
        echo "Removing entire installation directory..."
        rm -rf /opt/autoshield
    fi
fi


if [ -d "/usr/local/autoshield" ]; then
    echo "Removing files from /usr/local/autoshield..."
    rm -rf /usr/local/autoshield
fi


echo "Removing database and log files..."
rm -rf /var/lib/autoshield
rm -f /var/log/autoshield.log
rm -f /var/log/autoshield-web.log


echo "Cleaning up Python cache files..."
if [ -d "$REPO_DIR" ]; then
    find "$REPO_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find "$REPO_DIR" -name "*.pyc" -type f -delete 2>/dev/null || true
fi

echo ""
echo "=== Uninstallation Complete ==="
echo "AutoShield has been completely removed from your system while preserving the repository."
echo ""