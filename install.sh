#!/bin/bash
# AutoShield Installation Script

set -e  # Exit on any error

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Determine install location
if [ -z "$1" ]; then
    INSTALL_DIR="/opt/autoshield"
else
    INSTALL_DIR="$1"
fi

echo "=== AutoShield Installer ==="
echo "Installing to: $INSTALL_DIR"

# Check dependencies
echo "Checking dependencies..."
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required but not installed. Aborting."; exit 1; }
command -v nft >/dev/null 2>&1 || { echo "nftables is required but not installed. Aborting."; exit 1; }

# Create installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Copy files
echo "Copying files..."
cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/config" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"

# Create directories for logs and database
echo "Creating directories for logs and database..."
mkdir -p /var/log/autoshield
mkdir -p /var/lib/autoshield

# Setup virtual environment
echo "Setting up virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Configure service file
echo "Installing systemd service..."
cat > /etc/systemd/system/autoshield.service << EOF
[Unit]
Description=AutoShield Intrusion Prevention Service
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/venv/bin/python -m src.main
Restart=on-failure
RestartSec=10
User=root
WorkingDirectory=$INSTALL_DIR

# Security settings
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
echo "Setting permissions..."
chmod -R 750 "$INSTALL_DIR"
chmod 640 /etc/systemd/system/autoshield.service

# Enable and start service
echo "Enabling and starting service..."
systemctl daemon-reload
systemctl enable autoshield.service
systemctl start autoshield.service

echo ""
echo "=== Installation Complete ==="
echo "AutoShield has been installed to $INSTALL_DIR"
echo ""
echo "Service Status:"
systemctl status autoshield.service --no-pager
echo ""
echo "To check logs: tail -f /var/log/autoshield.log"
echo "To manage service: systemctl {start|stop|restart|status} autoshield"
echo ""

echo "Starting web interface..."
nohup "$INSTALL_DIR/venv/bin/python" webapp.py > /var/log/autoshield-web.log 2>&1 &
HOST_IP=$(hostname -I | awk '{print $1}')
echo "Web interface is available at: http://$HOST_IP:5000"
