#!/bin/bash
# Installation script for SSH Login Discord Notification System

set -e

echo "=========================================="
echo "SSH Login Discord Notifier - Installation"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if required files exist
if [ ! -f "$SCRIPT_DIR/ssh_notify.py" ]; then
    echo "Error: ssh_notify.py not found in $SCRIPT_DIR"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/ssh_failed_monitor.py" ]; then
    echo "Error: ssh_failed_monitor.py not found in $SCRIPT_DIR"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "Error: .env file not found!"
    echo "Please create .env file with your Discord credentials:"
    echo "  cp .env.example .env"
    echo "  nano .env  # Edit with your bot token and channel ID"
    exit 1
fi

echo "[1/8] Installing Python dependencies..."
pip3 install requests >/dev/null 2>&1 || {
    echo "Warning: pip3 install failed, trying with --break-system-packages"
    pip3 install requests --break-system-packages
}

echo "[2/8] Creating installation directory..."
INSTALL_DIR="/usr/local/bin/ssh-notify"
mkdir -p "$INSTALL_DIR"

echo "[3/8] Copying files..."
cp "$SCRIPT_DIR/ssh_notify.py" "$INSTALL_DIR/ssh_notify.py"
cp "$SCRIPT_DIR/ssh_failed_monitor.py" "$INSTALL_DIR/ssh_failed_monitor.py"
cp "$SCRIPT_DIR/.env" "$INSTALL_DIR/.env"
chmod +x "$INSTALL_DIR/ssh_notify.py"
chmod +x "$INSTALL_DIR/ssh_failed_monitor.py"
chmod 600 "$INSTALL_DIR/.env"

echo "[4/8] Configuring PAM for SSH..."
PAM_SSH_FILE="/etc/pam.d/sshd"

# Check if our hook is already installed
if grep -q "ssh_notify.py" "$PAM_SSH_FILE"; then
    echo "PAM hook already exists, skipping..."
else
    # Backup original PAM configuration
    cp "$PAM_SSH_FILE" "$PAM_SSH_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Add our notification hook after successful authentication
    # Using 'optional' so SSH login won't fail if notification fails
    echo "" >> "$PAM_SSH_FILE"
    echo "# SSH Login Discord Notification" >> "$PAM_SSH_FILE"
    echo "session optional pam_exec.so seteuid $INSTALL_DIR/ssh_notify.py" >> "$PAM_SSH_FILE"
    
    echo "PAM configuration updated"
fi

echo "[5/8] Creating wrapper script..."
cat > /usr/local/bin/ssh-notify-test << 'EOF'
#!/bin/bash
# Test script for SSH notification
export PAM_USER="${USER}"
export PAM_RHOST="127.0.0.1"
/usr/local/bin/ssh-notify/ssh_notify.py
EOF
chmod +x /usr/local/bin/ssh-notify-test

echo "[6/8] Setting up log directory..."
mkdir -p /var/log/ssh-notify
chmod 755 /var/log/ssh-notify

echo "[7/8] Creating systemd service for failed login monitoring..."
cat > /etc/systemd/system/ssh-failed-monitor.service << 'EOF'
[Unit]
Description=SSH Failed Login Monitor
After=network.target syslog.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssh-notify/ssh_failed_monitor.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/ssh-notify/failed-monitor.log
StandardError=append:/var/log/ssh-notify/failed-monitor.log

# Security settings
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

echo "[8/8] Enabling and starting failed login monitor service..."
systemctl daemon-reload
systemctl enable ssh-failed-monitor.service
systemctl start ssh-failed-monitor.service

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Configuration file: $INSTALL_DIR/.env"
echo "Script location: $INSTALL_DIR/ssh_notify.py"
echo "Monitor service: ssh-failed-monitor.service"
echo ""
echo "Services Status:"
systemctl status ssh-failed-monitor.service --no-pager -l | head -n 10
echo ""
echo "To test successful login notification:"
echo "  sudo ssh-notify-test"
echo ""
echo "To test failed login notification:"
echo "  ssh wronguser@localhost"
echo "  (use incorrect password or non-existent user)"
echo ""
echo "To check failed login monitor logs:"
echo "  sudo journalctl -u ssh-failed-monitor.service -f"
echo "  or: tail -f /var/log/ssh-notify/failed-monitor.log"
echo ""
echo "To test with actual SSH login:"
echo "  ssh localhost"
echo "  (or ssh to this machine from another terminal)"
echo ""
echo "To uninstall:"
echo "  1. Stop and disable service: sudo systemctl stop ssh-failed-monitor.service && sudo systemctl disable ssh-failed-monitor.service"
echo "  2. Remove the PAM configuration line from $PAM_SSH_FILE"
echo "  3. Remove service file: rm /etc/systemd/system/ssh-failed-monitor.service"
echo "  4. Remove directory: rm -rf $INSTALL_DIR"
echo "  5. Remove test script: rm /usr/local/bin/ssh-notify-test"
echo ""
echo "Note: Both successful and failed SSH login attempts will be monitored."
echo "      SSH logins will work even if Discord notification fails."
echo "=========================================="