#!/bin/bash
##########################################
# SSH Alert Discord Bot Installer
# Installs the Discord bot with commands
##########################################

set -e

echo "=========================================="
echo "SSH Alert Discord Bot - Installation"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if required files exist
if [ ! -f "$SCRIPT_DIR/discord_bot.py" ]; then
    echo "Error: discord_bot.py not found in $SCRIPT_DIR"
    exit 1
fi

echo "[1/7] Installing Python dependencies..."
pip3 install discord.py requests >/dev/null 2>&1 || {
    echo "Warning: pip3 install failed, trying with --break-system-packages"
    pip3 install discord.py requests --break-system-packages
}

# Install location
INSTALL_DIR="/usr/local/bin/ssh-notify"
echo "[2/7] Installing files to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Copy the bot script
cp "$SCRIPT_DIR/discord_bot.py" "$INSTALL_DIR/discord_bot.py"
chmod +x "$INSTALL_DIR/discord_bot.py"

echo "[3/7] Setting up .env file..."
# Check if .env exists, if not create a template
if [ ! -f "$INSTALL_DIR/.env" ]; then
    cat > "$INSTALL_DIR/.env" << 'EOF'
# Discord Bot Configuration
DISCORD_BOT_TOKEN=your_bot_token_here
DISCORD_CHANNEL_ID=your_channel_id_here
DISCORD_GUILD_ID=your_server_id_here

# Instructions:
# 1. Get your bot token from: https://discord.com/developers/applications
# 2. Get your channel ID by enabling Developer Mode in Discord, then right-click channel
# 3. Get your server/guild ID by right-clicking your server name
EOF
    echo "   Created template .env file at $INSTALL_DIR/.env"
    echo "   ⚠️  You MUST edit this file and add your Discord credentials!"
else
    echo "   .env file already exists, skipping..."
    # Add DISCORD_GUILD_ID if it doesn't exist
    if ! grep -q "DISCORD_GUILD_ID" "$INSTALL_DIR/.env"; then
        echo "" >> "$INSTALL_DIR/.env"
        echo "DISCORD_GUILD_ID=your_server_id_here" >> "$INSTALL_DIR/.env"
        echo "   Added DISCORD_GUILD_ID to existing .env file"
    fi
fi

# Set secure permissions on .env
chmod 600 "$INSTALL_DIR/.env"

echo "[4/7] Creating data directory..."
mkdir -p /var/lib/ssh-notify
chmod 700 /var/lib/ssh-notify

echo "[5/7] Setting up sudoers permissions..."
# Install sudoers file
if [ -f "$SCRIPT_DIR/ssh-notify-sudoers" ]; then
    cp "$SCRIPT_DIR/ssh-notify-sudoers" /etc/sudoers.d/ssh-notify
    chmod 440 /etc/sudoers.d/ssh-notify
    echo "   Installed sudoers configuration"
    echo "   ⚠️  Review /etc/sudoers.d/ssh-notify and adjust the username if needed"
else
    echo "   Warning: ssh-notify-sudoers file not found, creating basic configuration"
    cat > /etc/sudoers.d/ssh-notify << 'EOF'
# Allow root to run iptables without password (for Discord bot)
root ALL=(ALL) NOPASSWD: /usr/sbin/iptables
root ALL=(ALL) NOPASSWD: /usr/sbin/iptables-save
root ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/auth.log
root ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/secure
EOF
    chmod 440 /etc/sudoers.d/ssh-notify
fi

echo "[6/7] Creating systemd service..."
cat > /etc/systemd/system/ssh-alert-bot.service << 'EOF'
[Unit]
Description=SSH Alert Discord Bot
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssh-notify/discord_bot.py
Restart=always
RestartSec=10
WorkingDirectory=/usr/local/bin/ssh-notify
StandardOutput=append:/var/log/ssh-notify/discord-bot.log
StandardError=append:/var/log/ssh-notify/discord-bot.log

# Security settings
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Create log directory
mkdir -p /var/log/ssh-notify
chmod 755 /var/log/ssh-notify

echo "[7/7] Starting Discord bot service..."
systemctl daemon-reload
systemctl enable ssh-alert-bot.service
systemctl restart ssh-alert-bot.service

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "⚠️  IMPORTANT: Next Steps"
echo "1. Edit the .env file with your Discord credentials:"
echo "   sudo nano $INSTALL_DIR/.env"
echo ""
echo "2. Restart the bot service:"
echo "   sudo systemctl restart ssh-alert-bot.service"
echo ""
echo "3. Check bot status:"
echo "   sudo systemctl status ssh-alert-bot.service"
echo ""
echo "4. View bot logs:"
echo "   sudo tail -f /var/log/ssh-notify/discord-bot.log"
echo ""
echo "Available Discord Commands:"
echo "  /block_ip <ip>     - Block an IP address"
echo "  /list_blocked      - Show all blocked IPs"
echo "  /unblock_ip <ip>   - Unblock an IP address"
echo "  /recent_failures   - Show recent failed login attempts"
echo ""
echo "=========================================="
