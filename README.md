# 🔐 SSH Alert System with Discord Bot

A comprehensive SSH security monitoring system that sends Discord notifications for login attempts and provides interactive commands to block malicious IPs.

## 🌟 Features

### 📢 Automated Notifications
- **Successful SSH logins** - Get notified when someone logs into your server
- **Failed login attempts** - Real-time alerts for failed SSH authentication
- **Detailed information** - See username, IP address, timestamp, and server name

### 🤖 Interactive Discord Bot
- **Block IPs** - Block attacking IPs directly from Discord using `/block_ip`
- **List blocked IPs** - View all blocked IPs with `/list_blocked`
- **Unblock IPs** - Remove blocks with `/unblock_ip`
- **Recent failures** - Check recent failed attempts with `/recent_failures`

### 🛡️ Security Features
- **iptables integration** - Automatically applies firewall rules
- **Persistent blocking** - Blocks survive server reboots
- **Audit trail** - Track who blocked what and when
- **Rate limiting** - Prevents notification spam

## 📁 Project Structure

```
ssh_alert/
├── ssh_notify.py              # Sends Discord notifications for logins
├── ssh_failed_monitor.py      # Monitors logs for failed attempts
├── discord_bot.py             # Discord bot with interactive commands
├── install_ssh_notify.sh      # Installs the notification system
├── install_discord_bot.sh     # Installs the Discord bot
├── ssh-notify-sudoers         # Sudoers configuration for iptables
├── test_failed_alert.sh       # Test script for failed login alerts
├── DISCORD_BOT_SETUP.md       # Detailed bot setup guide
├── COMMANDS_REFERENCE.md      # Discord commands reference
└── CODE_EXPLANATION.md        # Beginner-friendly code walkthrough
```

## 🚀 Quick Start

### Option 1: Notifications Only (Simple)

Just want SSH login/failure notifications? Follow these steps:

1. **Clone the repository**:
   ```bash
   cd /tmp
   git clone <your-repo-url>
   cd ssh_alert
   ```

2. **Create a Discord bot** (see DISCORD_BOT_SETUP.md for detailed instructions)

3. **Create `.env` file** with your Discord credentials:
   ```bash
   nano .env
   ```
   
   Add:
   ```env
   DISCORD_BOT_TOKEN=your_bot_token_here
   DISCORD_CHANNEL_ID=your_channel_id_here
   ```

4. **Run the installer**:
   ```bash
   sudo ./install_ssh_notify.sh
   ```

5. **Done!** You'll now get Discord notifications for SSH logins.

### Option 2: Full System with Bot Commands (Recommended)

Want notifications AND interactive IP blocking commands?

1. **Follow Option 1 steps** (above)

2. **Get your Discord Server (Guild) ID**:
   - Enable Developer Mode in Discord (Settings → Advanced → Developer Mode)
   - Right-click your server name → Copy Server ID

3. **Add Guild ID to `.env`**:
   ```bash
   sudo nano /usr/local/bin/ssh-notify/.env
   ```
   
   Add this line:
   ```env
   DISCORD_GUILD_ID=your_server_id_here
   ```

4. **Install the Discord bot**:
   ```bash
   sudo ./install_discord_bot.sh
   ```

5. **Restart the bot**:
   ```bash
   sudo systemctl restart ssh-alert-bot.service
   ```

6. **Use commands in Discord**:
   - `/block_ip 192.168.1.100`
   - `/list_blocked`
   - `/recent_failures`

## 🎮 Discord Commands

### `/block_ip <ip_address>`
Block an IP address using iptables.

**Example**: `/block_ip 192.168.1.100`

```
🛡️ IP Address Blocked
IP Address: 192.168.1.100
Blocked By: @YourUsername
Status: ✅ Successfully blocked
```

### `/list_blocked`
Show all blocked IP addresses with details.

```
🛡️ Blocked IP Addresses

📋 Tracked Blocks (5 total)
192.168.1.100 - 2025-11-14 15:30 by User#1234
10.0.0.50 - 2025-11-14 14:20 by User#1234

🔥 Active iptables Rules (5 total)
192.168.1.100
10.0.0.50
```

### `/unblock_ip <ip_address>`
Remove an IP from the block list.

**Example**: `/unblock_ip 192.168.1.100`

### `/recent_failures`
View recent failed SSH login attempts.

```
⚠️ Recent Failed Login Attempts

🔴 192.168.1.100
Attempts: 15
Users: root, admin, ubuntu
```

## 📋 Requirements

- **OS**: Linux (tested on Ubuntu/Debian, RHEL/CentOS)
- **Python**: 3.7+
- **Root access**: Required for installation
- **Discord**: Bot token and server access
- **iptables**: For IP blocking (usually pre-installed)

### Python Dependencies
- `requests` - For sending Discord notifications
- `discord.py` - For Discord bot functionality

These are automatically installed by the installation scripts.

## 🔧 Configuration

### Environment Variables (`.env` file)

```env
# Required for all functionality
DISCORD_BOT_TOKEN=your_bot_token_here
DISCORD_CHANNEL_ID=your_channel_id_here

# Required for bot commands
DISCORD_GUILD_ID=your_server_id_here
```

### File Locations

**Installation directory**:
- `/usr/local/bin/ssh-notify/` - Scripts and configuration

**Data and logs**:
- `/var/lib/ssh-notify/blocked_ips.json` - Blocked IP database
- `/var/log/ssh-notify/` - Log files

**System integration**:
- `/etc/pam.d/sshd` - PAM hook for successful logins
- `/etc/systemd/system/ssh-failed-monitor.service` - Failed login monitor
- `/etc/systemd/system/ssh-alert-bot.service` - Discord bot service
- `/etc/sudoers.d/ssh-notify` - Sudoers configuration

## 🔍 Monitoring and Troubleshooting

### Check Service Status

```bash
# Check failed login monitor
sudo systemctl status ssh-failed-monitor.service

# Check Discord bot
sudo systemctl status ssh-alert-bot.service
```

### View Logs

```bash
# Failed login monitor logs
sudo tail -f /var/log/ssh-notify/failed-monitor.log

# Discord bot logs
sudo tail -f /var/log/ssh-notify/discord-bot.log

# System auth logs
sudo tail -f /var/log/auth.log  # or /var/log/secure
```

### Test Notifications

```bash
# Test successful login notification
sudo /usr/local/bin/ssh-notify-test

# Test failed login notification
sudo ./test_failed_alert.sh
```

### Restart Services

```bash
# Restart failed login monitor
sudo systemctl restart ssh-failed-monitor.service

# Restart Discord bot
sudo systemctl restart ssh-alert-bot.service
```

## 🛠️ Manual IP Blocking

You can also manage iptables manually:

```bash
# Block an IP
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# List all rules with line numbers
sudo iptables -L INPUT -n -v --line-numbers

# Unblock an IP
sudo iptables -D INPUT -s 192.168.1.100 -j DROP

# Save rules (Debian/Ubuntu)
sudo iptables-save > /etc/iptables/rules.v4

# Save rules (RHEL/CentOS)
sudo service iptables save
```

## 🔐 Security Considerations

### ⚠️ Important Warnings

1. **Don't lock yourself out!** Be careful when blocking IPs.
2. **Test first** - Try blocking a non-critical IP before using in production.
3. **Keep SSH keys** - Always have SSH key authentication as a backup.
4. **Monitor logs** - Regularly check what's being blocked.

### 🛡️ Best Practices

✅ **DO**:
- Use strong SSH passwords/keys
- Change default SSH port
- Enable SSH key authentication
- Regularly review blocked IPs
- Keep logs for security audits
- Use fail2ban alongside this system

❌ **DON'T**:
- Block your own IP address
- Block entire subnets without careful consideration
- Disable SSH password authentication without setting up keys first
- Share your Discord bot token
- Run the bot as root in production (use a dedicated user)

## 📚 Documentation

- **[DISCORD_BOT_SETUP.md](DISCORD_BOT_SETUP.md)** - Detailed Discord bot setup guide
- **[COMMANDS_REFERENCE.md](COMMANDS_REFERENCE.md)** - Complete command reference
- **[CODE_EXPLANATION.md](CODE_EXPLANATION.md)** - Beginner-friendly code walkthrough

## 🎯 How It Works

### Successful SSH Logins
1. User logs in via SSH
2. PAM (Linux authentication system) runs `ssh_notify.py`
3. Script sends blue notification to Discord

### Failed SSH Attempts
1. Failed login is logged to `/var/log/auth.log` or `/var/log/secure`
2. `ssh_failed_monitor.py` (running as service) detects the failure
3. Script sends red warning notification to Discord

### IP Blocking via Bot
1. User runs `/block_ip` command in Discord
2. Bot validates the IP address
3. Bot executes `sudo iptables -A INPUT -s <IP> -j DROP`
4. Block is saved to database with audit trail
5. Confirmation sent to Discord

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## 📝 License

This project is provided as-is for educational and security purposes.

## 🆘 Support

If you encounter issues:

1. **Check logs**: Most issues show up in logs
2. **Verify credentials**: Ensure Discord tokens are correct
3. **Check permissions**: Bot needs proper Discord and system permissions
4. **Review sudoers**: Make sure iptables commands are allowed
5. **Test manually**: Try commands manually to isolate the issue

## 🎓 Learning Resources

New to these concepts? Check out:
- **CODE_EXPLANATION.md** - Line-by-line code explanation
- **SSH Security** - https://www.ssh.com/academy/ssh/security
- **iptables Tutorial** - https://www.digitalocean.com/community/tutorials/iptables-essentials-common-firewall-rules-and-commands
- **Discord Bot Development** - https://discordpy.readthedocs.io/

---

Made with ❤️ for server security

**Stay safe and monitor your servers!** 🚀🔒
