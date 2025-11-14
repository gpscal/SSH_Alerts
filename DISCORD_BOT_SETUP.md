# 🤖 Discord Bot Setup Guide

This guide will help you set up the Discord bot with IP blocking commands for your SSH alert system.

## 📋 Prerequisites

- Root access to your server
- A Discord account
- Discord server (guild) where you have admin permissions

## 🔧 Step 1: Create a Discord Bot

1. **Go to Discord Developer Portal**
   - Visit: https://discord.com/developers/applications
   - Log in with your Discord account

2. **Create New Application**
   - Click "New Application"
   - Give it a name (e.g., "SSH Security Bot")
   - Click "Create"

3. **Create Bot User**
   - Go to the "Bot" tab in the left sidebar
   - Click "Add Bot"
   - Confirm by clicking "Yes, do it!"

4. **Get Bot Token**
   - Under the "Bot" tab, find "TOKEN"
   - Click "Reset Token" and then "Copy"
   - **⚠️ IMPORTANT**: Keep this token secret! It's like a password.

5. **Enable Necessary Intents**
   - Scroll down to "Privileged Gateway Intents"
   - Enable:
     - ✅ MESSAGE CONTENT INTENT
   - Save changes

6. **Set Bot Permissions**
   - Go to the "OAuth2" → "URL Generator" tab
   - Under "SCOPES", select:
     - ✅ `bot`
     - ✅ `applications.commands`
   - Under "BOT PERMISSIONS", select:
     - ✅ Send Messages
     - ✅ Embed Links
     - ✅ Read Message History
     - ✅ Use Slash Commands

7. **Invite Bot to Your Server**
   - Copy the generated URL at the bottom
   - Open it in your browser
   - Select your server from the dropdown
   - Click "Authorize"

## 🔑 Step 2: Get Discord IDs

### Get Channel ID
1. Enable Developer Mode in Discord:
   - Settings → Advanced → Developer Mode (toggle ON)
2. Right-click on the channel where you want alerts → Copy ID

### Get Server (Guild) ID
1. Right-click on your server name (at the top left)
2. Click "Copy Server ID"

## ⚙️ Step 3: Install the Bot on Your Server

1. **Run the installation script**:
   ```bash
   sudo ./install_discord_bot.sh
   ```

2. **Edit the .env file with your credentials**:
   ```bash
   sudo nano /usr/local/bin/ssh-notify/.env
   ```

   Replace the placeholders with your actual values:
   ```env
   DISCORD_BOT_TOKEN=YOUR_ACTUAL_BOT_TOKEN_HERE
   DISCORD_CHANNEL_ID=YOUR_CHANNEL_ID_HERE
   DISCORD_GUILD_ID=YOUR_SERVER_ID_HERE
   ```

   - Press `Ctrl+X`, then `Y`, then `Enter` to save

3. **Restart the bot service**:
   ```bash
   sudo systemctl restart ssh-alert-bot.service
   ```

4. **Check if the bot is running**:
   ```bash
   sudo systemctl status ssh-alert-bot.service
   ```

   You should see "active (running)" in green.

5. **View bot logs to verify it's working**:
   ```bash
   sudo tail -f /var/log/ssh-notify/discord-bot.log
   ```

   You should see a message like: "Bot logged in as YourBotName#1234"

## 🎮 Step 4: Use the Bot Commands

In your Discord server, use these slash commands:

### 🛡️ Block an IP Address
```
/block_ip 192.168.1.100
```
This will:
- Add the IP to iptables DROP rules
- Track it in the blocked IPs list
- Show who blocked it and when

### 📋 List Blocked IPs
```
/list_blocked
```
This shows:
- All IPs you've blocked via the bot
- Active iptables rules
- Who blocked each IP and when

### ✅ Unblock an IP Address
```
/unblock_ip 192.168.1.100
```
This will:
- Remove the IP from iptables
- Remove it from the tracking list

### ⚠️ View Recent Failed Attempts
```
/recent_failures
```
This shows:
- Recent failed SSH login attempts
- How many attempts from each IP
- Which usernames were tried

## 🔍 Troubleshooting

### Bot is offline
```bash
# Check service status
sudo systemctl status ssh-alert-bot.service

# View logs
sudo tail -50 /var/log/ssh-notify/discord-bot.log

# Restart the service
sudo systemctl restart ssh-alert-bot.service
```

### Commands not working
1. Make sure the bot has the right permissions in Discord
2. Check that DISCORD_GUILD_ID is set correctly in .env
3. The bot needs a few minutes to register commands after first start

### "Permission denied" when blocking IPs
1. Check sudoers configuration:
   ```bash
   sudo cat /etc/sudoers.d/ssh-notify
   ```
2. Make sure the user running the bot is listed

### Bot can't read logs for /recent_failures
1. Check sudoers allows reading log files
2. Verify the log file exists:
   ```bash
   ls -l /var/log/auth.log  # or /var/log/secure
   ```

## 🔐 Security Notes

1. **Keep your bot token secret!** Never share it publicly.
2. The bot runs as root by default for simplicity. In production, consider:
   - Running as a dedicated user
   - Using more restrictive sudoers rules
3. Review who has permission to use these commands in Discord
4. Consider using Discord role permissions to restrict command usage

## 🔄 Updating

If you make changes to `discord_bot.py`:

```bash
sudo cp discord_bot.py /usr/local/bin/ssh-notify/
sudo systemctl restart ssh-alert-bot.service
```

## 📊 Integration with Existing SSH Alerts

This bot works alongside your existing SSH notification system:
- `ssh_notify.py` - Sends alerts for successful logins
- `ssh_failed_monitor.py` - Sends alerts for failed logins
- `discord_bot.py` - Provides interactive commands to manage security

All three can run simultaneously!

## 🆘 Need Help?

Common issues:
- **Bot shows offline**: Check the service is running and token is correct
- **Commands don't appear**: Wait a few minutes or try kicking and re-inviting the bot
- **Can't block IPs**: Check sudoers configuration
- **Logs not found**: Make sure `/var/log/ssh-notify/` directory exists

---

Enjoy your enhanced SSH security! 🚀
