# 🎮 Discord Bot Commands Reference

## Quick Command List

### 🛡️ Block an IP
```
/block_ip <ip_address>
```
**Example**: `/block_ip 192.168.1.100`

**What it does**:
- Adds the IP to iptables DROP rule: `sudo iptables -A INPUT -s <IP> -j DROP`
- Tracks who blocked it and when
- Saves to persistent storage

---

### 📋 List Blocked IPs
```
/list_blocked
```

**What it does**:
- Shows all IPs blocked via the bot (with timestamps and who blocked them)
- Shows active iptables DROP rules
- Displays up to 10 most recent tracked blocks
- Displays up to 20 active iptables rules

---

### ✅ Unblock an IP
```
/unblock_ip <ip_address>
```
**Example**: `/unblock_ip 192.168.1.100`

**What it does**:
- Removes the IP from iptables: `sudo iptables -D INPUT -s <IP> -j DROP`
- Removes from tracking database
- Shows who unblocked it

---

### ⚠️ Recent Failed Logins
```
/recent_failures
```

**What it does**:
- Scans the last 100 lines of auth logs
- Shows IPs with failed login attempts
- Shows how many attempts from each IP
- Shows which usernames were tried
- Sorted by number of attempts (highest first)

---

## Typical Workflow

### 1. Monitor Failed Attempts
When you receive a failed login alert in Discord from the monitoring system, note the IP address.

### 2. Check Recent Failures
Use `/recent_failures` to see if there are repeated attempts from the same IP:
```
/recent_failures
```

### 3. Block Suspicious IP
If you see an IP with many failed attempts, block it:
```
/block_ip 192.168.1.100
```

### 4. Review Blocked IPs
Periodically check what's blocked:
```
/list_blocked
```

### 5. Unblock if Needed
If you accidentally blocked a legitimate IP or want to remove an old block:
```
/unblock_ip 192.168.1.100
```

---

## Command Output Examples

### Successful Block
```
🛡️ IP Address Blocked
IP Address: 192.168.1.100
Blocked By: @YourUsername
Status: ✅ Successfully blocked
```

### List Blocked Output
```
🛡️ Blocked IP Addresses

📋 Tracked Blocks (5 total)
192.168.1.100 - 2025-11-14 15:30 by User#1234
10.0.0.50 - 2025-11-14 14:20 by User#1234
...

🔥 Active iptables Rules (5 total)
192.168.1.100
10.0.0.50
...
```

### Recent Failures Output
```
⚠️ Recent Failed Login Attempts

🔴 192.168.1.100
Attempts: 15
Users: root, admin, ubuntu

🔴 10.0.0.50
Attempts: 8
Users: admin, test
...
```

---

## Behind the Scenes

### What happens when you block an IP?

1. **Validates the IP format** (IPv4 or IPv6)
2. **Checks if already blocked** (prevents duplicates)
3. **Runs iptables command**:
   ```bash
   sudo iptables -A INPUT -s <IP_ADDRESS> -j DROP
   ```
4. **Saves iptables rules** to persist across reboots:
   ```bash
   sudo iptables-save
   ```
5. **Logs to tracking database** at `/var/lib/ssh-notify/blocked_ips.json`:
   ```json
   {
     "ip": "192.168.1.100",
     "blocked_by": "User#1234",
     "blocked_at": "2025-11-14T15:30:00",
     "reason": "Manual block via Discord"
   }
   ```

### What happens when you list blocked IPs?

1. **Reads tracking database** from `/var/lib/ssh-notify/blocked_ips.json`
2. **Queries iptables** using:
   ```bash
   sudo iptables -L INPUT -n -v
   ```
3. **Parses iptables output** to find DROP rules with source IPs
4. **Displays both** tracked entries and active rules

### What happens when you check recent failures?

1. **Reads system auth log**:
   - `/var/log/auth.log` (Debian/Ubuntu)
   - `/var/log/secure` (RHEL/CentOS)
2. **Uses regex patterns** to find failed login lines
3. **Aggregates by IP** and counts attempts
4. **Shows top 10** most frequent attackers

---

## Technical Details

### File Locations
- Bot script: `/usr/local/bin/ssh-notify/discord_bot.py`
- Tracking database: `/var/lib/ssh-notify/blocked_ips.json`
- Bot logs: `/var/log/ssh-notify/discord-bot.log`
- Sudoers config: `/etc/sudoers.d/ssh-notify`

### Service Management
```bash
# Check bot status
sudo systemctl status ssh-alert-bot.service

# Restart bot
sudo systemctl restart ssh-alert-bot.service

# View logs
sudo tail -f /var/log/ssh-notify/discord-bot.log

# Stop bot
sudo systemctl stop ssh-alert-bot.service

# Start bot
sudo systemctl start ssh-alert-bot.service
```

### Manual iptables Commands

If you need to manually manage iptables:

```bash
# List all iptables rules
sudo iptables -L INPUT -n -v --line-numbers

# Block an IP manually
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# Unblock an IP manually (by source)
sudo iptables -D INPUT -s 192.168.1.100 -j DROP

# Or delete by line number
sudo iptables -D INPUT <line_number>

# Save rules
sudo iptables-save > /etc/iptables/rules.v4  # Debian/Ubuntu
sudo service iptables save  # RHEL/CentOS

# View blocked IPs only
sudo iptables -L INPUT -n | grep DROP
```

---

## Security Considerations

⚠️ **Important Notes**:

1. **Be careful with IP blocking** - Make sure you don't lock yourself out!
2. **Test with non-critical IPs first**
3. **Keep track** of what you block (that's why the bot maintains a database)
4. **Consider VPN/proxy IPs** - Blocking them might affect multiple users
5. **Review blocks periodically** - Remove outdated blocks

### Best Practices

✅ **DO**:
- Block IPs with repeated failed attempts (10+)
- Block IPs trying common usernames (root, admin, etc.)
- Review the blocked list monthly
- Keep logs for audit purposes

❌ **DON'T**:
- Block entire subnets unless absolutely necessary
- Block IPs from your own organization
- Block cloud provider IPs without investigation
- Forget to document why you blocked something

---

## Permissions

To use these commands in Discord, users need:
- Access to the Discord channel where the bot is
- Appropriate Discord permissions (you can configure this per-role)

To restrict who can use commands:
1. Go to Server Settings → Integrations → Bots
2. Click on your SSH Security Bot
3. Configure command permissions per role/channel

---

Enjoy managing your SSH security! 🚀
