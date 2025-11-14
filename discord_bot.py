#!/usr/bin/env python3
"""
Discord Bot for SSH Alert Management
Provides commands to block IPs and view blocked IPs
"""

import os
import sys
import json
import subprocess
import discord
from discord import app_commands
from pathlib import Path
from datetime import datetime
import re

# Load environment variables from .env file
def load_env():
    """Load environment variables from .env file"""
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

# Load environment variables
load_env()

# Configuration
BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
GUILD_ID = os.environ.get('DISCORD_GUILD_ID')  # Server ID for slash commands
BLOCKED_IPS_FILE = '/var/lib/ssh-notify/blocked_ips.json'

# Validate IP address format
def is_valid_ip(ip):
    """Check if the IP address is valid (IPv4 or IPv6)"""
    # IPv4 pattern
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    # IPv6 pattern (simplified)
    ipv6_pattern = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
    
    if ipv4_pattern.match(ip):
        # Validate each octet is 0-255
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    elif ipv6_pattern.match(ip):
        return True
    return False

# Load blocked IPs from file
def load_blocked_ips():
    """Load the list of blocked IPs from file"""
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"Error loading blocked IPs: {e}", file=sys.stderr)
        return []

# Save blocked IPs to file
def save_blocked_ips(blocked_ips):
    """Save the list of blocked IPs to file"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f, indent=2)
        # Set appropriate permissions
        os.chmod(BLOCKED_IPS_FILE, 0o600)
        return True
    except Exception as e:
        print(f"Error saving blocked IPs: {e}", file=sys.stderr)
        return False

# Block an IP using iptables
def block_ip_iptables(ip_address):
    """Block an IP address using iptables"""
    try:
        # Check if IP is already blocked in iptables
        check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP']
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            return False, "IP is already blocked in iptables"
        
        # Block the IP
        block_cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
        result = subprocess.run(block_cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Save iptables rules to persist across reboots
            save_cmd = ['sudo', 'iptables-save']
            subprocess.run(save_cmd, capture_output=True, timeout=10)
            return True, "IP blocked successfully"
        else:
            return False, f"Failed to block IP: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, f"Error: {str(e)}"

# Get list of blocked IPs from iptables
def get_iptables_blocked_ips():
    """Get list of IPs blocked in iptables"""
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-L', 'INPUT', '-n', '-v'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return []
        
        blocked_ips = []
        for line in result.stdout.split('\n'):
            # Look for DROP rules with source IPs
            if 'DROP' in line and 'anywhere' not in line:
                parts = line.split()
                # Find the source IP (format: x.x.x.x or x.x.x.x/xx)
                for part in parts:
                    if '.' in part or ':' in part:
                        ip = part.split('/')[0]  # Remove CIDR notation if present
                        if is_valid_ip(ip):
                            blocked_ips.append(ip)
                            break
        
        return blocked_ips
    except Exception as e:
        print(f"Error getting iptables blocked IPs: {e}", file=sys.stderr)
        return []

# Unblock an IP using iptables
def unblock_ip_iptables(ip_address):
    """Unblock an IP address using iptables"""
    try:
        # Remove the rule
        unblock_cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
        result = subprocess.run(unblock_cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Save iptables rules
            save_cmd = ['sudo', 'iptables-save']
            subprocess.run(save_cmd, capture_output=True, timeout=10)
            return True, "IP unblocked successfully"
        else:
            return False, f"Failed to unblock IP: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, f"Error: {str(e)}"

# Create Discord bot
class SSHBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        """Setup slash commands"""
        if GUILD_ID:
            guild = discord.Object(id=int(GUILD_ID))
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()

# Initialize bot
bot = SSHBot()

@bot.event
async def on_ready():
    print(f'Bot logged in as {bot.user}')
    print(f'Bot is ready to receive commands!')

# Block IP command
@bot.tree.command(name="block_ip", description="Block an IP address using iptables")
@app_commands.describe(ip_address="The IP address to block")
async def block_ip(interaction: discord.Interaction, ip_address: str):
    """Block an IP address"""
    await interaction.response.defer(ephemeral=False)
    
    # Validate IP address
    if not is_valid_ip(ip_address):
        await interaction.followup.send(
            f"❌ Invalid IP address format: `{ip_address}`",
            ephemeral=False
        )
        return
    
    # Check if already blocked
    blocked_ips = load_blocked_ips()
    already_blocked = any(entry['ip'] == ip_address for entry in blocked_ips)
    
    if already_blocked:
        await interaction.followup.send(
            f"⚠️ IP `{ip_address}` is already in the blocked list!",
            ephemeral=False
        )
        return
    
    # Block the IP
    success, message = block_ip_iptables(ip_address)
    
    if success:
        # Add to blocked IPs list
        blocked_ips.append({
            'ip': ip_address,
            'blocked_by': str(interaction.user),
            'blocked_at': datetime.now().isoformat(),
            'reason': 'Manual block via Discord'
        })
        save_blocked_ips(blocked_ips)
        
        # Create success embed
        embed = discord.Embed(
            title="🛡️ IP Address Blocked",
            color=discord.Color.red(),
            timestamp=datetime.now()
        )
        embed.add_field(name="IP Address", value=f"`{ip_address}`", inline=True)
        embed.add_field(name="Blocked By", value=interaction.user.mention, inline=True)
        embed.add_field(name="Status", value="✅ Successfully blocked", inline=False)
        embed.set_footer(text="SSH Security Manager")
        
        await interaction.followup.send(embed=embed)
    else:
        await interaction.followup.send(
            f"❌ Failed to block IP `{ip_address}`: {message}",
            ephemeral=False
        )

# List blocked IPs command
@bot.tree.command(name="list_blocked", description="Show all blocked IP addresses")
async def list_blocked(interaction: discord.Interaction):
    """List all blocked IP addresses"""
    await interaction.response.defer(ephemeral=False)
    
    # Get blocked IPs from both our list and iptables
    blocked_ips = load_blocked_ips()
    iptables_ips = get_iptables_blocked_ips()
    
    if not blocked_ips and not iptables_ips:
        await interaction.followup.send(
            "✅ No IP addresses are currently blocked.",
            ephemeral=False
        )
        return
    
    # Create embed
    embed = discord.Embed(
        title="🛡️ Blocked IP Addresses",
        color=discord.Color.red(),
        timestamp=datetime.now()
    )
    
    # Add tracked IPs
    if blocked_ips:
        ip_list = []
        for entry in blocked_ips[-10:]:  # Show last 10
            ip = entry['ip']
            blocked_at = entry.get('blocked_at', 'Unknown')
            blocked_by = entry.get('blocked_by', 'Unknown')
            try:
                # Format timestamp
                dt = datetime.fromisoformat(blocked_at)
                time_str = dt.strftime('%Y-%m-%d %H:%M')
            except:
                time_str = blocked_at
            
            ip_list.append(f"`{ip}` - {time_str} by {blocked_by}")
        
        embed.add_field(
            name=f"📋 Tracked Blocks ({len(blocked_ips)} total)",
            value="\n".join(ip_list) if ip_list else "None",
            inline=False
        )
    
    # Add iptables IPs
    if iptables_ips:
        iptables_list = [f"`{ip}`" for ip in iptables_ips[:20]]  # Show first 20
        embed.add_field(
            name=f"🔥 Active iptables Rules ({len(iptables_ips)} total)",
            value="\n".join(iptables_list) if iptables_list else "None",
            inline=False
        )
    
    embed.set_footer(text="SSH Security Manager")
    
    await interaction.followup.send(embed=embed)

# Unblock IP command
@bot.tree.command(name="unblock_ip", description="Unblock an IP address")
@app_commands.describe(ip_address="The IP address to unblock")
async def unblock_ip(interaction: discord.Interaction, ip_address: str):
    """Unblock an IP address"""
    await interaction.response.defer(ephemeral=False)
    
    # Validate IP address
    if not is_valid_ip(ip_address):
        await interaction.followup.send(
            f"❌ Invalid IP address format: `{ip_address}`",
            ephemeral=False
        )
        return
    
    # Unblock the IP
    success, message = unblock_ip_iptables(ip_address)
    
    if success:
        # Remove from blocked IPs list
        blocked_ips = load_blocked_ips()
        blocked_ips = [entry for entry in blocked_ips if entry['ip'] != ip_address]
        save_blocked_ips(blocked_ips)
        
        # Create success embed
        embed = discord.Embed(
            title="✅ IP Address Unblocked",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        embed.add_field(name="IP Address", value=f"`{ip_address}`", inline=True)
        embed.add_field(name="Unblocked By", value=interaction.user.mention, inline=True)
        embed.add_field(name="Status", value="✅ Successfully unblocked", inline=False)
        embed.set_footer(text="SSH Security Manager")
        
        await interaction.followup.send(embed=embed)
    else:
        await interaction.followup.send(
            f"❌ Failed to unblock IP `{ip_address}`: {message}",
            ephemeral=False
        )

# Recent failed logins command (bonus feature)
@bot.tree.command(name="recent_failures", description="Show recent failed SSH login attempts")
async def recent_failures(interaction: discord.Interaction):
    """Show recent failed login attempts"""
    await interaction.response.defer(ephemeral=False)
    
    try:
        # Try to read auth log
        auth_logs = ['/var/log/auth.log', '/var/log/secure']
        auth_log = None
        
        for log_path in auth_logs:
            if os.path.exists(log_path):
                auth_log = log_path
                break
        
        if not auth_log:
            await interaction.followup.send(
                "❌ Could not find authentication log file",
                ephemeral=False
            )
            return
        
        # Get last 100 lines and parse for failures
        result = subprocess.run(
            ['sudo', 'tail', '-n', '100', auth_log],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            await interaction.followup.send(
                "❌ Could not read authentication log",
                ephemeral=False
            )
            return
        
        # Parse failures
        failures = {}
        failed_pattern = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)')
        
        for line in result.stdout.split('\n'):
            match = failed_pattern.search(line)
            if match:
                user, ip = match.groups()
                if ip not in failures:
                    failures[ip] = {'count': 0, 'users': set()}
                failures[ip]['count'] += 1
                failures[ip]['users'].add(user)
        
        if not failures:
            await interaction.followup.send(
                "✅ No recent failed login attempts found!",
                ephemeral=False
            )
            return
        
        # Create embed
        embed = discord.Embed(
            title="⚠️ Recent Failed Login Attempts",
            color=discord.Color.orange(),
            timestamp=datetime.now()
        )
        
        # Sort by count and show top 10
        sorted_failures = sorted(failures.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
        
        for ip, data in sorted_failures:
            users = ', '.join(list(data['users'])[:3])
            if len(data['users']) > 3:
                users += f" (+{len(data['users'])-3} more)"
            
            embed.add_field(
                name=f"🔴 {ip}",
                value=f"Attempts: {data['count']}\nUsers: {users}",
                inline=True
            )
        
        embed.set_footer(text="SSH Security Manager • Last 100 log lines")
        
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(
            f"❌ Error reading recent failures: {str(e)}",
            ephemeral=False
        )

# Run the bot
if __name__ == "__main__":
    if not BOT_TOKEN:
        print("Error: DISCORD_BOT_TOKEN not set in .env file", file=sys.stderr)
        sys.exit(1)
    
    try:
        bot.run(BOT_TOKEN)
    except Exception as e:
        print(f"Error starting bot: {e}", file=sys.stderr)
        sys.exit(1)
