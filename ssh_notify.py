#!/usr/bin/env python3
"""
SSH Login Notification Script for Discord
Sends a notification to Discord when someone logs in via SSH
"""

import os
import sys
import json
import requests
from datetime import datetime
from pathlib import Path

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

def send_discord_notification(login_type="success", username=None, remote_host=None):
    """Send SSH login notification to Discord
    
    Args:
        login_type: "success" or "failed" - type of login attempt
        username: Username attempting to log in (optional, will try to get from env)
        remote_host: Remote IP address (optional, will try to get from env)
    """
    try:
        # Load environment variables
        load_env()
        
        # Get Discord credentials
        bot_token = os.environ.get('DISCORD_BOT_TOKEN')
        channel_id = os.environ.get('DISCORD_CHANNEL_ID')
        
        if not bot_token or not channel_id:
            print("Error: DISCORD_BOT_TOKEN or DISCORD_CHANNEL_ID not set", file=sys.stderr)
            return False
        
        # Get login information from environment variables (set by PAM) or use provided values
        if username is None:
            username = os.environ.get('PAM_USER', os.environ.get('USER', 'unknown'))
        if remote_host is None:
            remote_host = os.environ.get('PAM_RHOST', os.environ.get('SSH_CLIENT', 'unknown').split()[0] if os.environ.get('SSH_CLIENT') else 'unknown')
        
        hostname = os.popen('hostname').read().strip()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Customize message based on login type
        if login_type == "failed":
            title = "⚠️ SSH Failed Login Attempt"
            color = 15158332  # Red color
            status_field = {
                "name": "Status",
                "value": "❌ **FAILED**",
                "inline": False
            }
        else:
            title = "🔐 SSH Login Alert"
            color = 3447003  # Blue color
            status_field = {
                "name": "Status",
                "value": "✅ **SUCCESSFUL**",
                "inline": False
            }
        
        # Create embedded message
        embed = {
            "title": title,
            "color": color,
            "fields": [
                status_field,
                {
                    "name": "User",
                    "value": f"`{username}`",
                    "inline": True
                },
                {
                    "name": "Source IP",
                    "value": f"`{remote_host}`",
                    "inline": True
                },
                {
                    "name": "Server",
                    "value": f"`{hostname}`",
                    "inline": True
                },
                {
                    "name": "Time",
                    "value": f"`{timestamp}`",
                    "inline": False
                }
            ],
            "footer": {
                "text": "SSH Login Monitor"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Prepare the message payload
        payload = {
            "embeds": [embed]
        }
        
        # Send to Discord using bot token
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }
        
        url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
        
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        
        if response.status_code in [200, 204]:
            return True
        else:
            print(f"Discord API error: {response.status_code} - {response.text}", file=sys.stderr)
            return False
            
    except Exception as e:
        print(f"Error sending Discord notification: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    # Check if this is for a failed login attempt (called from log monitor)
    login_type = "success"  # Default to success for PAM hooks
    username = None
    remote_host = None
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--failed":
            login_type = "failed"
            # Get username and remote_host from arguments if provided
            if len(sys.argv) > 2:
                username = sys.argv[2]
            if len(sys.argv) > 3:
                remote_host = sys.argv[3]
    
    # Run notification in background to not block SSH login
    try:
        send_discord_notification(login_type, username, remote_host)
    except Exception as e:
        # Fail silently to not interfere with SSH login
        print(f"Notification failed: {e}", file=sys.stderr)
    
    # Always exit successfully so SSH login isn't blocked
    sys.exit(0)