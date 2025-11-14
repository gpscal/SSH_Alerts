#!/usr/bin/env python3
"""
SSH Failed Login Monitor
Monitors authentication logs for failed SSH login attempts and sends Discord alerts
"""

import os
import re
import subprocess
import time
from pathlib import Path
from datetime import datetime

# Possible auth log locations (checked in order)
AUTH_LOG_PATHS = [
    '/var/log/auth.log',      # Debian/Ubuntu
    '/var/log/secure',         # RHEL/CentOS/Fedora
    '/var/log/messages',       # Some other systems
]

# Regex patterns to detect failed SSH login attempts
FAILED_PATTERNS = [
    # Failed password attempts
    re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+ ssh'),
    # Authentication failures
    re.compile(r'authentication failure.*rhost=(\S+).*user=(\S+)'),
    # Invalid user attempts
    re.compile(r'Invalid user (\S+) from (\S+)'),
    # Connection closed due to auth failure
    re.compile(r'Connection closed by (?:invalid user )?(\S+) (\S+) port \d+ \[preauth\]'),
]

def find_auth_log():
    """Find the system's authentication log file"""
    for log_path in AUTH_LOG_PATHS:
        if os.path.exists(log_path):
            return log_path
    return None

def parse_failed_login(line):
    """Parse a log line to extract failed login information
    
    Returns:
        tuple: (username, remote_host) or None if not a failed login
    """
    for pattern in FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            groups = match.groups()
            # Handle different pattern formats
            if len(groups) >= 2:
                # Most patterns have user first, then IP
                user = groups[0] if groups[0] else 'unknown'
                ip = groups[1] if groups[1] else 'unknown'
                
                # Some patterns have IP first, then user
                # Check if first group looks like an IP
                if '.' in groups[0] or ':' in groups[0]:
                    ip = groups[0]
                    user = groups[1] if len(groups) > 1 and groups[1] else 'unknown'
                
                return (user, ip)
    return None

def send_alert(username, remote_host):
    """Send alert using the ssh_notify.py script"""
    try:
        script_path = Path(__file__).parent / 'ssh_notify.py'
        if not script_path.exists():
            # Try installed location
            script_path = Path('/usr/local/bin/ssh-notify/ssh_notify.py')
        
        if script_path.exists():
            subprocess.run(
                [str(script_path), '--failed', username, remote_host],
                timeout=10,
                capture_output=True
            )
    except Exception as e:
        print(f"Error sending alert: {e}")

def monitor_logs():
    """Monitor authentication logs for failed login attempts"""
    auth_log = find_auth_log()
    
    if not auth_log:
        print("Error: Could not find authentication log file")
        print(f"Checked locations: {', '.join(AUTH_LOG_PATHS)}")
        return
    
    print(f"Monitoring {auth_log} for failed SSH login attempts...")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Keep track of recent alerts to avoid duplicates (simple rate limiting)
    recent_alerts = {}  # key: (user, ip), value: timestamp
    ALERT_COOLDOWN = 60  # Don't send duplicate alert within 60 seconds
    
    try:
        # Use tail -F to follow the log file (handles log rotation)
        process = subprocess.Popen(
            ['tail', '-F', '-n', '0', auth_log],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Read and process log lines
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            
            # Check if this is a failed login attempt
            result = parse_failed_login(line)
            if result:
                username, remote_host = result
                
                # Check if we recently sent an alert for this user/IP combo
                alert_key = (username, remote_host)
                current_time = time.time()
                
                if alert_key in recent_alerts:
                    time_since_last = current_time - recent_alerts[alert_key]
                    if time_since_last < ALERT_COOLDOWN:
                        # Skip this alert (too soon)
                        continue
                
                # Send alert
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Failed login: user={username}, ip={remote_host}")
                send_alert(username, remote_host)
                
                # Update recent alerts
                recent_alerts[alert_key] = current_time
                
                # Clean up old entries from recent_alerts
                recent_alerts = {
                    k: v for k, v in recent_alerts.items() 
                    if current_time - v < ALERT_COOLDOWN * 2
                }
    
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"Error monitoring logs: {e}")
    finally:
        if 'process' in locals():
            process.terminate()

if __name__ == "__main__":
    monitor_logs()
