# 🎓 SSH Alert System - Code Explanation for Beginners

This guide explains every part of the SSH alert system in simple terms!

---

## 📄 File 1: `ssh_notify.py` - The Message Sender

This is the script that sends messages to Discord. Think of it as your "mailman" that delivers notifications.

### Line-by-Line Explanation:

```python
#!/usr/bin/env python3
```
**What it does:** This is like a label on a package that says "Open with Python3". It tells your computer to use Python3 to run this file.

---

```python
"""
SSH Login Notification Script for Discord
Sends a notification to Discord when someone logs in via SSH
"""
```
**What it does:** This is a description (called a "docstring") that explains what this script does. It's like a sticky note explaining the purpose of the file.

---

```python
import os
import sys
import json
import requests
from datetime import datetime
from pathlib import Path
```
**What it does:** These lines are like bringing tools to your workbench. Each `import` loads a different tool:
- `os`: Lets us read environment variables (like secrets stored on the computer)
- `sys`: Lets us interact with the system (like reading command-line arguments)
- `json`: Helps us work with JSON data (a way to structure information)
- `requests`: Lets us send messages to the internet (to Discord)
- `datetime`: Helps us work with dates and times
- `Path`: Makes it easier to work with file paths

---

```python
def load_env():
    """Load environment variables from .env file"""
```
**What it does:** This creates a function (a reusable piece of code) called `load_env`. Think of it as creating a recipe you can use later. This recipe will read your secret Discord credentials from a file.

---

```python
    env_path = Path(__file__).parent / '.env'
```
**What it does:** 
- `__file__` means "this current Python file"
- `.parent` means "the folder this file is in"
- `/ '.env'` adds ".env" to the path
- **Result:** This finds where the `.env` file should be (in the same folder as this script)

---

```python
    if env_path.exists():
```
**What it does:** Checks "Does the .env file exist?" Like checking if a box is on the shelf before trying to open it.

---

```python
        with open(env_path) as f:
```
**What it does:** Opens the `.env` file so we can read it. The `with` is like saying "open this, use it, then close it automatically when done."

---

```python
            for line in f:
```
**What it does:** Goes through the file line by line, like reading a book one line at a time.

---

```python
                line = line.strip()
```
**What it does:** Removes extra spaces and newlines from the beginning and end of the line. Like trimming the edges of a piece of paper.

---

```python
                if line and not line.startswith('#') and '=' in line:
```
**What it does:** This checks three things:
1. `line` - Is the line not empty?
2. `not line.startswith('#')` - Does it NOT start with # (which means it's not a comment)?
3. `'=' in line` - Does it have an = sign (which separates the key from the value)?

**Example:** `DISCORD_BOT_TOKEN=abc123` would pass all three checks!

---

```python
                    key, value = line.split('=', 1)
```
**What it does:** Splits the line at the `=` sign into two parts:
- `key`: The part before the = (like "DISCORD_BOT_TOKEN")
- `value`: The part after the = (like "abc123")
- The `1` means "only split once" (in case the value has = in it)

---

```python
                    os.environ[key.strip()] = value.strip()
```
**What it does:** Saves the key and value to the system's environment variables (like putting a sticky note where the computer can find it later). The `.strip()` removes any extra spaces.

---

```python
def send_discord_notification(login_type="success", username=None, remote_host=None):
```
**What it does:** Creates the main function that sends Discord notifications. It accepts three parameters:
- `login_type`: Was the login "success" or "failed"? (defaults to "success")
- `username`: Who tried to log in? (optional)
- `remote_host`: What IP address did they come from? (optional)

---

```python
    try:
```
**What it does:** Starts a "try block" - like saying "Try to do this, and if something goes wrong, we'll handle it gracefully."

---

```python
        load_env()
```
**What it does:** Calls our function from before to load the Discord credentials from the `.env` file.

---

```python
        bot_token = os.environ.get('DISCORD_BOT_TOKEN')
        channel_id = os.environ.get('DISCORD_CHANNEL_ID')
```
**What it does:** Gets the Discord bot token and channel ID from the environment variables (the sticky notes we saved earlier).

---

```python
        if not bot_token or not channel_id:
            print("Error: DISCORD_BOT_TOKEN or DISCORD_CHANNEL_ID not set", file=sys.stderr)
            return False
```
**What it does:** Checks "Do we have both the bot token AND the channel ID?" If either is missing, print an error message and stop (return False means "this didn't work").

---

```python
        if username is None:
            username = os.environ.get('PAM_USER', os.environ.get('USER', 'unknown'))
```
**What it does:** If no username was provided to the function, try to find it:
1. First, check `PAM_USER` (set by the system during SSH login)
2. If that's not available, check `USER` (current user)
3. If nothing is found, use 'unknown'

This is like a chain of backup plans!

---

```python
        if remote_host is None:
            remote_host = os.environ.get('PAM_RHOST', os.environ.get('SSH_CLIENT', 'unknown').split()[0] if os.environ.get('SSH_CLIENT') else 'unknown')
```
**What it does:** Similar to username, but for the IP address:
1. Check `PAM_RHOST` (set during SSH login)
2. If not found, check `SSH_CLIENT` and take the first part (the IP)
3. If nothing works, use 'unknown'

---

```python
        hostname = os.popen('hostname').read().strip()
```
**What it does:** Runs the command `hostname` on the computer to get the server's name, reads the output, and removes extra spaces. Like asking your computer "What's your name?"

---

```python
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
```
**What it does:** Gets the current date and time and formats it as "2025-11-14 15:30:45". The `.strftime()` is like using a template to format the date nicely.

---

```python
        if login_type == "failed":
            title = "⚠️ SSH Failed Login Attempt"
            color = 15158332  # Red color
            status_field = {
                "name": "Status",
                "value": "❌ **FAILED**",
                "inline": False
            }
```
**What it does:** If this is a FAILED login attempt:
- Set the title with a warning emoji
- Set the color to red (Discord uses numbers for colors)
- Create a status field that says "FAILED" with a red X

---

```python
        else:
            title = "🔐 SSH Login Alert"
            color = 3447003  # Blue color
            status_field = {
                "name": "Status",
                "value": "✅ **SUCCESSFUL**",
                "inline": False
            }
```
**What it does:** If this is a SUCCESSFUL login:
- Set the title with a lock emoji
- Set the color to blue
- Create a status field that says "SUCCESSFUL" with a green checkmark

---

```python
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
                ...
            ],
            "footer": {
                "text": "SSH Login Monitor"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
```
**What it does:** Creates a fancy Discord message (called an "embed"). Think of it like creating a nice-looking card with:
- A title at the top
- A color on the side
- Multiple fields with information (User, IP, Server, Time)
- A footer at the bottom
- A timestamp

The `f"..."` is called an f-string - it lets you put variables inside text using `{variable}`.

---

```python
        payload = {
            "embeds": [embed]
        }
```
**What it does:** Wraps our message in a "payload" (the data we'll send to Discord). Discord expects messages in this format.

---

```python
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }
```
**What it does:** Creates headers (like an envelope for our message) that tell Discord:
1. "I'm a bot with this token" (Authorization)
2. "My message is in JSON format" (Content-Type)

---

```python
        url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
```
**What it does:** Creates the URL (web address) where we'll send the message. It's like the mailing address for Discord's API.

---

```python
        response = requests.post(url, json=payload, headers=headers, timeout=10)
```
**What it does:** Sends the message to Discord! 
- `requests.post()` sends an HTTP POST request (a way to send data)
- We include our payload (the message) and headers (authentication)
- `timeout=10` means "give up if it takes more than 10 seconds"

---

```python
        if response.status_code in [200, 204]:
            return True
```
**What it does:** Checks if Discord responded with "200" or "204" (both mean success). If yes, return True (meaning "it worked!").

---

```python
        else:
            print(f"Discord API error: {response.status_code} - {response.text}", file=sys.stderr)
            return False
```
**What it does:** If Discord responded with a different code (an error), print what went wrong and return False (meaning "it didn't work").

---

```python
    except Exception as e:
        print(f"Error sending Discord notification: {e}", file=sys.stderr)
        return False
```
**What it does:** This catches ANY error that might happen in the try block. If something goes wrong, print the error and return False. It's like a safety net!

---

```python
if __name__ == "__main__":
```
**What it does:** This checks "Am I being run directly (not imported by another script)?" It's like saying "Only do this if I'm the main program."

---

```python
    login_type = "success"
    username = None
    remote_host = None
```
**What it does:** Sets default values. We assume it's a successful login unless told otherwise.

---

```python
    if len(sys.argv) > 1:
```
**What it does:** Checks "Did someone pass any command-line arguments when running this script?" `sys.argv` is a list of arguments. The first one (`sys.argv[0]`) is always the script name itself.

---

```python
        if sys.argv[1] == "--failed":
            login_type = "failed"
```
**What it does:** If the first argument is "--failed", change the login type to "failed".

---

```python
            if len(sys.argv) > 2:
                username = sys.argv[2]
            if len(sys.argv) > 3:
                remote_host = sys.argv[3]
```
**What it does:** If there are more arguments, use them as the username (argument 2) and remote_host (argument 3).

**Example:** Running `./ssh_notify.py --failed hacker 1.2.3.4` would set:
- login_type = "failed"
- username = "hacker"
- remote_host = "1.2.3.4"

---

```python
    try:
        send_discord_notification(login_type, username, remote_host)
    except Exception as e:
        print(f"Notification failed: {e}", file=sys.stderr)
```
**What it does:** Try to send the notification. If anything goes wrong, print the error but don't crash (we don't want to block SSH logins!).

---

```python
    sys.exit(0)
```
**What it does:** Exit the program with code 0 (meaning "success"). We always exit successfully so that SSH logins aren't blocked even if Discord notifications fail.

---

---

## 📄 File 2: `ssh_failed_monitor.py` - The Log Watcher

This script watches the system logs like a security guard, looking for failed login attempts.

### Line-by-Line Explanation:

```python
#!/usr/bin/env python3
```
**What it does:** Same as before - tells the computer to use Python3.

---

```python
import os
import re
import subprocess
import time
from pathlib import Path
from datetime import datetime
```
**What it does:** Imports our tools:
- `os`: For file operations
- `re`: For regular expressions (pattern matching in text)
- `subprocess`: For running other programs (like `tail`)
- `time`: For tracking time and creating delays
- `Path` and `datetime`: Same as before

---

```python
AUTH_LOG_PATHS = [
    '/var/log/auth.log',      # Debian/Ubuntu
    '/var/log/secure',         # RHEL/CentOS/Fedora
    '/var/log/messages',       # Some other systems
]
```
**What it does:** Creates a list of possible locations where Linux systems store authentication logs. Different Linux distributions put logs in different places, so we check multiple locations.

Think of it like a list of addresses where the security camera footage might be stored.

---

```python
FAILED_PATTERNS = [
    re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+ ssh'),
    re.compile(r'authentication failure.*rhost=(\S+).*user=(\S+)'),
    re.compile(r'Invalid user (\S+) from (\S+)'),
    re.compile(r'Connection closed by (?:invalid user )?(\S+) (\S+) port \d+ \[preauth\]'),
]
```
**What it does:** Creates patterns (using regular expressions) to detect failed login attempts in the logs.

**Regular expressions explained simply:**
- `r'...'` means "raw string" (treat backslashes literally)
- `\S+` means "one or more non-space characters" (catches words, IPs, etc.)
- `\d+` means "one or more digits" (catches numbers)
- `(?:...)` means "group this but don't capture it"
- `(\S+)` with parentheses means "capture this for later use"

**Example:** The pattern `Failed password for (\S+) from (\S+)` would match:
```
Failed password for john from 192.168.1.100 port 22 ssh
```
And capture: username="john", ip="192.168.1.100"

---

```python
def find_auth_log():
    """Find the system's authentication log file"""
    for log_path in AUTH_LOG_PATHS:
        if os.path.exists(log_path):
            return log_path
    return None
```
**What it does:** Goes through our list of possible log locations and returns the first one that exists. If none exist, return None.

It's like checking multiple drawers until you find where the security camera footage is stored.

---

```python
def parse_failed_login(line):
    """Parse a log line to extract failed login information
    
    Returns:
        tuple: (username, remote_host) or None if not a failed login
    """
```
**What it does:** This function will read a log line and try to extract the username and IP address from failed login attempts.

---

```python
    for pattern in FAILED_PATTERNS:
        match = pattern.search(line)
```
**What it does:** Goes through each pattern and tries to find it in the log line. Like trying different keys to see which one opens the lock.

---

```python
        if match:
            groups = match.groups()
```
**What it does:** If a pattern matched, get the captured groups (the parts in parentheses we wanted to extract).

---

```python
            if len(groups) >= 2:
                user = groups[0] if groups[0] else 'unknown'
                ip = groups[1] if groups[1] else 'unknown'
```
**What it does:** If we captured at least 2 things (username and IP), extract them. Use 'unknown' if either is empty.

---

```python
                if '.' in groups[0] or ':' in groups[0]:
                    ip = groups[0]
                    user = groups[1] if len(groups) > 1 and groups[1] else 'unknown'
```
**What it does:** Some log patterns put the IP first and username second. This checks: "Does the first captured thing look like an IP (has a dot or colon)?" If yes, swap them!

**Example:**
- `192.168.1.100` has a `.` so it's likely an IP
- `fe80::1` has a `:` so it's likely an IPv6 address

---

```python
                return (user, ip)
    return None
```
**What it does:** Return the username and IP as a tuple (a pair of values). If no pattern matched, return None.

---

```python
def send_alert(username, remote_host):
    """Send alert using the ssh_notify.py script"""
```
**What it does:** Creates a function to send an alert using our other script.

---

```python
    try:
        script_path = Path(__file__).parent / 'ssh_notify.py'
        if not script_path.exists():
            script_path = Path('/usr/local/bin/ssh-notify/ssh_notify.py')
```
**What it does:** Tries to find the `ssh_notify.py` script:
1. First, look in the same directory as this script
2. If not found, look in the installed location

---

```python
        if script_path.exists():
            subprocess.run(
                [str(script_path), '--failed', username, remote_host],
                timeout=10,
                capture_output=True
            )
```
**What it does:** If we found the script, run it! 
- `subprocess.run()` executes another program
- We pass arguments: the script path, "--failed", the username, and the IP
- `timeout=10` means give up after 10 seconds
- `capture_output=True` means catch any output (don't print it to screen)

**Example:** This is like running:
```bash
/path/to/ssh_notify.py --failed hacker 1.2.3.4
```

---

```python
    except Exception as e:
        print(f"Error sending alert: {e}")
```
**What it does:** If anything goes wrong, print the error but keep running (we don't want the monitor to crash).

---

```python
def monitor_logs():
    """Monitor authentication logs for failed login attempts"""
    auth_log = find_auth_log()
```
**What it does:** Starts the main monitoring function and finds the log file.

---

```python
    if not auth_log:
        print("Error: Could not find authentication log file")
        print(f"Checked locations: {', '.join(AUTH_LOG_PATHS)}")
        return
```
**What it does:** If we couldn't find the log file, print an error showing which locations we checked, then stop.

---

```python
    print(f"Monitoring {auth_log} for failed SSH login attempts...")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
```
**What it does:** Prints a message showing which log file we're watching and when we started.

---

```python
    recent_alerts = {}
    ALERT_COOLDOWN = 60
```
**What it does:** Creates a dictionary to remember recent alerts and sets a cooldown period (60 seconds). This prevents spam if someone tries to log in wrong multiple times quickly.

Think of it like a spam filter for notifications!

---

```python
    try:
        process = subprocess.Popen(
            ['tail', '-F', '-n', '0', auth_log],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
```
**What it does:** Starts the `tail` command to follow the log file. Let's break down the arguments:
- `tail`: A command that reads the end of files
- `-F`: Follow the file and handle log rotation (if the file is replaced)
- `-n 0`: Start from the end (don't read existing lines)
- `stdout=subprocess.PIPE`: Capture the output so we can read it
- `universal_newlines=True`: Treat output as text (not binary)

It's like opening a live video feed of the log file!

---

```python
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
```
**What it does:** Reads each new line from the log file as it appears. If the line is empty, skip it (continue to next line).

---

```python
            result = parse_failed_login(line)
            if result:
                username, remote_host = result
```
**What it does:** Check if this line indicates a failed login. If yes, extract the username and IP address.

---

```python
                alert_key = (username, remote_host)
                current_time = time.time()
```
**What it does:** Creates a unique key for this alert (combination of username and IP) and gets the current time in seconds.

---

```python
                if alert_key in recent_alerts:
                    time_since_last = current_time - recent_alerts[alert_key]
                    if time_since_last < ALERT_COOLDOWN:
                        continue
```
**What it does:** Checks: "Did we already send an alert for this user/IP combo recently?" If yes, and it's been less than 60 seconds, skip this alert (don't spam Discord).

---

```python
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Failed login: user={username}, ip={remote_host}")
                send_alert(username, remote_host)
```
**What it does:** Print a message to the console and send the Discord alert!

---

```python
                recent_alerts[alert_key] = current_time
```
**What it does:** Remember that we just sent an alert for this user/IP combo at this time.

---

```python
                recent_alerts = {
                    k: v for k, v in recent_alerts.items() 
                    if current_time - v < ALERT_COOLDOWN * 2
                }
```
**What it does:** Clean up old entries from our memory. This is called a "dictionary comprehension" - it creates a new dictionary containing only entries from the last 2 minutes (120 seconds).

Think of it as throwing away old receipts to keep your wallet clean!

---

```python
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
```
**What it does:** If someone presses Ctrl+C to stop the program, print a nice message.

---

```python
    except Exception as e:
        print(f"Error monitoring logs: {e}")
```
**What it does:** If any other error occurs, print it.

---

```python
    finally:
        if 'process' in locals():
            process.terminate()
```
**What it does:** No matter what happens (success or error), stop the tail process cleanly. The `finally` block always runs, even if there was an error.

---

```python
if __name__ == "__main__":
    monitor_logs()
```
**What it does:** If this script is run directly, start monitoring logs!

---

---

## 📄 File 3: `install_ssh_notify.sh` - The Installer

This bash script installs everything automatically. Bash is a different programming language than Python - it's the language of the terminal.

### Line-by-Line Explanation:

```bash
#!/bin/bash
```
**What it does:** Same concept as Python's shebang - tells the computer "use bash to run this."

---

```bash
set -e
```
**What it does:** Tells bash "if ANY command fails, stop the entire script immediately." It's a safety feature that prevents running with errors.

---

```bash
echo "=========================================="
echo "SSH Login Discord Notifier - Installation"
echo "=========================================="
```
**What it does:** `echo` prints text to the screen. This prints a nice header.

---

```bash
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi
```
**What it does:** 
- `$EUID` is the "Effective User ID" (0 means root/admin)
- `-ne` means "not equal"
- This checks "Are we running as root?" If not, print an error and exit

We need root privileges to modify system files.

---

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
```
**What it does:** Gets the directory where this script is located. Let's break it down:
- `${BASH_SOURCE[0]}` is the path to this script
- `dirname` gets the directory part of the path
- `cd` changes to that directory
- `pwd` prints the current directory (now the full absolute path)
- `$()` runs the command and captures the output

**Example:** If the script is at `/home/user/scripts/install.sh`, this sets `SCRIPT_DIR=/home/user/scripts`

---

```bash
if [ ! -f "$SCRIPT_DIR/ssh_notify.py" ]; then
    echo "Error: ssh_notify.py not found in $SCRIPT_DIR"
    exit 1
fi
```
**What it does:**
- `[ ! -f "$SCRIPT_DIR/ssh_notify.py" ]` checks "Does this file NOT exist?"
- `-f` means "is a regular file"
- `!` means "not"
- If the file doesn't exist, print error and exit

This ensures all required files are present before installing.

---

```bash
echo "[1/8] Installing Python dependencies..."
pip3 install requests >/dev/null 2>&1 || {
    echo "Warning: pip3 install failed, trying with --break-system-packages"
    pip3 install requests --break-system-packages
}
```
**What it does:**
- Tries to install the `requests` Python library
- `>/dev/null` sends normal output to the void (hides it)
- `2>&1` redirects errors to the same place as normal output
- `||` means "or" - if the first command fails, do the second
- `{...}` groups multiple commands together

On some systems (like recent Debian), you need the `--break-system-packages` flag.

---

```bash
INSTALL_DIR="/usr/local/bin/ssh-notify"
mkdir -p "$INSTALL_DIR"
```
**What it does:**
- Sets where we'll install the files
- `mkdir -p` creates the directory (and parent directories if needed)
- The `-p` flag means "don't error if it already exists"

---

```bash
cp "$SCRIPT_DIR/ssh_notify.py" "$INSTALL_DIR/ssh_notify.py"
```
**What it does:** Copies the file from the source directory to the installation directory. Like photocopying a document.

---

```bash
chmod +x "$INSTALL_DIR/ssh_notify.py"
```
**What it does:** Makes the file executable (adds execute permission). The `+x` means "add execute permission for everyone."

---

```bash
chmod 600 "$INSTALL_DIR/.env"
```
**What it does:** Sets file permissions to `600`, which means:
- `6`: Owner can read and write
- `0`: Group can't access
- `0`: Others can't access

This keeps your Discord credentials secret!

---

```bash
PAM_SSH_FILE="/etc/pam.d/sshd"
```
**What it does:** Sets a variable for the PAM configuration file. PAM (Pluggable Authentication Modules) controls how Linux handles authentication.

---

```bash
if grep -q "ssh_notify.py" "$PAM_SSH_FILE"; then
    echo "PAM hook already exists, skipping..."
```
**What it does:**
- `grep -q` searches for text (the `-q` means "quiet" - don't print matches)
- Checks "Does the PAM file already mention our script?"
- If yes, skip this step (don't add it twice)

---

```bash
else
    cp "$PAM_SSH_FILE" "$PAM_SSH_FILE.backup.$(date +%Y%m%d_%H%M%S)"
```
**What it does:** Creates a backup of the PAM file with a timestamp. 
- `$(date +%Y%m%d_%H%M%S)` runs the `date` command to get a timestamp like "20251114_153045"

**Example:** Creates `/etc/pam.d/sshd.backup.20251114_153045`

---

```bash
    echo "" >> "$PAM_SSH_FILE"
    echo "# SSH Login Discord Notification" >> "$PAM_SSH_FILE"
    echo "session optional pam_exec.so seteuid $INSTALL_DIR/ssh_notify.py" >> "$PAM_SSH_FILE"
```
**What it does:** Adds three lines to the PAM file:
- An empty line
- A comment explaining what we're adding
- The actual PAM rule

The `>>` means "append to file" (add to the end).

**The PAM rule explained:**
- `session`: Run this during the session phase (after successful login)
- `optional`: Don't fail the login if this doesn't work
- `pam_exec.so`: Execute an external program
- `seteuid`: Set the effective user ID (run as the logged-in user)
- Then the path to our script

---

```bash
cat > /usr/local/bin/ssh-notify-test << 'EOF'
#!/bin/bash
# Test script for SSH notification
export PAM_USER="${USER}"
export PAM_RHOST="127.0.0.1"
/usr/local/bin/ssh-notify/ssh_notify.py
EOF
```
**What it does:** Creates a new file with the content between `<<'EOF'` and `EOF`. This is called a "here document."

- `cat >` creates a new file
- Everything between the EOF markers becomes the file's content
- The single quotes around `'EOF'` prevent variable expansion

The test script simulates what PAM does by setting the environment variables.

---

```bash
chmod +x /usr/local/bin/ssh-notify-test
```
**What it does:** Makes the test script executable.

---

```bash
mkdir -p /var/log/ssh-notify
chmod 755 /var/log/ssh-notify
```
**What it does:** Creates a directory for log files and sets permissions to `755`:
- `7`: Owner can read, write, execute
- `5`: Group can read and execute
- `5`: Others can read and execute

---

```bash
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
```
**What it does:** Creates a systemd service file. Systemd is the program that manages services on Linux.

**Breaking down the service file:**

`[Unit]` section:
- `Description`: Human-readable name
- `After`: Start this service after network and syslog are ready

`[Service]` section:
- `Type=simple`: The process runs in the foreground
- `ExecStart`: The command to run
- `Restart=always`: If it crashes, restart it automatically
- `RestartSec=10`: Wait 10 seconds before restarting
- `StandardOutput/Error`: Where to send output and errors
- `NoNewPrivileges=true`: Security - can't gain more permissions
- `PrivateTmp=true`: Security - gets its own /tmp directory

`[Install]` section:
- `WantedBy=multi-user.target`: Start this when the system reaches multi-user mode (normal boot)

---

```bash
systemctl daemon-reload
```
**What it does:** Tells systemd "reload your configuration files" (so it sees our new service).

---

```bash
systemctl enable ssh-failed-monitor.service
```
**What it does:** Enables the service to start automatically on boot.

---

```bash
systemctl start ssh-failed-monitor.service
```
**What it does:** Starts the service right now (doesn't wait for reboot).

---

```bash
systemctl status ssh-failed-monitor.service --no-pager -l | head -n 10
```
**What it does:** Shows the status of the service:
- `--no-pager`: Don't use a pager (less/more)
- `-l`: Show full output
- `| head -n 10`: Only show first 10 lines

---

---

## 📄 File 4: `test_failed_alert.sh` - The Test Script

This is a simple script to test failed login alerts.

### Line-by-Line Explanation:

```bash
#!/bin/bash
```
**What it does:** Use bash to run this script.

---

```bash
echo "Testing failed SSH login notification..."
echo "This will send a test alert to Discord"
```
**What it does:** Prints informational messages to the user.

---

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
```
**What it does:** Gets the directory where this script is located (same technique as in the installer).

---

```bash
if [ -f "$SCRIPT_DIR/ssh_notify.py" ]; then
    NOTIFY_SCRIPT="$SCRIPT_DIR/ssh_notify.py"
elif [ -f "/usr/local/bin/ssh-notify/ssh_notify.py" ]; then
    NOTIFY_SCRIPT="/usr/local/bin/ssh-notify/ssh_notify.py"
else
    echo "Error: ssh_notify.py not found"
    exit 1
fi
```
**What it does:** Finds the notification script:
1. First check the local directory
2. If not found, check the installed location
3. If still not found, print error and exit

This is like looking in your desk drawer first, then checking the filing cabinet.

---

```bash
"$NOTIFY_SCRIPT" --failed "test_user" "192.168.1.100"
```
**What it does:** Runs the notification script with:
- `--failed` flag (indicates a failed login)
- Username: "test_user"
- IP address: "192.168.1.100"

The quotes around `$NOTIFY_SCRIPT` are important in case the path has spaces!

---

```bash
echo ""
echo "Test complete! Check your Discord channel for the alert."
echo "The alert should show a red warning with status: FAILED"
```
**What it does:** Prints a completion message telling the user what to expect.

---

---

## 🎯 Summary: How It All Works Together

1. **When someone logs in successfully via SSH:**
   - PAM (the authentication system) runs `ssh_notify.py`
   - The script reads who logged in and from where
   - It sends a **blue** notification to Discord

2. **When someone tries but fails to log in:**
   - Linux writes a failure message to `/var/log/auth.log` (or `/var/log/secure`)
   - `ssh_failed_monitor.py` is watching that file constantly
   - When it sees a failure pattern, it calls `ssh_notify.py --failed username ip`
   - The script sends a **red** notification to Discord

3. **The installer:**
   - Copies all scripts to `/usr/local/bin/ssh-notify/`
   - Modifies PAM to run the script on successful logins
   - Creates a systemd service that runs the monitor 24/7
   - Makes test scripts so you can verify everything works

---

## 🧠 Key Programming Concepts Used

1. **Functions**: Reusable blocks of code (like recipes)
2. **Regular Expressions**: Patterns to match text (like advanced search)
3. **Error Handling**: Try/except blocks to handle problems gracefully
4. **Subprocess**: Running other programs from within your program
5. **Environment Variables**: Secret storage that programs can read
6. **File I/O**: Reading from and writing to files
7. **API Calls**: Sending data to web services (Discord)
8. **Systemd Services**: Background programs that run continuously
9. **PAM Hooks**: Triggers that run when someone logs in

---

I hope this helps you understand exactly how everything works! Feel free to ask if you want me to explain any part in even more detail! 🎓
