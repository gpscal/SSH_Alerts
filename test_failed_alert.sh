#!/bin/bash
# Test script for failed SSH login notification

echo "Testing failed SSH login notification..."
echo "This will send a test alert to Discord"
echo ""

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if ssh_notify.py exists
if [ -f "$SCRIPT_DIR/ssh_notify.py" ]; then
    NOTIFY_SCRIPT="$SCRIPT_DIR/ssh_notify.py"
elif [ -f "/usr/local/bin/ssh-notify/ssh_notify.py" ]; then
    NOTIFY_SCRIPT="/usr/local/bin/ssh-notify/ssh_notify.py"
else
    echo "Error: ssh_notify.py not found"
    exit 1
fi

# Send test failed login notification
echo "Sending test failed login alert..."
"$NOTIFY_SCRIPT" --failed "test_user" "192.168.1.100"

echo ""
echo "Test complete! Check your Discord channel for the alert."
echo "The alert should show a red warning with status: FAILED"
