#!/bin/bash
# synthetic fixture: indicator strings only
echo "$(date): Running post-installation script..." >> /tmp/postinstall.log
if [ -f /var/tmp/zoom ]; then
  /var/tmp/zoom >> /tmp/postinstall.log 2>&1 &
fi
if [ -d "/var/tmp/InstallerAlert.app" ]; then
  open "/var/tmp/InstallerAlert.app" >> /tmp/postinstall.log 2>&1
fi
# bundle ids: Mac-Installer.InstallerAlert Mac-Installer.AlertMsg ; package versus.pkg
exit 0
