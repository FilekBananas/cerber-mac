#!/bin/zsh
# Inert YARA fixture for CERBER_MacOS_MacSync_Backdoor_2025 (strings only, no commands run)
MAGIC="SONOMAC1"
LOG="$HOME/Library/Logs/.sysnotif-agent.log"
PING="/v1/agent/ping"
HDR="X-Upload-Token"
