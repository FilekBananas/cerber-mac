#!/bin/zsh
# Inert YARA fixture for CERBER_MacOS_ClickFix_Encoded_Command_Pipe - text only, not a working sample.
echo 'Verification completed'
clear
echo 'ZWNobyB0aGlzIGlzIGFuIGluZXJ0IGZpeHR1cmUgZm9yIHlhcmEgcnVsZSBjb3ZlcmFnZSBvbmx5IGFuZCBpcyBub3QgYSByZWFsIHBheWxvYWQgYXQgYWxs' | base64 -D | zsh
