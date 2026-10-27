#!/bin/sh
# Inert YARA fixture for CERBER_MacOS_Shell_Hex_Decode - text only, not a working sample.
echo "6563686f20696563686f20696563686f20696563686f20696563686f20696563686f20696563686f20696563686f206e6f70" | xxd -p -r | sh
