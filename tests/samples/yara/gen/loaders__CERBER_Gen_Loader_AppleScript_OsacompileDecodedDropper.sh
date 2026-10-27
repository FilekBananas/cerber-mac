#!/bin/sh
echo "AAAA" | base64 -D | osacompile -o /tmp/example_placeholder.scpt
chmod +x /tmp/example_placeholder.scpt
