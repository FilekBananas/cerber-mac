#!/bin/zsh
# Inert YARA fixture for CERBER_MacOS_ClickFix_C2_Domains - text only, not a working sample.
servers=("0x666.info" "honestly.ink" "pla7ina.cfd" "play67.cc")
for s in $servers; do
  curl -s -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" "https://$s/upload.php" -o /dev/null
done
