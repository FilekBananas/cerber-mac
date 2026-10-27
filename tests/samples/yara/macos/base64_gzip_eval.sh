#!/bin/zsh
# Inert YARA fixture for CERBER_MacOS_Base64_Gzip_Eval - text only, not a working sample.
payload="H4sIAAAAAAAC/63Myw2AIBAFwLtVvBL8FoTkoSQIyboY6V4rMB72OJeh3wtipihCvLUKkV4i12OloEcoAt2J5sRBaiJ8uShuI5SnouTUOn4vg8kymiyTyTKbLMu/5QFjR89ypAEAAA=="
eval "$(echo "$payload" | base64 -D | gunzip)"
