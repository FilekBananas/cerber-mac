#!/bin/zsh
# Cerber launcher: ./cerber.sh scan ~/Downloads
DIR="${0:A:h}"
exec "$DIR/.venv/bin/python" -m cerber "$@"
